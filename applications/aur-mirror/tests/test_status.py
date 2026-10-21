"""Status documents: repo db parsing, package rows, retention, live file."""
import io
import json
import os
import tarfile
import time

from aurmirror import config as cfg
from aurmirror import status


def _db(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, ver in entries:
            body = (f"%FILENAME%\n{name}-{ver}-any.pkg.tar.zst\n\n%NAME%\n{name}\n\n"
                    f"%BASE%\n{name}\n\n%VERSION%\n{ver}\n\n%BUILDDATE%\n1700000000\n").encode()
            info = tarfile.TarInfo(f"{name}-{ver}/desc")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))


def test_read_repo_db(tmp_path):
    """Name, version, build date and filename come from the db."""
    _db(tmp_path / "r.db.tar.gz", [("x", "1.0-1"), ("y", "2-3")])
    got = status.read_repo_db(tmp_path / "r.db.tar.gz")
    assert got["x"]["version"] == "1.0-1" and got["y"]["builddate"] == 1700000000
    assert got["x"]["filename"] == "x-1.0-1-any.pkg.tar.zst"


def test_read_repo_db_corrupt_is_empty(tmp_path):
    """A corrupt db yields nothing rather than a partial map."""
    (tmp_path / "bad.tar.gz").write_bytes(b"not a tarball")
    assert not status.read_repo_db(tmp_path / "bad.tar.gz")


def _inputs(**kw):
    base = {"approved": [{"name": "x"}],
            "repo": status.RepoView(db={"x": {"version": "1.0-1"}}, built={"x": "c-built"}),
            "meta": {"x": {"version": "1.1-1", "pkgbase": "xb"}},
            "state": {"x": {"commit": "c-scanned"}}, "events": {}, "now": 1000}
    base.update(kw)
    return status.StatusInputs(**base)


def test_recipe_url_aur_and_github():
    """AUR links use the pkgbase and commit; GitHub sources link the blob."""
    aur = status.recipe_url({"name": "freeipa-client"}, "freeipa", "abc")
    assert aur == "https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=freeipa&id=abc"
    assert status.recipe_url({"name": "x"}, "x", None).endswith("PKGBUILD?h=x")
    gh = status.recipe_url({"name": "pac", "source": "https://github.com/usenix17/pac.git"},
                           "pac", "def")
    assert gh == "https://github.com/usenix17/pac/blob/def/PKGBUILD"
    assert status.recipe_url({"name": "y", "source": "https://gitea.example/y.git"},
                             "y", "z") is None


def test_pkgbuild_links_published_or_rejected_commit(dirs):  # pylint: disable=unused-argument
    """Healthy rows link the built commit; held rows link what was rejected."""
    row = status.package_entry({"name": "x"}, _inputs())
    assert row["pkgbuild_url"].endswith("h=xb&id=c-built")
    held = {"x": {"result": "held", "reason": "scan", "summary": "bad"}}
    row = status.package_entry({"name": "x"}, _inputs(events=held))
    assert row["pkgbuild_url"].endswith("h=xb&id=c-scanned")
    sibling = _inputs(repo=status.RepoView(db={"x": {"version": "1.0-1"}}))
    assert status.package_entry({"name": "x"}, sibling)["pkgbuild_url"].endswith("id=c-scanned")


def test_package_entry_ok_and_behind(dirs):  # pylint: disable=unused-argument
    """A published package behind upstream is flagged."""
    row = status.package_entry({"name": "x"}, _inputs())
    assert row["status"] == "ok" and row["behind"] and row["pkgbase"] == "xb"


def test_aur_flag_date_and_count(dirs):  # pylint: disable=unused-argument
    """The AUR out-of-date flag carries its date and is counted."""
    meta = {"x": {"version": "1.0-1", "out_of_date": 1792000000}}
    inp = _inputs(meta=meta)
    row = status.package_entry({"name": "x"}, inp)
    assert row["out_of_date"] and row["flagged_since"] == 1792000000
    assert status.build_packages_doc(inp, {})["counts"]["flagged"] == 1
    legacy = status.package_entry({"name": "x"}, _inputs(meta={"x": {"out_of_date": True}}))
    assert legacy["out_of_date"] and legacy["flagged_since"] is None


def test_package_entry_streak(dirs):  # pylint: disable=unused-argument
    """Consecutive held runs count up and keep the first failure time."""
    held = {"x": {"result": "failed", "reason": "build_error", "summary": "boom"}}
    prev = {"x": {"streak": 2, "failing_since": 500}}
    row = status.package_entry({"name": "x"}, _inputs(events=held, prev=prev))
    assert row["status"] == "held" and row["streak"] == 3 and row["failing_since"] == 500
    row = status.package_entry({"name": "x"}, _inputs(prev=prev))
    assert row["streak"] == 0 and row["failing_since"] is None


def test_package_entry_drops_expired_log(dirs):  # pylint: disable=unused-argument
    """A log removed by retention is not linked."""
    prev = {"x": {"log": "/status/logs/old/x.build.log"}}
    assert status.package_entry({"name": "x"}, _inputs(prev=prev))["log"] is None


def test_update_runs_trims(dirs):  # pylint: disable=unused-argument
    """Runs past the retention window are dropped; newest first."""
    now = int(time.time())
    old = {"id": "old", "started_at": now - (cfg.LOG_RETENTION_DAYS + 1) * 86400}
    keep = {"id": "keep", "started_at": now - 86400}
    doc = status.update_runs({"runs": [old, keep]}, {"id": "new", "started_at": now}, now)
    assert [r["id"] for r in doc["runs"]] == ["new", "keep"]


def test_cleanup_logs(dirs):  # pylint: disable=unused-argument
    """Old per-run log dirs are deleted, recent ones kept."""
    now = int(time.time())
    old = cfg.STATUS_DIR / "logs" / "old"
    new = cfg.STATUS_DIR / "logs" / "new"
    old.mkdir(parents=True)
    new.mkdir()
    stamp = now - (cfg.LOG_RETENTION_DAYS + 1) * 86400
    os.utime(old, (stamp, stamp))
    assert status.cleanup_logs(now) == 1 and new.exists() and not old.exists()


def test_write_live_keeps_run_start(dirs, monkeypatch):  # pylint: disable=unused-argument
    """started_at is fixed for a run and resets for the next one."""
    status.write_live("scan", "x", 1, 2)
    first = json.loads((cfg.STATUS_DIR / "live.json").read_text(encoding="utf-8"))
    status.write_live("build", "y", 1, 2)
    second = json.loads((cfg.STATUS_DIR / "live.json").read_text(encoding="utf-8"))
    assert second["started_at"] == first["started_at"] and second["phase"] == "build"
    monkeypatch.setattr(cfg, "RUN_ID", "run-2")
    (cfg.STATUS_DIR / "live.json").write_text(json.dumps({**second, "started_at": 1}),
                                              encoding="utf-8")
    status.write_live("scan", "z", 1, 2)
    third = json.loads((cfg.STATUS_DIR / "live.json").read_text(encoding="utf-8"))
    assert third["run_id"] == "run-2" and third["started_at"] != 1
