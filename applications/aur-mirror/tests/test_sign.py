"""Sign phase: downgrade guard, failure markers, sweeping and run documents."""
from aurmirror import config as cfg
from aurmirror import sign


def _rec(name: str) -> dict:
    return {"name": name, "sha256": "0"}


def test_classify_newer_same_older():
    """Only strictly newer artifacts are published."""
    published = {"x": {"version": "1.2-1"}}
    got = sign.classify_artifacts(
        [_rec("x-1.3-1-x86_64.pkg.tar.zst")], published)
    assert len(got["newer"]) == 1
    got = sign.classify_artifacts([_rec("x-1.2-1-x86_64.pkg.tar.zst")], published)
    assert len(got["same"]) == 1
    got = sign.classify_artifacts([_rec("x-1.1-1-x86_64.pkg.tar.zst")], published)
    assert len(got["older"]) == 1


def test_python_pkgrel_bump_is_newer():
    """A python rebuild (pkgrel 4 -> 4.14) outranks the original."""
    got = sign.classify_artifacts([_rec("x-1.0-4.14-any.pkg.tar.zst")],
                                  {"x": {"version": "1.0-4"}})
    assert len(got["newer"]) == 1


def test_first_publish_is_newer():
    """A package not yet in the database is published."""
    assert len(sign.classify_artifacts([_rec("x-1-1-any.pkg.tar.zst")], {})["newer"]) == 1


def test_update_failures(dirs):  # pylint: disable=unused-argument
    """Failures are recorded, successes clear them, siblings are ignored."""
    events = {
        "a": {"result": "failed", "reason": "build_error", "commit": "c1"},
        "b": {"result": "published"},
        "c": {"result": "failed", "reason": "fetch_error", "commit": "c3"},
        "d": {"result": "failed", "reason": "build_error", "owner": "a"},
    }
    (cfg.REPO_DIR / "aur-mirror.build-failures.json").write_text(
        '{"b": {"commit": "old"}, "gone": {"commit": "x"}}', encoding="utf-8")
    got = sign.update_failures(events, 100)
    assert got == {"a": {"commit": "c1", "reason": "build_error", "ts": 100}}


def test_sweep_unreferenced(dirs):  # pylint: disable=unused-argument
    """Superseded package files and their signatures are removed."""
    for name in ("x-1-1-any.pkg.tar.zst", "x-1-1-any.pkg.tar.zst.sig",
                 "x-2-1-any.pkg.tar.zst", "x-2-1-any.pkg.tar.zst.sig", "aur-mirror.db"):
        (cfg.REPO_DIR / name).write_text("", encoding="utf-8")
    removed = sign.sweep_unreferenced({"x": {"filename": "x-2-1-any.pkg.tar.zst"}})
    assert removed == 2
    assert sorted(p.name for p in cfg.REPO_DIR.iterdir()) == [
        "aur-mirror.db", "x-2-1-any.pkg.tar.zst", "x-2-1-any.pkg.tar.zst.sig"]


def test_sweep_refuses_empty_db(dirs):  # pylint: disable=unused-argument
    """An unreadable database deletes nothing."""
    (cfg.REPO_DIR / "x-1-1-any.pkg.tar.zst").write_text("", encoding="utf-8")
    assert sign.sweep_unreferenced({}) == 0


def test_run_document_omits_quiet_packages(dirs):  # pylint: disable=unused-argument
    """Up-to-date and still-held packages stay out of the run history."""
    events = {"a": {"result": "published", "version": "1-1"}, "b": {"result": "uptodate"},
              "c": {"result": "held", "reason": "scan"}, "d": {"result": "held"}}
    doc = sign.run_document({}, events, {"started_at": 5, "scan_logs": {"d": "/status/x"}}, 9)
    assert [e["name"] for e in doc["events"]] == ["a", "d"]
    assert doc["counts"]["published"] == 1 and doc["started_at"] == 5
