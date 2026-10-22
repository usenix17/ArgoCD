"""Build-phase decisions: skipping, backoff, artifact filtering, keys, logs."""
import subprocess
import time

from aurmirror import build
from aurmirror import config as cfg
from aurmirror.buildlog import LogTee, run_logged


def _ctx(**overrides) -> build.BuildContext:
    base = {"state": {}, "meta": {}, "built_commits": {}, "failures": {}, "wanted": {"x"},
            "python": build.PythonRebuild(now="3.14", stale=set()), "timeouts": {}}
    base.update(overrides)
    return build.BuildContext(**base)


def test_uptodate_skips():
    """The scanned commit is already published."""
    got = build.skip_reason({"name": "x"}, "c1", _ctx(built_commits={"x": "c1"}))
    assert got["result"] == "uptodate"


def test_new_commit_builds():
    """A new commit always builds, even after a failure."""
    ctx = _ctx(failures={"x": {"commit": "old", "reason": "build_error", "ts": time.time()}})
    assert build.skip_reason({"name": "x"}, "c2", ctx) is None


def test_recent_failure_backs_off():
    """The same failing commit is not rebuilt inside the window."""
    ctx = _ctx(failures={"x": {"commit": "c1", "reason": "build_error", "ts": time.time()}})
    got = build.skip_reason({"name": "x"}, "c1", ctx)
    assert got["result"] == "backoff" and got["reason"] == "build_failed"


def test_old_failure_retries():
    """Past the window the same commit is retried."""
    stale_ts = time.time() - (cfg.BUILD_FAILURE_RETRY_DAYS + 1) * 86400
    ctx = _ctx(failures={"x": {"commit": "c1", "reason": "build_error", "ts": stale_ts}})
    assert build.skip_reason({"name": "x"}, "c1", ctx) is None


def test_track_latest_and_python_always_build():
    """Moving-upstream and python-stranded packages ignore the skip rules."""
    ctx = _ctx(built_commits={"x": "c1"})
    assert build.skip_reason({"name": "x", "track": "latest"}, "c1", ctx) is None
    ctx = _ctx(built_commits={"x": "c1"}, python=build.PythonRebuild("3.14", {"x"}))
    assert build.skip_reason({"name": "x"}, "c1", ctx) is None


def test_scan_hold_is_reported():
    """No passing verdict means held, never built."""
    ctx = _ctx(state={"x": {"verdict": "error", "commit": "", "summary": "credit"}})
    event, record = build.build_entry({"name": "x"}, ctx)
    assert event["result"] == "held" and event["reason"] == "scan" and record is None


def test_select_artifacts_drops_unlisted_split_children(tmp_path):
    """Only allowlisted packages and their -debug variants are kept."""
    names = ["x-1.0-1-x86_64.pkg.tar.zst", "x-debug-1.0-1-x86_64.pkg.tar.zst",
             "x-extra-1.0-1-x86_64.pkg.tar.zst"]
    paths = []
    for name in names:
        (tmp_path / name).write_text("", encoding="utf-8")
        paths.append(tmp_path / name)
    kept = build.select_artifacts(paths, {"x"})
    assert [p.name for p in kept] == names[:2]
    assert not (tmp_path / names[2]).exists()


def test_keyserver_fallback_order(tmp_path, monkeypatch):
    """Missing keys are tried on each keyserver in order until one works, in the sandbox."""
    calls = []

    def fake_sandboxed(work, cmd, timeout):  # pylint: disable=unused-argument
        calls.append(cmd)
        failed = "--list-keys" in cmd or cfg.GPG_KEYSERVERS[0] in cmd
        return subprocess.CompletedProcess(cmd, 2 if failed else 0)
    monkeypatch.setattr(build, "run_sandboxed", fake_sandboxed)
    build.import_validpgpkeys(tmp_path, "\tvalidpgpkeys = AAAA\n", LogTee(None))
    servers = [c[c.index("--keyserver") + 1] for c in calls if "--keyserver" in c]
    assert servers == cfg.GPG_KEYSERVERS[:2]


def test_recipe_shipped_keys_imported_first(tmp_path, monkeypatch):
    """keys/pgp/*.asc in the recipe is imported, by its in-sandbox path, before lookups."""
    (tmp_path / "src" / "keys" / "pgp").mkdir(parents=True)
    (tmp_path / "src" / "keys" / "pgp" / "AAAA.asc").write_text("key", encoding="utf-8")
    calls = []
    monkeypatch.setattr(build, "run_sandboxed",
                        lambda w, cmd, timeout: calls.append(cmd)
                        or subprocess.CompletedProcess(cmd, 0))
    build.import_validpgpkeys(tmp_path, "\tvalidpgpkeys = AAAA\n", LogTee(None))
    assert calls[0][-2:] == ["--import", "/work/src/keys/pgp/AAAA.asc"]


def test_build_runs_makepkg_only_in_sandbox(tmp_path):
    """makepkg is launched through the sandbox, without -s or sudo."""
    cmd = build.sandbox_build_cmd(tmp_path)
    assert cmd[0] == "setpriv" and str(cfg.SANDBOX) in cmd
    assert cmd[-3:] == ["makepkg", "--noconfirm", "--noprogressbar"]
    assert "-s" not in cmd and "sudo" not in cmd


def test_run_logged_tees_and_times_out(dirs):  # pylint: disable=unused-argument
    """Output reaches the log file, and a timeout kills the process group."""
    tee = LogTee(cfg.STATUS_DIR / "out.log")
    assert tee.url == "/status/out.log"
    run_logged(["sh", "-c", "echo hello"], tee)
    try:
        run_logged(["sh", "-c", "sleep 30 & wait"], tee, timeout=1)
        raise AssertionError("expected a timeout")
    except subprocess.TimeoutExpired:
        pass
    tee.close()
    text = (cfg.STATUS_DIR / "out.log").read_text(encoding="utf-8")
    assert "hello" in text and "killed after 1s timeout" in text


def test_log_cap(dirs, monkeypatch):  # pylint: disable=unused-argument
    """Logs stop growing at the cap with a note."""
    monkeypatch.setattr(cfg, "LOG_MAX_BYTES", 50)
    tee = LogTee(cfg.STATUS_DIR / "out.log")
    for _ in range(20):
        tee.line("0123456789")
    tee.close()
    text = (cfg.STATUS_DIR / "out.log").read_text(encoding="utf-8")
    assert len(text) < 200 and "truncated" in text


def test_log_outside_status_dir_degrades(tmp_path):
    """A bad log path never breaks the build: console-only output."""
    tee = LogTee(tmp_path / "elsewhere.log")
    tee.line("still printed")
    assert tee.url is None
