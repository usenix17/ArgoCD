"""Build phase: build each scanned commit, Trivy-check it, stage what passes.

This container is the trusted orchestrator (root inside gVisor). Recipe code
never runs here directly: key import and makepkg go through the per-package
sandbox (sandbox.py), and dependencies are installed by root from the signed
repos around each build. No API key and no GPG key are present here.

Per-package outcomes go into the staging manifest as ``events`` (staged,
failed, held, backoff, uptodate) and ``failed`` (holds), and the run always
continues so the signer can publish whatever passed.
"""
import logging
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import config as cfg
from .aur import git_url, load_meta, pkgbase
from .buildlog import LogTee, run_logged
from .common import (artifact_parts, give_to_pipeline, hold, load_approved, read_json, run,
                     sha256_file, write_json)
from .metrics import push_progress
from .pyrebuild import bump_pkgrel, current_python, stale_python_packages
from .recipe import recipe_sha256
from .sandbox import (built_artifacts, hand_over, install_deps, make_work, remove_deps,
                      run_sandboxed, sandbox_cmd, srcinfo_deps, srcinfo_values)
from .scan import load_state
from .status import log_path

log = logging.getLogger("aurmirror")

# Failures that will repeat for the same commit; retried after the backoff window.
BACKOFF_REASONS = {"build_error", "build_timeout", "trivy", "no_artifacts", "bad_deps"}


def import_validpgpkeys(work: Path, srcinfo: str, tee: LogTee) -> None:
    """Make a recipe's signing keys available so makepkg can verify sources.

    Imports recipe-shipped keys/pgp/*.asc first, then fetches each
    validpgpkeys fingerprint still missing from the keyservers in order. gpg
    runs in the sandbox, into the package's own keyring. Non-fatal: makepkg
    still verifies signatures and fails if a key is absent.
    """
    for asc in sorted((work / "src" / "keys" / "pgp").glob("*.asc")):
        _gpg(work, ["--import", f"/work/src/keys/pgp/{asc.name}"], tee)
    for fpr in srcinfo_values(srcinfo, "validpgpkeys"):
        if _gpg(work, ["--list-keys", fpr], None):
            continue
        if not any(_gpg(work, ["--keyserver", ks, "--recv-keys", fpr], tee, ks)
                   for ks in cfg.GPG_KEYSERVERS):
            tee.line(f"WARNING: key {fpr} not found on any keyserver; build may fail")


def _gpg(work: Path, args: list[str], tee: LogTee | None, server: str = "") -> bool:
    try:
        ok = run_sandboxed(work, ["gpg", "--batch", *args], timeout=20).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
    if ok and tee is not None and server:
        tee.line(f"imported key {args[-1]} from {server}")
    return ok


def trivy_clean(artifact: Path, tee: LogTee) -> bool:
    """Scan the extracted package with Trivy; any error or finding fails closed.

    Trivy must scan the extracted tree: pointed at the tarball it scans nothing.
    """
    try:
        with tempfile.TemporaryDirectory(dir=cfg.BUILD_DIR) as tmp:
            subprocess.run(["bsdtar", "-xpf", str(artifact), "-C", tmp], check=True)
            run_logged(["trivy", "rootfs", "--exit-code", "1", "--severity", cfg.FAIL_SEVS,
                        "--scanners", "vuln,secret", "--no-progress", tmp], tee)
        return True
    except (subprocess.CalledProcessError, OSError) as exc:
        tee.line(f"Trivy failed for {artifact.name}: {exc}")
        return False


def select_artifacts(artifacts: list[Path], wanted: set[str]) -> list[Path]:
    """Keep allowlisted packages (and their -debug variants); delete the rest."""
    keep = []
    for artifact in artifacts:
        name = artifact_parts(artifact.name)[0]
        if name.removesuffix("-debug") in wanted:
            keep.append(artifact)
        else:
            log.info("Dropping non-allowlisted split package %s", artifact.name)
            artifact.unlink(missing_ok=True)
    return keep


def stage_artifacts(pkg: str, artifacts: list[Path]) -> list[dict]:
    """Move vetted artifacts into staging, recording each SHA256 for the signer."""
    dest = cfg.staging_dir() / pkg
    dest.mkdir(parents=True, exist_ok=True)
    give_to_pipeline(dest)  # the signer signs in place and empties staging
    recorded = []
    for artifact in artifacts:
        target = dest / artifact.name
        shutil.move(str(artifact), str(target))
        give_to_pipeline(target)
        recorded.append({"name": artifact.name, "sha256": sha256_file(target)})
    return recorded


@dataclass
class PythonRebuild:
    """The current python minor and the packages stranded on an older one."""

    now: str | None
    stale: set


@dataclass
class BuildContext:
    """Run-wide inputs for building packages."""

    state: dict
    meta: dict
    built_commits: dict
    failures: dict
    wanted: set
    python: PythonRebuild
    timeouts: dict


def _prepare(entry: dict, scan: dict, ctx: BuildContext,
             tee: LogTee) -> tuple[dict, Path | None]:
    """Fetch the scanned commit, verify it is what was reviewed, hand it to the sandbox."""
    pkg = entry["name"]
    work = cfg.BUILD_DIR / pkg
    src = make_work(work)
    try:
        run_logged(["git", "clone", "--quiet", git_url(pkg, entry.get("source"), ctx.meta),
                    str(src)], tee)
        run_logged(["git", "checkout", "--quiet", scan["commit"]], tee, cwd=src)
    except subprocess.CalledProcessError:
        return hold("fetch_error", "recipe fetch/checkout failed"), None
    if recipe_sha256(src) != scan.get("recipe_sha256"):
        return hold("hash_mismatch", "recipe content differs from what was scanned"), None
    if pkg in ctx.python.stale and not entry.get("source"):
        bump_pkgrel(src, pkg, ctx.python.now)  # after the hash check: it edits PKGBUILD
    hand_over(work)
    return {}, work


def sandbox_build_cmd(work: Path) -> list[str]:
    """The sandboxed makepkg invocation (deps are already installed, so no -s)."""
    return sandbox_cmd(work, ["makepkg", "--noconfirm", "--noprogressbar"])


def _sandboxed_build(work: Path, timeout: int, tee: LogTee) -> dict:
    """Keys and srcinfo in the sandbox, deps as root, then makepkg in the sandbox."""
    try:
        info = run_sandboxed(work, ["makepkg", "--printsrcinfo"], timeout=300)
    except subprocess.TimeoutExpired:
        return hold("build_error", "makepkg --printsrcinfo timed out")
    if info.returncode:
        tee.line(info.stderr)
        return hold("build_error", "makepkg --printsrcinfo failed")
    try:
        deps = srcinfo_deps(info.stdout)
    except ValueError as exc:
        return hold("bad_deps", str(exc)[:200])
    import_validpgpkeys(work, info.stdout, tee)
    added: list[str] = []
    try:
        added = install_deps(deps, tee)
        run_logged(sandbox_build_cmd(work), tee, timeout=timeout)
    except subprocess.TimeoutExpired:
        return hold("build_timeout", f"build exceeded {timeout}s")
    except subprocess.CalledProcessError:
        return hold("build_error", "dependency install or makepkg failed")
    finally:
        remove_deps(added, tee)
    return {}


def _make(entry: dict, scan: dict, ctx: BuildContext, tee: LogTee) -> tuple[dict, list | None]:
    """Prepare, build, filter and Trivy-check one package."""
    problem, work = _prepare(entry, scan, ctx, tee)
    if work is None:
        return problem, None
    pkg = entry["name"]
    timeout = ctx.timeouts.get(pkgbase(pkg, entry.get("source"), ctx.meta), cfg.BUILD_TIMEOUT)
    problem = _sandboxed_build(work, timeout, tee)
    if problem:
        return problem, None
    artifacts = select_artifacts(built_artifacts(work / "src"), ctx.wanted)
    if not artifacts:
        return hold("no_artifacts", "build produced no allowlisted packages"), None
    clean = [trivy_clean(a, tee) for a in artifacts]  # scan (and log) every artifact
    if not all(clean):
        return hold("trivy", f"Trivy found {cfg.FAIL_SEVS} CVE or embedded secret"), None
    return {}, stage_artifacts(pkg, artifacts)


def attempt_build(entry: dict, scan: dict, ctx: BuildContext) -> tuple[dict, dict | None]:
    """Build one package; returns (event, staged record or None)."""
    pkg = entry["name"]
    tee = LogTee(log_path(pkg, "build"))
    start = time.monotonic()
    try:
        problem, records = _make(entry, scan, ctx, tee)
    # One package must never abort the batch: everything else still publishes.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        log.exception("Unexpected error building %s", pkg)
        problem, records = hold("build_error", f"unexpected error: {exc}"[:200]), None
    finally:
        tee.close()
        shutil.rmtree(cfg.BUILD_DIR / pkg, ignore_errors=True)
    event = {"duration": round(time.monotonic() - start), "log": tee.url,
             "commit": scan["commit"]}
    if records is None:
        log.error("Build of %s held: %s", pkg, problem["summary"])
        return {**event, "result": "failed", **problem}, None
    event.update(result="staged", version=artifact_parts(records[0]["name"])[1])
    log.info("Staged for signing: %s (%d artifact(s))", pkg, len(records))
    return event, {"artifacts": records, "commit": scan["commit"]}


def skip_reason(entry: dict, commit: str, ctx: BuildContext) -> dict | None:
    """Event for a package that needn't build this run, or None to build it.

    Skipped when its scanned commit is already built, or when that commit
    already failed to build within the backoff window. ``track: latest``
    packages and python-stranded ones always rebuild.
    """
    pkg = entry["name"]
    if entry.get("track") == "latest" or pkg in ctx.python.stale:
        return None
    if ctx.built_commits.get(pkg) == commit:
        return {"result": "uptodate", "commit": commit}
    known = ctx.failures.get(pkg) or {}
    retry_at = known.get("ts", 0) + cfg.BUILD_FAILURE_RETRY_DAYS * 86400
    if known.get("commit") == commit and time.time() < retry_at:
        summary = (f"{known.get('reason', 'build')} at this commit; retry after "
                   f"{time.strftime('%Y-%m-%d', time.gmtime(retry_at))} or on a new commit")
        return {"result": "backoff", "commit": commit, **hold("build_failed", summary)}
    return None


def build_entry(entry: dict, ctx: BuildContext) -> tuple[dict, dict | None]:
    """Decide and run (or skip) one package's build."""
    scan = ctx.state.get(entry["name"]) or {}
    if scan.get("verdict") != "pass" or not scan.get("commit"):
        why = scan.get("summary") or "no passing scan verdict"
        return {"result": "held", **hold("scan", why, scan.get("risk", ""))}, None
    skipped = skip_reason(entry, scan["commit"], ctx)
    if skipped:
        return skipped, None
    return attempt_build(entry, scan, ctx)


def _context(packages: list[dict]) -> BuildContext:
    meta = load_meta(packages)
    timeouts: dict[str, int] = {}
    for entry in packages:
        key = pkgbase(entry["name"], entry.get("source"), meta)
        timeouts[key] = max(timeouts.get(key, 0),
                            int(entry.get("build_timeout") or cfg.BUILD_TIMEOUT))
    py_now = current_python()
    return BuildContext(
        state=load_state(), meta=meta,
        built_commits=read_json(cfg.repo_file("built-commits.json"), {}),
        failures=read_json(cfg.repo_file("build-failures.json"), {}),
        wanted={e["name"] for e in packages},
        python=PythonRebuild(now=py_now, stale=stale_python_packages(py_now)),
        timeouts=timeouts)


def run_build_phase() -> int:
    """Build all approved packages and write the staging manifest."""
    started = int(time.time())
    packages = load_approved()
    log.info("Build: %d approved packages", len(packages))
    ctx = _context(packages)
    cfg.staging_dir().mkdir(parents=True, exist_ok=True)
    give_to_pipeline(cfg.staging_dir())
    try:
        run(["pacman", "-Syu", "--noconfirm"])
    except subprocess.CalledProcessError as exc:
        log.warning("System refresh failed (continuing): %s", exc)
    events: dict[str, dict] = {}
    staged: dict[str, dict] = {}
    owners: dict[str, str] = {}
    for i, entry in enumerate(packages, 1):
        pkg = entry["name"]
        key = pkgbase(pkg, entry.get("source"), ctx.meta)
        if key in owners:  # split sibling: built (or held) together with its owner
            events[pkg] = {**events[owners[key]], "owner": owners[key]}
            continue
        owners[key] = pkg
        push_progress("build", pkg, i, len(packages))
        events[pkg], record = build_entry(entry, ctx)
        if record:
            staged[pkg] = record
    holds = {p: hold(e["reason"], e.get("summary", ""), e.get("risk", ""))
             for p, e in events.items() if e["result"] in ("held", "failed", "backoff")}
    write_json(cfg.manifest_path(), {
        "total": len(packages), "approved": sorted(ctx.wanted), "events": events,
        "entries": [{k: e.get(k) for k in ("name", "source", "note")} for e in packages],
        "staged": staged, "failed": holds, "build_started_at": started,
        "build_finished_at": int(time.time()),
        "skipped": sum(e["result"] == "uptodate" for e in events.values())})
    log.info("Build phase done: %d staged, %d up to date, %d held",
             len(staged), sum(e["result"] == "uptodate" for e in events.values()), len(holds))
    return 0
