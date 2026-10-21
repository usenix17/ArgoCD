"""Build phase: build each scanned commit, Trivy-check it, stage what passes.

No API key and no GPG key are present here. Per-package outcomes go into the
staging manifest as ``events`` (staged, failed, held, backoff, uptodate) and
``failed`` (holds), and the run always continues so the signer can publish
whatever passed.
"""
import logging
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import config as cfg
from .aur import load_meta, pkgbase
from .buildlog import LogTee, run_logged
from .common import artifact_parts, hold, load_approved, read_json, run, sha256_file, write_json
from .metrics import push_progress
from .pyrebuild import bump_pkgrel, current_python, stale_python_packages
from .recipe import recipe_sha256
from .scan import load_state
from .status import log_path

log = logging.getLogger("aurmirror")

# Failures that will repeat for the same commit; retried after the backoff window.
BACKOFF_REASONS = {"build_error", "build_timeout", "trivy", "no_artifacts"}


def import_validpgpkeys(pkg_subdir: Path, tee: LogTee) -> None:
    """Make a recipe's signing keys available so makepkg can verify sources.

    Imports recipe-shipped keys/pgp/*.asc first, then fetches each
    validpgpkeys fingerprint still missing from the keyservers in order.
    Non-fatal: makepkg still verifies signatures and fails if a key is absent.
    """
    for asc in sorted((pkg_subdir / "keys" / "pgp").glob("*.asc")):
        _gpg(["--import", str(asc)], tee)
    srcinfo = pkg_subdir / ".SRCINFO"
    if not srcinfo.exists():
        return
    lines = srcinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    fprs = [v.strip() for k, _, v in (ln.partition("=") for ln in lines)
            if k.strip() == "validpgpkeys" and v.strip()]
    for fpr in fprs:
        if _gpg(["--list-keys", fpr], None):
            continue
        if not any(_gpg(["--keyserver", ks, "--recv-keys", fpr], tee, ks)
                   for ks in cfg.GPG_KEYSERVERS):
            tee.line(f"WARNING: key {fpr} not found on any keyserver; build may fail")


def _gpg(args: list[str], tee: LogTee | None, server: str = "") -> bool:
    try:
        subprocess.run(["gpg", "--batch", *args], check=True, timeout=20,
                       capture_output=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    if tee is not None and server:
        tee.line(f"imported key {args[-1]} from {server}")
    return True


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
    recorded = []
    for artifact in artifacts:
        target = dest / artifact.name
        shutil.move(str(artifact), str(target))
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


def _fetch(entry: dict, commit: str, pkg_dir: Path, ctx: BuildContext, tee: LogTee) -> Path:
    """Fetch the recipe and check out the scanned commit."""
    pkg, source = entry["name"], entry.get("source")
    if source:
        run_logged(["git", "clone", "--quiet", source, pkg], tee, cwd=pkg_dir)
        subdir = pkg_dir / pkg
    else:
        base = pkgbase(pkg, None, ctx.meta)
        run_logged(["aur", "fetch", base], tee, cwd=pkg_dir)
        subdir = pkg_dir / base
    run_logged(["git", "checkout", "--quiet", commit], tee, cwd=subdir)
    return subdir


def _prepare(entry: dict, scan: dict, ctx: BuildContext,
             tee: LogTee) -> tuple[dict, Path | None]:
    """Fetch the scanned commit and verify it is exactly what was reviewed."""
    pkg = entry["name"]
    pkg_dir = cfg.BUILD_DIR / pkg
    pkg_dir.mkdir(parents=True, exist_ok=True)
    try:
        subdir = _fetch(entry, scan["commit"], pkg_dir, ctx, tee)
    except subprocess.CalledProcessError:
        return hold("fetch_error", "recipe fetch/checkout failed"), None
    if recipe_sha256(subdir) != scan.get("recipe_sha256"):
        return hold("hash_mismatch", "recipe content differs from what was scanned"), None
    if pkg in ctx.python.stale and not entry.get("source"):
        bump_pkgrel(subdir, pkg, ctx.python.now)  # after the hash check: it edits PKGBUILD
    import_validpgpkeys(subdir, tee)
    return {}, subdir


def _make(entry: dict, scan: dict, ctx: BuildContext, tee: LogTee) -> tuple[dict, list | None]:
    """Prepare, build, filter and Trivy-check one package."""
    problem, subdir = _prepare(entry, scan, ctx, tee)
    if subdir is None:
        return problem, None
    pkg = entry["name"]
    timeout = ctx.timeouts.get(pkgbase(pkg, entry.get("source"), ctx.meta), cfg.BUILD_TIMEOUT)
    try:
        run_logged(["makepkg", "-s", "--noconfirm", "--noprogressbar", "--needed"],
                   tee, cwd=subdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return hold("build_timeout", f"build exceeded {timeout}s"), None
    except subprocess.CalledProcessError:
        return hold("build_error", "makepkg build failed"), None
    artifacts = select_artifacts(sorted(subdir.glob("*.pkg.tar.zst")), ctx.wanted)
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
    try:
        run(["sudo", "pacman", "-Syu", "--noconfirm"])
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
