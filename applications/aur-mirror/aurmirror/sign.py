"""Sign phase: verify, sign and publish staged artifacts, then write status.

This is the only phase holding the GPG key and the only writer of REPO_DIR,
and it never runs PKGBUILD code. It trusts the build manifest, not the
staging directory: an artifact is signed only if its bytes still hash to
the value the build phase recorded after Trivy.
"""
import logging
import shutil
import subprocess
import time
from pathlib import Path

from . import config as cfg
from .aur import load_meta
from .common import artifact_parts, hold, read_json, run, sha256_file, write_json
from .metrics import push_metrics, push_progress
from .scan import load_state
from .status import (StatusInputs, build_packages_doc, cleanup_logs, read_repo_db,
                     update_runs, vercmp, write_text)

log = logging.getLogger("aurmirror")


def _db() -> Path:
    return cfg.repo_file("db.tar.gz")


def classify_artifacts(records: list[dict], published: dict[str, dict]) -> dict[str, list]:
    """Sort artifacts into newer / same / older than the published version.

    'older' happens when an overlapping run built from an earlier commit; it
    must never replace the newer published build.
    """
    out: dict[str, list] = {"newer": [], "same": [], "older": []}
    for rec in records:
        name, version = artifact_parts(rec["name"])
        current = (published.get(name) or {}).get("version")
        cmp = vercmp(version, current) if current else 1
        out["newer" if cmp > 0 else "same" if cmp == 0 else "older"].append(rec)
    return out


def _verified(stage: Path, rec: dict) -> Path:
    src = stage / rec["name"]
    if not src.exists():
        raise OSError(f"staged artifact missing: {rec['name']}")
    actual = sha256_file(src)
    if actual != rec["sha256"]:
        raise OSError(f"staged artifact {rec['name']} hash mismatch (manifest "
                      f"{rec['sha256'][:12]}, disk {actual[:12]}) -- refusing to sign")
    return src


def publish(pkg: str, records: list[dict]) -> None:
    """Verify, sign in staging, move into the repo, then repo-add (rolled back on failure)."""
    stage = cfg.staging_dir() / pkg
    signed = []
    for rec in records:
        src = _verified(stage, rec)
        run(["gpg", "--batch", "--yes", "--local-user", cfg.GPG_KEY_ID, "--detach-sign", str(src)])
        signed.append(src)
    moved: list[Path] = []
    try:
        for src in signed:
            for path in (src, src.with_name(src.name + ".sig")):
                # shutil.move, not rename: staging is an emptyDir and the repo is NFS.
                shutil.move(str(path), str(cfg.REPO_DIR / path.name))
                moved.append(cfg.REPO_DIR / path.name)
        run(["repo-add", "-R", "--sign", "--key", cfg.GPG_KEY_ID, str(_db()),
             *[str(cfg.REPO_DIR / s.name) for s in signed]])
    except (subprocess.CalledProcessError, OSError):
        for path in moved:
            path.unlink(missing_ok=True)
        raise


def sign_package(pkg: str, info: dict, published: dict[str, dict]) -> dict:
    """Publish one staged package; returns its updated event fields."""
    groups = classify_artifacts(info.get("artifacts", []), published)
    for rec in groups["same"] + groups["older"]:
        (cfg.staging_dir() / pkg / rec["name"]).unlink(missing_ok=True)
    if groups["older"] and not groups["newer"]:
        log.warning("Not publishing %s: an overlapping run already published newer", pkg)
        return {"result": "stale"}
    if not groups["newer"]:
        log.info("%s: rebuilt version is already published", pkg)
        return {"result": "unchanged"}
    try:
        publish(pkg, groups["newer"])
    except (subprocess.CalledProcessError, OSError) as exc:
        log.error("Publish FAILED for %s: %s", pkg, exc)
        return {"result": "failed", **hold("publish_error", str(exc)[:200])}
    log.info("Published: %s", pkg)
    return {"result": "published"}


def prune_repo(approved: set[str], published: dict[str, dict]) -> None:
    """Remove packages no longer allowlisted (-debug kept iff its base is)."""
    stale = sorted(n for n in published if n.removesuffix("-debug") not in approved)
    if stale:
        log.info("Pruning %d stale package(s): %s", len(stale), ", ".join(stale))
        run(["repo-remove", "-R", "--sign", "--key", cfg.GPG_KEY_ID, str(_db()), *stale])


def sweep_unreferenced(published: dict[str, dict]) -> int:
    """Delete package files the database no longer references (old versions)."""
    keep = {p["filename"] for p in published.values() if p.get("filename")}
    if not keep:
        return 0
    removed = 0
    for path in cfg.REPO_DIR.glob("*.pkg.tar.zst*"):
        base = path.name.removesuffix(".sig")
        if base.endswith(".pkg.tar.zst") and base not in keep:
            path.unlink(missing_ok=True)
            removed += 1
    return removed


def export_key() -> None:
    """Publish the repo's public signing key for clients to import."""
    try:
        res = subprocess.run(["gpg", "--batch", "--armor", "--export", cfg.GPG_KEY_ID],
                             capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        log.warning("Could not export public key: %s", exc)
        return
    if res.stdout.strip():
        write_text(cfg.STATUS_DIR / "aur-mirror.asc", res.stdout)


def update_failures(events: dict[str, dict], now: int) -> dict:
    """Persist build failures so the next run backs off the same commit."""
    failures = read_json(cfg.repo_file("build-failures.json"), {})
    for pkg, event in events.items():
        if event.get("owner"):
            continue
        if event["result"] == "failed" and event.get("reason") in (
                "build_error", "build_timeout", "trivy", "no_artifacts"):
            failures[pkg] = {"commit": event.get("commit"), "reason": event["reason"], "ts": now}
        elif event["result"] in ("published", "unchanged", "uptodate"):
            failures.pop(pkg, None)
    return {p: f for p, f in failures.items() if p in events}


RESULTS = ("published", "unchanged", "stale", "failed", "held", "backoff", "uptodate")
EVENT_KEYS = ("result", "reason", "summary", "duration", "log", "version", "owner")


def _this_run_state() -> dict:
    """The scan phase's record for this run, or {} if it belongs to another run."""
    run_state = read_json(cfg.RUN_STATE, {})
    return run_state if run_state.get("run_id") == cfg.RUN_ID else {}


def run_document(manifest: dict, events: dict, run_state: dict, now: int) -> dict:
    """This run's entry for runs.json; quiet packages (up to date, still held) are omitted."""
    scanned = run_state.get("scan_logs") or {}
    rows = [{"name": p, **{k: e.get(k) for k in EVENT_KEYS}}
            for p, e in sorted(events.items())
            if e["result"] not in ("uptodate", "held") or p in scanned]
    return {
        "id": cfg.RUN_ID, "finished_at": now,
        "started_at": run_state.get("started_at") or manifest.get("build_started_at", now),
        "scan": run_state.get("scan_counts", {}),
        "api_breaker": run_state.get("api_breaker", ""),
        "counts": {r: sum(e["result"] == r for e in events.values()) for r in RESULTS},
        "events": rows,
    }


def write_status(manifest: dict, events: dict) -> None:
    """Write packages.json and runs.json for the site, and trim old logs."""
    now = int(time.time())
    entries = manifest.get("entries") or [{"name": n} for n in manifest["approved"]]
    run_state = _this_run_state()
    for pkg, url in (run_state.get("scan_logs") or {}).items():
        if url and pkg in events and not events[pkg].get("log"):
            events[pkg]["log"] = url
    run_doc = run_document(manifest, events, run_state, now)
    prev_doc = read_json(cfg.STATUS_DIR / "packages.json", {})
    inputs = StatusInputs(approved=entries, db=read_repo_db(_db()), meta=load_meta(entries),
                          state=load_state(), events=events,
                          prev={p["name"]: p for p in prev_doc.get("packages", [])}, now=now)
    try:
        write_json(cfg.STATUS_DIR / "packages.json", build_packages_doc(inputs, run_doc))
        runs = update_runs(read_json(cfg.STATUS_DIR / "runs.json", {}), run_doc, now)
        write_json(cfg.STATUS_DIR / "runs.json", runs)
        log.info("Status written; %d old log dir(s) removed", cleanup_logs(now))
    except OSError as exc:
        log.warning("Could not write status files: %s", exc)


def run_sign_phase() -> int:
    """Publish staged packages, prune, persist markers, write status and metrics."""
    manifest = read_json(cfg.manifest_path(), None)
    if manifest is None:
        log.error("No staging manifest at %s -- build phase produced nothing",
                  cfg.manifest_path())
        return 1
    events: dict[str, dict] = manifest.get("events", {})
    holds: dict[str, dict] = dict(manifest.get("failed", {}))
    built = read_json(cfg.repo_file("built-commits.json"), {})
    published = read_repo_db(_db())
    for i, (pkg, info) in enumerate(manifest["staged"].items(), 1):
        push_progress("sign", pkg, i, len(manifest["staged"]))
        events[pkg].update(sign_package(pkg, info, published))
        if events[pkg]["result"] in ("published", "unchanged"):
            built[pkg] = info.get("commit")
        elif events[pkg]["result"] == "failed":
            holds[pkg] = hold(events[pkg]["reason"], events[pkg]["summary"])
    for pkg, event in events.items():
        if event.get("owner"):
            events[pkg] = {**events[event["owner"]], "owner": event["owner"]}
            if event["owner"] in holds:
                holds[pkg] = holds[event["owner"]]
    _finish_repo(set(manifest["approved"]), built, events)
    write_status(manifest, events)
    push_metrics(total=manifest["total"], skipped=manifest.get("skipped", 0), held=holds)
    push_progress("idle", None, 0, 0)
    shutil.rmtree(cfg.staging_dir(), ignore_errors=True)
    if holds:
        log.warning("Held %d package(s): %s", len(holds), ", ".join(sorted(holds)))
    return 0


def _finish_repo(approved: set[str], built: dict, events: dict) -> None:
    """Prune, sweep old files, and persist the built-commit and failure markers."""
    try:
        prune_repo(approved, read_repo_db(_db()))
        log.info("Removed %d unreferenced package file(s)",
                 sweep_unreferenced(read_repo_db(_db())))
    except (subprocess.CalledProcessError, OSError) as exc:
        log.error("Repo prune failed: %s", exc)
    now = int(time.time())
    try:
        write_json(cfg.repo_file("built-commits.json"),
                   {k: v for k, v in built.items() if k in approved})
        write_json(cfg.repo_file("build-failures.json"), update_failures(events, now))
    except OSError as exc:
        log.warning("Could not write repo markers: %s", exc)
    export_key()
