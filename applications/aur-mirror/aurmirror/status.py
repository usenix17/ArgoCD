"""Public status files for the mirror website, written under STATUS_DIR.

Layout (served read-only at https://aur.starnix.net/status/):
  live.json                     current phase/package, updated by every phase
  logs/<run_id>/<pkg>.<kind>.log  per-package scan and build logs
  packages.json, runs.json      written by the sign phase at the end of a run
  aur-mirror.asc                the repo's public signing key

The build container runs untrusted PKGBUILD code and can write here, so
nothing in this directory is trusted: nginx serves it only as JSON or plain
text and the page renders it with textContent. The signer rewrites the
summary files at the end of every run.
"""
import logging
import shutil
import subprocess
import re
import tarfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import config as cfg
from .common import read_json, write_json

log = logging.getLogger("aurmirror")

BUILT = ("published", "unchanged", "failed")


def _days(n: int) -> int:
    return n * 86400


def run_log_dir() -> Path:
    """Directory holding this run's logs."""
    return cfg.STATUS_DIR / "logs" / cfg.RUN_ID


def log_path(pkg: str, kind: str) -> Path:
    """Log file for one package in this run (kind is 'scan' or 'build')."""
    return run_log_dir() / f"{pkg}.{kind}.log"


def log_url(path: Path) -> str:
    """Site URL for a file under STATUS_DIR."""
    return "/status/" + path.relative_to(cfg.STATUS_DIR).as_posix()


def write_text(path: Path, text: str) -> str | None:
    """Best-effort write; returns the site URL, or None if the volume is unavailable."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        log.debug("status write failed for %s: %s", path, exc)
        return None
    return log_url(path)


def write_live(phase: str, package: str | None, current: int, total: int) -> None:
    """Update live.json; never raises (status must not perturb a build)."""
    path = cfg.STATUS_DIR / "live.json"
    now = int(time.time())
    prev = read_json(path, {})
    started = prev.get("started_at") if prev.get("run_id") == cfg.RUN_ID else now
    data = {"run_id": cfg.RUN_ID, "phase": phase, "package": package,
            "current": current, "total": total,
            "started_at": started or now, "updated_at": now}
    try:
        write_json(path, data)
    except OSError as exc:
        log.debug("live.json write failed: %s", exc)


def read_repo_db(db: Path) -> dict[str, dict]:
    """Parse the repo database into {pkgname: {version, base, builddate, ...}}.

    All or nothing: a read error returns {} rather than a partial map, because
    callers delete files the database doesn't reference.
    """
    out: dict[str, dict] = {}
    if not db.exists():
        return out
    try:
        with tarfile.open(db, "r:*") as tar:
            for member in tar.getmembers():
                if not member.name.endswith("/desc"):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                fields = _parse_desc(handle.read().decode("utf-8", errors="replace"))
                if "NAME" in fields:
                    out[fields["NAME"]] = {
                        "version": fields.get("VERSION", ""),
                        "base": fields.get("BASE", fields["NAME"]),
                        "builddate": int(fields.get("BUILDDATE", "0") or 0),
                        "size": int(fields.get("CSIZE", "0") or 0),
                        "filename": fields.get("FILENAME", ""),
                        "desc": fields.get("DESC", ""),
                    }
    except (OSError, tarfile.TarError) as exc:
        log.warning("Could not read repo db %s: %s", db, exc)
        return {}
    return out


def _parse_desc(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%"):
            key = line.strip("%")
        elif key and line:
            fields.setdefault(key, line)
    return fields


def vercmp(left: str, right: str) -> int:
    """Compare pacman versions with vercmp(8): <0, 0 or >0."""
    try:
        res = subprocess.run(["vercmp", left, right], capture_output=True,
                             text=True, check=True)
        return int(res.stdout.strip())
    except (OSError, ValueError, subprocess.CalledProcessError):
        return (left > right) - (left < right)


_GITHUB = re.compile(r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$")


def recipe_url(entry: dict, pkgbase: str, commit: str | None) -> str | None:
    """Web link to a recipe's PKGBUILD, at ``commit`` when known.

    AUR recipes link to the AUR's cgit view of the pkgbase; first-party
    recipes link to GitHub. Other git hosts get no link.
    """
    source = entry.get("source")
    if source:
        match = _GITHUB.match(source)
        if not match:
            return None
        return f"https://github.com/{match.group(1)}/blob/{commit or 'HEAD'}/PKGBUILD"
    query = urllib.parse.urlencode({"h": pkgbase, **({"id": commit} if commit else {})})
    return f"https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?{query}"


@dataclass
class RepoView:
    """The published repo: parsed database plus the commit each package was built from."""

    db: dict[str, dict]
    built: dict[str, str] = field(default_factory=dict)


@dataclass
class StatusInputs:
    """Everything the sign phase knows at the end of a run."""

    approved: list[dict]
    repo: RepoView
    meta: dict[str, dict]
    state: dict[str, dict]
    events: dict[str, dict]
    prev: dict[str, dict] = field(default_factory=dict)
    now: int = field(default_factory=lambda: int(time.time()))


def _existing_log(url: str | None) -> str | None:
    """Drop links to logs that retention has already deleted."""
    if not url or not url.startswith("/status/"):
        return None
    return url if (cfg.STATUS_DIR / url[len("/status/"):]).exists() else None


HOLD_RESULTS = ("held", "failed", "backoff")


def hold_of(event: dict) -> dict | None:
    """The hold record for a package's run event, or None if it isn't held."""
    if event.get("result") not in HOLD_RESULTS:
        return None
    return {k: event.get(k, "") for k in ("reason", "risk", "summary")}


def _flag_time(value) -> int | None:
    """AUR out-of-date flag time (epoch seconds), or None."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _row_commit(name: str, scan: dict, hold: dict | None, repo: RepoView) -> str | None:
    """Commit a row's PKGBUILD link points at.

    Held: the commit that was reviewed or failed. Otherwise what is published;
    split siblings fall back to the scan commit they share with their owner.
    """
    if hold:
        return scan.get("commit") or None
    return repo.built.get(name) or scan.get("commit") or None


def _streak(prev: dict, held: bool, now: int) -> tuple[int, int | None]:
    if not held:
        return 0, None
    return prev.get("streak", 0) + 1, prev.get("failing_since") or now


def package_entry(entry: dict, inp: StatusInputs) -> dict:
    """One package's row for packages.json."""
    name = entry["name"]
    prev = inp.prev.get(name, {})
    pub = inp.repo.db.get(name, {})
    meta = inp.meta.get(name, {})
    scan = inp.state.get(name, {})
    event = inp.events.get(name, {})
    hold = hold_of(event)
    streak, since = _streak(prev, hold is not None, inp.now)
    last_build = prev.get("last_build")
    if event.get("result") in BUILT:
        last_build = {k: event.get(k) for k in ("result", "duration", "log", "version")}
        last_build.update(ts=inp.now, run=cfg.RUN_ID)
    upstream = meta.get("version", "")
    version = pub.get("version", "")
    pkgbase = meta.get("pkgbase") or pub.get("base") or name
    return {
        "name": name,
        "pkgbase": pkgbase,
        "pkgbuild_url": recipe_url(entry, pkgbase, _row_commit(name, scan, hold, inp.repo)),
        "first_party": bool(entry.get("source")),
        "description": meta.get("description") or pub.get("desc", ""),
        "url": meta.get("url", ""),
        "note": entry.get("note", ""),
        "version": version,
        "upstream_version": upstream,
        "behind": bool(version and upstream and vercmp(version, upstream) < 0),
        "out_of_date": bool(meta.get("out_of_date")),
        # Older meta.json files stored a bare True: no date to show for those.
        "flagged_since": _flag_time(meta.get("out_of_date")),
        "builddate": pub.get("builddate") or None,
        "size": pub.get("size") or None,
        "status": "held" if hold else ("ok" if pub else "pending"),
        "hold": hold,
        "streak": streak,
        "failing_since": since,
        "scan": {k: scan.get(k) for k in ("verdict", "risk", "kind", "ts", "summary")},
        "last_build": last_build,
        "log": _existing_log(event.get("log") or prev.get("log")),
    }


def build_packages_doc(inp: StatusInputs, run: dict) -> dict:
    """The full packages.json document."""
    rows = [package_entry(e, inp) for e in sorted(inp.approved, key=lambda e: e["name"])]
    return {
        "generated_at": inp.now,
        "repo": {"name": cfg.REPO_NAME, "server": cfg.PUBLIC_URL,
                 "key_id": cfg.GPG_KEY_ID, "key_url": "/status/aur-mirror.asc"},
        "run": run,
        "counts": {
            "total": len(rows),
            "ok": sum(r["status"] == "ok" for r in rows),
            "held": sum(r["status"] == "held" for r in rows),
            "pending": sum(r["status"] == "pending" for r in rows),
            "behind": sum(r["behind"] for r in rows),
            "flagged": sum(r["out_of_date"] for r in rows),
        },
        "packages": rows,
    }


def update_runs(prev_doc: dict, run: dict, now: int) -> dict:
    """Append this run to runs.json and drop runs past the retention window."""
    cutoff = now - _days(cfg.LOG_RETENTION_DAYS)
    runs = [r for r in prev_doc.get("runs", [])
            if r.get("started_at", 0) >= cutoff and r.get("id") != run["id"]]
    runs.append(run)
    runs.sort(key=lambda r: r.get("started_at", 0), reverse=True)
    return {"generated_at": now, "runs": runs}


def cleanup_logs(now: int) -> int:
    """Delete per-run log directories older than the retention window."""
    root = cfg.STATUS_DIR / "logs"
    cutoff = now - _days(cfg.LOG_RETENTION_DAYS)
    removed = 0
    if not root.is_dir():
        return removed
    for run_dir in root.iterdir():
        try:
            if run_dir.is_dir() and run_dir.stat().st_mtime < cutoff:
                shutil.rmtree(run_dir)
                removed += 1
        except OSError as exc:
            log.warning("log cleanup failed for %s: %s", run_dir, exc)
    return removed
