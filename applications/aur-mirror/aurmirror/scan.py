"""Scan phase: resolve each package's recipe HEAD and Claude-review changes.

This is the only phase holding ANTHROPIC_API_KEY, and it never runs makepkg.
Verdicts persist in SCAN_STATE keyed by package name:
  commit, recipe_sha256, verdict (pass | fail | error), risk, summary,
  findings, kind, lane, partial, ts, last_pass_commit
``error`` means no verdict was reached (API or git trouble). It is retried
next run and never reused, and a transient error keeps a prior ``pass``.
"""
import logging
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import config as cfg
from .aur import git_url, pkgbase, refresh_meta
from .common import load_approved, read_json, write_json
from .metrics import push_progress
from .recipe import (classify_diff, clone, collect_recipe, git_head, recipe_sha256,
                     remote_head, route_scan)
from .review import Reviewer
from .status import log_path, write_text

log = logging.getLogger("aurmirror")


def load_state() -> dict:
    """The scan-state map {pkg: verdict record}."""
    return read_json(cfg.SCAN_STATE, {})


def _save_state(state: dict) -> None:
    try:
        write_json(cfg.SCAN_STATE, state)
    except OSError as exc:
        log.warning("incremental state save failed: %s", exc)


def error_state(prev: dict | None, summary: str) -> dict:
    """Record a failure that reached no verdict.

    A prior pass is kept (its commit stays buildable) with the error noted;
    otherwise the entry gets an empty commit so the next run retries it.
    """
    now = int(time.time())
    if prev and prev.get("verdict") == "pass":
        kept = dict(prev)
        kept.update(last_error=summary[:200], last_error_ts=now)
        return kept
    return {"commit": "", "recipe_sha256": "", "verdict": "error", "risk": "error",
            "summary": summary[:200], "ts": now,
            "last_pass_commit": (prev or {}).get("last_pass_commit", "")}


def reusable(prev: dict | None, head: str) -> bool:
    """Whether a stored verdict still applies: same commit and a real verdict."""
    return (bool(prev) and prev.get("commit") == head
            and prev.get("verdict") in ("pass", "fail") and prev.get("risk") != "error")


def diff_base(prev: dict | None) -> str:
    """Commit to diff against: the last one that passed, never a failed one."""
    if not prev:
        return ""
    if prev.get("last_pass_commit"):
        return prev["last_pass_commit"]
    return prev.get("commit", "") if prev.get("verdict") == "pass" else ""


@dataclass
class ScanContext:
    """Per-run state shared across packages."""

    state: dict
    meta: dict
    reviewer: Reviewer
    workdir: Path
    owners: dict = field(default_factory=dict)
    logs: dict = field(default_factory=dict)


def _review(pkg: str, recipe_dir: Path, base: str, ctx: ScanContext) -> tuple[dict, dict]:
    """Classify and review a cloned recipe; returns (verdict, scan details)."""
    head = git_head(recipe_dir)
    kind, diff_text = "new", None
    if base:
        try:
            kind, diff_text = classify_diff(recipe_dir, base, head)
        except (subprocess.CalledProcessError, OSError) as exc:
            log.warning("diff against %s failed for %s (escalating): %s",
                        base[:12], pkg, str(exc)[:120])
            kind = "substantive"
    recipe = collect_recipe(recipe_dir)
    lane = "escalated" if recipe.partial else route_scan(kind)
    if lane == "haiku":
        verdict = ctx.reviewer.quick(pkg, recipe)
    else:
        verdict = ctx.reviewer.escalated(pkg, recipe, diff_text)
    details = {"commit": head, "recipe_sha256": recipe_sha256(recipe_dir), "kind": kind,
               "lane": lane, "partial": recipe.partial, "omitted": recipe.omitted,
               "diff": diff_text or ""}
    return verdict, details


def scan_recipe(entry: dict, prev: dict | None, ctx: ScanContext) -> dict:
    """Clone the recipe at HEAD, review it, and return the new state record."""
    pkg = entry["name"]
    base = diff_base(prev)
    url = git_url(pkg, entry.get("source"), ctx.meta)
    recipe_dir = clone(url, ctx.workdir, pkg, shallow=not base)
    try:
        verdict, det = _review(pkg, recipe_dir, base, ctx)
    finally:
        shutil.rmtree(recipe_dir, ignore_errors=True)
    if verdict.get("transient"):
        log.warning("Scan: %s reached no verdict (will retry): %s", pkg, verdict["summary"])
        return error_state(prev, verdict["summary"])
    ok = bool(verdict.get("safe"))
    ctx.logs[pkg] = write_text(log_path(pkg, "scan"), _scan_log(pkg, verdict, det))
    return {"commit": det["commit"], "recipe_sha256": det["recipe_sha256"],
            "verdict": "pass" if ok else "fail", "risk": verdict.get("risk", ""),
            "summary": verdict.get("summary", ""), "findings": verdict.get("findings", [])[:10],
            "kind": det["kind"], "lane": det["lane"], "partial": det["partial"],
            "ts": int(time.time()), "last_pass_commit": det["commit"] if ok else base}


def _scan_log(pkg: str, verdict: dict, det: dict) -> str:
    lines = [f"package:  {pkg}", f"commit:   {det['commit']}",
             f"change:   {det['kind']}  (lane: {det['lane']})",
             f"verdict:  {'pass' if verdict.get('safe') else 'FAIL'}  risk={verdict.get('risk')}",
             f"summary:  {verdict.get('summary', '')}", ""]
    lines += [f"finding:  {f}" for f in verdict.get("findings", [])]
    lines += [f"omitted:  {o}" for o in det["omitted"]]
    if det["diff"]:
        lines += ["", "---- diff reviewed ----", det["diff"][:60000]]
    return "\n".join(lines) + "\n"


def scan_entry(entry: dict, ctx: ScanContext) -> str:
    """Process one allowlist entry; returns its outcome for the run counts."""
    pkg = entry["name"]
    prev = ctx.state.get(pkg)
    key = pkgbase(pkg, entry.get("source"), ctx.meta)
    owner = ctx.owners.get(key)
    if owner is not None and owner in ctx.state:
        ctx.state[pkg] = dict(ctx.state[owner])  # split sibling: same recipe
        return "sibling"
    ctx.owners[key] = pkg
    try:
        head = remote_head(git_url(pkg, entry.get("source"), ctx.meta))
    except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
        log.warning("ls-remote failed for %s: %s", pkg, str(exc)[:160])
        ctx.state[pkg] = error_state(prev, f"ls-remote failed: {exc}")
        return "error"
    if reusable(prev, head):
        return "reused"
    try:
        ctx.state[pkg] = scan_recipe(entry, prev, ctx)
    # One package must never abort the batch: record a retryable error instead.
    except Exception as exc:  # pylint: disable=broad-exception-caught
        log.error("Scan failed for %s: %s", pkg, str(exc)[:160])
        ctx.state[pkg] = error_state(prev, f"scan failed: {exc}")
        return "error"
    rec = ctx.state[pkg]
    log.info("Scan: %s @ %s [%s/%s] -> %s (%s)", pkg, rec.get("commit", "")[:12],
             rec.get("kind"), rec.get("lane"), rec["verdict"], rec.get("risk"))
    return "scanned" if rec["verdict"] != "error" else "error"


def run_scan_phase() -> int:
    """Scan every approved package; returns 1 only if state can't be persisted."""
    started = int(time.time())
    approved = load_approved()
    log.info("Scan: %d approved packages", len(approved))
    names = {e["name"] for e in approved}
    meta = refresh_meta(approved)
    state = {k: v for k, v in load_state().items() if k in names}
    counts: Counter = Counter()
    with tempfile.TemporaryDirectory() as tmp:
        ctx = ScanContext(state=state, meta=meta, reviewer=Reviewer(), workdir=Path(tmp))
        for i, entry in enumerate(approved, 1):
            push_progress("scan", entry["name"], i, len(approved))
            counts[scan_entry(entry, ctx)] += 1
            _save_state(state)
    if ctx.reviewer.tripped:
        log.error("Claude API unavailable for this run, scans deferred: %s", ctx.reviewer.tripped)
    try:
        write_json(cfg.SCAN_STATE, state)
        write_json(cfg.RUN_STATE, {"run_id": cfg.RUN_ID, "started_at": started,
                                   "scan_finished_at": int(time.time()),
                                   "scan_counts": dict(counts), "scan_logs": ctx.logs,
                                   "api_breaker": ctx.reviewer.tripped})
    except OSError as exc:
        log.error("FATAL: could not write scan state: %s", exc)
        return 1
    passes = sum(v.get("verdict") == "pass" for v in state.values())
    log.info("Scan phase done: %s; %d pass, %d not passing",
             dict(counts), passes, len(state) - passes)
    return 0
