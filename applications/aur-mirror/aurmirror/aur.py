"""AUR RPC metadata: pkgbase resolution plus upstream version info.

AUR git repos are keyed by pkgbase, not pkgname, so a split child such as
freeipa-client must be fetched from the ``freeipa`` repo. The scan phase
resolves every allowlisted name in a few batched RPC calls and saves the
result to ``meta.json`` on the state volume, so all three phases agree.
"""
import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from . import config as cfg
from .common import read_json, write_json

log = logging.getLogger("aurmirror")

AUR_URL = "https://aur.archlinux.org"
RPC_BATCH = 100


def fetch_info(names: list[str]) -> dict[str, dict]:
    """Fetch AUR info for ``names`` in batches; names the RPC can't resolve are omitted."""
    out: dict[str, dict] = {}
    for start in range(0, len(names), RPC_BATCH):
        batch = names[start:start + RPC_BATCH]
        query = urllib.parse.urlencode([("arg[]", n) for n in batch])
        try:
            with urllib.request.urlopen(f"{AUR_URL}/rpc/v5/info?{query}", timeout=30) as resp:
                results = json.load(resp).get("results", [])
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("AUR RPC batch failed (%d names): %s", len(batch), str(exc)[:160])
            continue
        for res in results:
            out[res["Name"]] = {
                "pkgbase": res.get("PackageBase") or res["Name"],
                "version": res.get("Version", ""),
                "description": res.get("Description") or "",
                "url": res.get("URL") or "",
                # Epoch seconds when an AUR user flagged it out of date, else None.
                "out_of_date": res.get("OutOfDate") or None,
                "last_modified": res.get("LastModified") or 0,
            }
    return out


def refresh_meta(approved: list[dict]) -> dict[str, dict]:
    """Resolve metadata for every AUR entry and persist it (scan phase).

    A name the RPC fails on keeps its previously saved metadata, so a
    transient RPC outage can't flip a split child's pkgbase back to its own
    name between phases.
    """
    prev = read_json(cfg.AUR_META, {})
    names = [e["name"] for e in approved if not e.get("source")]
    fresh = fetch_info(names)
    meta = {n: fresh.get(n) or prev.get(n) for n in names if fresh.get(n) or prev.get(n)}
    write_json(cfg.AUR_META, meta)
    log.info("AUR metadata: %d/%d resolved this run", len(fresh), len(names))
    return meta


def load_meta(approved: list[dict]) -> dict[str, dict]:
    """Metadata saved by the scan phase, fetched live if the file is missing."""
    meta = read_json(cfg.AUR_META, {})
    if not meta:
        meta = fetch_info([e["name"] for e in approved if not e.get("source")])
    return meta


def pkgbase(name: str, source: str | None, meta: dict[str, dict]) -> str:
    """Work key for a package: its pkgbase, or its own name if first-party."""
    if source:
        return name
    return (meta.get(name) or {}).get("pkgbase") or name


def git_url(name: str, source: str | None, meta: dict[str, dict]) -> str:
    """Recipe repo URL: the first-party source, else the AUR pkgbase repo."""
    return source or f"{AUR_URL}/{pkgbase(name, None, meta)}.git"
