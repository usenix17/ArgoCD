"""Small helpers shared by every phase."""
import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path

import yaml

from . import config as cfg

log = logging.getLogger("aurmirror")


def setup_logging() -> None:
    """Configure the root logger once for a phase run."""
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, logging it first; raises CalledProcessError on failure."""
    log.info("+ %s", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, check=True, **kwargs)


def read_json(path: Path, default):
    """Load JSON from ``path``, returning ``default`` if missing or corrupt."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def give_to_pipeline(path: Path) -> None:
    """Hand a file the root build orchestrator wrote to the uid the other phases use.

    The signer (uid 1000) rewrites status files, signs in staging and deletes
    old log dirs, so nothing it later touches may stay root-owned.
    """
    if os.geteuid() == 0:
        try:
            os.chown(path, cfg.SIGNER_UID, cfg.SIGNER_UID, follow_symlinks=False)
        except OSError as exc:
            log.warning("Could not chown %s: %s", path, exc)


def write_json(path: Path, data) -> None:
    """Write JSON atomically (tmp file + rename), so readers never see a torn file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    give_to_pipeline(tmp)
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    """Hex SHA256 of a file, read in 1 MiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hold(reason: str, summary: str, risk: str = "") -> dict:
    """Structured hold record carried into the manifest, metrics and status."""
    return {"reason": reason, "risk": risk, "summary": summary}


def load_approved() -> list[dict]:
    """Approved packages from the bare allowlist YAML. Raises on read error."""
    with cfg.ALLOWLIST.open(encoding="utf-8") as fh:
        config = yaml.safe_load(fh)
    return [p for p in config.get("packages", []) if p.get("approved") is True]


def artifact_parts(filename: str) -> tuple[str, str]:
    """Split ``name-pkgver-pkgrel-arch.pkg.tar.zst`` into (name, 'pkgver-pkgrel')."""
    name, pkgver, pkgrel, _ = filename.rsplit("-", 3)
    return name, f"{pkgver}-{pkgrel}"
