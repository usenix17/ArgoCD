"""Runtime configuration, read once from the environment.

Other modules read these as attributes (``cfg.REPO_DIR``) rather than
importing the names, so tests can monkeypatch them.
"""
import os
import socket
from pathlib import Path

# Published pacman repo (NFS). Only the sign phase mounts it read-write.
REPO_DIR = Path(os.environ["REPO_DIR"])
REPO_NAME = os.environ.get("REPO_NAME", "aur-mirror")
# Per-pod scratch (emptyDir) shared by the build and sign containers.
BUILD_DIR = Path(os.environ.get("BUILD_DIR", "/build"))
ALLOWLIST = Path(os.environ.get("ALLOWLIST", "/config/allowlist.yaml"))
# Scan state (NFS). Written only by the scan phase.
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
SCAN_STATE = Path(os.environ.get("SCAN_STATE", str(STATE_DIR / "verdicts.json")))
AUR_META = STATE_DIR / "meta.json"
RUN_STATE = STATE_DIR / "run.json"
# Public status files (NFS), served read-only by the repo-server.
STATUS_DIR = Path(os.environ.get("STATUS_DIR", "/status"))

BUILD_PHASE = os.environ.get("BUILD_PHASE", "all")
# All three containers of one run share the pod name, so it identifies a run.
RUN_ID = os.environ.get("RUN_ID") or socket.gethostname()

GPG_KEY_ID = os.environ.get("GPG_KEY_ID", "")
FAIL_SEVS = os.environ.get("TRIVY_FAIL_SEVERITY", "HIGH,CRITICAL")
PUSHGATEWAY_URL = os.environ.get("PUSHGATEWAY_URL", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://aur.starnix.net")

# Per-package makepkg timeout in seconds (0 disables). An allowlist entry's
# `build_timeout:` overrides it; the largest value in a pkgbase group wins.
BUILD_TIMEOUT = int(os.environ.get("BUILD_TIMEOUT", "7200"))
# A failed build is not retried for the same commit until this many days pass.
BUILD_FAILURE_RETRY_DAYS = int(os.environ.get("BUILD_FAILURE_RETRY_DAYS", "7"))
# Keyservers tried in order for a recipe's validpgpkeys.
GPG_KEYSERVERS = [s.strip() for s in os.environ.get(
    "GPG_KEYSERVERS",
    "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org,"
    "hkps://keyserver.archlinux.org").split(",") if s.strip()]

# Scan phase only: never mounted where PKGBUILD code runs.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
SCAN_MODEL = os.environ.get("SCAN_MODEL", "claude-haiku-5-5")
ESCALATION_MODEL = os.environ.get("ESCALATION_MODEL", "claude-sonnet-5-5")
ESCALATION_PASSES = int(os.environ.get("ESCALATION_PASSES", "2"))

# Status files and build logs older than this are trimmed by the sign phase.
LOG_RETENTION_DAYS = int(os.environ.get("LOG_RETENTION_DAYS", "30"))
# Build logs stop growing past this size (the console copy is never capped).
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(5 * 1024 * 1024)))


def staging_dir() -> Path:
    """Directory where the build phase hands vetted artifacts to the signer."""
    return BUILD_DIR / ".staging"


def manifest_path() -> Path:
    """Build-phase manifest consumed by the sign phase."""
    return staging_dir() / "manifest.json"


def repo_file(suffix: str) -> Path:
    """A repo-level file such as ``db.tar.gz`` or ``built-commits.json``."""
    return REPO_DIR / f"{REPO_NAME}.{suffix}"
