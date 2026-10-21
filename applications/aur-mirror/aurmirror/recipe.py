"""Recipe git operations, change classification, hashing and collection."""
import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .common import run

# Per-file and total character caps for what the reviewer is shown.
FILE_CAP = 16384
TOTAL_CAP = 131072

_RECIPE_VERSION_FILES = {"PKGBUILD", ".SRCINFO"}
_VERSION_KEYS = {"pkgver", "pkgrel", "epoch", "_pkgver", "_commit", "_gitcommit"}
_CKSUM_KEY = re.compile(r"^(sha\d+sums|md5sums|b2sums|cksums)(_[A-Za-z0-9]+)?(\(\))?$")
_CKSUM_VAL = re.compile(r"^['\"]?(?:[0-9a-fA-F]{32,128}|SKIP)['\"]?\)?$")


def _git_out(args: list[str], cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, check=True).stdout


def git_head(repo: Path) -> str:
    """Commit SHA checked out in ``repo``."""
    return _git_out(["rev-parse", "HEAD"], repo).strip()


def remote_head(url: str) -> str:
    """Resolve a remote's HEAD with ``git ls-remote`` (no clone)."""
    res = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True,
                         text=True, check=True, timeout=30)
    out = res.stdout.split()
    if not out:
        raise RuntimeError("ls-remote returned no HEAD")
    return out[0]


def clone(url: str, dest: Path, name: str, shallow: bool) -> Path:
    """Clone ``url`` into ``dest/name``; shallow unless history is needed for a diff."""
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--quiet"] + (["--depth", "1"] if shallow else []) + [url, name]
    run(cmd, cwd=dest)
    return dest / name


def classify_diff(repo: Path, base: str, head: str) -> tuple[str, str]:
    """Return (kind, unified diff) where kind is 'version' or 'substantive'.

    Biased to 'substantive': anything not positively recognized as a pure
    version or checksum bump gets the escalated review. A touched file outside
    PKGBUILD/.SRCINFO is always substantive, and so is a source= URL change.
    """
    diff = _git_out(["diff", "--no-color", f"{base}..{head}"], repo)
    changed = _git_out(["diff", "--name-only", f"{base}..{head}"], repo).split()
    if any(Path(f).name not in _RECIPE_VERSION_FILES for f in changed):
        return "substantive", diff
    for raw in _git_out(["diff", "--no-color", "-U0", f"{base}..{head}"], repo).splitlines():
        if raw[:3] in ("+++", "---") or raw.startswith("@@") or raw[:1] not in "+-":
            continue
        line = raw[1:].strip()
        if not line or _CKSUM_VAL.match(line):
            continue
        key = line.split("=", 1)[0].strip() if "=" in line else line.split(None, 1)[0]
        if key in _VERSION_KEYS or _CKSUM_KEY.match(key):
            continue
        return "substantive", diff
    return "version", diff


def route_scan(kind: str) -> str:
    """Scan lane for a change kind: version bumps go to Haiku, everything else escalates."""
    return "haiku" if kind == "version" else "escalated"


def recipe_sha256(recipe_dir: Path) -> str:
    """Deterministic hash over every committed recipe file (excluding .git).

    The scan phase records it; the build phase recomputes it on the checked-out
    commit and refuses to build on mismatch, so the reviewed bytes are the
    built bytes.
    """
    digest = hashlib.sha256()
    for path in sorted(recipe_dir.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        digest.update(path.relative_to(recipe_dir).as_posix().encode())
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


@dataclass
class RecipeText:
    """Recipe content for the reviewer, plus whether anything was left out."""

    text: str
    partial: bool
    omitted: list[str]


def collect_recipe(recipe_dir: Path) -> RecipeText:
    """Concatenate recipe files for review, recording anything truncated or skipped.

    A file is truncated past FILE_CAP characters, binary files (NUL in the first
    4 KB) are skipped, and collection stops at TOTAL_CAP. Any of those makes the
    result ``partial`` so the caller can force the escalated lane.
    """
    parts: list[str] = []
    omitted: list[str] = []
    total = 0
    for path in sorted(recipe_dir.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(recipe_dir).as_posix()
        if total >= TOTAL_CAP:
            omitted.append(f"{rel} (total size cap)")
            continue
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            omitted.append(f"{rel} (binary)")
            continue
        text = raw.decode("utf-8", errors="replace")
        if len(text) > FILE_CAP:
            omitted.append(f"{rel} (truncated at {FILE_CAP} chars)")
            text = text[:FILE_CAP]
        parts.append(f"--- {rel} ---\n{text}")
        total += len(text)
    return RecipeText("\n\n".join(parts), bool(omitted), omitted)
