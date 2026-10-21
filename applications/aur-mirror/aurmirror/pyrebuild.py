"""Rebuild python packages stranded by a python minor-version bump.

A python 3.13 -> 3.14 bump moves site-packages without changing a package's
pkgver, so the normal "commit already built" skip would leave it broken. The
build phase detects these from the repo .files db and bumps pkgrel so the
rebuild outranks the original (pkgrel=4 -> 4.14, as Arch does).
"""
import logging
import re
import subprocess
import tempfile
from pathlib import Path

from . import config as cfg

log = logging.getLogger("aurmirror")


def current_python() -> str | None:
    """The build host's python minor version, e.g. '3.14'."""
    try:
        res = subprocess.run(
            ["python3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
            capture_output=True, text=True, check=True)
        return res.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def published_python_versions() -> dict[str, str]:
    """Map pkgname to the python minor its published build ships files for."""
    files_db = cfg.repo_file("files.tar.gz")
    out: dict[str, str] = {}
    if not files_db.exists():
        return out
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(["tar", "-xzf", str(files_db), "-C", tmp], check=True)
        except (OSError, subprocess.CalledProcessError):
            return out
        for files_path in Path(tmp).glob("*/files"):
            name, *rest = files_path.parent.name.rsplit("-", 2)
            if len(rest) != 2:
                continue
            match = re.search(r"usr/lib/python(\d+\.\d+)/",
                              files_path.read_text(encoding="utf-8", errors="replace"))
            if match:
                out[name] = match.group(1)
    return out


def stale_python_packages(py_now: str | None) -> set[str]:
    """Published packages built against a python other than the current one."""
    if not py_now:
        return set()
    return {p for p, v in published_python_versions().items() if v != py_now}


def bump_pkgrel(pkg_subdir: Path, pkg: str, py_now: str) -> None:
    """Append the python minor to pkgrel so the rebuild outranks the original."""
    pkgbuild = pkg_subdir / "PKGBUILD"
    try:
        text = pkgbuild.read_text(encoding="utf-8")
    except OSError:
        return
    match = re.search(r"(?m)^pkgrel=(\d+)", text)
    if not match:
        log.warning("Cannot bump pkgrel for %s (missing/non-integer pkgrel)", pkg)
        return
    new_rel = f"{match.group(1)}.{py_now.split('.')[-1]}"
    text = re.sub(r"(?m)^pkgrel=\d+(?:\.\d+)?", f"pkgrel={new_rel}", text, count=1)
    pkgbuild.write_text(text, encoding="utf-8")
    log.info("Bumped %s pkgrel -> %s (rebuilt for python %s)", pkg, new_rel, py_now)
