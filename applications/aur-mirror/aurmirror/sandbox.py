"""Per-package build sandbox and the trusted dependency install around it.

Untrusted recipe code (makepkg, gpg key import) only runs through
``sandbox_cmd``: a fresh user, mount and pid namespace as BUILD_UID that sees
the system read-only and nothing of the container but its own work dir (see
aur-sandbox). Dependencies are installed by root from signed repos before the
build and removed after it, so every build starts from the same base.
"""
import logging
import os
import re
import signal
import stat
import subprocess
from pathlib import Path

from . import config as cfg
from .buildlog import LogTee, run_logged

log = logging.getLogger("aurmirror")

# Inside the sandbox the work dir is /work; the recipe checkout is /work/src.
WORK_SUBDIRS = ("src", "gnupg", "home", "tmp")
DEP_KEYS = ("depends", "makedepends", "checkdepends")
_DEP_NAME = re.compile(r"[A-Za-z0-9@_+][A-Za-z0-9@._+-]*")
_DEP_VERSION = re.compile(r"[<>=].*$")


def sandbox_cmd(work: Path, cmd: list[str]) -> list[str]:
    """Wrap ``cmd`` to run as BUILD_UID inside a sandbox rooted at ``work``."""
    uid = str(cfg.BUILD_UID)
    return ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--init-groups", "--reset-env",
            "--", "unshare", "-U", "-r", "-m", "-p", "-i", "-u", "--fork", "--",
            str(cfg.SANDBOX), str(work), *cmd]


def run_sandboxed(work: Path, cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run ``cmd`` in the sandbox and capture its output.

    On timeout the whole process group is killed, which takes the sandbox's
    pid namespace down with it, and TimeoutExpired is raised.
    """
    with subprocess.Popen(sandbox_cmd(work, cmd), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, errors="replace",
                          start_new_session=True) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def make_work(work: Path) -> Path:
    """Create the work dir layout; returns the (not yet populated) src path."""
    for name in WORK_SUBDIRS[1:]:
        (work / name).mkdir(parents=True, exist_ok=True)
    (work / "gnupg").chmod(0o700)
    return work / WORK_SUBDIRS[0]


def hand_over(work: Path) -> None:
    """Give the populated work dir to BUILD_UID; nothing in it is trusted after this."""
    for top, dirs, files in os.walk(work):
        for name in (top, *(os.path.join(top, n) for n in dirs + files)):
            os.chown(name, cfg.BUILD_UID, cfg.BUILD_UID, follow_symlinks=False)


def srcinfo_deps(srcinfo: str) -> list[str]:
    """Build dependencies of the pkgbase section of ``makepkg --printsrcinfo`` output.

    Version constraints are dropped (makepkg re-checks them against what was
    installed). Raises ValueError on a name pacman could read as an option.
    """
    deps: list[str] = []
    for line in srcinfo.splitlines():
        key, sep, value = (part.strip() for part in line.partition("="))
        if key == "pkgname":
            break  # split-package sections: runtime metadata, not build deps
        if not sep or key.removesuffix(f"_{cfg.ARCH}") not in DEP_KEYS:
            continue
        name = _DEP_VERSION.sub("", value)
        if not _DEP_NAME.fullmatch(name):
            raise ValueError(f"unusable dependency {value!r}")
        if name not in deps:
            deps.append(name)
    return deps


def srcinfo_values(srcinfo: str, key: str) -> list[str]:
    """Every value of ``key`` in .SRCINFO text."""
    pairs = (line.partition("=") for line in srcinfo.splitlines())
    return [v.strip() for k, _, v in pairs if k.strip() == key and v.strip()]


def installed() -> set[str]:
    """Names of the packages installed in the build container."""
    out = subprocess.run(["pacman", "-Qq"], check=True, capture_output=True, text=True)
    return set(out.stdout.split())


def install_deps(deps: list[str], tee: LogTee) -> list[str]:
    """Install ``deps`` from the signed repos as root; returns what was added."""
    before = installed()
    if deps:
        run_logged(["pacman", "-S", "--needed", "--asdeps", "--noconfirm", "--", *deps], tee)
    return sorted(installed() - before)


def remove_deps(added: list[str], tee: LogTee) -> None:
    """Return the container to its base package set after a build."""
    if not added:
        return
    try:
        run_logged(["pacman", "-Rdd", "--noconfirm", "--", *added], tee)
    except subprocess.CalledProcessError:
        log.warning("Could not remove build deps: %s", " ".join(added))


def built_artifacts(src: Path) -> list[Path]:
    """Package files the build left in ``src``; anything but a regular file is refused.

    The build ran untrusted, so a "package" could be a symlink to a file the
    orchestrator (root) would then hash and stage.
    """
    found = []
    for path in sorted(src.glob("*.pkg.tar.zst")):
        if stat.S_ISREG(path.lstat().st_mode):
            found.append(path)
        else:
            log.warning("Refusing non-regular artifact %s", path.name)
    return found
