"""Sandbox launch, dependency handling and artifact pickup."""
import hashlib
import os
import subprocess

import pytest

from aurmirror import build
from aurmirror import config as cfg
from aurmirror import sandbox
from aurmirror.buildlog import LogTee

SRCINFO = """pkgbase = x
\tpkgver = 1
\tdepends = glibc
\tdepends = python>=3.12
\tmakedepends = cmake
\tmakedepends_x86_64 = nasm
\tmakedepends_aarch64 = armonly
\tcheckdepends = python-pytest
\tdepends = glibc
\tvalidpgpkeys = ABCD

pkgname = x
\tdepends = runtime-only-of-split-child
"""


def test_sandbox_cmd_drops_to_build_uid(tmp_path):
    """The command runs as BUILD_UID in fresh user, mount and pid namespaces."""
    cmd = sandbox.sandbox_cmd(tmp_path, ["true"])
    assert cmd[:2] == ["setpriv", f"--reuid={cfg.BUILD_UID}"]
    unshare = cmd[cmd.index("unshare"):cmd.index(str(cfg.SANDBOX))]
    assert {"-U", "-m", "-p", "--fork"} <= set(unshare)
    assert cmd[-2:] == [str(tmp_path), "true"]


def test_srcinfo_deps_pkgbase_only():
    """Build deps for this arch, versions stripped, deduped, split sections ignored."""
    assert sandbox.srcinfo_deps(SRCINFO) == [
        "glibc", "python", "cmake", "nasm", "python-pytest"]


@pytest.mark.parametrize("bad", ["--overwrite=*", "-Syu", "foo bar", "$(id)"])
def test_srcinfo_deps_rejects_option_like_names(bad):
    """A dependency pacman could read as an option or a second word is refused."""
    with pytest.raises(ValueError):
        sandbox.srcinfo_deps(f"pkgbase = x\n\tdepends = {bad}\n")


def test_srcinfo_values():
    """validpgpkeys come from the same srcinfo text."""
    assert sandbox.srcinfo_values(SRCINFO, "validpgpkeys") == ["ABCD"]


def test_deps_installed_then_exactly_removed(monkeypatch):
    """Only what the install added is removed afterwards."""
    states = iter([{"base"}, {"base", "cmake", "jsoncpp"}])
    monkeypatch.setattr(sandbox, "installed", lambda: next(states))
    calls = []
    monkeypatch.setattr(sandbox, "run_logged", lambda cmd, tee: calls.append(cmd))
    added = sandbox.install_deps(["cmake"], LogTee(None))
    sandbox.remove_deps(added, LogTee(None))
    assert added == ["cmake", "jsoncpp"]
    assert calls[0][:2] == ["pacman", "-S"] and calls[0][-2:] == ["--", "cmake"]
    assert calls[1] == ["pacman", "-Rdd", "--noconfirm", "--", "cmake", "jsoncpp"]


def test_remove_deps_failure_is_not_fatal(monkeypatch):
    """A failed cleanup is logged, never raised."""
    def boom(cmd, tee):
        raise subprocess.CalledProcessError(1, cmd)
    monkeypatch.setattr(sandbox, "run_logged", boom)
    sandbox.remove_deps(["x"], LogTee(None))


def test_symlinked_artifact_refused(tmp_path):
    """A package file the build made a symlink is never picked up."""
    (tmp_path / "x-1-1-x86_64.pkg.tar.zst").write_bytes(b"pkg")
    (tmp_path / "evil-1-1-x86_64.pkg.tar.zst").symlink_to("/etc/passwd")
    assert [p.name for p in sandbox.built_artifacts(tmp_path)] == ["x-1-1-x86_64.pkg.tar.zst"]


def test_stage_records_hash(dirs):  # pylint: disable=unused-argument
    """A regular artifact is moved into staging with its SHA256."""
    art = cfg.BUILD_DIR / "x-1-1-x86_64.pkg.tar.zst"
    art.write_bytes(b"pkg")
    rec = build.stage_artifacts("x", [art])
    assert rec[0]["sha256"] == hashlib.sha256(b"pkg").hexdigest()
    assert (cfg.staging_dir() / "x" / art.name).is_file() and not art.exists()


def test_work_layout_and_hand_over(tmp_path, monkeypatch):
    """The work dir gets its subdirs and is chowned to BUILD_UID, links untouched."""
    monkeypatch.setattr(cfg, "BUILD_UID", os.getuid())
    src = sandbox.make_work(tmp_path / "w")
    src.mkdir()
    (src / "PKGBUILD").write_text("x", encoding="utf-8")
    (src / "link").symlink_to("/etc/passwd")
    sandbox.hand_over(tmp_path / "w")
    assert sorted(p.name for p in (tmp_path / "w").iterdir()) == ["gnupg", "home", "src", "tmp"]
    assert ((tmp_path / "w" / "gnupg").stat().st_mode & 0o777) == 0o700


def test_run_sandboxed_timeout_kills_group(tmp_path, monkeypatch):
    """A hung sandboxed command is killed with its whole process group."""
    monkeypatch.setattr(sandbox, "sandbox_cmd", lambda work, cmd: cmd)
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox.run_sandboxed(tmp_path, ["sh", "-c", "sleep 30 & wait"], timeout=1)
    assert sandbox.run_sandboxed(tmp_path, ["sh", "-c", "echo hi"], 5).stdout == "hi\n"
