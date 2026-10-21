"""Shared fixtures: import the package and point every config path at tmp dirs."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

os.environ.setdefault("REPO_DIR", "/nonexistent-aur-mirror-repo")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aurmirror import config as cfg  # noqa: E402  pylint: disable=wrong-import-position


@pytest.fixture(name="dirs")
def fixture_dirs(tmp_path, monkeypatch):
    """Isolate repo, state, status and build dirs per test."""
    for attr in ("REPO_DIR", "STATE_DIR", "STATUS_DIR", "BUILD_DIR"):
        path = tmp_path / attr.lower()
        path.mkdir()
        monkeypatch.setattr(cfg, attr, path)
    monkeypatch.setattr(cfg, "SCAN_STATE", cfg.STATE_DIR / "verdicts.json")
    monkeypatch.setattr(cfg, "AUR_META", cfg.STATE_DIR / "meta.json")
    monkeypatch.setattr(cfg, "RUN_STATE", cfg.STATE_DIR / "run.json")
    monkeypatch.setattr(cfg, "RUN_ID", "run-1")
    monkeypatch.setattr(cfg, "PUSHGATEWAY_URL", "")
    return tmp_path


class GitRepo:
    """A throwaway git repo for recipe tests."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")

    def git(self, *args: str) -> str:
        """Run git in the repo and return stdout."""
        return subprocess.run(["git", *args], cwd=self.path, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, files: dict[str, str]) -> str:
        """Write files, commit them, and return the new commit SHA."""
        for name, body in files.items():
            (self.path / name).write_text(body, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "c")
        return self.git("rev-parse", "HEAD")


@pytest.fixture(name="make_repo")
def fixture_make_repo(tmp_path):
    """Factory for git repos under tmp_path."""
    return lambda name="recipe": GitRepo(tmp_path / name)
