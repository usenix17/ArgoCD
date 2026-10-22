"""Cross-pod run lock: acquire, wait, heartbeat, stale break, ownership."""
import os
import threading
import time

import pytest

from aurmirror import config as cfg
from aurmirror import lock


@pytest.fixture(name="lockdir")
def fixture_lockdir(tmp_path, monkeypatch):
    """A private lock volume with short timings."""
    monkeypatch.setattr(cfg, "LOCK_DIR", tmp_path)
    monkeypatch.setattr(cfg, "LOCK_STALE_SECONDS", 60)
    monkeypatch.setattr(cfg, "LOCK_HEARTBEAT_SECONDS", 0.05)
    monkeypatch.setattr(cfg, "LOCK_POLL_SECONDS", 0.05)
    return tmp_path


def _make_old(path, seconds):
    old = time.time() - seconds
    os.utime(path, (old, old))


def test_acquire_and_release(lockdir):  # pylint: disable=unused-argument
    """The lock exists while held and is gone after."""
    with lock.run_lock("scan"):
        assert lock.lock_path().is_dir()
        assert not lock.try_acquire("other")
    assert not lock.lock_path().exists()


def test_second_holder_waits(lockdir):  # pylint: disable=unused-argument
    """A second run blocks until the first releases."""
    order = []
    assert lock.try_acquire("first")

    def second():
        with lock.run_lock("build"):
            order.append("second")
    thread = threading.Thread(target=second)
    thread.start()
    time.sleep(0.3)
    order.append("first-done")
    lock.release("first")
    thread.join(timeout=5)
    assert order == ["first-done", "second"]


def test_heartbeat_keeps_lock_fresh(lockdir):  # pylint: disable=unused-argument
    """A held lock's owner file keeps being touched, so it never looks stale."""
    with lock.run_lock("build"):
        owner = lock.lock_path() / "owner"
        _make_old(owner, 3600)
        time.sleep(0.3)
        assert time.time() - owner.stat().st_mtime < 5
        assert not lock.break_if_stale()


def test_stale_lock_is_broken(lockdir):  # pylint: disable=unused-argument
    """A lock whose holder stopped heartbeating is taken over."""
    assert lock.try_acquire("dead-pod")
    _make_old(lock.lock_path() / "owner", 3600)
    with lock.run_lock("sign"):
        assert "sign" in (lock.lock_path() / "owner").read_text(encoding="utf-8")


def test_fresh_lock_not_broken(lockdir):  # pylint: disable=unused-argument
    """A live holder's lock is left alone."""
    assert lock.try_acquire("alive")
    assert not lock.break_if_stale()
    assert lock.lock_path().is_dir()


def test_release_leaves_someone_elses_lock(lockdir):  # pylint: disable=unused-argument
    """A holder whose lock was taken over does not delete the new owner's lock."""
    assert lock.try_acquire("new-owner")
    lock.release("old-owner")
    assert lock.lock_path().is_dir()
