"""Cross-pod run lock on the NFS lock volume.

Each phase holds it so the hourly CronJob and the ArgoCD PostSync hook never
write the repo, state or staging at the same time. flock() can't do this under
gVisor: each pod's sandbox keeps file locks in its own kernel, so they never
reach NFS. A lock directory works because mkdir is atomic on the NFS server.
The holder refreshes a heartbeat file; a lock whose heartbeat stops (a killed
pod) is broken after LOCK_STALE_SECONDS.
"""
import contextlib
import logging
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

from . import config as cfg
from .common import give_to_pipeline

log = logging.getLogger("aurmirror")


def lock_path() -> Path:
    """The lock directory; it exists exactly while some phase holds the lock."""
    return cfg.LOCK_DIR / ".build.lockd"


def _owner_file(lock: Path) -> Path:
    return lock / "owner"


def _age(lock: Path) -> float:
    """Seconds since the last heartbeat (or since the lock was made), 0 if gone."""
    for path in (_owner_file(lock), lock):
        try:
            return time.time() - path.stat().st_mtime
        except FileNotFoundError:
            continue
    return 0.0


def _owner(lock: Path) -> str:
    try:
        return _owner_file(lock).read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def try_acquire(owner: str) -> bool:
    """Take the lock if it is free."""
    lock = lock_path()
    try:
        lock.mkdir()
    except FileExistsError:
        return False
    _owner_file(lock).write_text(owner, encoding="utf-8")
    give_to_pipeline(lock)  # the uid-1000 phases must be able to break it if stale
    give_to_pipeline(_owner_file(lock))
    return True


def break_if_stale() -> bool:
    """Remove a lock whose holder stopped heartbeating; True if one was removed.

    The lock is renamed aside first so that two waiters can't both break it.
    If the renamed lock turns out to be fresh (another pod took it between our
    check and the rename), it is put back.
    """
    lock = lock_path()
    if _age(lock) < cfg.LOCK_STALE_SECONDS:
        return False
    aside = lock.with_name(f"{lock.name}.stale-{uuid.uuid4().hex}")
    try:
        lock.rename(aside)
    except OSError:
        return False
    if _age(aside) < cfg.LOCK_STALE_SECONDS:
        with contextlib.suppress(OSError):
            aside.rename(lock)
        return False
    log.warning("Broke stale run lock held by %s", _owner(aside))
    shutil.rmtree(aside, ignore_errors=True)
    return True


def _heartbeat(lock: Path, stop: threading.Event) -> None:
    while not stop.wait(cfg.LOCK_HEARTBEAT_SECONDS):
        try:
            os.utime(_owner_file(lock))
        except OSError as exc:
            log.warning("Run lock heartbeat failed: %s", exc)


def release(owner: str) -> None:
    """Drop the lock, but only if it is still ours."""
    lock = lock_path()
    if _owner(lock) != owner:
        log.warning("Run lock was taken over while held (now %s); leaving it", _owner(lock))
        return
    shutil.rmtree(lock, ignore_errors=True)


@contextlib.contextmanager
def run_lock(phase: str):
    """Hold the run lock for one phase, waiting for any other run to finish."""
    owner = f"{cfg.RUN_ID} {phase} {uuid.uuid4().hex[:8]}"
    waiting = False
    while not try_acquire(owner):
        if not waiting:
            log.info("Waiting for the run lock held by %s", _owner(lock_path()))
            waiting = True
        if not break_if_stale():
            time.sleep(cfg.LOCK_POLL_SECONDS)
    log.info("Run lock acquired for %s", phase)
    stop = threading.Event()
    beat = threading.Thread(target=_heartbeat, args=(lock_path(), stop), daemon=True)
    beat.start()
    try:
        yield
    finally:
        stop.set()
        beat.join(timeout=5)
        release(owner)
