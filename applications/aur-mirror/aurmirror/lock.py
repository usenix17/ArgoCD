"""Cross-pod run lock on the NFS lock volume.

Each phase holds it so the hourly CronJob and the ArgoCD PostSync hook never
write the repo, state or staging at the same time. flock() can't do this under
gVisor: each pod's sandbox keeps file locks in its own kernel, so they never
reach NFS. The lock is a file created with O_EXCL, which is atomic on the NFS
server. It is a file, not a directory, because a gVisor sandbox can keep
seeing a directory another pod removed, while it rechecks files properly.
The holder refreshes the file's mtime as a heartbeat; a lock whose heartbeat
stops (a killed pod) is broken after LOCK_STALE_SECONDS.
"""
import contextlib
import logging
import os
import threading
import time
import uuid
from pathlib import Path

from . import config as cfg
from .common import give_to_pipeline

log = logging.getLogger("aurmirror")


def lock_path() -> Path:
    """The lock file; it exists exactly while some phase holds the lock."""
    return cfg.LOCK_DIR / ".run.lock"


def _age(path: Path) -> float:
    """Seconds since the holder's last heartbeat, 0 if there is no holder."""
    try:
        return time.time() - path.stat().st_mtime
    except FileNotFoundError:
        return 0.0


def _owner(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def try_acquire(owner: str) -> bool:
    """Take the lock if it is free."""
    try:
        fd = os.open(lock_path(), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o664)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(owner)
    give_to_pipeline(lock_path())  # the uid-1000 phases must be able to break it if stale
    return True


def break_if_stale() -> bool:
    """Remove a lock whose holder stopped heartbeating; True if one was removed.

    The lock is renamed aside first so that two waiters can't both break it.
    If the renamed lock turns out to be fresh (another pod took it between our
    check and the rename), it is put back unless a new lock already exists.
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
            os.link(aside, lock)  # fails rather than clobbering a newer lock
        aside.unlink(missing_ok=True)
        return False
    log.warning("Broke stale run lock held by %s", _owner(aside))
    aside.unlink(missing_ok=True)
    return True


def _heartbeat(stop: threading.Event) -> None:
    while not stop.wait(cfg.LOCK_HEARTBEAT_SECONDS):
        try:
            os.utime(lock_path())
        except OSError as exc:
            log.warning("Run lock heartbeat failed: %s", exc)


def release(owner: str) -> None:
    """Drop the lock, but only if it is still ours."""
    lock = lock_path()
    if _owner(lock) != owner:
        log.warning("Run lock was taken over while held (now %s); leaving it", _owner(lock))
        return
    try:
        lock.unlink()
    except OSError as exc:
        log.warning("Could not release the run lock: %s", exc)


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
    beat = threading.Thread(target=_heartbeat, args=(stop,), daemon=True)
    beat.start()
    try:
        yield
    finally:
        stop.set()
        beat.join(timeout=5)
        release(owner)
