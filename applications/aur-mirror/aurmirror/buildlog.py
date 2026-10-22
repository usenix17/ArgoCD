"""Run commands with output streamed to the console and a per-package log file."""
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import config as cfg
from .common import give_to_pipeline
from .status import log_url


class LogTee:
    """Mirror lines to stdout (for Graylog) and a capped log file (for the site).

    The file is best-effort: if the status volume is unavailable the build
    carries on with console output only.
    """

    def __init__(self, path: Path | None) -> None:
        self.url = None
        self._fh = None
        self._written = 0
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.url = log_url(path)
            self._fh = path.open("w", encoding="utf-8", errors="replace")
            give_to_pipeline(path.parent)
            give_to_pipeline(path)
        except (OSError, ValueError):
            self.url = None
            self._fh = None

    def line(self, text: str) -> None:
        """Write one line (newline added if missing)."""
        if not text.endswith("\n"):
            text += "\n"
        sys.stdout.write(text)
        sys.stdout.flush()
        if self._fh is None:
            return
        if self._written < cfg.LOG_MAX_BYTES:
            self._fh.write(text)
            self._written += len(text)
            if self._written >= cfg.LOG_MAX_BYTES:
                self._fh.write("[log truncated; full output is in the console log]\n")
            self._fh.flush()

    def close(self) -> None:
        """Close the file handle, if any."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _pump(stream, tee: LogTee) -> None:
    for line in stream:
        tee.line(line)


def _clear_pacman_lock() -> None:
    """A killed dependency install can leave pacman's lock behind and break later builds."""
    Path("/var/lib/pacman/db.lck").unlink(missing_ok=True)


def run_logged(cmd: list[str], tee: LogTee, cwd: Path | None = None,
               timeout: int | None = None) -> None:
    """Run ``cmd`` streaming output to ``tee``.

    On timeout the whole process group is killed (makepkg's children too) and
    TimeoutExpired is raised; a non-zero exit raises CalledProcessError.
    """
    tee.line("+ " + " ".join(str(c) for c in cmd))
    with subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, errors="replace", start_new_session=True) as proc:
        reader = threading.Thread(target=_pump, args=(proc.stdout, tee), daemon=True)
        reader.start()
        try:
            code = proc.wait(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            reader.join(timeout=10)
            _clear_pacman_lock()
            tee.line(f"[killed after {timeout}s timeout]")
            raise
        reader.join()
    if code:
        raise subprocess.CalledProcessError(code, cmd)
