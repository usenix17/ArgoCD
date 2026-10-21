"""Pushgateway metrics (dashboards, alerts) and live progress for the site."""
import logging
import time
import urllib.error
import urllib.request

from . import config as cfg
from .status import write_live

log = logging.getLogger("aurmirror")


def _esc(value) -> str:
    """Escape a Prometheus label value."""
    return (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", " ").replace("\r", " "))


def _put(job: str, lines: list[str], timeout: int) -> None:
    url = f"{cfg.PUSHGATEWAY_URL.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(url, data=("\n".join(lines) + "\n").encode(), method="PUT")
    req.add_header("Content-Type", "text/plain; version=0.0.4")
    with urllib.request.urlopen(req, timeout=timeout):
        pass


def push_metrics(total: int, skipped: int, held: dict[str, dict]) -> None:
    """End-of-run summary (job aur-mirror); series names are unchanged."""
    if not cfg.PUSHGATEWAY_URL:
        return
    lines = ["# HELP aur_mirror_package_held Package held back from the mirror (1=held)",
             "# TYPE aur_mirror_package_held gauge"]
    for pkg, info in held.items():
        lines.append(
            f'aur_mirror_package_held{{package="{_esc(pkg)}",'
            f'reason="{_esc(info.get("reason", ""))}",risk="{_esc(info.get("risk", ""))}",'
            f'summary="{_esc(info.get("summary", ""))[:200]}"}} 1')
    gauges = {
        "last_run_timestamp_seconds": int(time.time()),
        "last_run_success": 0 if held else 1,
        "packages_total": total,
        "packages_succeeded_total": total - skipped - len(held),
        "packages_skipped_total": skipped,
        "packages_held_total": len(held),
    }
    for name, value in gauges.items():
        lines += [f"# TYPE aur_mirror_{name} gauge", f"aur_mirror_{name} {value}"]
    try:
        _put("aur-mirror", lines, timeout=15)
        log.info("Metrics pushed to Pushgateway (%d held)", len(held))
    except (urllib.error.URLError, OSError) as exc:
        log.warning("Failed to push metrics to Pushgateway: %s", exc)


def push_progress(phase: str, package: str | None, current: int, total: int) -> None:
    """Live progress (job aur-mirror-live) plus live.json; never raises."""
    write_live(phase, package, current, total)
    if not cfg.PUSHGATEWAY_URL:
        return
    lines = ["# TYPE aur_mirror_active_phase gauge",
             f'aur_mirror_active_phase{{phase="{_esc(phase)}"}} 1',
             "# TYPE aur_mirror_progress_current gauge", f"aur_mirror_progress_current {current}",
             "# TYPE aur_mirror_progress_total gauge", f"aur_mirror_progress_total {total}",
             "# TYPE aur_mirror_activity_timestamp_seconds gauge",
             f"aur_mirror_activity_timestamp_seconds {int(time.time())}"]
    if package:
        lines += ["# TYPE aur_mirror_active_package gauge",
                  f'aur_mirror_active_package{{package="{_esc(package)}"}} 1']
    try:
        _put("aur-mirror-live", lines, timeout=5)
    except (urllib.error.URLError, OSError) as exc:
        log.debug("progress push failed: %s", exc)
