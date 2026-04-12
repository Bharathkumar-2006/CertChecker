"""
Continuous monitoring module — polls domains at a regular interval
and alerts when certificates are about to expire or have issues.
"""

import time
import datetime
from typing import List, Optional, Callable


def monitor_domains(
    hostnames: List[str],
    port: int = 443,
    interval: int = 3600,
    warn_days: int = 30,
    critical_days: int = 7,
    timeout: int = 10,
    on_result: Optional[Callable] = None,
    max_iterations: Optional[int] = None,
):
    """
    Continuously monitor domains and invoke callback on each result.

    Args:
        hostnames: List of hostnames to monitor.
        port: TCP port for TLS connection.
        interval: Seconds between each full poll cycle.
        warn_days: Days remaining threshold for WARNING alert.
        critical_days: Days remaining threshold for CRITICAL alert.
        timeout: Socket connection timeout.
        on_result: Callback(result_dict, alert_level) called for each check.
        max_iterations: If set, stop after this many rounds (for testing).
    """
    from certchecker.checker import get_certificate, CertCheckError

    iteration = 0
    while True:
        iteration += 1
        cycle_start = datetime.datetime.now()

        for hostname in hostnames:
            try:
                result = get_certificate(hostname, port=port, timeout=timeout)
                days = result.get("days_remaining", 999)
                is_expired = result.get("is_expired", False)

                if is_expired:
                    level = "EXPIRED"
                elif days <= critical_days:
                    level = "CRITICAL"
                elif days <= warn_days:
                    level = "WARNING"
                else:
                    level = "OK"

                result["alert_level"] = level

            except CertCheckError as e:
                result = {
                    "hostname": hostname,
                    "port": port,
                    "error": str(e),
                    "alert_level": "ERROR",
                    "checked_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                }

            if on_result:
                on_result(result)

        if max_iterations and iteration >= max_iterations:
            break

        # Sleep until next interval
        elapsed = (datetime.datetime.now() - cycle_start).total_seconds()
        sleep_time = max(0, interval - elapsed)
        time.sleep(sleep_time)


def get_alert_color(level: str) -> str:
    """Return a Rich color tag for an alert level."""
    return {
        "OK": "green",
        "WARNING": "yellow",
        "CRITICAL": "orange1",
        "EXPIRED": "red",
        "ERROR": "bright_red",
    }.get(level, "white")
