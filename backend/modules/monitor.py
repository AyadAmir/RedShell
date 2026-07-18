"""
RedShell :: Monitor Module (Blue Team / Detection)
-----------------------------------------------------
Lightweight host-based monitoring: watches system resource usage and
network connections on the machine RedShell itself runs on, applies
simple rule-based + statistical anomaly detection, and raises alerts.

This is intentionally a defensive/observability module — it reads local
system state (via psutil) and flags suspicious patterns (port-scan-like
connection bursts, unusual outbound connection counts, high resource
spikes) rather than monitoring third-party infrastructure.
"""

import psutil
import time
import asyncio
from dataclasses import dataclass, asdict, field
from collections import deque, Counter
from typing import Optional
import datetime


@dataclass
class Alert:
    timestamp: str
    severity: str  # INFO, WARNING, CRITICAL
    category: str
    title: str
    description: str


# Rolling history for simple statistical baselining
_cpu_history = deque(maxlen=30)
_conn_history = deque(maxlen=30)
_alerts_log = deque(maxlen=200)

# Known sensitive/admin ports — unexpected LISTEN state here from a
# non-standard process is interesting for a blue-team view
SENSITIVE_PORTS = {22, 23, 3389, 445, 5985, 5986, 135}


def _get_snapshot() -> dict:
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        connections = []

    listen_ports = []
    established_remote_ips = []
    for c in connections:
        if c.status == psutil.CONN_LISTEN and c.laddr:
            listen_ports.append(c.laddr.port)
        if c.status == "ESTABLISHED" and c.raddr:
            established_remote_ips.append(c.raddr.ip)

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "disk_percent": disk.percent,
        "listen_ports": sorted(set(listen_ports)),
        "established_count": len(established_remote_ips),
        "unique_remote_ips": len(set(established_remote_ips)),
        "top_remote_ips": Counter(established_remote_ips).most_common(5),
        "process_count": len(psutil.pids()),
    }


def _analyze_snapshot(snap: dict) -> list:
    """Rule-based + simple statistical anomaly detection over the snapshot."""
    alerts = []
    now = snap["timestamp"]

    # CPU spike detection (statistical: compare to rolling baseline)
    _cpu_history.append(snap["cpu_percent"])
    if len(_cpu_history) >= 5:
        avg = sum(list(_cpu_history)[:-1]) / max(len(_cpu_history) - 1, 1)
        if snap["cpu_percent"] > 85 and snap["cpu_percent"] > avg * 1.8:
            alerts.append(Alert(
                timestamp=now, severity="WARNING", category="Resource Anomaly",
                title="Abnormal CPU spike detected",
                description=f"CPU usage jumped to {snap['cpu_percent']}% vs a rolling baseline of {avg:.1f}%. Could indicate crypto-mining, a runaway process, or resource-exhaustion activity.",
            ))

    # Memory pressure
    if snap["memory_percent"] > 90:
        alerts.append(Alert(
            timestamp=now, severity="WARNING", category="Resource Anomaly",
            title="High memory utilization",
            description=f"Memory usage at {snap['memory_percent']}%. Sustained high memory pressure can indicate a memory leak or denial-of-service condition.",
        ))

    # Connection burst (port-scan-like pattern detection against this host)
    _conn_history.append(snap["established_count"])
    if len(_conn_history) >= 5:
        avg_conn = sum(list(_conn_history)[:-1]) / max(len(_conn_history) - 1, 1)
        if snap["established_count"] > 40 and snap["established_count"] > avg_conn * 2:
            alerts.append(Alert(
                timestamp=now, severity="CRITICAL", category="Network Anomaly",
                title="Unusual spike in established connections",
                description=f"Established connection count jumped to {snap['established_count']} (baseline ~{avg_conn:.0f}). This pattern can indicate the host is being scanned, is under connection-flood, or is itself compromised and beaconing/scanning outward.",
            ))

    # Sensitive port listening check
    sensitive_open = set(snap["listen_ports"]) & SENSITIVE_PORTS
    if sensitive_open:
        alerts.append(Alert(
            timestamp=now, severity="INFO", category="Exposure",
            title=f"Sensitive service port(s) listening: {sorted(sensitive_open)}",
            description="These ports correspond to remote-access/admin services (SSH/RDP/SMB/WinRM/RPC). Confirm this is expected and restricted by firewall/VPN, not exposed broadly.",
        ))

    # Single remote IP dominating connections (possible C2 beacon pattern)
    if snap["top_remote_ips"]:
        top_ip, top_count = snap["top_remote_ips"][0]
        if top_count >= 10 and snap["unique_remote_ips"] <= 2:
            alerts.append(Alert(
                timestamp=now, severity="WARNING", category="Network Anomaly",
                title=f"Repeated connections to single remote host {top_ip}",
                description=f"{top_count} established connections concentrated on {top_ip} with little diversity. Worth confirming this is a known/expected service (e.g. CDN, DB) and not anomalous beaconing.",
            ))

    return alerts


async def get_live_snapshot() -> dict:
    """Single point-in-time snapshot + analysis, used by the polling endpoint."""
    loop = asyncio.get_event_loop()
    snap = await loop.run_in_executor(None, _get_snapshot)
    new_alerts = _analyze_snapshot(snap)
    for a in new_alerts:
        _alerts_log.appendleft(a)
    return {
        "snapshot": snap,
        "new_alerts": [asdict(a) for a in new_alerts],
        "recent_alerts": [asdict(a) for a in list(_alerts_log)[:25]],
    }


def get_alert_history() -> list:
    return [asdict(a) for a in list(_alerts_log)]


def clear_alerts():
    _alerts_log.clear()
