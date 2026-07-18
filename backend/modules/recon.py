"""
RedShell :: Recon Module
-------------------------
Performs authorized host discovery, TCP port scanning, banner grabbing,
and lightweight service fingerprinting against a user-specified target.

LEGAL NOTE: This module is intended for use only against systems you own
or have explicit written authorization to test. Scanning third-party
infrastructure without permission is illegal in most jurisdictions
(e.g. Computer Fraud and Abuse Act, Computer Misuse Act, PECA in Pakistan).
"""

import socket
import asyncio
import re
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress

# Common ports with descriptive names — kept intentionally small & fast
# rather than a full 65535 sweep, which is both slow and rarely necessary
# for an assessment-style scan.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP",
    5000: "Dev-HTTP-Alt", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9000: "Dev-HTTP", 9200: "Elasticsearch", 27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""
    tls: bool = False
    response_time_ms: float = 0.0


@dataclass
class ReconResult:
    target: str
    resolved_ip: str
    is_alive: bool
    open_ports: list = field(default_factory=list)
    os_guess: str = "Unknown"
    scan_duration_s: float = 0.0
    error: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d["open_ports"] = [asdict(p) for p in self.open_ports]
        return d


def _validate_target(target: str) -> str:
    """Resolve hostname to IP, raise on invalid/unresolvable input."""
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve target '{target}': {e}")


def _grab_banner(sock: socket.socket, port: int) -> str:
    """Attempt to read a service banner. Sends a minimal probe for
    protocols that don't greet first (e.g. HTTP)."""
    try:
        sock.settimeout(1.5)
        if port in (80, 8080, 8000, 3000, 5000, 9000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443 or port == 8443:
            return ""  # handled separately via TLS wrapper
        banner = sock.recv(256)
        return banner.decode(errors="ignore").strip().replace("\r\n", " | ")[:200]
    except Exception:
        return ""


def _check_tls(host: str, port: int) -> str:
    """Grab TLS cert CN / issuer if the port speaks TLS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                version = tls_sock.version()
                return f"TLS:{version}"
    except Exception:
        return ""


def _scan_one_port(host: str, port: int) -> Optional[PortResult]:
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.8)
            result = sock.connect_ex((host, port))
            elapsed = (time.time() - start) * 1000
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = _grab_banner(sock, port)
                tls_info = ""
                if port in (443, 8443, 993, 995, 465, 5986):
                    tls_info = _check_tls(host, port)
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner or tls_info,
                    tls=bool(tls_info),
                    response_time_ms=round(elapsed, 2),
                )
    except Exception:
        pass
    return None


def _guess_os(open_ports: list) -> str:
    """Very lightweight heuristic OS guess based on open port signature.
    Not a replacement for real fingerprinting (e.g. nmap -O), but gives
    a reasonable hint for the report."""
    ports = {p.port for p in open_ports}
    if 3389 in ports or 445 in ports or 5985 in ports or 135 in ports:
        return "Likely Windows (RDP/SMB/WinRM/RPC signature)"
    if 22 in ports and 3306 in ports:
        return "Likely Linux (SSH + MySQL signature)"
    if 22 in ports:
        return "Likely Linux/Unix (SSH present)"
    if not ports:
        return "Unknown (no open ports detected)"
    return "Unknown"


async def run_recon(target: str, ports: Optional[list] = None, progress_cb=None) -> dict:
    """
    Main entry point. Runs a concurrent TCP connect scan against `target`.

    progress_cb: optional async callable(percent:int, message:str) for
    live progress reporting over websocket.
    """
    start_time = time.time()
    scan_ports = ports or list(COMMON_PORTS.keys())

    try:
        ip = _validate_target(target)
    except ValueError as e:
        return make_error_result(target, str(e))

    # Liveness check
    is_alive = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            # try the most common port as a liveness probe; doesn't fully
            # guarantee host-down if closed, so we still scan regardless
            s.connect_ex((ip, 80))
        is_alive = True
    except Exception:
        is_alive = True  # proceed with scan anyway; firewalls often block ICMP/probe

    open_ports = []
    loop = asyncio.get_event_loop()
    total = len(scan_ports)

    # Run blocking socket scans in a thread pool, batched for concurrency
    # without overwhelming the OS socket limits.
    batch_size = 50
    completed = 0
    for i in range(0, total, batch_size):
        batch = scan_ports[i:i + batch_size]
        tasks = [loop.run_in_executor(None, _scan_one_port, ip, p) for p in batch]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                open_ports.append(r)
        completed += len(batch)
        if progress_cb:
            pct = int((completed / total) * 100)
            await progress_cb(pct, f"Scanned {completed}/{total} ports — {len(open_ports)} open so far")

    open_ports.sort(key=lambda p: p.port)
    duration = round(time.time() - start_time, 2)

    result = ReconResult(
        target=target,
        resolved_ip=ip,
        is_alive=is_alive,
        open_ports=open_ports,
        os_guess=_guess_os(open_ports),
        scan_duration_s=duration,
    )
    return result.to_dict()


def make_error_result(target, error):
    r = ReconResult(target=target, resolved_ip="", is_alive=False, error=error)
    return r.to_dict()

