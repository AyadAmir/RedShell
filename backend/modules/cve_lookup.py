"""
RedShell :: CVE Lookup Module
-------------------------------
Cross-references detected services/banners from the recon module against
the NVD (National Vulnerability Database) public API to surface known
CVEs. Falls back to a small bundled offline dataset if the API is
unreachable (offline demo / no internet in the lab).
"""

import httpx
import re
import asyncio
from dataclasses import dataclass, asdict
from typing import Optional

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Minimal offline fallback dataset — a handful of well-known, illustrative
# CVEs keyed by service so the tool still demonstrates the feature without
# internet access (useful for an offline viva/demo).
OFFLINE_CVE_DB = {
    "ftp": [
        {"id": "CVE-2021-3618", "summary": "FTP server ALPACA confusion attack allowing cross-protocol exploitation.", "severity": "MEDIUM", "score": 5.9},
    ],
    "ssh": [
        {"id": "CVE-2023-38408", "summary": "OpenSSH forwarded ssh-agent allows remote code execution via crafted PKCS#11 provider.", "severity": "CRITICAL", "score": 9.8},
        {"id": "CVE-2018-15473", "summary": "OpenSSH user enumeration via crafted authentication packets.", "severity": "MEDIUM", "score": 5.3},
    ],
    "telnet": [
        {"id": "CVE-2020-10188", "summary": "Telnet client/server buffer overflow leading to remote code execution.", "severity": "CRITICAL", "score": 9.8},
    ],
    "smb": [
        {"id": "CVE-2020-0796", "summary": "SMBv3 ('SMBGhost') wormable remote code execution in compression handling.", "severity": "CRITICAL", "score": 10.0},
        {"id": "CVE-2017-0144", "summary": "SMBv1 ('EternalBlue') remote code execution exploited by WannaCry.", "severity": "CRITICAL", "score": 9.3},
    ],
    "rdp": [
        {"id": "CVE-2019-0708", "summary": "RDP ('BlueKeep') wormable pre-authentication remote code execution.", "severity": "CRITICAL", "score": 9.8},
    ],
    "http": [
        {"id": "CVE-2021-41773", "summary": "Apache HTTP Server path traversal allowing remote code execution.", "severity": "CRITICAL", "score": 9.8},
    ],
    "https": [
        {"id": "CVE-2014-0160", "summary": "OpenSSL 'Heartbleed' allowing remote memory disclosure.", "severity": "CRITICAL", "score": 9.4},
    ],
    "mysql": [
        {"id": "CVE-2021-2154", "summary": "MySQL Server privilege escalation vulnerability in the Optimizer component.", "severity": "HIGH", "score": 7.2},
    ],
    "redis": [
        {"id": "CVE-2022-0543", "summary": "Redis Lua sandbox escape allowing remote code execution on Debian-based systems.", "severity": "CRITICAL", "score": 10.0},
    ],
    "elasticsearch": [
        {"id": "CVE-2015-1427", "summary": "Elasticsearch Groovy scripting engine sandbox bypass allowing remote code execution.", "severity": "CRITICAL", "score": 9.8},
    ],
    "mongodb": [
        {"id": "CVE-2021-32039", "summary": "MongoDB server side integer overflow in BSON parsing leading to denial of service.", "severity": "HIGH", "score": 7.5},
    ],
    "vnc": [
        {"id": "CVE-2019-15681", "summary": "VNC client/server heap buffer overflow leading to remote code execution.", "severity": "HIGH", "score": 8.8},
    ],
    "docker": [
        {"id": "CVE-2019-5736", "summary": "runc container escape allowing host root access via overwritten binary.", "severity": "CRITICAL", "score": 8.6},
    ],
}


@dataclass
class CVEMatch:
    cve_id: str
    summary: str
    severity: str
    score: float
    matched_service: str
    matched_port: int
    source: str  # "NVD" or "OFFLINE"


def _normalize_service(service: str) -> str:
    return service.lower().strip()


async def _query_nvd(keyword: str, client: httpx.AsyncClient) -> list:
    """Query the live NVD API for CVEs matching a keyword (service name)."""
    try:
        resp = await client.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        matches = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")
            metrics = cve.get("metrics", {})
            score, severity = 0.0, "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = metrics[key][0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                    break
            matches.append({
                "id": cve_id,
                "summary": summary[:300],
                "severity": severity,
                "score": score,
            })
        return matches
    except Exception:
        return []


async def lookup_cves_for_services(open_ports: list, use_live_api: bool = True, progress_cb=None) -> list:
    """
    Takes the list of open_ports dicts from recon.py and returns a flat
    list of CVEMatch dicts. Tries the live NVD API first (rate-limited to
    avoid hammering it), falls back to the offline dataset per service.
    """
    results = []
    seen_services = set()

    async with httpx.AsyncClient() as client:
        for idx, p in enumerate(open_ports):
            service = _normalize_service(p.get("service", ""))
            port = p.get("port")

            if not service or service == "unknown":
                continue

            cache_key = service
            found_any = False

            if use_live_api and cache_key not in seen_services:
                live_matches = await _query_nvd(service, client)
                seen_services.add(cache_key)
                for m in live_matches:
                    results.append(CVEMatch(
                        cve_id=m["id"], summary=m["summary"], severity=m["severity"],
                        score=m["score"], matched_service=service, matched_port=port,
                        source="NVD",
                    ))
                    found_any = True
                # NVD public API is rate-limited (~5 req/30s without a key)
                await asyncio.sleep(1.2)

            if not found_any and service in OFFLINE_CVE_DB:
                for entry in OFFLINE_CVE_DB[service]:
                    results.append(CVEMatch(
                        cve_id=entry["id"], summary=entry["summary"], severity=entry["severity"],
                        score=entry["score"], matched_service=service, matched_port=port,
                        source="OFFLINE",
                    ))

            if progress_cb:
                pct = int(((idx + 1) / max(len(open_ports), 1)) * 100)
                await progress_cb(pct, f"Checked CVEs for {service} ({idx+1}/{len(open_ports)})")

    # Sort by severity score, highest first
    results.sort(key=lambda r: r.score, reverse=True)
    return [asdict(r) for r in results]
