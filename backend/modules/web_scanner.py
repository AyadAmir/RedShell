"""
RedShell :: Web Application Scanner Module
---------------------------------------------
Performs SAFE, NON-DESTRUCTIVE detection checks against a target web
application: security header analysis, TLS/cert hygiene, cookie flags,
basic reflected-XSS/SQLi DETECTION probes (using inert canary strings,
not real exploit payloads), and common information-disclosure checks.

This module intentionally does NOT contain working exploit payloads,
shells, or anything that modifies/damages target state. It is built to
flag *possible* weaknesses for a human to verify manually — exactly how
a legitimate DAST (Dynamic Application Security Testing) tool behaves.

LEGAL NOTE: Only run against applications you own or are authorized to
test (e.g. the bundled demo_target, your own lab deployment, or an app
you have written permission to assess).
"""

import httpx
import re
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Optional


@dataclass
class Finding:
    category: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: str = ""
    recommendation: str = ""


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

SECURITY_HEADERS = {
    "strict-transport-security": Finding(
        category="Headers", title="Missing HSTS Header", severity="MEDIUM",
        description="Strict-Transport-Security header is absent, allowing potential SSL-stripping / protocol downgrade attacks.",
        recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
    ),
    "x-content-type-options": Finding(
        category="Headers", title="Missing X-Content-Type-Options", severity="LOW",
        description="Without 'nosniff', browsers may MIME-sniff responses, enabling certain content-type confusion attacks.",
        recommendation="Add 'X-Content-Type-Options: nosniff' to all responses.",
    ),
    "x-frame-options": Finding(
        category="Headers", title="Missing X-Frame-Options / frame-ancestors", severity="MEDIUM",
        description="Application may be embeddable in an iframe on a malicious site, enabling clickjacking attacks.",
        recommendation="Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "content-security-policy": Finding(
        category="Headers", title="Missing Content-Security-Policy", severity="MEDIUM",
        description="No CSP header found. CSP is a key defense-in-depth control against XSS and data injection attacks.",
        recommendation="Define a restrictive CSP, e.g. \"default-src 'self'\", and tighten per resource type.",
    ),
    "referrer-policy": Finding(
        category="Headers", title="Missing Referrer-Policy", severity="LOW",
        description="No Referrer-Policy set; full URLs (potentially with sensitive query params) may leak to third parties via the Referer header.",
        recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "permissions-policy": Finding(
        category="Headers", title="Missing Permissions-Policy", severity="INFO",
        description="No Permissions-Policy header found to restrict use of sensitive browser features (camera, geolocation, etc).",
        recommendation="Add a Permissions-Policy header scoped to only the features the app actually needs.",
    ),
}

# Inert canary string used purely to detect whether input is reflected
# unescaped in the response. This is NOT a working XSS payload — it
# contains no executable script tag — it only checks if special HTML
# characters survive into the response unescaped, which indicates a
# *potential* reflection point a human should investigate further.
XSS_CANARY = "rs_canary_<>\"'_test"
SQLI_CANARIES = ["'", "\"", "1' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]


async def _check_headers(resp: httpx.Response) -> list:
    findings = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header, template in SECURITY_HEADERS.items():
        if header not in headers_lower:
            f = Finding(**asdict(template))
            findings.append(f)
    # Server / X-Powered-By disclosure
    for leaky_header in ("server", "x-powered-by", "x-aspnet-version"):
        if leaky_header in headers_lower:
            findings.append(Finding(
                category="Information Disclosure",
                title=f"Verbose '{leaky_header}' header",
                severity="LOW",
                description=f"Server discloses technology/version info via the '{leaky_header}' header, aiding attacker reconnaissance.",
                evidence=f"{leaky_header}: {headers_lower[leaky_header]}",
                recommendation=f"Suppress or genericize the '{leaky_header}' header in server/proxy config.",
            ))
    return findings


async def _check_cookies(resp: httpx.Response) -> list:
    findings = []
    for cookie_header in resp.headers.get_list("set-cookie"):
        name = cookie_header.split("=")[0].strip()
        lower = cookie_header.lower()
        if "httponly" not in lower:
            findings.append(Finding(
                category="Cookies", title=f"Cookie '{name}' missing HttpOnly",
                severity="MEDIUM",
                description="Cookie can be accessed via JavaScript (document.cookie), increasing impact of any XSS vulnerability.",
                evidence=cookie_header[:120],
                recommendation="Set the HttpOnly flag on all session/auth cookies.",
            ))
        if "secure" not in lower and resp.url.scheme == "https":
            findings.append(Finding(
                category="Cookies", title=f"Cookie '{name}' missing Secure flag",
                severity="MEDIUM",
                description="Cookie may be transmitted over unencrypted HTTP, risking interception.",
                evidence=cookie_header[:120],
                recommendation="Set the Secure flag so the cookie is only sent over HTTPS.",
            ))
        if "samesite" not in lower:
            findings.append(Finding(
                category="Cookies", title=f"Cookie '{name}' missing SameSite",
                severity="LOW",
                description="Without SameSite, cookie may be sent on cross-site requests, increasing CSRF risk.",
                evidence=cookie_header[:120],
                recommendation="Set 'SameSite=Lax' or 'SameSite=Strict' depending on app requirements.",
            ))
    return findings


async def _detect_reflection(client: httpx.AsyncClient, base_url: str) -> list:
    """
    Detection-only check: appends an inert canary string to common query
    parameters and checks if it's reflected unescaped. This flags a
    *potential* injection point — it does not exploit anything.
    """
    findings = []
    parsed = urlparse(base_url)
    test_params = ["q", "search", "id", "name", "query", "page", "redirect"]

    for param in test_params:
        try:
            test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={XSS_CANARY}"
            resp = await client.get(test_url, timeout=5.0, follow_redirects=True)
            if XSS_CANARY in resp.text and f"&lt;" not in resp.text.split(XSS_CANARY)[0][-50:]:
                findings.append(Finding(
                    category="Input Validation",
                    title=f"Possible reflected input via '{param}' parameter",
                    severity="HIGH",
                    description=f"The value of parameter '{param}' appears to be reflected in the response without apparent HTML-encoding. This MAY indicate a reflected XSS vector — manual verification with a browser is required before treating this as confirmed.",
                    evidence=f"Tested: {test_url}",
                    recommendation="Ensure all user-controllable output is context-appropriately encoded (HTML entity encoding for HTML body context) before manual confirmation and remediation.",
                ))
        except Exception:
            continue

    return findings


async def _detect_sqli_indicators(client: httpx.AsyncClient, base_url: str) -> list:
    """
    Detection-only check: sends benign SQL meta-characters and compares
    response behavior/error signatures. Does NOT attempt data extraction,
    blind timing exfiltration, or any destructive query.
    """
    findings = []
    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-01756", "sqlite3.operationalerror",
        "unclosed quotation mark", "pg_query", "syntax error at or near",
        "sqlstate", "you have an error in your sql syntax",
    ]
    test_params = ["id", "user", "product", "category"]

    for param in test_params:
        try:
            baseline = await client.get(base_url, timeout=5.0)
            for canary in SQLI_CANARIES[:2]:  # only quote-based canaries, no real injection logic
                test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={canary}"
                resp = await client.get(test_url, timeout=5.0, follow_redirects=True)
                lower_text = resp.text.lower()
                for sig in error_signatures:
                    if sig in lower_text and sig not in baseline.text.lower():
                        findings.append(Finding(
                            category="Input Validation",
                            title=f"Possible SQL error disclosure via '{param}' parameter",
                            severity="CRITICAL",
                            description=f"Submitting a SQL meta-character to parameter '{param}' triggered what appears to be a database error message in the response. This is a strong indicator of a SQL injection vulnerability and requires immediate manual verification.",
                            evidence=f"Signature matched: '{sig}' | Tested: {test_url}",
                            recommendation="Use parameterized queries / prepared statements exclusively. Never concatenate user input into SQL strings. Disable verbose DB error output in production.",
                        ))
                        break
        except Exception:
            continue

    return findings


async def _check_tls_basic(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(Finding(
            category="Transport Security",
            title="Site served over plain HTTP",
            severity="HIGH",
            description="The application does not enforce HTTPS, exposing all traffic (including credentials/session tokens) to interception on the network path.",
            recommendation="Enforce HTTPS site-wide with a redirect from HTTP, and enable HSTS.",
        ))
    return findings


async def run_web_scan(target_url: str, progress_cb=None) -> dict:
    """
    Main entry point. Runs the full suite of safe detection checks against
    a target URL and returns a structured findings report.
    """
    start = time.time()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    all_findings = []
    error = None

    try:
        async with httpx.AsyncClient(verify=False) as client:
            if progress_cb:
                await progress_cb(10, "Fetching base page...")
            resp = await client.get(target_url, timeout=8.0, follow_redirects=True)

            if progress_cb:
                await progress_cb(30, "Analyzing security headers...")
            all_findings += await _check_headers(resp)

            if progress_cb:
                await progress_cb(45, "Analyzing cookies...")
            all_findings += await _check_cookies(resp)

            if progress_cb:
                await progress_cb(55, "Checking transport security...")
            all_findings += await _check_tls_basic(str(resp.url))

            if progress_cb:
                await progress_cb(70, "Probing for reflected input (detection only)...")
            all_findings += await _detect_reflection(client, target_url)

            if progress_cb:
                await progress_cb(90, "Checking for SQL error disclosure (detection only)...")
            all_findings += await _detect_sqli_indicators(client, target_url)

            if progress_cb:
                await progress_cb(100, "Web scan complete")

    except httpx.ConnectError as e:
        error = f"Could not connect to {target_url}: {e}"
    except Exception as e:
        error = f"Scan error: {e}"

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    duration = round(time.time() - start, 2)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "target": target_url,
        "findings": [asdict(f) for f in all_findings],
        "severity_counts": severity_counts,
        "total_findings": len(all_findings),
        "scan_duration_s": duration,
        "error": error,
    }
