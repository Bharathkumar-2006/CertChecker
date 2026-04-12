"""
HTTP-level checks: HSTS, redirect detection, security headers analysis.
"""

import requests
from typing import Optional
import socket


# Important security headers and what they protect
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — Forces HTTPS connections",
    "Content-Security-Policy": "CSP — Prevents XSS / injection attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-Frame-Options": "Clickjacking protection",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser feature access",
    "X-XSS-Protection": "Legacy XSS filter (browsers)",
    "Cache-Control": "Controls caching behavior",
    "Cross-Origin-Opener-Policy": "Isolates browsing context",
    "Cross-Origin-Resource-Policy": "Restricts cross-origin resource sharing",
}


def run_http_checks(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Perform HTTP-level security checks on a host.
    Returns a dict with redirect info, HSTS, headers, etc.
    """
    result = {
        "http_redirects_to_https": None,
        "hsts_enabled": False,
        "hsts_max_age": None,
        "hsts_include_subdomains": False,
        "hsts_preload": False,
        "security_headers": {},
        "missing_headers": [],
        "present_headers": [],
        "redirect_chain": [],
        "final_url": None,
        "status_code": None,
        "server": None,
    }

    session = requests.Session()
    session.max_redirects = 10

    # Check HTTP → HTTPS redirect
    http_url = f"http://{hostname}"
    try:
        http_resp = session.get(
            http_url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        final = http_resp.url
        result["final_url"] = final
        result["redirect_chain"] = [r.url for r in http_resp.history] + [final]
        result["http_redirects_to_https"] = final.startswith("https://")
    except requests.exceptions.RequestException:
        result["http_redirects_to_https"] = None

    # Check HTTPS endpoint
    https_url = f"https://{hostname}" if port == 443 else f"https://{hostname}:{port}"
    try:
        https_resp = session.get(
            https_url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        result["status_code"] = https_resp.status_code
        result["server"] = https_resp.headers.get("Server")

        # HSTS analysis
        hsts = https_resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            result["hsts_enabled"] = True
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        result["hsts_max_age"] = int(part.split("=")[1])
                    except ValueError:
                        pass
                elif part == "includesubdomains":
                    result["hsts_include_subdomains"] = True
                elif part == "preload":
                    result["hsts_preload"] = True

        # Security headers scan
        for header, description in SECURITY_HEADERS.items():
            value = https_resp.headers.get(header)
            if value:
                result["present_headers"].append({
                    "header": header,
                    "value": value,
                    "description": description,
                })
                result["security_headers"][header] = value
            else:
                result["missing_headers"].append({
                    "header": header,
                    "description": description,
                })

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


def check_port_open(hostname: str, port: int, timeout: int = 5) -> bool:
    """Check if a specific port is open on a host."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_tls_ports(hostname: str, timeout: int = 5) -> list:
    """Scan common TLS ports and report which are open."""
    common_tls_ports = {
        443: "HTTPS",
        8443: "HTTPS (alt)",
        465: "SMTPS",
        587: "SMTP STARTTLS",
        993: "IMAPS",
        995: "POP3S",
        636: "LDAPS",
        5061: "SIP TLS",
    }

    results = []
    for port, service in common_tls_ports.items():
        open_port = check_port_open(hostname, port, timeout)
        results.append({
            "port": port,
            "service": service,
            "open": open_port,
        })

    return results
