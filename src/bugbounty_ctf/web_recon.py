"""Web reconnaissance automation: systematic recon against a web target.

Security fix: uses subprocess.run with argument lists (shell=False) to prevent
shell injection from malicious target URLs. The old version interpolated URLs
into shell strings with shell=True.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse


def run_cmd(args: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command safely with argument list (no shell interpolation).

    Args:
        args: Command and arguments as a list, e.g. ["curl", "-sI", url]
        timeout: Maximum seconds to wait

    Returns:
        (stdout, stderr, returncode)
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "[TIMEOUT]", -1
    except FileNotFoundError as e:
        return "", str(e), -1


def _curl_status_code(url: str, timeout: int = 5) -> str:
    """Get just the HTTP status code for a URL."""
    stdout, _, rc = run_cmd(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout), url],
        timeout=timeout + 2,
    )
    if rc == 0 and stdout:
        return stdout
    return "000"


def _curl_headers(url: str, timeout: int = 10) -> dict[str, str]:
    """Fetch headers for a URL."""
    stdout, _, _ = run_cmd(["curl", "-sI", "-L", "--max-time", str(timeout), url])
    headers: dict[str, str] = {}
    if stdout:
        for line in stdout.split("\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()
    return headers


def _curl_body(url: str, timeout: int = 5) -> str:
    """Fetch the response body for a URL."""
    stdout, _, _ = run_cmd(["curl", "-s", "--max-time", str(timeout), url])
    return stdout or ""


def recon_target(url: str, quick: bool = False) -> dict[str, Any]:
    """Full recon workflow against a target URL."""
    result: dict[str, Any] = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "quick_mode": quick,
        "sections": {},
    }

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)

    # Validate URL — prevent injection via malformed input
    if not host:
        result["error"] = "Invalid URL — no hostname could be parsed"
        return result

    base = f"{scheme}://{host}:{port}"

    # 1. Basic HTTP Info
    print(f"[*] Checking basic HTTP info for {url}")
    headers = _curl_headers(url)
    result["sections"]["http_headers"] = headers

    # Extract tech hints
    tech_hints: dict[str, str] = {}
    if "server" in headers:
        tech_hints["server"] = headers["server"]
    if "x-powered-by" in headers:
        tech_hints["framework"] = headers["x-powered-by"]
    if "set-cookie" in headers:
        cookie = headers["set-cookie"]
        if "PHPSESSID" in cookie:
            tech_hints["language"] = "PHP"
        elif "JSESSIONID" in cookie:
            tech_hints["language"] = "Java"
        elif "csrftoken" in cookie:
            tech_hints["framework"] = "Django"
    result["sections"]["technology"] = tech_hints

    # 2. robots.txt & sitemap — check status code, not body content
    print("[*] Checking robots.txt and sitemap")
    for path in ["/robots.txt", "/sitemap.xml"]:
        full_url = f"{base}{path}"
        status = _curl_status_code(full_url)
        if status not in ("000", "404"):
            body = _curl_body(full_url)
            result["sections"][path[1:]] = body[:2000]

    # 3. Common paths
    print("[*] Checking common paths")
    common_paths = [
        "/admin",
        "/login",
        "/api",
        "/api/v1",
        "/graphql",
        "/.env",
        "/config.php",
        "/wp-admin",
        "/phpinfo.php",
        "/server-status",
        "/actuator",
        "/swagger.json",
        "/.git/config",
        "/backup.sql",
        "/debug",
    ]
    found_paths: list[dict[str, str]] = []
    for path in common_paths:
        full_url = f"{base}{path}"
        status = _curl_status_code(full_url)
        if status not in ("000", "404"):
            found_paths.append({"path": path, "status": status})
    result["sections"]["interesting_paths"] = found_paths

    if not quick:
        # 4. Subdomain enumeration via crt.sh
        print("[*] Checking for subdomains")
        stdout, _, _ = run_cmd(
            ["curl", "-s", "--max-time", "10", f"https://crt.sh/?q={host}&output=json"],
            timeout=15,
        )
        subdomains: set[str] = set()
        if stdout:
            try:
                certs = json.loads(stdout)
                for cert in certs[:50]:
                    name = cert.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if "*" not in sub:
                            subdomains.add(sub)
            except (ValueError, json.JSONDecodeError):
                pass
        result["sections"]["subdomains"] = list(subdomains)[:20]

    # 5. Security headers check
    print("[*] Checking security headers")
    sec_headers = {
        "strict-transport-security": "HSTS missing",
        "content-security-policy": "CSP missing",
        "x-content-type-options": "X-Content-Type-Options missing",
        "x-frame-options": "X-Frame-Options missing",
        "x-xss-protection": "X-XSS-Protection missing",
        "referrer-policy": "Referrer-Policy missing",
    }
    missing_headers: list[str] = []
    for header, issue in sec_headers.items():
        if header not in headers:
            missing_headers.append(issue)
    result["sections"]["security_headers"] = {
        "present": [h for h in sec_headers if h in headers],
        "missing": missing_headers,
    }

    # 6. Quick vuln checks
    print("[*] Running quick vulnerability checks")
    vulns: list[dict[str, str]] = []

    # Check for directory listing
    root_body = _curl_body(base)
    if "Index of" in root_body:
        vulns.append({"type": "Directory Listing", "path": "/", "severity": "Low"})

    # Check for default pages
    default_pages = ["/default.html", "/index.php", "/test.php", "/info.php"]
    for page in default_pages:
        full_url = f"{base}{page}"
        status = _curl_status_code(full_url)
        if status == "200":
            body = _curl_body(full_url)
            if len(body) > 100:
                vulns.append({"type": "Default Page", "path": page, "severity": "Info"})

    result["sections"]["quick_vulns"] = vulns

    # Summary
    result["summary"] = {
        "technology": tech_hints,
        "security_headers_missing": len(missing_headers),
        "interesting_paths_found": len(found_paths),
        "quick_vulns_found": len(vulns),
    }

    return result


def recon_report(result: dict[str, Any]) -> str:
    """Format recon result as readable report."""
    lines: list[str] = [
        "=" * 60,
        f"RECON REPORT: {result['target']}",
        f"Generated: {result['timestamp']}",
        "=" * 60,
    ]

    if result.get("error"):
        lines.append(f"\nERROR: {result['error']}")
        return "\n".join(lines)

    if result.get("summary"):
        lines.append("\nSUMMARY:")
        for k, v in result["summary"].items():
            lines.append(f"  {k}: {v}")

    if result["sections"].get("technology"):
        lines.append("\nTECHNOLOGY:")
        for k, v in result["sections"]["technology"].items():
            lines.append(f"  {k}: {v}")

    if result["sections"].get("interesting_paths"):
        lines.append("\nINTERESTING PATHS:")
        for p in result["sections"]["interesting_paths"]:
            lines.append(f"  [{p['status']}] {p['path']}")

    if result["sections"].get("security_headers"):
        sec = result["sections"]["security_headers"]
        lines.append("\nSECURITY HEADERS:")
        lines.append(f"  Present: {', '.join(sec.get('present', []))}")
        lines.append(f"  Missing: {', '.join(sec.get('missing', []))}")

    if result["sections"].get("quick_vulns"):
        lines.append("\nQUICK FINDINGS:")
        for v in result["sections"]["quick_vulns"]:
            lines.append(f"  [{v['severity']}] {v['type']} at {v['path']}")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [--quick]")
        sys.exit(1)
    target_url = sys.argv[1]
    is_quick = "--quick" in sys.argv
    res = recon_target(target_url, quick=is_quick)
    print(recon_report(res))
