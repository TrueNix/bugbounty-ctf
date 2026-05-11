"""
Web Recon Automation: Systematic recon against a web target.
Generates structured recon report.

Usage:
    exec(open("scripts/web_recon.py").read())
    result = recon_target("http://target.com")
    result = recon_target("https://api.target.com", quick=True)
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

def run_cmd(cmd, timeout=30):
    """Run command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "[TIMEOUT]", -1
    except Exception as e:
        return "", str(e), -1

def recon_target(url, quick=False):
    """Full recon workflow against a target URL."""
    result = {
        "target": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "quick_mode": quick,
        "sections": {},
    }
    
    parsed = urlparse(url)
    host = parsed.hostname
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)
    
    # 1. Basic HTTP Info
    print(f"[*] Checking basic HTTP info for {url}")
    stdout, stderr, rc = run_cmd(f"curl -sI -L --max-time 10 {url}")
    result["sections"]["http_headers"] = {}
    if stdout:
        for line in stdout.split('\n'):
            if ':' in line:
                key, _, val = line.partition(':')
                result["sections"]["http_headers"][key.strip().lower()] = val.strip()
    
    # Extract tech hints
    tech_hints = {}
    headers = result["sections"].get("http_headers", {})
    if 'server' in headers:
        tech_hints['server'] = headers['server']
    if 'x-powered-by' in headers:
        tech_hints['framework'] = headers['x-powered-by']
    if 'set-cookie' in headers:
        cookie = headers['set-cookie']
        if 'PHPSESSID' in cookie:
            tech_hints['language'] = 'PHP'
        elif 'JSESSIONID' in cookie:
            tech_hints['language'] = 'Java'
        elif 'csrftoken' in cookie:
            tech_hints['framework'] = 'Django'
    result["sections"]["technology"] = tech_hints
    
    # 2. robots.txt & sitemap
    print(f"[*] Checking robots.txt and sitemap")
    for path in ['/robots.txt', '/sitemap.xml']:
        stdout, _, _ = run_cmd(f"curl -s --max-time 5 {scheme}://{host}:{port}{path}")
        if stdout and '404' not in stdout[:50]:
            result["sections"][path[1:]] = stdout[:2000]
    
    # 3. Common paths (quick check)
    print(f"[*] Checking common paths")
    common_paths = [
        '/admin', '/login', '/api', '/api/v1', '/graphql',
        '/.env', '/config.php', '/wp-admin', '/phpinfo.php',
        '/server-status', '/actuator', '/swagger.json',
        '/.git/config', '/backup.sql', '/debug',
    ]
    found_paths = []
    for path in common_paths:
        stdout, _, _ = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {scheme}://{host}:{port}{path}")
        if stdout and stdout not in ['000', '404']:
            found_paths.append({"path": path, "status": stdout})
    result["sections"]["interesting_paths"] = found_paths
    
    if not quick:
        # 4. Subdomain enumeration (if domain provided)
        print(f"[*] Checking for subdomains")
        stdout, _, _ = run_cmd(f"curl -s --max-time 10 https://crt.sh/?q={host}&output=json")
        subdomains = set()
        if stdout:
            try:
                certs = json.loads(stdout)
                for cert in certs[:50]:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if '*' not in sub:
                            subdomains.add(sub)
            except:
                pass
        result["sections"]["subdomains"] = list(subdomains)[:20]
    
    # 5. Security headers check
    print(f"[*] Checking security headers")
    sec_headers = {
        'strict-transport-security': 'HSTS missing',
        'content-security-policy': 'CSP missing',
        'x-content-type-options': 'X-Content-Type-Options missing',
        'x-frame-options': 'X-Frame-Options missing',
        'x-xss-protection': 'X-XSS-Protection missing',
        'referrer-policy': 'Referrer-Policy missing',
    }
    missing_headers = []
    for header, issue in sec_headers.items():
        if header not in headers:
            missing_headers.append(issue)
    result["sections"]["security_headers"] = {
        "present": [h for h in sec_headers if h in headers],
        "missing": missing_headers,
    }
    
    # 6. Quick vuln checks
    print(f"[*] Running quick vulnerability checks")
    vulns = []
    
    # Check for directory listing
    stdout, _, _ = run_cmd(f"curl -s --max-time 5 {scheme}://{host}:{port}/")
    if 'Index of' in stdout:
        vulns.append({"type": "Directory Listing", "path": "/", "severity": "Low"})
    
    # Check for default pages
    default_pages = ['/default.html', '/index.php', '/test.php', '/info.php']
    for page in default_pages:
        stdout, _, _ = run_cmd(f"curl -s --max-time 5 {scheme}://{host}:{port}{page}")
        if stdout and len(stdout) > 100:
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


def recon_report(result):
    """Format recon result as readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"RECON REPORT: {result['target']}")
    lines.append(f"Generated: {result['timestamp']}")
    lines.append("=" * 60)
    
    if result.get('summary'):
        lines.append("\nSUMMARY:")
        for k, v in result['summary'].items():
            lines.append(f"  {k}: {v}")
    
    if result['sections'].get('technology'):
        lines.append("\nTECHNOLOGY:")
        for k, v in result['sections']['technology'].items():
            lines.append(f"  {k}: {v}")
    
    if result['sections'].get('interesting_paths'):
        lines.append("\nINTERESTING PATHS:")
        for p in result['sections']['interesting_paths']:
            lines.append(f"  [{p['status']}] {p['path']}")
    
    if result['sections'].get('security_headers'):
        sec = result['sections']['security_headers']
        lines.append(f"\nSECURITY HEADERS:")
        lines.append(f"  Present: {', '.join(sec.get('present', []))}")
        lines.append(f"  Missing: {', '.join(sec.get('missing', []))}")
    
    if result['sections'].get('quick_vulns'):
        lines.append("\nQUICK FINDINGS:")
        for v in result['sections']['quick_vulns']:
            lines.append(f"  [{v['severity']}] {v['type']} at {v['path']}")
    
    return '\n'.join(lines)
