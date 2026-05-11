"""
Hermes Security Testing Engine

Systematic payload testing with response diffing, attack surface mapping,
and state persistence. Designed to be imported via execute_code.

Usage:
    exec(open(".../security_engine.py").read())
    
    # Initialize scanner
    scanner = SecurityScanner("http://target/")
    
    # Test a single endpoint
    result = scanner.test_endpoint("/login", "POST", {"username": "admin"})
    
    # Run full payload set against an endpoint
    results = scanner.run_payloads("/login", "POST", {"username": "{PAYLOAD}"})
    
    # Map attack surface
    surface = scanner.map_surface("/")
    
    # Get findings
    print(scanner.findings)
"""

import requests
import time
import hashlib
import json
import re
import os
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class ResponseDiff:
    """Compare two HTTP responses and identify meaningful differences."""
    
    def __init__(self, baseline, test_response):
        self.baseline = baseline
        self.test = test_response
        self.differences = []
        self.interesting = False
        self.indicators = []
        
    def analyze(self):
        """Run all diff checks and return analysis."""
        self._check_status_code()
        self._check_length()
        self._check_timing()
        self._check_content()
        self._check_errors()
        self._check_redirects()
        self._check_headers()
        self._check_security_indicators()
        
        return {
            "status_changed": self.baseline.status_code != self.test.status_code,
            "length_diff": abs(len(self.baseline.text) - len(self.test.text)),
            "timing_diff": getattr(self.test, 'response_time', 0) - getattr(self.baseline, 'response_time', 0),
            "content_differs": self.baseline.text != self.test.text,
            "interesting": self.interesting,
            "indicators": self.indicators,
            "differences": self.differences
        }
    
    def _check_status_code(self):
        if self.baseline.status_code != self.test.status_code:
            self.differences.append(f"Status: {self.baseline.status_code} → {self.test.status_code}")
            self.interesting = True
            self.indicators.append("status_code_change")
    
    def _check_length(self):
        base_len = len(self.baseline.text)
        test_len = len(self.test.text)
        diff = abs(test_len - base_len)
        
        if base_len > 0 and diff / base_len > 0.05:  # 5% difference
            self.differences.append(f"Length: {base_len} → {test_len} ({diff:+d} bytes)")
            self.interesting = True
            self.indicators.append("length_change")
        elif base_len == 0 and test_len > 100:
            self.differences.append(f"Length: 0 → {test_len}")
            self.interesting = True
            self.indicators.append("content_appeared")
    
    def _check_timing(self):
        base_time = getattr(self.baseline, 'response_time', 0)
        test_time = getattr(self.test, 'response_time', 0)
        
        if test_time > base_time * 2 and test_time > 1.0:
            self.differences.append(f"Timing: {base_time:.3f}s → {test_time:.3f}s")
            self.interesting = True
            self.indicators.append("timing_delay")
    
    def _check_content(self):
        """Check for interesting content patterns."""
        patterns = {
            "sql_error": [r"SQL syntax", r"You have an error in your SQL", r"sqlite3\.OperationalError", 
                          r"pymysql\.err", r"psycopg2\.ProgrammingError", r"ORA-\d+"],
            "command_output": [r"uid=\d+", r"gid=\d+", r"groups=\d+", r"root:", r"bin:", r"daemon:"],
            "file_contents": [r"/bin/bash", r"/usr/sbin/nologin", r"root:x:0:0"],
            "ssti_evaluated": [r"\b49\b", r"\b343\b"],
            "xxe_triggered": [r"root:x:0:", r"daemon:x:1:", r"bin:x:2:"],
            "auth_bypass": [r"welcome", r"dashboard", r"admin panel", r"authenticated"],
            "info_leak": [r"version", r"stack trace", r"traceback", r"debug", r"error in"],
            "flag_found": [r"flag\{", r"CTF\{", r"pwn\{", r"secret\{", r"key\{"]
        }
        
        for category, regexes in patterns.items():
            for regex in regexes:
                if re.search(regex, self.test.text, re.IGNORECASE):
                    self.indicators.append(category)
                    self.interesting = True
                    self.differences.append(f"Pattern found: {category}")
                    break
    
    def _check_errors(self):
        """Detect error responses that weren't in baseline."""
        error_patterns = [r"error", r"exception", r"failed", r"invalid", r"denied", r"forbidden"]
        
        baseline_has_error = any(re.search(p, self.baseline.text, re.IGNORECASE) for p in error_patterns)
        test_has_error = any(re.search(p, self.test.text, re.IGNORECASE) for p in error_patterns)
        
        if test_has_error and not baseline_has_error:
            self.differences.append("New error message detected")
            self.interesting = True
            self.indicators.append("error_appeared")
    
    def _check_redirects(self):
        if self.test.status_code in (301, 302, 303, 307, 308):
            location = self.test.headers.get('Location', '')
            self.differences.append(f"Redirect to: {location}")
            self.interesting = True
            self.indicators.append("redirect")
    
    def _check_headers(self):
        """Check for interesting header changes."""
        interesting_headers = ['set-cookie', 'x-powered-by', 'server', 'access-control-allow-origin']
        
        for header in interesting_headers:
            base_val = self.baseline.headers.get(header, '')
            test_val = self.test.headers.get(header, '')
            if base_val != test_val:
                self.differences.append(f"Header {header}: '{base_val}' → '{test_val}'")
                if header == 'set-cookie':
                    self.interesting = True
                    self.indicators.append("cookie_set")
    
    def _check_security_indicators(self):
        """Check for WAF responses, rate limiting, etc."""
        waf_patterns = [
            r"blocked", r"forbidden", r"rate.limit", r"too.many", r"cloudflare", 
            r"akamai", r"incapsula", r"mod.security", r"request.blocked"
        ]
        
        for pattern in waf_patterns:
            if re.search(pattern, self.test.text, re.IGNORECASE) and \
               not re.search(pattern, self.baseline.text, re.IGNORECASE):
                self.differences.append(f"Defense triggered: {pattern}")
                self.indicators.append("defense_triggered")
                break


class SecurityScanner:
    """Main security testing engine."""
    
    def __init__(self, base_url, session=None, state_file=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.state_file = state_file or os.path.expanduser("~/.hermes/security_state.json")
        self.findings = []
        self.test_history = []
        self.attack_surface = {}
        self.defenses_detected = []
        self._load_state()
    
    def _load_state(self):
        """Load previous testing state if exists."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    state = json.load(f)
                if state.get("base_url") == self.base_url:
                    self.findings = state.get("findings", [])
                    self.test_history = state.get("test_history", [])
                    self.attack_surface = state.get("attack_surface", {})
                    self.defenses_detected = state.get("defenses_detected", [])
            except:
                pass
    
    def _save_state(self):
        """Save current testing state."""
        state = {
            "base_url": self.base_url,
            "findings": self.findings,
            "test_history": self.test_history,
            "attack_surface": self.attack_surface,
            "defenses_detected": self.defenses_detected,
            "updated_at": datetime.now().isoformat()
        }
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _make_request(self, method, url, **kwargs):
        """Make HTTP request with timing measurement."""
        start = time.time()
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            response.response_time = time.time() - start
            return response
        except requests.exceptions.RequestException as e:
            response = requests.Response()
            response.status_code = 0
            response.text = f"Request failed: {e}"
            response.response_time = time.time() - start
            return response
    
    def get_baseline(self, method, url, **kwargs):
        """Establish baseline response for an endpoint."""
        return self._make_request(method, url, **kwargs)
    
    def test_payload(self, baseline, method, url, payload_data, payload_name="test"):
        """Test a single payload against a baseline."""
        start = time.time()
        
        # Replace {PAYLOAD} placeholder if present
        if isinstance(payload_data, dict):
            test_data = {}
            for k, v in payload_data.items():
                if isinstance(v, str) and '{PAYLOAD}' in v:
                    test_data[k] = v.replace('{PAYLOAD}', payload_name)
                else:
                    test_data[k] = v
        else:
            test_data = payload_data
        
        kwargs = {}
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            if isinstance(test_data, dict):
                # Try form data first, then JSON
                kwargs['data'] = test_data
            else:
                kwargs['data'] = test_data
        else:
            kwargs['params'] = test_data
        
        response = self._make_request(method, url, **kwargs)
        
        # Analyze differences
        diff = ResponseDiff(baseline, response)
        analysis = diff.analyze()
        
        result = {
            "payload": payload_name,
            "method": method,
            "url": url,
            "baseline_status": baseline.status_code,
            "test_status": response.status_code,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def run_payload_set(self, baseline, method, url, payloads, param_name="input"):
        """Run a set of payloads against an endpoint."""
        results = []
        
        for payload_name, payload_value in payloads.items():
            # Create payload data with placeholder replacement
            payload_data = {param_name: payload_value}
            
            result = self.test_payload(baseline, method, url, payload_data, payload_name)
            results.append(result)
            
            # Record in history
            self.test_history.append({
                "endpoint": url,
                "method": method,
                "payload": payload_name,
                "interesting": result["analysis"]["interesting"],
                "indicators": result["analysis"]["indicators"]
            })
            
            # Auto-add findings for interesting results
            if result["analysis"]["interesting"]:
                finding = {
                    "type": "potential_vulnerability",
                    "endpoint": url,
                    "method": method,
                    "payload": payload_name,
                    "indicators": result["analysis"]["indicators"],
                    "details": result["analysis"]["differences"],
                    "timestamp": datetime.now().isoformat()
                }
                self.findings.append(finding)
        
        self._save_state()
        return results
    
    def map_surface(self, start_url="/"):
        """Map the attack surface by crawling and extracting inputs."""
        url = urljoin(self.base_url, start_url)
        
        try:
            response = self.session.get(url, timeout=10)
        except:
            return {"error": "Could not reach target"}
        
        # Extract forms
        forms = []
        form_pattern = r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, response.text, re.DOTALL | re.IGNORECASE):
            method = match.group(1).upper()
            action = match.group(2)
            form_html = match.group(3)
            
            # Extract inputs
            inputs = []
            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:value=["\']([^"\']*)["\'][^>]*)?/?>', form_html, re.IGNORECASE):
                inputs.append({
                    "name": inp.group(1),
                    "value": inp.group(2) or "",
                    "type": "text"
                })
            
            forms.append({
                "method": method,
                "action": urljoin(self.base_url, action),
                "inputs": inputs
            })
        
        # Extract links (potential endpoints)
        links = []
        for match in re.finditer(r'href=["\']([^"\']*)["\']', response.text, re.IGNORECASE):
            link = match.group(1)
            if link and not link.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                links.append(urljoin(self.base_url, link))
        
        surface = {
            "url": url,
            "status_code": response.status_code,
            "forms": forms,
            "links": list(set(links)),
            "headers": dict(response.headers),
            "tech_hints": self._detect_technology(response)
        }
        
        self.attack_surface[start_url] = surface
        self._save_state()
        return surface
    
    def _detect_technology(self, response):
        """Detect technology stack from response."""
        hints = []
        
        server = response.headers.get('Server', '')
        if 'werkzeug' in server.lower():
            hints.append("Flask/Python (Werkzeug)")
        if 'nginx' in server.lower():
            hints.append("nginx")
        if 'apache' in server.lower():
            hints.append("Apache")
        
        x_powered = response.headers.get('X-Powered-By', '')
        if x_powered:
            hints.append(f"X-Powered-By: {x_powered}")
        
        set_cookie = response.headers.get('Set-Cookie', '')
        if 'sessionid=' in set_cookie.lower():
            hints.append("Django/Python")
        if 'PHPSESSID' in set_cookie:
            hints.append("PHP")
        if 'connect.sid' in set_cookie:
            hints.append("Node.js/Express")
        
        if 'jinja' in response.text.lower():
            hints.append("Jinja2 template engine")
        
        return hints
    
    def test_common_vulns(self, url, method="GET", params=None, data=None):
        """Test an endpoint for common vulnerabilities."""
        results = {}
        
        # Determine request type and data
        if method.upper() in ('POST', 'PUT', 'PATCH'):
            test_data = data or {}
            kwargs = {'data': test_data}
        else:
            test_data = params or {}
            kwargs = {'params': test_data}
        
        baseline = self._make_request(method, url, **kwargs)
        
        # SQL Injection tests
        sqli_payloads = {
            "single_quote": "'",
            "or_true": "' OR 1=1--",
            "or_true_alt": "' OR '1'='1",
            "comment": "admin'--",
            "union_null": "' UNION SELECT NULL--",
        }
        
        # Find the parameter to test
        test_param = None
        if isinstance(test_data, dict) and test_data:
            test_param = list(test_data.keys())[0]
        elif isinstance(kwargs.get('params'), dict) and kwargs['params']:
            test_param = list(kwargs['params'].keys())[0]
        
        if test_param:
            results["sqli"] = self.run_payload_set(
                baseline, method, url, sqli_payloads, test_param
            )
        
        # SSTI test
        if test_param:
            ssti_payloads = {"ssti_basic": "{{7*7}}"}
            results["ssti"] = self.run_payload_set(
                baseline, method, url, ssti_payloads, test_param
            )
        
        return {
            "baseline": {
                "status": baseline.status_code,
                "length": len(baseline.text),
                "timing": baseline.response_time
            },
            "tests": results
        }
    
    def get_summary(self):
        """Get testing summary."""
        return {
            "target": self.base_url,
            "findings_count": len(self.findings),
            "tests_run": len(self.test_history),
            "interesting_tests": sum(1 for t in self.test_history if t.get("interesting")),
            "defenses_detected": self.defenses_detected,
            "findings": self.findings,
            "last_updated": datetime.now().isoformat()
        }
