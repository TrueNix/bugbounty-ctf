# Recreating CTF Labs Locally as Docker Compose

When a user wants to "copy" or "keep" a CTF target for offline practice, you can rebuild it from observed artifacts without needing shell access to the original box.

## What You Can Extract Remotely

| Artifact | How to get | What it gives you |
|----------|-----------|-------------------|
| HTML pages | `curl http://target:port/` | Full page templates, CSS, JS |
| JS source | Visible in browser or curl | Client-side logic, XSS sinks, product data |
| DB schema | SQLi UNION SELECT from sqlite_master | Table structure, column types |
| DB data | SQLi UNION SELECT all rows | Complete product/user/content data |
| Banner output | `nc target port` or curl | ASCII art, hints, service banners |
| Error paths | Trigger SQL errors | File paths, tech stack info |
| HTTP headers | `curl -I` or nmap -sV | Server versions, tech fingerprinting |

## Docker Compose Template Structure

```
lab-local/
├── docker-compose.yml
├── web8000/
│   └── index.php          # Vulnerable PHP app (recreated from HTML + SQLi)
├── web8080/
│   └── index.php          # Dev app with XSS (recreated from JS source)
├── web80/
│   └── index.html         # Apache default page (from curl)
├── banner3000/
│   ├── banner.txt         # ASCII art (from nc)
│   └── Dockerfile         # Tiny socat-based TCP banner
└── php-vuln.ini           # PHP config for error display
```

## Key Patterns

### PHP Built-in Dev Server (`php -S`)
Matches original PHP CLI dev server behavior exactly:
```yaml
command: php -S 0.0.0.0:8000 -t /app
```
Routes everything to index.php unless a real file exists.

### PHP Error Display
Original labs often have `display_errors=On`. Mount a custom ini:
```yaml
volumes:
  - ./php-vuln.ini:/usr/local/etc/php/conf.d/vuln.ini
```
With `php-vuln.ini`:
```ini
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
html_errors = On
```

### SQLite Database
Recreate from schema + data extracted via SQLi:
```php
$db = new SQLite3('/data/shop.sqlite');
// Insert all rows found via SQLi UNION SELECT
```

### TCP Banner Service
For non-HTTP services on random ports:
```dockerfile
FROM alpine:latest
RUN apk add --no-cache socat
COPY banner.txt /banner.txt
CMD exec socat -T2 TCP-LISTEN:3000,reuseaddr,fork SYSTEM:'cat /banner.txt'
```

## Verification Checklist

After building:
1. `curl http://localhost:8000/` matches original HTML
2. SQLi payloads produce same errors/results
3. XSS sinks are present in JS source
4. Banner service returns same content
5. All ports from original nmap scan are open

## Example: Marketplace Lab Recreation

From aclabs.pro Marketplace (10.10.10.236):
- Port 80: Apache default page (from curl)
- Port 8000: PHP shop with SQLi (recreated from HTML + DB schema via SQLi)
- Port 8080: PHP dev page with DOM XSS (recreated from JS source)
- Port 3000: TCP banner with ASCII art (from nc)
- Port 22: Erlang SSH (not recreated - needs actual Erlang SSH server)

All vulnerable behaviors reproduced exactly. See `/home/truenix/aclabs/marketplace-local/` for complete example.
