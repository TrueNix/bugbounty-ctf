# HTB Machine Recon & CTF Challenge Identification

## DuckDuckGo HTML Search Pattern

When you have an IP but don't know the machine name, use DuckDuckGo's HTML endpoint (bypasses JavaScript/CAPTCHA):

```
https://html.duckduckgo.com/html/?q=YOUR_QUERY
```

Extract results with regex:
```python
import re
snippets = re.findall(r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
for s in snippets:
    clean = re.sub(r'<[^>]+>', ' ', s).strip()
    print(clean)
```

## Machine Identification Queries (in priority order)

1. **Exact IP search**: `"10.10.10.XXX" hackthebox` or `"10.10.10.XXX" ctf`
2. **Unique page text**: Search for exact Russian/non-English strings from the page (e.g., `"Секретная лаборатория" ctf`)
3. **Combined characteristics**: `hackthebox nginx php machine 2025` (OS + web server + year)
4. **GitHub repos**: `github ctf "unique phrase from page"` - many CTF challenges have public source repos

## CTF Source Code Discovery

Many CTF challenges have public GitHub repos. Search for unique phrases:
- Page titles, warning messages, footer text
- Non-English text (Russian, Chinese, etc.) is especially searchable
- Look for repos with `SOLUTION.md` or `writeup.md` files
- Check for `docker-compose.yml` and `Dockerfile` to understand the challenge setup

## Machine Instability

HTB machines frequently crash, especially when:
- Sending rapid requests (rate limit triggers)
- SQLi/fuzzing tools hit the machine hard
- Machine has been running for a while

**Retry pattern:**
1. Machine unreachable → wait 2-5 minutes → retry ping/nmap
2. If still down after 5 minutes → user needs to restart on HTB platform
3. After restart → wait 60-120 seconds for full boot before scanning
4. If machine crashes mid-exploit → note what you were doing, restart, and continue from last known good state

## Web App Recon on HTB Machines

### Rate Limiting Detection
- Many HTB web challenges implement rate limiting (~10 requests per 60 seconds)
- Session-based: new sessions may bypass or have independent limits
- Watch for messages like "Too much attempts! Wait 60 seconds"
- Strategy: batch requests, wait between batches, use parallel sessions with different cookies

### Login Form Analysis
- Check if password field has a `name` attribute (missing name = client-side only?)
- Try sending both surname/username AND password parameters
- Test with common SQLi payloads: `' OR '1'='1' --`, `admin'--`
- Check response differences between baseline and with input (length changes indicate server processing)

### PHP Source Code Disclosure
- Try `php://filter/convert.base64-encode/resource=index.php` in any file parameter
- Try `.php.bak`, `.php.swp`, `.php~` for source code leaks
- Check for `phpinfo.php`, `info.php`, `test.php` default pages
