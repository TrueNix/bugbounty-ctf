"""OSINT module — open-source intelligence gathering for CTF and recon.

Handles:
- Subdomain enumeration via crt.sh, certificate transparency
- Google dorking for finding exposed files and endpoints
- Wayback machine lookups for historical content
- Metadata extraction from files (EXIF, document properties)
- DNS enumeration
- Technology fingerprinting from public sources

Usage:
    from bugbounty_ctf.osint import OSINTToolkit

    osint = OSINTToolkit()
    subs = osint.subdomain_enum("target.com")
    dorks = osint.google_dorks("target.com")
    history = osint.wayback_lookup("target.com")
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3

# OSINT scans deliberately hit hosts with broken/absent TLS (verify=False);
# silence the per-request InsecureRequestWarning so it does not bury findings.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]

# Response signatures of SaaS providers that serve an "unclaimed resource" page
# when a dangling CNAME points at a deprovisioned target. Used by
# OSINTToolkit.check_subdomain_takeover.
TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Fastly": ["Fastly error: unknown domain"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
    "Bitbucket": ["Repository not found"],
    "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "Surge.sh": ["project not found"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Readme.io": ["Project doesnt exist... yet!"],
    "Webflow": ["The page you are looking for doesn't exist or has been moved"],
    "Wordpress.com": ["Do you want to register"],
    "Acquia": ["The site you are looking for could not be found"],
}

GOOGLE_DORK_TEMPLATES = [
    "site:{domain} filetype:pdf",
    "site:{domain} filetype:txt",
    "site:{domain} filetype:env",
    "site:{domain} filetype:sql",
    "site:{domain} filetype:bak",
    "site:{domain} filetype:config",
    "site:{domain} filetype:xml",
    "site:{domain} filetype:json",
    "site:{domain} inurl:admin",
    "site:{domain} inurl:login",
    "site:{domain} inurl:dashboard",
    "site:{domain} inurl:config",
    "site:{domain} inurl:api",
    "site:{domain} inurl:upload",
    "site:{domain} inurl:debug",
    'site:{domain} intitle:"index of"',
    'site:{domain} intitle:"admin"',
    'site:{domain} "password"',
    'site:{domain} "secret"',
    'site:{domain} "api key"',
    'site:{domain} "token"',
    'site:{domain} "BEGIN RSA PRIVATE KEY"',
    "site:{domain} ext:php inurl:config",
    "site:{domain} ext:py inurl:settings",
    "site:{domain} ext:js inurl:api",
]

COMMON_SUBDOMAIN_PREFIXES = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "vpn",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "dashboard",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "internal",
    "intranet",
    "app",
    "apps",
    "auth",
    "sso",
    "cdn",
    "static",
    "assets",
    "docs",
    "wiki",
    "support",
    "help",
    "status",
    "monitor",
    "grafana",
    "prometheus",
    "kibana",
    "elastic",
    "db",
    "backup",
    "old",
    "new",
    "beta",
    "alpha",
    "stage",
    "ftp",
    "sftp",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "imap",
]


@dataclass
class OSINTFinding:
    """A finding from OSINT gathering."""

    source: str
    finding_type: str
    value: str = ""
    url: str = ""
    is_flag: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "finding_type": self.finding_type,
            "value": self.value[:500],
            "url": self.url,
            "is_flag": self.is_flag,
            "details": self.details,
        }


def _extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for pattern in FLAG_PATTERNS:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(set(flags))


def _run_cmd(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", "", -1


class OSINTToolkit:
    """Open-source intelligence gathering toolkit."""

    def __init__(self, *, timeout: int = 15) -> None:
        self.timeout = timeout
        self.findings: list[OSINTFinding] = []
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (bugbounty-ctf OSINT scanner)"

    def enumerate_all(self, domain: str) -> list[OSINTFinding]:
        """Run all OSINT checks against a domain."""
        self.findings = []
        self.subdomain_enum(domain)
        self.wayback_lookup(domain)
        self.dns_enum(domain)
        self.tech_fingerprint(domain)
        return self.findings

    def subdomain_enum(self, domain: str) -> list[str]:
        """Enumerate subdomains via certificate transparency (crt.sh) and DNS."""
        print(f"[*] Subdomain enumeration for {domain}")
        subdomains: set[str] = set()

        # crt.sh certificate transparency
        try:
            r = self.session.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=self.timeout,
            )
            if r.status_code == 200:
                certs = r.json()
                for cert in certs[:200]:
                    name = cert.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and domain in sub and sub != domain:
                            subdomains.add(sub)
                print(f"  [crt.sh] Found {len(subdomains)} subdomains")
        except Exception as e:
            print(f"  [-] crt.sh error: {e}")

        # DNS brute force common prefixes
        for prefix in COMMON_SUBDOMAIN_PREFIXES:
            candidate = f"{prefix}.{domain}"
            try:
                import socket

                ip = socket.gethostbyname(candidate)
                if ip and candidate not in subdomains:
                    subdomains.add(candidate)
            except socket.gaierror:
                pass
            except Exception:
                pass

        if subdomains:
            self.findings.append(
                OSINTFinding(
                    source="subdomain_enum",
                    finding_type="subdomains",
                    value=str(list(subdomains)[:20]),
                    details={"count": len(subdomains), "subdomains": list(subdomains)},
                )
            )

        for sub in sorted(subdomains):
            print(f"    {sub}")

        return list(subdomains)

    def google_dorks(self, domain: str) -> list[str]:
        """Generate Google dork queries for a domain.

        Note: Actual Google searching requires a browser or API.
        This generates the dork strings that the agent can use.
        """
        print(f"[*] Google dork generation for {domain}")
        dorks = [dork.format(domain=domain) for dork in GOOGLE_DORK_TEMPLATES]

        self.findings.append(
            OSINTFinding(
                source="google_dorks",
                finding_type="dorks",
                value=f"{len(dorks)} dork queries generated",
                details={"dorks": dorks},
            )
        )

        for dork in dorks[:10]:
            print(f"    {dork}")
        print(f"    ... and {len(dorks) - 10} more")

        return dorks

    def wayback_lookup(self, domain: str) -> list[dict[str, str]]:
        """Look up historical URLs via Wayback Machine."""
        print(f"[*] Wayback Machine lookup for {domain}")
        results: list[dict[str, str]] = []

        try:
            r = self.session.get(
                f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100",
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                if len(data) > 1:
                    for entry in data[1:50]:
                        if len(entry) >= 3:
                            url_path = entry[2]
                            timestamp = entry[1] if len(entry) > 1 else ""
                            results.append({"url": url_path, "timestamp": timestamp})
                    print(f"  [wayback] Found {len(results)} historical URLs")

                    interesting = [
                        entry
                        for entry in results
                        if any(
                            kw in entry["url"].lower()
                            for kw in [
                                "flag",
                                "secret",
                                "config",
                                "env",
                                "admin",
                                "backup",
                                "password",
                                ".sql",
                                ".bak",
                            ]
                        )
                    ]
                    if interesting:
                        self.findings.append(
                            OSINTFinding(
                                source="wayback",
                                finding_type="interesting_urls",
                                value=str([hit["url"] for hit in interesting[:10]]),
                                details={"interesting_count": len(interesting)},
                            )
                        )
                        for hit in interesting[:5]:
                            print(f"    [!] {hit['url']}")
        except Exception as e:
            print(f"  [-] Wayback error: {e}")

        return results

    def dns_enum(self, domain: str) -> dict[str, Any]:
        """Enumerate DNS records."""
        print(f"[*] DNS enumeration for {domain}")
        records: dict[str, list[str]] = {}

        for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            stdout, _, rc = _run_cmd(["dig", "+short", record_type, domain])
            if rc == 0 and stdout.strip():
                values = [v.strip() for v in stdout.strip().split("\n") if v.strip()]
                records[record_type] = values
                print(f"    {record_type}: {values}")

        if records:
            self.findings.append(
                OSINTFinding(
                    source="dns",
                    finding_type="dns_records",
                    value=str(records),
                    details=records,
                )
            )

            for txt in records.get("TXT", []):
                flags = _extract_flags(txt)
                if flags:
                    self.findings.append(
                        OSINTFinding(
                            source="dns",
                            finding_type="flag_in_txt",
                            value=txt,
                            is_flag=True,
                            details={"flags": flags},
                        )
                    )
                    print(f"    [FLAG] {flags}")

        return records

    def tech_fingerprint(self, domain: str) -> dict[str, str]:
        """Fingerprint technology from public sources."""
        print(f"[*] Technology fingerprinting for {domain}")
        tech: dict[str, str] = {}

        try:
            r = self.session.get(f"https://{domain}", timeout=self.timeout, verify=False)
            server = r.headers.get("Server", "")
            x_powered = r.headers.get("X-Powered-By", "")
            powered_by = r.headers.get("X-AspNet-Version", "")

            if server:
                tech["server"] = server
            if x_powered:
                tech["x-powered-by"] = x_powered
            if powered_by:
                tech["aspnet"] = powered_by

            cookies = r.headers.get("Set-Cookie", "")
            if "PHPSESSID" in cookies:
                tech["language"] = "PHP"
            elif "JSESSIONID" in cookies:
                tech["language"] = "Java"
            elif "sessionid" in cookies.lower():
                tech["framework"] = "Django"
            elif "connect.sid" in cookies:
                tech["framework"] = "Express"

            if tech:
                self.findings.append(
                    OSINTFinding(
                        source="tech_fingerprint",
                        finding_type="technology",
                        value=str(tech),
                        details=tech,
                    )
                )
                for k, v in tech.items():
                    print(f"    {k}: {v}")
        except Exception as e:
            print(f"  [-] Fingerprint error: {e}")

        return tech

    def check_subdomain_takeover(self, subdomain: str) -> dict[str, Any]:
        """Check a subdomain for a dangling-resource takeover fingerprint.

        Fetches the host and matches the response against signatures of common
        SaaS providers that serve an "unclaimed resource" page when a CNAME
        points at a deprovisioned target — the classic subdomain-takeover
        precondition. A match is a strong (but not absolute) indicator; always
        confirm the CNAME and claim path before reporting.
        """
        print(f"[*] Subdomain takeover check for {subdomain}")
        body = ""
        for scheme in ("https", "http"):
            try:
                r = self.session.get(f"{scheme}://{subdomain}", timeout=self.timeout, verify=False)
                body = r.text
                if body:
                    break
            except requests.exceptions.RequestException:
                continue

        result: dict[str, Any] = {"subdomain": subdomain, "vulnerable": False}
        if not body:
            return result

        for service, signatures in TAKEOVER_FINGERPRINTS.items():
            for sig in signatures:
                if sig.lower() in body.lower():
                    result.update({"vulnerable": True, "service": service, "evidence": sig})
                    print(f"  [!] Possible {service} takeover: matched {sig!r}")
                    self.findings.append(
                        OSINTFinding(
                            source="subdomain_takeover",
                            finding_type="takeover",
                            value=f"{subdomain} → {service}",
                            details={"service": service, "evidence": sig},
                        )
                    )
                    return result

        print("  [-] No takeover fingerprint matched")
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract metadata from a file (images, documents, PDFs)."""
        print(f"[*] Metadata extraction for {file_path}")
        metadata: dict[str, str] = {}

        # exiftool
        stdout, _, rc = _run_cmd(["exiftool", file_path])
        if rc == 0 and stdout.strip():
            for line in stdout.strip().split("\n"):
                if ":" in line:
                    key, _, val = line.partition(":")
                    metadata[key.strip()] = val.strip()

        # strings for hidden data
        stdout, _, _ = _run_cmd(["strings", file_path])
        flags = _extract_flags(stdout)
        if flags:
            self.findings.append(
                OSINTFinding(
                    source="metadata",
                    finding_type="flag_in_file",
                    value=flags[0],
                    is_flag=True,
                    details={"flags": flags},
                )
            )
            print(f"  [FLAG] {flags}")

        interesting_patterns = [
            (r"password[=:]\s*\S+", "password"),
            (r"email[=:]\s*\S+@", "email"),
            (r"https?://[^\s]+", "url"),
            (r"/(?:home|Users?|root)/[^\s]+", "filepath"),
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "ip_address"),
        ]

        for pattern, ptype in interesting_patterns:
            matches = re.findall(pattern, stdout, re.IGNORECASE)
            if matches:
                metadata[f"strings_{ptype}"] = str(list(set(matches))[:10])
                print(f"  [strings] {ptype}: {matches[:5]}")

        if metadata:
            self.findings.append(
                OSINTFinding(
                    source="metadata",
                    finding_type="file_metadata",
                    value=str(metadata)[:500],
                    details=metadata,
                )
            )

        return metadata

    def get_findings(self) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str, str, bool, str]] = set()
        results: list[dict[str, Any]] = []
        for finding in self.findings:
            key = (
                finding.source,
                finding.finding_type,
                finding.value,
                finding.url,
                finding.is_flag,
                repr(sorted(finding.details.items())),
            )
            if key in seen:
                continue
            seen.add(key)
            results.append(finding.to_dict())
        return results
