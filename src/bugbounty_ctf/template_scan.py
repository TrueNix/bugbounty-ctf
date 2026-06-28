"""Template-driven discovery — the open, self-contained Nessus alternative.

Self-contained by default, accelerated and refreshed when online:

1. ``builtin_template_scan`` — a dependency-free engine over templates bundled in
   the package (``data/templates.json``). Works fully offline, no external tools.

2. ``nuclei_scan`` — uses the open ``nuclei`` engine for breadth; auto-downloads
   the binary (``ensure_nuclei``) and refreshes community templates each run when
   online, falling back to the builtin engine otherwise. No proprietary plugins.

3. ``correlate_cves`` — the "stop trusting the version banner" fix: map the
   service/version fingerprints we collect to CVEs via a bundled dataset
   (``data/cve_db.json``), plus a live NVD pull per product when ``online`` is
   set (``update_cve_db``, cached + refreshed per run). Generic matching; CVE
   data is external, never hardcoded per target.

Usage:
    from bugbounty_ctf.template_scan import builtin_template_scan, nuclei_scan, correlate_cves

    builtin_template_scan("http://target/", scanner=scanner)            # offline
    nuclei_scan("http://target/", scanner=scanner)                      # auto-provisions nuclei
    correlate_cves([{"product": "roundcube", "version": "1.6.10"}], online=True)
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_BIN_DIR = os.path.expanduser("~/.hermes/bin")
_NUCLEI_RELEASE = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
_cve_cache: dict[str, list[dict[str, str]]] | None = None
_tpl_cache: list[dict[str, Any]] | None = None

# A tiny, factual seed so the correlator is useful out of the box. Production
# use should load a full NVD/Vulners feed via load_cve_db() or online=True.
_SEED_CVE_DB: dict[str, list[dict[str, str]]] = {
    "roundcube": [
        {"cve": "CVE-2025-49113", "affected": "<=1.6.10", "severity": "critical"},
    ],
}


@dataclass
class TemplateFinding:
    """One result from a template engine (nuclei) or a CVE correlation."""

    template_id: str
    name: str
    severity: str = "info"
    matched_at: str = ""
    tags: list[str] = field(default_factory=list)
    source: str = "nuclei"

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "tags": self.tags,
            "source": self.source,
        }


def _nuclei_path() -> str | None:
    """Return a usable nuclei binary path: PATH first, then the local cache."""
    found = shutil.which("nuclei")
    if found:
        return found
    cached = os.path.join(_BIN_DIR, "nuclei")
    return cached if os.path.exists(cached) else None


def nuclei_available() -> bool:
    """True if a ``nuclei`` binary is available (on PATH or in the local cache)."""
    return _nuclei_path() is not None


def ensure_nuclei(*, auto_install: bool = True, fetcher: Any | None = None) -> str | None:
    """Return a nuclei binary path, downloading the latest release if needed.

    Keeps the toolkit self-contained-on-demand: if nuclei is not installed, the
    matching release for this OS/arch is fetched from GitHub into ``~/.hermes/bin``
    (once; reused after). Returns None if unavailable and not installable
    (offline) — callers fall back to ``builtin_template_scan``.
    """
    existing = _nuclei_path()
    if existing or not auto_install:
        return existing

    try:
        import io
        import platform
        import zipfile

        import requests

        get = fetcher or requests.get
        release = get(_NUCLEI_RELEASE, timeout=30).json()
        osname = {"linux": "linux", "darwin": "macos", "windows": "windows"}.get(
            platform.system().lower(), platform.system().lower()
        )
        arch = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
        }.get(platform.machine().lower(), platform.machine().lower())
        asset = next(
            (
                a
                for a in release.get("assets", [])
                if osname in a["name"].lower()
                and arch in a["name"].lower()
                and a["name"].endswith(".zip")
            ),
            None,
        )
        if not asset:
            print(f"[-] no nuclei release asset for {osname}/{arch}")
            return None
        blob = get(asset["browser_download_url"], timeout=180).content
        os.makedirs(_BIN_DIR, exist_ok=True)
        dest = os.path.join(_BIN_DIR, "nuclei")
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            member = next(
                (
                    n
                    for n in zf.namelist()
                    if n in ("nuclei", "nuclei.exe") or n.endswith("/nuclei")
                ),
                None,
            )
            if not member:
                return None
            with zf.open(member) as src, open(dest, "wb") as out:
                out.write(src.read())
        os.chmod(dest, 0o755)
        print(f"[+] installed nuclei → {dest}")
        return dest
    except Exception as e:
        print(f"[-] nuclei auto-install failed: {str(e)[:80]}")
        return None


def nuclei_scan(
    target: str,
    *,
    scanner: Any | None = None,
    severity: str = "medium,high,critical",
    tags: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 600,
    auto_install: bool = True,
    update_templates: bool = True,
) -> list[TemplateFinding]:
    """Run nuclei against ``target`` and return parsed findings.

    Auto-provisions nuclei (downloads the binary if missing) and refreshes its
    community templates each run by default, so template scanning works out of
    the box. Records findings to the second brain (``nuclei:<template-id>``).
    Returns an empty list (never an error) when nuclei can't be provisioned
    (offline) — callers fall back to :func:`builtin_template_scan`.
    """
    binary = ensure_nuclei(auto_install=auto_install)
    if not binary:
        print("[*] nuclei unavailable — use builtin_template_scan() for offline coverage")
        return []

    if update_templates:
        with contextlib.suppress(Exception):
            subprocess.run(
                [binary, "-update-templates", "-silent"], capture_output=True, timeout=300
            )

    cmd = [binary, "-silent", "-jsonl", "-severity", severity, "-u", target]
    if tags:
        cmd += ["-tags", tags]
    if extra_args:
        cmd += extra_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[-] nuclei timed out after {timeout}s")
        return []
    except OSError as e:
        print(f"[-] nuclei failed to launch: {e}")
        return []

    return _parse_nuclei(result.stdout, scanner=scanner)


def _parse_nuclei(stdout: str, *, scanner: Any | None = None) -> list[TemplateFinding]:
    findings: list[TemplateFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info", {}) or {}
        tid = str(obj.get("template-id") or obj.get("templateID") or "unknown")
        finding = TemplateFinding(
            template_id=tid,
            name=str(info.get("name") or tid),
            severity=str(info.get("severity") or "info"),
            matched_at=str(obj.get("matched-at") or obj.get("host") or ""),
            tags=[str(t) for t in (info.get("tags") or [])],
            source="nuclei",
        )
        findings.append(finding)
        if scanner is not None:
            with contextlib.suppress(Exception):
                scanner._record_finding(
                    endpoint=finding.matched_at,
                    method="",
                    payload=finding.template_id,
                    indicators=["nuclei", finding.severity],
                    details=[finding.name],
                    vuln_type=f"nuclei:{finding.template_id}",
                    source=f"nuclei:{finding.template_id}",
                )
    print(f"[*] nuclei: {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------- CVE correlation
def _parse_version(v: str) -> tuple[int, ...]:
    # Take only the LEADING digits of each dotted part so patch suffixes like
    # "9.7p1" -> (9, 7) compare correctly (a trailing-digit grab gave (9, 71)).
    nums: list[int] = []
    for part in v.strip().split("."):
        m = re.match(r"\d+", part)
        nums.append(int(m.group(0)) if m else 0)
    return tuple(nums)


def _cmp(a: str, b: str) -> int:
    va, vb = _parse_version(a), _parse_version(b)
    width = max(len(va), len(vb))
    va += (0,) * (width - len(va))
    vb += (0,) * (width - len(vb))
    return (va > vb) - (va < vb)


def version_matches(version: str, spec: str) -> bool:
    """Test a version against a spec: ``<=x`` ``<x`` ``>=x`` ``>x`` ``==x`` ``a-b`` or ``*``."""
    spec = spec.strip()
    if spec in ("", "*"):
        return True
    if "-" in spec and spec[0] not in "<>=":
        lo, hi = (s.strip() for s in spec.split("-", 1))
        return _cmp(version, lo) >= 0 and _cmp(version, hi) <= 0
    for op in ("<=", ">=", "==", "<", ">"):
        if spec.startswith(op):
            target = spec[len(op) :].strip()
            c = _cmp(version, target)
            return {
                "<=": c <= 0,
                ">=": c >= 0,
                "==": c == 0,
                "<": c < 0,
                ">": c > 0,
            }[op]
    return _cmp(version, spec) == 0


def load_cve_db(path: str) -> dict[str, list[dict[str, str]]]:
    """Load a CVE dataset: ``{product: [{cve, affected, severity}, ...]}``."""
    with open(path) as f:
        data: dict[str, list[dict[str, str]]] = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def default_cve_db() -> dict[str, list[dict[str, str]]]:
    """Return the CVE dataset bundled in the package (cached)."""
    global _cve_cache
    if _cve_cache is None:
        path = os.path.join(_DATA_DIR, "cve_db.json")
        try:
            _cve_cache = load_cve_db(path)
        except OSError:
            _cve_cache = dict(_SEED_CVE_DB)
    return _cve_cache


def load_templates(path: str | None = None) -> list[dict[str, Any]]:
    """Load detection templates (defaults to the bundled set; cached)."""
    global _tpl_cache
    if path is not None:
        with open(path) as f:
            loaded: list[dict[str, Any]] = json.load(f)
        return loaded
    if _tpl_cache is None:
        try:
            with open(os.path.join(_DATA_DIR, "templates.json")) as f:
                _tpl_cache = json.load(f)
        except OSError:
            _tpl_cache = []
    return _tpl_cache


def _template_matches(text: str, status: int, match: dict[str, Any]) -> bool:
    exp = match.get("status")
    if exp is not None:
        allowed = exp if isinstance(exp, list) else [exp]
        if status not in allowed:
            return False
    words = match.get("words") or []
    if words and not all(w in text for w in words):
        return False
    words_any = match.get("words_any") or []
    if words_any and not any(w in text for w in words_any):
        return False
    rx = match.get("regex")
    if rx and not re.search(rx, text):
        return False
    # Require at least one positive condition so a template can't match everything.
    return bool(words or words_any or rx or exp is not None)


def builtin_template_scan(
    base_url: str,
    *,
    scanner: Any | None = None,
    templates: list[dict[str, Any]] | None = None,
    workers: int = 16,
) -> list[TemplateFinding]:
    """Dependency-free template scan using the bundled detections (no nuclei).

    Requests each template's path through the scanner and matches the response,
    so the toolkit can do template-based discovery fully self-contained. Hits are
    recorded to the second brain (provenance ``template:<id>``).
    """
    from bugbounty_ctf.engine import SecurityScanner, derive_base_url

    if scanner is None:
        scanner = SecurityScanner(derive_base_url(base_url))
    origin = derive_base_url(base_url)
    tpls = templates if templates is not None else load_templates()

    def run(tpl: dict[str, Any]) -> TemplateFinding | None:
        target = urljoin(origin + "/", tpl.get("path", "/").lstrip("/"))
        r = scanner._make_request("GET", target)
        if r.status_code in (0, 404):
            return None
        if not _template_matches(r.text, r.status_code, tpl.get("match", {})):
            return None
        return TemplateFinding(
            template_id=str(tpl.get("id", "?")),
            name=str(tpl.get("name", tpl.get("id", "?"))),
            severity=str(tpl.get("severity", "info")),
            matched_at=target,
            tags=[str(t) for t in (tpl.get("tags") or [])],
            source="builtin-template",
        )

    findings: list[TemplateFinding] = []
    if workers <= 1:
        results = [run(t) for t in tpls]
    else:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(run, tpls))
    for f in results:
        if f is None:
            continue
        findings.append(f)
        with contextlib.suppress(Exception):
            scanner._record_finding(
                endpoint=f.matched_at,
                method="GET",
                payload=f.template_id,
                indicators=["template", f.severity],
                details=[f.name],
                vuln_type=f"template:{f.template_id}",
                source=f"template:{f.template_id}",
            )
        print(f"[+] template {f.template_id} ({f.severity}) → {f.matched_at}")
    print(f"[*] builtin templates: {len(findings)}/{len(tpls)} matched")
    return findings


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_DIR = os.path.expanduser("~/.hermes/cve_cache")


def _parse_nvd(data: dict[str, Any]) -> list[dict[str, str]]:
    """Parse an NVD API 2.0 response into our ``{cve, affected, severity, name}`` schema."""
    out: list[dict[str, str]] = []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cid = cve.get("id", "")
        if not cid:
            continue
        # severity from the best available CVSS metric
        severity = "unknown"
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                cvss = arr[0].get("cvssData", {}) or {}
                severity = (
                    cvss.get("baseSeverity") or arr[0].get("baseSeverity") or "unknown"
                ).lower()
                break
        # affected range from the first cpeMatch with version bounds
        affected = "*"
        for conf in cve.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for cpe in node.get("cpeMatch", []) or []:
                    end_excl = cpe.get("versionEndExcluding")
                    end_incl = cpe.get("versionEndIncluding")
                    start_incl = cpe.get("versionStartIncluding")
                    if start_incl and (end_excl or end_incl):
                        affected = f"{start_incl}-{end_excl or end_incl}"
                    elif end_excl:
                        affected = f"<{end_excl}"
                    elif end_incl:
                        affected = f"<={end_incl}"
                    if affected != "*":
                        break
                if affected != "*":
                    break
            if affected != "*":
                break
        name = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                name = (d.get("value") or "")[:160]
                break
        out.append({"cve": cid, "affected": affected, "severity": severity, "name": name})
    return out


def update_cve_db(
    product: str,
    *,
    refresh: bool = False,
    ttl: int = 21600,
    fetcher: Any | None = None,
    api_key: str | None = None,
) -> list[dict[str, str]]:
    """Fetch CVEs for ``product`` from NVD, cached on disk (refreshed per run).

    Returns our-schema entries. Uses a polite ``ttl`` cache (NVD rate-limits);
    ``refresh=True`` always re-downloads. Falls back to any cached copy, then to
    the bundled dataset, when offline — so the toolkit stays self-contained.
    """
    import time

    safe = re.sub(r"[^a-z0-9._-]", "_", product.lower())
    cache_file = os.path.join(_CACHE_DIR, f"{safe}.json")

    if not refresh and os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            if time.time() - cached.get("ts", 0) < ttl:
                entries: list[dict[str, str]] = cached.get("entries", [])
                return entries
        except (OSError, ValueError):
            pass

    try:
        import requests

        get = fetcher or requests.get
        headers = {"apiKey": api_key} if api_key else {}
        resp = get(
            _NVD_URL,
            params={"keywordSearch": product, "resultsPerPage": 50},
            headers=headers,
            timeout=20,
        )
        entries = _parse_nvd(resp.json())
        with contextlib.suppress(OSError):
            os.makedirs(_CACHE_DIR, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump({"ts": time.time(), "entries": entries}, f)
        print(f"[*] NVD: {len(entries)} CVEs for {product!r}")
        return entries
    except Exception as e:  # offline / rate-limited → fall back to cache, then bundle
        print(f"[-] NVD fetch failed for {product!r}: {str(e)[:80]}")
        if os.path.exists(cache_file):
            with contextlib.suppress(OSError, ValueError), open(cache_file) as f:
                return list(json.load(f).get("entries", []))
        return list(default_cve_db().get(product.lower(), []))


def correlate_cves(
    fingerprints: list[dict[str, str]],
    *,
    cve_db: dict[str, list[dict[str, str]]] | None = None,
    scanner: Any | None = None,
    online: bool = False,
    refresh: bool = False,
) -> list[dict[str, Any]]:
    """Map ``[{product, version}]`` fingerprints to known CVEs.

    Layered, never per-target hardcoded:
      1. the bundled dataset (self-contained, always available offline),
      2. plus a live NVD pull per product when ``online`` is set — refreshed on
         each run (``refresh`` bypasses the polite on-disk cache).

    This is the systematic "verify the version against known CVEs" step instead
    of trusting a banner.
    """
    if cve_db is not None:
        db = cve_db
    else:
        db = dict(default_cve_db())
        if online:
            products = {
                (fp.get("product") or "").lower() for fp in fingerprints if fp.get("product")
            }
            for product in products:
                fetched = update_cve_db(product, refresh=refresh)
                if fetched:
                    db[product] = db.get(product, []) + fetched

    matches: list[dict[str, Any]] = []
    for fp in fingerprints:
        product = (fp.get("product") or "").lower()
        version = fp.get("version") or ""
        if not product or not version:
            continue
        for entry in db.get(product, []):
            if version_matches(version, entry.get("affected", "*")):
                match = {
                    "product": product,
                    "version": version,
                    "cve": entry.get("cve", ""),
                    "severity": entry.get("severity", "unknown"),
                    "affected": entry.get("affected", "*"),
                }
                matches.append(match)
                if scanner is not None:
                    with contextlib.suppress(Exception):
                        scanner._record_finding(
                            endpoint=scanner.base_url,
                            method="",
                            payload=f"{product} {version}",
                            indicators=["cve", match["severity"]],
                            details=[f"{match['cve']} affects {product} {entry.get('affected')}"],
                            vuln_type=f"cve:{match['cve']}",
                            source="correlate_cves",
                        )
    return matches
