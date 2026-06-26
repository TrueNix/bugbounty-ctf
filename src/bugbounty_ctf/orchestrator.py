"""Multi-agent orchestration for security testing.

Spawns specialized sub-agents for each phase of pentesting:
- Recon agent: maps attack surface, identifies tech stack
- Research agent: queries RAG knowledge base for methodology
- Fuzz agent: tests payloads against discovered endpoints
- Exploit agent: chains confirmed findings into exploit paths

All agents share state via ScannerDB (SQLite) and receive RAG context
from KnowledgeBase. The orchestrator runs phases sequentially with
findings flowing between them.

Usage:
    from bugbounty_ctf.orchestrator import Orchestrator

    orch = Orchestrator("http://target/")
    report = orch.run()  # autonomous mode
    # or:
    report = orch.run(interactive=True)  # pause between phases
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase


@dataclass
class PhaseResult:
    """Result from a single orchestration phase."""

    phase: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    surface: dict[str, Any] = field(default_factory=dict)
    methodology: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class OrchestratorReport:
    """Full report from an orchestration run."""

    target: str
    phases: list[PhaseResult] = field(default_factory=list)
    total_findings: int = 0
    confirmed_vulns: int = 0
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "phases": [
                {
                    "phase": p.phase,
                    "findings": p.findings,
                    "surface": p.surface,
                    "methodology": p.methodology,
                    "recommendations": p.recommendations,
                    "timestamp": p.timestamp,
                }
                for p in self.phases
            ],
            "total_findings": self.total_findings,
            "confirmed_vulns": self.confirmed_vulns,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class Orchestrator:
    """Multi-agent security testing orchestrator.

    Runs specialized agents in sequence:
    1. Recon: map surface, detect tech
    2. Research: query knowledge base for relevant methodology
    3. Fuzz: test payloads against discovered endpoints
    4. Exploit: chain confirmed findings

    Each phase feeds its output into the next phase.
    All findings persist to ScannerDB (SQLite).
    """

    def __init__(
        self,
        target_url: str,
        *,
        scanner: SecurityScanner | None = None,
        knowledge_base: KnowledgeBase | None = None,
        delay: float = 0.5,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.scanner = scanner or SecurityScanner(target_url, delay=delay)
        self.kb = knowledge_base or KnowledgeBase()
        self.report = OrchestratorReport(target=self.target_url)

    def run_phase_recon(self) -> PhaseResult:
        """Phase 1: Map the attack surface and detect technology."""
        print(f"\n{'='*60}")
        print(f"[ORCHESTRATOR] Phase 1: RECON — {self.target_url}")
        print(f"{'='*60}")

        result = PhaseResult(phase="recon")

        surface = self.scanner.map_surface("/")
        result.surface = surface

        all_forms = surface.get("forms", [])
        all_links = surface.get("links", [])
        tech_hints = list(surface.get("tech_hints", []))

        crawled = {"/"}
        to_crawl = [link for link in all_links if link not in crawled]

        for link in to_crawl[:10]:
            if link in crawled:
                continue
            crawled.add(link)
            path = link.replace(self.target_url, "")
            if not path:
                path = "/"
            sub_surface = self.scanner.map_surface(path)
            all_forms.extend(sub_surface.get("forms", []))
            all_links.extend(sub_surface.get("links", []))
            tech_hints.extend(sub_surface.get("tech_hints", []))

        tech_hints = list(set(tech_hints))
        seen: set[tuple[Any, ...]] = set()
        unique_forms: list[dict[str, Any]] = []
        for f in all_forms:
            key: tuple[Any, ...] = (f["action"], f["method"], tuple(i["name"] for i in f["inputs"]))
            if key not in seen:
                seen.add(key)
                unique_forms.append(f)
        all_forms = unique_forms

        result.surface["forms"] = all_forms
        result.surface["links"] = list(set(all_links))
        result.surface["tech_hints"] = tech_hints

        self.scanner.attack_surface["/"] = result.surface

        print(f"  Status: {surface.get('status_code')}")
        print(f"  Tech: {tech_hints}")
        print(f"  Forms: {len(all_forms)}")
        print(f"  Links: {len(result.surface['links'])}")

        for form in all_forms:
            result.recommendations.append(
                f"Test form at {form['action']} ({form['method']}) "
                f"with params: {[i['name'] for i in form['inputs']]}"
            )

        for link in result.surface["links"]:
            result.recommendations.append(f"Investigate endpoint: {link}")

        if tech_hints:
            result.recommendations.append(
                f"Research methodology for: {', '.join(tech_hints)}"
            )

        self.report.phases.append(result)
        return result

    def run_phase_research(self, tech_hints: list[str] | None = None) -> PhaseResult:
        """Phase 2: Query the RAG knowledge base for relevant methodology."""
        print(f"\n{'='*60}")
        print("[ORCHESTRATOR] Phase 2: RESEARCH — querying knowledge base")
        print(f"{'='*60}")

        result = PhaseResult(phase="research")

        if tech_hints is None:
            tech_hints = self.scanner.attack_surface.get("/", {}).get("tech_hints", [])

        if tech_hints:
            suggestions = self.kb.suggest_methodology(tech_hints)
            result.methodology = suggestions
            print(f"  Found {len(suggestions)} methodology suggestions")
            for s in suggestions[:5]:
                print(f"    {s['filename']} — {s['section']}")
                print(f"    {s['snippet'][:100]}")
        else:
            general = self.kb.search("web vulnerability testing methodology")
            result.methodology = general
            print(f"  No tech hints — using general methodology ({len(general)} results)")

        for m in result.methodology:
            result.recommendations.append(
                f"Consult {m['filename']} section '{m['section']}' for methodology"
            )

        self.report.phases.append(result)
        return result

    def run_phase_fuzz(self, endpoints: list[str] | None = None) -> PhaseResult:
        """Phase 3: Test payloads against discovered endpoints."""
        print(f"\n{'='*60}")
        print("[ORCHESTRATOR] Phase 3: FUZZ — testing payloads")
        print(f"{'='*60}")

        result = PhaseResult(phase="fuzz")

        surface = self.scanner.attack_surface.get("/", {})
        forms = surface.get("forms", [])

        if endpoints is None:
            links = surface.get("links", [])
            endpoints = []

            for form in forms:
                endpoints.append(form["action"])

            for link in links:
                if any(keyword in link for keyword in ["login", "search", "api", "upload", "submit", "preview", "jobs"]):
                    endpoints.append(link)

        endpoints = list(set(endpoints))
        print(f"  Testing {len(endpoints)} endpoints")

        form_params_map: dict[str, dict[str, str]] = {}
        form_method_map: dict[str, str] = {}
        form_url_params: dict[str, list[str]] = {}

        for f in forms:
            action = f["action"]
            if action not in form_params_map:
                form_params_map[action] = {}
            form_params_map[action].update({inp["name"]: "test" for inp in f["inputs"]})
            form_method_map[action] = f["method"]
            url_params = [inp["name"] for inp in f["inputs"] if "url" in inp["name"].lower()]
            if action not in form_url_params:
                form_url_params[action] = []
            form_url_params[action].extend(url_params)

        for endpoint in endpoints:
            print(f"\n  Scanning: {endpoint}")
            try:
                if endpoint in form_params_map:
                    params = form_params_map[endpoint]
                    method = form_method_map.get(endpoint, "POST")
                    if method == "POST":
                        results = self.scanner.scan_endpoint(endpoint, method="POST", data=params)
                    else:
                        results = self.scanner.scan_endpoint(endpoint, method="GET", params=params)
                else:
                    results = self.scanner.scan_endpoint(endpoint, method="GET", params={"q": "test"})

                for vuln_type, test_results in results.items():
                    confirmed = [r for r in test_results if r.confirmed]
                    if confirmed:
                        print(f"    [!] {vuln_type}: {len(confirmed)} confirmed")
                        for c in confirmed:
                            finding = {
                                "type": vuln_type,
                                "endpoint": endpoint,
                                "payload": c.payload,
                                "indicators": c.indicators,
                                "details": c.details,
                            }
                            result.findings.append(finding)
                            print(f"      Payload: {c.payload}")
                            print(f"      Indicators: {c.indicators}")

                for url_param in form_url_params.get(endpoint, []):
                    self._test_ssrf_on_form(result, endpoint, form_method_map.get(endpoint, "POST"), url_param)

            except Exception as e:
                print(f"    Error: {e}")

        print(f"\n  Total findings: {len(result.findings)}")
        self.report.phases.append(result)
        return result

    def _test_ssrf_on_form(
        self, result: PhaseResult, endpoint: str, method: str, param_name: str
    ) -> None:
        """Test for SSRF on a URL-accepting form parameter."""
        from bugbounty_ctf.quick_tests import test_ssrf as _test_ssrf_fn

        print(f"    Testing SSRF on parameter: {param_name}")
        try:
            ssrf_results = _test_ssrf_fn(
                endpoint, method=method, param_name=param_name,
                scanner=self.scanner, url_suffix="#.yaml",
            )
            for r in ssrf_results:
                if r.get("interesting"):
                    finding = {
                        "type": "ssrf",
                        "endpoint": endpoint,
                        "payload": r.get("payload", ""),
                        "indicators": r.get("analysis", {}).get("indicators", []),
                        "details": r.get("analysis", {}).get("differences", []),
                    }
                    result.findings.append(finding)
                    print(f"      [!] SSRF: {r.get('payload', '')}")

            from bugbounty_ctf.engine import get_aws_credentials

            creds = get_aws_credentials(self.scanner)
            if creds:
                finding = {
                    "type": "aws_credentials",
                    "endpoint": "metadata-service",
                    "payload": "2852039166 (decimal IP bypass)",
                    "indicators": ["iam_credentials_leaked"],
                    "details": [f"AccessKeyId: {creds.get('AccessKeyId', '?')}"],
                }
                result.findings.append(finding)
                print(f"      [!] AWS credentials leaked: {creds.get('AccessKeyId', '?')}")
        except Exception as e:
            print(f"      SSRF test error: {e}")

    def run_phase_exploit(self, findings: list[dict[str, Any]] | None = None) -> PhaseResult:
        """Phase 4: Chain confirmed findings into exploit paths."""
        print(f"\n{'='*60}")
        print("[ORCHESTRATOR] Phase 4: EXPLOIT — chaining findings")
        print(f"{'='*60}")

        result = PhaseResult(phase="exploit")

        if findings is None:
            findings = self.scanner.findings

        if not findings:
            print("  No findings to chain")
            self.report.phases.append(result)
            return result

        print(f"  {len(findings)} findings to analyze")

        chains = self._identify_chains(findings)
        for chain in chains:
            print(f"\n  [CHAIN] {chain['name']}")
            for step in chain["steps"]:
                print(f"    {step}")
            result.recommendations.append(f"Exploit chain: {chain['name']}")

        result.findings = chains
        self.report.phases.append(result)
        return result

    @staticmethod
    def _identify_chains(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify potential exploit chains from findings."""
        chains: list[dict[str, Any]] = []

        sqli_findings = [f for f in findings if "sqli" in f.get("type", "").lower() or "sql" in f.get("indicators", [])]
        xss_findings = [f for f in findings if "xss" in f.get("type", "").lower() or "xss" in f.get("indicators", [])]
        ssrf_findings = [f for f in findings if "ssrf" in f.get("type", "").lower() or "ssrf" in f.get("indicators", [])]
        aws_findings = [f for f in findings if "aws" in f.get("type", "").lower() or "credential" in f.get("type", "").lower()]
        ssti_findings = [f for f in findings if "ssti" in f.get("type", "").lower() or "ssti" in f.get("indicators", [])]
        cmdi_findings = [f for f in findings if "cmdi" in f.get("type", "").lower() or "command" in f.get("indicators", [])]

        if sqli_findings:
            chains.append({
                "name": "SQLi → data exfiltration",
                "steps": [
                    f"SQLi found at {sqli_findings[0].get('endpoint', '?')}",
                    "Dump database schema via UNION SELECT",
                    "Extract credentials from users table",
                    "Use credentials for authenticated access",
                ],
            })

        if ssrf_findings or aws_findings:
            chains.append({
                "name": "SSRF → cloud metadata → credential theft",
                "steps": [
                    f"SSRF found at {ssrf_findings[0].get('endpoint', '?') if ssrf_findings else '?'}",
                    "Bypass IP filter with decimal encoding (2852039166)",
                    "Access /latest/meta-data/iam/security-credentials/ for IAM creds",
                    f"AWS credentials leaked: {aws_findings[0].get('details', ['?'])[0] if aws_findings else 'not yet extracted'}",
                    "Use credentials to access STS/S3/SQS or other cloud resources",
                ],
            })

        if ssti_findings:
            chains.append({
                "name": "SSTI → RCE",
                "steps": [
                    f"SSTI found at {ssti_findings[0].get('endpoint', '?')}",
                    "Escalate from {{7*7}} to Jinja2 RCE",
                    "Read /etc/passwd and environment variables",
                    "Access flag or credentials",
                ],
            })

        if cmdi_findings:
            chains.append({
                "name": "CMDi → RCE",
                "steps": [
                    f"Command injection at {cmdi_findings[0].get('endpoint', '?')}",
                    "Execute id; whoami; cat /etc/passwd",
                    "Enumerate filesystem for flags",
                    "Establish persistence if needed",
                ],
            })

        if xss_findings:
            chains.append({
                "name": "XSS → session theft",
                "steps": [
                    f"XSS found at {xss_findings[0].get('endpoint', '?')}",
                    "Steal session cookies via callback listener",
                    "Impersonate user with stolen session",
                    "Access authenticated functionality",
                ],
            })

        return chains

    def run(self, interactive: bool = False) -> OrchestratorReport:
        """Run all phases sequentially.

        Args:
            interactive: If True, pause for human review between phases.
        """
        print(f"\n{'#'*60}")
        print(f"# ORCHESTRATOR STARTING — {self.target_url}")
        print(f"{'#'*60}")

        recon = self.run_phase_recon()
        if interactive:
            input("\n[Press Enter to continue to research phase...]")

        tech_hints = recon.surface.get("tech_hints", [])
        self.run_phase_research(tech_hints)
        if interactive:
            input("\n[Press Enter to continue to fuzz phase...]")

        fuzz = self.run_phase_fuzz()
        if interactive:
            input("\n[Press Enter to continue to exploit phase...]")

        self.run_phase_exploit(fuzz.findings)

        self.report.total_findings = len(self.scanner.findings)
        self.report.confirmed_vulns = sum(
            1 for p in self.report.phases if p.phase == "fuzz" for f in p.findings
        )

        print(f"\n{'#'*60}")
        print("# ORCHESTRATOR COMPLETE")
        print(f"# Total findings: {self.report.total_findings}")
        print(f"# Confirmed vulns: {self.report.confirmed_vulns}")
        print(f"{'#'*60}")

        return self.report

    def save_report(self, path: str | None = None) -> str:
        """Save the orchestrator report to disk."""
        import os

        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = self.scanner.host
            path = os.path.expanduser(f"~/.hermes/reports/orchestrator_{host}_{ts}.json")

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(self.report.to_json())
        print(f"[*] Report saved to {path}")
        return path
