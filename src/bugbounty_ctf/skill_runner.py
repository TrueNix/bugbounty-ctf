"""Hermes skill integration for security testing.

When installed as a Hermes skill, the Hermes agent itself IS the reasoning
engine. This module provides phase guidance with RAG context and scanner
state, but does NOT prescribe specific actions. The agent decides what to
test based on what it discovered.

The orchestrator is target-agnostic. It presents:
- What was discovered (forms, links, tech, findings)
- What tools are available
- What the knowledge base suggests
The agent decides what to do with that information.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase


@dataclass
class PhaseGuidance:
    """Context provided to the Hermes agent at each phase."""

    phase: str
    discovered: dict[str, Any] = field(default_factory=dict)
    available_tools: list[str] = field(default_factory=list)
    rag_context: str = ""
    scanner_state: str = ""
    previous_findings: list[dict[str, Any]] = field(default_factory=list)


class SkillOrchestrator:
    """Target-agnostic orchestrator for Hermes skill-based testing.

    Provides phase context without prescribing actions. The Hermes agent
    uses its own reasoning to decide what to test based on discoveries.

    Flow:
    1. get_recon_guidance() → agent maps surface, discovers forms/links/tech
    2. get_research_guidance() → RAG returns methodology, agent prioritizes
    3. get_fuzz_guidance() → agent tests whatever it deems relevant
    4. get_exploit_guidance() → agent chains whatever it confirmed
    5. collect_results() → aggregate
    """

    def __init__(
        self,
        target_url: str,
        *,
        scanner: SecurityScanner | None = None,
        knowledge_base: KnowledgeBase | None = None,
        delay: float = 0.3,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.scanner = scanner or SecurityScanner(target_url, delay=delay)
        self.kb = knowledge_base or KnowledgeBase()
        self.current_phase = "recon"

    def _query_rag(self, query: str, limit: int = 5) -> str:
        results = self.kb.search(query, limit=limit)
        if not results:
            return ""
        lines = []
        for r in results:
            lines.append(f"{r['filename']} > {r['section']}: {r['snippet'][:120]}")
        return "\n".join(lines)

    def _format_state(self) -> str:
        summary = self.scanner.get_summary()
        lines = [
            f"target: {summary['target']}",
            f"tests_run: {summary['tests_run']}",
            f"findings: {summary['findings_count']}",
            f"waf: {summary['waf_detected']}",
        ]
        discovered = self._format_discovered()
        if discovered.get("tech_hints"):
            lines.append(f"tech: {', '.join(discovered['tech_hints'])}")
        if discovered.get("forms"):
            lines.append(f"forms: {len(discovered['forms'])}")
        if discovered.get("links"):
            lines.append(f"links: {len(discovered['links'])}")
        if self.scanner.findings:
            lines.append(f"confirmed: {len(self.scanner.findings)}")
        return "\n".join(lines)

    def _format_discovered(self) -> dict[str, Any]:
        all_forms: list[dict[str, Any]] = []
        all_links: list[str] = []
        all_tech: list[str] = []

        for surface in self.scanner.attack_surface.values():
            if not isinstance(surface, dict):
                continue
            for f in surface.get("forms", []):
                all_forms.append(
                    {
                        "action": f.get("action"),
                        "method": f.get("method"),
                        "inputs": [i.get("name") for i in f.get("inputs", [])],
                    }
                )
            all_links.extend(surface.get("links", []))
            all_tech.extend(surface.get("tech_hints", []))

        seen_form_keys: set[tuple[Any, ...]] = set()
        unique_forms: list[dict[str, Any]] = []
        for f in all_forms:
            key: tuple[Any, ...] = (f.get("action"), f.get("method"), tuple(f.get("inputs", [])))
            if key not in seen_form_keys:
                seen_form_keys.add(key)
                unique_forms.append(f)

        return {
            "forms": unique_forms,
            "links": list(set(all_links)),
            "tech_hints": list(set(all_tech)),
            "defenses": self.scanner.defenses_detected,
            "waf_detected": self.scanner.waf_detected,
        }

    def get_recon_guidance(self) -> PhaseGuidance:
        self.current_phase = "recon"
        rag = self._query_rag("reconnaissance attack surface mapping web application")
        return PhaseGuidance(
            phase="recon",
            discovered=self._format_discovered(),
            available_tools=[
                "scanner.map_surface(path)",
                "detect_defenses(url, scanner=scanner)",
                "scanner._make_request(method, url)",
            ],
            rag_context=rag,
            scanner_state=self._format_state(),
        )

    def get_research_guidance(self) -> PhaseGuidance:
        self.current_phase = "research"
        tech = self.scanner.attack_surface.get("/", {}).get("tech_hints", [])
        if tech:
            methodology = self.kb.suggest_methodology(tech)
        else:
            methodology = self.kb.search("web vulnerability testing")
        rag_lines = [
            f"{m['filename']} > {m['section']}: {m['snippet'][:120]}" for m in methodology[:10]
        ]
        return PhaseGuidance(
            phase="research",
            discovered=self._format_discovered(),
            available_tools=[
                "kb.search(query)",
                "kb.suggest_methodology(tech_hints)",
                "kb.get_doc(filename)",
            ],
            rag_context="\n".join(rag_lines),
            scanner_state=self._format_state(),
        )

    def get_fuzz_guidance(self) -> PhaseGuidance:
        self.current_phase = "fuzz"
        rag = self._query_rag("payload testing vulnerability detection")
        return PhaseGuidance(
            phase="fuzz",
            discovered=self._format_discovered(),
            available_tools=[
                "scanner.scan_endpoint(url, method, params/data)",
                "test_ssrf(url, method, param_name, scanner, url_suffix)",
                "test_login_sqli(url, scanner=scanner)",
                "test_ssti(url, scanner=scanner)",
                "test_xss(url, scanner=scanner)",
                "test_idor(url_template, scanner=scanner)",
                "test_command_injection(url, scanner=scanner)",
                "test_path_traversal(url, scanner=scanner)",
                "test_nosqli(url, scanner=scanner)",
                "test_graphql_alias_batch(url, query, scanner=scanner)",
                "get_aws_credentials(scanner)",
                "enumerate_aws_metadata(scanner)",
                "detect_ssrf_filter(url, scanner=scanner)",
            ],
            rag_context=rag,
            scanner_state=self._format_state(),
            previous_findings=self.scanner.findings,
        )

    def get_exploit_guidance(self) -> PhaseGuidance:
        self.current_phase = "exploit"
        rag = self._query_rag("exploit chaining privilege escalation")
        return PhaseGuidance(
            phase="exploit",
            discovered=self._format_discovered(),
            available_tools=[
                "get_aws_credentials(scanner)",
                "generate_aws_presigned_url(service, action, ...)",
                "ChainContext()",
                "save_report(scanner)",
                "scanner.db.query_findings(where, params)",
            ],
            rag_context=rag,
            scanner_state=self._format_state(),
            previous_findings=self.scanner.findings,
        )

    def collect_results(self) -> dict[str, Any]:
        summary = self.scanner.get_summary()
        return {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "total_findings": summary["findings_count"],
            "tests_run": summary["tests_run"],
            "waf_detected": summary["waf_detected"],
            "findings": summary["findings"],
            "attack_surface": self.scanner.attack_surface,
            "defenses_detected": summary["defenses_detected"],
        }

    def save_results(self, path: str | None = None) -> str:
        import os

        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = self.scanner.host
            path = os.path.expanduser(f"~/.hermes/reports/skill_{host}_{ts}.json")

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.collect_results(), f, indent=2, default=str)
        print(f"[*] Results saved to {path}")
        return path

    def run_all_phases(self) -> list[PhaseGuidance]:
        return [
            self.get_recon_guidance(),
            self.get_research_guidance(),
            self.get_fuzz_guidance(),
            self.get_exploit_guidance(),
        ]
