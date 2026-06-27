"""Hermes skill integration for security testing.

Spawns Hermes sub-agents for each phase of security testing. Each sub-agent
gets its own context window with RAG context injected and the available
toolkit functions. The orchestrator coordinates between phases and feeds
findings forward.

Agent spawning uses `hermes -z` (one-shot mode) with the main model
configured in Hermes config (qwen3.7-plus via alibaba-coding-plan).

The orchestrator is target-agnostic — it discovers what's there and
lets each sub-agent decide what to test based on what it found.
"""

from __future__ import annotations

import json
import os
import subprocess
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

    def spawn_agent(self, guidance: PhaseGuidance, *, timeout: int = 120) -> str:
        """Spawn a Hermes sub-agent for a phase using `hermes -z`.

        The sub-agent gets the phase guidance as a one-shot prompt,
        including RAG context, scanner state, and available tools.
        The sub-agent executes using the main Hermes model.
        """
        prompt = self._build_agent_prompt(guidance)

        cmd = ["hermes", "-z", prompt, "--yolo"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "HERMES_NO_STREAM": "1"},
            )
            response = result.stdout.strip()
            print(f"[{guidance.phase}] Agent response: {len(response)} chars")
            return response
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT after {timeout}s]"
        except Exception as e:
            return f"[ERROR: {e}]"

    @staticmethod
    def _build_agent_prompt(guidance: PhaseGuidance) -> str:
        """Build a prompt for the Hermes sub-agent from phase guidance."""
        import json as _json

        lines = [
            f"You are a security testing agent for the {guidance.phase} phase.",
            "",
            "## Discovered so far",
            _json.dumps(guidance.discovered, indent=2, default=str)[:1000],
            "",
            "## Available tools",
        ]

        for tool in guidance.available_tools:
            lines.append(f"  - {tool}")

        if guidance.rag_context:
            lines.extend(["", "## Methodology from knowledge base", guidance.rag_context[:500]])

        if guidance.scanner_state:
            lines.extend(["", "## Current scanner state", guidance.scanner_state])

        if guidance.previous_findings:
            lines.extend(["", "## Previous findings"])
            for f in guidance.previous_findings[:10]:
                lines.append(f"  - {f.get('type', '?')}: {f.get('endpoint', '?')}")

        lines.extend(
            [
                "",
                "## Your task",
                f"Execute the {guidance.phase} phase. Use the available tools.",
                "Report findings as structured text with type, endpoint, payload, and evidence.",
            ]
        )

        return "\n".join(lines)

    def run_with_agents(self, *, timeout_per_phase: int = 120) -> dict[str, Any]:
        """Run all phases with Hermes sub-agents.

        Each phase spawns a Hermes sub-agent that gets the guidance prompt.
        Findings from each phase feed into the next.
        """
        print(f"\n{'#' * 60}")
        print(f"# SKILL ORCHESTRATOR WITH AGENTS — {self.target_url}")
        print(f"{'#' * 60}")

        phases = self.run_all_phases()
        results: dict[str, str] = {}

        for guidance in phases:
            print(f"\n{'=' * 60}")
            print(f"[{guidance.phase.upper()}] Spawning Hermes sub-agent...")
            print(f"{'=' * 60}")

            response = self.spawn_agent(guidance, timeout=timeout_per_phase)
            results[guidance.phase] = response[:2000]

            print(f"\n[{guidance.phase.upper()}] Response preview:")
            print(response[:500])

        final = self.collect_results()
        final["agent_responses"] = results

        self.save_results()
        return final
