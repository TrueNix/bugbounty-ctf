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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase


def _sanitize_for_prompt(value: object, maxlen: int = 120) -> str:
    """Flatten target-derived data so it can't inject prompt structure."""
    return str(value).replace("\r", " ").replace("\n", " ").replace("\x00", "")[:maxlen]


@dataclass
class PhaseGuidance:
    """Context provided to the Hermes agent at each phase."""

    phase: str
    discovered: dict[str, Any] = field(default_factory=dict)
    available_tools: list[str] = field(default_factory=list)
    rag_context: str = ""
    scanner_state: str = ""
    previous_findings: list[dict[str, Any]] = field(default_factory=list)
    # Findings recalled from prior runs against this host (the DB "memory").
    prior_memory: list[dict[str, Any]] = field(default_factory=list)
    # Resolved hypotheses and high-confidence observations from past runs.
    prior_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    prior_observations: list[dict[str, Any]] = field(default_factory=list)
    # Shared-persistence handles so a spawned sub-agent writes its findings to
    # the same state file / DB the orchestrator reads back between phases.
    target_url: str = ""
    state_file: str = ""
    db_path: str = ""


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

    def _recall_prior(self, limit: int = 20) -> list[dict[str, Any]]:
        """Recall findings from past runs against this host (DB second-brain).

        Deduped by (vuln_type, endpoint) for a compact memory summary that seeds
        the new session instead of starting cold every time.
        """
        try:
            rows = self.scanner.db.findings_for_host(self.scanner.host, limit=limit)
        except Exception:
            return []
        seen: set[tuple[Any, Any]] = set()
        memory: list[dict[str, Any]] = []
        for r in rows:
            key = (r.get("vuln_type"), r.get("endpoint"))
            if key in seen:
                continue
            seen.add(key)
            memory.append(
                {
                    "vuln_type": r.get("vuln_type"),
                    "endpoint": r.get("endpoint"),
                    "payload": r.get("payload"),
                    "confidence": r.get("confidence"),
                    "last_seen": r.get("timestamp"),
                }
            )
        return memory

    def _recall_hypotheses(self, limit: int = 40) -> list[dict[str, Any]]:
        """Recall resolved hypotheses (confirmed + rejected) for this host.

        Confirmed → known weak points to re-check; rejected → dead ends the new
        run can skip. Deduped by (vuln_type, param), keeping the latest verdict.
        """
        try:
            rows = self.scanner.db.query_hypotheses(self.scanner.host, limit=limit)
        except Exception:
            return []
        seen: set[tuple[Any, Any]] = set()
        out: list[dict[str, Any]] = []
        for h in rows:
            status = (
                "confirmed"
                if h.get("confirmed")
                else "rejected"
                if h.get("rejected")
                else "pending"
            )
            if status == "pending":
                continue
            key = (h.get("vuln_type"), h.get("param"))
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "vuln_type": h.get("vuln_type"),
                    "param": h.get("param"),
                    "endpoint": h.get("endpoint"),
                    "status": status,
                    "confidence": round(float(h.get("confidence", 0.0)), 2),
                }
            )
        return out

    def _recall_observations(self, limit: int = 40) -> list[dict[str, Any]]:
        """Recall high-confidence observations (with their next-test hints)."""
        try:
            rows = self.scanner.db.query_observations(
                self.scanner.host, min_confidence=0.5, limit=limit
            )
        except Exception:
            return []
        seen: set[tuple[Any, Any]] = set()
        out: list[dict[str, Any]] = []
        for o in rows:
            key = (o.get("vuln_type"), o.get("endpoint"))
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "vuln_type": o.get("vuln_type"),
                    "endpoint": o.get("endpoint"),
                    "next_test": o.get("next_test", ""),
                    "confidence": o.get("confidence"),
                }
            )
        return out

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
            prior_memory=self._recall_prior(),
            prior_hypotheses=self._recall_hypotheses(),
            prior_observations=self._recall_observations(),
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
            prior_memory=self._recall_prior(),
            prior_hypotheses=self._recall_hypotheses(),
            prior_observations=self._recall_observations(),
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
                "find_ssrf_endpoints(scanner)  # discover the SSRF sink first",
                "detect_ssrf_filter(url, scanner=scanner, ssrf_endpoint=..., url_suffix=...)",
                "enumerate_aws_metadata(scanner, ssrf_endpoint=..., url_suffix=...)",
                "get_aws_credentials(scanner, ssrf_endpoint=..., url_suffix=...)",
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

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.collect_results(), f, indent=2, default=str)
        print(f"[*] Results saved to {path}")
        return path

    PHASES: tuple[str, ...] = ("recon", "research", "fuzz", "exploit")
    FINDINGS_TAG = "FINDINGS"
    VERDICT_TAG = "VERDICT"

    def run_all_phases(self) -> list[PhaseGuidance]:
        return [
            self.get_recon_guidance(),
            self.get_research_guidance(),
            self.get_fuzz_guidance(),
            self.get_exploit_guidance(),
        ]

    def _guidance_for(self, phase: str) -> PhaseGuidance:
        """Build the guidance for a single phase from CURRENT scanner state.

        Used by the sub-agent workflow so each phase's prompt reflects what the
        previous phase's agent actually discovered (unlike ``run_all_phases``,
        which snapshots every phase upfront).
        """
        builders = {
            "recon": self.get_recon_guidance,
            "research": self.get_research_guidance,
            "fuzz": self.get_fuzz_guidance,
            "exploit": self.get_exploit_guidance,
        }
        guidance = builders[phase]()
        return self._attach_shared_context(guidance)

    def _attach_shared_context(self, guidance: PhaseGuidance) -> PhaseGuidance:
        """Stamp the shared-persistence handles onto a guidance object."""
        guidance.target_url = self.target_url
        guidance.state_file = self.scanner.state_file
        guidance.db_path = self.scanner.db.db_path
        return guidance

    def _reload_state(self) -> None:
        """Re-read findings/surface a sub-agent persisted, so the next phase
        (and the final report) reflect what it discovered."""
        self.scanner._load_state()

    class HermesNotFoundError(RuntimeError):
        """Raised when the `hermes` binary is not on PATH."""

    def spawn_agent(self, guidance: PhaseGuidance, *, timeout: int = 120) -> str:
        """Spawn a Hermes sub-agent for a phase using `hermes -z`.

        The sub-agent gets the phase guidance as a one-shot prompt,
        including RAG context, scanner state, and available tools.
        The sub-agent executes using the main Hermes model.

        The prompt is passed as a single argv element with the list form of
        ``subprocess.run`` (no ``shell=True``), so target-derived data baked
        into the prompt (form names, endpoints, response snippets) cannot break
        out into shell arguments. A non-zero exit surfaces stderr instead of
        being silently reported as an empty response, and a missing ``hermes``
        binary raises :class:`HermesNotFoundError` so the caller can abort
        rather than recording four empty phases.
        """
        return self._run_hermes(
            self._build_agent_prompt(guidance), timeout=timeout, label=guidance.phase
        )

    def _run_hermes(self, prompt: str, *, timeout: int, label: str = "agent") -> str:
        """Run one `hermes -z` sub-agent with a prebuilt prompt and return stdout.

        The prompt is a single argv element (list-form ``subprocess.run``, no
        shell), so target-derived data inside it cannot break out into shell
        arguments. Non-zero exit surfaces stderr; a missing binary raises
        :class:`HermesNotFoundError`.
        """
        cmd = ["hermes", "-z", prompt, "--yolo"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "HERMES_NO_STREAM": "1"},
            )
        except FileNotFoundError as e:
            raise self.HermesNotFoundError(
                "`hermes` binary not found on PATH — cannot spawn sub-agents"
            ) from e
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT after {timeout}s]"

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            return f"[HERMES ERROR rc={result.returncode}] {stderr[:500]}"

        response = result.stdout.strip()
        print(f"[{label}] Agent response: {len(response)} chars")
        return response

    @staticmethod
    def _build_agent_prompt(guidance: PhaseGuidance) -> str:
        """Build a prompt for the Hermes sub-agent from phase guidance."""
        import json as _json

        lines = [
            f"You are a security testing agent for the {guidance.phase} phase.",
        ]

        if guidance.target_url:
            # Share the orchestrator's persistence so findings written here are
            # visible to the next phase and to the final report.
            lines.extend(
                [
                    "",
                    "## Bootstrap (use this exact scanner — it shares state with the orchestrator)",
                    "```python",
                    "from bugbounty_ctf import SecurityScanner",
                    "from bugbounty_ctf.engine import ScannerDB",
                    "from bugbounty_ctf import api  # test_*, detect_defenses, get_aws_credentials…",
                    "scanner = SecurityScanner(",
                    f"    {guidance.target_url!r},",
                    f"    state_file={guidance.state_file!r},",
                    f"    db=ScannerDB({guidance.db_path!r}),",
                    ")",
                    "```",
                    "Run the tools against `scanner` so every finding is persisted automatically.",
                ]
            )

        lines.extend(
            [
                "",
                "## Discovered so far",
                _json.dumps(guidance.discovered, indent=2, default=str)[:1000],
                "",
                "## Available tools",
            ]
        )

        for tool in guidance.available_tools:
            lines.append(f"  - {tool}")

        if guidance.rag_context:
            lines.extend(["", "## Methodology from knowledge base", guidance.rag_context[:500]])

        if guidance.scanner_state:
            lines.extend(["", "## Current scanner state", guidance.scanner_state])

        if guidance.prior_memory:
            lines.extend(["", "## Prior memory (confirmed on this host in past runs)"])
            for m in guidance.prior_memory[:15]:
                lines.append(
                    f"  - {_sanitize_for_prompt(m.get('vuln_type', '?'))} @ "
                    f"{_sanitize_for_prompt(m.get('endpoint', '?'))}"
                    f" (payload: {_sanitize_for_prompt(m.get('payload', ''), 60)})"
                )
            lines.append("Re-check these first; they are known weak points.")

        if guidance.prior_hypotheses:
            confirmed = [h for h in guidance.prior_hypotheses if h.get("status") == "confirmed"]
            rejected = [h for h in guidance.prior_hypotheses if h.get("status") == "rejected"]
            lines.extend(["", "## Prior hypotheses (past runs)"])
            if confirmed:
                lines.append(
                    "  confirmed (re-check): "
                    + ", ".join(
                        f"{_sanitize_for_prompt(h['vuln_type'])}@{_sanitize_for_prompt(h['param'])}"
                        for h in confirmed[:8]
                    )
                )
            if rejected:
                lines.append(
                    "  rejected (skip — already ruled out): "
                    + ", ".join(
                        f"{_sanitize_for_prompt(h['vuln_type'])}@{_sanitize_for_prompt(h['param'])}"
                        for h in rejected[:8]
                    )
                )

        if guidance.prior_observations:
            lines.extend(["", "## Prior observations — suggested next tests"])
            for o in guidance.prior_observations[:8]:
                hint = _sanitize_for_prompt(o.get("next_test", ""), 80)
                lines.append(
                    f"  - {_sanitize_for_prompt(o.get('vuln_type', '?'))} @ "
                    f"{_sanitize_for_prompt(o.get('endpoint', '?'))}: {hint}"
                )

        if guidance.previous_findings:
            lines.extend(["", "## Previous findings"])
            for f in guidance.previous_findings[:10]:
                lines.append(
                    f"  - {_sanitize_for_prompt(f.get('type', '?'))}: "
                    f"{_sanitize_for_prompt(f.get('endpoint', '?'))}"
                )

        lines.extend(
            [
                "",
                "## Your task",
                f"Execute the {guidance.phase} phase. Use the available tools against `scanner`.",
                "",
                "## Required output",
                "End your reply with a machine-readable findings block — a JSON array",
                f"wrapped in <{SkillOrchestrator.FINDINGS_TAG}> … </{SkillOrchestrator.FINDINGS_TAG}> tags.",
                "Each finding object must have: type, endpoint, method, payload, evidence,",
                'confidence (one of "low"/"medium"/"high"), and source (the methodology',
                "doc or reasoning that led to it). Emit an empty array if nothing was",
                "found. Example:",
                f"<{SkillOrchestrator.FINDINGS_TAG}>",
                '[{"type":"sqli","endpoint":"/login","method":"POST",'
                '"payload":"\' OR 1=1--","evidence":"SQL error reflected",'
                '"confidence":"high","source":"sqlite-php-sqli-playbook.md"}]',
                f"</{SkillOrchestrator.FINDINGS_TAG}>",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _extract_tagged_json(text: str, tag: str) -> Any:
        """Extract and parse a JSON payload wrapped in <TAG> … </TAG>.

        Returns the parsed object, or None when the block is absent or invalid.
        Tolerant of an optional ```json fence inside the tags.
        """
        start = text.find(f"<{tag}>")
        end = text.find(f"</{tag}>")
        if start == -1 or end == -1 or end < start:
            return None
        body = text[start + len(tag) + 2 : end].strip()
        if body.startswith("```"):
            body = body.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None

    @classmethod
    def _parse_findings(cls, response: str) -> list[dict[str, Any]]:
        """Parse the <FINDINGS> JSON array a sub-agent emits (best-effort)."""
        parsed = cls._extract_tagged_json(response, cls.FINDINGS_TAG)
        if not isinstance(parsed, list):
            return []
        return [f for f in parsed if isinstance(f, dict) and f.get("type")]

    def _merge_agent_findings(self, parsed: list[dict[str, Any]]) -> int:
        """Merge sub-agent-reported findings into the scanner, de-duplicated.

        This is the robust feed-forward path: even if a sub-agent never touched
        the shared ScannerDB, its declared findings are recorded centrally so
        the next phase and the final report see them. Dedup key is
        (type, endpoint, payload).
        """
        existing = {
            (f.get("type"), f.get("endpoint"), f.get("payload")) for f in self.scanner.findings
        }
        added = 0
        for f in parsed:
            key = (f.get("type"), f.get("endpoint"), f.get("payload"))
            if key in existing:
                continue
            existing.add(key)
            evidence = str(f.get("evidence", ""))
            source = str(f.get("source") or f"agent:{self.current_phase}")
            self.scanner._record_finding(
                endpoint=str(f.get("endpoint", "")),
                method=str(f.get("method", "")),
                payload=str(f.get("payload", "")),
                indicators=[f"agent_reported:{f.get('confidence', 'unknown')}"],
                details=[evidence] if evidence else [],
                vuln_type=str(f.get("type", "")),
                source=source,
            )
            added += 1
        return added

    def run_with_agents(
        self,
        *,
        timeout_per_phase: int = 120,
        verify: bool = True,
        verify_votes: int = 3,
    ) -> dict[str, Any]:
        """Run the four-phase workflow, spawning one Hermes sub-agent per phase.

        This is the autonomous (headless) path. Each phase's guidance is built
        **lazily from the current scanner state**, so a phase reflects what the
        previous phase's agent discovered. Sub-agents share the orchestrator's
        state file and ScannerDB (see :meth:`_build_agent_prompt`), and each
        agent also emits a machine-readable ``<FINDINGS>`` block that the
        orchestrator parses and merges centrally — so feed-forward is robust
        even if an agent forgets to persist via the shared DB.

        When ``verify`` is set, every merged finding is then put through an
        adversarial verification pass (:meth:`verify_findings`): a panel of
        skeptic sub-agents tries to refute it, and findings the majority can
        refute are dropped from the confirmed set.

        For an interactive Hermes session, prefer the in-process flow
        (``get_recon_guidance()`` … executed by the running agent itself) —
        no sub-processes are spawned there.
        """
        print(f"\n{'#' * 60}")
        print(f"# SKILL ORCHESTRATOR WITH AGENTS — {self.target_url}")
        print(f"{'#' * 60}")

        results: dict[str, str] = {}

        for phase in self.PHASES:
            # Build guidance NOW so it includes findings the previous agent persisted.
            guidance = self._guidance_for(phase)

            print(f"\n{'=' * 60}")
            print(f"[{phase.upper()}] Spawning Hermes sub-agent...")
            print(f"{'=' * 60}")

            try:
                response = self.spawn_agent(guidance, timeout=timeout_per_phase)
            except self.HermesNotFoundError as e:
                print(f"[!] {e}")
                final = self.collect_results()
                final["agent_responses"] = results
                final["agent_error"] = str(e)
                return final

            results[phase] = response[:2000]
            print(f"\n[{phase.upper()}] Response preview:")
            print(response[:500])

            # Order matters: first pull in anything the sub-agent persisted to
            # the shared store directly, THEN merge its declared <FINDINGS> on
            # top and persist the result — otherwise the next reload would
            # clobber the in-memory merge (which only touched memory + DB).
            self._reload_state()
            merged = self._merge_agent_findings(self._parse_findings(response))
            if merged:
                print(f"[{phase}] Merged {merged} reported finding(s)")
                self.scanner._save_state()

        final = self.collect_results()
        final["agent_responses"] = results

        if verify:
            verdicts = self.verify_findings(votes=verify_votes, timeout=timeout_per_phase)
            final["verification"] = verdicts
            confirmed = [v["finding"] for v in verdicts if not v["refuted"]]
            final["confirmed_findings"] = confirmed
            final["refuted_findings"] = [v["finding"] for v in verdicts if v["refuted"]]
        else:
            confirmed = list(self.scanner.findings)

        # Write-back: persist what worked into the searchable knowledge base so
        # future runs recall it (the second-brain learning loop).
        final["lessons_written"] = self._writeback_lessons(confirmed)

        self.save_results()
        return final

    def _build_task_prompt(self, label: str, instruction: str) -> str:
        """Build a self-contained prompt for one independent fan-out task.

        Unlike :meth:`_build_agent_prompt` (phase-shaped, tool-listed), this takes
        a free-form ``instruction`` for one track (e.g. NFS enum, mail spray). It
        still injects the shared scanner bootstrap so findings persist centrally,
        and requires the same ``<FINDINGS>`` output contract.
        """
        lines = [f"You are a security testing sub-agent working the {label!r} track."]
        if self.target_url:
            lines.extend(
                [
                    "",
                    "## Bootstrap (use this exact scanner — it shares state with the orchestrator)",
                    "```python",
                    "from bugbounty_ctf import SecurityScanner",
                    "from bugbounty_ctf.engine import ScannerDB",
                    "from bugbounty_ctf import api  # test_*, NFSEnumerator, MailEnumerator, …",
                    "scanner = SecurityScanner(",
                    f"    {self.target_url!r},",
                    f"    state_file={self.scanner.state_file!r},",
                    f"    db=ScannerDB({self.scanner.db.db_path!r}),",
                    ")",
                    "```",
                ]
            )
        lines.extend(
            [
                "",
                "## Your task",
                instruction,
                "",
                "## Required output",
                f"End your reply with a <{self.FINDINGS_TAG}> … </{self.FINDINGS_TAG}> JSON array.",
                "Each finding object: type, endpoint, method, payload, evidence,",
                'confidence ("low"/"medium"/"high"), source. Emit an empty array if',
                "nothing was found.",
            ]
        )
        return "\n".join(lines)

    def fan_out(
        self,
        tasks: list[tuple[str, str]],
        *,
        timeout: int = 180,
        max_workers: int = 4,
    ) -> dict[str, Any]:
        """Run independent tracks as CONCURRENT ``hermes -z`` sub-agents.

        ``tasks`` is a list of ``(label, instruction)`` pairs — each instruction
        a self-contained directive for one independent track (NFS enum, mail
        spray, web discovery, CVE correlation). The tracks run in parallel, each
        in its own sub-agent context, so the driving agent's context stays clean
        and wall-clock is the slowest single track rather than their sum.

        Each sub-agent's ``<FINDINGS>`` block is parsed and merged centrally (in
        this thread — no concurrent scanner mutation), so feed-forward is robust
        even if a sub-agent never writes to the shared DB. Returns
        ``{"responses": {label: text}, "merged": int}``. Fails closed: a missing
        ``hermes`` binary raises :class:`HermesNotFoundError`.
        """
        prompts = [(label, self._build_task_prompt(label, instr)) for label, instr in tasks]
        if not prompts:
            return {"responses": {}, "merged": 0}

        def run_one(item: tuple[str, str]) -> tuple[str, str]:
            label, prompt = item
            try:
                return label, self._run_hermes(prompt, timeout=timeout, label=label)
            except self.HermesNotFoundError:
                # Affects every track (binary missing) — fail closed, re-raise.
                raise
            except Exception as e:
                # Isolate a single track's failure so the others still return.
                return label, f"[TRACK ERROR] {type(e).__name__}: {e}"

        workers = max(1, min(max_workers, len(prompts)))
        print(f"\n[fan-out] {len(prompts)} parallel track(s), {workers} worker(s)")
        responses: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for label, response in pool.map(run_one, prompts):
                responses[label] = response

        # Order matters: all workers have exited, so reload any state a sub-agent
        # persisted directly BEFORE merging declared <FINDINGS> on top — otherwise
        # _save_state() would clobber what the sub-agents wrote.
        self._reload_state()
        merged = 0
        for response in responses.values():
            merged += self._merge_agent_findings(self._parse_findings(response))
        if merged:
            print(f"[fan-out] Merged {merged} reported finding(s)")
            self.scanner._save_state()
        return {"responses": responses, "merged": merged}

    def _writeback_lessons(self, findings: list[dict[str, Any]]) -> int:
        """Record confirmed findings as searchable KB lessons. Returns count added."""
        tech = self._format_discovered().get("tech_hints", [])
        written = 0
        for f in findings:
            vuln = str(f.get("type") or f.get("vuln_type") or "finding")
            endpoint = str(f.get("endpoint", ""))
            payload = str(f.get("payload", ""))
            evidence = "; ".join(str(d) for d in (f.get("details") or [])) or str(
                f.get("evidence", "")
            )
            title = f"{vuln} on {self.scanner.host}{endpoint}"
            body = (
                f"Confirmed {vuln} at {endpoint} on {self.target_url}.\n"
                f"Payload: {payload}\nEvidence: {evidence}\n"
                f"Tech: {', '.join(tech) if tech else 'unknown'}"
            )
            tags = ", ".join([vuln, *tech])
            try:
                if self.kb.add_lesson(title, body, tags=tags, host=self.scanner.host, key=vuln):
                    written += 1
            except Exception:
                continue
        if written:
            print(f"[memory] Wrote {written} lesson(s) to the knowledge base")
        return written

    @staticmethod
    def _build_verify_prompt(finding: dict[str, Any], target_url: str) -> str:
        """Prompt a skeptic sub-agent to REFUTE a single finding."""
        import json as _json

        return "\n".join(
            [
                "You are an adversarial verifier. Your job is to REFUTE the claim below,",
                "not to confirm it. Re-test it independently against the target and decide",
                "whether it actually reproduces. Default to refuted=true when uncertain.",
                "",
                f"Target: {target_url}",
                "## Claimed finding",
                _json.dumps(finding, indent=2, default=str)[:800],
                "",
                "## Required output",
                f"End with a verdict block: <{SkillOrchestrator.VERDICT_TAG}>"
                '{"refuted": true|false, "reason": "..."}'
                f"</{SkillOrchestrator.VERDICT_TAG}>",
            ]
        )

    def verify_finding(
        self, finding: dict[str, Any], *, votes: int = 3, timeout: int = 60
    ) -> dict[str, Any]:
        """Spawn ``votes`` skeptic sub-agents and refute by majority.

        Returns ``{"finding", "refuted", "votes"}``. A finding is refuted when a
        majority of verifiers say so (ties favour keeping the finding).
        """
        prompt = self._build_verify_prompt(finding, self.target_url)

        verdicts: list[dict[str, Any]] = []
        refuted_count = 0
        for _ in range(max(1, votes)):
            response = self._run_hermes(prompt, timeout=timeout, label="verify")
            verdict = self._extract_tagged_json(response, self.VERDICT_TAG)
            if isinstance(verdict, dict):
                verdicts.append(verdict)
                if verdict.get("refuted") is True:
                    refuted_count += 1

        refuted = refuted_count > (len(verdicts) / 2) if verdicts else False
        return {"finding": finding, "refuted": refuted, "votes": verdicts}

    def verify_findings(
        self,
        findings: list[dict[str, Any]] | None = None,
        *,
        votes: int = 3,
        timeout: int = 60,
    ) -> list[dict[str, Any]]:
        """Adversarially verify findings (defaults to all current findings)."""
        targets = findings if findings is not None else list(self.scanner.findings)
        if not targets:
            return []
        print(f"\n[verify] Adversarially verifying {len(targets)} finding(s), {votes} votes each")
        results: list[dict[str, Any]] = []
        for finding in targets:
            try:
                results.append(self.verify_finding(finding, votes=votes, timeout=timeout))
            except self.HermesNotFoundError as e:
                print(f"[verify] aborted: {e}")
                # Without verifiers we cannot refute — keep findings unverified.
                return [{"finding": f, "refuted": False, "votes": []} for f in targets]
        return results
