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

import contextlib
import json
import os
import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase
from bugbounty_ctf.recon import clear_dead_end, list_dead_ends, record_dead_end
from bugbounty_ctf.taint import render, render_json

# Minimum recalled-pattern confidence for run(mode="auto") to FRONT-LOAD it
# (reorder fan-out tracks to follow its proven step order). Below this, the
# surface is treated as novel and dispatch degrades to default ordering.
PATTERN_RECALL_THRESHOLD = 0.5

# Maps a playbook Track's generalized ``capability`` (a CAPABILITY_TOKEN) to the
# pattern technique token(s) that exercise it. Used by run(mode="auto") to find
# where a selected track sits in a recalled pattern's step sequence, so tracks
# whose technique appears earlier in the proven chain run first. Capabilities
# absent here simply have no pattern position (kept in original relative order).
_CAPABILITY_TO_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "nfs_export": ("nfs_enum_exports", "nfs_uid_spoof"),
    "imap_open": ("cred_spray_mail_users", "mailbox_secret_pivot"),
    "smtp_open": ("cred_spray_mail_users",),
    "webmail_vhost": ("webadmin_login_reuse",),
    "web_app": (
        "web_content_discovery",
        "webadmin_login_reuse",
        "admin_panel_backup_to_rce",
        "file_upload_rce",
        "sqli_dump_creds",
        "ssti_rce",
        "ssrf_metadata_creds",
    ),
    "version_banner": ("cve_exploit",),
    "smb_open": (),
}


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
    prior_dead_ends: list[dict[str, Any]] = field(default_factory=list)
    prior_observations: list[dict[str, Any]] = field(default_factory=list)
    # Generalized, surface-keyed attack patterns recalled from prior engagements
    # (the cross-box pattern memory). Plain dicts so they render directly.
    recalled_patterns: list[dict[str, Any]] = field(default_factory=list)
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
        # Surface the run dispatched on — reused by :meth:`_writeback_pattern`
        # to build the (generalized) trigger of a captured pattern. Set in
        # :meth:`run` when ports/tech are provided; empty otherwise.
        self._dispatch_ports: tuple[int, ...] = ()
        self._dispatch_tech: tuple[str, ...] = ()
        # Pattern ids surfaced to the agent / used to reorder dispatch this run.
        # _recall_patterns populates it; _score_pattern_feedback scores them
        # against what the run actually achieved, then clears it (Deliverable A).
        self._surfaced_pattern_ids: set[str] = set()

    def _query_rag(self, query: str, limit: int = 5) -> str:
        results = self.kb.search(query, limit=limit)
        if not results:
            return ""
        lines = []
        for r in results:
            # KB lessons can embed target-derived payload/evidence (see
            # _writeback_lessons), so render every leaf before it joins a line.
            lines.append(
                f"{render(r['filename'])} > {render(r['section'])}: {render(r['snippet'], maxlen=120)}"
            )
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
            # tech_hints are scraped from target responses — render each leaf.
            lines.append(f"tech: {', '.join(render(t) for t in discovered['tech_hints'])}")
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

    def _recall_dead_ends(self) -> list[dict[str, Any]]:
        try:
            return list_dead_ends(self.kb, host=self.scanner.host)
        except Exception:
            return []

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

    def _surface_capabilities(
        self,
        ports: tuple[int, ...],
        tech: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Derive GENERALIZED surface capabilities from ports + tech (no findings).

        Complements :meth:`_derive_capabilities` (which reads confirmed findings):
        this maps the *discovered surface* — open ports and tech hints — to closed
        capability tokens so a recall can run before anything is confirmed. Only
        tokens in :data:`patterns.CAPABILITY_TOKENS` are emitted.
        """
        from bugbounty_ctf import patterns

        # Port → capability for the surface signals a recall can key on.
        port_caps: dict[int, str] = {
            2049: "nfs_export",
            111: "nfs_export",
            143: "imap_open",
            993: "imap_open",
            110: "imap_open",
            995: "imap_open",
            25: "smtp_open",
            465: "smtp_open",
            587: "smtp_open",
            445: "smb_open",
            139: "smb_open",
            80: "web_app",
            443: "web_app",
            8080: "web_app",
            8000: "web_app",
            8443: "web_app",
            8888: "web_app",
        }
        caps: list[str] = []
        for p in ports:
            token = port_caps.get(p)
            if token and token not in caps and token in patterns.CAPABILITY_TOKENS:
                caps.append(token)
        # Tech hints can name a capability directly (reuse the substring hints).
        haystacks = [t.lower() for t in tech]
        for needle, token in self._CAPABILITY_HINTS:
            if token in caps:
                continue
            if token in patterns.CAPABILITY_TOKENS and any(needle in h for h in haystacks):
                caps.append(token)
        return tuple(caps)

    def _recall_patterns(
        self,
        *,
        ports: tuple[int, ...] | None = None,
        tech: tuple[str, ...] | None = None,
        capabilities: tuple[str, ...] | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Recall the top GENERALIZED attack patterns for the current surface.

        Resolves the surface (ports/tech/capabilities) from args or, when absent,
        from the dispatched surface and discovered tech, then asks the pattern
        store for candidates and ranks them by surface overlap
        (:func:`patterns.rank_patterns`). Returns the top ``limit`` as plain
        dicts (via :meth:`AttackPattern.to_dict`) so they render directly into a
        prompt. Defensive like the other ``_recall_*`` methods: any DB error
        yields ``[]`` rather than aborting a run.
        """
        from bugbounty_ctf import patterns

        resolved_ports = ports if ports is not None else self._dispatch_ports
        if tech is not None:
            resolved_tech = tuple(t.lower() for t in tech)
        else:
            resolved_tech = tuple(
                str(t).lower() for t in self._format_discovered().get("tech_hints", [])
            )
        if capabilities is not None:
            resolved_caps = capabilities
        else:
            resolved_caps = self._surface_capabilities(resolved_ports, resolved_tech)

        try:
            candidates = self.scanner.db.match_patterns(
                resolved_ports, resolved_tech, resolved_caps
            )
        except Exception:
            return []

        # Time-decay each candidate's confidence BEFORE ranking so stale
        # patterns sink (Deliverable D). The decay is applied to a COPY used
        # only for ranking/threshold — the returned dicts keep the true stored
        # confidence (decay is a recall concern, not a persisted one).
        now = datetime.now().isoformat()
        decayed = [
            replace(
                c,
                confidence=patterns.decayed_confidence(c.confidence, c.last_seen, now),
            )
            for c in candidates
        ]
        ranked_decayed = patterns.rank_patterns(
            decayed,
            ports=resolved_ports,
            tech=resolved_tech,
            capabilities=resolved_caps,
        )
        # Map back to the originals (true stored confidence) by id, order kept.
        by_id = {c.pattern_id: c for c in candidates}
        ranked = [by_id[d.pattern_id] for d in ranked_decayed if d.pattern_id in by_id]

        top = ranked[:limit]
        # Attribution: remember which patterns influenced THIS run so the
        # feedback pass can score them (Deliverable A).
        self._surfaced_pattern_ids.update(p.pattern_id for p in top)
        return [p.to_dict() for p in top]

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
            prior_dead_ends=self._recall_dead_ends(),
            prior_observations=self._recall_observations(),
            recalled_patterns=self._recall_patterns(),
        )

    def get_research_guidance(self) -> PhaseGuidance:
        self.current_phase = "research"
        tech = self.scanner.attack_surface.get("/", {}).get("tech_hints", [])
        if tech:
            methodology = self.kb.suggest_methodology(tech)
        else:
            methodology = self.kb.search("web vulnerability testing")
        rag_lines = [
            f"{render(m['filename'])} > {render(m['section'])}: {render(m['snippet'], maxlen=120)}"
            for m in methodology[:10]
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
            prior_dead_ends=self._recall_dead_ends(),
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
            recalled_patterns=self._recall_patterns(),
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
        """Re-read findings/surface a sub-agent persisted to the shared
        ScannerDB, so the next phase (and the final report) reflect what it
        discovered. There is a single store now, so this is a DB re-query — no
        JSON read, no clobber-ordering dance."""
        self.scanner.reload()

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
                render_json(guidance.discovered, maxlen=1000),
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

        # Proven, transferable playbook FIRST — above per-host prior memory — so
        # the agent reads the generalized plan that won on a same-shaped box and
        # tries it before re-deriving. Top 1-2 only (don't flood). Every leaf is
        # funneled through render() (defense-in-depth: patterns are secret-free,
        # but this is the same valve the other recall blocks use).
        for pattern in guidance.recalled_patterns[:2]:
            steps = pattern.get("steps", [])
            if not isinstance(steps, list) or not steps:
                continue
            conf = render(f"{float(pattern.get('confidence', 0.0)):.2f}")
            worked = render(str(pattern.get("worked", 0)))
            applied = render(str(pattern.get("applied", pattern.get("worked", 0))))
            caps = pattern.get("capabilities", [])
            surface = " + ".join(render(str(c)) for c in caps) if caps else "(generalized)"
            lines.extend(
                [
                    "",
                    f"## Proven attack pattern for this surface "
                    f"(confidence {conf}, worked {worked}/{applied})",
                    f"Surface match: {surface}",
                    "Try this sequence FIRST, before re-deriving from scratch:",
                ]
            )
            for i, step in enumerate(steps, start=1):
                technique = render(str(step.get("technique", "?")))
                rationale = render(str(step.get("rationale", "")), maxlen=120)
                lines.append(f"  {i}. {technique}  — {rationale}")
            lines.extend(
                [
                    "This is a generalized technique sequence from prior engagements, NOT",
                    "target-specific data. Adapt each step to THIS target.",
                ]
            )

        if guidance.prior_memory:
            lines.extend(["", "## Prior memory (confirmed on this host in past runs)"])
            for m in guidance.prior_memory[:15]:
                lines.append(
                    f"  - {render(m.get('vuln_type', '?'))} @ "
                    f"{render(m.get('endpoint', '?'))}"
                    f" (payload: {render(m.get('payload', ''), maxlen=60)})"
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
                        f"{render(h['vuln_type'])}@{render(h['param'])}" for h in confirmed[:8]
                    )
                )
            if rejected:
                lines.append(
                    "  rejected (skip — already ruled out): "
                    + ", ".join(
                        f"{render(h['vuln_type'])}@{render(h['param'])}" for h in rejected[:8]
                    )
                )

        if guidance.prior_dead_ends:
            track_ids = [
                render(str(d.get("track_id", "?")))
                for d in guidance.prior_dead_ends[:15]
                if d.get("track_id")
            ]
            if track_ids:
                lines.extend(
                    [
                        "",
                        "## Known dead-ends on this host (deprioritize — no findings in past runs)",
                        "  - " + ", ".join(track_ids),
                        "Re-test only if the surface changed (new port/service since last run).",
                    ]
                )

        if guidance.prior_observations:
            lines.extend(["", "## Prior observations — suggested next tests"])
            for o in guidance.prior_observations[:8]:
                hint = render(o.get("next_test", ""), maxlen=80)
                lines.append(
                    f"  - {render(o.get('vuln_type', '?'))} @ "
                    f"{render(o.get('endpoint', '?'))}: {hint}"
                )

        if guidance.previous_findings:
            lines.extend(["", "## Previous findings"])
            for f in guidance.previous_findings[:10]:
                lines.append(f"  - {render(f.get('type', '?'))}: {render(f.get('endpoint', '?'))}")

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

            # Single store: reload from the shared ScannerDB to pull in anything
            # the sub-agent persisted directly, then merge its declared
            # <FINDINGS> on top. _merge_agent_findings persists each new finding
            # to the same DB, so the merged set is already durable — no
            # round-trip needed to reconcile two stores.
            self._reload_state()
            merged = self._merge_agent_findings(self._parse_findings(response))
            if merged:
                print(f"[{phase}] Merged {merged} reported finding(s)")

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
        # Capture: synthesize a generalized, surface-keyed pattern from the
        # solved chain so a future run on a same-shaped box can recall it.
        final["pattern_captured"] = self._writeback_pattern(confirmed)
        # Feedback: score the patterns this run was shown against what it
        # actually achieved, so their confidence self-corrects. Runs AFTER
        # capture so it reads post-capture state (Deliverable C).
        final["pattern_feedback"] = self._score_pattern_feedback(
            confirmed, now=datetime.now().isoformat()
        )
        # Retention: drop patterns that have been tried enough yet keep failing.
        with contextlib.suppress(Exception):
            self.scanner.db.prune_patterns()

        self.save_results()
        return final

    @staticmethod
    def _track_pattern_index(capability: str, technique_order: dict[str, int]) -> int | None:
        """Earliest index in a pattern's step order that a track's capability hits.

        A track exercises one or more techniques (via :data:`_CAPABILITY_TO_TECHNIQUES`);
        its position in the proven chain is the *min* index at which any of those
        techniques appears in ``technique_order`` (technique → step index).
        Returns ``None`` when the track is not referenced by the pattern at all.
        """
        candidates = _CAPABILITY_TO_TECHNIQUES.get(capability, ())
        hits = [technique_order[t] for t in candidates if t in technique_order]
        return min(hits) if hits else None

    def _apply_pattern_to_tracks(
        self,
        tracks: list[Any],
        *,
        ports: tuple[int, ...],
        tech: tuple[str, ...],
    ) -> tuple[list[tuple[str, str]], str | None]:
        """Front-load fan-out tasks to follow a proven pattern's step order.

        Recalls the top pattern for the surface. If its confidence clears
        :data:`PATTERN_RECALL_THRESHOLD` AND it shares surface with the selected
        tracks (at least one track maps into the pattern's steps), tracks are
        REORDERED so those whose capability-technique appears earlier in the
        chain run first; unreferenced tracks keep their original relative order,
        appended after. The lead task's instruction is prefixed with the proven,
        secret-free step list as a short preamble.

        This NEVER replaces selection: a novel surface (no pattern, low
        confidence, or no shared surface) returns the tasks in their original
        order with a ``None`` pattern id — today's behavior, unchanged. Returns
        ``(tasks, pattern_id)``.
        """
        default = [(t.id, t.instruction) for t in tracks]
        recalled = self._recall_patterns(ports=ports, tech=tech, limit=1)
        if not recalled:
            return default, None
        pattern = recalled[0]
        if float(pattern.get("confidence", 0.0)) < PATTERN_RECALL_THRESHOLD:
            return default, None

        steps = pattern.get("steps", [])
        if not isinstance(steps, list) or not steps:
            return default, None
        technique_order: dict[str, int] = {}
        for idx, step in enumerate(steps):
            technique = str(step.get("technique", ""))
            if technique and technique not in technique_order:
                technique_order[technique] = idx

        # (original_index, pattern_index|None, track) — stable sort keeps the
        # original relative order both within a tie and among unreferenced tracks.
        annotated = [
            (i, self._track_pattern_index(t.capability, technique_order), t)
            for i, t in enumerate(tracks)
        ]
        if not any(pidx is not None for _, pidx, _ in annotated):
            # No selected track is referenced by the pattern → no shared surface.
            return default, None

        # Referenced tracks sort by their pattern step index; unreferenced tracks
        # sort after all referenced ones, preserving original relative order.
        unreferenced_rank = len(steps)

        def sort_key(item: tuple[int, int | None, Any]) -> tuple[int, int]:
            orig_i, pidx, _track = item
            return (pidx if pidx is not None else unreferenced_rank, orig_i)

        reordered = sorted(annotated, key=sort_key)
        tasks = [(t.id, t.instruction) for _, _, t in reordered]

        # Prepend the proven step order to the lead task as a short preamble.
        preamble_steps = "; ".join(
            f"{render(str(s.get('technique', '?')))} — "
            f"{render(str(s.get('rationale', '')), maxlen=100)}"
            for s in steps
        )
        if tasks:
            lead_label, lead_instr = tasks[0]
            preamble = (
                "Proven order from a prior same-shaped engagement (adapt to THIS "
                f"target): {preamble_steps}\n\n"
            )
            tasks[0] = (lead_label, preamble + lead_instr)

        pid = pattern.get("pattern_id")
        return tasks, (str(pid) if pid else None)

    def run(
        self,
        *,
        mode: str = "auto",
        ports: Iterable[int] | None = None,
        tech: Iterable[str] | None = None,
        timeout_per_phase: int = 120,
        verify: bool = True,
        autodetect: bool = True,
    ) -> dict[str, Any]:
        """Autonomous entry point — dispatch to fan-out or the headless flow.

        This is the single autonomous orchestration entry. It does NOT
        reimplement any logic; it selects a strategy and delegates to the
        existing :meth:`fan_out` and :meth:`run_with_agents` methods.

        When ``ports`` and ``tech`` are both ``None`` and ``autodetect=True``
        (the default), the method automatically runs :func:`~bugbounty_ctf.recon.detect_surface`
        against the orchestrator's target host to produce a :class:`~bugbounty_ctf.recon.Surface`,
        then uses its ``open_ports`` and ``tech`` as if the caller had passed them
        explicitly.  Pass ``autodetect=False`` to skip this step (e.g. when you
        already know the target has no reachable ports from the agent host).

        Modes:

        - ``"auto"`` (default): if ``ports``/``tech`` are given, select playbook
          tracks (:func:`bugbounty_ctf.playbook.select`) and fan out the
          ``parallel_safe`` ones when there are at least two; otherwise fall back
          to the headless per-phase flow. With no surface hints, always falls
          back to the headless flow.
        - ``"fanout"``: require ``ports``/``tech`` and always fan out the
          ``parallel_safe`` selected tracks.
        - ``"headless"``: always run the four-phase per-agent flow.

        The interactive in-process path (``get_*_guidance()`` driven by the
        running agent) is unaffected — that remains the agent-owned loop.
        """
        from bugbounty_ctf import playbook

        # Auto-detect surface when no ports/tech given and we know the target.
        if ports is None and tech is None and autodetect and self.target_url:
            try:
                from bugbounty_ctf.recon import detect_surface

                host = self.target_url.split("://", 1)[-1].split("/")[0].rsplit(":", 1)[0]
                if host:
                    surface = detect_surface(host)
                    auto_ports, auto_tech = surface.for_run()
                    if auto_ports or auto_tech:
                        ports = auto_ports
                        tech = auto_tech
                        vhost_hint = f", vhosts={list(surface.vhosts)}" if surface.vhosts else ""
                        print(
                            f"[recon] auto-detected: ports={auto_ports}, "
                            f"tech={auto_tech}{vhost_hint}"
                        )
            except Exception as exc:
                print(f"[recon] surface autodetect failed ({exc}), proceeding without")

        # Remember the surface this run dispatched on so a captured pattern's
        # trigger reflects the ports/tech it actually ran against (generalized).
        if ports is not None:
            self._dispatch_ports = tuple(int(p) for p in ports)
        if tech is not None:
            self._dispatch_tech = tuple(str(t) for t in tech)

        def _parallel_tracks() -> list[playbook.Track]:
            tracks = playbook.select(ports, tech)
            return [t for t in tracks if t.parallel_safe]

        if mode == "headless":
            return self.run_with_agents(timeout_per_phase=timeout_per_phase, verify=verify)

        if mode == "fanout":
            if ports is None and tech is None:
                raise ValueError("mode='fanout' requires ports and/or tech")
            tracks = _parallel_tracks()
            tasks, pattern_id = self._apply_pattern_to_tracks(
                tracks, ports=self._dispatch_ports, tech=self._dispatch_tech
            )
            result = self.fan_out(tasks)
            result["selected_tracks"] = [t.id for t in tracks]
            result["pattern_applied"] = pattern_id
            return result

        if mode == "auto":
            if ports is None and tech is None:
                return self.run_with_agents(timeout_per_phase=timeout_per_phase, verify=verify)
            tracks = _parallel_tracks()
            if len(tracks) >= 2:
                tasks, pattern_id = self._apply_pattern_to_tracks(
                    tracks, ports=self._dispatch_ports, tech=self._dispatch_tech
                )
                result = self.fan_out(tasks)
                result["selected_tracks"] = [t.id for t in tracks]
                result["pattern_applied"] = pattern_id
                return result
            return self.run_with_agents(timeout_per_phase=timeout_per_phase, verify=verify)

        raise ValueError(f"unknown mode: {mode!r}")

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
            return {
                "responses": {},
                "merged": 0,
                "dead_ends_recorded": 0,
                "dead_ends_cleared": 0,
            }

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

        # All workers have exited. Single store: reload from the shared
        # ScannerDB to pull in what sub-agents persisted directly, then merge
        # declared <FINDINGS> on top. _merge_agent_findings persists each new
        # finding to the same DB, so the merged set is already durable.
        self._reload_state()
        merged = 0
        for response in responses.values():
            merged += self._merge_agent_findings(self._parse_findings(response))
        if merged:
            print(f"[fan-out] Merged {merged} reported finding(s)")

        dead_ends_recorded = 0
        dead_ends_cleared = 0
        for label, response in responses.items():
            track_findings = self._parse_findings(response)
            track_error = response.startswith("[TRACK ERROR]")
            if not track_findings or track_error:
                reason = "track error" if track_error else "no findings reported"
                with contextlib.suppress(Exception):
                    if record_dead_end(
                        self.kb,
                        host=self.scanner.host,
                        track_id=label,
                        reason=reason,
                    ):
                        dead_ends_recorded += 1
            else:
                with contextlib.suppress(Exception):
                    if clear_dead_end(self.kb, host=self.scanner.host, track_id=label):
                        dead_ends_cleared += 1

        # Final step: persist what worked. Lessons (technique-level, secret-free)
        # feed the per-host KB; the captured pattern (generalized, surface-keyed)
        # feeds the cross-box pattern memory. Confirmed = the merged finding set.
        confirmed = list(self.scanner.findings)
        lessons = self._writeback_lessons(confirmed)
        pattern_id = self._writeback_pattern(confirmed)
        # Feedback: score the patterns this run was shown against what it
        # achieved (AFTER capture, so post-capture state is read). Then prune
        # patterns that have been tried enough yet keep failing (Deliverables C/E).
        pattern_feedback = self._score_pattern_feedback(confirmed, now=datetime.now().isoformat())
        with contextlib.suppress(Exception):
            self.scanner.db.prune_patterns()
        return {
            "responses": responses,
            "merged": merged,
            "dead_ends_recorded": dead_ends_recorded,
            "dead_ends_cleared": dead_ends_cleared,
            "lessons_written": lessons,
            "pattern_captured": pattern_id,
            "pattern_feedback": pattern_feedback,
        }

    def _writeback_lessons(self, findings: list[dict[str, Any]]) -> int:
        """Record confirmed findings as searchable KB lessons. Returns count added.

        KB lessons are retrieved CROSS-TARGET (via FTS), so the lesson BODY must
        carry no box-specific secrets: no raw payload, no raw target_url, and no
        secret-shaped evidence. The body is generalized to the technique level
        (vuln type + tech stack + a generalized endpoint *shape*), and every
        retained free-text fragment is funneled through
        :meth:`patterns.PatternGuard.redact` — fail-closed: a fragment that trips
        the secret detector is OMITTED rather than baked in. The title/host stay
        as-is: ``host`` is a DB column (not cross-target prose), not the body.
        """
        from bugbounty_ctf import patterns

        tech = self._format_discovered().get("tech_hints", [])
        written = 0
        for f in findings:
            vuln = str(f.get("type") or f.get("vuln_type") or "finding")
            endpoint = str(f.get("endpoint", ""))
            # Generalize the endpoint to a SHAPE: redact() strips host/path noise
            # to placeholders and rejects (→ None) anything secret-shaped, in
            # which case we omit the endpoint shape entirely (fail-closed).
            endpoint_shape = patterns.PatternGuard.redact(endpoint) if endpoint else ""
            tech_line = ", ".join(tech) if tech else "unknown"
            title = f"{vuln} on {self.scanner.host}{endpoint}"
            body_lines = [f"Confirmed {vuln}."]
            if endpoint_shape:
                body_lines.append(f"Endpoint shape: {endpoint_shape}")
            body_lines.append(f"Tech: {tech_line}")
            body = "\n".join(body_lines)
            tags = ", ".join([vuln, *tech])
            try:
                if self.kb.add_lesson(title, body, tags=tags, host=self.scanner.host, key=vuln):
                    written += 1
            except Exception:
                continue
        if written:
            print(f"[memory] Wrote {written} lesson(s) to the knowledge base")
        return written

    # Generalized observable capabilities derived from a confirmed finding's
    # type/source or a discovered tech hint. Keys are matched as substrings
    # (lowercased) and values MUST be members of patterns.CAPABILITY_TOKENS.
    _CAPABILITY_HINTS: tuple[tuple[str, str], ...] = (
        ("nfs", "nfs_export"),
        ("imap", "imap_open"),
        ("mail", "imap_open"),
        ("smtp", "smtp_open"),
        ("smb", "smb_open"),
        ("roundcube", "webmail_vhost"),
        ("webmail", "webmail_vhost"),
        ("cve", "version_banner"),
        ("version", "version_banner"),
        ("http", "web_app"),
        ("web", "web_app"),
    )

    def _derive_capabilities(self, confirmed: list[dict[str, Any]]) -> tuple[str, ...]:
        """Derive GENERALIZED surface capabilities (subset of CAPABILITY_TOKENS).

        Observables only — read from the confirmed findings' type/source and the
        discovered tech hints. No box-specific text enters: each candidate is a
        closed token, and only tokens in :data:`patterns.CAPABILITY_TOKENS` are
        emitted (PatternGuard re-filters anyway, fail-closed).
        """
        from bugbounty_ctf import patterns

        haystacks: list[str] = []
        for f in confirmed:
            haystacks.append(str(f.get("type") or f.get("vuln_type") or "").lower())
            haystacks.append(str(f.get("source") or "").lower())
        haystacks.extend(t.lower() for t in self._format_discovered().get("tech_hints", []))

        caps: list[str] = []
        for needle, token in self._CAPABILITY_HINTS:
            if token in caps:
                continue
            if token in patterns.CAPABILITY_TOKENS and any(needle in h for h in haystacks):
                caps.append(token)
        return tuple(caps)

    # Outcome inference: RCE-terminal techniques win, then cred techniques.
    _RCE_TECHNIQUES: frozenset[str] = frozenset(
        {"admin_panel_backup_to_rce", "file_upload_rce", "ssti_rce", "cve_exploit"}
    )
    _CRED_TECHNIQUES: frozenset[str] = frozenset(
        {
            "cred_harvest_from_doc",
            "cred_spray_mail_users",
            "mailbox_secret_pivot",
            "sqli_dump_creds",
            "ssrf_metadata_creds",
            "cred_reuse_ssh",
            "su_local_cred_reuse",
            "webadmin_login_reuse",
        }
    )

    def _writeback_pattern(self, confirmed: list[dict[str, Any]]) -> str | None:
        """Synthesize and store a GENERALIZED attack pattern from a solved chain.

        This is the capture half of the pattern-memory loop. It builds a
        surface-keyed, secret-free :class:`patterns.AttackPattern` from the
        confirmed findings and persists it, so a chain that won here can be
        recalled on a different box with the same shape. NO target specifics
        enter the pattern: the trigger is generalized (ports/tech/capabilities),
        each step's technique is a closed token, and each rationale comes from
        :data:`patterns.TECHNIQUE_RATIONALES` (never a finding's payload or
        evidence). :meth:`patterns.PatternGuard.build` is the fail-closed gate;
        if it rejects the pattern (or there are < 2 steps), this returns ``None``.

        Returns the saved ``pattern_id`` or ``None``.
        """
        from datetime import datetime

        from bugbounty_ctf import patterns

        if not confirmed:
            return None

        # Trigger: generalized surface only.
        tech = tuple(str(t).lower() for t in self._format_discovered().get("tech_hints", []))
        ports = self._dispatch_ports
        capabilities = self._derive_capabilities(confirmed)

        # Step sequence: ordered by the engine-recorded timestamp, mapped to
        # closed technique tokens; unmapped findings are skipped; consecutive
        # duplicate techniques are collapsed (preserving order).
        ordered = sorted(confirmed, key=lambda f: str(f.get("timestamp", "")))
        steps: list[patterns.TechniqueStep] = []
        last_technique: str | None = None
        for f in ordered:
            key = str(f.get("type") or f.get("vuln_type") or "").lower()
            technique = patterns.VULN_TO_TECHNIQUE.get(key)
            if technique is None:
                technique = patterns.VULN_TO_TECHNIQUE.get(str(f.get("source") or "").lower())
            if technique is None or technique == last_technique:
                continue
            steps.append(
                patterns.TechniqueStep(
                    technique=technique,
                    rationale=patterns.TECHNIQUE_RATIONALES.get(technique, ""),
                    tool_hint="",
                )
            )
            last_technique = technique

        # A single step is not a pattern.
        if len(steps) < 2:
            return None

        techniques = {s.technique for s in steps}
        if techniques & self._RCE_TECHNIQUES:
            outcome = "rce"
        elif techniques & self._CRED_TECHNIQUES:
            outcome = "cred_pivot"
        else:
            outcome = "foothold"

        now = datetime.now().isoformat()
        # Host-agnostic provenance: a timestamp tag, never the target host.
        run_id = f"run-{now}"
        pattern = patterns.PatternGuard.build(
            ports=ports,
            tech=tech,
            capabilities=capabilities,
            steps=tuple(steps),
            outcome=outcome,
            provenance=(run_id,),
            now=now,
        )
        if pattern is None:
            return None
        self.scanner.db.save_pattern(pattern)
        print(f"[memory] Captured pattern {pattern.pattern_id[:12]} ({outcome})")
        return pattern.pattern_id

    def _achieved_techniques(self, confirmed: list[dict[str, Any]]) -> set[str]:
        """Map confirmed findings' type/source → generalized technique tokens.

        The run's ``achieved`` technique-set: each finding's ``type``/``vuln_type``
        (then ``source``) is looked up in :data:`patterns.VULN_TO_TECHNIQUE`;
        unmapped findings contribute nothing. This is the same vocabulary the
        capture path uses, so scoring compares like with like.
        """
        from bugbounty_ctf import patterns

        achieved: set[str] = set()
        for f in confirmed:
            key = str(f.get("type") or f.get("vuln_type") or "").lower()
            technique = patterns.VULN_TO_TECHNIQUE.get(key)
            if technique is None:
                technique = patterns.VULN_TO_TECHNIQUE.get(str(f.get("source") or "").lower())
            if technique is not None:
                achieved.add(technique)
        return achieved

    def _score_pattern_feedback(
        self, confirmed: list[dict[str, Any]], *, now: str
    ) -> dict[str, str]:
        """Score each surfaced pattern on whether it actually helped this run.

        The feedback half of the pattern-memory loop (Deliverable C). For every
        pattern recalled this run (``self._surfaced_pattern_ids``), compute how
        much of its proven step sequence the run actually ACHIEVED::

            overlap = |{pattern step techniques} ∩ achieved| / max(1, num_steps)

        where ``achieved`` is the run's confirmed findings mapped to technique
        tokens (:meth:`_achieved_techniques`). The pattern was surfaced, so it
        counts as applied; it ``worked`` when overlap ≥ 0.5 and ``failed``
        otherwise. :meth:`ScannerDB.bump_pattern_stats` nudges the counts and
        recomputes confidence, so it self-corrects over time. Returns a small
        ``{pattern_id: "worked"|"failed"}`` map for the run summary.

        Always clears ``self._surfaced_pattern_ids`` and is fully defensive —
        feedback must never break a run.
        """
        feedback: dict[str, str] = {}
        try:
            achieved = self._achieved_techniques(confirmed)
            for pid in self._surfaced_pattern_ids:
                pattern = self.scanner.db.get_pattern(pid)
                if pattern is None:
                    continue
                step_techniques = {s.technique for s in pattern.steps}
                overlap = len(step_techniques & achieved) / max(1, len(pattern.steps))
                worked = overlap >= 0.5
                self.scanner.db.bump_pattern_stats(
                    pid,
                    applied=1,
                    worked=1 if worked else 0,
                    failed=0 if worked else 1,
                    now=now,
                )
                feedback[pid] = "worked" if worked else "failed"
        except Exception:
            pass
        finally:
            self._surfaced_pattern_ids.clear()
        return feedback

    @staticmethod
    def _build_verify_prompt(finding: dict[str, Any], target_url: str) -> str:
        """Prompt a skeptic sub-agent to REFUTE a single finding."""
        return "\n".join(
            [
                "You are an adversarial verifier. Your job is to REFUTE the claim below,",
                "not to confirm it. Re-test it independently against the target and decide",
                "whether it actually reproduces. Default to refuted=true when uncertain.",
                "",
                f"Target: {render(target_url)}",
                "## Claimed finding",
                render_json(finding, maxlen=800),
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
