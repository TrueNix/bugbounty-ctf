from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol

from bugbounty_ctf.knowledge import KnowledgeBase


class IoCType(str, Enum):
    CVE = "CVE"
    IP = "IP"
    HASH = "HASH"
    URL = "URL"
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"
    TOOL = "TOOL"
    TECHNIQUE = "TECHNIQUE"
    CREDENTIAL_PATTERN = "CREDENTIAL_PATTERN"


@dataclass(frozen=True, slots=True)
class Extraction:
    type: IoCType
    value: str
    context: str
    confidence: float
    source: str


class _SpacySpan(Protocol):
    text: str
    label_: str


class _SpacyDoc(Protocol):
    ents: Sequence[_SpacySpan]


class _SpacyModel(Protocol):
    def __call__(self, text: str) -> _SpacyDoc: ...


_Extractor = Callable[[str, str], list[Extraction]]

TOOL_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "amass",
        "bloodhound",
        "burp suite",
        "burpsuite",
        "crackmapexec",
        "dirb",
        "dirbuster",
        "ffuf",
        "gobuster",
        "hashcat",
        "hydra",
        "impacket",
        "john",
        "linpeas",
        "masscan",
        "metasploit",
        "mimikatz",
        "nikto",
        "nmap",
        "nuclei",
        "rustscan",
        "sqlmap",
        "subfinder",
        "winpeas",
        "wpscan",
    }
)

CVE_RE: Final = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE: Final = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_PATTERNS: Final[tuple[tuple[re.Pattern[str], float], ...]] = (
    (re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"), 0.9),
    (re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"), 0.86),
    (re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"), 0.82),
)
URL_RE: Final = re.compile(r"https?://[^\s<>'\"\)\]\}]+", re.IGNORECASE)
EMAIL_RE: Final = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE: Final = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|htb|local|lan|internal|test)\b",
    re.IGNORECASE,
)
TECHNIQUE_RE: Final = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CREDENTIAL_RE: Final = re.compile(
    r"\b(password|passwd|key|token|secret)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)
SPACY_LABEL_TYPES: Final[dict[str, IoCType]] = {
    "ORG": IoCType.TOOL,
    "PRODUCT": IoCType.TOOL,
    "GPE": IoCType.DOMAIN,
}
CONTEXT_CHARS: Final = 48


class IoCExtractor:
    def __init__(self, *, spacy_model: str | None = None) -> None:
        self._spacy_model = _load_spacy_model(spacy_model)

    def extract(self, text: str, *, source: str = "") -> list[Extraction]:
        extractors: tuple[_Extractor, ...] = (
            self._extract_cves,
            self._extract_ips,
            self._extract_hashes,
            self._extract_urls,
            self._extract_emails,
            self._extract_domains,
            self._extract_tools,
            self._extract_techniques,
            self._extract_credentials,
        )
        findings: list[Extraction] = []
        for extractor in extractors:
            findings.extend(extractor(text, source))
        findings.extend(self._spacy_extract(text, source))
        return _dedupe_findings(findings)

    def _extract_cves(self, text: str, source: str) -> list[Extraction]:
        return [
            Extraction(IoCType.CVE, match.group(0).upper(), _context(text, match), 0.95, source)
            for match in CVE_RE.finditer(text)
        ]

    def _extract_ips(self, text: str, source: str) -> list[Extraction]:
        findings: list[Extraction] = []
        for match in IP_RE.finditer(text):
            value = match.group(0)
            if not _valid_ipv4(value):
                continue
            if _is_loopback_or_unspecified(value) and not _is_url_context(text, match.start()):
                continue
            findings.append(Extraction(IoCType.IP, value, _context(text, match), 0.9, source))
        return findings

    def _extract_hashes(self, text: str, source: str) -> list[Extraction]:
        findings: list[Extraction] = []
        for pattern, confidence in HASH_PATTERNS:
            findings.extend(
                Extraction(
                    IoCType.HASH, match.group(0).lower(), _context(text, match), confidence, source
                )
                for match in pattern.finditer(text)
            )
        return findings

    def _extract_urls(self, text: str, source: str) -> list[Extraction]:
        return [
            Extraction(IoCType.URL, _clean_url(match.group(0)), _context(text, match), 0.8, source)
            for match in URL_RE.finditer(text)
        ]

    def _extract_emails(self, text: str, source: str) -> list[Extraction]:
        return [
            Extraction(IoCType.EMAIL, match.group(0).lower(), _context(text, match), 0.88, source)
            for match in EMAIL_RE.finditer(text)
        ]

    def _extract_domains(self, text: str, source: str) -> list[Extraction]:
        return [
            Extraction(IoCType.DOMAIN, match.group(0).lower(), _context(text, match), 0.58, source)
            for match in DOMAIN_RE.finditer(text)
            if not _looks_like_email_domain(text, match.start())
        ]

    def _extract_tools(self, text: str, source: str) -> list[Extraction]:
        findings: list[Extraction] = []
        for keyword in TOOL_KEYWORDS:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_-]){re.escape(keyword)}(?![A-Za-z0-9_-])",
                re.IGNORECASE,
            )
            findings.extend(
                Extraction(IoCType.TOOL, keyword, _context(text, match), 0.76, source)
                for match in pattern.finditer(text)
            )
        return findings

    def _extract_techniques(self, text: str, source: str) -> list[Extraction]:
        return [
            Extraction(
                IoCType.TECHNIQUE,
                match.group(0).upper(),
                _context(text, match),
                0.9,
                source,
            )
            for match in TECHNIQUE_RE.finditer(text)
        ]

    def _extract_credentials(self, text: str, source: str) -> list[Extraction]:
        findings: list[Extraction] = []
        for match in CREDENTIAL_RE.finditer(text):
            key = match.group(1).lower()
            secret = match.group(2)
            context = _context(text, match).replace(secret, "***")
            findings.append(
                Extraction(IoCType.CREDENTIAL_PATTERN, f"{key}=***", context, 0.7, source)
            )
        return findings

    def _spacy_extract(self, text: str, source: str) -> list[Extraction]:
        if self._spacy_model is None:
            return []
        findings: list[Extraction] = []
        for entity in self._spacy_model(text).ents:
            value = entity.text.strip()
            if not value:
                continue
            ioc_type = SPACY_LABEL_TYPES.get(entity.label_.upper())
            if ioc_type is None:
                continue
            start = text.find(entity.text)
            if start == -1:
                start = 0
            match_context = _context_from_span(text, start, start + len(entity.text))
            findings.append(Extraction(ioc_type, value, match_context, 0.62, source))
        return findings


def extract_from_kb(
    kb: KnowledgeBase,
    *,
    source_prefix: str = KnowledgeBase.INGESTED_PREFIX,
) -> dict[str, list[Extraction]]:
    extractor = IoCExtractor()
    results: dict[str, list[Extraction]] = {}
    for doc in kb.list_references():
        filename = doc["filename"]
        if source_prefix and not filename.startswith(source_prefix):
            continue
        results[filename] = extractor.extract(doc["content"], source=filename)
    return results


def summarize_extractions(extractions: list[Extraction]) -> dict[IoCType, list[str]]:
    grouped: dict[IoCType, set[str]] = {}
    for extraction in extractions:
        grouped.setdefault(extraction.type, set()).add(extraction.value)
    return {ioc_type: sorted(grouped[ioc_type]) for ioc_type in IoCType if ioc_type in grouped}


def format_extraction_summary(extractions: list[Extraction]) -> str:
    summary = summarize_extractions(extractions)
    return "\n".join(
        f"{ioc_type.value}: {', '.join(values)}" for ioc_type, values in summary.items()
    )


def _load_spacy_model(model_name: str | None) -> _SpacyModel | None:
    if model_name is None:
        return None
    try:
        import spacy
    except ImportError:
        return None
    try:
        model: _SpacyModel = spacy.load(model_name)
    except (ImportError, OSError, ValueError):
        return None
    return model


def _dedupe_findings(findings: list[Extraction]) -> list[Extraction]:
    best: dict[tuple[IoCType, str], Extraction] = {}
    for finding in findings:
        key = (finding.type, finding.value)
        previous = best.get(key)
        if previous is None or finding.confidence > previous.confidence:
            best[key] = finding
    return sorted(best.values(), key=lambda item: (-item.confidence, item.type.value, item.value))


def _context(text: str, match: re.Match[str]) -> str:
    return _context_from_span(text, match.start(), match.end())


def _context_from_span(text: str, start: int, end: int) -> str:
    left = max(start - CONTEXT_CHARS, 0)
    right = min(end + CONTEXT_CHARS, len(text))
    return re.sub(r"\s+", " ", text[left:right]).strip()


def _valid_ipv4(value: str) -> bool:
    return all(0 <= int(part) <= 255 for part in value.split("."))


def _is_loopback_or_unspecified(value: str) -> bool:
    return value == "0.0.0.0" or value.startswith("127.")


def _is_url_context(text: str, start: int) -> bool:
    window = text[max(0, start - 32) : start].lower()
    marker = max(window.rfind("http://"), window.rfind("https://"))
    return marker != -1 and not any(char.isspace() for char in window[marker:])


def _clean_url(value: str) -> str:
    return value.rstrip(".,;:!?")


def _looks_like_email_domain(text: str, start: int) -> bool:
    return start > 0 and text[start - 1] == "@"
