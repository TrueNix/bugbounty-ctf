from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Final, Protocol, TypedDict
from urllib.parse import urlparse

import requests

from bugbounty_ctf.knowledge import KnowledgeBase

FEEDS: Final[list[str]] = [
    "https://ctftime.org/writeups/rss/",
    "https://portswigger.net/research/rss",
    "https://projectdiscovery.io/blog/rss.xml",
]
DEFAULT_LIMIT: Final = 20
MAX_SUMMARY_CHARS: Final = 4000
REQUEST_TIMEOUT_SECONDS: Final = 20

logger = logging.getLogger(__name__)


class FeedResponse(Protocol):
    text: str

    def raise_for_status(self) -> None: ...


class FeedFetcher(Protocol):
    def __call__(self, url: str) -> FeedResponse: ...


class IngestSummary(TypedDict):
    feeds: int
    fetched: int
    added: int
    skipped_duplicates: int


@dataclass(frozen=True, slots=True)
class FeedEntry:
    feed_url: str
    title: str
    link: str
    published: str
    summary: str


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self._parts.append(text)

    def text(self) -> str:
        return _collapse_ws(" ".join(self._parts))


def ingest_writeups(
    feeds: list[str] | None = None,
    kb: KnowledgeBase | None = None,
    fetcher: FeedFetcher | None = None,
    limit: int = DEFAULT_LIMIT,
    retention_cap: int | None = None,
) -> IngestSummary:
    feed_urls = list(feeds) if feeds is not None else list(FEEDS)
    feed_fetcher = fetcher if fetcher is not None else _default_fetcher
    entry_limit = max(limit, 0)
    store_owned = kb is None
    store = kb if kb is not None else KnowledgeBase()
    summary = IngestSummary(feeds=len(feed_urls), fetched=0, added=0, skipped_duplicates=0)

    try:
        for feed_url in feed_urls:
            try:
                response = feed_fetcher(feed_url)
                response.raise_for_status()
                entries = _parse_feed(feed_url, response.text)
            except (ET.ParseError, OSError, TimeoutError, ValueError, requests.RequestException) as exc:
                logger.warning("skipping feed %s: %s", feed_url, exc)
                continue

            for entry in entries[:entry_limit]:
                title, body, key = _entry_to_doc(entry)
                added = store.add_reference(
                    source=_feed_host(feed_url),
                    title=title,
                    body=body,
                    tags="writeup,ingested",
                    key=key,
                    retention_cap=retention_cap,
                )
                summary["fetched"] += 1
                if added:
                    summary["added"] += 1
                else:
                    summary["skipped_duplicates"] += 1
    finally:
        if store_owned:
            store.close()

    return summary


def _default_fetcher(url: str) -> FeedResponse:
    response: FeedResponse = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
    return response


def _parse_feed(feed_url: str, xml_text: str) -> list[FeedEntry]:
    root = ET.fromstring(xml_text)
    root_name = _local_name(root.tag).lower()
    if root_name == "rss":
        return _parse_rss(feed_url, root)
    if root_name == "feed":
        return _parse_atom(feed_url, root)
    return []


def _parse_rss(feed_url: str, root: ET.Element[str]) -> list[FeedEntry]:
    channel = next((child for child in root if _local_name(child.tag).lower() == "channel"), root)
    return [_element_to_entry(feed_url, item) for item in _children_named(channel, "item")]


def _parse_atom(feed_url: str, root: ET.Element[str]) -> list[FeedEntry]:
    return [_element_to_entry(feed_url, entry) for entry in _children_named(root, "entry")]


def _element_to_entry(feed_url: str, element: ET.Element[str]) -> FeedEntry:
    return FeedEntry(
        feed_url=feed_url,
        title=_first_child_text(element, {"title"}) or "Untitled writeup",
        link=_entry_link(element),
        published=_first_child_text(element, {"pubdate", "published", "updated"}) or "unknown",
        summary=_first_child_text(
            element,
            {"description", "summary", "content", "encoded"},
        ),
    )


def _entry_to_doc(entry: FeedEntry) -> tuple[str, str, str]:
    summary = _truncate(_strip_html(entry.summary) or "No summary provided.")
    link = entry.link or "unknown"
    published = entry.published or "unknown"
    body = "\n".join(
        [
            f"Source feed: {entry.feed_url}",
            f"Link: {link}",
            f"Published: {published}",
            "",
            summary,
        ]
    )
    stable_id = entry.link or f"{entry.feed_url}:{entry.title}"
    key = hashlib.sha256(stable_id.encode("utf-8")).hexdigest()[:16]
    return entry.title, body, key


def _strip_html(raw_html: str) -> str:
    parser = _HTMLTextExtractor()
    parser.feed(raw_html)
    parser.close()
    return parser.text()


def _truncate(text: str) -> str:
    if len(text) <= MAX_SUMMARY_CHARS:
        return text
    return f"{text[: MAX_SUMMARY_CHARS - 3].rstrip()}..."


def _children_named(element: ET.Element[str], name: str) -> list[ET.Element[str]]:
    return [child for child in element if _local_name(child.tag).lower() == name]


def _first_child_text(element: ET.Element[str], names: set[str]) -> str:
    for child in element:
        if _local_name(child.tag).lower() in names and child.text is not None:
            return _collapse_ws(child.text)
    return ""


def _entry_link(element: ET.Element[str]) -> str:
    for child in element:
        if _local_name(child.tag).lower() != "link":
            continue
        href = child.attrib.get("href")
        if href is not None and href.strip():
            return href.strip()
        if child.text is not None:
            return _collapse_ws(child.text)
    return ""


def _local_name(tag: str) -> str:
    if "}" not in tag:
        return tag
    return tag.rsplit("}", 1)[1]


def _feed_host(feed_url: str) -> str:
    parsed = urlparse(feed_url)
    return parsed.netloc or feed_url


def _collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _configured_feeds() -> list[str]:
    raw = os.environ.get("INGEST_FEEDS")
    if raw is None or not raw.strip():
        return list(FEEDS)
    return [feed.strip() for feed in raw.split(",") if feed.strip()]


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_optional_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def main() -> int:
    db_path = os.environ.get("INGEST_DB", "data/reference_knowledge.db")
    with KnowledgeBase(db_path=db_path) as kb:
        summary = ingest_writeups(
            feeds=_configured_feeds(),
            kb=kb,
            limit=_env_int("INGEST_LIMIT", DEFAULT_LIMIT),
            retention_cap=_env_optional_int("INGEST_RETENTION_CAP"),
        )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
