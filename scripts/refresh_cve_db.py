#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, TypeAlias

from bugbounty_ctf.template_scan import update_cve_db

CveEntry = dict[str, str]
CveDatabase = dict[str, list[CveEntry]]
JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
Sleeper = Callable[[float], None]


class CveResponse(Protocol):
    def json(self) -> dict[str, JsonValue]: ...


CveFetcher = Callable[..., CveResponse]

DEFAULT_CVE_DB_PATH = Path(__file__).resolve().parents[1] / "src/bugbounty_ctf/data/cve_db.json"
HIGH_VALUE_PRODUCTS = (
    "nginx",
    "apache",
    "openssh",
    "log4j",
    "roundcube",
    "confluence",
    "spring-framework",
    "jenkins",
    "gitlab",
    "tomcat",
    "php",
    "wordpress",
    "joomla",
    "exim",
    "sudo",
)
ENTRY_FIELD_ORDER = ("cve", "affected", "severity", "name")
KEYLESS_DELAY_SECONDS = 6.0
KEYED_DELAY_SECONDS = 0.7


@dataclass(frozen=True, slots=True)
class RefreshOptions:
    db_path: Path = DEFAULT_CVE_DB_PATH
    api_key: str | None = None
    fetcher: CveFetcher | None = None
    sleeper: Sleeper = time.sleep
    extra_products: Sequence[str] = field(default=HIGH_VALUE_PRODUCTS)


@dataclass(frozen=True, slots=True)
class RefreshSummary:
    products_checked: int
    products_updated: int
    total_cves: int
    net_new_cves: int


@dataclass(frozen=True, slots=True)
class CveDbFormatError(RuntimeError):
    path: Path
    reason: str

    def __str__(self) -> str:
        return f"{self.path}: {self.reason}"


def refresh_cve_db(options: RefreshOptions) -> RefreshSummary:
    comment, database = _read_cve_db(options.db_path)
    products = _tracked_products(database, options.extra_products)
    before_total = _count_cves(database)
    delay = KEYED_DELAY_SECONDS if options.api_key else KEYLESS_DELAY_SECONDS

    refreshed: CveDatabase = {}
    products_updated = 0
    for index, product in enumerate(products):
        existing_entries = database.get(product, [])
        fetched_entries = update_cve_db(
            product,
            refresh=True,
            fetcher=options.fetcher,
            api_key=options.api_key,
        )
        merged_entries = _merge_entries(existing_entries, fetched_entries)
        if merged_entries != _sort_entries(existing_entries):
            products_updated += 1
        if merged_entries or product in database:
            refreshed[product] = merged_entries
        if index < len(products) - 1:
            options.sleeper(delay)

    _write_cve_db(options.db_path, comment, refreshed)
    total_cves = _count_cves(refreshed)
    return RefreshSummary(
        products_checked=len(products),
        products_updated=products_updated,
        total_cves=total_cves,
        net_new_cves=total_cves - before_total,
    )


def _tracked_products(database: Mapping[str, Sequence[CveEntry]], extra_products: Sequence[str]) -> list[str]:
    products = {product.lower() for product in database}
    products.update(product.lower() for product in extra_products)
    return sorted(products)


def _merge_entries(
    existing_entries: Sequence[Mapping[str, str]],
    fetched_entries: Sequence[Mapping[str, str]],
) -> list[CveEntry]:
    by_cve: dict[str, CveEntry] = {}
    for entry in existing_entries:
        normalized = _normalize_entry(entry)
        cve_id = normalized.get("cve")
        if cve_id:
            by_cve[cve_id] = normalized
    for entry in fetched_entries:
        normalized = _normalize_entry(entry)
        cve_id = normalized.get("cve")
        if cve_id:
            by_cve[cve_id] = normalized
    return [by_cve[cve_id] for cve_id in sorted(by_cve)]


def _sort_entries(entries: Sequence[Mapping[str, str]]) -> list[CveEntry]:
    return _merge_entries(entries, ())


def _normalize_entry(entry: Mapping[str, str]) -> CveEntry:
    normalized: CveEntry = {}
    for key in ENTRY_FIELD_ORDER:
        value = entry.get(key)
        if value is not None:
            normalized[key] = value
    for key in sorted(entry):
        if key not in normalized:
            normalized[key] = entry[key]
    return normalized


def _count_cves(database: Mapping[str, Sequence[CveEntry]]) -> int:
    return sum(len(entries) for entries in database.values())


def _read_cve_db(path: Path) -> tuple[str | None, CveDatabase]:
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise CveDbFormatError(path, "expected a top-level JSON object")

    comment = raw.get("_comment")
    if comment is not None and not isinstance(comment, str):
        raise CveDbFormatError(path, "expected _comment to be a string")

    database: CveDatabase = {}
    for product, raw_entries in raw.items():
        if product.startswith("_"):
            continue
        if not isinstance(raw_entries, list):
            raise CveDbFormatError(path, f"expected {product} entries to be a list")
        database[product.lower()] = _parse_entries(path, product, raw_entries)
    return comment, database


def _parse_entries(path: Path, product: str, raw_entries: Sequence[JsonValue]) -> list[CveEntry]:
    entries: list[CveEntry] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            raise CveDbFormatError(path, f"expected {product} CVE entries to be objects")
        entry: CveEntry = {}
        for key, value in raw_entry.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise CveDbFormatError(path, f"expected {product} CVE fields to be strings")
            entry[key] = value
        entries.append(_normalize_entry(entry))
    return entries


def _write_cve_db(path: Path, comment: str | None, database: Mapping[str, Sequence[CveEntry]]) -> None:
    payload: dict[str, str | list[CveEntry]] = {}
    if comment is not None:
        payload["_comment"] = comment
    for product in sorted(database):
        payload[product] = _sort_entries(database[product])
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    summary = refresh_cve_db(
        RefreshOptions(
            api_key=os.getenv("NVD_API_KEY"),
        )
    )
    print(
        "CVE DB refresh: "
        f"{summary.products_updated}/{summary.products_checked} products updated, "
        f"{summary.total_cves} total CVEs, "
        f"{summary.net_new_cves:+d} net new"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
