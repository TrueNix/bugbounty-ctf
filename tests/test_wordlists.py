"""Tests for the wordlist loader and its bundled-list resolution."""

from __future__ import annotations

import os
from pathlib import Path

from bugbounty_ctf.wordlists import WORDLIST_SOURCES, WordlistLoader, _bundled_dirs


class TestBundledResolution:
    def test_package_wordlists_dir_is_a_candidate(self) -> None:
        # The package-relative location must be first so the loader finds the
        # bundled lists in dev, pip-installed, and Hermes-skill-copy layouts.
        candidates = _bundled_dirs()
        assert candidates[0].endswith(os.path.join("bugbounty_ctf", "wordlists"))
        assert os.path.isdir(candidates[0]), "bundled wordlists must ship inside the package"

    def test_loader_finds_bundled_dir(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        assert loader.bundled_dirs, "expected at least one bundled dir to exist"

    def test_load_prefers_bundled_over_fallback(self, tmp_path: Path) -> None:
        # cache_dir is an empty temp dir, so a non-empty result with more than
        # the tiny fallback dict proves the bundled file was used (no network).
        loader = WordlistLoader(cache_dir=str(tmp_path))
        payloads = loader.load("sqli")
        assert payloads
        fallback = WORDLIST_SOURCES["sqli"]["fallback"]
        assert isinstance(fallback, list)
        assert len(payloads) > len(fallback)


class TestLoadFile:
    def test_load_file_strips_comments_and_blanks(self, tmp_path: Path) -> None:
        f = tmp_path / "wl.txt"
        f.write_text("# comment\npayload1\n\n  payload2  \n# another\n")
        result = WordlistLoader.load_file(str(f))
        assert result == ["payload1", "payload2"]

    def test_load_missing_file_returns_empty(self) -> None:
        assert WordlistLoader.load_file("/nonexistent/path/xyz.txt") == []


class TestLoadFromMarkdown:
    def test_extracts_code_blocks_and_bullets(self, tmp_path: Path) -> None:
        md = tmp_path / "payloads.md"
        md.write_text(
            "# Section\n\n- bullet payload\n\n```\ncode payload\n```\n",
        )
        loader = WordlistLoader(cache_dir=str(tmp_path))
        result = loader.load_from_markdown(str(md))
        assert "bullet payload" in result
        assert "code payload" in result

    def test_missing_markdown_returns_empty(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        assert loader.load_from_markdown("/nope.md") == []


class TestMisc:
    def test_unknown_type_returns_empty(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        assert loader.load("not_a_real_type") == []

    def test_get_payload_dict_is_named(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        d = loader.get_payload_dict("ssti")
        assert d
        assert all(k.startswith("ssti_") for k in d)

    def test_merge_appends_without_duplicates(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        base = loader.load("ssti")
        merged = loader.merge("ssti", [base[0], "{{custom_unique_payload}}"])
        assert "{{custom_unique_payload}}" in merged
        assert merged.count(base[0]) == 1

    def test_in_memory_cache_returns_same_list(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        first = loader.load("ssti")
        second = loader.load("ssti")
        assert first is second

    def test_list_types_covers_sources(self, tmp_path: Path) -> None:
        loader = WordlistLoader(cache_dir=str(tmp_path))
        assert set(loader.list_types()) == set(WORDLIST_SOURCES)
