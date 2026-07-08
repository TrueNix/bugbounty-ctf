"""Tests for optional embedding providers."""

from __future__ import annotations

import math
from collections.abc import Sequence

from bugbounty_ctf.embedders import LocalEmbedder, SentenceTransformerEmbedder, default_embedder


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(left * right for left, right in zip(a, b, strict=False))
    left_norm = math.sqrt(sum(value * value for value in a))
    right_norm = math.sqrt(sum(value * value for value in b))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


class _FakeModel:
    def encode(self, text: str) -> list[float]:
        return [float(len(text)), 1.0, 0.5]


def test_local_embedder_returns_normalized_vector() -> None:
    # Given: a non-empty text with repeated security terms.
    embedder = LocalEmbedder()
    text = "sql injection union select sql database"

    # When: the local embedder hashes the text into a vector.
    vector = embedder(text)

    # Then: the vector has unit length for cosine reranking.
    norm = math.sqrt(sum(value * value for value in vector))
    assert math.isclose(norm, 1.0, rel_tol=1e-9)


def test_local_embedder_similarity() -> None:
    # Given: one related pair with shared vocabulary and one unrelated text.
    embedder = LocalEmbedder()
    query = embedder("sql injection union select database login")
    related = embedder("database login sql injection payload bypass")
    unrelated = embedder("docker container kernel privilege escalation")

    # When: cosine similarity compares the hashed vectors.
    related_score = _cosine(query, related)
    unrelated_score = _cosine(query, unrelated)

    # Then: shared security vocabulary ranks higher than unrelated content.
    assert related_score > unrelated_score


def test_local_embedder_dim_consistent() -> None:
    # Given: a configured local embedder.
    embedder = LocalEmbedder(dimensions=128)

    # When: texts of different lengths are embedded.
    short_vector = embedder("xss")
    long_vector = embedder("stored xss payload script alert cookie theft")

    # Then: every output uses the configured dimensionality.
    assert len(short_vector) == 128
    assert len(long_vector) == 128


def test_sentence_transformer_embedder_skips_when_unavailable() -> None:
    # Given: an injected model factory that simulates a missing optional package.
    def missing_model(_model_name: str) -> _FakeModel:
        raise ImportError("sentence-transformers unavailable")

    embedder = SentenceTransformerEmbedder(model_factory=missing_model)

    # When: unavailable sentence-transformers is called.
    vector = embedder("sql injection")

    # Then: it behaves as unavailable without loading a real model.
    assert embedder.is_available is False
    assert vector == []


def test_default_embedder_fallback() -> None:
    # Given: sentence-transformers is unavailable.
    def missing_model(_model_name: str) -> _FakeModel:
        raise ImportError("sentence-transformers unavailable")

    # When: the default embedder is requested.
    embedder = default_embedder(model_factory=missing_model)

    # Then: the pure-stdlib local embedder is used.
    assert isinstance(embedder, LocalEmbedder)
