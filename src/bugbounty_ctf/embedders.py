"""Optional embedding providers for hybrid knowledge-base search."""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from hashlib import blake2b
from typing import Final, Protocol, runtime_checkable

from bugbounty_ctf.knowledge import Embedder

DEFAULT_LOCAL_DIMENSIONS: Final = 256
DEFAULT_SENTENCE_TRANSFORMER_MODEL: Final = "all-MiniLM-L6-v2"
_TOKEN_RE: Final = re.compile(r"[a-z0-9][a-z0-9_.+/-]*")


@dataclass(frozen=True, slots=True)
class InvalidEmbeddingDimensionError(ValueError):
    dimensions: int

    def __str__(self) -> str:
        return f"embedding dimensions must be positive, got {self.dimensions}"


@runtime_checkable
class _VectorLike(Protocol):
    def tolist(self) -> Sequence[float]: ...


class _SentenceModel(Protocol):
    def encode(self, text: str) -> Sequence[float] | _VectorLike: ...


SentenceTransformerFactory = Callable[[str], _SentenceModel]


@dataclass(frozen=True, slots=True)
class LocalEmbedder:
    """Pure-stdlib hash embedding for zero-dependency semantic-ish reranking."""

    dimensions: int = DEFAULT_LOCAL_DIMENSIONS

    def __post_init__(self) -> None:
        if self.dimensions < 1:
            raise InvalidEmbeddingDimensionError(self.dimensions)

    def __call__(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in _TOKEN_RE.findall(text.casefold()):
            digest = blake2b(token.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign
        return _l2_normalize(vector)


@dataclass(frozen=True, slots=True)
class SentenceTransformerEmbedder:
    """Lazy optional wrapper around sentence-transformers models."""

    model_name: str = DEFAULT_SENTENCE_TRANSFORMER_MODEL
    model_factory: SentenceTransformerFactory | None = field(
        default=None, repr=False, compare=False
    )
    _model: _SentenceModel | None = field(init=False, default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        factory = self.model_factory or _load_sentence_transformer
        try:
            model = factory(self.model_name)
        except ImportError:
            model = None
        object.__setattr__(self, "_model", model)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    def __call__(self, text: str) -> list[float]:
        model = self._model
        if model is None:
            return []
        return _coerce_vector(model.encode(text))


def default_embedder(
    *,
    model_name: str = DEFAULT_SENTENCE_TRANSFORMER_MODEL,
    model_factory: SentenceTransformerFactory | None = None,
) -> Embedder | None:
    """Return sentence-transformers when available, otherwise the local embedder."""
    try:
        sentence_embedder = SentenceTransformerEmbedder(
            model_name=model_name,
            model_factory=model_factory,
        )
    except (OSError, RuntimeError, ValueError):
        sentence_embedder = None
    if sentence_embedder is not None and sentence_embedder.is_available:
        return sentence_embedder
    try:
        return LocalEmbedder()
    except InvalidEmbeddingDimensionError:
        return None


def _load_sentence_transformer(model_name: str) -> _SentenceModel:
    from sentence_transformers import SentenceTransformer

    model: _SentenceModel = SentenceTransformer(model_name)
    return model


def _coerce_vector(raw_vector: Sequence[float] | _VectorLike) -> list[float]:
    values = raw_vector.tolist() if isinstance(raw_vector, _VectorLike) else raw_vector
    return [float(value) for value in values]


def _l2_normalize(vector: Sequence[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        return list(vector)
    return [value / norm for value in vector]


__all__ = [
    "DEFAULT_LOCAL_DIMENSIONS",
    "DEFAULT_SENTENCE_TRANSFORMER_MODEL",
    "InvalidEmbeddingDimensionError",
    "LocalEmbedder",
    "SentenceTransformerEmbedder",
    "SentenceTransformerFactory",
    "default_embedder",
]
