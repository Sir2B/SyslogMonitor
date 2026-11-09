"""Message frequency analysis: exact texts, number-insensitive patterns and similar-text groups."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, replace
from difflib import SequenceMatcher
from typing import Callable

MODE_EXACT = "exact"
MODE_NUMBERS = "numbers"
MODE_SIMILAR = "similar"
MODES = (MODE_EXACT, MODE_NUMBERS, MODE_SIMILAR)
DEFAULT_SIMILARITY = 0.8
MIN_SIMILARITY = 0.5
MAX_GROUPS = 5000
# Similarity grouping compares patterns pairwise, so its input is smaller.
MAX_SIMILAR_INPUT = 2000
NUMBER_PLACEHOLDER = "#"
_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


@dataclass(frozen=True, slots=True)
class FrequencyGroup:
    pattern: str  # exact text, or text with numbers shown as NUMBER_PLACEHOLDER
    count: int
    variants: int  # distinct exact messages in this group
    first_ms: int
    last_ms: int
    example: str
    patterns: int = 1  # number-insensitive patterns merged into a similar-text group


@dataclass(frozen=True, slots=True)
class FrequencyReport:
    mode: str
    total: int  # all messages matching the filter
    groups: tuple[FrequencyGroup, ...]
    truncated: bool
    limit: int
    similarity: float = DEFAULT_SIMILARITY


def group_limit(mode: str) -> int:
    return MAX_SIMILAR_INPUT if mode == MODE_SIMILAR else MAX_GROUPS


def tokens(pattern: str) -> tuple[str, ...]:
    """Words and punctuation; whitespace differences are ignored."""
    return tuple(_TOKEN_RE.findall(pattern))


def similarity(left: str, right: str) -> float:
    """Share of matching tokens (0..1), the measure used by :func:`cluster_similar`."""
    a, b = tokens(left), tokens(right)
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b, autojunk=False).ratio()


def cluster_similar(groups: list[FrequencyGroup] | tuple[FrequencyGroup, ...],
                    threshold: float = DEFAULT_SIMILARITY,
                    should_stop: Callable[[], bool] = lambda: False) -> tuple[FrequencyGroup, ...]:
    """Merge patterns whose tokens are at least ``threshold`` similar to a group's leading pattern.

    Patterns are processed from most to least frequent; each joins the first sufficiently
    similar group, otherwise it starts a new one. Comparing with the leading pattern (not
    every member) prevents long chains of slightly different messages from merging.
    Raises :class:`sqlite3.OperationalError` ("interrupted") as soon as ``should_stop`` is true,
    like an interrupted database query.
    """
    if not MIN_SIMILARITY <= threshold <= 1:
        raise ValueError("Similarity must be between 0.5 and 1.")
    ordered = sorted(groups, key=lambda g: (-g.count, g.pattern))
    leaders: list[tuple[tuple[str, ...], int]] = []  # (tokens, index into merged)
    by_length: dict[int, list[int]] = {}
    merged: list[FrequencyGroup] = []
    matcher = SequenceMatcher(None, autojunk=False)
    for group in ordered:
        if should_stop():
            raise sqlite3.OperationalError("interrupted")
        words = tokens(group.pattern)
        size = len(words)
        matcher.set_seq2(words)
        target = None
        # ratio = 2*matches/(a+b) <= 2*min(a,b)/(a+b): skip lengths that cannot reach the threshold.
        low = size * threshold / (2 - threshold)
        high = size * (2 - threshold) / threshold if threshold else float("inf")
        for length in sorted(by_length):
            if length < low - 1e-9 or length > high + 1e-9:
                continue
            for leader in by_length[length]:
                other, index = leaders[leader]
                if not other and not words:
                    target = index
                    break
                matcher.set_seq1(other)
                if (matcher.real_quick_ratio() >= threshold and matcher.quick_ratio() >= threshold
                        and matcher.ratio() >= threshold):
                    target = index
                    break
            if target is not None:
                break
        if target is None:
            by_length.setdefault(size, []).append(len(leaders))
            leaders.append((words, len(merged)))
            merged.append(group)
            continue
        current = merged[target]
        merged[target] = replace(
            current, count=current.count + group.count, variants=current.variants + group.variants,
            first_ms=min(current.first_ms, group.first_ms), last_ms=max(current.last_ms, group.last_ms),
            patterns=current.patterns + group.patterns)
    return tuple(sorted(merged, key=lambda g: (-g.count, g.pattern)))
