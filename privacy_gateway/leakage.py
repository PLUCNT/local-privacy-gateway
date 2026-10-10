"""Fail-closed validation that pseudonymized text carries no original data."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping

from privacy_gateway.classes import ClassRegistry, Policy
from privacy_gateway.model import DetectionReport, Leak, LeakageError, Span, VaultEntry

MIN_DIGITS_FOR_DIGIT_SEARCH = 6
MIN_LENGTH_FOR_FUZZY_SEARCH = 4
MIN_DIGITS_FOR_NUMBER_VALUE = 4
MIN_LETTERS_FOR_WORD_VALUE = 3
# Allerweltswörter, die eine Fehlerkennung als Name oder Ort tragen können
COMMON_WORDS = frozenset({
    "ich", "bei", "der", "die", "das", "des", "dem", "den", "ein", "und", "von", "vom", "mit", "für",
    "aus", "auf", "nach", "vor", "bis", "als", "wie", "wir", "ihr", "sie", "er", "es", "man", "im",
    "am", "an", "zu", "in", "so", "da",
})

_ANY_TOKEN = re.compile(r"<[A-Z][A-Z_]*?_(?:\d{3,}|REDACTED)>")
_NUMBERED_TOKEN = re.compile(r"<[A-Z][A-Z_]*?_\d{3,}>")
_WHITESPACE = re.compile(r"\s+")


def _collapsed(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    offsets: list[int] = []
    previous_space = False
    for index, char in enumerate(text):
        if char.isspace():
            if previous_space:
                continue
            chars.append(" ")
            previous_space = True
        else:
            chars.append(char)
            previous_space = False
        offsets.append(index)
    return "".join(chars), offsets


def _digits_only(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    offsets: list[int] = []
    for index, char in enumerate(text):
        if char.isdigit():
            chars.append(char)
            offsets.append(index)
    return "".join(chars), offsets


def _needle_pattern(needle: str, *, bounded: bool) -> re.Pattern[str]:
    body = re.escape(needle)
    if not bounded:
        return re.compile(body, re.IGNORECASE)
    prefix = r"(?<![^\W_])" if needle[:1].isalnum() else ""
    suffix = r"s?(?![^\W_])" if needle[-1:].isalnum() else ""
    return re.compile(prefix + body + suffix, re.IGNORECASE)


def _projected_hits(
    projection: str, offsets: list[int], needle: str, *, bounded: bool
) -> set[tuple[int, int]]:
    if not needle:
        return set()
    hits: set[tuple[int, int]] = set()
    for match in _needle_pattern(needle, bounded=bounded).finditer(projection):
        if match.end() == match.start():
            continue
        hits.add((offsets[match.start()], offsets[match.end() - 1] + 1))
    return hits


def _merged(hits: set[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(hits):
        if merged and start < merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
            continue
        merged.append((start, end))
    return merged


class _Projections:
    """The whole-text views a leak search needs, each built at most once per text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.collapsed = _collapsed(text)
        self._digits: tuple[str, list[int]] | None = None

    def digits(self) -> tuple[str, list[int]]:
        """The digits of the text with their original offsets."""
        if self._digits is None:
            self._digits = _digits_only(self.text)
        return self._digits


def is_weak_value(value: str) -> bool:
    """True for values that identify nothing on their own: short numbers and common words.

    Such a value is replaced where it was detected, but it is neither searched in the rest of
    the text nor re-detected in later messages – a stored "12" would otherwise hit every date.
    """
    stripped = value.strip()
    letters = sum(char.isalpha() for char in stripped)
    digits = sum(char.isdigit() for char in stripped)
    if letters == 0:
        return digits < MIN_DIGITS_FOR_NUMBER_VALUE
    if digits == 0 and stripped.lower() in COMMON_WORDS:
        return True
    return letters + digits < MIN_LETTERS_FOR_WORD_VALUE


def normalize_allowed(value: str) -> str:
    """The form in which a released value is compared: trimmed and case-folded."""
    return value.strip().casefold()


def repair_known_values(text: str, leaks: list[Leak]) -> str | None:
    """Replace unreplaced occurrences of known values by their token; None when nothing to do."""
    token_spans = [Span(match.start(), match.end()) for match in _ANY_TOKEN.finditer(text)]
    fixable = [
        leak for leak in leaks
        if leak.kind == "original_value" and leak.token
        and not any(Span(leak.start, leak.end).overlaps(token) for token in token_spans)
    ]
    if not fixable:
        return None
    for leak in sorted(fixable, key=lambda item: item.start, reverse=True):
        text = text[: leak.start] + leak.token + text[leak.end :]
    return text


def _occurrences(views: _Projections, value: str) -> set[tuple[int, int]]:
    if not value or is_weak_value(value):
        return set()
    text = views.text
    hits: set[tuple[int, int]] = set()
    if len(value) < MIN_LENGTH_FOR_FUZZY_SEARCH:
        pattern = rf"(?<!\w){re.escape(value)}(?!\w)"
        return {(m.start(), m.end()) for m in re.finditer(pattern, text)}
    digits = "".join(char for char in value if char.isdigit())
    bounded = not digits
    for match in _needle_pattern(value, bounded=bounded).finditer(text):
        hits.add((match.start(), match.end()))
    projection, offsets = views.collapsed
    collapsed_value = _WHITESPACE.sub(" ", value).strip()
    hits |= _projected_hits(projection, offsets, collapsed_value, bounded=bounded)
    if len(digits) >= MIN_DIGITS_FOR_DIGIT_SEARCH:
        projection, offsets = views.digits()
        hits |= _projected_hits(projection, offsets, digits, bounded=False)
    return hits


def _policy(registry: ClassRegistry, data_class: str) -> Policy:
    if data_class in registry:
        return registry.get(data_class).policy
    return Policy.TOKENIZE


def _deduplicate(leaks: list[Leak]) -> list[Leak]:
    seen: set[Leak] = set()
    unique: list[Leak] = []
    for leak in leaks:
        if leak in seen:
            continue
        seen.add(leak)
        unique.append(leak)
    return unique


def check_leakage(
    text: str,
    entries: Mapping[str, VaultEntry],
    scan: Callable[[str], DetectionReport],
    registry: ClassRegistry,
) -> None:
    """Raise `LeakageError` when the pseudonymized text still exposes data."""
    leaks: list[Leak] = []
    token_spans = [Span(match.start(), match.end()) for match in _ANY_TOKEN.finditer(text)]

    for finding in scan(text).findings:
        if _policy(registry, finding.data_class) is Policy.IGNORE:
            continue
        if any(token.contains(finding.span) for token in token_spans):
            continue
        leaks.append(
            Leak("residual_finding", finding.data_class, finding.span.start, finding.span.end)
        )

    views = _Projections(text)
    for token, entry in entries.items():
        hits: set[tuple[int, int]] = set()
        for value in dict.fromkeys([entry.value, *entry.surface_forms]):
            hits |= _occurrences(views, value)
        for start, end in _merged(hits):
            leaks.append(Leak("original_value", entry.data_class, start, end, token))

    for match in _NUMBERED_TOKEN.finditer(text):
        if match.group(0) not in entries:
            leaks.append(Leak("unknown_token", "", match.start(), match.end()))

    if leaks:
        raise LeakageError(_deduplicate(leaks))
