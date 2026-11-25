"""Canonicalization helpers for HTTP request header sets.

The public API is intentionally small: header lines are split into pairs,
names and values are canonicalized, duplicate names are merged, a stable
digest can be computed, raw input can be validated, and batches of requests
can be normalized together.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Mapping, Sequence, Tuple

_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_WS_RE = re.compile(r"\s+")

HeaderPairs = List[Tuple[str, str]]


def split_headers(lines: Sequence[str]) -> HeaderPairs:
    """Split raw header lines into ``(name, value)`` pairs.

    A line beginning with a space or tab continues the previous header.  The
    first colon separates the name from the value.  Both ends of the value are
    trimmed, while whitespace inside the value is left untouched.
    """
    result: HeaderPairs = []
    for line in lines:
        if line[:1] in (" ", "\t"):
            if not result:
                raise ValueError("continuation line without a preceding header")
            name, value = result[-1]
            extra = line.strip()
            result[-1] = (name, value + extra)
        else:
            if ":" not in line:
                raise ValueError("header line is missing a colon")
            name, value = line.split(":", 1)
            result.append((name.strip(), value.strip()))
    return result


def canonical_name(name: str) -> str:
    """Return the canonical spelling of a header name."""
    return name.lower()


def merge_values(values: Sequence[str]) -> str:
    """Merge the values of one header into a single field value."""
    ordered = sorted(values)
    return ",".join(ordered)


def fold_whitespace(value: str) -> str:
    """Fold runs of whitespace inside a header value."""
    collapsed = _WS_RE.sub(" ", value).strip()
    if not collapsed:
        return ""
    return " " + collapsed + " "


def canonical(headers: Mapping[str, Sequence[str]]) -> Dict[str, str]:
    """Return the canonical representation of a header mapping."""
    merged: Dict[str, List[str]] = {}
    for name, values in headers.items():
        cname = canonical_name(name)
        kept = [fold_whitespace(value) for value in values if fold_whitespace(value)]
        if not kept:
            continue
        merged.setdefault(cname, [])
        merged[cname].extend(kept)
    return {name: merge_values(values) for name, values in merged.items()}


def stable_digest(headers: Mapping[str, Sequence[str]]) -> str:
    """Return a digest that identifies the request headers."""
    parts: List[str] = []
    for name, values in headers.items():
        for value in values:
            parts.append(name + "=" + value)
    payload = ";".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate(headers: Sequence[str]) -> List[str]:
    """Return a list of problems found in raw header lines."""
    problems: List[str] = []
    seen_header = False
    for line in headers:
        if line[:1] in (" ", "\t"):
            if not seen_header:
                problems.append("bad-fold")
            continue
        seen_header = True
        if ":" not in line:
            problems.append("invalid-name")
            continue
        name, _value = line.split(":", 1)
        if not _NAME_RE.match(name):
            problems.append("invalid-name")
    return problems


def normalize_batch(
    requests: Sequence[Mapping[str, Sequence[str]]],
) -> Dict[int, Dict[str, str]]:
    """Normalize several independent requests."""
    results: Dict[int, Dict[str, str]] = {}
    shared: Dict[str, List[str]] = {}
    for index, headers in enumerate(requests):
        for name, values in headers.items():
            cname = canonical_name(name)
            kept = [fold_whitespace(value) for value in values if fold_whitespace(value)]
            if not kept:
                continue
            shared.setdefault(cname, [])
            shared[cname].extend(kept)
        results[index] = {
            name: merge_values(values) for name, values in shared.items()
        }
    return results