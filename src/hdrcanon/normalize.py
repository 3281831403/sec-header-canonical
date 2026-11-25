"""Canonicalization helpers for HTTP request header sets.

The public API is intentionally small: header lines are split into pairs,
names and values are canonicalized, duplicate names are merged, a stable
digest can be computed, raw input can be validated, and batches of requests
can be normalized together.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, List, Mapping, Sequence, Tuple, Union

_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_WS_RE = re.compile(r"\s+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

HeaderPairs = List[Tuple[str, str]]
HeaderValues = Union[str, Sequence[str]]
HeaderMapping = Mapping[str, HeaderValues]


def split_headers(lines: Sequence[str]) -> HeaderPairs:
    """Split raw header lines into ``(name, value)`` pairs.

    A line beginning with a space or tab continues the previous header.  The
    first colon separates the name from the value.  Both ends of the value are
    trimmed.  An obs-fold boundary is replaced by a single space so the folded
    pieces are not glued together; the later whitespace-folding step collapses
    any resulting runs.
    """
    result: HeaderPairs = []
    for line in lines:
        if line[:1] in (" ", "\t"):
            if not result:
                raise ValueError("continuation line without a preceding header")
            name, value = result[-1]
            extra = line.strip()
            if extra:
                value = f"{value} {extra}".strip()
            result[-1] = (name, value)
        else:
            if ":" not in line:
                raise ValueError("header line is missing a colon")
            name, value = line.split(":", 1)
            result.append((name.strip(), value.strip()))
    return result


def canonical_name(name: str) -> str:
    """Return the canonical spelling of a header name.

    Header names are case-insensitive and the surrounding whitespace is not
    part of their identity.
    """
    return name.strip().lower()


def fold_whitespace(value: str) -> str:
    """Fold runs of whitespace inside a header value.

    Leading and trailing whitespace is removed; runs of internal whitespace
    collapse to a single space.  A lone internal space is preserved.  The
    function is idempotent.
    """
    return _WS_RE.sub(" ", value).strip()


def _value_sequence(values: HeaderValues) -> Sequence[str]:
    """Treat a bare string as one scalar value, not a sequence of characters."""
    if isinstance(values, str):
        return (values,)
    return values


def merge_values(values: HeaderValues) -> str:
    """Merge the values of one header into a single field value.

    Values keep the exact order supplied by the caller; they are never
    reordered.  The separator is a comma followed by one space.
    """
    if isinstance(values, str):
        return fold_whitespace(values)
    return ", ".join(fold_whitespace(value) for value in values)


def canonical(headers: HeaderMapping) -> Dict[str, str]:
    """Return the canonical representation of a header mapping.

    Names are case-insensitive and whitespace-insensitive.  Values belonging
    to the same canonical name are merged in the order supplied by the caller.
    An empty string is a real value: it keeps the header present, while an
    absent name stays absent.  The result is independent of the order in which
    different header names appear and is idempotent.
    """
    merged: Dict[str, List[str]] = {}
    for raw_name, raw_values in headers.items():
        cname = canonical_name(raw_name)
        merged.setdefault(cname, [])
        merged[cname].extend(
            fold_whitespace(value) for value in _value_sequence(raw_values)
        )

    # Sorting names makes iteration and serialization independent of the
    # header line order.  Value order is intentionally left untouched.
    return {name: merge_values(merged[name]) for name in sorted(merged)}


def stable_digest(headers: HeaderMapping) -> str:
    """Return a digest determined solely by the canonical header result.

    The canonical result is serialized with sorted keys and no ignored
    whitespace, so the digest does not depend on the input spelling or on the
    order of the header lines, and different canonical results map to
    different payloads (and thus different digests) without ambiguity.
    """
    canonical_headers = canonical(headers)
    payload = json.dumps(
        canonical_headers,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate(headers: Sequence[str]) -> List[str]:
    """Return a list of problems found in raw header lines.

    Reports illegal header names, control characters in values (including
    folded continuation content) and orphaned continuation lines.
    """
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
        name, value = line.split(":", 1)
        if not _NAME_RE.match(name):
            problems.append("invalid-name")
        if _CONTROL_RE.search(value):
            problems.append("control-character")
    return problems


def normalize_batch(
    requests: Sequence[HeaderMapping],
) -> Dict[int, Dict[str, str]]:
    """Normalize several independent requests.

    Each request is canonicalized from scratch, so no key or value can leak
    from one request into another.
    """
    return {index: canonical(headers) for index, headers in enumerate(requests)}
