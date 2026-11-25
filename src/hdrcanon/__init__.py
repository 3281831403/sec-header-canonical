"""Public interface for the sec-header-canonical exercise."""

from .normalize import (
    canonical,
    canonical_name,
    fold_whitespace,
    merge_values,
    normalize_batch,
    split_headers,
    stable_digest,
    validate,
)

__all__ = [
    "split_headers",
    "canonical_name",
    "merge_values",
    "fold_whitespace",
    "canonical",
    "stable_digest",
    "validate",
    "normalize_batch",
]