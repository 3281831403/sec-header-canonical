"""Public smoke tests for request header canonicalization."""

from __future__ import annotations

from hdrcanon import canonical, normalize_batch


def test_name_case_variants_share_one_key() -> None:
    headers = {"Host": ["Example.COM"], "HOST": ["example.com"]}
    assert canonical(headers) == {"host": "Example.COM, example.com"}


def test_duplicate_headers_merge_into_a_single_key() -> None:
    headers = {"X-Foo": ["b"], "x-foo": ["a", "c"]}
    assert canonical(headers) == {"x-foo": "b, a, c"}


def test_value_end_whitespace_is_removed() -> None:
    assert canonical({"X-Test": ["  alpha  "]}) == {"x-test": "alpha"}


def test_single_value_header_is_preserved() -> None:
    assert canonical({"Accept": ["text/html"]}) == {"accept": "text/html"}


def test_batch_requests_are_independent() -> None:
    requests = [{"X-A": ["1"]}, {"X-B": ["2"]}]
    assert normalize_batch(requests) == {0: {"x-a": "1"}, 1: {"x-b": "2"}}