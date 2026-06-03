"""The cross-language canonicalization vectors are the contract a non-Python
verifier (Go/Rust/TS, or the sm-conformance-viewer's TS canonicalizer) checks
itself against. The Python reference MUST match them exactly. (Audit item 10.)"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sm_conformance.badge import CanonicalizationError, canonical_json

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[1] / "sm_conformance/vectors/canonicalization.json"
    ).read_text()
)


@pytest.mark.parametrize("case", _VECTORS["valid"], ids=[c["id"] for c in _VECTORS["valid"]])
def test_valid_canonicalizes_to_expected_bytes(case: dict) -> None:
    assert canonical_json(case["input"]) == case["canonical"].encode("utf-8")


@pytest.mark.parametrize("case", _VECTORS["invalid"], ids=[c["id"] for c in _VECTORS["invalid"]])
def test_invalid_is_rejected(case: dict) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(case["input"])


def test_bytes_value_rejected_in_language() -> None:
    """Not expressible as a JSON vector — pinned here so the in-language guard is covered."""
    with pytest.raises(CanonicalizationError):
        canonical_json({"v": b"\x00\x01"})
