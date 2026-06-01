"""Run each badge vector through the verifier; assert documented outcome.

These tests are the runtime-agnostic harness for the vectors at
``tests/fixtures/`` per ``SPEC.md`` §12.
A non-Python verifier passes the same JSON files; whether the verifier
correctly accepts the positive vector and rejects each negative one at
the documented stage is the conformance contract.

The vectors are deterministic: regenerating them via
``python -m sm_conformance._badge_vector_gen`` produces byte-identical
files. The ``test_vectors_are_byte_stable`` test confirms this by
re-running the generator's logic in memory.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from sm_conformance.badge import VerificationError, sign_envelope, verify_envelope
from sm_conformance.verify_badge import main as verify_badge_main

VECTORS_DIR = Path(__file__).resolve().parent / "fixtures"

# (file stem, expected_outcome). Mirrors what's encoded inside each vector
# but also fixes the relationship at the test level so a vector whose
# expected_outcome was edited maliciously is still caught by the test.
EXPECTED_OUTCOMES: dict[str, str] = {
    "valid-signed-badge": "verify_pass",
    "tampered-payload": "signature_fail",
    "tampered-signature": "signature_fail",
    "wrong-signer": "signature_fail",
    "non-didkey-signer": "didkey_parse_fail",
    "missing-signature": "envelope_shape_fail",
    "failing-run": "pass_gate_fail",
}


def _load(stem: str) -> dict[str, Any]:
    path = VECTORS_DIR / f"{stem}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_vector_present() -> None:
    """Every vector named in conformance.md §12 must exist on disk."""
    missing = [stem for stem in EXPECTED_OUTCOMES if not (VECTORS_DIR / f"{stem}.json").exists()]
    assert not missing, f"missing badge vectors: {missing}"


def test_every_vector_self_declares_expected_outcome() -> None:
    """The expected_outcome inside each vector matches this test's pin."""
    for stem, expected in EXPECTED_OUTCOMES.items():
        doc = _load(stem)
        actual = doc.get("expected_outcome")
        assert actual == expected, (
            f"{stem}.json declares expected_outcome={actual!r}; test pin says {expected!r}"
        )


# --- §9.1-9.6 — signature verification path -----------------------------------


@pytest.mark.parametrize(
    "stem",
    ["valid-signed-badge", "failing-run"],
    ids=lambda s: s,
)
def test_signature_verifies(stem: str) -> None:
    """Both the happy vector AND the failing-run vector must verify
    cryptographically — the failing-run's signature is valid even though
    the payload records failures; only the pass-gate distinguishes them.
    """
    doc = _load(stem)
    payload = verify_envelope(doc["envelope"])
    assert payload == doc["envelope"]["payload"]


@pytest.mark.parametrize(
    "stem,expected_match",
    [
        ("tampered-payload", "signature verification failed"),
        ("tampered-signature", "signature verification failed"),
        ("wrong-signer", "signature verification failed"),
        ("non-didkey-signer", "invalid signed_by"),
        ("missing-signature", "missing required field: signature"),
    ],
    ids=lambda v: str(v)[:30],
)
def test_negative_vector_fails_at_documented_stage(stem: str, expected_match: str) -> None:
    doc = _load(stem)
    with pytest.raises(VerificationError, match=expected_match):
        verify_envelope(doc["envelope"])


# --- §9.7 — pass-gate -------------------------------------------------------


def test_cli_rejects_failing_run_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    """The failing-run vector verifies cryptographically but the CLI
    refuses it by default because payload.failed > 0.
    """
    doc = _load("failing-run")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(doc["envelope"], tmp)
        path = tmp.name
    try:
        assert verify_badge_main([path]) == 1
        err = capsys.readouterr().err
        assert "non-passing run" in err
    finally:
        Path(path).unlink(missing_ok=True)


def test_cli_accepts_failing_run_with_allow_failures() -> None:
    """The same vector verifies cryptographically; --allow-failures
    opts into signature-only verification.
    """
    doc = _load("failing-run")
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(doc["envelope"], tmp)
        path = tmp.name
    try:
        assert verify_badge_main([path, "--allow-failures"]) == 0
    finally:
        Path(path).unlink(missing_ok=True)


# --- Byte-stability — vectors must be reproducible from fixed inputs ----------


def test_valid_vector_is_byte_stable() -> None:
    """Re-running the generator's signing step with the same fixed
    seed + timestamps + payload produces a byte-identical envelope.
    Any divergence means a generator change broke determinism.
    """
    from sm_conformance._badge_vector_gen import (
        FIXED_SIGNED_AT,
        RUNTIME_SEED,
        _base_payload,
    )

    expected_envelope = _load("valid-signed-badge")["envelope"]
    regenerated = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    assert regenerated == expected_envelope, (
        "valid-signed-badge.json drifted from its generator inputs. "
        "Re-run `python -m sm_conformance._badge_vector_gen` and commit the diff."
    )
