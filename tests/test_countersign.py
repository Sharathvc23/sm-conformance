"""Trust-ladder rung 2 — counter-signature: round-trip, tamper, and CLI gates."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from sm_conformance import (
    CountersignError,
    counter_sign,
    is_countersigned,
    sign_envelope,
    verify_countersigned,
)
from sm_conformance.verify_badge import main as verify_badge_main

RUNTIME_KEY = bytes(range(32))
LAB_KEY = bytes(range(32, 64))
TS = "2026-05-31T00:00:00+00:00"


def _badge(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "runtime": "demo-runtime",
        "protocol_versions": ["0.1"],
        "suite_digest": "sha256:" + "0" * 64,
        "completed_at": TS,
        "exit_status": 0,
        "passed": 42,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    payload.update(overrides)
    return sign_envelope(payload, RUNTIME_KEY, TS)


def test_countersign_round_trip_returns_inner_payload() -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    inner = verify_countersigned(cs)
    assert inner["runtime"] == "demo-runtime"
    assert is_countersigned(cs)
    assert cs["payload"]["method"] == "lab-rerun"


def test_method_verified_is_recorded() -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS, method="verified")
    assert cs["payload"]["method"] == "verified"
    verify_countersigned(cs)


def test_counter_sign_rejects_unknown_method() -> None:
    with pytest.raises(ValueError, match="method must be one of"):
        counter_sign(_badge(), LAB_KEY, TS, method="hand-waved")


def test_tampered_inner_badge_rejected() -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    cs["payload"]["badge"]["payload"]["passed"] = 999  # break inner runtime signature
    with pytest.raises(CountersignError, match="inner badge failed verification"):
        verify_countersigned(cs)


def test_tampered_method_rejected() -> None:
    """method is inside the signed payload — altering it breaks the counter-signature."""
    cs = counter_sign(_badge(), LAB_KEY, TS, method="verified")
    cs["payload"]["method"] = "lab-rerun"  # forge a stronger attestation
    with pytest.raises(CountersignError, match="counter-signature verification failed"):
        verify_countersigned(cs)


def test_tampered_countersignature_rejected() -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    sig = bytearray(base64.b64decode(cs["countersignature"]))
    sig[0] ^= 0xFF
    cs["countersignature"] = base64.b64encode(bytes(sig)).decode("ascii")
    with pytest.raises(CountersignError, match="counter-signature verification failed"):
        verify_countersigned(cs)


def test_wrong_lab_signer_rejected() -> None:
    """A countersigned_by did:key that did not produce the signature is rejected."""
    cs = counter_sign(_badge(), LAB_KEY, TS)
    from sm_conformance import derive_did_key

    cs["countersigned_by"] = derive_did_key(bytes([7] * 32))
    with pytest.raises(CountersignError, match="counter-signature verification failed"):
        verify_countersigned(cs)


def test_missing_field_rejected() -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    del cs["countersignature"]
    with pytest.raises(CountersignError, match="missing required field: countersignature"):
        verify_countersigned(cs)


def test_is_countersigned_false_for_bare_badge() -> None:
    assert not is_countersigned(_badge())


# -- CLI: counter-signed badges verify both signatures + honour the pass-gate --


def _write(tmp_path: Path, env: dict[str, Any]) -> str:
    p = tmp_path / "cs.json"
    p.write_text(json.dumps(env), encoding="utf-8")
    return str(p)


def test_cli_accepts_countersigned_passing_badge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    assert verify_badge_main([_write(tmp_path, cs)]) == 0
    out = capsys.readouterr().out
    assert "counter-signed by" in out
    assert "method=lab-rerun" in out


def test_cli_rejects_countersigned_failing_run_by_default(tmp_path: Path) -> None:
    cs = counter_sign(_badge(failed=2, exit_status=1, passed=40), LAB_KEY, TS)
    assert verify_badge_main([_write(tmp_path, cs)]) == 1
    assert verify_badge_main([_write(tmp_path, cs), "--allow-failures"]) == 0


def test_cli_rejects_countersigned_with_tampered_inner(tmp_path: Path) -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    cs["payload"]["badge"]["payload"]["passed"] = 999
    assert verify_badge_main([_write(tmp_path, cs)]) == 1


# -- admission gates: a relying party can REQUIRE a counter-signature ----------


def test_cli_require_countersigned_rejects_self_signed(tmp_path: Path) -> None:
    assert verify_badge_main([_write(tmp_path, _badge()), "--require-countersigned"]) == 1


def test_cli_require_countersigned_accepts_countersigned(tmp_path: Path) -> None:
    cs = counter_sign(_badge(), LAB_KEY, TS)
    assert verify_badge_main([_write(tmp_path, cs), "--require-countersigned"]) == 0


def test_cli_require_method_enforces_minimum(tmp_path: Path) -> None:
    verified = counter_sign(_badge(), LAB_KEY, TS, method="verified")
    # 'verified' does not satisfy a 'lab-rerun' requirement
    assert verify_badge_main([_write(tmp_path, verified), "--require-method", "lab-rerun"]) == 1
    # ...but does satisfy a 'verified' requirement
    assert verify_badge_main([_write(tmp_path, verified), "--require-method", "verified"]) == 0
    rerun = counter_sign(_badge(), LAB_KEY, TS, method="lab-rerun")
    assert verify_badge_main([_write(tmp_path, rerun), "--require-method", "lab-rerun"]) == 0


def test_cli_trusted_signer_gate(tmp_path: Path) -> None:
    from sm_conformance import derive_did_key

    cs = counter_sign(_badge(), LAB_KEY, TS)
    signer = cs["countersigned_by"]
    untrusted = derive_did_key(bytes([9] * 32))
    assert verify_badge_main([_write(tmp_path, cs), "--trusted-signer", untrusted]) == 1
    assert verify_badge_main([_write(tmp_path, cs), "--trusted-signer", signer]) == 0
