"""0.2.0 hardening: honest canonicalization, load-bearing schema, count gate.

Covers the verify-path enforcement that 0.1.0 left decorative — see SPEC.md
§6 (JCS + value-space), §9 (schema validation + vector accounting), §12.1.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_conformance.badge import (
    CanonicalizationError,
    VerificationError,
    canonical_json,
    derive_did_key,
    sign_envelope,
    verify_envelope,
)
from sm_conformance.countersign import CountersignError, counter_sign, verify_countersigned
from sm_conformance.verify_badge import main as verify_badge_main


def dt_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


SIGNED_AT = "2026-06-01T00:00:00+00:00"


def _seed() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _payload(**over: Any) -> dict[str, Any]:
    p: dict[str, Any] = {
        "schema_version": 1,
        "runtime": "sm-test",
        "protocol_versions": ["0.3"],
        "suite_digest": "sha256:" + "a" * 64,
        "completed_at": SIGNED_AT,
        "exit_status": 0,
        "passed": 46,
        "failed": 0,
        "skipped": 1,
        "xfailed": 0,
        "xpassed": 0,
        "total_vectors": 47,
    }
    p.update(over)
    return p


def _badge_file(envelope: dict[str, Any]) -> Iterator[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(envelope, tmp)
        path = tmp.name
    try:
        yield path
    finally:
        Path(path).unlink(missing_ok=True)


# --- #1 canonicalization is honest (JCS + value-space reject) ----------------


def test_canonical_json_rejects_float() -> None:
    with pytest.raises(CanonicalizationError, match="uncanonicalizable"):
        canonical_json(_payload(passed=1.5))


def test_canonical_json_rejects_non_ascii_string() -> None:
    with pytest.raises(CanonicalizationError, match="non-ASCII"):
        canonical_json(_payload(runtime="café"))


def test_canonical_json_rejects_bytes_value() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"k": b"\x00\x01"})


def test_canonical_json_is_key_order_independent_jcs() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1}) == b'{"a":2,"b":1}'


# --- #2 schema validation is load-bearing on the verify path -----------------


def test_verify_rejects_schema_invalid_payload_despite_valid_signature() -> None:
    # runtime violates ^[a-z0-9-]+$ but is ASCII (canonicalizable), so it signs fine.
    env = sign_envelope(_payload(runtime="Bad_Upper"), _seed(), SIGNED_AT)
    with pytest.raises(VerificationError, match="schema validation"):
        verify_envelope(env)


def test_verify_rejects_negative_count_despite_valid_signature() -> None:
    env = sign_envelope(_payload(passed=-1), _seed(), SIGNED_AT)
    with pytest.raises(VerificationError, match="schema validation"):
        verify_envelope(env)


def test_verify_accepts_well_formed_badge() -> None:
    env = sign_envelope(_payload(), _seed(), SIGNED_AT)
    assert verify_envelope(env)["runtime"] == "sm-test"


# --- #2 rung-2 counter-signed path is hardened the same way ------------------


def _manual_countersign(badge: dict[str, Any], lab_seed: bytes, method: str) -> dict[str, Any]:
    """Like counter_sign but bypasses its method check, to forge a schema-invalid
    yet validly-signed envelope — the only way to reach the outer schema gate."""
    payload = {"schema_version": 1, "badge": badge, "method": method}
    priv = Ed25519PrivateKey.from_private_bytes(lab_seed)
    sig = priv.sign(canonical_json(payload))
    return {
        "payload": payload,
        "countersigned_by": derive_did_key(priv.public_key().public_bytes_raw()),
        "countersigned_at": SIGNED_AT,
        "countersignature": base64.b64encode(sig).decode(),
    }


def test_countersign_round_trip_still_verifies() -> None:
    badge = sign_envelope(_payload(), _seed(), SIGNED_AT)
    cs = counter_sign(badge, _seed(), SIGNED_AT, method="lab-rerun")
    assert verify_countersigned(cs)["runtime"] == "sm-test"


def test_countersign_verify_rejects_schema_invalid_method() -> None:
    badge = sign_envelope(_payload(), _seed(), SIGNED_AT)
    forged = _manual_countersign(badge, _seed(), method="not-a-method")
    with pytest.raises(CountersignError, match="schema validation"):
        verify_countersigned(forged)


# --- #3 the count gate (CLI) -------------------------------------------------


def test_cli_rejects_accounting_mismatch() -> None:
    # total_vectors says 99 but counts sum to 47 — an incomplete run.
    env = sign_envelope(_payload(total_vectors=99), _seed(), SIGNED_AT)
    for path in _badge_file(env):
        assert verify_badge_main([path]) == 1


def test_cli_expected_total_vectors_mismatch_rejected() -> None:
    env = sign_envelope(_payload(), _seed(), SIGNED_AT)  # total_vectors=47
    for path in _badge_file(env):
        assert verify_badge_main([path, "--expected-total-vectors", "63"]) == 1
        assert verify_badge_main([path, "--expected-total-vectors", "47"]) == 0


def test_cli_require_total_vectors_when_absent_rejected() -> None:
    payload = _payload()
    del payload["total_vectors"]
    env = sign_envelope(payload, _seed(), SIGNED_AT)
    for path in _badge_file(env):
        assert verify_badge_main([path]) == 0  # absent is fine by default
        assert verify_badge_main([path, "--require-total-vectors"]) == 1


# --- generator + skip-identity + build + freshness gates (2nd hardening) ------


def _badge(**over: Any) -> dict[str, Any]:
    """A signed badge via the generator, with overridable build_badge kwargs."""
    from sm_conformance.badge import build_badge

    kw: dict[str, Any] = dict(
        runtime="sm-test",
        signing_key32=_seed(),
        suite_digest="sha256:" + "a" * 64,
        protocol_versions=["0.3"],
        completed_at=SIGNED_AT,
        passed=46,
        failed=0,
        skipped=1,
        total_vectors=47,
    )
    kw.update(over)
    return build_badge(**kw)


def test_build_badge_emits_skip_ids_and_build() -> None:
    from sm_conformance.badge import run_extensions

    env = _badge(
        skipped=2,
        total_vectors=48,
        skipped_vectors=["b", "a"],
        extensions=run_extensions("server", "https://x.test/", build="abc123"),
    )
    p = verify_envelope(env)
    assert p["skipped_vectors"] == ["a", "b"]  # sorted
    assert p["extensions"]["conformance.run.build"] == "abc123"
    assert p["extensions"]["conformance.run.target"] == "https://x.test"


def test_max_skipped_gate() -> None:
    env = _badge(skipped=3, total_vectors=49)
    for path in _badge_file(env):
        assert verify_badge_main([path, "--max-skipped", "2"]) == 1
        assert verify_badge_main([path, "--max-skipped", "3"]) == 0


def test_forbid_skip_gate() -> None:
    env = _badge(skipped=2, total_vectors=48, skipped_vectors=["adversarial-x", "env-y"])
    for path in _badge_file(env):
        assert verify_badge_main([path, "--forbid-skip", "adversarial-x"]) == 1
        assert verify_badge_main([path, "--forbid-skip", "not-skipped"]) == 0


def test_require_skip_ids_gate() -> None:
    env = _badge(skipped=1, total_vectors=47)  # has skips but no skipped_vectors
    for path in _badge_file(env):
        assert verify_badge_main([path, "--require-skip-ids"]) == 1


def test_expected_build_gate() -> None:
    from sm_conformance.badge import run_extensions

    env = _badge(extensions=run_extensions("client", "offline", build="deadbeef"))
    for path in _badge_file(env):
        assert verify_badge_main([path, "--expected-build", "deadbeef"]) == 0
        assert verify_badge_main([path, "--expected-build", "other"]) == 1


def test_freshness_gate_on_signed_completed_at() -> None:
    fresh = _badge(completed_at=dt_now())
    stale = _badge(completed_at="2020-01-01T00:00:00+00:00")
    for path in _badge_file(fresh):
        assert verify_badge_main([path, "--max-age-days", "1"]) == 0
    for path in _badge_file(stale):
        assert verify_badge_main([path, "--max-age-days", "30"]) == 1


def test_xfailed_run_is_rejected_by_default() -> None:
    """xfailed > 0 = failures laundered into drift; not a passing run."""
    env = _badge(passed=45, failed=0, skipped=0, xfailed=2, total_vectors=47)
    for path in _badge_file(env):
        assert verify_badge_main([path]) == 1
        assert verify_badge_main([path, "--allow-failures"]) == 0


def test_errored_run_is_rejected_by_default() -> None:
    """errored > 0 = a test could not even run (setup/teardown error); the corpus
    was not exercised, so it is not a passing run — even with failed==exit==0."""
    env = _badge(passed=44, failed=0, skipped=1, errored=2, total_vectors=47)
    for path in _badge_file(env):
        assert verify_badge_main([path]) == 1
        assert verify_badge_main([path, "--allow-failures"]) == 0


def test_errored_counts_toward_accounting() -> None:
    """errored is part of the completeness sum: a run that errors instead of passing
    still has to add up to total_vectors, so errors can't silently shrink the corpus."""
    # 44 + 0 + 1 + 0 + 0 + 2(errored) = 47 == total_vectors → accounting OK.
    env = _badge(passed=44, failed=0, skipped=1, errored=2, total_vectors=47)
    for path in _badge_file(env):
        # accounting passes (sums to 47); only the failure gate trips it.
        assert verify_badge_main([path, "--allow-failures"]) == 0
    # Drop the errored count from the sum → accounting mismatch (44+1 != 47).
    env_bad = _badge(passed=44, failed=0, skipped=1, total_vectors=47)
    for path in _badge_file(env_bad):
        assert verify_badge_main([path]) == 1


def test_compute_code_digest_deterministic_and_guards(tmp_path: Any) -> None:
    import pathlib

    from sm_conformance.badge import compute_code_digest

    root = pathlib.Path(tmp_path)
    (root / "a.py").write_text("x = 1\n")
    (root / "b.py").write_text("y = 2\n")
    d1 = compute_code_digest(root)
    d2 = compute_code_digest(root)
    assert d1 == d2 and d1.startswith("sha256:")
    (root / "a.py").write_text("x = 999\n")  # change code → digest changes
    assert compute_code_digest(root) != d1
    with pytest.raises(ValueError):
        compute_code_digest(root, pattern="*.nope")


def test_expected_code_digest_gate() -> None:
    from sm_conformance.badge import SUITE_CODE_DIGEST_KEY

    cd = "sha256:" + "c" * 64
    env = _badge(extensions={SUITE_CODE_DIGEST_KEY: cd})
    for path in _badge_file(env):
        assert verify_badge_main([path, "--expected-code-digest", cd]) == 0
        assert verify_badge_main([path, "--expected-code-digest", "sha256:" + "d" * 64]) == 1
