"""Audit 2026-11 #1 and #2: the library-level admission gate and the future-skew guard.

Before 0.4.0 the pass gate, freshness bound and every other SPEC.md §9 gate lived
only in the CLI's ``main``; ``verify_envelope`` returned the payload of a
``failed=3`` badge and a library caller had to re-derive the gates by hand.
THREATMODEL.md T5 also promised a clock-skew guard that did not exist: a badge
``completed_at`` 400 days in the future passed ``--max-age-days 30``.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_conformance import (
    DEFAULT_MAX_FUTURE_SKEW_S,
    BadgeVerdict,
    CountersignError,
    VerificationError,
    build_badge,
    counter_sign,
    derive_did_key,
    run_extensions,
    verify_badge,
    verify_countersigned,
    verify_envelope,
)
from sm_conformance.cli import main as cli_main
from sm_conformance.verify import check_not_in_future, parse_rfc3339_utc

NOW = dt.datetime(2026, 11, 11, 12, 0, 0, tzinfo=dt.UTC)
COMPLETED = "2026-11-10T12:00:00+00:00"  # one day before NOW
LAB_KEY = bytes([7] * 32)
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _iso(ts: dt.datetime) -> str:
    return ts.isoformat()


def _seed() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _badge(**over: Any) -> dict[str, Any]:
    kw: dict[str, Any] = dict(
        runtime="sm-test",
        signing_key32=_seed(),
        suite_digest="sha256:" + "a" * 64,
        protocol_versions=["0.3"],
        completed_at=COMPLETED,
        passed=46,
        failed=0,
        skipped=1,
        total_vectors=47,
    )
    kw.update(over)
    return build_badge(**kw)


def _write(tmp_path: Path, doc: dict[str, Any]) -> str:
    p = tmp_path / "badge.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# --- #2 the pass gate is in the library ---------------------------------------


def test_verify_envelope_is_not_a_pass_gate_but_verify_badge_is() -> None:
    env = _badge(passed=43, failed=3, total_vectors=47)
    assert env["payload"]["exit_status"] == 1
    # The primitive proves signature + shape only: the failing run verifies.
    assert verify_envelope(env)["failed"] == 3
    # The gate refuses it ...
    with pytest.raises(VerificationError, match="non-passing run.*failed=3"):
        verify_badge(env, now=NOW)
    # ... unless the caller explicitly opts into signature-only mode.
    verdict = verify_badge(env, allow_failures=True, now=NOW)
    assert isinstance(verdict, BadgeVerdict)
    assert verdict.payload["failed"] == 3
    assert "pass" not in verdict.gates


@pytest.mark.parametrize(
    "over",
    [{"passed": 44, "errored": 2}, {"passed": 44, "xfailed": 2}],
    ids=["errored", "xfailed"],
)
def test_verify_badge_rejects_errored_and_xfailed(over: dict[str, int]) -> None:
    with pytest.raises(VerificationError, match="non-passing run"):
        verify_badge(_badge(**over), now=NOW)


def test_verify_badge_rejects_hand_signed_exit_status_mismatch() -> None:
    """A payload that claims exit_status=1 with zero failures is still non-passing."""
    from sm_conformance import sign_envelope

    env = _badge()
    payload = dict(env["payload"], exit_status=1)
    seed = _seed()
    env = sign_envelope(payload, seed, COMPLETED)
    with pytest.raises(VerificationError, match="exit_status=1"):
        verify_badge(env, now=NOW)


def test_verify_badge_verdict_fields_for_self_signed() -> None:
    env = _badge()
    v = verify_badge(env, now=NOW)
    assert v.signed_by == env["signed_by"]
    assert v.countersigned is False
    assert v.countersigned_by is None and v.method is None
    assert v.payload == env["payload"]
    # Only the gates that actually ran are claimed.
    assert v.gates == ("signature", "accounting", "future_skew", "pass")


def test_verify_badge_every_gate_is_recorded_when_applied() -> None:
    env = _badge(
        skipped=1,
        skipped_vectors=["slow-one"],
        extensions={
            **run_extensions("server", "https://x.test", build="abc"),
            "conformance.suite.code_digest": "sha256:" + "c" * 64,
        },
    )
    cs = counter_sign(env, LAB_KEY, COMPLETED, method="lab-rerun")
    v = verify_badge(
        cs,
        expected_suite_digest="sha256:" + "a" * 64,
        expected_total_vectors=47,
        require_total_vectors=True,
        max_skipped=1,
        forbid_skip=["adversarial-1"],
        require_skip_ids=True,
        expected_build="abc",
        expected_code_digest="sha256:" + "c" * 64,
        max_age_days=30,
        require_countersigned=True,
        require_method="lab-rerun",
        trusted_signers=[cs["countersigned_by"]],
        now=NOW,
    )
    assert v.countersigned and v.method == "lab-rerun"
    assert v.countersigned_by == cs["countersigned_by"]
    assert v.signed_by == env["signed_by"]
    assert set(v.gates) == {
        "countersignature",
        "signature",
        "suite_digest",
        "accounting",
        "expected_total_vectors",
        "require_skip_ids",
        "max_skipped",
        "forbid_skip",
        "build",
        "code_digest",
        "max_age",
        "future_skew",
        "pass",
        "method",
        "trusted_signer",
        "countersigned",
    }


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"expected_suite_digest": "sha256:" + "b" * 64}, "suite_digest mismatch"),
        ({"expected_total_vectors": 99}, "total_vectors mismatch"),
        ({"max_skipped": 0}, "too many skipped"),
        ({"require_skip_ids": True}, "does not enumerate skipped_vectors"),
        ({"expected_build": "deadbeef"}, "build mismatch"),
        ({"expected_code_digest": "sha256:" + "c" * 64}, "code_digest mismatch"),
        ({"require_countersigned": True}, "counter-signed badge is required"),
        ({"require_method": "verified"}, "counter-signed badge is required"),
        ({"trusted_signers": ["did:key:zNope"]}, "counter-signed badge is required"),
    ],
)
def test_verify_badge_gate_failures_raise_verification_error(
    kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(VerificationError, match=match):
        verify_badge(_badge(), now=NOW, **kwargs)


def test_verify_badge_forbid_skip_and_accounting_and_require_total() -> None:
    env = _badge(skipped=1, skipped_vectors=["adversarial-1"])
    with pytest.raises(VerificationError, match="required vectors were skipped"):
        verify_badge(env, forbid_skip=["adversarial-1"], now=NOW)
    with pytest.raises(VerificationError, match="accounting mismatch"):
        verify_badge(_badge(total_vectors=50), now=NOW)
    no_total = _badge(total_vectors=None)
    with pytest.raises(VerificationError, match="does not declare total_vectors"):
        verify_badge(no_total, require_total_vectors=True, now=NOW)
    assert "accounting" not in verify_badge(no_total, now=NOW).gates


def test_verify_badge_rung2_method_and_signer_gates() -> None:
    verified = counter_sign(_badge(), LAB_KEY, COMPLETED, method="verified")
    with pytest.raises(VerificationError, match="below the required"):
        verify_badge(verified, require_method="lab-rerun", now=NOW)
    assert verify_badge(verified, require_method="verified", now=NOW).method == "verified"
    stranger = derive_did_key(bytes([9] * 32))
    with pytest.raises(VerificationError, match="not in the trusted-signer set"):
        verify_badge(verified, trusted_signers=[stranger], now=NOW)
    with pytest.raises(ValueError, match="require_method"):
        verify_badge(verified, require_method="notarized", now=NOW)


def test_verify_badge_propagates_countersign_errors() -> None:
    cs = counter_sign(_badge(), LAB_KEY, COMPLETED)
    cs["payload"]["method"] = "verified"  # alter the signed method
    with pytest.raises(CountersignError):
        verify_badge(cs, now=NOW)


def test_verify_badge_requires_aware_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_badge(_badge(), now=dt.datetime(2026, 11, 11))


def test_verify_badge_default_clock_is_now() -> None:
    """Without ``now`` the system clock is used; a badge completed moments ago passes."""
    fresh = _badge(completed_at=_iso(dt.datetime.now(dt.UTC)))
    assert verify_badge(fresh, max_age_days=1).gates[-1] == "pass"


# --- #1 future-skew guard (THREATMODEL T5) ------------------------------------


def test_forward_dated_badge_is_rejected_even_inside_age_window() -> None:
    """The audit's reproduction: completed_at 400 days ahead passed --max-age-days 30."""
    future = _iso(NOW + dt.timedelta(days=400))
    env = _badge(completed_at=future)
    with pytest.raises(VerificationError, match="completed_at is .* in the future"):
        verify_badge(env, max_age_days=30, now=NOW)
    # And with no age bound at all — the guard is on by default.
    with pytest.raises(VerificationError, match="forward-dated"):
        verify_badge(env, now=NOW)
    # Opting out is explicit.
    assert "future_skew" not in verify_badge(env, max_future_skew_s=None, now=NOW).gates


def test_future_skew_boundary_is_configurable() -> None:
    ahead_60s = _iso(NOW + dt.timedelta(seconds=60))
    env = _badge(completed_at=ahead_60s)
    assert "future_skew" in verify_badge(env, now=NOW).gates  # 60 s < default 300 s
    with pytest.raises(VerificationError, match="max_future_skew_s=30"):
        verify_badge(env, max_future_skew_s=30, now=NOW)
    exactly = _iso(NOW + dt.timedelta(seconds=DEFAULT_MAX_FUTURE_SKEW_S))
    assert verify_badge(_badge(completed_at=exactly), now=NOW)  # <= skew passes
    just_over = _iso(NOW + dt.timedelta(seconds=DEFAULT_MAX_FUTURE_SKEW_S + 1))
    with pytest.raises(VerificationError, match="forward-dated"):
        verify_badge(_badge(completed_at=just_over), now=NOW)


def test_future_signed_at_is_rejected() -> None:
    env = _badge(signed_at=_iso(NOW + dt.timedelta(days=2)))
    with pytest.raises(VerificationError, match="signed_at is .* in the future"):
        verify_badge(env, now=NOW)


def test_future_countersigned_at_is_rejected_and_inner_timestamps_checked() -> None:
    inner = _badge()
    cs = counter_sign(inner, LAB_KEY, _iso(NOW + dt.timedelta(days=3)))
    assert verify_countersigned(cs) == inner["payload"]  # the primitive does not care
    with pytest.raises(VerificationError, match="countersigned_at is .* in the future"):
        verify_badge(cs, now=NOW)
    cs_future_inner = counter_sign(
        _badge(completed_at=_iso(NOW + dt.timedelta(days=400))), LAB_KEY, COMPLETED
    )
    with pytest.raises(VerificationError, match="completed_at is .* in the future"):
        verify_badge(cs_future_inner, max_age_days=30, now=NOW)


def test_check_not_in_future_and_parse_helpers() -> None:
    check_not_in_future(COMPLETED, "completed_at", now=NOW, max_future_skew_s=0)
    with pytest.raises(VerificationError, match="cannot parse completed_at"):
        check_not_in_future("not-a-time", "completed_at", now=NOW, max_future_skew_s=0)
    with pytest.raises(VerificationError, match="cannot parse"):
        parse_rfc3339_utc(None, "completed_at")
    # A naive timestamp is read as UTC; a Z suffix is accepted.
    assert parse_rfc3339_utc("2026-11-10T12:00:00", "x") == parse_rfc3339_utc(
        "2026-11-10T12:00:00Z", "x"
    )


def test_stale_badge_still_rejected_by_max_age() -> None:
    old = _badge(completed_at="2020-01-01T00:00:00+00:00")
    with pytest.raises(VerificationError, match="stale badge"):
        verify_badge(old, max_age_days=30, now=NOW)


# --- the CLI is a front-end to verify_badge -----------------------------------


def test_cli_rejects_forward_dated_badge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    future = _iso(dt.datetime.now(dt.UTC) + dt.timedelta(days=400))
    path = _write(tmp_path, _badge(completed_at=future))
    assert cli_main([path, "--max-age-days", "30"]) == 1
    assert "in the future" in capsys.readouterr().err
    assert cli_main([path]) == 1
    # The skew is configurable from the CLI too (here: wide enough to admit it).
    assert cli_main([path, "--max-future-skew-s", str(401 * 86400)]) == 0


def test_cli_rejects_forward_dated_countersigned_at(tmp_path: Path) -> None:
    cs = counter_sign(_badge(), LAB_KEY, _iso(dt.datetime.now(dt.UTC) + dt.timedelta(days=2)))
    assert cli_main([_write(tmp_path, cs)]) == 1


def test_cli_success_reports_applied_gates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, _badge())
    assert cli_main([path, "--expected-suite-digest", "sha256:" + "a" * 64]) == 0
    out = capsys.readouterr().out
    assert "OK: signed by did:key:z6Mk" in out
    assert "gates=signature,suite_digest,accounting,future_skew,pass" in out


def test_cli_countersigned_success_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inner = _badge()
    cs = counter_sign(inner, LAB_KEY, COMPLETED)
    assert cli_main([_write(tmp_path, cs), "--require-method", "lab-rerun"]) == 0
    out = capsys.readouterr().out
    assert f"counter-signed by {cs['countersigned_by']} (method=lab-rerun)" in out
    assert f"inner badge signed by {inner['signed_by']}" in out


# --- golden vectors through the library gate ----------------------------------


def _vector(stem: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{stem}.json").read_text(encoding="utf-8"))["envelope"]


def test_golden_vectors_through_verify_badge() -> None:
    assert verify_badge(_vector("valid-signed-badge"), now=NOW).gates[-1] == "pass"
    with pytest.raises(VerificationError, match="non-passing run"):
        verify_badge(_vector("failing-run"), now=NOW)
    assert verify_badge(_vector("failing-run"), allow_failures=True, now=NOW).payload["failed"] == 3
    with pytest.raises(VerificationError, match="signature verification failed"):
        verify_badge(_vector("tampered-payload"), now=NOW)
