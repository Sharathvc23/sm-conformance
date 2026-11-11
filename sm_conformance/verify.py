"""Library-level admission gate: :func:`verify_badge`.

:func:`sm_conformance.badge.verify_envelope` and
:func:`sm_conformance.countersign.verify_countersigned` are the *cryptographic
primitives*: they prove the bytes were signed by the named key and are
well-formed. They are **not** a pass gate — a badge recording ``failed: 99``
verifies perfectly well (THREATMODEL.md T2). Until 0.4.0 the gates that turn
"verified" into "conformant" lived only in the ``sm-verify-badge`` CLI, so a
library caller who stopped at ``verify_envelope`` admitted failing runs.

:func:`verify_badge` is the one implementation of those gates, in SPEC.md §9
order, and the CLI is a thin argument parser over it. It returns a
:class:`BadgeVerdict` on success and raises :class:`VerificationError` (or
:class:`CountersignError` for a rung-2 signature failure) otherwise.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sm_conformance.badge import (
    RUN_BUILD_KEY,
    SUITE_CODE_DIGEST_KEY,
    VerificationError,
    verify_envelope,
)
from sm_conformance.countersign import is_countersigned, verify_countersigned

#: Default tolerance for a timestamp that lies *ahead* of the verifier's clock.
#: Honest producers and verifiers disagree by seconds, not days; anything beyond
#: this is a forward-dated badge (THREATMODEL.md T5), which would otherwise sit
#: inside any ``max_age_days`` window forever.
DEFAULT_MAX_FUTURE_SKEW_S: float = 300.0

#: Outcome buckets whose non-zero value makes a run non-passing (SPEC.md §9 step 11).
NON_PASSING_BUCKETS: tuple[str, ...] = ("failed", "errored", "xfailed")

#: Every outcome bucket; their sum must equal ``total_vectors`` when it is present.
COUNT_BUCKETS: tuple[str, ...] = ("passed", "failed", "skipped", "xfailed", "xpassed", "errored")

_METHOD_RANK: dict[str, int] = {"verified": 1, "lab-rerun": 2}


@dataclass(frozen=True)
class BadgeVerdict:
    """What :func:`verify_badge` established about an admitted badge.

    ``payload`` is the runtime's signed run result (the *inner* payload for a
    counter-signed badge). ``gates`` names every check that was applied and
    passed, in order, so a caller — or a log line — can see which assurances the
    verdict actually rests on rather than inferring them from the options it
    thinks it passed.
    """

    payload: dict[str, Any]
    signed_by: str
    countersigned: bool
    countersigned_by: str | None
    method: str | None
    gates: tuple[str, ...]


def parse_rfc3339_utc(value: Any, field: str) -> dt.datetime:
    """Parse a badge timestamp field to an aware UTC datetime, or raise."""
    try:
        ts = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"cannot parse {field} as a timestamp: {value!r}.") from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.UTC)
    return ts.astimezone(dt.UTC)


def check_not_in_future(
    value: Any,
    field: str,
    *,
    now: dt.datetime,
    max_future_skew_s: float,
) -> None:
    """Reject a timestamp more than ``max_future_skew_s`` seconds ahead of ``now``.

    A forward-dated ``completed_at`` defeats every age bound: a badge stamped 400
    days ahead is "fresh" under ``max_age_days=30`` for the next 430 days. The
    skew guard closes that (THREATMODEL.md T5, SPEC.md §9 step 10).
    """
    ts = parse_rfc3339_utc(value, field)
    ahead_s = (ts - now).total_seconds()
    if ahead_s > max_future_skew_s:
        raise VerificationError(
            f"{field} is {ahead_s:.0f}s in the future (> max_future_skew_s={max_future_skew_s:g}): "
            f"forward-dated badge."
        )


def verify_badge(
    envelope: dict[str, Any],
    *,
    allow_failures: bool = False,
    expected_suite_digest: str | None = None,
    expected_total_vectors: int | None = None,
    require_total_vectors: bool = False,
    max_skipped: int | None = None,
    forbid_skip: Iterable[str] | None = None,
    require_skip_ids: bool = False,
    expected_build: str | None = None,
    expected_code_digest: str | None = None,
    max_age_days: float | None = None,
    max_future_skew_s: float | None = DEFAULT_MAX_FUTURE_SKEW_S,
    require_countersigned: bool = False,
    require_method: str | None = None,
    trusted_signers: Iterable[str] | None = None,
    now: dt.datetime | None = None,
) -> BadgeVerdict:
    """Verify a badge **and** apply the admission gates of SPEC.md §9.

    Accepts a bare (rung-1) or counter-signed (rung-2) envelope. In order:
    signature(s) + schema; ``expected_suite_digest``; vector accounting and
    ``expected_total_vectors`` / ``require_total_vectors``; the skip policy
    (``max_skipped``, ``forbid_skip``, ``require_skip_ids``); ``expected_build``;
    ``expected_code_digest``; freshness — ``max_age_days`` on the *signed*
    ``completed_at`` and the always-on future-skew guard (``max_future_skew_s``,
    pass ``None`` to disable) on ``completed_at``, ``signed_at`` and, when present,
    ``countersigned_at``; the pass gate (``failed``, ``errored``, ``xfailed`` and
    ``exit_status`` must all be 0 unless ``allow_failures``); and the rung-2
    admission gates (``require_countersigned``, ``require_method``,
    ``trusted_signers``).

    ``now`` is the verifier's clock (default: the system UTC clock); injectable
    so the freshness and skew gates are testable without sleeping.

    Returns a :class:`BadgeVerdict`. Raises :class:`VerificationError` when any
    gate refuses the badge, or :class:`CountersignError` when a counter-signed
    envelope's own signature or shape is invalid.
    """
    if require_method is not None and require_method not in _METHOD_RANK:
        raise ValueError(
            f"require_method must be one of {tuple(_METHOD_RANK)}, got {require_method!r}"
        )
    clock = now if now is not None else dt.datetime.now(dt.UTC)
    if clock.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    gates: list[str] = []

    # (1)–(5) signature(s) + load-bearing schema. verify_countersigned verifies the
    # inner badge too and returns the inner payload.
    countersigned = is_countersigned(envelope)
    if countersigned:
        payload = verify_countersigned(envelope)
        signed_by = envelope["payload"]["badge"]["signed_by"]
        countersigned_by: str | None = envelope["countersigned_by"]
        method: str | None = envelope["payload"].get("method")
        gates.append("countersignature")
    else:
        payload = verify_envelope(envelope)
        signed_by = envelope["signed_by"]
        countersigned_by = None
        method = None
    gates.append("signature")

    # (6) corpus pin.
    if expected_suite_digest is not None:
        actual = payload.get("suite_digest")
        if actual != expected_suite_digest:
            raise VerificationError(
                f"suite_digest mismatch — expected {expected_suite_digest}, got {actual}"
            )
        gates.append("suite_digest")

    # (7) vector accounting. total_vectors is self-attested: when present the counts
    # MUST sum to it (catches an honest partial run). The transferable guarantee is
    # expected_total_vectors, a count the relying party knows for the suite_digest.
    total_vectors = payload.get("total_vectors")
    if require_total_vectors and total_vectors is None:
        raise VerificationError(
            "badge does not declare total_vectors (required by require_total_vectors)."
        )
    if total_vectors is not None:
        accounted = sum(int(payload.get(k, 0)) for k in COUNT_BUCKETS)
        if accounted != total_vectors:
            raise VerificationError(
                f"vector accounting mismatch — total_vectors={total_vectors} but "
                f"{'+'.join(COUNT_BUCKETS)}={accounted} (run was incomplete)."
            )
        gates.append("accounting")
    if expected_total_vectors is not None:
        if total_vectors != expected_total_vectors:
            raise VerificationError(
                f"total_vectors mismatch — expected {expected_total_vectors} for this suite, "
                f"got {total_vectors}. The run did not execute the full corpus."
            )
        gates.append("expected_total_vectors")

    # (8) skip policy. The bare `skipped` count + accounting lets a runtime skip the
    # adversarial vectors and still pass; skipped_vectors makes the skips gateable.
    skipped = int(payload.get("skipped", 0))
    skipped_vectors = payload.get("skipped_vectors")
    if require_skip_ids:
        if skipped > 0 and not skipped_vectors:
            raise VerificationError(
                f"badge skipped {skipped} vectors but does not enumerate skipped_vectors."
            )
        gates.append("require_skip_ids")
    if max_skipped is not None:
        if skipped > max_skipped:
            raise VerificationError(
                f"too many skipped vectors — {skipped} > max_skipped {max_skipped}."
            )
        gates.append("max_skipped")
    if forbid_skip is not None:
        forbidden = set(forbid_skip)
        if forbidden:
            hit = sorted(set(skipped_vectors or []) & forbidden)
            if hit:
                raise VerificationError(f"required vectors were skipped: {hit}.")
            gates.append("forbid_skip")

    extensions = payload.get("extensions") or {}

    # (9) build pin: "which build passed?" — suite_digest pins the corpus, not the runtime.
    if expected_build is not None:
        actual_build = extensions.get(RUN_BUILD_KEY)
        if actual_build != expected_build:
            raise VerificationError(
                f"build mismatch — expected {expected_build}, got {actual_build!r}."
            )
        gates.append("build")

    # code-digest pin: for a behavioral suite, suite_digest does not pin the test code.
    if expected_code_digest is not None:
        actual_code = extensions.get(SUITE_CODE_DIGEST_KEY)
        if actual_code != expected_code_digest:
            raise VerificationError(
                f"code_digest mismatch — expected {expected_code_digest}, got {actual_code!r}. "
                f"The test code deciding pass/fail is not the expected one."
            )
        gates.append("code_digest")

    # (10) freshness, on the SIGNED completed_at (never the forgeable countersigned_at).
    completed_at = payload.get("completed_at")
    if max_age_days is not None:
        age_days = (clock - parse_rfc3339_utc(completed_at, "completed_at")).total_seconds() / 86400
        if age_days > max_age_days:
            raise VerificationError(
                f"stale badge — {age_days:.1f}d old > max_age_days {max_age_days:g}."
            )
        gates.append("max_age")
    # Future-skew guard (T5). On by default: a forward-dated completed_at is inside
    # every age window, so the age bound alone is no bound at all. signed_at and
    # countersigned_at are unsigned, but an honest producer never emits them in the
    # future either, so a future value is an inconsistency to refuse, not to trust.
    if max_future_skew_s is not None:
        check_not_in_future(
            completed_at, "completed_at", now=clock, max_future_skew_s=max_future_skew_s
        )
        signed_at = (
            envelope["payload"]["badge"]["signed_at"] if countersigned else envelope["signed_at"]
        )
        check_not_in_future(signed_at, "signed_at", now=clock, max_future_skew_s=max_future_skew_s)
        if countersigned:
            check_not_in_future(
                envelope["countersigned_at"],
                "countersigned_at",
                now=clock,
                max_future_skew_s=max_future_skew_s,
            )
        gates.append("future_skew")

    # (11) pass gate. Verification ≠ conformance (T2): a signed `failed: 3` is a valid
    # badge of a failing run. xfailed > 0 is failures laundered into expected drift;
    # errored > 0 means part of the corpus never ran. Neither is a passing run.
    if not allow_failures:
        failed = payload.get("failed")
        exit_status = payload.get("exit_status")
        xfailed = int(payload.get("xfailed", 0))
        errored = int(payload.get("errored", 0))
        if failed is None or failed != 0 or exit_status != 0 or xfailed != 0 or errored != 0:
            raise VerificationError(
                f"badge records a non-passing run "
                f"(failed={failed}, exit_status={exit_status}, xfailed={xfailed}, "
                f"errored={errored}). Use allow_failures to verify signature only."
            )
        gates.append("pass")

    # Rung-2 admission gates (§12.2): a relying party may REQUIRE a counter-signature,
    # a minimum attestation method, and a trusted lab.
    trusted = tuple(trusted_signers) if trusted_signers is not None else ()
    wants_rung2 = require_countersigned or require_method is not None or bool(trusted)
    if wants_rung2 and not countersigned:
        raise VerificationError(
            "a counter-signed badge is required; this badge is self-signed only."
        )
    if countersigned:
        if require_method is not None:
            if _METHOD_RANK.get(str(method), 0) < _METHOD_RANK[require_method]:
                raise VerificationError(
                    f"counter-sign method {method!r} is below the required {require_method!r}."
                )
            gates.append("method")
        if trusted:
            if countersigned_by not in trusted:
                raise VerificationError(
                    f"counter-signer {countersigned_by} is not in the trusted-signer set."
                )
            gates.append("trusted_signer")
        if require_countersigned:
            gates.append("countersigned")

    return BadgeVerdict(
        payload=payload,
        signed_by=signed_by,
        countersigned=countersigned,
        countersigned_by=countersigned_by,
        method=method,
        gates=tuple(gates),
    )
