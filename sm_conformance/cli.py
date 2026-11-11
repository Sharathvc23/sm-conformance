"""CLI verifier for signed conformance badges.

A thin argument parser over :func:`sm_conformance.verify.verify_badge` — every
gate lives there, so a library caller and this CLI cannot disagree.

Usage::

    sm-verify-badge <path-to-badge.json>
    sm-verify-badge <path> --expected-suite-digest sha256:<hex>
    python -m sm_conformance <path>        # same thing without the console script

(Until 0.4.0 this module was ``sm_conformance.verify_badge``; it moved so the
module name no longer shadows the :func:`sm_conformance.verify_badge` function.)

Exit status:
    0 — badge verifies, and (if asserted) suite_digest matches
    1 — verification failed
    2 — file not found / not JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sm_conformance.badge import VerificationError
from sm_conformance.countersign import CountersignError
from sm_conformance.verify import DEFAULT_MAX_FUTURE_SKEW_S, verify_badge


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a signed conformance badge",
    )
    parser.add_argument("path", help="Path to conformance.json")
    parser.add_argument(
        "--expected-suite-digest",
        default=None,
        help="Optional: assert the badge pins to this suite_digest (format: sha256:<hex>).",
    )
    parser.add_argument(
        "--expected-total-vectors",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Optional: assert the badge's total_vectors equals N — the count a relying "
            "party knows for this suite_digest. This is the real under-execution check; "
            "the in-band total_vectors is self-attested and only catches honest partial runs."
        ),
    )
    parser.add_argument(
        "--require-total-vectors",
        action="store_true",
        default=False,
        help="Fail unless the badge declares total_vectors.",
    )
    parser.add_argument(
        "--max-skipped",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Fail if the run skipped more than N vectors. Skips are the residual "
            "hole the count gate leaves — a runtime can skip the adversarial "
            "vectors and still sum to total_vectors."
        ),
    )
    parser.add_argument(
        "--forbid-skip",
        action="append",
        default=None,
        metavar="VECTOR_ID",
        help="Fail if this vector ID appears in skipped_vectors (repeatable).",
    )
    parser.add_argument(
        "--require-skip-ids",
        action="store_true",
        default=False,
        help="Fail if the badge skipped vectors but does not enumerate skipped_vectors.",
    )
    parser.add_argument(
        "--expected-build",
        default=None,
        metavar="BUILD",
        help="Assert the badge's conformance.run.build extension equals this (which build passed).",
    )
    parser.add_argument(
        "--expected-code-digest",
        default=None,
        metavar="DIGEST",
        help=(
            "Assert the badge's conformance.suite.code_digest extension equals this. "
            "For a behavioral (non-vector) suite, suite_digest does not pin the test "
            "code — this pins it (format: sha256:<hex>)."
        ),
    )
    parser.add_argument(
        "--max-age-days",
        type=float,
        default=None,
        metavar="DAYS",
        help="Fail if completed_at is older than DAYS (freshness gate; stale = weak evidence).",
    )
    parser.add_argument(
        "--max-future-skew-s",
        type=float,
        default=DEFAULT_MAX_FUTURE_SKEW_S,
        metavar="SECONDS",
        help=(
            "Fail if completed_at, signed_at or countersigned_at is more than SECONDS ahead "
            "of this machine's clock (default %(default)s). A forward-dated badge would "
            "otherwise satisfy any --max-age-days bound; this is the clock-skew guard "
            "THREATMODEL.md T5 relies on. Always on."
        ),
    )
    parser.add_argument(
        "--allow-failures",
        action="store_true",
        default=False,
        help=(
            "By default the verifier fails if the badge records failed, errored or xfailed "
            "> 0, or a non-zero exit_status. Pass --allow-failures to verify signature only."
        ),
    )
    parser.add_argument(
        "--require-countersigned",
        action="store_true",
        default=False,
        help="Fail unless the badge is counter-signed (trust-ladder rung 2).",
    )
    parser.add_argument(
        "--require-method",
        choices=("verified", "lab-rerun"),
        default=None,
        help="Require at least this counter-sign method (lab-rerun > verified).",
    )
    parser.add_argument(
        "--trusted-signer",
        action="append",
        default=None,
        metavar="DID",
        help="Require the counter-signer's did:key to be one of these (repeatable).",
    )
    args = parser.parse_args(argv)

    try:
        envelope = json.loads(Path(args.path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"FAIL: file not found: {args.path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"FAIL: invalid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        verdict = verify_badge(
            envelope,
            allow_failures=args.allow_failures,
            expected_suite_digest=args.expected_suite_digest,
            expected_total_vectors=args.expected_total_vectors,
            require_total_vectors=args.require_total_vectors,
            max_skipped=args.max_skipped,
            forbid_skip=args.forbid_skip,
            require_skip_ids=args.require_skip_ids,
            expected_build=args.expected_build,
            expected_code_digest=args.expected_code_digest,
            max_age_days=args.max_age_days,
            max_future_skew_s=args.max_future_skew_s,
            require_countersigned=args.require_countersigned,
            require_method=args.require_method,
            trusted_signers=args.trusted_signer,
        )
    except (VerificationError, CountersignError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    payload = verdict.payload
    if verdict.countersigned:
        print(f"OK: counter-signed by {verdict.countersigned_by} (method={verdict.method})")
        print(f"    inner badge signed by {verdict.signed_by}")
    else:
        print(f"OK: signed by {verdict.signed_by}")
    print(
        f"    runtime={payload.get('runtime')} "
        f"versions={payload.get('protocol_versions')} "
        f"passed={payload.get('passed')} failed={payload.get('failed')}"
    )
    print(f"    suite_digest={payload.get('suite_digest')}")
    print(f"    gates={','.join(verdict.gates)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
