"""CLI verifier for signed conformance badges.

Usage::

    python -m sm_conformance.verify_badge <path-to-badge.json>
    python -m sm_conformance.verify_badge <path> --expected-suite-digest sha256:<hex>

Exit status:
    0 — badge verifies, and (if asserted) suite_digest matches
    1 — verification failed
    2 — file not found / not JSON
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from sm_conformance.badge import VerificationError, verify_envelope
from sm_conformance.countersign import (
    CountersignError,
    is_countersigned,
    verify_countersigned,
)


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
        "--allow-failures",
        action="store_true",
        default=False,
        help=(
            "By default the verifier fails if the badge records failures or "
            "non-zero exit_status. Pass --allow-failures to verify signature only."
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

    countersigned = is_countersigned(envelope)
    try:
        payload = verify_countersigned(envelope) if countersigned else verify_envelope(envelope)
    except (VerificationError, CountersignError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.expected_suite_digest:
        actual = payload.get("suite_digest")
        if actual != args.expected_suite_digest:
            print(
                f"FAIL: suite_digest mismatch — "
                f"expected {args.expected_suite_digest}, got {actual}",
                file=sys.stderr,
            )
            return 1

    # Vector accounting (§9). total_vectors is self-attested: when present, the
    # counts MUST sum to it (catches an *honest* partial run). The transferable
    # guarantee is --expected-total-vectors, where the count comes from what the
    # relying party knows for the suite_digest, not from the runtime.
    total_vectors = payload.get("total_vectors")
    if args.require_total_vectors and total_vectors is None:
        print(
            "FAIL: badge does not declare total_vectors (required by --require-total-vectors).",
            file=sys.stderr,
        )
        return 1
    if total_vectors is not None:
        accounted = sum(
            int(payload.get(k, 0)) for k in ("passed", "failed", "skipped", "xfailed", "xpassed")
        )
        if accounted != total_vectors:
            print(
                f"FAIL: vector accounting mismatch — total_vectors={total_vectors} but "
                f"passed+failed+skipped+xfailed+xpassed={accounted} (run was incomplete).",
                file=sys.stderr,
            )
            return 1
    if args.expected_total_vectors is not None and total_vectors != args.expected_total_vectors:
        print(
            f"FAIL: total_vectors mismatch — expected {args.expected_total_vectors} for this "
            f"suite, got {total_vectors}. The run did not execute the full corpus.",
            file=sys.stderr,
        )
        return 1

    # Skip gate (§9). The bare `skipped` count + accounting lets a runtime skip the
    # adversarial vectors and still pass. skipped_vectors makes the skips visible;
    # these gates let a relying party bound or forbid them.
    skipped = int(payload.get("skipped", 0))
    skipped_vectors = payload.get("skipped_vectors")
    if args.require_skip_ids and skipped > 0 and not skipped_vectors:
        print(
            f"FAIL: badge skipped {skipped} vectors but does not enumerate skipped_vectors.",
            file=sys.stderr,
        )
        return 1
    if args.max_skipped is not None and skipped > args.max_skipped:
        print(
            f"FAIL: too many skipped vectors — {skipped} > --max-skipped {args.max_skipped}.",
            file=sys.stderr,
        )
        return 1
    if args.forbid_skip:
        forbidden_hit = sorted(set(skipped_vectors or []) & set(args.forbid_skip))
        if forbidden_hit:
            print(f"FAIL: required vectors were skipped: {forbidden_hit}.", file=sys.stderr)
            return 1

    # Build gate (§9): "which build passed?" — suite_digest pins the corpus, not the runtime.
    if args.expected_build is not None:
        actual_build = (payload.get("extensions") or {}).get("conformance.run.build")
        if actual_build != args.expected_build:
            print(
                f"FAIL: build mismatch — expected {args.expected_build}, got {actual_build!r}.",
                file=sys.stderr,
            )
            return 1

    # Code-digest gate (§8): pins the behavioral test CODE for a suite whose
    # pass/fail is not vector-driven (suite_digest alone is inert there).
    if args.expected_code_digest is not None:
        actual_code = (payload.get("extensions") or {}).get("conformance.suite.code_digest")
        if actual_code != args.expected_code_digest:
            print(
                f"FAIL: code_digest mismatch — expected {args.expected_code_digest}, "
                f"got {actual_code!r}. The test code deciding pass/fail is not the expected one.",
                file=sys.stderr,
            )
            return 1

    # Freshness gate (§9): a stale badge is weak evidence. Gated on the SIGNED
    # completed_at (NOT the forgeable, out-of-payload countersigned_at).
    if args.max_age_days is not None:
        completed_at = payload.get("completed_at")
        try:
            ts = dt.datetime.fromisoformat(str(completed_at))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=dt.UTC)
            age_days = (dt.datetime.now(dt.UTC) - ts).total_seconds() / 86400.0
        except (TypeError, ValueError):
            print(
                f"FAIL: cannot parse completed_at for freshness: {completed_at!r}.", file=sys.stderr
            )
            return 1
        if age_days > args.max_age_days:
            print(
                f"FAIL: stale badge — {age_days:.1f}d old > --max-age-days {args.max_age_days}.",
                file=sys.stderr,
            )
            return 1

    if not args.allow_failures:
        failed = payload.get("failed")
        exit_status = payload.get("exit_status")
        # xfailed > 0 means failures were laundered into expected-drift (the suite
        # was run with a drift mode that exits 0). Reject it: a run with xfails is
        # not a passing run, even though failed==0 and exit_status==0.
        xfailed = int(payload.get("xfailed", 0))
        if failed is None or failed != 0 or exit_status != 0 or xfailed != 0:
            print(
                f"FAIL: badge records a non-passing run "
                f"(failed={failed}, exit_status={exit_status}, xfailed={xfailed}). "
                f"Use --allow-failures to verify signature only.",
                file=sys.stderr,
            )
            return 1

    # Trust-ladder admission gates (rung 2) — let a relying party *require* a
    # counter-signature, a minimum attestation method, and a trusted signer.
    method_rank = {"verified": 1, "lab-rerun": 2}
    require_countersign = bool(
        args.require_countersigned or args.require_method or args.trusted_signer
    )
    if require_countersign and not countersigned:
        print(
            "FAIL: a counter-signed badge is required; this badge is self-signed only.",
            file=sys.stderr,
        )
        return 1
    if countersigned:
        method = envelope["payload"].get("method")
        signer = envelope["countersigned_by"]
        if args.require_method and method_rank.get(method, 0) < method_rank[args.require_method]:
            print(
                f"FAIL: counter-sign method {method!r} is below the required "
                f"{args.require_method!r}.",
                file=sys.stderr,
            )
            return 1
        if args.trusted_signer and signer not in args.trusted_signer:
            print(
                f"FAIL: counter-signer {signer} is not in the trusted-signer set.",
                file=sys.stderr,
            )
            return 1

    if countersigned:
        cs = envelope["payload"]
        print(f"OK: counter-signed by {envelope['countersigned_by']} (method={cs.get('method')})")
        print(f"    inner badge signed by {cs['badge']['signed_by']}")
    else:
        print(f"OK: signed by {envelope['signed_by']}")
    print(
        f"    runtime={payload.get('runtime')} "
        f"versions={payload.get('protocol_versions')} "
        f"passed={payload.get('passed')} failed={payload.get('failed')}"
    )
    print(f"    suite_digest={payload.get('suite_digest')}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
