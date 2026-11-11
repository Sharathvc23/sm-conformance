"""End-to-end demo: run a toy suite, ship a signed badge, verify it offline.

Run with::

    python examples/demo.py

This stands in for a real protocol's conformance suite. The point is the *shape*:
a runtime runs its own tests, then attests the result with a badge anyone can
re-verify — without this package knowing anything about the protocol under test.
"""

from __future__ import annotations

from sm_conformance import (
    build_badge,
    derive_did_key,
    verify_badge,
    verify_envelope,
)


def run_toy_suite() -> tuple[int, int]:
    """Pretend conformance suite for an 'echo' protocol. Returns (passed, failed)."""
    cases = [("hi", "hi"), ("", ""), ("a b", "a b")]
    passed = sum(1 for sent, echoed in cases if echoed == sent)
    return passed, len(cases) - passed


def main() -> None:
    passed, failed = run_toy_suite()

    # In a real runtime this seed is the long-lived Ed25519 key in secure storage.
    seed = bytes(range(32))
    signed_at = "2026-05-31T00:00:00+00:00"

    badge = build_badge(
        "echo-demo",
        signing_key32=seed,
        # A real suite digests its vector corpus; the toy suite has none.
        suite_digest="sha256:" + "0" * 64,
        protocol_versions=["0.1"],
        completed_at=signed_at,
        passed=passed,
        failed=failed,
        total_vectors=passed + failed,
    )
    print("signed by:", badge["signed_by"])
    print("derived  :", derive_did_key(bytes(range(32)))[:24] + "...")

    # Any holder of the did:key can do this, offline, with no service. verify_badge
    # is the admission gate: signature + schema + pass gate + freshness guard.
    verdict = verify_badge(badge)
    print(f"verdict  : {verdict.payload['passed']} passed, gates={','.join(verdict.gates)}")

    # verify_envelope is the primitive underneath — signature + shape only. It would
    # also return the payload of a FAILING run; never stop there when admitting.
    assert verify_envelope(badge) == verdict.payload


if __name__ == "__main__":
    main()
