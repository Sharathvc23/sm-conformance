"""sm-conformance — mechanical, cryptographically-attestable protocol conformance.

A signed **conformance badge**: a runtime runs a vectors-driven suite, then ships
a JSON envelope signed by its own Ed25519 key recording which suite (pinned by a
``suite_digest``) it passed and the counts. Anyone can re-verify the badge
offline against the ``signed_by`` did:key — no service on the path.

Public surface::

    from sm_conformance import sign_envelope, verify_envelope, compute_suite_digest
"""

from __future__ import annotations

from sm_conformance.badge import (
    ED25519_MULTICODEC_PREFIX,
    RUN_SURFACE_KEY,
    RUN_TARGET_KEY,
    VerificationError,
    canonical_json,
    compute_suite_digest,
    derive_did_key,
    load_signing_key,
    parse_did_key,
    run_extensions,
    sign_envelope,
    verify_envelope,
)
from sm_conformance.countersign import (
    CountersignError,
    counter_sign,
    is_countersigned,
    verify_countersigned,
)

__version__ = "0.1.0"

__all__ = [
    "ED25519_MULTICODEC_PREFIX",
    "RUN_SURFACE_KEY",
    "RUN_TARGET_KEY",
    "VerificationError",
    "canonical_json",
    "compute_suite_digest",
    "derive_did_key",
    "load_signing_key",
    "parse_did_key",
    "run_extensions",
    "sign_envelope",
    "verify_envelope",
    # trust-ladder rung 2 — counter-signature
    "CountersignError",
    "counter_sign",
    "is_countersigned",
    "verify_countersigned",
    "__version__",
]
