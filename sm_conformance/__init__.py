"""sm-conformance — mechanical, cryptographically-attestable protocol conformance.

A signed **conformance badge**: a runtime runs a vectors-driven suite, then ships
a JSON envelope signed by its own Ed25519 key recording which suite (pinned by a
``suite_digest``) it passed and the counts. Anyone can re-verify the badge
offline against the ``signed_by`` did:key — no service on the path.

Public surface::

    from sm_conformance import build_badge, verify_badge, compute_suite_digest

``verify_badge`` is the admission gate (signature + schema + SPEC.md §9 gates);
``verify_envelope`` / ``verify_countersigned`` are the signature-only primitives
beneath it and do **not** gate on the run result.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

from sm_conformance.badge import (
    ED25519_MULTICODEC_PREFIX,
    MAX_SAFE_INTEGER,
    RUN_BUILD_KEY,
    RUN_SURFACE_KEY,
    RUN_TARGET_KEY,
    SUITE_CODE_DIGEST_KEY,
    CanonicalizationError,
    VerificationError,
    build_badge,
    canonical_json,
    compute_code_digest,
    compute_suite_digest,
    derive_did_key,
    derive_exit_status,
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
from sm_conformance.verify import (
    DEFAULT_MAX_FUTURE_SKEW_S,
    BadgeVerdict,
    verify_badge,
)

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them —
# the shape that shipped sm-provision 0.1.0 reporting "0.0.1" and sm-authority
# 0.1.0 reporting the same wrong value from the same template. Correct today is
# not the test; it drifts at the next bump.
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-conformance")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = [
    "ED25519_MULTICODEC_PREFIX",
    "MAX_SAFE_INTEGER",
    "RUN_BUILD_KEY",
    "RUN_SURFACE_KEY",
    "RUN_TARGET_KEY",
    "SUITE_CODE_DIGEST_KEY",
    "CanonicalizationError",
    "VerificationError",
    "build_badge",
    "canonical_json",
    "compute_code_digest",
    "compute_suite_digest",
    "derive_did_key",
    "derive_exit_status",
    "load_signing_key",
    "parse_did_key",
    "run_extensions",
    "sign_envelope",
    "verify_envelope",
    # admission gate — the one implementation behind the CLI
    "DEFAULT_MAX_FUTURE_SKEW_S",
    "BadgeVerdict",
    "verify_badge",
    # trust-ladder rung 2 — counter-signature
    "CountersignError",
    "counter_sign",
    "is_countersigned",
    "verify_countersigned",
    "__version__",
]
