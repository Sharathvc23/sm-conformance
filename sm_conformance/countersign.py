"""Trust-ladder rung 2: lab counter-signature over a runtime's badge.

A self-signed badge (rung 1) is a *claim* by the holder of the signing key. A
**counter-signed** badge adds a neutral lab's attestation that it verified — or
re-ran — the runtime's badge. Both signatures are present and independently
verifiable, so a relying party trusts the lab rather than the runtime's
self-assertion. This is the rung registry admission requires in untrusted
settings (see SPEC.md §5, §11).

The counter-signed envelope mirrors the badge envelope shape::

    {
      "payload": {
        "schema_version": 1,
        "badge": { ... },          # the runtime's full signed badge, verbatim
        "method": "lab-rerun"      # how the lab attests (see below)
      },
      "countersigned_by": "did:key:z...",   # the lab's did:key
      "countersigned_at": "<rfc3339>",
      "countersignature": "<base64 Ed25519 over canonical_json(payload)>"
    }

``method`` is signed, so it cannot be altered:

- ``lab-rerun`` — the lab re-ran the conformance suite against the runtime's
  deployed surface and obtained this badge. The strongest attestation.
- ``verified`` — the lab confirmed the badge's signature and counts only,
  without re-running. Weaker; useful when re-running is impractical.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema.exceptions import ValidationError

from sm_conformance.badge import (
    VerificationError,
    canonical_json,
    derive_did_key,
    make_validator,
    parse_did_key,
    verify_envelope,
)

COUNTERSIGN_SCHEMA_VERSION = 1
_METHODS = ("lab-rerun", "verified")
_COUNTERSIGN_VALIDATOR = make_validator("counter-signed-envelope.schema.json")


class CountersignError(Exception):
    pass


def counter_sign(
    badge: dict[str, Any],
    lab_private_key32: bytes,
    countersigned_at: str,
    method: str = "lab-rerun",
) -> dict[str, Any]:
    """Wrap a runtime's signed ``badge`` in a lab counter-signature.

    The lab signs ``canonical_json({schema_version, badge, method})`` with its own
    Ed25519 key, committing to the exact runtime badge (signature and all) and the
    attestation method. Returns the counter-signed envelope.
    """
    if len(lab_private_key32) != 32:
        raise ValueError(f"lab key must be 32 bytes, got {len(lab_private_key32)}")
    if method not in _METHODS:
        raise ValueError(f"method must be one of {_METHODS}, got {method!r}")
    payload = {
        "schema_version": COUNTERSIGN_SCHEMA_VERSION,
        "badge": badge,
        "method": method,
    }
    priv = Ed25519PrivateKey.from_private_bytes(lab_private_key32)
    pub_bytes = priv.public_key().public_bytes_raw()
    signature = priv.sign(canonical_json(payload))
    return {
        "payload": payload,
        "countersigned_by": derive_did_key(pub_bytes),
        "countersigned_at": countersigned_at,
        "countersignature": base64.b64encode(signature).decode("ascii"),
    }


def verify_countersigned(envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify a counter-signed badge — *both* signatures.

    Confirms (1) the inner runtime badge's own signature, and (2) the lab's
    counter-signature over the wrapping payload. Returns the inner badge's
    run-result payload on success; raises ``CountersignError`` otherwise.

    Like ``verify_envelope``, this checks signatures only — the pass-gate
    (``failed == 0``) is applied by the verifier CLI, against the returned
    inner payload.
    """
    for field in ("payload", "countersigned_by", "countersigned_at", "countersignature"):
        if field not in envelope:
            raise CountersignError(f"counter-signed envelope missing required field: {field}")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or not isinstance(payload.get("badge"), dict):
        raise CountersignError("payload must be an object containing a 'badge' object")

    # 1 — the inner runtime badge must verify on its own.
    try:
        inner_payload = verify_envelope(payload["badge"])
    except VerificationError as exc:
        raise CountersignError(f"inner badge failed verification: {exc}") from exc

    # 2 — the lab's counter-signature over canonical_json(payload).
    try:
        lab_pubkey = parse_did_key(envelope["countersigned_by"])
    except ValueError as exc:
        raise CountersignError(f"invalid countersigned_by: {exc}") from exc
    try:
        sig = base64.b64decode(envelope["countersignature"], validate=True)
    except Exception as exc:
        raise CountersignError(f"countersignature is not valid base64: {exc}") from exc
    try:
        Ed25519PublicKey.from_public_bytes(lab_pubkey).verify(sig, canonical_json(payload))
    except InvalidSignature as exc:
        raise CountersignError("counter-signature verification failed") from exc

    # Both signatures authentic — now enforce the wrapping envelope is well-formed
    # (rung-2 gets the same load-bearing schema check as rung-1; SPEC.md §12.1).
    try:
        _COUNTERSIGN_VALIDATOR.validate(envelope)
    except ValidationError as exc:
        raise CountersignError(
            f"counter-signed envelope failed schema validation: {exc.message}"
        ) from exc

    return inner_payload


def is_countersigned(envelope: dict[str, Any]) -> bool:
    """True if ``envelope`` is a counter-signed badge (vs a bare badge)."""
    return "countersignature" in envelope and isinstance(envelope.get("payload"), dict) and (
        "badge" in envelope["payload"]
    )
