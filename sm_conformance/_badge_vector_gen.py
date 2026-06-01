"""ARP Conformance Badge vector generator.

One-shot tool. Run from repo root to regenerate every vector in
``tests/fixtures/``. Vectors are deterministic: the
signing key seed and all timestamps are fixed, so re-running this
script produces byte-identical vector files.

The vectors exercise SPEC.md §9 verification:

- ``valid-signed-badge`` — happy path. Verifies, passes pass-gate.
- ``tampered-payload`` — payload mutated after signing. §9.5 fail.
- ``tampered-signature`` — signature byte flipped. §9.5 fail.
- ``wrong-signer`` — signed_by DID does not match the signing key. §9.5 fail.
- ``non-didkey-signer`` — signed_by is did:web. §9.2 fail.
- ``missing-signature`` — signature field absent. §9.1 fail.
- ``failing-run`` — well-formed envelope with failed > 0. Passes §9.1-9.5
  signature checks; fails §9.7 pass-gate by default; accepted with
  --allow-failures.

Each output file is a JSON document with this shape::

    {
      "id":               "<vector-id>",
      "description":      "<one-line>",
      "spec_ref":         "<conformance.md section refs>",
      "expected_outcome": "verify_pass"
                          | "envelope_shape_fail"
                          | "didkey_parse_fail"
                          | "signature_fail"
                          | "pass_gate_fail",
      "verifier_options": { "allow_failures": bool },
      "private_keys":     { "runtime": "<base64 seed>" },
      "envelope":         { ... }   # the badge under test
    }

Usage::

    python conformance/_badge_vector_gen.py

Outputs to ``tests/fixtures/``.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from sm_conformance.badge import derive_did_key, sign_envelope

# Fixed inputs for deterministic vectors. Re-running this script with
# the same constants produces byte-identical files.
RUNTIME_SEED = bytes(range(32))
WRONG_RUNTIME_SEED = bytes(range(32, 64))
FIXED_COMPLETED_AT = "2026-05-30T12:00:00+00:00"
FIXED_SIGNED_AT = "2026-05-30T12:00:00+00:00"
FIXED_SUITE_DIGEST = "sha256:" + "f" * 64  # synthetic digest, not a real run

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _base_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "runtime": "spec-reference",
        "protocol_versions": ["0.3"],
        "suite_digest": FIXED_SUITE_DIGEST,
        "completed_at": FIXED_COMPLETED_AT,
        "exit_status": 0,
        "passed": 46,
        "failed": 0,
        "skipped": 1,
        "xfailed": 0,
        "xpassed": 0,
        "total_vectors": 47,
    }


def _write(name: str, doc: dict[str, Any]) -> None:
    out = OUTPUT_DIR / f"{name}.json"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"  wrote {out.relative_to(OUTPUT_DIR.parent.parent)}")


def _runtime_keys_block() -> dict[str, str]:
    return {"runtime": base64.b64encode(RUNTIME_SEED).decode("ascii")}


def gen_valid_signed_badge() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    _write(
        "valid-signed-badge",
        {
            "id": "valid-signed-badge",
            "description": "Complete envelope, valid signature, passing-run payload.",
            "spec_ref": "conformance.md §4, §7, §9.1-9.7",
            "expected_outcome": "verify_pass",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


def gen_tampered_payload() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    # Mutate one payload field after signing — signature now binds the
    # original bytes; canonical_json over the mutated payload differs.
    envelope["payload"]["passed"] = 999
    _write(
        "tampered-payload",
        {
            "id": "tampered-payload",
            "description": "payload.passed mutated from 46 to 999 after signing.",
            "spec_ref": "conformance.md §9.5",
            "expected_outcome": "signature_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


def gen_tampered_signature() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    sig_bytes = bytearray(base64.b64decode(envelope["signature"]))
    sig_bytes[0] ^= 0xFF  # flip every bit of the first byte
    envelope["signature"] = base64.b64encode(bytes(sig_bytes)).decode("ascii")
    _write(
        "tampered-signature",
        {
            "id": "tampered-signature",
            "description": "First byte of the Ed25519 signature flipped.",
            "spec_ref": "conformance.md §9.5",
            "expected_outcome": "signature_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


def gen_wrong_signer() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    # Replace signed_by with the did:key of an UNRELATED runtime key —
    # the signature was made with RUNTIME_SEED but the envelope now
    # claims a different signer; verify against the claimed signer fails.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    wrong_pub = (
        Ed25519PrivateKey.from_private_bytes(WRONG_RUNTIME_SEED).public_key().public_bytes_raw()
    )
    envelope["signed_by"] = derive_did_key(wrong_pub)
    _write(
        "wrong-signer",
        {
            "id": "wrong-signer",
            "description": "signed_by replaced with an unrelated runtime DID after signing.",
            "spec_ref": "conformance.md §9.5",
            "expected_outcome": "signature_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": {
                "runtime": base64.b64encode(RUNTIME_SEED).decode("ascii"),
                "wrong_runtime": base64.b64encode(WRONG_RUNTIME_SEED).decode("ascii"),
            },
            "envelope": envelope,
        },
    )


def gen_non_didkey_signer() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    envelope["signed_by"] = "did:web:example.com"
    _write(
        "non-didkey-signer",
        {
            "id": "non-didkey-signer",
            "description": (
                "signed_by is a did:web; other DID methods are reserved for future versions."
            ),
            "spec_ref": "conformance.md §9.2",
            "expected_outcome": "didkey_parse_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


def gen_missing_signature() -> None:
    envelope = sign_envelope(_base_payload(), RUNTIME_SEED, FIXED_SIGNED_AT)
    del envelope["signature"]
    _write(
        "missing-signature",
        {
            "id": "missing-signature",
            "description": "signature field absent — envelope shape check fails.",
            "spec_ref": "conformance.md §9.1",
            "expected_outcome": "envelope_shape_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


def gen_failing_run() -> None:
    payload = _base_payload()
    payload["failed"] = 3
    payload["exit_status"] = 1
    payload["passed"] = 43
    envelope = sign_envelope(payload, RUNTIME_SEED, FIXED_SIGNED_AT)
    _write(
        "failing-run",
        {
            "id": "failing-run",
            "description": (
                "Well-formed envelope, valid signature, but payload records "
                "failed=3 and exit_status=1. Verifier rejects by default "
                "(pass-gate, §9.7); accepts with --allow-failures."
            ),
            "spec_ref": "conformance.md §9.7",
            "expected_outcome": "pass_gate_fail",
            "verifier_options": {"allow_failures": False},
            "private_keys": _runtime_keys_block(),
            "envelope": envelope,
        },
    )


GENERATORS = [
    gen_valid_signed_badge,
    gen_tampered_payload,
    gen_tampered_signature,
    gen_wrong_signer,
    gen_non_didkey_signer,
    gen_missing_signature,
    gen_failing_run,
]


def main() -> None:
    print(f"Generating {len(GENERATORS)} badge vectors → {OUTPUT_DIR}")
    for gen in GENERATORS:
        gen()
    print("Done.")


if __name__ == "__main__":
    main()
