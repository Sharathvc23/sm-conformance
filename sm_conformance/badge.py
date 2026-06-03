"""Signed conformance badge — generation, canonical encoding, and verification.

A conformance badge is the wrapped envelope a runtime ships at
``conformance.json`` to prove it passed a suite. ``suite_digest`` pins the
*vector corpus* that was run (not the runtime's own build) — the runtime's
build, when known, is recorded separately in the ``conformance.run.build``
extension (see ``run_extensions``). The badge is signed by the runtime's
Ed25519 key; the verifier canonically re-encodes the payload and confirms
the signature against the ``signed_by`` did:key.

Envelope shape::

    {
      "payload": {
        "schema_version": 1,
        "runtime": "spec-reference",
        "protocol_versions": ["0.2", "0.3"],
        "suite_digest": "sha256:<hex>",
        "completed_at": "<iso8601>",
        "exit_status": 0,
        "passed": 47, "failed": 0, "skipped": 1,
        "xfailed": 0, "xpassed": 0
      },
      "signed_by": "did:key:z6Mk...",
      "signed_at": "<iso8601>",
      "signature": "<base64>"
    }

The signature is over the UTF-8 bytes of ``canonical_json(payload)``.
For payloads containing only ASCII strings, ints, bools, null, and
nested dicts/lists with the same constraint, the encoding is byte-
identical to RFC 8785 JCS. Non-ASCII or floating-point payloads will
require proper JCS — flagged as future work for a future SPEC.md version.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.resources
import json
from pathlib import Path
from typing import Any

import base58
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry
from referencing.jsonschema import DRAFT202012

ED25519_MULTICODEC_PREFIX = b"\xed\x01"


class CanonicalizationError(Exception):
    """A value cannot be safely canonicalized for signing (see SPEC.md §6)."""


def _reject_uncanonicalizable(value: Any, path: str = "$") -> None:
    """Reject anything outside the badge's signed value space.

    Signed payloads are restricted to ASCII strings, integers, booleans, null,
    and containers thereof. Floats (ambiguous encoding), bytes, and non-ASCII
    strings are rejected *on both the sign and verify paths* — so a value that
    two implementations might canonicalize differently can never be signed or
    accepted in the first place. This is the belt to JCS's suspenders.
    """
    if value is None or isinstance(value, bool | int):  # bool is an int subclass; both allowed
        return
    if isinstance(value, str):
        if not value.isascii():
            raise CanonicalizationError(f"non-ASCII string at {path}: signed values must be ASCII")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _reject_uncanonicalizable(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}")
            if not key.isascii():
                raise CanonicalizationError(f"non-ASCII object key at {path}: {key!r}")
            _reject_uncanonicalizable(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"uncanonicalizable {type(value).__name__} at {path}: badge-signed values must be "
        f"ASCII strings, integers, booleans, null, or containers thereof"
    )


def canonical_json(payload: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonical bytes for signing, after a strict value-space check.

    The reject-guard constrains the input to a value space where JCS is
    unambiguous and matches any other conformant JCS implementation byte-for-byte
    (the ``arp`` receipt suite uses the same library). The two together are what
    make a signature portable across implementations.
    """
    _reject_uncanonicalizable(payload)
    canonical: bytes = jcs.canonicalize(payload)
    return canonical


def _load_schema(filename: str) -> dict[str, Any]:
    text = (importlib.resources.files("sm_conformance") / "schema" / filename).read_text(
        encoding="utf-8"
    )
    schema: dict[str, Any] = json.loads(text)
    return schema


def _build_registry() -> Registry:
    resources = []
    for filename in ("common.schema.json", "conformance-envelope.schema.json"):
        schema = _load_schema(filename)
        resource = DRAFT202012.create_resource(schema)
        resources.append((filename, resource))
        resources.append((schema["$id"], resource))
    return Registry().with_resources(resources)


_REGISTRY = _build_registry()


def make_validator(filename: str) -> Draft202012Validator:
    """Draft 2020-12 validator for a packaged schema, with cross-file $ref resolution."""
    return Draft202012Validator(_load_schema(filename), registry=_REGISTRY)


_ENVELOPE_VALIDATOR = make_validator("conformance-envelope.schema.json")


def derive_did_key(pubkey32: bytes) -> str:
    if len(pubkey32) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
    prefixed = ED25519_MULTICODEC_PREFIX + pubkey32
    encoded = base58.b58encode(prefixed).decode()
    return f"did:key:z{encoded}"


def parse_did_key(did_key: str) -> bytes:
    """Inverse of derive_did_key — returns the 32-byte public key."""
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did_key!r}")
    multibase = did_key[len("did:key:z") :]
    decoded = base58.b58decode(multibase)
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError(f"did:key does not encode an Ed25519 key: {did_key!r}")
    pubkey = decoded[len(ED25519_MULTICODEC_PREFIX) :]
    if len(pubkey) != 32:
        raise ValueError(f"decoded key has wrong length: {len(pubkey)}")
    return pubkey


def compute_suite_digest(vectors_root: Path) -> str:
    """sha256 over every JSON vector file under ``vectors_root``.

    Pins a badge to a specific vector corpus. Any change to any vector file
    changes the digest, invalidating prior badges.

    ``vectors_root`` is required and MUST exist and contain at least one
    ``*.json`` file. Digesting a missing or empty corpus would return a
    valid-looking hash that pins to nothing — the exact footgun a suite digest
    exists to prevent — so both cases raise instead.
    """
    vectors_root = Path(vectors_root)
    if not vectors_root.exists():
        raise FileNotFoundError(f"vectors_root does not exist: {vectors_root}")
    hasher = hashlib.sha256()
    # Sort on the POSIX relative-path string, not on Path objects: Path ordering
    # is platform-dependent, so a string sort is what makes the digest identical
    # across OSes. (Pair this with a `.gitattributes` that forces LF on the
    # vectors, or a CRLF checkout on Windows changes the bytes and the digest.)
    rels = sorted(p.relative_to(vectors_root).as_posix() for p in vectors_root.rglob("*.json"))
    if not rels:
        raise ValueError(f"no *.json vectors found under {vectors_root}")
    for rel in rels:
        path = vectors_root / rel
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(path.read_bytes())
        hasher.update(b"\x00")
    return f"sha256:{hasher.hexdigest()}"


def compute_code_digest(root: Path, pattern: str = "*.py") -> str:
    """sha256 over the code files (default ``*.py``) under ``root``.

    ``compute_suite_digest`` pins the *vector corpus*; for a suite whose pass/fail
    lives in **test modules**, not vectors (e.g. an HTTP server suite), the corpus
    digest does not pin the deciding code. Emit this as the signed
    ``conformance.suite.code_digest`` extension so a relying party can pin the code
    too (and assert it with ``--expected-code-digest``). Same byte-stable scheme as
    the suite digest: POSIX-relative-path-string sort, raw bytes, NUL-delimited —
    pair with a ``.gitattributes`` pinning LF.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"code-digest root does not exist: {root}")
    hasher = hashlib.sha256()
    rels = sorted(p.relative_to(root).as_posix() for p in root.rglob(pattern))
    if not rels:
        raise ValueError(f"no {pattern} files found under {root}")
    for rel in rels:
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update((root / rel).read_bytes())
        hasher.update(b"\x00")
    return f"sha256:{hasher.hexdigest()}"


SUITE_CODE_DIGEST_KEY = "conformance.suite.code_digest"


# Informational provenance keys recording *what* a run attested. Two runs of the
# same runtime against different surfaces (e.g. an offline client suite vs a live
# server suite) produce payloads that differ only in their counts; these
# namespaced keys let a reader tell them apart. Forward-compatible additions per
# SPEC.md §5.2 (the ``conformance.*`` namespace marks them informational, not
# protocol wire): a verifier MUST preserve and MUST NOT fail on them, but is not
# required to interpret them. They satisfy the extensionsObject contract in
# sm_conformance/schema/common.schema.json (namespace-prefixed, >=3 dotted segments).
RUN_SURFACE_KEY = "conformance.run.surface"
RUN_TARGET_KEY = "conformance.run.target"
RUN_BUILD_KEY = "conformance.run.build"


def run_extensions(surface: str, target: str, build: str | None = None) -> dict[str, str]:
    """Provenance for a run: ``surface``, the ``target`` it ran against, and the
    runtime ``build`` it tested.

    Example: ``run_extensions("server", "https://api.example.test", build="a16905c")``.
    ``build`` answers an auditor's "which build passed?" — ``suite_digest`` pins the
    *suite corpus*, not the runtime — so record the runtime's commit/version/artifact
    hash here when it is known. Informational only — see SPEC.md §5.2.
    """
    ext = {
        RUN_SURFACE_KEY: surface,
        RUN_TARGET_KEY: target.rstrip("/"),
    }
    if build is not None:
        ext[RUN_BUILD_KEY] = build
    return ext


def load_signing_key(path: Path) -> bytes:
    """Read an Ed25519 private key — 64 hex characters (preferred) or 32 raw bytes.

    Hex is the canonical format. Raw is best-effort: a legitimate 32-byte raw
    key that happens to end in 0x0a or 0x20 cannot be distinguished from a
    33-byte hex file with trailing whitespace, so this routine never strips
    raw bytes — the file must be exactly 32 bytes long for the raw path.
    """
    raw = path.read_bytes()
    # Hex path: file is a printable ASCII hex string, possibly with trailing
    # whitespace from an editor. Strip and require exactly 64 hex chars.
    try:
        stripped = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        stripped = None
    if (
        stripped is not None
        and len(stripped) == 64
        and all(c in "0123456789abcdefABCDEF" for c in stripped)
    ):
        return bytes.fromhex(stripped)
    # Raw path: file must be exactly 32 bytes, no stripping.
    if len(raw) == 32:
        return raw
    raise ValueError(
        f"signing key file {path} must be 64 hex characters (preferred) "
        f"or exactly 32 raw bytes, got {len(raw)} bytes"
    )


def sign_envelope(
    payload: dict[str, Any],
    private_key32: bytes,
    signed_at: str,
) -> dict[str, Any]:
    """Wrap payload in a signed envelope ready for JSON serialization."""
    if len(private_key32) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
    priv = Ed25519PrivateKey.from_private_bytes(private_key32)
    pub_bytes = priv.public_key().public_bytes_raw()
    did_key = derive_did_key(pub_bytes)
    canonical = canonical_json(payload)
    signature = priv.sign(canonical)
    return {
        "payload": payload,
        "signed_by": did_key,
        "signed_at": signed_at,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def build_badge(
    runtime: str,
    *,
    signing_key32: bytes,
    suite_digest: str,
    protocol_versions: list[str],
    completed_at: str,
    passed: int,
    failed: int,
    skipped: int = 0,
    xfailed: int = 0,
    xpassed: int = 0,
    errored: int = 0,
    total_vectors: int | None = None,
    skipped_vectors: list[str] | None = None,
    extensions: dict[str, str] | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Assemble and sign a conformance badge from a test run's results.

    The turnkey generator: given the counts — and, when known, the *identities*
    of the skipped vectors (``skipped_vectors``) and run provenance
    (``extensions``, e.g. from :func:`run_extensions`) — produce the signed
    envelope a runtime ships. ``exit_status`` is derived (0 iff ``failed == 0``);
    ``signed_at`` defaults to ``completed_at``. Recording *which* vectors were
    skipped is what lets a relying party tell a fully-run badge from one that
    skipped the adversarial cases (SPEC.md §5.2, §9).
    """
    payload: dict[str, Any] = {
        "schema_version": 1,
        "runtime": runtime,
        "protocol_versions": list(protocol_versions),
        "suite_digest": suite_digest,
        "completed_at": completed_at,
        "exit_status": 0 if failed == 0 else 1,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "xfailed": xfailed,
        "xpassed": xpassed,
        "errored": errored,
    }
    if total_vectors is not None:
        payload["total_vectors"] = total_vectors
    if skipped_vectors is not None:
        payload["skipped_vectors"] = sorted(skipped_vectors)
    if extensions:
        payload["extensions"] = dict(extensions)
    return sign_envelope(payload, signing_key32, signed_at or completed_at)


class VerificationError(Exception):
    pass


def verify_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify a signed envelope. Returns the payload on success; raises otherwise."""
    for field in ("payload", "signed_by", "signed_at", "signature"):
        if field not in envelope:
            raise VerificationError(f"envelope missing required field: {field}")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise VerificationError("payload must be an object")
    try:
        pubkey = parse_did_key(envelope["signed_by"])
    except ValueError as exc:
        raise VerificationError(f"invalid signed_by: {exc}") from exc
    try:
        sig = base64.b64decode(envelope["signature"], validate=True)
    except Exception as exc:
        raise VerificationError(f"signature is not valid base64: {exc}") from exc
    try:
        canonical = canonical_json(payload)
    except CanonicalizationError as exc:
        raise VerificationError(f"payload is not canonicalizable: {exc}") from exc
    pub = Ed25519PublicKey.from_public_bytes(pubkey)
    try:
        pub.verify(sig, canonical)
    except InvalidSignature as exc:
        raise VerificationError("signature verification failed") from exc
    # Authenticate the bytes first (above), then enforce that the signed structure
    # is well-formed — schema constraints are load-bearing on the verify path, not
    # merely a test-time check (SPEC.md §9).
    try:
        _ENVELOPE_VALIDATOR.validate(envelope)
    except ValidationError as exc:
        raise VerificationError(f"envelope failed schema validation: {exc.message}") from exc
    return payload
