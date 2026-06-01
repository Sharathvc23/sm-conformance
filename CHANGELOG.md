# Changelog

## v0.2.0 — Honest canonicalization & load-bearing verification

Hardens the verify path so the constraints the badge relied on are enforced, not
decorative. Backward-compatible: every v0.1.0 badge (ASCII/integer payload, schema-
conformant) still verifies — confirmed against the shipped fixtures and live badges.

**Canonicalization (honest, non-divergent)**
- `canonical_json` now uses **RFC 8785 (JCS)** via the `jcs` library — the same
  library the `arp` receipt suite uses, so the two cannot diverge.
- The signed value space is **constrained**: floats, non-ASCII strings, and bytes
  are rejected on *both* the sign and verify paths (`CanonicalizationError`), before
  any signature is computed or checked.

**Load-bearing schema validation**
- `verify_envelope` validates against `conformance-envelope.schema.json` **after**
  signature verification — a malformed-but-signed badge is now rejected by the
  library, not only in tests.
- `verify_countersigned` validates against a new
  `counter-signed-envelope.schema.json` — rung-2 gets the same enforcement as rung-1.

**Under-execution gate**
- New optional `total_vectors` payload member; when present, the counts MUST sum to
  it (completeness). It is self-attested — `verify_badge --expected-total-vectors N`
  is the transferable check (the count comes from what the verifier knows for the
  `suite_digest`). New `--require-total-vectors` flag.

**Spec**
- §3.1 (new): a badge attests *one* run and is **not a transferable credential** —
  relying parties MUST bind acceptance to `suite_digest` / target / freshness.
- §6 rewritten (JCS + value-space); §9 adds the schema-validate and accounting steps.

**Dependencies**
- `jcs`, `jsonschema`, `referencing` promoted from dev to runtime dependencies.

**Known follow-up**
- The umbrella's forked `badge.py` (which signs the runtime badges) still carries
  the v0.1.0 naive encoder; aligning it to import this primitive is tracked
  separately. The divergence guarantee currently holds across the public repos.

## v0.1.0 — Initial public release

First public release of `sm-conformance` — the signed conformance-badge toolkit,
shipping trust-ladder rungs 1 and 2.

**Badge (rung 1, self-signed)**
- Signed badge envelope: build, sign, verify, and pin to a vector corpus by
  `suite_digest`; offline-verifiable against the runtime's `did:key`.
- `sm-verify-badge` CLI + JSON Schemas for the envelope.

**Counter-signature (rung 2, lab-attested)**
- `counter_sign` / `verify_countersigned` — a neutral lab wraps a runtime's badge
  in its own Ed25519 signature, attesting it re-ran (`lab-rerun`) or verified
  (`verified`) it; both signatures verify independently, the signed `method` is
  unalterable.
- Admission gates — `--require-countersigned`, `--require-method`,
  `--trusted-signer` let a relying party *require* rung 2, making registry
  admission enforceable.
- Normative wire format: `SPEC.md` §12.

The attested-CI rung (SLSA / Sigstore) is the next slice.

- 62 tests; ruff + mypy clean; 93% coverage.
