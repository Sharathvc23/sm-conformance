# Changelog

## v0.1.0 — Initial public release

First public release of `sm-conformance` — the signed conformance-badge toolkit,
shipping trust-ladder rungs 1 and 2 with an honest, load-bearing verify path.

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

**Honest canonicalization**
- `canonical_json` uses **RFC 8785 (JCS)** via the `jcs` library — the same library
  the `arp` receipt suite uses, so the two cannot diverge.
- The signed value space is **constrained**: floats, non-ASCII strings, and bytes
  are rejected on *both* the sign and verify paths (`CanonicalizationError`), before
  any signature is computed or checked.

**Load-bearing verification**
- `verify_envelope` validates against `conformance-envelope.schema.json` **after**
  signature verification — a malformed-but-signed badge is rejected by the library,
  not merely flagged in a test. `verify_countersigned` validates against
  `counter-signed-envelope.schema.json`, so rung 2 is enforced like rung 1.
- Optional signed `total_vectors`; when present the counts MUST sum to it. It is
  self-attested — `verify_badge --expected-total-vectors N` is the transferable
  under-execution check (the count comes from what the verifier knows for the
  `suite_digest`), with `--require-total-vectors` to demand the field. A badge
  attests *one* run and is not a transferable credential (`SPEC.md` §3.1).

The attested-CI rung (SLSA / Sigstore) is the next slice.

**Known follow-up**
- The umbrella's forked `badge.py` (which signs the runtime badges) carries its own
  encoder; aligning it to import this primitive is tracked separately.

- 74 tests; ruff + mypy --strict clean; 93% coverage.
