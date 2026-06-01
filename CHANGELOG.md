# Changelog

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
