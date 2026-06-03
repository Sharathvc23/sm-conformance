# Changelog

## v0.3.0 — Tier-3 audit fixes: cross-language vectors, tight regex, base64, freshness honesty

- **Cross-language canonicalization vectors** (`sm_conformance/vectors/canonicalization.json`):
  valid→canonical-bytes + invalid (float / non-ASCII) the future Go/Rust/TS verifiers
  check themselves against. Authoring them caught a real bug: **non-ASCII object keys**
  were not rejected (only non-string keys) — now rejected.
- **Tighter `didKey` regex**: Ed25519 did:key is always `z6Mk`+44 base58 chars; bound it
  (was `{32,}`), matching the tight signature regex.
- **SPEC §7**: signature is **standard** base64 (RFC 4648 §4), not url-safe.
- **SPEC §12.1**: a relying party **MUST NOT** gate freshness on the forgeable, unsigned
  `countersigned_at`; use the signed inner `completed_at`. `method: "verified"` carries no
  fresh signed timestamp.
- **SPEC §2**: the "why not Sigstore / in-toto / cosign" case (offline, no transparency log
  or PKI, dependency-light cross-language verify; they compose as rungs above, not the base).


## v0.2.0 — Second hardening: skip-identity, build & code binding, freshness, generator

Closes the holes that survive a correctly-configured verifier (an external audit's
Tier-1/2 findings), and adds the generate side the toolkit was missing.

- **build_badge()** — turnkey generator: counts + skipped-vector IDs + run provenance
  → signed badge.
- **skipped_vectors** (signed) + `--max-skipped` / `--forbid-skip` / `--require-skip-ids`
  — the bare `skipped` count let a runtime skip the adversarial vector it would fail
  and still pass; the identities make skips gateable.
- **compute_code_digest** + `conformance.suite.code_digest` + `--expected-code-digest`
  — pins a behavioral suite's *test code*, which `suite_digest` (vectors-only) cannot.
- **conformance.run.build** + `--expected-build` — "which build passed?"; fixed the
  docstring that claimed commit-binding with no field.
- **`--max-age-days`** against the **signed** `completed_at` (not the forgeable
  `countersigned_at`); reject **`xfailed > 0`** (drift-laundering) by default.
- **compute_suite_digest**: POSIX-string sort + `.gitattributes` (LF) — no cross-platform drift.
- SPEC §3.2/§5.2/§8/§9 (+ §9.1 locked-down invocation). All additive; `schema_version`
  stays 1, every v0.1.0 badge still verifies.


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
