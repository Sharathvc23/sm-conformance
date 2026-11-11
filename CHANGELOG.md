# Changelog

## v0.4.0 — Audit 2026-11: future-timestamp guard, library pass gate, errored exit status, canonicalization errors

Four confirmed audit findings, each a promise the docs made that the code did not keep.

- **Future-skew guard (THREATMODEL T5).** T5 said forward-dated badges were defended by a
  "clock-skew guard (reject future timestamps)"; none existed — a badge with `completed_at`
  400 days in the future passed `--max-age-days 30` (and would have for 430 days). The
  verifier now rejects `completed_at` (signed), `signed_at` and `countersigned_at` more than
  `max_future_skew_s` (default **300 s**) ahead of its clock, **on by default**. CLI:
  `--max-future-skew-s SECONDS`; library: `max_future_skew_s=` (`None` disables).
- **Library-level pass gate: `verify_badge()`.** Every SPEC §9 gate lived only in the CLI;
  `verify_envelope()` returned the payload of a `failed=3` badge and a library caller had to
  re-derive the gates by hand (T2's "silent footgun", left in place). New
  `sm_conformance.verify.verify_badge(envelope, *, allow_failures=False, expected_suite_digest=None,
  expected_total_vectors=None, require_total_vectors=False, max_skipped=None, forbid_skip=None,
  require_skip_ids=False, expected_build=None, expected_code_digest=None, max_age_days=None,
  max_future_skew_s=300, require_countersigned=False, require_method=None, trusted_signers=None,
  now=None) -> BadgeVerdict` is the one implementation; the CLI calls it. `BadgeVerdict.gates`
  records which checks actually ran. `verify_envelope` / `verify_countersigned` remain the
  signature+schema primitives and are now documented as **not a pass gate**.
- **`build_badge` exit status.** `exit_status` derived from `failed` alone, so `errored=2`
  (or `xfailed=2`) produced a badge claiming exit 0 — contradicting the verifier's own gate.
  New `derive_exit_status(failed=, errored=, xfailed=)`: 0 iff all three are 0.
- **Big integers.** Ints with |n| > 2^53−1 escaped `_reject_uncanonicalizable` and surfaced
  as a raw `jcs` `ValueError` traceback. They are now rejected as `CanonicalizationError`
  (→ `VerificationError` on the verify path) with a clear message, and any residual JCS
  refusal is wrapped the same way. New cross-language vectors: `max-safe-integer-boundary`
  (valid), `integer-above-2^53` / `integer-below-negative-2^53` (invalid).

**Breaking (module path only):** the CLI module moved from `sm_conformance.verify_badge` to
`sm_conformance.cli` — a submodule named `verify_badge` shadows the `verify_badge` function
the moment it is imported. The `sm-verify-badge` console script is unchanged; `python -m
sm_conformance badge.json` is new. Badge wire format and `schema_version` are unchanged; every
0.1.0 badge still verifies.

Docs: SPEC §5.2 (exit_status), §6 (integer bound), §9 (future-skew step, `verify_badge`),
§12.1; THREATMODEL T2/T5 and checklist now name checks that exist in code; README test
count corrected (said 74, suite has 142). Package root now also exports `build_badge`,
`derive_exit_status`, `CanonicalizationError`, `compute_code_digest`, `BadgeVerdict`,
`DEFAULT_MAX_FUTURE_SKEW_S`, `MAX_SAFE_INTEGER`, `RUN_BUILD_KEY`, `SUITE_CODE_DIGEST_KEY`.

## v0.3.2 — fix `__version__` string

- `sm_conformance.__version__` reported `0.1.0` while the published package was
  already `0.3.x` (the string was never bumped alongside `pyproject.toml`). It now
  matches the package version. No API or behavioral changes.

## v0.3.1 — `errored` outcome bucket

- Add the optional `errored` payload count: a test that **errored** (setup/teardown
  failure) rather than ran-and-failed. Previously such tests fell into no bucket and
  silently vanished from the accounting.
- `errored` counts toward the `total_vectors` completeness sum, and a verifier rejects
  `errored > 0` by default (not a passing run), like `failed`/`xfailed`.


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
