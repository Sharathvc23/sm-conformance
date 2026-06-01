# sm-conformance

**Mechanical, cryptographically-attestable protocol conformance — signed badges any party re-verifies offline.**

A protocol is only "open" if compliance is *checkable*. `sm-conformance` is the
toolkit for that check: a runtime runs a vectors-driven suite, then ships a small
JSON **badge** signed by its own Ed25519 key recording *which* suite it passed
(pinned by a `suite_digest`) and the pass/fail counts. Anyone holding the
runtime's `did:key` can re-verify the badge **offline** — no service, no vendor,
no trust-me. This package owns exactly that envelope: building it, signing it,
pinning it, and verifying it. It does **not** define your protocol's tests — you
bring those.

## What this package secures (v0.1)

- **Offline-verifiable attestation.** A badge is an Ed25519 signature over an
  RFC 8785-style canonical JSON payload; verification needs only the embedded
  `did:key` and `cryptography` — no network, no proprietary service.
- **Corpus pinning.** `suite_digest` is a SHA-256 over the vector corpus, so a
  badge proves *which* suite ran; swapping in a weaker corpus changes the digest.
- **Honest gating.** The verifier refuses a badge that records `failed > 0` or a
  non-zero exit status unless you explicitly opt into signature-only mode.
- **Adversarially tested.** Tampered payloads, tampered signatures, wrong signer,
  non-`did:key` signer, missing fields, and pass-gate evasion are all covered by
  golden vectors and unit tests (40 tests).

## What this package does NOT (yet) do

- **Run your tests.** It attests *the result* of a suite; wiring a suite (and the
  adapter that plugs a runtime in) is the consumer's responsibility — see the
  reference example.
- **Establish third-party trust.** A self-signed badge is a *claim*. The
  self → lab-counter-signed → attested-CI trust ladder is specified in
  [`SPEC.md`](./SPEC.md) §11 but the counter-sign/attestation tooling is a v0.2
  property.
- **Canonicalize non-ASCII / floating-point payloads** to full RFC 8785 JCS — the
  current encoding is byte-identical to JCS for ASCII payloads only (SPEC §6).

## Features

- `sign_envelope` / `verify_envelope` — build and check a signed badge.
- `compute_suite_digest(path)` — pin a badge to a vector corpus.
- `derive_did_key` / `parse_did_key` — W3C `did:key` (base58btc, multicodec `0xed01`).
- `run_extensions(surface, target)` — optional, namespaced run provenance.
- `sm-verify-badge` CLI (`python -m sm_conformance.verify_badge`).
- JSON Schemas for the envelope (`sm_conformance/schema/`), validated in tests.

## Installation

```bash
pip install sm-conformance
# working draft: pip install git+https://github.com/Sharathvc23/sm-conformance.git
```

## Quick start

```python
from sm_conformance import sign_envelope, verify_envelope, compute_suite_digest

payload = {
    "schema_version": 1,
    "runtime": "my-runtime",
    "protocol_versions": ["0.1"],
    "suite_digest": compute_suite_digest("vectors"),  # SHA-256 over your corpus
    "completed_at": "2026-05-31T00:00:00+00:00",
    "exit_status": 0,
    "passed": 42, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0,
}

seed = bytes(range(32))                      # your runtime's Ed25519 seed (32 bytes)
badge = sign_envelope(payload, seed, "2026-05-31T00:00:00+00:00")

verify_envelope(badge)                       # raises VerificationError if invalid
```

```bash
sm-verify-badge badge.json --expected-suite-digest sha256:<hex>
```

## Reference fixtures

`tests/fixtures/` holds the golden badge vectors — one positive
(`valid-signed-badge`) and six negative (`tampered-payload`, `tampered-signature`,
`wrong-signer`, `non-didkey-signer`, `missing-signature`, `failing-run`), each
self-declaring its expected verification outcome. They are deterministic
(regenerate with `python -m sm_conformance._badge_vector_gen`). The keys are
fixed test seeds, not production signers.

## Specification

- [`SPEC.md`](./SPEC.md) — normative envelope, canonical encoding, signing,
  suite-digest, verification algorithm, and trust ladder. Working draft.
- [`WHITEPAPER.md`](./WHITEPAPER.md) — why mechanical conformance matters for an
  internet of independently-built agents.

## Related packages

| Package | Role |
| --- | --- |
| [`sm-attest-viewer`](https://github.com/Sharathvc23/sm-attest-viewer) | Renderer for attested agent action-envelope chains |
| [`sm-decision-inspector`](https://github.com/Sharathvc23/sm-decision-inspector) | Human-in-the-loop decision workbench |
| [`sm-locp`](https://github.com/Sharathvc23/sm-locp) | Open compliance protocol (defeasible logic + W3C VCs) |

## License

[MIT](./LICENSE)

---

*First published: 2026-05-31 | Last modified: 2026-05-31*

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
