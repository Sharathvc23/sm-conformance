# Conformance Badge — Working Draft

**Version (wire):** `sm-conformance/0.1`
**Status:** Working Draft. Reviewable, not yet frozen.
**Last updated:** 2026-05-31

> **Source of truth.** When an implementation disagrees with this specification,
> the implementation is wrong by definition. Behaviour changes require a PR to
> this document plus updates to `sm_conformance/schema/`, the vectors under
> `tests/fixtures/`, and the reference implementation. Conformance is verified
> mechanically by the test suite.

> **Conformance language.** Normative requirements use RFC 2119 keywords
> (**MUST**, **SHOULD**, **MAY**). All other text is non-normative.

---

## 1. Scope and non-goals

### 1.1 Scope
This document defines the **conformance badge**: a signed, self-describing JSON
record that a runtime passed a conformance suite at a specific corpus. It defines
the envelope shape, the canonical encoding signed over, the signing algorithm,
the suite-digest pin, and the verification algorithm.

### 1.2 Non-goals
- It does **not** define any particular protocol's tests, vectors, or adapter.
  Those belong to the consuming suite.
- It does **not** define transport, storage, or where a badge is published.
- It does **not** by itself establish third-party trust — see §11.

### 1.3 Audiences
| Audience | Read |
| --- | --- |
| Runtime author shipping a badge | §4–§8 |
| Verifier implementer | §6, §9, §10 |
| Registry / relying party | §11 |

## 2. Relationship to other specifications
Ed25519 signatures per RFC 8032; `did:key` per the W3C did:key method (multibase
base58btc over multicodec `0xed01 ‖ pubkey32`); canonical JSON aligned with
RFC 8785 (JCS) for ASCII payloads; SHA-256 per FIPS 180-4. The badge is the
verifiable-conformance layer for an internet of independently-built agents
(aligned with [Project NANDA](https://projectnanda.org) standards).

## 3. What the badge is and is not
A badge is a **claim by the holder of a signing key** that a suite was run with a
given corpus and these were the counts. The signature proves the claim came from
that key holder and the payload was not altered. It does **not**, on its own,
prove the run actually happened or that the counts are truthful — a key holder
can sign a fabricated payload. §11 covers establishing trust in untrusted
settings.

### 3.1 A badge attests one run; it is not a transferable credential
A badge commits to a *specific* run, identified by its `suite_digest` (which
corpus), `completed_at` (when), `runtime` (who), and — for a live run — the
`conformance.run.*` extensions (the surface and target it ran against). A relying
party **MUST** bind acceptance to that context: it **MUST NOT** treat a badge as a
free-floating credential transferable to a different corpus, target, or session.
Concretely, a verifier that admits a runtime on a badge **MUST** check the badge's
`suite_digest` against the corpus it actually requires (`--expected-suite-digest`),
**SHOULD** apply a freshness bound on `completed_at` appropriate to its setting, and
for a server runtime **SHOULD** confirm the run target matches the deployment it is
admitting. A badge detached from the context it was issued for proves nothing about
the context it is presented in — this binding is the assumption every other
guarantee in this document rests on.

## 4. Envelope

```json
{
  "payload": { ... },
  "signed_by": "did:key:z6Mk...",
  "signed_at": "<rfc3339-utc>",
  "signature": "<base64-ed25519>"
}
```

### 4.1 Required members
`payload` (object), `signed_by` (did:key), `signed_at` (RFC 3339 UTC),
`signature` (base64 Ed25519 over §6). All **MUST** be present.

### 4.2 Strictness
The envelope object is closed: unknown top-level members **MUST** be rejected by
the schema (`additionalProperties: false`).

## 5. Payload

### 5.1 Required members
`schema_version` (const `1`), `runtime` (`^[a-z0-9-]+$`), `protocol_versions`
(non-empty array of `^[0-9]+\.[0-9]+$`), `suite_digest` (§8), `completed_at`
(RFC 3339 UTC), `exit_status` (int), and the counts `passed` / `failed` /
`skipped` / `xfailed` / `xpassed` (non-negative ints).

### 5.2 Optional members
`adapter` (string), `total_vectors` (non-negative int), and `extensions` (object).
`extensions` keys **MUST** be namespace-prefixed (`<domain>.<sub>.<field>`). A
verifier **MUST** preserve and **MUST NOT** fail on unrecognised extension keys,
and is **not required** to interpret them. New extension keys **MAY** ship without
bumping `schema_version`.

`total_vectors` is the count of vectors the run should have executed. When present,
the counts **MUST** be complete: `passed + failed + skipped + xfailed + xpassed ==
total_vectors`. **This is self-attested** — a runtime that ran a subset can report a
matching smaller `total_vectors` and satisfy the equality. It therefore catches an
*honest* partial run, not a dishonest one. The transferable guarantee is §9's
`--expected-total-vectors`, where the count a verifier compares against comes from
what it independently knows for the `suite_digest`, not from the runtime. Closing
under-execution against an adversarial signer is what rung-2 lab-rerun (§11) is for.

## 6. Canonical encoding
The signature is over the UTF-8 bytes of `canonical_json(payload)`, computed by
**RFC 8785 (JCS)**. The signed value space is **constrained**: a payload **MUST**
contain only ASCII strings, integers, booleans, null, and nested objects/arrays of
the same. A value outside this space (a float, a non-ASCII string, raw bytes)
**MUST** be rejected — on both the sign and the verify paths — before any signature
is computed or checked. The constraint is what makes the encoding unambiguous: two
conformant implementations (this library and the `arp` receipt suite use the same
JCS library) produce byte-identical canonical bytes for every admissible payload,
so a signature is portable across them. Rejecting the rest is not a limitation but
the guarantee — an implementation cannot sign, or be made to accept, a value it
would canonicalize differently from a peer.

## 7. Signing
`signature = base64(Ed25519_sign(seed, canonical_json(payload)))`. `signed_by`
**MUST** be the `did:key` derived from the signing key's public key. The key that
signs the badge is the runtime's own key, so possession is the provenance.

## 8. Suite digest
`suite_digest = "sha256:" + hex(SHA-256(corpus))` where the corpus hash folds, in
sorted path order, each vector file's POSIX-relative path and bytes (NUL-delimited).
Any change to any vector changes the digest, invalidating prior badges. A verifier
**MAY** assert an expected digest to pin a badge to a known corpus.

## 9. Verification algorithm
A verifier **MUST**, in order: (1) confirm the four envelope members are present;
(2) parse `signed_by` to a 32-byte Ed25519 key (reject non-`did:key`); (3) base64-
decode `signature`; (4) verify the signature over `canonical_json(payload)`
(rejecting a payload outside the §6 value space before checking); (5) **validate the
envelope against the schema** (`conformance-envelope.schema.json`) — the schema is
load-bearing on the verify path, not merely a test-time check, so a malformed-but-
signed payload is rejected; (6) if an expected `suite_digest` was supplied, confirm
it matches; (7) if `total_vectors` is present, confirm `passed + failed + skipped +
xfailed + xpassed == total_vectors`, and if an expected total was supplied
(`--expected-total-vectors`), confirm `total_vectors` equals it; (8) unless
signature-only mode is requested, reject a payload recording `failed != 0` or
`exit_status != 0`. Schema validation (5) runs **after** signature verification (4):
the verifier authenticates the bytes, then enforces their structure. Each negative
vector in `tests/fixtures/` fixes the stage at which a malformed badge **MUST** fail.

## 10. Verifier output
On success the verifier reports the signer, runtime, versions, and counts, exit 0.
On failure it reports the failing stage, exit 1. Malformed input (not found / not
JSON) is exit 2.

## 11. Establishing trust (the ladder)
A self-signed badge is the bottom rung. For untrusted settings, trust is
established by one of: (a) **lab re-run** — a neutral party re-runs the suite and
signs the result; (b) **counter-signed** — the runtime signs, a lab signs the
runtime's envelope, both verifiable; (c) **attested CI** — the badge is produced
in a pipeline whose provenance attestation (SLSA, Sigstore, in-toto) the relying
party trusts. Registry admission **SHOULD** require one of these, not a bare
self-signature.

## 12. The counter-signed envelope (rung 2)

Rung 2 of the trust ladder (§11) — a neutral lab's counter-signature over a runtime's badge — has a normative wire format. A **counter-signed envelope** wraps a badge (§4) in a lab signature:

```json
{
  "payload": {
    "schema_version": 1,
    "badge": { "...": "a §4 badge envelope, verbatim" },
    "method": "lab-rerun"
  },
  "countersigned_by": "did:key:z...",
  "countersigned_at": "<rfc3339-utc>",
  "countersignature": "<base64 Ed25519 over canonical_json(payload)>"
}
```

The lab signs `canonical_json(payload)` (§6) with its own Ed25519 key. Because `method` and the entire inner `badge` sit inside the signed payload, neither can be altered without invalidating the counter-signature. `method` is normative:

- `lab-rerun` — the lab re-ran the conformance suite against the runtime's deployed surface and obtained the inner badge. The strongest attestation.
- `verified` — the lab confirmed the inner badge's signature and counts only, without re-running.

### 12.1 Verification

A verifier given a counter-signed envelope **MUST**:

1. Verify the inner `payload.badge` as a badge per §9 (the runtime's own signature). Reject if it fails.
2. Recover the lab public key from `countersigned_by` (`did:key`, §9.2) and verify `countersignature` over `canonical_json(payload)`. Reject if it fails.
3. Apply the pass-gate (§9.7) to the **inner** badge payload.

Like the badge's `signed_at`, `countersigned_at` sits outside the signed payload — attestation *freshness* (e.g. "re-run within 90 days") is therefore an out-of-band policy a relying party enforces, not a property the envelope carries.

Both signatures **MUST** verify. A relying party that trusts the `countersigned_by` lab thereby gains the lab's attestation that the inner badge is genuine — the assurance a self-signed badge cannot provide, and the rung registry admission requires for untrusted runtimes.



### 12.2 Admission gates

A verifier **SHOULD** let a relying party *require* rung 2: reject a badge that is not counter-signed, whose method is below a required minimum (`lab-rerun` > `verified`), or whose `countersigned_by` is not in a trusted-signer set. The reference verifier exposes `--require-countersigned`, `--require-method`, and `--trusted-signer` for this. This is how SPEC §11's "registry admission SHOULD require a rung" is mechanically enforced.

## 13. Test vectors
`tests/fixtures/` contains one positive and six negative golden vectors, each
self-declaring its `expected_outcome`. They are language-agnostic: a non-Python
verifier passes the same JSON files. They are deterministic — regenerated
byte-identically by `python -m sm_conformance._badge_vector_gen`.

## 14. Versioning
SemVer. A breaking change to the envelope/payload shape or signing input bumps the
major and `schema_version`; additive optional fields or extension keys bump minor;
clarifications bump patch.

## 15. References
RFC 8032 (Ed25519), RFC 8785 (JCS), FIPS 180-4 (SHA-256), W3C did:key method,
[Project NANDA](https://projectnanda.org).
