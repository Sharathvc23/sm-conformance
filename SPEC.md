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

**Why not Sigstore / in-toto / cosign?** Those are excellent for software *supply-chain*
provenance — "this artifact was built from this source in this pipeline" — and a
conformance badge composes *under* them (a `lab-rerun` counter-signature can itself be
produced in an attested CI pipeline; SPEC §11 rung 3). But the badge's job is narrower
and its constraints are different: it answers "did *this runtime* pass *this suite*,"
and it must be verifiable by **anyone, fully offline, in any language, with no service
on the path**. Sigstore presumes a transparency log and Fulcio/OIDC PKI; in-toto
presumes a layout-and-functionary model; both pull in dependencies and online trust
roots a relying party at internet scale cannot assume. The badge deliberately bottoms
out on four primitives a 200-line verifier reimplements in any language — Ed25519,
canonical JSON, SHA-256, `did:key` — with **possession of the key as the only trust
root** and the trust ladder (§11) layering lab/CI attestation on top when more is
needed. Decentralized, dependency-light verification is the requirement that rules the
heavier toolchains out as the *base* layer, not as composable rungs above it.

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

### 3.2 Publishing the badge
A runtime ships its badge on disk at `.nanda/conformance.json` (the convention a
repository, registry crawler, or CI artifact looks for). A runtime that also serves
it over HTTP **SHOULD** do so at the canonical URL **`/.well-known/conformance.json`**
— **unauthenticated**, since the badge is verifiable offline by anyone against the
embedded `did:key`, and gating a public proof behind authentication defeats its
purpose. A runtime **SHOULD** advertise that URL from its discovery document (e.g. a
`conformance` field in `/.well-known/nanda-agent.json`) so a relying party reaches
it in one hop. The on-disk path and the served URL are distinct concerns: the file
is where the artifact lives, `.well-known/` is where discovery metadata is fetched.

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
`adapter` (string), `total_vectors` (non-negative int), `errored` (non-negative
int), `skipped_vectors`, and `extensions` (object).
`extensions` keys **MUST** be namespace-prefixed (`<domain>.<sub>.<field>`). A
verifier **MUST** preserve and **MUST NOT** fail on unrecognised extension keys,
and is **not required** to interpret them. New extension keys **MAY** ship without
bumping `schema_version`.

`errored` is the count of tests that **errored** — a setup or teardown failure that
prevented the test body from running — as distinct from a test that ran and
`failed`. A run with `errored > 0` did not actually exercise that part of the
corpus, so a verifier **MUST** treat it as non-passing (rejected unless
`--allow-failures`), exactly like `failed > 0`. When present it also counts toward
the completeness sum below, so an error cannot silently shrink the executed corpus.

`total_vectors` is the count of vectors the run should have executed. When present,
the counts **MUST** be complete: `passed + failed + skipped + xfailed + xpassed +
errored == total_vectors`. **This is self-attested** — a runtime that ran a subset can report a
matching smaller `total_vectors` and satisfy the equality. It therefore catches an
*honest* partial run, not a dishonest one. The transferable guarantee is §9's
`--expected-total-vectors`, where the count a verifier compares against comes from
what it independently knows for the `suite_digest`, not from the runtime. Closing
*count* fabrication against an adversarial signer is what rung-2 lab-rerun (§11)
is for — but a re-run reproduces a capability-gated **skip**, so lab-rerun does
**not** close coverage gaps; that is what `skipped_vectors` + a skip policy below
are for.

`skipped_vectors` (array of unique non-empty strings) is the **identity** of the
skipped vectors. The bare `skipped` count is insufficient: a runtime can skip the
one adversarial vector it would fail and still satisfy the `total_vectors`
accounting and `failed == 0`. When `skipped > 0` a producer **SHOULD** enumerate
`skipped_vectors` (length equal to `skipped`), and a relying party gates on it
(§9: `--max-skipped`, `--forbid-skip`, `--require-skip-ids`).

`extensions.conformance.run.build` (string) records **which build** of the runtime
was tested — a commit SHA, image digest, or version. `suite_digest` pins the *suite
corpus*, not the runtime, so without this an auditor cannot answer "which build
passed?" and a regressed redeploy keeps verifying on the old badge. A relying party
asserts it with `--expected-build`.

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
`signature = base64(Ed25519_sign(seed, canonical_json(payload)))`, where `base64`
is **standard** base64 (RFC 4648 §4, the `+`/`/` alphabet with `=` padding) — **not**
url-safe (§4 of 4648, not §5). `signed_by` **MUST** be the `did:key` derived from the
signing key's public key. The key that signs the badge is the runtime's own key, so
possession is the provenance.

## 8. Suite digest
`suite_digest = "sha256:" + hex(SHA-256(corpus))` where the corpus hash folds each
`*.json` vector file's POSIX-relative path and raw bytes (NUL-delimited). For
cross-platform reproducibility three things are **normative**: (a) files are sorted
on their **POSIX-relative-path string** (not on platform-dependent path objects);
(b) the corpus is **`*.json` only**; (c) vector bytes **MUST** be checked out with
LF line endings (ship a `.gitattributes` pinning `*.json text eol=lf`, or a CRLF
checkout forks the digest). Any change to any vector changes the digest, invalidating
prior badges. A verifier **MAY** assert an expected digest to pin a badge to a known
corpus.

> **Scope (load-bearing).** The digest pins the *vector corpus*. For a suite whose
> pass/fail is **vector-driven** (e.g. the client signing suite) it pins what was
> checked. For a suite that is **behavioral code** (e.g. an HTTP server suite whose
> assertions live in test modules, not vectors), the digest does **not** pin the
> deciding code — two revisions of those tests yield the same digest. Such a suite
> **SHOULD** carry a signed **`conformance.suite.code_digest`** extension —
> `compute_code_digest(root)` hashes the test modules with the same byte-stable
> scheme — and a relying party pins it with `--expected-code-digest` (§9). Until a
> badge carries it, corpus-pinning is inert for that suite and a relying party
> **MUST NOT** treat the digest alone as proof of *what behavior* was checked.

## 9. Verification algorithm
A verifier **MUST**, in order: (1) confirm the four envelope members are present;
(2) parse `signed_by` to a 32-byte Ed25519 key (reject non-`did:key`); (3) base64-
decode `signature`; (4) verify the signature over `canonical_json(payload)`
(rejecting a payload outside the §6 value space before checking); (5) **validate the
envelope against the schema** (`conformance-envelope.schema.json`) — the schema is
load-bearing on the verify path, not merely a test-time check, so a malformed-but-
signed payload is rejected; (6) if an expected `suite_digest` was supplied, confirm
it matches; (7) if `total_vectors` is present, confirm `passed + failed + skipped +
xfailed + xpassed + errored == total_vectors`, and if an expected total was supplied
(`--expected-total-vectors`), confirm `total_vectors` equals it; (8) apply the skip
policy — fail if `skipped > --max-skipped`, if any `--forbid-skip` ID is in
`skipped_vectors`, or (with `--require-skip-ids`) if `skipped > 0` without
`skipped_vectors`; (9) if `--expected-build` was supplied, confirm
`extensions.conformance.run.build` equals it; (10) if `--max-age-days` was supplied,
confirm the **signed `completed_at`** (never the unsigned `countersigned_at`, §12.1)
is within the bound; (11) unless signature-only mode is requested, reject a payload
recording `failed != 0`, `exit_status != 0`, `xfailed != 0`, or `errored != 0`.
Schema validation (5) runs **after**
signature verification (4): the verifier authenticates the bytes, then enforces their
structure. Each negative vector in `tests/fixtures/` fixes the stage at which a
malformed badge **MUST** fail.

### 9.1 Locked-down invocation
For registry admission of an untrusted runtime, all gates **SHOULD** be on at once —
pin the corpus *and* the count, demand skip identities and bound them, pin the build,
bound freshness, and require a lab counter-signature:

```
sm-verify-badge badge.json \
  --expected-suite-digest sha256:<known> --expected-total-vectors <N> \
  --require-skip-ids --max-skipped <K> --forbid-skip <id> \
  --expected-build <sha> --max-age-days 90 \
  --require-countersigned --require-method lab-rerun --trusted-signer did:key:z<lab>
```

A self-signed badge with only `--expected-suite-digest` is **non-repudiation + a
stable reference**, not proof a run happened (§3, §11).

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

Like the badge's `signed_at`, `countersigned_at` sits outside the signed payload, so it is **forgeable**: a holder can set it to any value without invalidating the countersignature. A relying party **MUST NOT** gate freshness on `countersigned_at`. Freshness, if required, **MUST** be taken from a **signed** timestamp — the inner badge's `completed_at` (which `verify_countersigned` returns and `--max-age-days` reads). Note that a `method: "verified"` counter-sign (the lab confirmed the inner signature and counts without re-running) carries **no fresh signed timestamp of its own** beyond that inner `completed_at`, so it cannot support a freshness claim newer than the original run; only `lab-rerun` re-stamps a recent run.

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
