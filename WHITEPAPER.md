# sm-conformance: Mechanical Compliance for the Internet of AI Agents

*Personal research contribution by [Stellarminds.ai](https://stellarminds.ai), aligned with [Project NANDA](https://projectnanda.org) standards.*

---

## Abstract

The Conformance Badge is a verification primitive for open agent protocols: a small, signed, machine-checkable record that a runtime passed a specific conformance suite — naming which suite (pinned by a digest over its vector corpus), which protocol versions, who produced the run, and the pass/fail counts. The badge is signed by the runtime's own Ed25519 key and re-verifiable offline by anyone holding the runtime's `did:key`, with no service on the path. `sm-conformance` is the reference implementation of that badge — the mechanism every Protocol in the portfolio uses to turn "passed the tests" into portable proof.

This whitepaper makes the case that conformance attestation is a primitive in its own right, separable from the protocols it checks, and that a generic, signed, offline-verifiable badge is the right shape for it. The envelope, canonical encoding, signing, suite-digest, and verification algorithm are documented in [`SPEC.md`](./SPEC.md) as a working draft. This document covers motivation, design choices, and composition.

---

## 1. Problem

Open agent protocols only work if compliance is *checkable*. The moment runtimes are built by different people, in different languages, and operated by organizations that have never met, someone has to answer a hard question before trusting one: *does this runtime actually implement the protocol, or does it just claim to?*

That question is asked at concrete chokepoints:

- A **registry** decides whether to admit a runtime to a federation other agents will route to.
- A **vendor** onboards a third-party agent into a workflow that moves money, files records, or touches infrastructure.
- A **regulator** or **auditor** asks, after the fact, whether a deployed runtime was ever actually conformant — and against which version of the rules.

The default answer today is *trust me*. It breaks down on every axis:

- **Claims are unfalsifiable.** A README asserts compliance; a logo implies it. Neither can be checked. The party relying on the claim has no way to confirm it without asking the claimant's permission.
- **Prose and implementation drift silently.** A specification and the code that claims to honor it diverge over time until something breaks in production. Nothing catches the divergence at the moment it happens.
- **Where a check exists, it depends on a service.** A hosted "verify" endpoint or a proprietary verifier cannot cross an organizational boundary at internet scale — the relying party would have to trust the very service it is trying to hold accountable.
- **Claims don't say what was checked.** "Conformant" with no named test corpus is meaningless: a runtime can pass a weak, outdated suite and assert the same word as one that passes the current one.

For runtimes to interoperate at scale under any consequential protocol, relying parties need a different artefact: a **per-run, cryptographically-bound, corpus-pinned, offline-verifiable badge** — proof a party can re-check itself, with nothing but public information. That artefact is the Conformance Badge.

## 2. The Conformance-Badge Primitive

A badge binds five facts about one run of a conformance suite into a single signed envelope:

| Fact | Field(s) | Notes |
|---|---|---|
| **Which suite** was run | `suite_digest` | SHA-256 over the vector corpus — change one vector, the digest changes |
| **Which protocol versions** | `protocol_versions` | e.g. `["0.2", "0.3"]` |
| **Who produced** the run | `signed_by` (did:key) + `signature` | the runtime's own Ed25519 key; possession is the provenance |
| **What the result was** | `passed` / `failed` / `skipped` / `xfailed` / `xpassed`, `exit_status` | the counts the signature commits to |
| **When** it completed | `completed_at`, `signed_at` | RFC 3339 UTC |

The envelope is plain JSON: a `payload` carrying those facts, plus `signed_by`, `signed_at`, and a `signature` over the canonical encoding of the payload. The wire format is documented in [`SPEC.md`](./SPEC.md) §4–§8.

A badge is intentionally protocol-neutral. It applies anywhere a runtime claims to implement a versioned protocol and a third party needs to check that claim — agent registries, vendor onboarding gates, regulator audit trails, downstream-agent capability negotiation, and any other setting where *"did this runtime really pass, and against what"* is a question worth answering.

## 3. Why Conformance Is a Separate Primitive

The natural reaction to "every protocol ships a conformance suite" is to assume each protocol also bakes its own badge format and verifier. The argument against that conflation:

- **The mechanism is identical across protocols.** Signing a run result, canonicalizing it deterministically, pinning it to a corpus digest, and verifying the signature against a `did:key` — none of this is protocol-specific. ARP, AAE, and `sm-locp` would each re-implement byte-for-byte the same envelope. Duplicating a shared mechanism inside each consumer forks a standard that should be one thing.
- **One mechanism, many protocols.** A single badge format lets a registry verify badges from any protocol with one verifier, and lets a runtime that implements several protocols ship one kind of artefact. The protocols supply vectors and criteria; they should not each ship a verifier.
- **Verification ages independently.** The badge envelope is anchored to a small, slow-moving set of primitives — Ed25519, canonical JSON, SHA-256, `did:key`. Individual protocols version on their own, faster cadence. Separating them lets each move at its natural speed.

So: conformance is a primitive because the attestation mechanism is generic, cross-cutting, and has its own lifecycle — distinct from any one protocol it attests.

## 4. Design Axioms

`sm-conformance` is built on four axioms. They are not preferences; they are load-bearing for the badge to compose with the rest of the portfolio.

### 4.1 Compliance is an exit code, not a claim

A runtime is conformant if and only if a mechanical suite passes against it. Everything else — a README, a logo, a vendor's assurance — is commentary.

Consequence: the badge records a *run*, not an *assertion*. It carries the counts and the exit status the suite actually produced, signed, so a reader checks the outcome rather than trusting a sentence.

### 4.2 Verifiable offline, by anyone

Verification needs only public information — the runtime's `did:key`, embedded in the badge — and standard cryptography. No hosted endpoint, no proprietary library, no service on the path.

Consequence: a relying party that has never contacted the runtime, the registry, or the author can confirm the badge unforged. That is what lets the badge cross organizational boundaries at scale.

### 4.3 Pin what was checked

A badge that does not name its corpus proves nothing. The `suite_digest` is a SHA-256 over the vector corpus; any change to any vector changes the digest and invalidates prior badges.

Consequence: "conformant" stops being a floating word. A registry publishes the digest of the canonical suite at each release and rejects badges that do not pin to it — no passing a weaker, superseded corpus and claiming the same status.

### 4.4 Honest about trust

A self-signed badge is a *claim* by the holder of a key, not *proof* a run happened. Nothing prevents a key holder from hand-authoring a payload with chosen counts and signing it.

Consequence: the badge spec states this boundary explicitly and defines a trust ladder (§5) for the cases where a self-signature is not enough. The primitive does not pretend a self-signature is more than it is.

## 5. The Trust Ladder

A self-signed badge proves authorship and asserts a claim; on its own it does not establish that the run actually happened or that the counts are accurate. For untrusted settings, trust climbs a ladder:

| Rung | What it adds |
|---|---|
| **Self-signed** | A claim by the holder of the signing key — "I ran the suite, these are the counts." |
| **Lab counter-signed** | A neutral party re-runs the suite (or verifies the run) and signs an envelope wrapping the runtime's badge. Both signatures verify; the relying party trusts the counter-signer. |
| **Attested CI** | The badge is produced inside a build pipeline whose provenance attestation (SLSA, Sigstore, in-toto) the relying party trusts. Authenticity derives from the pipeline, not the runtime's self-signature. |

The verifier confirms only the cryptographic contract — signature valid, payload unaltered, digest as expected, pass-gate met. The *social* trust that a run happened is established by the upper rungs. A registry that admits self-signed badges without one of them is making a claim the badge does not substantiate; admission should require lab re-run, counter-signature, or attested CI.

## 6. Where This Fits

The portfolio organizes into four trust tiers, each aligned with a Project NANDA pillar. `sm-conformance` is **orthogonal to all of them** — not a tier, but the substrate that lets any tier prove it is honestly implemented:

```
  +-----------------------------------------------------------+      +-----------------+
  |                    OPERATOR SURFACES                      |      |                 |
  |   sm-attest-viewer · sm-decision-inspector ·             |      |                 |
  |   sm-attest-auditor                                       |      |                 |
  +--------------------------- ↑ AAE envelopes ---------------+      |  sm-conformance |
  |                      BEHAVIORAL TRUST                     |  ←   |                 |
  |   sm-locp (emits AAEs) · sm-airlock · sm-enclave          |      |  every Protocol |
  +-----------------------------------------------------------+      |  defines its    |
  |                         MODEL TRUST                       |  ←   |  own vectors;   |
  |   sm-model-provenance · sm-model-card ·                   |      |  this turns     |
  |   sm-model-integrity-layer · sm-model-governance          |      |  "passed them"  |
  +-----------------------------------------------------------+      |  into a signed, |
  |                         FEDERATION                        |  ←   |  offline-       |
  |   sm-bridge — registry endpoints, Quilt delta sync        |      |  verifiable     |
  +-----------------------------------------------------------+      |  badge          |
                                                                     +-----------------+
```

Every Protocol in the portfolio defines what its vectors are and what passing means. `sm-conformance` is the single mechanism that turns "passed the vectors" into a badge a registry can demand and any party can re-verify. That is what makes federation of independently-built runtimes possible without a central gatekeeper: the test suite is the gate, and the badge is the portable proof a runtime cleared it.

## 7. Composition With Sister Primitives

The handoffs are well-defined. A Protocol supplies the vectors; `sm-conformance` produces the badge; a relying party consumes it.

| Producer | Output | Consumer |
|---|---|---|
| any Protocol (`arp`, AAE, `sm-locp`) | vectors + conformance criteria | the runtime under test, which runs them |
| the runtime under test | a signed `.nanda/conformance.json` badge via `sm-conformance` | a registry, vendor gate, or regulator |
| a neutral lab / attested CI | a counter-signed or pipeline-attested badge | a registry admitting the runtime to a federation |

`arp` (the Agency Receipt Protocol) is the first consumer: it defines its receipt vectors and conformance criteria, then points at `sm-conformance` for the badge rather than minting its own. Any future Protocol consumes it the same way.

## 8. NANDA Alignment

[Project NANDA](https://projectnanda.org) defines four pillars the open Internet of Agents must solve: **DNS** (discovery), **CA** (decentralized identity), **Orchestration** (dynamic routing), and **Attestation** (verifiable evidence). The trust those pillars promise is only real if the runtimes implementing them are *actually* conformant — and that is not something the pillars check for themselves.

`sm-conformance` is the mechanical check beneath them. A registry implementing the DNS pillar should not admit a runtime on a free-text claim; it should demand a verifiable badge. A federation built on the CA pillar's decentralized identities still needs to know those identities belong to conformant runtimes. Conformance is what turns "this runtime says it speaks the protocol" into "this runtime proved it" — the precondition for trusting any pillar across an organizational boundary.

## 9. Future Work

Items deferred from v0.1, in rough priority order:

1. **Attested-CI tooling.** Counter-signature (rung 2) ships — `counter_sign` / `verify_countersigned`, with the normative envelope in SPEC.md §12. Reference tooling for the attested-CI rung (SLSA, Sigstore) is the next slice.
2. **A conformance registry.** A registry at `labs.stellarminds.ai/conformance` whose admission is gated on a lab re-run, counter-signed badge, or trusted CI attestation — never a bare self-signature.
3. **Multi-language reference verifiers.** The vectors are language-agnostic; reference verifiers in TypeScript, Go, and Rust would let non-Python runtimes verify badges natively.

The canonical encoding is RFC 8785 (JCS) over a constrained value space, and schema validation is load-bearing on the verify path (SPEC.md §6, §9) — both shipped in v0.1.

## 10. Related Packages

| Package | Role |
|---|---|
| [`arp`](https://github.com/Sharathvc23/sm-arp) | Agency Receipt Protocol — first consumer; defines receipt vectors, points here for its badge |
| [`sm-locp`](https://github.com/Sharathvc23/sm-locp) | Open Compliance Protocol — defeasible-logic engine + W3C VC issuance. Defines its own vectors. |
| [`sm-attest-viewer`](https://github.com/Sharathvc23/sm-attest-viewer) | Reference renderer for AAE action-envelope streams. |
| [`sm-bridge`](https://github.com/Sharathvc23/sm-bridge) | NANDA-compatible registry endpoints + Quilt delta sync — a natural consumer of badges at admission. |

---

*First published: 2026-05-31 | Last modified: 2026-05-31*

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
