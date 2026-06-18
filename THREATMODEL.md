# Threat Model — sm-conformance

This document states what an `sm-conformance` badge *does* and *does not* prove, the
adversaries it defends against, and the residual risks a relying party (RP) must
handle itself. It complements `SPEC.md` (the normative protocol) and is written for
implementers building or consuming badges.

## 1. The organizing idea

A rung-1 badge cryptographically binds a **conformance claim to a key** — not to
reality. A valid signature proves only:

> "the holder of key `K` asserts that runtime `R` ran suite `S` and produced these
> counts at time `completed_at`."

It does **not** prove the run happened, was honest, or is still true. **Every threat
below is a variation on closing the gap between "`K` signed this claim" and "`R`
actually conforms."** Read the whole model through that lens.

## 2. Assets, trusted base, trust boundaries

**Assets**
- Integrity of a conformance claim (which suite a runtime passed, with which counts).
- The signer ↔ runtime identity binding (the `did:key`).
- The relying party's trust decision that consumes the badge.

**Trusted computing base (TCB)** — security reduces to the correctness of:
- the Ed25519 implementation,
- the **JCS canonicalization** (RFC 8785) used to compute the signed bytes,
- the JSON Schema validator (with `additionalProperties: false`),
- and the RP's out-of-band mapping of `suite_digest → "what this suite means"`.

Every new language port of the verifier *joins* this TCB. Verification itself needs
**no network, no PKI, and no transparency log** — a deliberate design choice
(`SPEC.md` §2: "why not Sigstore / in-toto / cosign").

**Trust boundary:** everything outside the *signed payload* is forgeable. In
particular `signed_at` and `countersigned_at` sit outside the signature and a holder
can set them to anything (`SPEC.md` §12.1). Only fields inside the signed payload —
notably `completed_at` — carry signed meaning.

## 3. Adversaries

- **Dishonest runtime** — wants unearned conformance (forge, substitute, skip, replay).
- **Relay / man-in-the-middle** — wants to replay or swap a badge in transit.
- **Malicious or lazy rung-2 lab** — over-attests, or stamps without re-checking.

## 4. Threats

Ordered roughly cheapest-first.

| # | Attack | Defended by | Residual risk |
|---|---|---|---|
| **T1** | **Self-attestation.** Anyone mints a `did:key` and signs `passed:50, failed:0`. | rung-2 lab counter-signature; out-of-band reputation of `K` | a rung-1 badge *alone* proves nothing about reality — trusting it equals trusting a stranger's self-report |
| **T2** | **"Verifies ≠ passed."** `verify_envelope` checks signature + schema, **not** the run result; a `failed:99` badge is a *valid* badge. | RP gates `failed / exit_status / errored / xfailed == 0` | a silent footgun: any RP that treats "verified" as "conformant" is fooled |
| **T3** | **Weak-suite substitution.** Pass a trivial suite and present it as the real one. | pin `expected_suite_digest`; pin `code_digest` (`--expected-code-digest`) to defend a suite that "tests nothing" | the `digest → meaning` map must be known to the RP out of band |
| **T4** | **Skip the adversarial vectors.** Report high `passed` while quietly `skipped`-ing the hard ones. | `skipped_vectors` + `total_vectors` completeness + skip policy (`--max-skipped`, `--forbid-skip`, `--require-skip-ids`) | only bites if the RP enforces the policy *and* knows the expected total |
| **T5** | **Replay / regression / time-lying.** A static badge is re-presented after `R` regresses; or the runtime back-dates / **forward-dates** `completed_at`. | freshness bound on the **signed** `completed_at`; clock-skew guard (reject future timestamps); prefer a `lab-rerun` countersignature for recency | **fundamental, not merely residual:** `completed_at` is self-asserted — the runtime stamps its own clock. Only a `lab-rerun`'s independent timestamp constrains it. There is **no revocation** to pull a known-bad badge (see T6). |
| **T6** | **Key compromise / rotation.** A leaked seed lets an attacker mint badges as `R`; and after a legitimate rotation, badges from the *old* key remain cryptographically valid for their `completed_at` window. | custody discipline; rotate keys; RP tracks the runtime's **key history** | **no in-protocol revocation/CRL.** RPs must decide a grandfathering policy (accept old-key badges within their freshness window vs. hard-cut at the rotation time). RPs on stale key lists stay exposed. |
| **T7** | **Rung-2 over-attestation.** A lab counter-signs without gating, or `method:"verified"` is misread as a re-run. | lab must apply the same admission gates before stamping; RP must know what a given lab's stamp *means* | trust in rung-2 = trust in that lab's key **and** its policy; `"verified"` carries **no fresh signed timestamp** beyond the inner `completed_at` |
| **T8** | **Canonicalization divergence.** Two verifiers canonicalize differently → a payload that verifies-and-means differently across implementations. | shared cross-language JCS vectors (authoring them caught a real non-ASCII-key bug in 0.3.0); strict schema | every new language port is new TCB surface |
| **T9** | **Equivocation / split view.** With no transparency log, a signer can hand *different* badges to *different* parties with no globally detectable inconsistency. | *by design* — offline, no log/PKI on the path | accept it, or layer a transparency log above as **rung-3** (see §6) |
| **T10** | **Stale suite version (refinement of T3).** A suite is later patched (bugs fixed, vectors added); an old `suite_digest`/`code_digest` from the **weaker** version is still a valid pin, so an RP pinning only a digest can be satisfied by a known-deficient suite. | RP enforces a **minimum suite version** (a `digest → semver` map, or an optional `suite_semver` field — see §7) alongside the digest | requires the RP to maintain version metadata the bare digest does not carry |

## 5. Explicit non-goals

Stated so they read as scope, not gaps:

- **Confidentiality** — badges are public.
- **Suite quality** — `code_digest` proves *which* test code ran, not that the suite is
  *good*; a vacuous suite that passes is meaningless.
- **Anti-cheating inside the runtime** — a runtime that mocks or stubs its own suite.
- **Revocation / expiry** of an issued credential.
- **Global non-equivocation** (see T9 / §6).

## 6. Trust rungs (and the roadmap)

The protocol is a **ladder of escalating trust**, and naming the rungs makes the
residual risks deliberate rather than open holes:

- **Rung 1 — self-attestation.** The runtime signs its own badge. Cheapest; proves
  only key-holding (T1).
- **Rung 2 — lab counter-signature.** An independent lab re-attests. `method:"verified"`
  = the lab re-checked the signature + counts; `method:"lab-rerun"` = the lab actually
  re-ran the suite and re-stamped a recent run (the only method that strengthens
  freshness). Trust here is trust in the lab's key and policy (T7).
- **Rung 3 — transparency log (roadmap).** A **Sigstore-style append-only log** layered
  above the base would give global non-equivocation and a public, monitorable record of
  issuance — closing T9. It is intentionally *not* in the base (which must verify offline
  with no log on the path), but composes cleanly as a higher rung.

## 7. Relying-party checklist

The practical distillation. The Town Notary
(<https://github.com/Sharathvc23/town-notary>) implements steps 1–6 server-side and is a
working reference for consuming these badges.

1. **Verify** signature + schema with `verify_envelope` / `verify_countersigned`.
2. **Gate the result:** require `failed == 0`, `exit_status == 0`, `errored == 0`,
   `xfailed == 0`. (Verification ≠ conformance — T2.)
3. **Pin the suite:** require `suite_digest == expected`, ideally also `code_digest`
   (`--expected-code-digest`), **and a minimum suite version** so a patched/strengthened
   suite is not satisfied by an old weaker digest (T3, T10). If the badge carries no
   version, maintain a `digest → semver` map; protocol-side, an optional `suite_semver`
   field (e.g. under `extensions`) lets RPs gate "at least version X" directly.
4. **Enforce coverage:** apply the skip policy (`--max-skipped` / `--forbid-skip` /
   `--require-skip-ids`) and check `total_vectors` completeness (T4).
5. **Bind identity:** pin the signer `did:key` to a known runtime **or** require a rung-2
   stamp from a lab you trust (T1, T7). **Track key history** and choose a grandfathering
   policy for badges whose `completed_at` predates a key rotation (T6).
6. **Establish recency (strongest signal first):**
   - **Preferred:** require a rung-2 `method:"lab-rerun"` — an independently timestamped
     re-run is a stronger freshness guarantee than any self-asserted age check.
   - **Otherwise:** bound the age of the **signed** `completed_at` (`--max-age-days`),
     **and** reject any badge whose `completed_at` is more than a small skew (e.g. a few
     minutes) **in the future**, defending against forward-dated badges as well as stale
     ones (T5). Never gate freshness on the unsigned `countersigned_at` (`SPEC.md` §12.1).

> Steps 1–4 are local and cheap; step 5 is where policy and out-of-band knowledge enter;
> step 6 is where most implementers under-reach — prefer a `lab-rerun` over a bare
> timestamp check.
