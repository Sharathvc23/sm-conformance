# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| The signed badge envelope: build, sign, suite-digest pin, verify, CLI, schemas, vectors. | A specific protocol's tests / vectors / adapter; transport and publication of badges; the counter-sign and attested-CI tooling (tracked for v0.2). |

The primitive owns one thing. Anything outside the table belongs to a companion
package or the consumer's stack.

## Versioning

Semantic Versioning 2.0.0. The protocol surface (wire shape / algorithm) is
frozen within a major. A change to it requires an RFC-style PR to `SPEC.md`
before code.

## Conformance

The test suite under `tests/` (and any vectors it loads) is the authoritative
behavioural specification. A change in behaviour without a corresponding test
change is a bug.

## Contributions

- PRs must include tests and pass `ruff` + `mypy --strict` + `pytest`.
- No expansion of the protocol surface without an accepted RFC.
- No domain-specific or deployment-specific content — this is a generic
  primitive (see the neutrality checklist in the extraction playbook).
- Sign off with the Developer Certificate of Origin (DCO), not a CLA.

## Attribution

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
