# Publishing sm-conformance to PyPI

`sm-conformance` publishes via **PyPI Trusted Publishing** — no API tokens. PyPI
trusts this repo's `release.yml` workflow; pushing a version tag builds and
uploads automatically.

## One-time setup (the part only you can do)

1. PyPI account with 2FA → https://pypi.org/account/register/
2. https://pypi.org/manage/account/publishing/ → "Add a pending publisher".
3. Fill the form with **exactly**:

   | Field | Value |
   |-------|-------|
   | PyPI Project Name | `sm-conformance` |
   | Owner | `Sharathvc23` |
   | Repository name | `sm-conformance` |
   | **Workflow name** | `release.yml` |
   | Environment name | *(leave blank)* |

   > The **Workflow name must be `release.yml`** to match the file in this repo —
   > a mismatch makes the publish step fail with a trust error.

## Releasing

```bash
# version in pyproject.toml is the one that publishes; tag should match it
git tag v0.3.1
git push origin v0.3.1
```

The `release` workflow builds + `twine check`s + uploads over OIDC. Watch it
under the repo's **Actions** tab; within a minute `pip install sm-conformance`
works for everyone, and `sm-arp[conformance]` resolves against it.

## Notes
- Tag and `pyproject.toml` `version` should match.
- Dry run, no upload: `python -m build && python -m twine check dist/*`.
- TestPyPI trial: add a pending publisher on test.pypi.org and add
  `with: { repository-url: https://test.pypi.org/legacy/ }` to the publish step.
