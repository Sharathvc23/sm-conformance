"""``python -m sm_conformance badge.json`` — same as the ``sm-verify-badge`` script."""

from __future__ import annotations

import sys

from sm_conformance.cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
