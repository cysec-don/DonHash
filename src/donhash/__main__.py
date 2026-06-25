"""Allow ``python -m donhash`` invocation."""

from __future__ import annotations

from donhash.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
