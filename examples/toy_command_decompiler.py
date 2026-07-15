"""Tiny command-backend example for framework fixtures, not a real decompiler."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assembly", type=Path, required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.assembly.read_text(encoding="utf-8").strip():
        return 2
    args.output.write_text(f"int {args.function}(void) {{ return 0; }}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

