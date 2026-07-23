#!/usr/bin/env python3
from __future__ import annotations

import gzip
import sys
from pathlib import Path

TEXT_EXTS = {".html", ".css", ".js", ".svg", ".webmanifest"}


def compress_file(path: Path) -> int:
    data = path.read_bytes()
    out = path.with_suffix(path.suffix + ".gz")
    with gzip.open(out, "wb", compresslevel=9) as fh:
        fh.write(data)
    return len(data)


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    if not root.exists():
        print(f"missing directory: {root}", file=sys.stderr)
        return 1

    total = 0
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in TEXT_EXTS:
            continue
        total += compress_file(path)
        count += 1

    print(f"optimized {count} static assets under {root} ({total} bytes source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
