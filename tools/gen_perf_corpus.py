"""Synthetic performance-corpus generator (PLAN Sec. 35).

Creates S/M/L/adversarial trees of fake-only content for benchmarking:

    python tools/gen_perf_corpus.py --size S --dest ./perf-corpus

All embedded "secrets" are synthetic fixtures (no sensitive material).
Measures: wall time, files/sec, MB/sec via the scanner's own stats.
"""

from __future__ import annotations

import argparse
import random
import string
import sys
import time
from pathlib import Path

SIZES = {
    "S": (500, 10),      # ~500 files / ~5 MB
    "M": (5000, 16),     # ~5k files
    "L": (20000, 20),    # ~20k files
}

FILLER = "def handler_{i}(request):\n    result = process(request, {n})\n    return result\n"
SECRET_LINE = 'API_TOKEN_{k} = "{v}"\n'


def _rand_token(rng: random.Random, n: int = 40) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def build(dest: Path, files: int, kb_per_file: int, secrets_every: int = 25, seed: int = 7) -> tuple[int, int]:
    rng = random.Random(seed)
    total_bytes = 0
    for i in range(files):
        sub = dest / f"pkg{i % 50}"
        sub.mkdir(parents=True, exist_ok=True)
        lines = [FILLER.format(i=i, n=j) for j in range(kb_per_file * 14)]
        if i % secrets_every == 0:
            lines.append(SECRET_LINE.format(k=i, v=_rand_token(rng)))
        blob = "".join(lines)
        (sub / f"mod{i}.py").write_text(blob, encoding="utf-8")
        total_bytes += len(blob.encode("utf-8"))
    # Adversarial members: one huge single-line file + many empty files.
    (dest / "huge_one_line.txt").write_text("x = '" + "A" * (1024 * 1024) + "'\n", encoding="utf-8")
    empty_dir = dest / "empties"
    empty_dir.mkdir(exist_ok=True)
    for i in range(200):
        (empty_dir / f"e{i}.txt").write_text("", encoding="utf-8")
    return files, total_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic SecretSieve perf corpus.")
    parser.add_argument("--size", choices=("S", "M", "L"), default="S")
    parser.add_argument("--dest", default="./perf-corpus")
    args = parser.parse_args(argv)
    files, _kb = SIZES[args.size]
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    nfiles, nbytes = build(dest, files, _kb)
    took = time.perf_counter() - start
    print(f"wrote {nfiles} files ({nbytes / 1e6:.1f} MB) to {dest} in {took:.2f}s")
    print("Benchmark with: secretsieve scan --no-color --verbose " + str(dest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
