# Performance

Copyright (c) 3rabDev - https://3rabdev.online

Design: stat-first gating, compiled patterns + cheap prefilter, candidate-scoped
entropy (<=512 chars), line streaming, sequential deterministic scan (no threads
in v0.1; `--jobs` only if future benchmarks prove a 2x win with identical findings).

## How to measure

```bash
python tools/gen_perf_corpus.py --size S --dest ./perf-corpus
secretsieve scan --no-color --verbose ./perf-corpus
```

Record: wall time, files/sec, MB/sec, `--verbose` stage behavior, plus the
adversarial members (1 MB single-line file, 200 empty files, deep nesting).
Report medians of repeated runs with machine + Python version. No marketing
claims in the README; numbers live here when measured.

## Bounds (tested, not promised)

- 5 MiB default file cap; 100 KiB line truncation; per-file candidate/finding caps; 10k total finding cap.
- Adversarial single-line and deep-tree cases are in `tests/integration/test_fs_edges.py` and must complete bounded.

## Measured (dev machine, Python 3.14, Windows)

Synthetic S-corpus from `tools/gen_perf_corpus.py --size S` (500 code files +
200 empty files + one 1 MB single-line file; ~5.5 MB total, 20 embedded
medium findings): **~1.3 s wall** for 701 files after the literal pre-gate +
file-flag hoisting optimization (was ~2.9 s before). Typical small projects
(<100 files) complete in well under a second. Method: warm runs, wall clock
from the CLI summary line. Re-measure on your hardware before quoting.
