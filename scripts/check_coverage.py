#!/usr/bin/env python3
"""Per-crate coverage gate — issue #139 / TEST-VV-001 (REQ-NF-MNT-001).

Parses an lcov.info produced by `cargo llvm-cov --workspace --lcov`,
aggregates line coverage **per crate**, and fails CI if any crate falls
below its configured threshold (80 % by default, per REQ-NF-MNT-001).

Per-crate (not workspace-total) gating is the point: a single
high-coverage crate must not mask a low-coverage one. Thresholds live in
`THRESHOLDS` below so a temporary lower bound for a crate under active
build-out (e.g. one waiting on #133 / #137) is an explicit, reviewable
exception rather than a silent slackening.

Usage: ``python3 scripts/check_coverage.py path/to/lcov.info``

Exit 0 = every crate at/above its threshold. Exit 1 = at least one below.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

# Per-crate line-coverage floor, in percent. Default 80 per REQ-NF-MNT-001.
# Crates not listed default to `DEFAULT_THRESHOLD`.
DEFAULT_THRESHOLD = 80.0
THRESHOLDS: dict[str, float] = {
    "pae": 80.0,
    "eapol-supp": 80.0,
    "eap-peer": 80.0,
    "logon": 80.0,
    "wpa-supplicant": 80.0,
}

# SF paths look like .../crates/<crate>/src/<file>.rs — pull the crate name.
CRATE_RE = re.compile(r"/crates/([^/]+)/")


def parse_lcov(path: Path) -> dict[str, tuple[int, int]]:
    """Return ``{crate: (lines_found, lines_hit)}`` aggregated from lcov."""
    found: dict[str, int] = defaultdict(int)
    hit: dict[str, int] = defaultdict(int)
    current_crate: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            m = CRATE_RE.search(line)
            current_crate = m.group(1) if m else None
        elif line.startswith("LF:") and current_crate:
            found[current_crate] += int(line[3:])
        elif line.startswith("LH:") and current_crate:
            hit[current_crate] += int(line[3:])
        elif line == "end_of_record":
            current_crate = None
    return {c: (found[c], hit[c]) for c in found}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <lcov.info>", file=sys.stderr)
        return 2
    lcov = Path(argv[1])
    if not lcov.is_file():
        print(f"error: lcov report not found: {lcov}", file=sys.stderr)
        return 2

    per_crate = parse_lcov(lcov)
    if not per_crate:
        print("error: no coverage records parsed from lcov report", file=sys.stderr)
        return 2

    failed: list[str] = []
    print(f"{'crate':<18}{'lines':>10}{'covered':>10}{'pct':>10}{'floor':>8}  result")
    print("-" * 62)
    for crate in sorted(per_crate):
        lf, lh = per_crate[crate]
        pct = (lh / lf * 100.0) if lf else 0.0
        floor = THRESHOLDS.get(crate, DEFAULT_THRESHOLD)
        ok = pct >= floor
        if not ok:
            failed.append(crate)
        print(
            f"{crate:<18}{lf:>10}{lh:>10}{pct:>9.2f}%{floor:>7.0f}%  "
            f"{'PASS' if ok else 'FAIL'}"
        )

    if failed:
        print(
            f"\nerror: {len(failed)} crate(s) below the 80 % line-coverage floor: "
            f"{', '.join(failed)}",
            file=sys.stderr,
        )
        return 1

    print("\nok: every crate meets its line-coverage floor")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
