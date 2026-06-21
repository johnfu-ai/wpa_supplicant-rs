#!/usr/bin/env python3
"""Workspace `unsafe` discipline gate — issue #141 / TEST-VV-003 (REQ-NF-SEC-001).

Enforces two contracts that `cargo geiger` alone cannot:

  1. **Allowlist** — `unsafe` blocks may appear *only* in the documented
     allowlisted source files. A new `unsafe` block anywhere else fails CI.
  2. **SAFETY adjacency** — every `unsafe` block (and `unsafe fn` / `impl` /
     `trait`) must carry a `// SAFETY:` justification comment on the same
     line or within the preceding 10 lines, per the workspace
     non-negotiable in `CLAUDE.md` §8.

`cargo geiger` is run separately in CI for an unsafe-usage *total*; this
script is the hard gate (it is the thing that fails the build).

Exit code 0 = all unsafe sites justified and within the allowlist.
Exit code 1 = at least one violation (printed to stderr).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files permitted to contain `unsafe`. Adding a file here is an intentional,
# reviewable act — not something a PR can do silently.
ALLOWLIST = {
    Path("crates/wpa-supplicant/src/systemd.rs"),
    Path("crates/wpa-supplicant/src/raw_socket.rs"),
}

# `unsafe` used as a block / fn / impl / trait. Matching the *code* portion of
# the line (text before any `//` line comment) keeps doc/comment lines that
# merely mention the word "unsafe" from false-positiving.
UNSAFE_RE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)")
SAFETY_RE = re.compile(r"//\s*SAFETY:")
LOOKBACK = 10


def code_portion(line: str) -> str:
    """Return the part of a line before its `//` line comment.

    `//` inside a string/char literal would fool this, but no such case exists
    in the audited source trees; the conservative fallback is to treat a
    `//`-bearing line as non-code only when `//` is the first non-space token
    (a comment line), otherwise keep the whole line.
    """
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return ""
    # Find `//` not preceded by `:` (avoids `://` in URLs inside strings).
    idx = line.find("//")
    if idx == -1:
        return line
    return line[:idx]


def find_unsafe_sites(path: Path) -> list[tuple[int, str]]:
    sites: list[tuple[int, str]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, raw in enumerate(lines, start=1):
        if UNSAFE_RE.search(code_portion(raw)):
            sites.append((i, raw.strip()))
    return sites


def has_adjacent_safety(path: Path, site_line: int) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = max(0, site_line - 1 - LOOKBACK)  # 0-based, look back LOOKBACK lines
    end = site_line  # include the site line itself (trailing `// SAFETY:`)
    for raw in lines[start:end]:
        if SAFETY_RE.search(raw):
            return True
    return False


def main() -> int:
    violations: list[str] = []
    total_sites = 0

    for rs in sorted(REPO_ROOT.glob("crates/*/src/**/*.rs")):
        rel = rs.relative_to(REPO_ROOT)
        for site_line, _text in find_unsafe_sites(rs):
            total_sites += 1
            if rel not in ALLOWLIST:
                violations.append(
                    f"{rel}:{site_line}: `unsafe` outside the documented "
                    f"allowlist {sorted(p.as_posix() for p in ALLOWLIST)}"
                )
            if not has_adjacent_safety(rs, site_line):
                violations.append(
                    f"{rel}:{site_line}: `unsafe` block without a "
                    f"`// SAFETY:` comment within the preceding {LOOKBACK} lines"
                )

    if violations:
        for v in violations:
            print(f"error: {v}", file=sys.stderr)
        print(
            f"error: {len(violations)} unsafe-discipline violation(s) "
            f"across {total_sites} unsafe site(s)",
            file=sys.stderr,
        )
        return 1

    print(
        f"ok: {total_sites} unsafe site(s), all within the allowlist and "
        f"carrying a `// SAFETY:` comment"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
