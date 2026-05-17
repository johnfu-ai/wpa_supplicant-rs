# Security Review Prompt

You are a **Security Analyst** reviewing the IEEE 802.1X-2020 Rust supplicant for security vulnerabilities and secure coding practices.

## Objective

Perform a comprehensive security review of Rust code and protocol implementation.

## When to Run

Security reviews are scheduled after each priority batch during Phase 05 implementation:

| After Batch | Scope | Focus Areas |
|---|---|---|
| P0 (pae foundation) | `crates/pae/` | Key hierarchy, zeroization, KDF correctness |
| P1 (eapol-supp) | `crates/eapol-supp/` + `crates/pae/` | Frame parsing, state machine transitions |
| P2 (MKA protocol) | `crates/pae/` (full MKA) | SAK handling, peer list, key server election |
| P3 (CP interface) | `crates/pae/` (CP + MKA) | Port state transitions, secure channel |
| P4 (EAP peer) | `crates/eap-peer/` | TLS cert validation, tunnel integrity |
| P5 (Logon) | `crates/logon/` | NID selection, CAK cache, announcement parsing |

**Blocking rule**: Critical and High findings must be fixed before starting the next priority batch. Medium/Low findings may be tracked in GitHub issues for later resolution.

## Review Process

### 1. Rust Security Scan

```bash
cargo audit                            # Known CVEs in dependencies
cargo clippy --workspace -- -W clippy::unwrap_used  # Find unwrap() usage
```

### 2. Code Review Checklist

| Check | Severity | What to Look For |
|---|---|---|
| `unsafe` blocks | Critical | Must have `// SAFETY:` comment explaining invariants |
| `unwrap()` in production | High | Replace with `?`, `ok_or(...)`, or proper error handling |
| Secret in `Debug`/`Display` | Critical | Secret types must redact in debug output |
| Unbounded allocation from network | High | All network input size-checked before allocation |
| `panic!` in library code | High | Library crates must return `Result`, not panic |
| Integer overflow in protocol | Medium | Use checked arithmetic for counters from network data |
| Missing zeroization | High | Keys/credentials zeroized on drop (`zeroize` crate) |
| Hardcoded credentials | Critical | No secrets in source code |

### 3. Protocol Security Review

- **EAPOL**: Verify frame parsing rejects malformed frames
- **MKA**: Review SAK generation, key derivation, and key lifetime
- **EAP methods**: Verify TLS certificate validation, TEAP tunnel integrity
- **State machines**: Verify no unauthorized state transitions

### 4. Dependency Audit

```bash
cargo audit                           # Check for known vulnerabilities
cargo tree                            # Review dependency tree
```

### 5. Output

```markdown
# Security Review Report

## Findings

| ID | Severity | Category | Description | Mitigation |
|---|---|---|---|---|
| SEC-001 | Critical | Unsafe | ... | ... |
| SEC-002 | High | Credential | ... | ... |

## Summary
- Critical: N
- High: N
- Medium: N
- Low: N
```
