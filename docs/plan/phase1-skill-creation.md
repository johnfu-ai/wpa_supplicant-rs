# Plan: Create Development SKILLs for wpa_supplicant-rs

## Context

The user is building a Rust port of wpa_supplicant with IEEE 802.1X-2020 compliance (supplicant role only). The `std_dev_practices-8021X-2020/` repo contains a mature AI asset system — 6 agents, 7 skills, 9 phase instructions, and 30+ prompts — designed for the C implementation. These need to be **converted and adapted** into a self-contained SKILLs system under `wpa_supplicant-rs/SKILL/` that is:

1. Independent from `std_dev_practices-8021X-2020` after creation
2. Adapted for Rust (not C), Cargo (not Makefile), and the supplicant-only scope
3. Capable of driving the full 9-phase lifecycle from a single invocation
4. Following the same skill/agent/instruction architecture patterns

## Scope: EAP Supplicant Only

The Rust implementation targets **supplicant role only** — no authenticator PAE, no AP-side logic. This means:
- Clause 8: Supplicant PAE state machine (core)
- Clause 9: MKA (supplicant perspective)
- Clause 10: CP (supplicant-controlled port)
- Clause 12: Logon Process (supplicant-side NID selection)
- EAP methods: TLS, PEAP, TEAP (supplicant peer)
- EAPOL: Supplicant EAPOL transport

## Deliverables

### 1. Directory Structure

```
wpa_supplicant-rs/
├── SKILL/
│   ├── README.md                          # Index and usage guide
│   ├── agents/
│   │   ├── README.md                      # Agent overview and selection guide
│   │   ├── requirements-analyst.md        # Phase 01-02 agent
│   │   ├── architecture-strategist.md     # Phase 03 agent
│   │   ├── tdd-driver.md                  # Phase 05 agent (Rust TDD)
│   │   ├── testing-specialist.md          # Test quality agent
│   │   ├── documentation-expert.md        # Docs agent
│   │   └── security-analyst.md            # Security review agent
│   ├── instructions/
│   │   ├── root.instructions.md           # Root instructions (Rust-adapted)
│   │   ├── phase-01-stakeholder-requirements.instructions.md
│   │   ├── phase-02-requirements.instructions.md
│   │   ├── phase-03-architecture.instructions.md
│   │   ├── phase-04-design.instructions.md
│   │   ├── phase-05-implementation.instructions.md
│   │   ├── phase-06-integration.instructions.md
│   │   ├── phase-07-verification-validation.instructions.md
│   │   ├── phase-08-transition.instructions.md
│   │   └── phase-09-operation-maintenance.instructions.md
│   ├── skills/
│   │   ├── README.md                      # Skill map and agent-to-skill mapping
│   │   ├── 8021x-domain-model/
│   │   │   └── SKILL.md
│   │   ├── requirements-traceability/
│   │   │   └── SKILL.md
│   │   ├── architecture-governance/
│   │   │   └── SKILL.md
│   │   ├── rust-tdd-implementation/       # Renamed from wpa-tdd-implementation
│   │   │   └── SKILL.md
│   │   ├── verification-validation/
│   │   │   └── SKILL.md
│   │   ├── security-review/
│   │   │   └── SKILL.md
│   │   └── documentation-governance/
│   │       └── SKILL.md
│   └── prompts/
│       ├── README.md
│       ├── project-kickoff.prompt.md
│       ├── requirements-elicit.prompt.md
│       ├── requirements-validate.prompt.md
│       ├── architecture-starter.prompt.md
│       ├── phase-gate-check.prompt.md
│       ├── tdd-compile.prompt.md
│       ├── test-validate.prompt.md
│       ├── traceability-builder.prompt.md
│       └── security-review.prompt.md      # New: Rust security review prompt
```

### 2. Key Adaptations from C to Rust

Every converted file must make these substitutions:

| C / wpa_supplicant concept | Rust / wpa_supplicant-rs replacement |
|---|---|
| `wpa_supplicant-8021X-2020/` implementation repo | `wpa_supplicant-rs/` (this repo) |
| C11 language | Rust (latest stable) |
| `wpa_supplicant Makefile` | `Cargo.toml` + `cargo` commands |
| `os_malloc`, `os_free`, `wpa_printf` | Rust std/alloc, `tracing`/`log` crates |
| `dl_list_*` | `std::collections` or `heapless` for no-std |
| `#ifdef CONFIG_xxx` | `#[cfg(feature = "xxx")]` |
| `eapol_test` harness | `cargo test` + integration test binaries |
| Mock injection via function pointers | Trait-based mock injection (`dyn Trait`) |
| `.c`/`.h` file pairs | `.rs` modules with `pub` visibility |
| `src/pae/`, `src/eapol_supp/` | `crates/pae/`, `crates/eapol-supp/` (Cargo workspace) |
| "No new upper-layer library" | "Idiomatic Rust workspace with protocol crates" |
| "Extend wpa_supplicant in-place" | "Build standalone Rust supplicant workspace" |
| Authenticator + Supplicant scope | **Supplicant-only scope** |

### 3. File-by-File Conversion Plan

#### 3a. Root Instructions (`SKILL/instructions/root.instructions.md`)

Source: `ai/instructions/root.instructions.md` + `.github/copilot-instructions.md`

Changes:
- Replace C language constraints with Rust constraints
- Replace Makefile build with Cargo build
- Replace wpa_supplicant utility references with Rust equivalents
- Scope to supplicant-only (remove Authenticator PAE references)
- Update workspace layout to single-repo model
- Keep: 7-pillar methodology, XP practices, DDD practices, traceability rules, lifecycle phases, copyright rules
- Remove: C-specific coding rules, CMake/Makefile references, OS-specific C include prohibitions

#### 3b. Phase Instructions (`SKILL/instructions/phase-0N-*.instructions.md`)

Source: `ai/instructions/phase-0N-*.instructions.md` (9 files)

Each phase instruction needs:
- `applyTo` frontmatter updated to match new directory paths under `wpa_supplicant-rs/`
- C-specific examples replaced with Rust equivalents (e.g., `cargo test` instead of `make`, `#[cfg(test)]` instead of `#ifdef`, `trait` instead of function pointers)
- Phase 05 in particular: complete rewrite of code location guidance, build commands, test patterns, traceability header format (Rust doc comments instead of C block comments)
- All authenticator-specific content removed (e.g., `src/eapol_auth/` references)

#### 3c. Skills (`SKILL/skills/*/SKILL.md`)

Source: `ai/skills/*/SKILL.md` (7 skills)

Changes per skill:
- **8021x-domain-model**: Update file pointers from C paths to Rust module paths; add supplicant-only scope note; update YANG reference paths
- **requirements-traceability**: Minimal changes — traceability rules are language-independent
- **architecture-governance**: Replace "in-place wpa_supplicant extension" constraint with "idiomatic Rust crate" constraint
- **rust-tdd-implementation** (renamed from wpa-tdd-implementation): Rewrite entirely — `cargo test` instead of `make`, `#[cfg(test)]` modules instead of C test harness, trait-based mocking instead of function pointer injection
- **verification-validation**: Update test commands to `cargo test`; keep coverage/gap analysis concepts
- **security-review**: Add Rust-specific security concerns (`unsafe` blocks, `unwrap()` in production, credential handling in memory)
- **documentation-governance**: Update path references to new `SKILL/` layout

#### 3d. Agents (`SKILL/agents/*.md`)

Source: `ai/agents/*.md` (6 agents)

Each agent needs:
- Frontmatter `skills` field updated (e.g., `wpa-tdd-implementation` → `rust-tdd-implementation`)
- C-specific examples replaced with Rust
- Authenticator PAE references removed
- TDD Driver: significant rewrite for Rust patterns (`cargo test`, trait mocking, `#[cfg(test)]`)
- Security Analyst: add Rust `unsafe` audit, memory safety review
- Architecture Strategist: update for Rust crate/module architecture instead of C file structure

#### 3e. Prompts (`SKILL/prompts/*.md`)

Source: Select the most useful prompts from `ai/prompts/` (10 of 30+). Selection criteria: directly relevant to active development phases, not redundant with agent capabilities.

Selected prompts:
1. `project-kickoff.prompt.md` — Starting a new project/feature
2. `requirements-elicit.prompt.md` — Eliciting requirements from the standard
3. `requirements-validate.prompt.md` — Validating requirements quality
4. `architecture-starter.prompt.md` — Starting architecture design
5. `phase-gate-check.prompt.md` — Phase transition validation
6. `tdd-compile.prompt.md` — TDD cycle with compilation
7. `test-validate.prompt.md` — Test quality validation
8. `traceability-builder.prompt.md` — Building traceability links
9. `corrective-action-loop.prompt.md` — Fix-build-retest loop
10. `security-review.prompt.md` — New prompt for Rust security review (adapted from security-analyst agent content)

Each prompt needs C→Rust adaptation similar to agents.

### 4. Phase Output Directories

Create the 9-phase directory structure within `wpa_supplicant-rs/`:

```
wpa_supplicant-rs/
├── 01-stakeholder-requirements/
├── 02-requirements/
├── 03-architecture/
├── 04-design/
├── 05-implementation/          # Evidence docs only; Rust code goes in src/
├── 06-integration/
├── 07-verification-validation/
├── 08-transition/
└── 09-operation-maintenance/
```

Each with a README.md and `.gitkeep` files, modeled after the structure in `std_dev_practices-8021X-2020/`.

### 5. Cargo Project Bootstrap

Initialize the Rust project as a **Cargo workspace** with crates per protocol component:

```
wpa_supplicant-rs/
├── Cargo.toml                  # Workspace root [workspace]
├── crates/
│   ├── eapol-supp/             # Supplicant EAPOL state machine (Clause 8)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── eap-peer/               # EAP peer methods (TLS, PEAP, TEAP)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── pae/                    # PAE, MKA, CP state machines (Clauses 9-10)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── logon/                  # Logon Process (Clause 12)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── wpa-supplicant/         # Top-level binary crate
│       ├── Cargo.toml
│       └── src/main.rs
```

Build commands:
- `cargo build` — Build entire workspace
- `cargo build -p eapol-supp` — Build single crate
- `cargo test` — Run all tests across workspace
- `cargo test -p pae` — Run tests for single crate
- `cargo clippy --workspace` — Lint all crates
- `cargo fmt --all -- --check` — Check formatting

## Execution Order

1. **Create directory structure** — `SKILL/` tree + phase directories
2. **Convert root instructions** — This is the foundation all other files reference
3. **Convert skills** (7 files) — Focused, composable capabilities
4. **Convert agents** (6 files) — Role profiles that compose skills
5. **Convert phase instructions** (9 files) — Phase-specific guidance
6. **Convert prompts** (10 files) — Actionable workflow prompts
7. **Write README files** — SKILL/README.md, agents/README.md, skills/README.md, prompts/README.md
8. **Initialize Cargo project** — Cargo.toml, src/lib.rs skeleton
9. **Initialize phase directories** — README.md + .gitkeep per phase
10. **Update CLAUDE.md** — Add SKILL system reference

## Verification

After creating all files:

1. **Content integrity**: Every SKILL file references Rust, Cargo, and supplicant-only scope — no stale C references remain
2. **Internal consistency**: Agent `skills` frontmatter matches skill directory names; skill guardrails reference correct Rust paths
3. **Independence**: No file under `SKILL/` references `std_dev_practices-8021X-2020/` paths
4. **Phase coverage**: All 9 phases have instructions and output directories
5. **Build verification**: `cargo check` passes on the skeleton project
6. **SKILL usability**: `SKILL/README.md` explains how to invoke a skill and start a lifecycle phase
