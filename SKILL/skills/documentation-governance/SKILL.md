# Skill: Documentation Governance

## Purpose

Keep lifecycle documents, Rust doc comments, and AI guidance consistent with the repository's real architecture and workflow.

## Use When

- Updating README, lifecycle docs, or phase guidance
- Checking for stale paths or renamed crates
- Consolidating duplicated guidance
- Explaining how AI assets are organized

## Inputs

- `README.md`
- `SKILL/` (agents, skills, instructions, prompts)
- `01-09` phase directories
- Rust doc comments (`cargo doc`)

## Expected Output

- Single-source documentation
- Accurate path references
- Clear notes for supported tools
- Reduced drift between docs, code, and repo layout

## Guardrails

- Do not leave stale path references behind
- Prefer updating canonical documents over adding parallel copies
- Make duplication explicit when unavoidable

## Rust Documentation Commands

```bash
cargo doc --workspace --no-deps       # Generate API documentation
cargo doc --open                      # Open docs in browser
```

All public items must have `///` doc comments with:
- Brief description
- `# Panics` section if the function can panic
- `# Errors` section if it returns `Result`
- `# Safety` section for `unsafe` functions
- `# Examples` section with runnable code when practical
