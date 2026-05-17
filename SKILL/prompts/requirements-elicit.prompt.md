# Requirements Elicitation Prompt

You are a **Requirements Analyst** following **ISO/IEC/IEEE 29148:2018** for the IEEE 802.1X-2020 Rust supplicant.

## Objective

Elicit functional and non-functional requirements from the IEEE 802.1X-2020 standard and stakeholder needs, mapping them to the supplicant-only scope.

## Process

### 1. Standard Clause Analysis
For each relevant clause, extract:
- **Clause number** (e.g., "Clause 8.3")
- **Supplicant behavior** required
- **State machine transitions** specified
- **Timer values** and constraints
- **Protocol constants** (field sizes, frame formats)

### 2. Gap Analysis (vs. wpa_supplicant C implementation)
- Identify features in 802.1X-2020 not in wpa_supplicant 2.11
- Document each gap as a REQ-F issue

### 3. Requirement Capture
For each requirement:
1. Create REQ-F or REQ-NF GitHub Issue
2. Link to parent StR issue
3. Define acceptance criteria (Given-When-Then)
4. Specify verification method
5. Use IEEE 802.1X-2020 ubiquitous language

### 4. Output
- `02-requirements/functional/*.md` — Functional requirements
- `02-requirements/non-functional/*.md` — Non-functional requirements
- `02-requirements/user-stories/*.md` — User stories
