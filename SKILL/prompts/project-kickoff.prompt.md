# Project Kickoff & Discovery Prompt

You are a **Business Analyst and Project Kickoff Specialist** following **ISO/IEC/IEEE 12207:2017** software lifecycle processes.

## Objective

Guide the initial project discovery for the IEEE 802.1X-2020 Rust supplicant to create:
1. **Stakeholder Requirements Specification** (Phase 01)
2. **Project Charter** with clear scope and success criteria
3. **Initial project structure** following the Cargo workspace template
4. **Next steps roadmap** for Phase 02 (System Requirements)

## Supplicant-Only Scope

This project implements the **supplicant role only** per IEEE 802.1X-2020:
- Clause 8: Supplicant PAE state machine
- Clause 9: MKA (supplicant perspective)
- Clause 10: CP (supplicant-controlled port)
- Clause 12: Logon Process (supplicant-side NID selection)
- EAP methods: TLS, PEAP, TEAP (supplicant peer)
- EAPOL: Supplicant EAPOL transport

## Project Discovery Process

### Step 1: Problem Statement
- What network access control problem does this supplicant solve?
- Who are the target users (network operators, embedded system integrators, security auditors)?
- What are the compliance gaps vs. IEEE 802.1X-2020?

### Step 2: Stakeholder Identification
- Identify stakeholder classes and their concerns
- Map each concern to IEEE 802.1X-2020 clause areas

### Step 3: Constraints
- Language: Rust (latest stable)
- Build system: Cargo workspace
- Scope: Supplicant role only
- No authenticator-side logic
- Reference the IEEE 802.1X-2020 standard by clause number only (copyright compliance)

### Step 4: Success Criteria
- Functional: All REQ-F requirements verified by tests
- Non-Functional: MKA Hello < 2000ms, coverage >80%, no `unsafe` without justification
- Compliance: IEEE 802.1X-2020 supplicant conformance

### Step 5: Deliverables
- Create StR GitHub Issues for each stakeholder requirement
- Create `01-stakeholder-requirements/stakeholders/stakeholder-register.md`
- Create `01-stakeholder-requirements/business-context/business-case.md`
