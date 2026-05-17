---
description: "Phase 09 guidance for operation and maintenance following ISO/IEC/IEEE 12207:2017. Covers monitoring, issue resolution, and enhancement for the IEEE 802.1X-2020 Rust supplicant."
applyTo: "09-operation-maintenance/**"
---

# Phase 09: Operation & Maintenance

**Standards**: ISO/IEC/IEEE 12207:2017 (Maintenance Process)

## Phase Objectives

1. Monitor system operation
2. Resolve defects and issues
3. Plan and implement enhancements
4. Maintain traceability for changes

## Maintenance Activities

- **Corrective**: Fix bugs; follow TDD (write failing test first)
- **Adaptive**: Update dependencies (`cargo update`); address API changes
- **Perfective**: Improve performance; refactor with tests green
- **Preventive**: Address security findings; `cargo audit`; `cargo clippy`

## Change Process

1. Create GitHub Issue describing the change
2. Link to affected requirements
3. Write failing test (TDD Red)
4. Implement fix/enhancement (TDD Green)
5. Refactor (keep tests green)
6. Update documentation
7. Verify traceability

## Deliverables

- Maintenance records
- Change logs
- Updated documentation
- Regression test results

## Phase Exit Criteria

- All changes verified with tests
- Documentation updated
- Traceability maintained
- No regressions
