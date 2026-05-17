# Functional Requirements: Controlled Port (Clause 10/12)

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-003 (#3)

## REQ-F-CP-001: CP State Machine

The supplicant shall implement the CP state machine per Clause 12.4, managing Controlled Port connectivity based on authentication and MKA status. The CP state machine shall support states: SECURE, UNSECURE, and DISABLED, transitioning based on MKA principal actor status.

**Traces to**: StR-003 (#3)

### Acceptance Criteria

- **Given** authentication succeeds and MKA establishes secured connectivity, **When** the CP state machine transitions to SECURE and enables `controlledPortEnabled`, **Then** the Controlled Port is MAC_Operational
- **Given** MKA fails, **When** the CP state machine transitions to DISABLED, **Then** `controlledPortEnabled` is cleared and the Controlled Port becomes MAC_Operational = FALSE
- **Given** authentication succeeds without MACsec, **When** the CP state machine transitions to UNSECURE and the Logon Process authorizes unsecured connectivity, **Then** `controlledPortEnabled` is set without MACsec protection

### Verification Method

Unit test: CP state transitions driven by MKA and Logon Process inputs

---

## REQ-F-CP-002: CP State Machine Interface

The CP state machine shall implement the interface per Clause 12.3, including: `controlledPortEnabled`, `newInfo`, `secure`, `authenticated`, `failed` from the principal actor.

**Traces to**: StR-003 (#3)

### Acceptance Criteria

- **Given** the principal actor is secured, **When** `secure` is TRUE, **Then** the CP state machine sets `controlledPortEnabled` and enables MACsec
- **Given** the principal actor is authenticated (without MACsec), **When** `authenticated` is TRUE, **Then** the CP state machine sets `controlledPortEnabled` without MACsec
- **Given** all actors have failed, **When** `failed` is TRUE, **Then** the CP state machine clears `controlledPortEnabled`

### Verification Method

Unit test: CP interface variable transitions

---

## REQ-F-CP-003: Secure Channel and Secure Association Management

The supplicant shall manage Secure Channels (SC) and Secure Associations (SA) per Clause 9.10, installing and retiring SAKs with correct AN (Association Number) assignment.

**Traces to**: StR-003 (#3), StR-002 (#2)

### Acceptance Criteria

- **Given** a new SAK is installed, **When** the Key Server distributes SAKuse parameters, **Then** the supplicant enables receive then transmit for the specified AN
- **Given** an old SAK, **When** SAK Retire time elapses, **Then** the old SA is removed from the SecY

### Verification Method

Integration test: SAK lifecycle with mock SecY

---

## REQ-F-CP-004: MACsec Cipher Suite Support

The supplicant shall support MACsec cipher suites per Clause 9.7: GCM-AES-128, GCM-AES-256, and GCM-AES-XPN-256.

**Traces to**: StR-003 (#3)

### Acceptance Criteria

- **Given** each supported cipher suite, **When** selected by the Key Server, **Then** SAKs of the correct length are generated/installed and the SecY is configured accordingly

### Verification Method

Unit test: cipher suite configuration for each supported suite
