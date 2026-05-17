# User Stories

Per ISO/IEC/IEEE 29148:2018 — Phase 02

## US-001: Supplicant Authenticates via EAP-TLS

**As a** network operator
**I want** the supplicant to authenticate using EAP-TLS with a client certificate
**So that** mutual authentication is established and MACsec keys are derived

### Acceptance Criteria

- Given a configured client certificate, CA certificate, and private key
- When the Supplicant PAE enters AUTHENTICATING
- Then EAP-TLS completes mutual authentication
- And an MSK of at least 64 octets is provided for MKA CAK derivation

**Traces to**: StR-004 (#4), REQ-F-EAP-002

---

## US-002: Supplicant Establishes MACsec Secure Channel

**As a** security auditor
**I want** the supplicant to establish a MACsec-secured Controlled Port after EAP authentication
**So that** data traffic is cryptographically protected

### Acceptance Criteria

- Given successful EAP authentication with MKA
- When MKA completes SAK distribution and installation
- Then the Controlled Port transitions to SECURE
- And data frames are transmitted with MACsec encryption

**Traces to**: StR-002 (#2), StR-003 (#3), REQ-F-MKA-006, REQ-F-CP-001

---

## US-003: Supplicant Recovers from Link Flap

**As a** network operator
**I want** the supplicant to re-authenticate automatically after a link interruption
**So that** secured connectivity is restored without manual intervention

### Acceptance Criteria

- Given MACsec-secured connectivity is established
- When the link goes down and comes back
- Then the supplicant re-authenticates and re-establishes MKA within 10 seconds
- And the Controlled Port returns to SECURE

**Traces to**: StR-010 (#10), REQ-NF-REL-003

---

## US-004: Supplicant Selects Network by NID

**As a** network operator
**I want** the supplicant to select a specific network from multiple available networks
**So that** the correct credentials and authorization are used

### Acceptance Criteria

- Given an EAPOL-Announcement with multiple NIDs
- When the supplicant matches a NID to a configured network profile
- Then the correct credentials are selected for authentication
- And the NID is included in EAPOL-Start

**Traces to**: StR-005 (#5), REQ-F-LOGON-002

---

## US-005: Integrator Embeds Supplicant Library

**As a** system integrator
**I want** to embed the supplicant library in my application
**So that** I can drive the EAP/MKA state machines programmatically without a separate daemon

### Acceptance Criteria

- Given the supplicant library crate as a dependency
- When I create a SupplicantPae instance with injected trait implementations
- Then I can drive the event loop and receive state change callbacks
- And no global mutable state is required

**Traces to**: StR-009 (#9), REQ-F-PAE-001

---

## US-006: Compliance Officer Audits Traceability

**As a** compliance officer
**I want** to trace every implemented protocol behavior back to an IEEE 802.1X-2020 clause
**So that** conformance can be demonstrated to auditors

### Acceptance Criteria

- Given any source file in a protocol crate
- When I read the module doc comment
- Then I find the IEEE 802.1X-2020 clause reference
- And I can follow the GitHub Issue link chain from StR → REQ → ADR → Code → TEST

**Traces to**: StR-006 (#6), REQ-NF-TRC-001, REQ-NF-TRC-002

---

## US-007: Security Auditor Validates No Unsafe Code

**As a** security auditor
**I want** to verify that the supplicant contains no undocumented unsafe code
**So that** memory safety guarantees are maintained

### Acceptance Criteria

- Given the workspace source code
- When I run `cargo geiger`
- Then zero unsafe operations are reported without safety justification comments

**Traces to**: StR-008 (#8), REQ-NF-SEC-001

---

## US-008: Network Operator Deploys Daemon on Linux

**As a** network operator
**I want** to deploy the supplicant as a systemd service on Linux
**So that** it starts automatically and integrates with the network management stack

### Acceptance Criteria

- Given a compiled daemon binary and systemd unit file
- When the service is started
- Then the daemon listens on a D-Bus or Unix socket control interface
- And supports graceful shutdown on SIGTERM

**Traces to**: StR-007 (#7)
