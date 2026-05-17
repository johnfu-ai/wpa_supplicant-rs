# Functional Requirements: EAP Peer Methods

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-004 (#4)

## REQ-F-EAP-001: EAP Peer Framework

The supplicant shall implement an EAP peer framework per IETF RFC 3748, supporting EAP-Request/Response messaging, method negotiation, and result reporting (eapSuccess, eapFail, eapTimeout).

**Traces to**: StR-004 (#4)

### Acceptance Criteria

- **Given** an EAP-Request/Identity, **When** received by the peer, **Then** an EAP-Response/Identity is transmitted
- **Given** an EAP method exchange completes, **When** the method succeeds, **Then** `eapSuccess` is set with `eapResults` containing the MSK (at least 64 octets)
- **Given** an EAP method exchange fails, **When** the method reports failure, **Then** `eapFail` is set

### Verification Method

Unit test: EAP peer state machine with mock authenticator

---

## REQ-F-EAP-002: EAP-TLS

The supplicant shall implement EAP-TLS per IETF RFC 5216, supporting mutual certificate-based authentication with TLS 1.2+ (per IETF RFC 8446), generating an MSK of at least 64 octets.

**Traces to**: StR-004 (#4)

### Acceptance Criteria

- **Given** a configured client certificate and CA certificate, **When** EAP-TLS negotiation begins, **Then** mutual authentication is performed using TLS
- **Given** successful EAP-TLS, **When** the TLS handshake completes, **Then** an MSK of at least 64 octets is derived for MKA use
- **Given** a certificate validation failure, **When** the server certificate is untrusted, **Then** EAP-TLS fails with `eapFail`

### Verification Method

Integration test: EAP-TLS against FreeRADIUS with TLS

---

## REQ-F-EAP-003: PEAP

The supplicant shall implement PEAP (Protected EAP) per IETF RFC 7170, establishing a TLS tunnel and performing inner EAP-MSCHAPv2 authentication.

**Traces to**: StR-004 (#4)

### Acceptance Criteria

- **Given** a configured CA certificate and username/password, **When** PEAP negotiation begins, **Then** a TLS tunnel is established and inner authentication proceeds
- **Given** successful PEAP, **When** inner authentication completes, **Then** an MSK is derived for MKA use
- **Given** inner authentication failure, **When** credentials are invalid, **Then** PEAP fails with `eapFail`

### Verification Method

Integration test: PEAP against FreeRADIUS with MSCHAPv2

---

## REQ-F-EAP-004: TEAP

The supplicant shall implement TEAP (Tunnel EAP) per IETF RFC 7170, with compound binding and support for both certificate and password inner methods.

**Traces to**: StR-004 (#4)

### Acceptance Criteria

- **Given** configured credentials (certificate and/or password), **When** TEAP negotiation begins, **Then** a TLS tunnel with compound binding is established
- **Given** successful TEAP, **When** inner authentication completes, **Then** an MSK is derived with compound binding verification
- **Given** compound binding verification fails, **When** the binding is invalid, **Then** TEAP fails with `eapFail`

### Verification Method

Integration test: TEAP against FreeRADIUS

---

## REQ-F-EAP-005: EAP Method Mutual Authentication

All EAP methods used by the supplicant shall support mutual authentication per Clause 8.11.

**Traces to**: StR-004 (#4)

### Acceptance Criteria

- **Given** any supported EAP method, **When** authentication completes, **Then** both Supplicant and Authenticator have been authenticated

### Verification Method

Code review: no EAP method without mutual authentication is configurable

---

## REQ-F-EAP-006: EAP Method Key Derivation for MKA

All EAP methods used with MKA shall support key derivation per Clause 8.11.1, generating an MSK of at least 64 octets and a Session-Id per IETF RFC 5247.

**Traces to**: StR-004 (#4), StR-002 (#2)

### Acceptance Criteria

- **Given** a successful EAP authentication used with MKA, **When** `eapResults` is provided, **Then** the MSK is at least 64 octets and the first 16 or 32 octets are usable for CAK derivation per Clause 6.2.2

### Verification Method

Unit test: MSK length validation; integration test: CAK derivation from EAP MSK
