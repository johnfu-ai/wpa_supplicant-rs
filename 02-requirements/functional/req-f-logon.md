# Functional Requirements: Logon Process (Clause 12)

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-005 (#5)

## REQ-F-LOGON-001: Logon Process State Machine

The supplicant shall implement the Logon Process per Clause 12.5, controlling when and how the PAE attempts authentication, uses PSKs, or allows unsecured connectivity.

**Traces to**: StR-005 (#5)

### Acceptance Criteria

- **Given** the Logon Process is in an unauthenticated state, **When** the port becomes MAC_Operational, **Then** the Logon Process instructs the PAE to authenticate
- **Given** authentication succeeds, **When** MKA establishes connectivity, **Then** the Logon Process instructs the CP state machine to enable the Controlled Port
- **Given** authentication fails and PSK fallback is configured, **When** EAP fails, **Then** the Logon Process attempts PSK-based MKA
- **Given** MKA fails after secured connectivity was established, **When** the CP state machine reports failure and the `authenticate` variable is still set, **Then** the Logon Process shall attempt reauthentication

### Verification Method

Unit test: Logon Process state transitions

---

## REQ-F-LOGON-002: NID Selection

The supplicant shall select a Network Identifier (NID) per Clauses 10 and 12, using EAPOL-Announcements to identify available networks and select appropriate credentials.

**Traces to**: StR-005 (#5)

### Acceptance Criteria

- **Given** an EAPOL-Announcement is received, **When** it contains NID information, **Then** the supplicant evaluates the NID against configured network profiles
- **Given** a matching NID, **When** the network profile specifies credentials, **Then** those credentials are used for authentication
- **Given** no matching NID, **When** the null NID is supported, **Then** the supplicant may attempt authentication with default credentials

### Verification Method

Unit test: NID matching and credential selection

---

## REQ-F-LOGON-003: EAPOL-Announcement Reception

The supplicant shall receive and interpret EAPOL-Announcements per Clauses 10.3 and 11.12, extracting NID, access status, and capability information.

**Traces to**: StR-005 (#5)

### Acceptance Criteria

- **Given** an EAPOL-Announcement frame, **When** it is received on the Uncontrolled Port, **Then** NID Set TLVs are parsed and access capabilities extracted
- **Given** announcement filtering is configured, **When** a NID is in the ignore list, **Then** the announcement for that NID is discarded

### Verification Method

Unit test: EAPOL-Announcement parsing and filtering

---

## REQ-F-LOGON-004: NID in EAPOL-Start

The supplicant shall encode NID selection in EAPOL-Start frames per Clauses 11.6 and 10.16.

**Traces to**: StR-005 (#5)

### Acceptance Criteria

- **Given** a selected NID, **When** the supplicant transmits EAPOL-Start, **Then** the Packet Body includes TLVs specifying the chosen NID

### Verification Method

Unit test: EAPOL-Start frame encoding with NID TLV

---

## REQ-F-LOGON-005: CAK Cache Management

The supplicant shall manage cached CAKs per Clause 12.6, associating each with CKN, KMD, NID, and lifetime.

**Traces to**: StR-005 (#5), StR-002 (#2)

### Acceptance Criteria

- **Given** a CAK derived from EAP, **When** caching is permitted, **Then** the CAK is stored with its CKN, KMD, NID, and an expiration lifetime
- **Given** a cached CAK, **When** its lifetime expires, **Then** the CAK is deleted from the cache
- **Given** a cached CAK matching a peer's CKN, **When** MKA is enabled, **Then** a participant is created using the cached CAK without requiring reauthentication

### Verification Method

Unit test: CAK cache store, retrieve, and expiry
