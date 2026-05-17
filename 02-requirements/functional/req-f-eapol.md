# Functional Requirements: EAPOL Transport (Clause 11)

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-001 (#1)

## REQ-F-EAPOL-001: EAPOL Frame Encoding and Decoding

The supplicant shall encode and decode EAPOL frames per Clause 11, supporting all required EAPOL Packet Types: EAPOL-Start, EAPOL-Logoff, EAPOL-EAP, EAPOL-Announcement, EAPOL-Announcement-Req, and EAPOL-MKA.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** each supported EAPOL Packet Type, **When** a frame is encoded, **Then** the Protocol Version, Packet Type, and Packet Body Length fields are correct
- **Given** a received EAPOL frame, **When** the Packet Type is decoded, **Then** the correct handler is invoked

### Verification Method

Unit test: encode/decode roundtrip for each Packet Type

---

## REQ-F-EAPOL-002: EAPOL Frame Transmission

The supplicant shall transmit EAPOL frames on the Uncontrolled Port per Clause 11.1, using the destination MAC address allocation per Clause 12.7.

**Traces to**: StR-001 (#1), StR-010 (#10)

### Acceptance Criteria

- **Given** an EAPOL frame to transmit, **When** the port is enabled, **Then** the frame is transmitted on the Uncontrolled Port with the correct destination MAC address

### Verification Method

Integration test: frame transmission with mock network interface

---

## REQ-F-EAPOL-003: EAPOL Frame Reception

The supplicant shall receive EAPOL frames on the Uncontrolled Port per Clause 11.1, dispatching to the appropriate handler (PACP, MKA, or Logon Process) based on Packet Type.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** a received EAPOL-EAP frame, **When** dispatched, **Then** it is delivered to the EAP higher layer
- **Given** a received EAPOL-MKA frame, **When** dispatched, **Then** it is delivered to the KaY
- **Given** a received EAPOL-Announcement frame, **When** dispatched, **Then** it is delivered to the Logon Process

### Verification Method

Unit test: frame dispatch by Packet Type

---

## REQ-F-EAPOL-004: MKPDU Format

The supplicant shall encode and decode MKPDUs per Clause 11.11, including Basic Parameter Set, Live Peer List, Potential Peer List, and application data parameter sets (DistribSAK, SAKuse, etc.).

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** an MKPDU to transmit, **When** encoded, **Then** the Basic Parameter Set, peer lists, and application data are correctly formatted
- **Given** a received MKPDU, **When** decoded, **Then** all parameter sets are extracted and validated

### Verification Method

Unit test: MKPDU encode/decode with all parameter set types
