# Functional Requirements: MKA Supplicant (Clause 9)

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-002 (#2)

## REQ-F-MKA-001: MKA Key Hierarchy

The MKA supplicant shall implement the key hierarchy per Clause 9.3, deriving ICK (ICV Key) and KEK (Key Encrypting Key) from the CAK using the KDF specified in Clause 6.2.1 (AES-CMAC per RFC 4493).

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** a CAK and CKN, **When** keys are derived, **Then** ICK = KDF(CAK, "IEEE8021 ICK", CKN[0..15], ICKLength) and KEK = KDF(CAK, "IEEE8021 KEK", CKN[0..15], KEKLength)
- **Given** the CAK changes, **When** a new instance is created, **Then** new ICK and KEK are derived independently from the prior instance keys

### Verification Method

Unit test: KDF output matches known test vectors (Annex G)

---

## REQ-F-MKA-002: MKA Transport (MKPDU)

The MKA supplicant shall transmit and receive MKPDUs per Clause 9.4, authenticating each MKPDU with the ICK, and including actor MI (Member Identifier), MN (Message Number), Live Peer List, and Potential Peer List.

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** an active participant, **When** the MKA Hello Time expires, **Then** an MKPDU is transmitted with authenticated integrity
- **Given** a received MKPDU, **When** the ICV validates using the ICK, **Then** the peer is added to or refreshed in the peer lists

### Verification Method

Unit test: MKPDU encode/decode and ICV verification

---

## REQ-F-MKA-003: MKA Peer List Management

The MKA supplicant shall maintain Live Peer List and Potential Peer List per Clause 9.4.3, removing peers when MKA Life Time (6.0s) has elapsed since the participant's recent MN was included in a peer's MKPDU.

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** a peer's MI and recent MN appear in a received MKPDU, **When** the participant's own MI/MN is included in that MKPDU, **Then** the peer is on the Live Peer List
- **Given** a peer on the Live Peer List, **When** MKA Life Time elapses without refresh, **Then** the peer is removed

### Verification Method

Unit test: peer list add, refresh, and timeout behavior

---

## REQ-F-MKA-004: Key Server Election

The MKA supplicant shall participate in Key Server election per Clause 9.5, using Key Server Priority to select the participant with the highest priority (lowest numerical value) as Key Server.

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** multiple participants in a CA, **When** each advertises its Key Server Priority, **Then** the participant with the highest priority (lowest value) is elected Key Server
- **Given** the actor's priority is higher than all peers, **When** election completes, **Then** the actor becomes Key Server

### Verification Method

Unit test: election with varying priorities

---

## REQ-F-MKA-005: MKA Cipher Suite Selection

The MKA supplicant shall support cipher suite selection per Clause 9.7, advertising supported cipher suites and selecting the highest-priority cipher suite common to all CA members.

**Traces to**: StR-002 (#2), StR-003 (#3)

### Acceptance Criteria

- **Given** the supplicant and peers advertise supported cipher suites, **When** the Key Server selects a cipher suite, **Then** it is the highest-priority suite common to all live peers
- **Given** the selected cipher suite is the Null Cipher Suite, **When** the Key Server distributes no SAK, **Then** communication proceeds without MACsec encryption

### Verification Method

Unit test: cipher suite negotiation with various peer capabilities

---

## REQ-F-MKA-006: SAK Reception and Installation

The MKA supplicant shall receive and install SAKs distributed by the Key Server per Clause 9.8, using AES Key Wrap to unwrap the SAK, and install the SAK in the SecY for receive and transmit use per Clause 9.10.

**Traces to**: StR-002 (#2), StR-003 (#3)

### Acceptance Criteria

- **Given** a DistribSAK parameter set in an MKPDU, **When** the SAK is unwrapped using the KEK, **Then** the SAK is installed in the SecY for the specified AN (Association Number)
- **Given** a newly installed SAK, **When** the Key Server begins transmitting with that SAK, **Then** the supplicant enables its transmit SA

### Verification Method

Integration test: SAK unwrap and SecY installation with mock Key Server

---

## REQ-F-MKA-007: MKA Participant Timer Values

The MKA supplicant shall implement participant timers per Clause 9.15 and Table 9-3: MKA Hello Time (2.0s), MKA Bounded Hello Time (0.5s), MKA Life Time (6.0s), MKA Suspension Limit (120.0s).

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** an active participant, **When** the periodic transmission timer expires, **Then** an MKPDU is transmitted within MKA Hello Time (2.0s) or MKA Bounded Hello Time (0.5s)
- **Given** a participant, **When** MKA Life Time (6.0s) elapses without receiving an MKPDU confirming liveness, **Then** the participant may be deleted per Clause 9.14

### Verification Method

Unit test: timer initialization, expiry, and participant deletion

---

## REQ-F-MKA-008: MKA Participant Creation and Deletion

The MKA supplicant shall create and delete MKA participants per Clause 9.14, including conditions for deletion: management disable, port MAC_Operational false, CAK lifetime expiry, no live peer within MKA Life Time.

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** a new CAK is available (from EAP or PSK), **When** MKA is enabled, **Then** a participant is created for that CKN
- **Given** a participant, **When** MKA Life Time elapses with no live peer, **Then** the participant is deleted and `failed` is set

### Verification Method

Unit test: participant lifecycle management

---

## REQ-F-MKA-009: CAK Identification

The MKA supplicant shall identify each CAK by its CKN per Clause 9.3.1, where CKN is 1–32 octets.

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** a CAK, **When** a participant is created, **Then** it is identified by its CKN (1–32 octets)
- **Given** MKPDUs received for different CKNs, **When** the CKN is processed, **Then** the correct CAK-derived keys are used for ICV verification

### Verification Method

Unit test: CKN-based key selection

---

## REQ-F-MKA-010: Random Number Generation

The MKA supplicant shall use a strong random number generator per Clause 9.2.1 for all random values (MI, nonce, SAK contributions).

**Traces to**: StR-002 (#2)

### Acceptance Criteria

- **Given** the system has no hardware RNG, **When** random values are needed, **Then** a deterministic RNG seeded with sufficient entropy is used
- **Given** a hardware RNG is available, **When** random values are needed, **Then** the hardware RNG is preferred

### Verification Method

Code review: RNG source and entropy pool audit
