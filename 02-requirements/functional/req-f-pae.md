# Functional Requirements: Supplicant PAE (Clause 8)

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-001 (#1)

## REQ-F-PAE-001: Supplicant PACP State Machine

The Supplicant PAE shall implement the PACP state machine per IEEE 802.1X-2020 Clause 8.7, with states: UNAUTHENTICATED, AUTHENTICATING, AUTHENTICATED, HELD, and LOGOFF.

**Traces to**: StR-001 (#1)

### Acceptance Criteria (Given-When-Then)

- **Given** the Supplicant PAE is in UNAUTHENTICATED state and `authenticate` is set, **When** `portEnabled` is TRUE, **Then** the state machine transitions to AUTHENTICATING, increments `retryCount`, and calls `txEapolStart()`
- **Given** the Supplicant PAE is in AUTHENTICATING state, **When** `eapSuccess` is set, **Then** it transitions to AUTHENTICATED, sets `authenticated`, clears `retryCount`
- **Given** the Supplicant PAE is in AUTHENTICATING state, **When** `eapFail` is set and `retryCount < retryMax`, **Then** it re-enters AUTHENTICATING, increments `retryCount`
- **Given** the Supplicant PAE is in AUTHENTICATING state, **When** `eapFail` is set and `retryCount >= retryMax`, **Then** it transitions to HELD, sets `failed`, starts `heldWhile` timer
- **Given** the Supplicant PAE is in AUTHENTICATING state, **When** `eapTimeout` is set and `retryCount < retryMax`, **Then** it re-enters AUTHENTICATING, increments `retryCount`
- **Given** the Supplicant PAE is in AUTHENTICATING state, **When** `eapTimeout` is set and `retryCount >= retryMax`, **Then** it transitions to HELD
- **Given** the Supplicant PAE is in AUTHENTICATED state, **When** the Logon Process deasserts `authenticate`, **Then** it transitions to LOGOFF and calls `txEapolLogoff()`
- **Given** the Supplicant PAE is in HELD state, **When** `heldWhile` expires and `authenticate` is set, **Then** it transitions to AUTHENTICATING, resets `retryCount` to 1

### Verification Method

Unit test: state machine transition table validation against Clause 8.7

---

## REQ-F-PAE-002: Supplicant PAE Higher Layer Interface

The Supplicant PAE shall implement the higher layer interface per Clause 8.3, including: `eapStop`, `eapStart`, `eapTimeout`, `eapFail`, `eapSuccess`, `eapResults`, `eapRxMsg`, `eapRxData`, and `eapTxMsg(eapTxData)`.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** `eapStart` is set by PACP, **When** the EAP higher layer begins the authentication attempt, **Then** `eapStart` is cleared and eventually one of `eapSuccess`, `eapTimeout`, or `eapFail` is set
- **Given** `eapStop` is set, **When** the higher layer initializes, **Then** `eapStop` is cleared and no EAP messages are processed until `eapStart` is set

### Verification Method

Integration test: mock EAP higher layer validates interface contract

---

## REQ-F-PAE-003: Supplicant PAE Client Interface

The Supplicant PAE shall implement the client interface per Clause 8.4, including: `enabled`, `authenticate`, `authenticated`, `results`, and `failed`.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** the port is enabled and PAE functionality available, **When** `enabled` is set, **Then** the Logon Process can set `authenticate` to request authentication
- **Given** authentication succeeds, **When** PACP sets `authenticated`, **Then** the Logon Process can read `results`
- **Given** authentication fails or is terminated, **When** PACP sets `failed`, **Then** `authenticated` is cleared

### Verification Method

Unit test: client interface variable state transitions

---

## REQ-F-PAE-004: Supplicant PAE Timers

The Supplicant PAE shall implement the `heldWhile` timer per Clause 8.6, with `heldPeriod` default of 60 seconds (configurable 0–65535s).

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** the state machine transitions to HELD, **When** `heldWhile` is started, **Then** its initial value is `heldPeriod` (default 60s)
- **Given** `heldPeriod` is set by management, **When** a value in range 0–65535 is provided, **Then** the timer uses that value

### Verification Method

Unit test: timer initialization and decrement behavior

---

## REQ-F-PAE-005: EAPOL-Start Transmission

The Supplicant PAE shall transmit an EAPOL-Start frame per Clause 8.5 when transitioning from UNAUTHENTICATED to AUTHENTICATING.

**Traces to**: StR-001 (#1), StR-010 (#10)

### Acceptance Criteria

- **Given** the Supplicant PAE enters AUTHENTICATING from UNAUTHENTICATED, **When** `txEapolStart()` is called, **Then** an EAPOL-Start frame is transmitted on the Uncontrolled Port

### Verification Method

Unit test: frame transmission verification

---

## REQ-F-PAE-006: EAPOL-Logoff Transmission

The Supplicant PAE shall transmit an EAPOL-Logoff per Clause 8.5 when transitioning to LOGOFF, unless connectivity is secured by MACsec/MKA.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** the Supplicant PAE transitions to LOGOFF, **When** connectivity is not secured by MACsec or MKA, **Then** `txEapolLogoff()` transmits an EAPOL-Logoff frame
- **Given** the Supplicant PAE transitions to LOGOFF, **When** connectivity is secured by MACsec or MKA, **Then** `txEapolLogoff()` may return without transmitting

### Verification Method

Unit test: conditional EAPOL-Logoff behavior

---

## REQ-F-PAE-007: Supplicant PAE Retry Control

The Supplicant PAE shall implement `retryCount` and `retryMax` per Clause 8.7, with `retryMax` default of 2 (configurable by management).

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** authentication fails, **When** `retryCount < retryMax`, **Then** the state machine retries
- **Given** authentication fails, **When** `retryCount >= retryMax`, **Then** the state machine transitions to HELD

### Verification Method

Unit test: retry count and max enforcement

---

## REQ-F-PAE-008: Supplicant PAE Counters

The Supplicant PAE shall maintain diagnostic counters per Clause 8.8: `suppEntersAuthenticating`, `suppAuthTimeoutsWhileAuthenticating`, `suppEapLogoffWhileAuthenticating`, `suppAuthFailWhileAuthenticating`, `suppAuthSuccessesWhileAuthenticating`, `suppAuthFailWhileAuthenticated`, `suppAuthEapLogoffWhileAuthenticated`.

**Traces to**: StR-001 (#1)

### Acceptance Criteria

- **Given** each specified state transition occurs, **When** the transition is taken, **Then** the corresponding counter is incremented

### Verification Method

Unit test: counter increment on state transitions
