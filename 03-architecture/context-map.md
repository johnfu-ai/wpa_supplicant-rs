# Context Map: Bounded Context Relationships

Per ISO/IEC/IEEE 42010:2011 and DDD — Phase 03

## Bounded Contexts

| Context | Crate | IEEE Clause | Core Responsibility |
|---|---|---|---|
| **PAE Core** | `pae` | 9, 10 | MKA key agreement, CP state machine, port states, timer wheel, crypto abstractions |
| **Supplicant EAPOL** | `eapol-supp` | 8, 11 | Supplicant PACP state machine, EAPOL frame encoding/decoding |
| **EAP Authentication** | `eap-peer` | RFC 3748/5216 | EAP peer framework, method implementations (TLS, PEAP, TEAP) |
| **Logon Process** | `logon` | 12 | NID selection, CAK cache, Logon state machine |
| **Application** | `wpa-supplicant` | — | Event loop, daemon, config, control interface |

## Context Map

```
┌─────────────────────────────────────────────────────────┐
│                    Application                           │
│                  (wpa-supplicant)                        │
│  ┌─────────┐  ┌──────────┐  ┌──────┐  ┌────────────┐  │
│  │Event    │  │Config    │  │CLI   │  │Control     │  │
│  │Loop     │  │(TOML)    │  │      │  │Interface   │  │
│  └────┬────┘  └──────────┘  └──────┘  └────────────┘  │
│       │ dispatches events                                  │
└───────┼──────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│                  Protocol Event Bus                        │
│         (PaeEvent enum — defined in pae)                   │
└──┬────────┬──────────┬────────────┬───────────────────────┘
   │        │          │            │
   ▼        ▼          ▼            ▼
┌──────┐ ┌──────┐ ┌────────┐ ┌──────────┐
│PAE   │ │EAPOL │ │EAP     │ │Logon     │
│Core  │ │Supp  │ │Peer    │ │Process   │
│(pae) │ │      │ │        │ │          │
└──┬───┘ └──┬───┘ └───┬────┘ └──┬───────┘
   │        │         │         │
   │   ┌────┘         │    ┌────┘
   │   │ depends on   │    │ depends on
   ▼   ▼              ▼    ▼
┌──────────────────────────────────┐
│          PAE Core (pae)          │
│     Shared Kernel / Core Domain  │
│                                  │
│  • MkaParticipant, Cak, Sak      │
│  • CpState, PortState            │
│  • TimerWheel, PaeEvent          │
│  • Kdf, KeyWrap, Rng traits      │
│  • CipherSuite                   │
└──────────────────────────────────┘
```

## Upstream/Downstream Relationships

| Upstream (Supplier) | Downstream (Consumer) | Relationship | Shared Types |
|---|---|---|---|
| PAE Core | Supplicant EAPOL | Customer–Supplier | `CpState`, `PortState`, `PaeEvent`, `PaeError` |
| PAE Core | EAP Authentication | Customer–Supplier | `PaeEvent`, `PaeError` |
| PAE Core | Logon Process | Customer–Supplier | `CpState`, `Cak`, `Ckn`, `PaeEvent`, `PaeError` |
| Supplicant EAPOL | Logon Process | Customer–Supplier | `EapolFrame`, `EapolError` |
| All crates | Application | Conformist | All types (binary crate assembles) |

## Shared Kernel

The **PAE Core** (`pae`) crate is the shared kernel. It defines types used across multiple bounded contexts:

| Type | Used By | Purpose |
|---|---|---|
| `PaeEvent` | All crates | Inter-crate event communication |
| `CpState` | eapol-supp, logon, wpa-supplicant | Controlled Port state |
| `Cak`, `Ckn`, `Sak` | eapol-supp, logon, wpa-supplicant | Key types with zeroization |
| `CipherSuite` | eap-peer, logon, wpa-supplicant | Cipher suite selection |
| `PaeError` | eapol-supp, eap-peer, logon | Error propagation base |
| `TimerWheel`, `TimerId` | eapol-supp, logon, wpa-supplicant | Protocol timer management |
| `Kdf`, `KeyWrap`, `Rng` | eap-peer, logon (via pae) | Crypto abstractions |

## Anti-Corruption Layers

| Boundary | Protection |
|---|---|
| EAP → PAE | EAP methods return `Msk` (zeroized); PAE core never sees TLS internals |
| EAPOL → Network | `EapolFrame` abstracts raw L2 packet bytes; parsers reject malformed input |
| Application → All | `wpa-supplicant` translates between external interfaces (TOML, D-Bus, L2 socket) and internal types |

## Dependency Rules (Enforced by Cargo)

1. **No upward dependencies**: `pae` never imports from `eapol-supp`, `eap-peer`, or `logon`
2. **No lateral dependencies**: `eapol-supp` never imports from `eap-peer` or `logon`
3. **No circular dependencies**: All edges point toward `pae` or `wpa-supplicant`
4. **`pae` has minimal external deps**: Only `zeroize`, `tracing`, `thiserror` — no I/O, no async, no TLS

## Architecture Decision Records

| ADR | Issue | Affects Contexts |
|---|---|---|
| ADR-WS-001: Workspace Boundaries | #73 | All |
| ADR-SM-002: Trait-Based State Machines | #74 | All protocol contexts |
| ADR-TMR-003: Timer Wheel | #75 | PAE Core, Supplicant EAPOL |
| ADR-SEC-004: Key Zeroization | #76 | PAE Core, EAP Authentication |
| ADR-ERR-005: Error Handling | #77 | All |
| ADR-FF-006: Feature Flags | #78 | PAE Core, EAP Authentication |
| ADR-EVT-007: Event-Driven Communication | #79 | All protocol contexts |
| ADR-KDF-008: KDF/Crypto Abstraction | #80 | PAE Core |

## Architecture Components

| Component | Issue | Crate |
|---|---|---|
| ARC-C-PAE-001: PAE Core | #81 | `pae` |
| ARC-C-EAPOL-002: Supplicant EAPOL | #82 | `eapol-supp` |
| ARC-C-EAP-003: EAP Authentication | #83 | `eap-peer` |
| ARC-C-LOGON-004: Logon Process | #84 | `logon` |
| ARC-C-WPA-005: Application | #85 | `wpa-supplicant` |
