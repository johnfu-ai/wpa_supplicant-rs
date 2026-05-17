# Ubiquitous Language: IEEE 802.1X-2020 Domain Model

Per ISO/IEC/IEEE 29148:2018 and DDD ubiquitous language practice.
All terms follow IEEE 802.1X-2020 definitions exactly.

## Protocol Entities

| Term | Definition | Do NOT Say |
|---|---|---|
| **Supplicant PAE** | The PAE entity requesting network access, implementing the Supplicant PACP state machine | "client", "endpoint" |
| **Authenticator PAE** | The PAE entity controlling network access (referenced only, not implemented) | "server", "access point" |
| **KaY** | Key Agreement Entity — the PAE entity responsible for MKA | "key manager" |
| **SecY** | MAC Security Entity — provides MACsec cryptographic protection for the Controlled Port | "crypto engine" |
| **PAC** | Port Access Control — protocol-less shim controlling frame transmission/reception by Controlled Port clients | "port filter" |

## Protocol State Machines

| Term | Definition | Do NOT Say |
|---|---|---|
| **PACP** | Port Access Control Protocol — initiates, retries, and terminates EAP authentication | "auth protocol" |
| **CP State Machine** | Controlled Port state machine — manages port connectivity based on authentication and MKA status | "port state machine" |
| **Logon Process** | PAE control logic governing when and how EAP, PSK, and unsecured connectivity are used | "login flow" |

## Key Management

| Term | Definition | Do NOT Say |
|---|---|---|
| **CAK** | Secure Connectivity Association Key — root key for a CA | "master key" |
| **CKN** | secure Connectivity association Key Name — identifies a CAK | "key ID" |
| **ICK** | ICV Key — derived from CAK, used to authenticate MKPDUs | "integrity key" |
| **KEK** | Key Encrypting Key — derived from CAK, used with AES Key Wrap to distribute SAKs | "encryption key" |
| **SAK** | Secure Association Key — used by SecY for MACsec encryption/decryption | "session key" |
| **MSK** | Master Session Key — derived from EAP, first 16/32 octets used for CAK derivation per Clause 6.2.2 | "EAP key" |
| **EMSK** | Extended Master Session Key — derived from EAP (not used by this standard) | — |
| **PSK** | Pre-Shared Key — a CAK configured by management | "static key" |

## MKA Protocol

| Term | Definition | Do NOT Say |
|---|---|---|
| **MKPDU** | MKA Protocol Data Unit — authenticated message exchanged between MKA participants | "MKA packet" |
| **Participant** | A single KaY's participation in a given MKA instance (identified by a CAK/CKN) | "MKA peer" |
| **Actor** | The participant under discussion | "local participant" |
| **Partner** | Another participant in the same MKA instance | "remote peer" |
| **Principal Actor** | The successful actor selected by a KaY to control its PAC or SecY | "active participant" |
| **Key Server** | The participant elected to generate and distribute SAKs | "key distributor" |
| **Live Peer List** | Peers that have included the actor's MI and recent MN in a recent MKPDU | "active peer list" |
| **Potential Peer List** | Peers that have transmitted a directly received MKPDU or were in a peer's Live Peer List | "discovered peer list" |
| **MI** | Member Identifier — randomly chosen identifier for a participant | "peer ID" |
| **MN** | Message Number — incremented with each MKPDU transmission | "sequence number" |
| **SCI** | Secure Channel Identifier — MAC address + Port Identifier | "channel ID" |
| **AN** | Association Number — identifies an SA within an SC | "SA index" |

## Network Access

| Term | Definition | Do NOT Say |
|---|---|---|
| **Controlled Port** | The access point providing secure MAC Service to a SecY client | "authenticated port", "data port" |
| **Uncontrolled Port** | The access point used for EAPOL and discovery protocol exchange | "management port" |
| **NID** | Network Identity — a UTF-8 string identifying a network or network service | "network ID", "SSID" |
| **EAPOL** | EAP over LAN — protocol carrying EAP and PAE messages over the LAN | "EAP over LAN" (use abbreviation) |
| **CA** | Connectivity Association — a set of PAEs authorized to communicate securely | "security group" |
| **SC** | Secure Channel — unidirectional secure communication identified by an SCI | "secure channel" (acceptable but prefer abbreviation) |
| **SA** | Secure Association — an association within an SC identified by an AN | "secure association" (acceptable but prefer abbreviation) |

## MKA Timers

| Term | Value | Definition |
|---|---|---|
| **MKA Hello Time** | 2.0s | Per-participant periodic MKPDU transmission interval |
| **MKA Bounded Hello Time** | 0.5s | Bounded receive delay guarantee transmission interval |
| **MKA Life Time** | 6.0s | Participant lifetime; expiry causes peer removal or participant deletion |
| **MKA Suspension Limit** | 120.0s | Maximum suspendFor value for in-service upgrades |

## Supplicant PACP States

| State | Description |
|---|---|
| **UNAUTHENTICATED** | Initial state; no authentication in progress |
| **AUTHENTICATING** | EAP authentication in progress |
| **AUTHENTICATED** | Authentication succeeded |
| **HELD** | Authentication failed; waiting for heldWhile timer |
| **LOGOFF** | Authentication terminated by client |

## EAPOL Packet Types

| Type | Description |
|---|---|
| **EAPOL-Start** | Supplicant-initiated authentication request |
| **EAPOL-Logoff** | Supplicant termination of authentication |
| **EAPOL-EAP** | EAP message encapsulation |
| **EAPOL-MKA** | MKPDU encapsulation |
| **EAPOL-Announcement** | Network capability and NID advertisement |
| **EAPOL-Announcement-Req** | Solicitation for EAPOL-Announcement |
