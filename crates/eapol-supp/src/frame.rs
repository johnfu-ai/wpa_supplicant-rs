//! EAPOL frame types and parsing.

/// EAPOL packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolPacketType {
    /// EAP Packet.
    EapPacket,
    /// EAPOL-Start.
    EapolStart,
    /// EAPOL-Logoff.
    EapolLogoff,
    /// EAPOL-Key.
    EapolKey,
    /// EAPOL-Encapsulated-ASF-Alert.
    AsfAlert,
}
