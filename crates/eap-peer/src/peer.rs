//! EAP peer core types and state machine.

/// EAP code field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// EAP Request.
    Request,
    /// EAP Response.
    Response,
    /// EAP Success.
    Success,
    /// EAP Failure.
    Failure,
}
