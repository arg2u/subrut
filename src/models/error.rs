//! # Application errors

/// Error struct
#[derive(Debug)]
pub struct Error {
    /// Error message
    pub err: String,
}

impl From<serde_json::Error> for Error {
    /// Generates error from `serde_json::Error`
    fn from(e: serde_json::Error) -> Self {
        Error { err: e.to_string() }
    }
}

impl From<std::io::Error> for Error {
    /// Generates error from `std::io::Error`
    fn from(e: std::io::Error) -> Self {
        Error { err: e.to_string() }
    }
}

impl From<trust_dns_resolver::error::ResolveError> for Error {
    /// Generates error from `trust_dns_resolver::error::ResolveError`
    fn from(e: trust_dns_resolver::error::ResolveError) -> Self {
        Error { err: e.to_string() }
    }
}
