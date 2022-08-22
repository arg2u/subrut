//! # Host

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Host struct contains subdomain name and IPs
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Host {
    /// Subdomain
    pub name: String,
    /// IPs
    pub ips: Vec<IpAddr>,
}

/// Initializer implementation
impl Host {
    /// Creates an empty host struct for a provided subdomain.
    /// ```
    /// use subrut::models::host::Host;
    /// Host::new("subdomain.domain.com.".to_string());
    /// ```
    pub fn new(name: String) -> Self {
        Self { name, ips: vec![] }
    }
}
