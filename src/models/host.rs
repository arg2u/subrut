use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Host {
    pub name: String,
    pub ips: Vec<IpAddr>,
}

impl Host {
    pub fn new(name: String) -> Self {
        Self { name, ips: vec![] }
    }
}