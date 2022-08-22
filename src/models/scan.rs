//! # Scan

use super::error;
use crate::models::host::Host;
use crate::resolvers;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use trust_dns_resolver::config::ResolverConfig;

/// Scan is a main model in the application.
///
/// It provides all functionality which is related to a brute forcing process.
///
/// It used serde for serialization, and deserialization.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Scan {
    /// List of subdomains for which IP addresses were found
    pub hosts: Vec<Host>,
    /// Scanned domain
    pub domain: String,
    /// Number of scanned subdomains
    pub ticks: i64,
}

/// Initializers implementation
impl Scan {
    /// Creates new instance of Scan for domain.
    /// ```
    /// use subrut::models::scan::Scan;
    /// Scan::new("domain.com".to_string());
    /// ```
    pub fn new(domain: String) -> Self {
        let domain = format!("{}.", domain);
        Scan {
            hosts: vec![],
            domain,
            ticks: 0,
        }
    }
    /// Creates new instance of Arc<Mutex<Scan>> for domain.
    /// ```
    /// use subrut::models::scan::Scan;
    /// Scan::new_arc_mutex("domain.com".to_string());
    /// ```
    pub fn new_arc_mutex(domain: String) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Scan::new(domain)))
    }
}
/// Implements functions for working with the counter of scanned subdomains
impl Scan {
    /// Increment ticks by value
    /// ```
    /// use subrut::models::scan::Scan;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.inc_tick(1);
    /// ```
    pub fn inc_tick(&mut self, i: i64) {
        self.ticks += i;
    }
    /// Checks ticks availability by passing a words count of a wordlist to function.
    ///
    /// Only `ticks < words_count` will return true.
    /// ```
    /// use subrut::models::scan::Scan;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// assert!(scan.is_tick_available(&usize::try_from(1).unwrap()) == true);
    /// ```
    pub fn is_tick_available(&self, len: &usize) -> bool {
        return &usize::try_from(self.ticks).unwrap() < len;
    }
}
/// Implements functions to manipulation with hosts variable
impl Scan {
    /// Checks if hosts vec contains a specific subdomain
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// let host = Host::new("sub.domain.com".to_string());
    /// scan.hosts.push(host);
    /// assert!(scan.contains_host(&"sub.domain.com".to_string()) == true);
    /// ```
    pub fn contains_host(&self, name: &String) -> bool {
        let names = self
            .hosts
            .iter()
            .map(|h| h.name.clone())
            .collect::<Vec<String>>();
        names.contains(&name)
    }
    /// Adds a new host to hosts vec
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// assert!(scan.hosts.len() == 0);
    /// scan.add_host("sub.domain.com".to_string());
    /// assert!(scan.hosts.len() == 1);
    /// ```
    pub fn add_host(&mut self, name: String) {
        let host = Host::new(name);
        self.hosts.push(host);
    }
    /// Adds a new found ip to a specific host
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// assert!(scan.hosts.len() == 0);
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// assert!(scan.hosts[0].ips.len() == 1);
    /// ```
    pub fn add_ip_for_host(&mut self, name: &String, ip: IpAddr) {
        for host in &mut self.hosts {
            if &host.name == name {
                if !host.ips.contains(&ip) {
                    host.ips.push(ip);
                }
            }
        }
    }
    /// Gets a host reference by subdomain name
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// assert!(scan.hosts.len() == 0);
    /// scan.add_host("sub.domain.com".to_string());
    /// let host = scan.get_host_by_name(&"sub.domain.com".to_string());
    /// assert!(host.name == "sub.domain.com".to_string());
    /// ```
    pub fn get_host_by_name(&self, name: &String) -> &Host {
        return self
            .hosts
            .iter()
            .filter(|h| &h.name == name)
            .collect::<Vec<&Host>>()[0];
    }
    /// Checks if there is a host that already contains a specific ip
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// assert!(scan.hosts.len() == 0);
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// assert!(scan.host_contains_ip(&"sub.domain.com".to_string(), &"0.0.0.0".parse().unwrap()) == true);
    /// ```
    pub fn host_contains_ip(&self, name: &String, ip: &IpAddr) -> bool {
        let host: &Host = self.get_host_by_name(name);
        if host.ips.contains(ip) {
            return true;
        }
        return false;
    }
}
/// Implements function to work with DNS resolver
impl Scan {
    /// Returns ResolverConfig for provided name.
    ///
    /// Resolver name has to be one of those variants: google, quad9, cloudflare.
    ///
    /// If you do not provide available resolver name, this function will return google resolver config by default.
    /// ```
    /// use subrut::models::scan::Scan;
    /// Scan::get_resolver_config(&"google".to_string());
    /// Scan::get_resolver_config(&"cloudflare".to_string());
    /// Scan::get_resolver_config(&"quad9".to_string());
    /// Scan::get_resolver_config(&"dugacloud".to_string());
    /// ```
    pub fn get_resolver_config(name: &String) -> ResolverConfig {
        let resolver_config: ResolverConfig;
        if name == resolvers::CLOUDFLARE {
            resolver_config = ResolverConfig::cloudflare();
        } else if name == resolvers::QUAD {
            resolver_config = ResolverConfig::quad9();
        } else {
            resolver_config = ResolverConfig::google();
        }
        resolver_config
    }
}
/// Implements to json conversion functionality
impl Scan {
    /// Converts a scan model into json format
    ///
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// let json = scan.to_json().unwrap();
    /// assert!(json == r#"{"hosts":[{"name":"sub.domain.com","ips":["0.0.0.0"]}],"domain":"domain.com.","ticks":0}"#)
    /// ```
    pub fn to_json(&self) -> Result<String, error::Error> {
        match serde_json::to_string(self) {
            Ok(res) => Ok(res),
            Err(e) => Err(error::Error::from(e)),
        }
    }
}
/// Implements to vec conversion functionality
impl Scan {
    /// Converts a scan model into vec [[domain1, ip1],...,[domainN, ipN]]
    ///
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// let vec = scan.to_vec();
    /// assert!(vec == vec![["sub.domain.com", "0.0.0.0"]]);
    /// ```
    pub fn to_vec(&self) -> Vec<[String; 2]> {
        let mut string_vec = vec![];
        for host in &self.hosts {
            for ip in &host.ips {
                string_vec.push([host.name.clone(), ip.to_string()])
            }
        }
        return string_vec;
    }
}
/// Implements special to string convertors
impl Scan {
    /// Converts a scan model into strting:
    ///
    /// `subdomain1{seprator}ip1`
    ///
    /// ...
    ///
    /// `subdomainN{seprator}ipN`
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// let s = scan.to_string_with_sep(" || ");
    /// assert!(s == "sub.domain.com || 0.0.0.0".to_string());
    /// ```
    pub fn to_string_with_sep(&self, sep: &str) -> String {
        self.to_vec()
            .iter()
            .map(|r| r.join(sep))
            .collect::<Vec<String>>()
            .join("\n")
    }
}
/// Implements basic string convertors
impl ToString for Scan {
    /// Converts a scan model into strting:
    ///
    /// `subdomain1 ip1`
    ///
    /// ...
    ///
    /// `subdomainN ipN`
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// let s = scan.to_string();
    /// assert!(s == "sub.domain.com 0.0.0.0".to_string());
    /// ```
    fn to_string(&self) -> String {
        self.to_string_with_sep(" ")
    }
}
/// Implements to csv convertors
impl Scan {
    /// Converts a scan model into strting:
    /// `Subdomain,Ip`
    /// `subdomain1,ip1`
    ///
    /// ...
    ///
    /// `subdomainN,ipN`
    /// ```
    /// use subrut::models::scan::Scan;
    /// use subrut::models::host::Host;
    /// use std::net::IpAddr;
    /// let mut scan = Scan::new("domain.com".to_string());
    /// scan.add_host("sub.domain.com".to_string());
    /// scan.add_ip_for_host(&"sub.domain.com".to_string(), "0.0.0.0".parse().unwrap());
    /// let s = scan.to_csv();
    /// assert!(s == vec!["Subdomain,Ip".to_string(), "sub.domain.com,0.0.0.0".to_string()].join("\n"));
    /// ```
    pub fn to_csv(&self) -> String {
        return vec!["Subdomain,Ip".to_string(), self.to_string_with_sep(",")].join("\n");
    }
}
