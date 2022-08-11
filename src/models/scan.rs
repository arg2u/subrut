use crate::models::host::Host;
use crate::resolvers;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
};
use trust_dns_resolver::config::ResolverConfig;

#[derive(Debug, Clone)]
pub struct Scan {
    pub hosts: Vec<Host>,
    pub domain: String,
    pub ticks: Arc<AtomicI64>,
}

impl Scan {
    pub fn new(domain: String) -> Self {
        let domain = format!("{}.", domain);
        Scan {
            hosts: vec![],
            domain,
            ticks: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn new_arc_mutex(domain: String) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Scan::new(domain)))
    }
}

impl Scan {
    pub fn inc_tick(&self, i: i64) {
        self.ticks.fetch_add(i, Ordering::SeqCst);
    }

    pub fn is_tick_available(&self, len: &usize) -> bool {
        &usize::try_from(self.ticks.load(Ordering::SeqCst)).unwrap() < len
    }

    pub fn get_ticks_count(&self) -> i64 {
        self.ticks.load(Ordering::SeqCst)
    }
}

impl Scan {
    pub fn contains_host(&self, name: &String) -> bool {
        let names = self
            .hosts
            .iter()
            .map(|h| h.name.clone())
            .collect::<Vec<String>>();
        names.contains(&name)
    }

    pub fn add_host(&mut self, name: String) {
        let host = Host::new(name);
        self.hosts.push(host);
    }

    pub fn add_ip_for_host(&mut self, name: &String, ip: IpAddr) {
        for host in &mut self.hosts {
            if &host.name == name {
                if !host.ips.contains(&ip) {
                    host.ips.push(ip);
                }
            }
        }
    }

    pub fn get_host_by_name(&self, name: &String) -> &Host {
        return self
            .hosts
            .iter()
            .filter(|h| &h.name == name)
            .collect::<Vec<&Host>>()[0];
    }

    pub fn host_contains_ip(&self, name: &String, ip: &IpAddr) -> bool {
        let host: &Host = self.get_host_by_name(name);
        if host.ips.contains(ip) {
            return true;
        }
        return false;
    }
}

impl Scan {
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
