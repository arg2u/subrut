use super::host::Host;
use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
};

#[derive(Debug, Clone)]
pub struct Scan {
    pub hosts: Vec<Host>,
    pub wordlist: String,
    pub root_domain: String,
    pub ticks: Arc<AtomicI64>,
}

impl Scan {
    pub fn inc_tick(&self, i: i64) {
        self.ticks.fetch_add(i, Ordering::SeqCst);
    }

    pub fn build_arc_mutex(wordlist_path: PathBuf, domain: String) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Scan::new(wordlist_path, domain)))
    }

    pub fn new(wordlist_path: PathBuf, domain: String) -> Self {
        let wordlist = fs::read_to_string(wordlist_path).unwrap();
        let root_domain = format!("{}.", domain);
        Scan {
            hosts: vec![],
            wordlist,
            root_domain,
            ticks: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn contains(&self, name: &String) -> bool {
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

    pub fn add_ip(&mut self, name: &String, ip: IpAddr) {
        for host in &mut self.hosts {
            if &host.name == name {
                if !host.ips.contains(&ip) {
                    host.ips.push(ip);
                }
            }
        }
    }

    pub fn host_contains_ip(&self, name: &String, ip: &IpAddr) -> bool {
        let host: &Host = self
            .hosts
            .iter()
            .filter(|h| &h.name == name)
            .collect::<Vec<&Host>>()[0];
        if host.ips.contains(ip) {
            return true;
        }
        return false;
    }

    pub fn wordlist_len(&self) -> usize {
        self.wordlist.lines().collect::<Vec<&str>>().len()
    }
}
