use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
pub mod models;
use models::scan::*;

pub fn scan(scan: Arc<Mutex<Scan>>, on_tick: Option<&dyn Fn(i64)>) {
    let locked_scan = &scan.lock().unwrap().to_owned();
    let wordlist = &locked_scan.wordlist;
    let wordlist_len = &locked_scan.wordlist_len();
    let root_domain = &locked_scan.root_domain;
    for word in wordlist.lines() {
        let scan = scan.clone();
        let domain = format!("{}.{}", word, root_domain);
        tokio::spawn(async move {
            let resolver =
                TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default())
                    .unwrap();
            match resolver.lookup_ip(&domain).await {
                Ok(ips) => {
                    let mut scan = scan.lock().unwrap();
                    if !scan.contains(&domain) {
                        scan.add_host(domain.clone());
                    }
                    for ip in ips.into_iter() {
                        if !scan.host_contains_ip(&domain, &ip) {
                            scan.add_ip(&domain, ip)
                        }
                    }
                    scan.inc_tick(1);
                }
                Err(_) => {
                    let scan = scan.lock().unwrap();
                    scan.inc_tick(1);
                }
            };
        });
    }
    while &usize::try_from(locked_scan.ticks.load(Ordering::SeqCst)).unwrap() < wordlist_len {
        if on_tick.is_some() {
            on_tick.unwrap()(locked_scan.ticks.load(Ordering::SeqCst));
        }
    }
}
