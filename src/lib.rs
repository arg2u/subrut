use std::sync::MutexGuard;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
pub mod models;
pub mod resolvers;
use models::scan::*;

pub fn run(
    wordslist: String,
    domain: String,
    server: String,
    on_tick: Option<&dyn Fn(&MutexGuard<Scan>)>,
) -> Result<Scan, ()> {
    let wordslist_len = &wordslist.lines().collect::<Vec<&str>>().len();
    let scan = Scan::new_arc_mutex(domain.clone());
    for word in wordslist.lines() {
        let resolver = Scan::get_resolver_config(&server);
        let domain = format!("{}.{}", word, domain);
        let scan = scan.clone();
        tokio::spawn(async move {
            // Resolver Error
            let resolver = TokioAsyncResolver::tokio(resolver, ResolverOpts::default()).unwrap();
            if let Ok(ips) = resolver.lookup_ip(&domain).await {
                let mut scan = scan.lock().unwrap();
                if !scan.contains_host(&domain) {
                    scan.add_host(domain.clone());
                }
                for ip in ips.into_iter() {
                    if !scan.host_contains_ip(&domain, &ip) {
                        scan.add_ip_for_host(&domain, ip)
                    }
                }
            };
            let scan = scan.lock().unwrap();
            scan.inc_tick(1);
        });
    }
    while scan.lock().unwrap().is_tick_available(wordslist_len) {
        if let Some(on_tick) = on_tick {
            on_tick(&scan.lock().unwrap());
        }
    }
    let result = scan.lock().unwrap().clone();
    Ok(result)
}
