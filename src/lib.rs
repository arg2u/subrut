//! Scan Runner

use models::error::Error;
use std::sync::Arc;
use std::sync::MutexGuard;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
pub mod models;
pub mod resolvers;
use models::scan::*;

/// Start scan proccess
/// `wordlist` - read from a file list of subdomains
/// `domain` - root domain to scan, for example google.com
/// `resolver` - google/quad9/cloudflare
/// `on_tick` - callback which handles on one subdomain check completion
/// This function returns isntance of Scan model.
/// ```
/// use subrut::run;
/// 
/// #[tokio::main]
/// async fn main(){
///     let scan = run("admin\nips\n".to_string(),"google.com".to_string(), "google".to_string(), None).unwrap();
///     assert!(scan.contains_host(&"admin.google.com".to_string()) == true);
/// }
/// ```
pub fn run(
    wordslist: String,
    domain: String,
    resolver: String,
    on_tick: Option<&dyn Fn(&MutexGuard<Scan>)>,
) -> Result<Scan, Error> {
    let wordslist_len = &wordslist.lines().collect::<Vec<&str>>().len();
    let scan = Scan::new_arc_mutex(domain.clone());
    let resolver = Scan::get_resolver_config(&resolver);
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        resolver,
        ResolverOpts::default(),
    )?);
    for word in wordslist.lines() {
        let domain = format!("{}.{}", word, domain);
        let scan = scan.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
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
            let mut scan = scan.lock().unwrap();
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
