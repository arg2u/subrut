use indicatif::HumanDuration;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use subrut::models::scan::Scan;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Please provide a name to a query");
        std::process::exit(1);
    }
    let path = PathBuf::from("wordlist_sm.txt");
    let scan = Scan::build_arc_mutex(path, args[1].to_string());
    let pb = progress_bar(scan.clone());
    println!("\nStarting ...");
    subrut::scan(
        scan.clone(),
        Some(&|tick| pb.set_position(tick.try_into().unwrap())),
    );
    pb.finish_with_message(format!(
        "Brute forcing was done in {}.\nFound {} subdomains.",
        HumanDuration(pb.elapsed()),
        &scan.lock().unwrap().hosts.len()
    ));
}

fn progress_bar(scan: Arc<Mutex<Scan>>) -> ProgressBar {
    let pb = ProgressBar::new(scan.lock().unwrap().wordlist_len().try_into().unwrap());
    pb.set_style(
        ProgressStyle::with_template(
            "\n[{elapsed_precise}] {bar:60.cyan/blue} {pos:>7}/{len:7}\n\n{msg}\n\n",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb
}
