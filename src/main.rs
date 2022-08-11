use indicatif::HumanDuration;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::fs;
use std::path::PathBuf;
use structopt;
use structopt::StructOpt;

#[allow(unused)]
#[derive(Debug, StructOpt)]
#[structopt(
    name = "Subrut",
    about = "This is the tool for brute forcing subdomains."
)]
struct Opt {
    /// Domain to scan
    #[structopt(short)]
    domain: String,
    /// Wordslist file
    #[structopt(short, parse(from_os_str), default_value = "wordslist.txt")]
    wordslist: PathBuf,
    /// Resolver (google, quad9, cloudflare)
    #[structopt(short, default_value = "google")]
    resolver: String,
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    println!("\nWelcome to Subrut!\n");
    let wordslist_path = opt.wordslist;
    let domain = opt.domain;
    let resolver = opt.resolver;
    // IO Error
    let wordslist = fs::read_to_string(wordslist_path).unwrap();
    let pb = progress_bar(&wordslist);
    println!("Domain: {}", domain);
    println!("Resolver: {}", resolver);
    println!("\nSpawning threads ...");
    let scan = subrut::run(
        wordslist,
        domain,
        resolver,
        Some(&|scan| pb.set_position(scan.get_ticks_count().try_into().unwrap())),
    )
    .unwrap();
    pb.finish_with_message(format!(
        "Brute forcing was done in {}.\nFound {} subdomains.",
        HumanDuration(pb.elapsed()),
        &scan.hosts.len()
    ));
}

fn progress_bar(wordslist: &String) -> ProgressBar {
    let len = wordslist.lines().collect::<Vec<&str>>().len();
    let pb = ProgressBar::new(len.try_into().unwrap());
    pb.set_style(
        ProgressStyle::with_template(
            "\n[{elapsed_precise}] {bar:60.cyan/blue} {pos:>7}/{len:7}\n\n{msg}\n\n",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb
}
