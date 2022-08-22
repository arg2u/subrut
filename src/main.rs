use anscape::seq::base::RESET;
use anscape::{seq::colors::*, seq::styles::*};
use indicatif::HumanDuration;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use structopt;
use structopt::StructOpt;
use subrut::models::error::Error as SubrutError;

#[allow(unused)]
#[derive(Debug, StructOpt)]
#[structopt(
    name = "Subrut",
    about = "The super fast tool for brute forcing subdomains."
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
    /// Output format (txt ,json, csv)
    #[structopt(short, default_value = "txt")]
    output: String,
    /// Output filepath. If not provided will print results to console.
    #[structopt(short, default_value = "")]
    file: PathBuf,
}
#[tokio::main]
async fn main() -> Result<(), SubrutError> {
    let opt = Opt::from_args();
    println!("{}{}\nWelcome to Subrut!\n{}", BOLD, GREEN, RESET);
    let wordslist_path = opt.wordslist;
    let domain = opt.domain;
    let output_format = opt.output;
    let output_file = opt.file;
    let resolver = opt.resolver;
    let wordslist = fs::read_to_string(wordslist_path)?;
    let pb = progress_bar(&wordslist);
    println!("{}Domain: {}", BLUE, domain);
    println!("Resolver: {}", resolver);
    println!(
        "{}Words: {}",
        BLUE,
        wordslist.lines().collect::<Vec<&str>>().len()
    );
    println!("Output format: {}", &output_format);
    if !&output_file.to_str().unwrap().is_empty() {
        println!("Output file: {}{}", &output_file.to_str().unwrap(), RESET);
    }
    println!("{}\nStarting to work ...{}", BOLD, RESET);
    let scan = subrut::run(
        wordslist,
        domain,
        resolver,
        Some(&|scan| pb.set_position(scan.ticks.try_into().unwrap())),
    )?;
    pb.finish_with_message(format!(
        "{}Brute forcing was done in {}.\nFound {} subdomains.{}",
        BOLD,
        HumanDuration(pb.elapsed()),
        &scan.hosts.len(),
        RESET,
    ));
    let mut output = scan.to_string();
    match &output_format[..] {
        "json" => output = scan.to_json()?,
        "csv" => output = scan.to_csv().clone(),
        _ => {}
    }
    if output_file.to_str().unwrap().is_empty() {
        println!("{}\n", output);
    } else {
        let mut file = File::create(output_file).unwrap();
        file.write_all(output.as_bytes())?;
    }
    println!("{}{}Did you like the results?", BOLD, MAGENTA);
    println!(
        "Donation(BTC): 1BXuTySFfiamKSa2GeC7vjDPBE4uxtz3a6\n{}",
        RESET
    );
    Ok(())
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
