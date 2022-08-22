[![Latest Version](https://img.shields.io/crates/v/subrut.svg)](https://crates.io/crates/subrut) | [Documentation](https://docs.rs/subrut)
===

**Subrut** is the super fast tool for brute forcing subdomains. From arg2u with ♥

## **Requirments**
To use Subrut you need to install Cargo and Rust.
Just paste into your terminal window: 
```bash
curl https://sh.rustup.rs -sSf | sh
```

## **Usage**
```bash
subrut [OPTIONS] -d <domain>
```

## **Flags**
```bash
-h, --help       Prints help information
-V, --version    Prints version information
```
## **Options**
```bash
-d <domain>           Domain to scan
-f <file>             Output filepath. If not provided will print results to console [default: ""]
-o <output>           Output format (txt ,json, csv) [default: txt]
-r <resolver>         Resolver (google, quad9, cloudflare) [default: google]
-w <wordslist>        Wordslist file [default: wordslist.txt]
```
## **In-Code Example**

```rust
use subrut::models::error::Error;
#[tokio:main]
async fn main() ->  Result<(), Error> {
    let scan = subrut::run("admin\nips\n".to_string(),"google.com".to_string(), "google".to_string(), None)?;
    println!("JSON = {}", &scan.to_json()?);
    println!("CSV = {}", &scan.to_csv());
    println!("Pure string = {}", &scan.to_string());
    Ok(())
}
```

## **Library Dependecies**
    trust-dns-resolver = "0.21.2"
    tokio = { version = "1", features = ["full"] }
    serde = {version = "1.0.143", features = ["derive"]}
    serde_json = "1.0"

## **Donation**

BTC: 1BXuTySFfiamKSa2GeC7vjDPBE4uxtz3a6

## **License**

MIT
