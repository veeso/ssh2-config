use dirs::home_dir;
use ssh2_config::SshConfig;
use std::env::args;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() {
    // get args
    let args: Vec<String> = args().collect();
    let address = match args.get(1) {
        Some(addr) => addr.to_string(),
        None => {
            usage();
            exit(255)
        }
    };
    // check path
    let config_path = match args.get(2) {
        Some(p) => PathBuf::from(p),
        None => {
            let mut p = home_dir().expect("Failed to get home_dir for guest OS");
            p.extend(Path::new(".ssh/config"));
            p
        }
    };
    // Open config file
    let config = read_config(config_path.as_path());
    let params = config.query(address.as_str());
    println!("Configuration for {}: {:?}", address, params);
}

fn usage() {
    eprintln!("Usage: cargo run --example query -- <address> [config-path]");
}

fn read_config(p: &Path) -> SshConfig {
    let mut reader = match File::open(p) {
        Ok(f) => BufReader::new(f),
        Err(err) => panic!("Could not open file '{}': {}", p.display(), err),
    };
    match SshConfig::default().parse(&mut reader) {
        Ok(config) => config,
        Err(err) => panic!("Failed to parse configuration: {}", err),
    }
}
