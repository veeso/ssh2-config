use std::env::args;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use dirs::home_dir;
use ssh2_config::{ParseRule, SshConfig};

fn main() {
    // get args
    let args: Vec<String> = args().collect();
    // check path
    let config_path = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            let mut p = home_dir().expect("Failed to get home_dir for guest OS");
            p.extend(Path::new(".ssh/config"));
            p
        }
    };
    // Open config file
    let config = read_config(config_path.as_path());

    println!("{config}");
}

fn read_config(p: &Path) -> SshConfig {
    let mut reader = match File::open(p) {
        Ok(f) => BufReader::new(f),
        Err(err) => panic!("Could not open file '{}': {}", p.display(), err),
    };
    match SshConfig::default().parse(&mut reader, ParseRule::STRICT) {
        Ok(config) => config,
        Err(err) => panic!("Failed to parse configuration: {}", err),
    }
}
