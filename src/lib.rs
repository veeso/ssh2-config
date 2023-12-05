#![crate_name = "ssh2_config"]
#![crate_type = "lib"]

//! # ssh2-config
//!
//! ssh2-config a library which provides a parser for the SSH configuration file,
//! to be used in pair with the [ssh2](https://github.com/alexcrichton/ssh2-rs) crate.
//!
//! This library provides a method to parse the configuration file and returns the
//! configuration parsed into a structure.
//! The `SshConfig` structure provides all the attributes which **can** be used to configure the **ssh2 Session**
//! and to resolve the host, port and username.
//!
//! Once the configuration has been parsed you can use the `query(&str)`
//! method to query configuration for a certain host, based on the configured patterns.
//! Even if many attributes are not exposed, since not supported, there is anyway a validation of the configuration,
//! so invalid configuration will result in a parsing error.
//!
//! ## Get started
//!
//! First of you need to add **ssh2-config** to your project dependencies:
//!
//! ```toml
//! ssh2-config = "^0.2.0"
//! ```
//!
//! ## Example
//!
//! Here is a basic example:
//!
//! ```rust
//!
//! use ssh2::Session;
//! use ssh2_config::{HostParams, ParseRule, SshConfig};
//! use std::fs::File;
//! use std::io::BufReader;
//! use std::path::Path;
//!
//! let mut reader = BufReader::new(
//!     File::open(Path::new("./assets/ssh.config"))
//!         .expect("Could not open configuration file")
//! );
//!
//! let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT).expect("Failed to parse configuration");
//!
//! // Query parameters for your host
//! // If there's no rule for your host, default params are returned
//! let params = config.query("192.168.1.2");
//!
//! ```
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;
// -- modules
mod host;
mod params;
mod parser;

// -- export
pub use host::{Host, HostClause};
pub use params::HostParams;
pub use parser::{ParseRule, SshParserError, SshParserResult};

/// Describes the ssh configuration.
/// Configuration is describes in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshConfig {
    /// Rulesets for hosts.
    /// Default config will be stored with key `*`
    hosts: Vec<Host>,
}

impl SshConfig {
    /// Query params for a certain host
    pub fn query<S: AsRef<str>>(&self, host: S) -> HostParams {
        let mut params = HostParams::default();
        // iter keys, merge from lowest to highest precedence
        for cfg_host in self.hosts.iter().rev() {
            if cfg_host.intersects(host.as_ref()) {
                params.merge(&cfg_host.params);
            }
        }
        // return calculated params
        params
    }

    /// Parse stream and return parsed configuration or parser error
    pub fn parse(mut self, reader: &mut impl BufRead, rules: ParseRule) -> SshParserResult<Self> {
        parser::SshConfigParser::parse(&mut self, reader, rules).map(|_| self)
    }

    #[cfg(target_family = "unix")]
    /// Parse ~/.ssh/config file and return parsed configuration or parser error
    pub fn parse_default_file(rules: ParseRule) -> SshParserResult<Self> {
        let ssh_folder = dirs::home_dir()
            .ok_or_else(|| {
                SshParserError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Home folder not found",
                ))
            })?
            .join(".ssh");

        let mut reader =
            BufReader::new(File::open(ssh_folder.join("config")).map_err(SshParserError::Io)?);

        Self::default().parse(&mut reader, rules)
    }

    pub fn get_hosts(&self) -> &Vec<Host> {
        &self.hosts
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_init_ssh_config() {
        let config = SshConfig::default();
        assert_eq!(config.hosts.len(), 0);
        assert_eq!(config.query("192.168.1.2"), HostParams::default());
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn should_parse_default_config() {
        assert!(SshConfig::parse_default_file(ParseRule::ALLOW_UNKNOWN_FIELDS).is_ok());
    }

    #[test]
    fn should_parse_config() {
        use std::fs::File;
        use std::io::BufReader;
        use std::path::Path;

        let mut reader = BufReader::new(
            File::open(Path::new("./assets/ssh.config"))
                .expect("Could not open configuration file"),
        );

        assert!(SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .is_ok());
    }

    #[test]
    fn should_query_ssh_config() {
        let mut config = SshConfig::default();
        // add config
        let mut params1 = HostParams::default();
        params1.bind_address = Some(String::from("0.0.0.0"));
        config.hosts.push(Host::new(
            vec![HostClause::new(String::from("192.168.*.*"), false)],
            params1.clone(),
        ));
        let mut params2 = HostParams::default();
        params2.bind_interface = Some(String::from("tun0"));
        config.hosts.push(Host::new(
            vec![HostClause::new(String::from("192.168.10.*"), false)],
            params2.clone(),
        ));
        let mut params3 = HostParams::default();
        params3.host_name = Some(String::from("172.26.104.4"));
        config.hosts.push(Host::new(
            vec![
                HostClause::new(String::from("172.26.*.*"), false),
                HostClause::new(String::from("172.26.104.4"), true),
            ],
            params3.clone(),
        ));
        // Query
        assert_eq!(config.query("192.168.1.32"), params1);
        // merged case
        params1.merge(&params2);
        assert_eq!(config.query("192.168.10.1"), params1);
        // Negated case
        assert_eq!(config.query("172.26.254.1"), params3);
        assert_eq!(config.query("172.26.104.4"), HostParams::default());
    }
}
