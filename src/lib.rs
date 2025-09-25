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
//! ssh2-config = "^0.6"
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
//! // ...
//!
//! // serialize configuration to string
//! let s = config.to_string();
//!
//! ```
//!
//! ---
//!
//! ## How host parameters are resolved
//!
//! This topic has been debated a lot over the years, so finally since 0.5 this has been fixed to follow the official ssh configuration file rules, as described in the MAN <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#DESCRIPTION>.
//!
//! > Unless noted otherwise, for each parameter, the first obtained value will be used. The configuration files contain sections separated by Host specifications, and that section is only applied for hosts that match one of the patterns given in the specification. The matched host name is usually the one given on the command line (see the CanonicalizeHostname option for exceptions).
//! >
//! > Since the first obtained value for each parameter is used, more host-specific declarations should be given near the beginning of the file, and general defaults at the end.
//!
//! This means that:
//!
//! 1. The first obtained value parsing the configuration top-down will be used
//! 2. Host specific rules ARE not overriding default ones if they are not the first obtained value
//! 3. If you want to achieve default values to be less specific than host specific ones, you should put the default values at the end of the configuration file using `Host *`.
//! 4. Algorithms, so `KexAlgorithms`, `Ciphers`, `MACs` and `HostKeyAlgorithms` use a different resolvers which supports appending, excluding and heading insertions, as described in the man page at ciphers: <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Ciphers>.
//!
//! ### Resolvers examples
//!
//! ```ssh
//! Compression yes
//!
//! Host 192.168.1.1
//!     Compression no
//! ```
//!
//! If we get rules for `192.168.1.1`, compression will be `yes`, because it's the first obtained value.
//!
//! ```ssh
//! Host 192.168.1.1
//!     Compression no
//!
//! Host *
//!     Compression yes
//! ```
//!
//! If we get rules for `192.168.1.1`, compression will be `no`, because it's the first obtained value.
//!
//! If we get rules for `172.168.1.1`, compression will be `yes`, because it's the first obtained value MATCHING the host rule.
//!
//! ```ssh
//!
//! Host 192.168.1.1
//!     Ciphers +c
//! ```
//!
//! If we get rules for `192.168.1.1`, ciphers will be `c` appended to default algorithms, which can be specified in the [`SshConfig`] constructor.
//!
//! ## Configuring default algorithms
//!
//! When you invoke [`SshConfig::default`], the default algorithms are set from openssh source code, which are the following:
//!
//! ```txt
//! ca_signature_algorithms:
//!     "ssh-ed25519",
//!     "ecdsa-sha2-nistp256",
//!     "ecdsa-sha2-nistp384",
//!     "ecdsa-sha2-nistp521",
//!     "sk-ssh-ed25519@openssh.com",
//!     "sk-ecdsa-sha2-nistp256@openssh.com",
//!     "rsa-sha2-512",
//!     "rsa-sha2-256",
//!
//! ciphers:
//!     "chacha20-poly1305@openssh.com",
//!     "aes128-ctr,aes192-ctr,aes256-ctr",
//!     "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
//!
//! host_key_algorithms:
//!     "ssh-ed25519-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp384-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp521-cert-v01@openssh.com",
//!     "sk-ssh-ed25519-cert-v01@openssh.com",
//!     "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "rsa-sha2-512-cert-v01@openssh.com",
//!     "rsa-sha2-256-cert-v01@openssh.com",
//!     "ssh-ed25519",
//!     "ecdsa-sha2-nistp256",
//!     "ecdsa-sha2-nistp384",
//!     "ecdsa-sha2-nistp521",
//!     "sk-ssh-ed25519@openssh.com",
//!     "sk-ecdsa-sha2-nistp256@openssh.com",
//!     "rsa-sha2-512",
//!     "rsa-sha2-256",
//!
//! kex_algorithms:
//!     "sntrup761x25519-sha512",
//!     "sntrup761x25519-sha512@openssh.com",
//!     "mlkem768x25519-sha256",
//!     "curve25519-sha256",
//!     "curve25519-sha256@libssh.org",
//!     "ecdh-sha2-nistp256",
//!     "ecdh-sha2-nistp384",
//!     "ecdh-sha2-nistp521",
//!     "diffie-hellman-group-exchange-sha256",
//!     "diffie-hellman-group16-sha512",
//!     "diffie-hellman-group18-sha512",
//!     "diffie-hellman-group14-sha256",
//!     "ssh-ed25519-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp384-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp521-cert-v01@openssh.com",
//!     "sk-ssh-ed25519-cert-v01@openssh.com",
//!     "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "rsa-sha2-512-cert-v01@openssh.com",
//!     "rsa-sha2-256-cert-v01@openssh.com",
//!     "ssh-ed25519",
//!     "ecdsa-sha2-nistp256",
//!     "ecdsa-sha2-nistp384",
//!     "ecdsa-sha2-nistp521",
//!     "sk-ssh-ed25519@openssh.com",
//!     "sk-ecdsa-sha2-nistp256@openssh.com",
//!     "rsa-sha2-512",
//!     "rsa-sha2-256",
//!     "chacha20-poly1305@openssh.com",
//!     "aes128-ctr,aes192-ctr,aes256-ctr",
//!     "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
//!     "chacha20-poly1305@openssh.com",
//!     "aes128-ctr,aes192-ctr,aes256-ctr",
//!     "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
//!     "umac-64-etm@openssh.com",
//!     "umac-128-etm@openssh.com",
//!     "hmac-sha2-256-etm@openssh.com",
//!     "hmac-sha2-512-etm@openssh.com",
//!     "hmac-sha1-etm@openssh.com",
//!     "umac-64@openssh.com",
//!     "umac-128@openssh.com",
//!     "hmac-sha2-256",
//!     "hmac-sha2-512",
//!     "hmac-sha1",
//!     "umac-64-etm@openssh.com",
//!     "umac-128-etm@openssh.com",
//!     "hmac-sha2-256-etm@openssh.com",
//!     "hmac-sha2-512-etm@openssh.com",
//!     "hmac-sha1-etm@openssh.com",
//!     "umac-64@openssh.com",
//!     "umac-128@openssh.com",
//!     "hmac-sha2-256",
//!     "hmac-sha2-512",
//!     "hmac-sha1",
//!     "none,zlib@openssh.com",
//!     "none,zlib@openssh.com",
//!
//! mac:
//!     "umac-64-etm@openssh.com",
//!     "umac-128-etm@openssh.com",
//!     "hmac-sha2-256-etm@openssh.com",
//!     "hmac-sha2-512-etm@openssh.com",
//!     "hmac-sha1-etm@openssh.com",
//!     "umac-64@openssh.com",
//!     "umac-128@openssh.com",
//!     "hmac-sha2-256",
//!     "hmac-sha2-512",
//!     "hmac-sha1",
//!
//! pubkey_accepted_algorithms:
//!     "ssh-ed25519-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp384-cert-v01@openssh.com",
//!     "ecdsa-sha2-nistp521-cert-v01@openssh.com",
//!     "sk-ssh-ed25519-cert-v01@openssh.com",
//!     "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
//!     "rsa-sha2-512-cert-v01@openssh.com",
//!     "rsa-sha2-256-cert-v01@openssh.com",
//!     "ssh-ed25519",
//!     "ecdsa-sha2-nistp256",
//!     "ecdsa-sha2-nistp384",
//!     "ecdsa-sha2-nistp521",
//!     "sk-ssh-ed25519@openssh.com",
//!     "sk-ecdsa-sha2-nistp256@openssh.com",
//!     "rsa-sha2-512",
//!     "rsa-sha2-256",
//! ```
//!
//! If you want you can use a custom constructor [`SshConfig::default_algorithms`] to set your own default algorithms.

#![doc(html_playground_url = "https://play.rust-lang.org")]

#[macro_use]
extern crate log;

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;
// -- modules
mod default_algorithms;
mod host;
mod params;
mod parser;
mod serializer;

// -- export
pub use self::default_algorithms::DefaultAlgorithms;
pub use self::host::{Host, HostClause};
pub use self::params::{Algorithms, HostParams};
pub use self::parser::{ParseRule, SshParserError, SshParserResult};

/// Describes the ssh configuration.
/// Configuration is described in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshConfig {
    /// Default algorithms for ssh.
    default_algorithms: DefaultAlgorithms,
    /// Rulesets for hosts.
    /// Default config will be stored with key `*`
    hosts: Vec<Host>,
}

impl fmt::Display for SshConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        serializer::SshConfigSerializer::from(self).serialize(f)
    }
}

impl SshConfig {
    /// Constructs a new [`SshConfig`] from a list of [`Host`]s.
    ///
    /// You can later also set the [`DefaultAlgorithms`] using [`SshConfig::default_algorithms`].
    ///
    /// ```rust
    /// use ssh2_config::{DefaultAlgorithms, Host, SshConfig};
    ///
    /// let config = SshConfig::from_hosts(vec![/* put your hosts here */]).default_algorithms(DefaultAlgorithms::default());
    /// ```
    pub fn from_hosts(hosts: Vec<Host>) -> Self {
        Self {
            default_algorithms: DefaultAlgorithms::default(),
            hosts,
        }
    }

    /// Query params for a certain host. Returns [`HostParams`] for the host.
    pub fn query<S: AsRef<str>>(&self, pattern: S) -> HostParams {
        let mut params = HostParams::new(&self.default_algorithms);
        // iter keys, overwrite if None top-down
        for host in self.hosts.iter() {
            if host.intersects(pattern.as_ref()) {
                debug!(
                    "Merging params for host: {:?} into params {params:?}",
                    host.pattern
                );
                params.overwrite_if_none(&host.params);
                trace!("Params after merge: {params:?}");
            }
        }
        // return calculated params
        params
    }

    /// Get an iterator over the [`Host`]s which intersect with the given host pattern
    pub fn intersecting_hosts(&self, pattern: &str) -> impl Iterator<Item = &'_ Host> {
        self.hosts.iter().filter(|host| host.intersects(pattern))
    }

    /// Set default algorithms for ssh.
    ///
    /// If you want to use the default algorithms from the system, you can use the `Default::default()` method.
    pub fn default_algorithms(mut self, algos: DefaultAlgorithms) -> Self {
        self.default_algorithms = algos;

        self
    }

    /// Parse [`SshConfig`] from stream which implements [`BufRead`] and return parsed configuration or parser error
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let mut reader = BufReader::new(
    ///    File::open(Path::new("./assets/ssh.config"))
    ///       .expect("Could not open configuration file")
    /// );
    ///
    /// let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT).expect("Failed to parse configuration");
    /// ```
    pub fn parse(mut self, reader: &mut impl BufRead, rules: ParseRule) -> SshParserResult<Self> {
        parser::SshConfigParser::parse(&mut self, reader, rules, None).map(|_| self)
    }

    /// Parse `~/.ssh/config`` file and return parsed configuration [`SshConfig`] or parser error
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

    /// Get list of [`Host`]s in the configuration
    pub fn get_hosts(&self) -> &Vec<Host> {
        &self.hosts
    }
}

#[cfg(test)]
fn test_log() {
    use std::sync::Once;

    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();
    });
}

#[cfg(test)]
mod tests {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_init_ssh_config() {
        test_log();

        let config = SshConfig::default();
        assert_eq!(config.hosts.len(), 0);
        assert_eq!(
            config.query("192.168.1.2"),
            HostParams::new(&DefaultAlgorithms::default())
        );
    }

    #[test]
    fn should_parse_default_config() -> Result<(), parser::SshParserError> {
        test_log();

        let _config = SshConfig::parse_default_file(ParseRule::ALLOW_UNKNOWN_FIELDS)?;
        Ok(())
    }

    #[test]
    fn should_parse_config() -> Result<(), parser::SshParserError> {
        test_log();

        use std::fs::File;
        use std::io::BufReader;
        use std::path::Path;

        let mut reader = BufReader::new(
            File::open(Path::new("./assets/ssh.config"))
                .expect("Could not open configuration file"),
        );

        SshConfig::default().parse(&mut reader, ParseRule::STRICT)?;

        Ok(())
    }

    #[test]
    fn should_query_ssh_config() {
        test_log();

        let mut config = SshConfig::default();
        // add config
        let mut params1 = HostParams::new(&DefaultAlgorithms::default());
        params1.bind_address = Some("0.0.0.0".to_string());
        config.hosts.push(Host::new(
            vec![HostClause::new(String::from("192.168.*.*"), false)],
            params1.clone(),
        ));
        let mut params2 = HostParams::new(&DefaultAlgorithms::default());
        params2.bind_interface = Some(String::from("tun0"));
        config.hosts.push(Host::new(
            vec![HostClause::new(String::from("192.168.10.*"), false)],
            params2.clone(),
        ));

        let mut params3 = HostParams::new(&DefaultAlgorithms::default());
        params3.host_name = Some("172.26.104.4".to_string());
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
        params1.overwrite_if_none(&params2);
        assert_eq!(config.query("192.168.10.1"), params1);
        // Negated case
        assert_eq!(config.query("172.26.254.1"), params3);
        assert_eq!(
            config.query("172.26.104.4"),
            HostParams::new(&DefaultAlgorithms::default())
        );
    }
}
