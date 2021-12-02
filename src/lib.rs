#![crate_name = "ssh2_config"]
#![crate_type = "lib"]

//! # ssh2-config
//!
//! ssh2-config TODO:
//!
//! ## Get started
//!
//! First of you need to add **ssh2-config** to your project dependencies:
//!
//! ```toml
//! ssh2-config = "^0.1.0"
//! ```
//!
//! ## Usage
//!
//! Here is a basic usage example:
//!
//! ```rust
//! ```
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]

/**
 * MIT License
 *
 * ssh2-config - Copyright (c) 2021 Christian Visintin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
use std::{io::BufRead, path::PathBuf, time::Duration};
// -- modules
mod host;
mod params;
mod parser;

// -- export
pub use host::{Host, HostClause};
pub use params::HostParams;
pub use parser::{SshParserError, SshParserResult};

/// Describes the ssh configuration.
/// Configuration is describes in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    /// Rulesets for hosts.
    /// Default config will be stored with key `*`
    hosts: Vec<Host>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            hosts: vec![Host::new(
                vec![HostClause::new(String::from("*"), false)],
                HostParams::default(),
            )],
        }
    }
}

impl SshConfig {
    /// Query params for a certain host
    pub fn query<S: AsRef<str>>(&self, host: S) -> HostParams {
        let mut params = self.default_params();
        // iter keys
        for cfg_host in self.hosts.iter() {
            if cfg_host.intersects(host.as_ref()) {
                params.merge(&cfg_host.params);
            }
        }
        // return calculated params
        params
    }

    /// Get default params
    pub fn default_params(&self) -> HostParams {
        self.hosts.get(0).map(|x| x.params.clone()).unwrap()
    }

    /// Parse stream and return parsed configuration or parser error
    pub fn parse(mut self, reader: &mut impl BufRead) -> SshParserResult<Self> {
        parser::SshConfigParser::parse(&mut self, reader).map(|_| self)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_init_ssh_config() {
        let config = SshConfig::default();
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.default_params(), HostParams::default());
        assert_eq!(config.query("192.168.1.2"), HostParams::default());
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
        assert_eq!(config.query("172.26.104.4"), config.default_params());
    }
}
