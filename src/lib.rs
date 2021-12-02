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
//! TODO: features and protocols
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
use std::{collections::HashMap, path::PathBuf, time::Duration};

const DEFAULT_HOST_KEY: &str = "*";

// -- modules
mod params;
mod parser;

// -- export
pub use params::HostParams;
pub use parser::{SshParserError, SshParserResult};

/// Describes the ssh configuration.
/// Configuration is describes in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    /// Rulesets for hosts.
    /// Default config will be stored with key `*`
    hosts: HashMap<String, Host>,
}

impl Default for SshConfig {
    fn default() -> Self {
        let mut hosts = HashMap::new();
        hosts.insert(DEFAULT_HOST_KEY.to_string(), Host::default());
        Self { hosts }
    }
}

impl SshConfig {
    /// Query params for a certain host
    pub fn query<S: AsRef<str>>(&self, host: S) -> HostParams {
        let mut params = self.default_params();
        // iter keys
        for (key, config) in self.hosts.iter() {
            if key.as_str() == DEFAULT_HOST_KEY {
                continue;
            }
            let wildmatch = wildmatch::WildMatch::new(key);
            let wild_matched = wildmatch.matches(host.as_ref());
            if wild_matched ^ config.negated {
                // Merge if only one of the two is true
                params.merge(&config.params);
            }
        }
        // return calculated params
        params
    }

    /// Get default params
    pub fn default_params(&self) -> HostParams {
        self.hosts.get("*").map(|x| x.params.clone()).unwrap()
    }

    /// Use ssh default paths, instead of empty options.
    /// This method works only if `home_dir` is supported on guest operating system.
    pub fn default_paths(mut self) -> Self {
        let home_path = match dirs::home_dir() {
            Some(p) => p,
            None => return self,
        };
        // set paths
        self.hosts
            .get_mut("*")
            .unwrap()
            .params
            .default_paths(home_path.as_path());
        self
    }

    /// Parse stream and return parsed configuration or parser error
    pub fn parse(mut self) -> SshParserResult<Self> {
        todo!() // TODO:
    }
}

/// Describes which address family to use when connecting
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Any,
    Inet,
    Inet6,
}

/// Describes the value for gateway_ports
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GatewayPorts {
    No,
    Yes,
    ClientSpecified(String),
}

/// Describes ssh message verbosity
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum LogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug,
    Debug1,
    Debug2,
    Debug3,
}

/// Describes ssh protocol version
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    V1,
    V2,
}

/// Describes the rules to be used for a certain host
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Host {
    pub negated: bool,
    pub params: HostParams,
}
