//! # params
//!
//! Ssh config params for host rule

mod algos;

use std::collections::HashMap;

pub use self::algos::Algorithms;
use super::{Duration, PathBuf};

/// Describes the ssh configuration.
/// Configuration is describes in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
/// Only arguments supported by libssh2 are implemented
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostParams {
    /// Specifies to use the specified address on the local machine as the source address of the connection
    pub bind_address: Option<String>,
    /// Use the specified address on the local machine as the source address of the connection
    pub bind_interface: Option<String>,
    /// Specifies which algorithms are allowed for signing of certificates by certificate authorities
    pub ca_signature_algorithms: Algorithms,
    /// Specifies a file from which the user's certificate is read
    pub certificate_file: Option<PathBuf>,
    /// Specifies the ciphers allowed for protocol version 2 in order of preference
    pub ciphers: Algorithms,
    /// Specifies whether to use compression
    pub compression: Option<bool>,
    /// Specifies the number of attempts to make before exiting
    pub connection_attempts: Option<usize>,
    /// Specifies the timeout used when connecting to the SSH server
    pub connect_timeout: Option<Duration>,
    /// Specifies the host key signature algorithms that the client wants to use in order of preference
    pub host_key_algorithms: Algorithms,
    /// Specifies the real host name to log into
    pub host_name: Option<String>,
    /// Specifies the path of the identity file to be used when authenticating.
    /// More than one file can be specified.
    /// If more than one file is specified, they will be read in order
    pub identity_file: Option<Vec<PathBuf>>,
    /// Specifies a pattern-list of unknown options to be ignored if they are encountered in configuration parsing
    pub ignore_unknown: Option<Vec<String>>,
    /// Specifies the available KEX (Key Exchange) algorithms
    pub kex_algorithms: Algorithms,
    /// Specifies the MAC (message authentication code) algorithms in order of preference
    pub mac: Algorithms,
    /// Specifies the port number to connect on the remote host.
    pub port: Option<u16>,
    /// Specifies the signature algorithms that will be used for public key authentication
    pub pubkey_accepted_algorithms: Algorithms,
    /// Specifies whether to try public key authentication using SSH keys
    pub pubkey_authentication: Option<bool>,
    /// Specifies that a TCP port on the remote machine be forwarded over the secure channel
    pub remote_forward: Option<u16>,
    /// Sets a timeout interval in seconds after which if no data has been received from the server, keep alive will be sent
    pub server_alive_interval: Option<Duration>,
    /// Specifies whether to send TCP keepalives to the other side
    pub tcp_keep_alive: Option<bool>,
    #[cfg(target_os = "macos")]
    /// specifies whether the system should search for passphrases in the user's keychain when attempting to use a particular key
    pub use_keychain: Option<bool>,
    /// Specifies the user to log in as.
    pub user: Option<String>,
    /// fields that the parser wasn't able to parse
    pub ignored_fields: HashMap<String, Vec<String>>,
    /// fields that the parser was able to parse but ignored
    pub unsupported_fields: HashMap<String, Vec<String>>,
}

impl HostParams {
    /// Return whether a certain `param` is in the ignored list
    pub(crate) fn ignored(&self, param: &str) -> bool {
        self.ignore_unknown
            .as_ref()
            .map(|x| x.iter().any(|x| x.as_str() == param))
            .unwrap_or(false)
    }

    /// Given a [`HostParams`] object `b`, it will overwrite all the params from `self` only if they are [`None`]
    pub fn overwrite_if_none(&mut self, b: &Self) {
        self.bind_address = self.bind_address.clone().or_else(|| b.bind_address.clone());
        self.bind_interface = self
            .bind_interface
            .clone()
            .or_else(|| b.bind_interface.clone());
        self.certificate_file = self
            .certificate_file
            .clone()
            .or_else(|| b.certificate_file.clone());
        self.compression = self.compression.or(b.compression);
        self.connection_attempts = self.connection_attempts.or(b.connection_attempts);
        self.connect_timeout = self.connect_timeout.or(b.connect_timeout);
        self.host_name = self.host_name.clone().or_else(|| b.host_name.clone());
        self.identity_file = self
            .identity_file
            .clone()
            .or_else(|| b.identity_file.clone());
        self.ignore_unknown = self
            .ignore_unknown
            .clone()
            .or_else(|| b.ignore_unknown.clone());
        self.port = self.port.or(b.port);
        self.pubkey_authentication = self.pubkey_authentication.or(b.pubkey_authentication);
        self.remote_forward = self.remote_forward.or(b.remote_forward);
        self.server_alive_interval = self.server_alive_interval.or(b.server_alive_interval);
        #[cfg(target_os = "macos")]
        {
            self.use_keychain = self.use_keychain.or(b.use_keychain);
        }
        self.tcp_keep_alive = self.tcp_keep_alive.or(b.tcp_keep_alive);
        self.user = self.user.clone().or_else(|| b.user.clone());
        for (ignored_field, args) in &b.ignored_fields {
            if !self.ignored_fields.contains_key(ignored_field) {
                self.ignored_fields
                    .insert(ignored_field.to_owned(), args.to_owned());
            }
        }
        for (unsupported_field, args) in &b.unsupported_fields {
            if !self.unsupported_fields.contains_key(unsupported_field) {
                self.unsupported_fields
                    .insert(unsupported_field.to_owned(), args.to_owned());
            }
        }

        // finally merge the algorithms
        self.merge_all_algorithms(b);
    }

    /// Given a [`HostParams`] object `b`, it will overwrite all the params from `self` if they are [`Some`].
    pub fn merge(&mut self, b: &Self) {
        if let Some(bind_address) = b.bind_address.as_deref() {
            self.bind_address = Some(bind_address.to_owned());
        }
        if let Some(bind_interface) = b.bind_interface.as_deref() {
            self.bind_interface = Some(bind_interface.to_owned());
        }
        if let Some(certificate_file) = b.certificate_file.as_deref() {
            self.certificate_file = Some(certificate_file.to_owned());
        }
        if let Some(compression) = b.compression {
            self.compression = Some(compression);
        }
        if let Some(connection_attempts) = b.connection_attempts {
            self.connection_attempts = Some(connection_attempts);
        }
        trace!(
            "wait comparing connect timeout: {:?} {:?}",
            self.connect_timeout, b.connect_timeout
        );
        if let Some(connect_timeout) = b.connect_timeout {
            self.connect_timeout = Some(connect_timeout);
        }
        if let Some(host_name) = b.host_name.as_deref() {
            self.host_name = Some(host_name.to_owned());
        }
        if let Some(identity_file) = b.identity_file.as_deref() {
            self.identity_file = Some(identity_file.to_owned());
        }
        if let Some(ignore_unknown) = b.ignore_unknown.as_deref() {
            self.ignore_unknown = Some(ignore_unknown.to_owned());
        }
        if let Some(port) = b.port {
            self.port = Some(port);
        }
        if let Some(pubkey_authentication) = b.pubkey_authentication {
            self.pubkey_authentication = Some(pubkey_authentication);
        }
        if let Some(remote_forward) = b.remote_forward {
            self.remote_forward = Some(remote_forward);
        }
        if let Some(server_alive_interval) = b.server_alive_interval {
            self.server_alive_interval = Some(server_alive_interval);
        }
        if let Some(tcp_keep_alive) = b.tcp_keep_alive {
            self.tcp_keep_alive = Some(tcp_keep_alive);
        }
        #[cfg(target_os = "macos")]
        if let Some(use_keychain) = b.use_keychain {
            self.use_keychain = Some(use_keychain);
        }
        if let Some(user) = b.user.as_deref() {
            self.user = Some(user.to_owned());
        }
        for (ignored_field, args) in &b.ignored_fields {
            if !self.ignored_fields.contains_key(ignored_field) {
                self.ignored_fields
                    .insert(ignored_field.to_owned(), args.to_owned());
            }
        }

        for (unsupported_field, args) in &b.unsupported_fields {
            if !self.unsupported_fields.contains_key(unsupported_field) {
                self.unsupported_fields
                    .insert(unsupported_field.to_owned(), args.to_owned());
            }
        }

        // finally merge the algorithms
        self.merge_all_algorithms(b);
    }

    /// Given a [`HostParams`] object `b`, it will merge all the algorithms from `self` and `b`.
    ///
    /// The merge is done following the [`resolve_algorithms`] logic
    ///
    /// Reference <https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Ciphers>
    fn merge_all_algorithms(&mut self, b: &Self) {
        self.ca_signature_algorithms
            .merge(&b.ca_signature_algorithms);
        self.ciphers.merge(&b.ciphers);
        self.host_key_algorithms.merge(&b.host_key_algorithms);
        self.kex_algorithms.merge(&b.kex_algorithms);
        self.mac.merge(&b.mac);
        self.pubkey_accepted_algorithms
            .merge(&b.pubkey_accepted_algorithms);
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_initialize_params() {
        let params = HostParams::default();
        assert!(params.bind_address.is_none());
        assert!(params.bind_interface.is_none());
        assert_eq!(params.ca_signature_algorithms, Algorithms::Undefined);
        assert!(params.certificate_file.is_none());
        assert_eq!(params.ciphers, Algorithms::Undefined);
        assert!(params.compression.is_none());
        assert!(params.connection_attempts.is_none());
        assert!(params.connect_timeout.is_none());
        assert_eq!(params.host_key_algorithms, Algorithms::Undefined);
        assert!(params.host_name.is_none());
        assert!(params.identity_file.is_none());
        assert!(params.ignore_unknown.is_none());
        assert_eq!(params.kex_algorithms, Algorithms::Undefined);
        assert_eq!(params.mac, Algorithms::Undefined);
        assert!(params.port.is_none());
        assert_eq!(params.pubkey_accepted_algorithms, Algorithms::Undefined);
        assert!(params.pubkey_authentication.is_none());
        assert!(params.remote_forward.is_none());
        assert!(params.server_alive_interval.is_none());
        #[cfg(target_os = "macos")]
        assert!(params.use_keychain.is_none());
        assert!(params.tcp_keep_alive.is_none());
    }

    #[test]
    fn test_should_overwrite_if_none() {
        let mut params = HostParams::default();
        params.bind_address = Some(String::from("pippo"));
        params.ciphers = Algorithms::Set(vec!["a".to_string(), "b".to_string()]);

        let mut b = HostParams::default();
        b.bind_address = Some(String::from("pluto"));
        b.bind_interface = Some(String::from("tun0"));
        b.ciphers = Algorithms::Set(vec!["c".to_string(), "d".to_string()]);
        b.mac = Algorithms::Set(vec!["e".to_string(), "f".to_string()]);

        params.overwrite_if_none(&b);
        assert_eq!(params.bind_address.unwrap(), "pippo");
        assert_eq!(params.bind_interface.unwrap(), "tun0");

        // algos
        assert_eq!(
            params.ciphers.algos(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(params.mac.algos(), vec!["e".to_string(), "f".to_string()]);
    }

    #[test]
    fn test_should_overwrite_if_none_plus_algos() {
        let mut params = HostParams::default();
        params.ciphers = Algorithms::Set(vec!["a".to_string(), "b".to_string()]);

        let mut b = HostParams::default();
        b.ciphers = Algorithms::Append(vec!["c".to_string(), "d".to_string()]);

        params.overwrite_if_none(&b);

        assert_eq!(
            params.ciphers.algos(),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
    }

    #[test]
    fn test_should_overwrite_if_none_minus_algos() {
        let mut params = HostParams::default();
        params.ciphers = Algorithms::Set(vec!["a".to_string(), "b".to_string()]);

        let mut b = HostParams::default();
        b.ciphers = Algorithms::Exclude(vec!["a".to_string()]);

        params.overwrite_if_none(&b);

        assert_eq!(params.ciphers.algos(), vec!["b".to_string(),]);
    }

    #[test]
    fn should_merge_params() {
        let mut params = HostParams::default();
        let mut b = HostParams {
            bind_address: Some(String::from("pippo")),
            bind_interface: Some(String::from("tun0")),
            ca_signature_algorithms: Algorithms::Undefined,
            certificate_file: Some(PathBuf::default()),
            ciphers: Algorithms::Undefined,
            compression: Some(true),
            connect_timeout: Some(Duration::from_secs(1)),
            connection_attempts: Some(3),
            host_key_algorithms: Algorithms::Undefined,
            host_name: Some(String::from("192.168.1.2")),
            identity_file: Some(vec![PathBuf::default()]),
            ignore_unknown: Some(vec![]),
            kex_algorithms: Algorithms::Undefined,
            mac: Algorithms::Undefined,
            port: Some(22),
            pubkey_accepted_algorithms: Algorithms::Undefined,
            pubkey_authentication: Some(true),
            remote_forward: Some(32),
            server_alive_interval: Some(Duration::from_secs(10)),
            #[cfg(target_os = "macos")]
            use_keychain: Some(true),
            tcp_keep_alive: Some(true),
            ..Default::default()
        };
        params.merge(&b);
        assert!(params.bind_address.is_some());
        assert!(params.bind_interface.is_some());
        assert!(params.certificate_file.is_some());
        assert!(params.compression.is_some());
        assert!(params.connection_attempts.is_some());
        assert!(params.connect_timeout.is_some());
        assert!(params.host_name.is_some());
        assert!(params.identity_file.is_some());
        assert!(params.ignore_unknown.is_some());
        assert!(params.port.is_some());
        assert!(params.pubkey_authentication.is_some());
        assert!(params.remote_forward.is_some());
        assert!(params.server_alive_interval.is_some());
        #[cfg(target_os = "macos")]
        assert!(params.use_keychain.is_some());
        assert!(params.tcp_keep_alive.is_some());
        // merge twices
        b.tcp_keep_alive = None;
        params.merge(&b);
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
    }
}
