//! # params
//!
//! Ssh config params for host rule

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
    pub ca_signature_algorithms: Option<Vec<String>>,
    /// Specifies a file from which the user's certificate is read
    pub certificate_file: Option<PathBuf>,
    /// Specifies the ciphers allowed for protocol version 2 in order of preference
    pub ciphers: Option<Vec<String>>,
    /// Specifies whether to use compression
    pub compression: Option<bool>,
    /// Specifies the number of attempts to make before exiting
    pub connection_attempts: Option<usize>,
    /// Specifies the timeout used when connecting to the SSH server
    pub connect_timeout: Option<Duration>,
    /// Specifies the host key signature algorithms that the client wants to use in order of preference
    pub host_key_algorithms: Option<Vec<String>>,
    /// Specifies the real host name to log into
    pub host_name: Option<String>,
    /// Specifies the path of the identity file to be used when authenticating.
    /// More than one file can be specified.
    /// If more than one file is specified, they will be read in order
    pub identity_file: Option<Vec<PathBuf>>,
    /// Specifies a pattern-list of unknown options to be ignored if they are encountered in configuration parsing
    pub ignore_unknown: Option<Vec<String>>,
    /// Specifies the available KEX (Key Exchange) algorithms
    pub kex_algorithms: Option<Vec<String>>,
    /// Specifies the MAC (message authentication code) algorithms in order of preference
    pub mac: Option<Vec<String>>,
    /// Specifies the port number to connect on the remote host.
    pub port: Option<u16>,
    /// Specifies the signature algorithms that will be used for public key authentication
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
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
}

impl HostParams {
    /// Return whether `param` is in ignored list
    pub(crate) fn ignored(&self, param: &str) -> bool {
        self.ignore_unknown
            .as_ref()
            .map(|x| x.iter().any(|x| x.as_str() == param))
            .unwrap_or(false)
    }

    /// Override current params with params of `b`
    pub fn merge(&mut self, b: &Self) {
        if let Some(bind_address) = b.bind_address.clone() {
            self.bind_address = Some(bind_address);
        }
        if let Some(bind_interface) = b.bind_interface.clone() {
            self.bind_interface = Some(bind_interface);
        }
        if let Some(ca_signature_algorithms) = b.ca_signature_algorithms.clone() {
            self.ca_signature_algorithms = Some(ca_signature_algorithms);
        }
        if let Some(certificate_file) = b.certificate_file.clone() {
            self.certificate_file = Some(certificate_file);
        }
        if let Some(ciphers) = b.ciphers.clone() {
            self.ciphers = Some(ciphers);
        }
        if let Some(compression) = b.compression {
            self.compression = Some(compression);
        }
        if let Some(connection_attempts) = b.connection_attempts {
            self.connection_attempts = Some(connection_attempts);
        }
        if let Some(connect_timeout) = b.connect_timeout {
            self.connect_timeout = Some(connect_timeout);
        }
        if let Some(host_key_algorithms) = b.host_key_algorithms.clone() {
            self.host_key_algorithms = Some(host_key_algorithms);
        }
        if let Some(host_name) = b.host_name.clone() {
            self.host_name = Some(host_name);
        }
        if let Some(identity_file) = b.identity_file.clone() {
            self.identity_file = Some(identity_file);
        }
        if let Some(ignore_unknown) = b.ignore_unknown.clone() {
            self.ignore_unknown = Some(ignore_unknown);
        }
        if let Some(kex_algorithms) = b.kex_algorithms.clone() {
            self.kex_algorithms = Some(kex_algorithms);
        }
        if let Some(mac) = b.mac.clone() {
            self.mac = Some(mac);
        }
        if let Some(port) = b.port {
            self.port = Some(port);
        }
        if let Some(pubkey_accepted_algorithms) = b.pubkey_accepted_algorithms.clone() {
            self.pubkey_accepted_algorithms = Some(pubkey_accepted_algorithms);
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
        if let Some(user) = b.user.clone() {
            self.user = Some(user);
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_initialize_params() {
        let params = HostParams::default();
        assert!(params.bind_address.is_none());
        assert!(params.bind_interface.is_none());
        assert!(params.ca_signature_algorithms.is_none());
        assert!(params.certificate_file.is_none());
        assert!(params.ciphers.is_none());
        assert!(params.compression.is_none());
        assert!(params.connection_attempts.is_none());
        assert!(params.connect_timeout.is_none());
        assert!(params.host_key_algorithms.is_none());
        assert!(params.host_name.is_none());
        assert!(params.identity_file.is_none());
        assert!(params.ignore_unknown.is_none());
        assert!(params.kex_algorithms.is_none());
        assert!(params.mac.is_none());
        assert!(params.port.is_none());
        assert!(params.pubkey_accepted_algorithms.is_none());
        assert!(params.pubkey_authentication.is_none());
        assert!(params.remote_forward.is_none());
        assert!(params.server_alive_interval.is_none());
        #[cfg(target_os = "macos")]
        assert!(params.use_keychain.is_none());
        assert!(params.tcp_keep_alive.is_none());
    }

    #[test]
    fn should_merge_params() {
        let mut params = HostParams::default();
        let mut b = HostParams::default();
        b.bind_address = Some(String::from("pippo"));
        b.bind_interface = Some(String::from("tun0"));
        b.ca_signature_algorithms = Some(vec![]);
        b.certificate_file = Some(PathBuf::default());
        b.ciphers = Some(vec![]);
        b.compression = Some(true);
        b.connect_timeout = Some(Duration::from_secs(1));
        b.connection_attempts = Some(3);
        b.host_key_algorithms = Some(vec![]);
        b.host_name = Some(String::from("192.168.1.2"));
        b.identity_file = Some(vec![PathBuf::default()]);
        b.ignore_unknown = Some(vec![]);
        b.kex_algorithms = Some(vec![]);
        b.mac = Some(vec![]);
        b.port = Some(22);
        b.pubkey_accepted_algorithms = Some(vec![]);
        b.pubkey_authentication = Some(true);
        b.remote_forward = Some(32);
        b.server_alive_interval = Some(Duration::from_secs(10));
        #[cfg(target_os = "macos")]
        {
            b.use_keychain = Some(true);
        }
        b.tcp_keep_alive = Some(true);
        params.merge(&b);
        assert!(params.bind_address.is_some());
        assert!(params.bind_interface.is_some());
        assert!(params.ca_signature_algorithms.is_some());
        assert!(params.certificate_file.is_some());
        assert!(params.ciphers.is_some());
        assert!(params.compression.is_some());
        assert!(params.connection_attempts.is_some());
        assert!(params.connect_timeout.is_some());
        assert!(params.host_key_algorithms.is_some());
        assert!(params.host_name.is_some());
        assert!(params.identity_file.is_some());
        assert!(params.ignore_unknown.is_some());
        assert!(params.kex_algorithms.is_some());
        assert!(params.mac.is_some());
        assert!(params.port.is_some());
        assert!(params.pubkey_accepted_algorithms.is_some());
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
