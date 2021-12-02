//! # params
//!
//! Ssh config params for host rule

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
use super::{AddressFamily, Duration, GatewayPorts, LogLevel, PathBuf, ProtocolVersion};

use std::path::Path;

/// Describes the ssh configuration.
/// Configuration is describes in this document: <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostParams {
    /// Specifies whether keys should be automatically added to a running ssh-agent
    pub add_keys_to_agent: Option<bool>,
    /// Specifies which address family to use when connecting.
    pub address_family: Option<AddressFamily>,
    /// If set to yes, passphrase/password querying will be disabled.
    /// This is useful for running the ssh client from shell script that do not have an interactive user,
    /// and prevents accidentally blocking on a password prompt.
    pub batch_mode: Option<bool>,
    /// Specifies to use the specified address on the local machine as the source address of the connection
    pub bind_address: Option<String>,
    /// Use the specified address on the local machine as the source address of the connection
    pub bind_interface: Option<String>,
    /// Specifies which algorithms are allowed for signing of certificates by certificate authorities
    pub ca_signature_algorithms: Option<Vec<String>>,
    /// Specifies a file from which the user's certificate is read
    pub certificate_file: Option<PathBuf>,
    /// Directs ssh to additionally check the host IP address in the known_hosts file.
    pub check_host_ip: Option<bool>,
    /// Specifies that all local, remote, and dynamic port forwardings specified in the configuration files or on the command line be cleared
    pub clear_all_forwardings: Option<bool>,
    /// Specifies the ciphers allowed for protocol version 2 in order of preference
    pub ciphers: Option<Vec<String>>,
    /// Specifies whether to use compression
    pub compression: Option<bool>,
    /// Specifies the number of attempts to make before exiting
    pub connection_attemps: Option<usize>,
    /// Specifies the timeout used when connecting to the SSH server
    pub connect_timeout: Option<Duration>,
    /// Enables the sharing of multiple sessions over a single network connection
    pub control_master: Option<bool>,
    /// Specify the path to the control socket used for connection sharing as described in the ControlMaster section above or the string none to disable connection sharing
    pub control_path: Option<PathBuf>,
    /// Specifies that a TCP port on the local machine be forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine
    pub dynamic_forward: Option<u16>,
    /// Sets the escape character
    pub escape_char: Option<char>,
    /// Specifies whether ssh should terminate the connection if it cannot set up all requested dynamic, tunnel, local, and remote port forwardings
    pub exit_on_forward_failure: Option<bool>,
    /// Specifies whether the connection to the authentication agent will be forwarded to the remote machine
    pub forward_agent: Option<bool>,
    /// Specifies whether X11 connections will be automatically redirected over the secure channel and DISPLAY set
    pub forward_x11: Option<bool>,
    /// If this option is set to yes, remote X11 clients will have full access to the original X11 display
    pub forward_x11_trusted: Option<bool>,
    /// Specifies whether remote hosts are allowed to connect to local forwarded ports
    pub gateway_ports: Option<GatewayPorts>,
    /// Specifies a file to use for the global host key database
    pub global_known_hosts_file: Option<PathBuf>,
    /// Specifies whether user authentication based on [GSSAPI](https://datatracker.ietf.org/doc/html/rfc2743) is allowed
    pub gssapi_authentication: Option<String>,
    /// Specifies whether key exchange based on GSSAPI may be used
    pub gssapi_key_exchange: Option<String>,
    /// If set, specifies the GSSAPI client identity that ssh should use when connecting to the server
    pub gssapi_client_identity: Option<String>,
    /// Forward (delegate) credentials to the server
    pub gssapi_delegate_credentials: Option<bool>,
    /// If set to yes then renewal of the client's GSSAPI credentials will force the rekeying of the ssh connection
    pub gssapi_renewal_forces_rekey: Option<bool>,
    /// Set to yes to indicate that the DNS is trusted to securely canonicalize the name of the host being connected to.
    /// If no, the hostname entered on the command line will be passed untouched to the GSSAPI library.
    pub gssapi_trust_dns: Option<bool>,
    /// Indicates that ssh should hash host names and addresses when they are added to ~/.ssh/known_hosts
    pub hash_known_hosts: Option<bool>,
    /// Specifies whether to try rhosts based authentication with public key authentication, using the .rhosts or .shosts files in the user's home directory
    /// and /etc/hosts.equiv and /etc/shosts.equiv in global configuration
    pub hostbased_authentication: Option<bool>,
    /// Specifies the protocol version 2 host key algorithms that the client wants to use in order of preference
    pub host_key_algorithms: Option<Vec<String>>,
    /// Specifies an alias that should be used instead of the real host name when looking up or saving the host key in the host key database files
    pub host_key_alias: Option<String>,
    /// Specifies the real host name to log into
    pub host_name: Option<String>,
    /// Specifies that ssh should only use the identity keys configured in the ssh_config files, even if ssh-agent offers more identities.
    pub identities_only: Option<bool>,
    /// Specifies a file from which the user's identity key is read when using public key authentication
    pub identity_file: Option<PathBuf>,
    /// Specifies the available KEX (Key Exchange) algorithms
    pub kex_algorithms: Option<Vec<String>>,
    /// Specifies whether to use keyboard-interactive authentication
    pub kbd_interactive_authentication: Option<bool>,
    /// Specifies the list of methods to use in keyboard-interactive authentication
    pub kbd_interactive_devices: Option<Vec<String>>,
    /// Specifies a command to execute on the local machine after successfully connecting to the server
    pub local_command: Option<String>,
    /// Specifies that a TCP port on the local machine be forwarded over the secure channel to the specified host and port from the remote machine
    pub local_forward: Option<String>,
    /// Specifies the verbosity of logging messages from ssh.
    pub log_level: Option<LogLevel>,
    /// Specifies the MAC (message authentication code) algorithms in order of preference
    pub mac: Option<Vec<String>>,
    /// This option can be used if the home directory is shared across machines
    pub no_host_authentication_for_localhost: Option<bool>,
    /// Specifies the order in which the client should try protocol 2 authentication methods
    pub preferred_authentications: Option<String>,
    /// Specifies the protocol versions in order of preference.
    pub protocol: Option<Vec<ProtocolVersion>>,
    /// Specifies the command to use to connect to the server
    pub proxy_command: Option<String>,
    /// Specifies the signature algorithms that will be used for public key authentication
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
    /// Specifies whether to try public key authentication using SSH keys
    pub pubkey_authentication: Option<bool>,
    /// Specifies that a TCP port on the remote machine be forwarded over the secure channel to the specified host and port from the local machine
    pub remote_forward: Option<String>,
    /// Specifies what environment variables should be sent to the server
    pub send_env: Option<Vec<String>>,
    /// Sets the number of keepalive messages that may be sent by the client without the client receiving any messages back from the server
    pub server_alive_count_max: Option<usize>,
    /// Specifies interval for sending keepalive messages to the server
    pub server_alive_interval: Option<Duration>,
    /// Specifies which smartcard device to use
    pub smartcard_device: Option<String>,
    /// Specifies if ssh should never automatically add host keys to the ~/.ssh/known_hosts file, and refuses to connect to hosts whose host key has changed
    pub strict_host_key_checking: Option<bool>,
    /// Specifies whether to send TCP keepalives to the other side
    pub tcp_keep_alive: Option<bool>,
    /// If yes, request tun device forwarding between the client and the server. This used for implementing a VPN over SSH
    pub tunnel: Option<bool>,
    /// Specifies the tun devices to open on the client (local_tun) and the server (remote_tun).
    pub tunnel_device: Option<(String, Option<String>)>,
    /// Specifies a file to use for per-user known host key database instead of the default ~/.ssh/known_hosts
    pub user_known_hosts_file: Option<PathBuf>,
    /// Specifies whether to verify the remote key using DNS and SSHFP resource records
    pub verify_host_key_dns: Option<bool>,
    /// Specifies whether an ASCII art representation of the remote host key fingerprint is printed in addition to the hex fingerprint string at login and for unknown host keys
    pub visual_host_key: Option<bool>,
}

impl HostParams {
    /// Set default paths according to ssh specifications
    pub fn default_paths(&mut self, home_dir: &Path) {
        todo!()
    }

    /// Override current params with params of `b`
    pub fn merge(&mut self, b: &Self) {
        if let Some(add_keys_to_agent) = b.add_keys_to_agent.clone() {
            self.add_keys_to_agent = Some(add_keys_to_agent);
        }
        if let Some(address_family) = b.address_family.clone() {
            self.address_family = Some(address_family);
        }
        if let Some(batch_mode) = b.batch_mode.clone() {
            self.batch_mode = Some(batch_mode);
        }
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
        if let Some(check_host_ip) = b.check_host_ip.clone() {
            self.check_host_ip = Some(check_host_ip);
        }
        if let Some(ciphers) = b.ciphers.clone() {
            self.ciphers = Some(ciphers);
        }
        if let Some(clear_all_forwardings) = b.clear_all_forwardings.clone() {
            self.clear_all_forwardings = Some(clear_all_forwardings);
        }
        if let Some(compression) = b.compression.clone() {
            self.compression = Some(compression);
        }
        if let Some(connection_attemps) = b.connection_attemps.clone() {
            self.connection_attemps = Some(connection_attemps);
        }
        if let Some(connect_timeout) = b.connect_timeout.clone() {
            self.connect_timeout = Some(connect_timeout);
        }
        if let Some(control_master) = b.control_master.clone() {
            self.control_master = Some(control_master);
        }
        if let Some(control_path) = b.control_path.clone() {
            self.control_path = Some(control_path);
        }
        if let Some(dynamic_forward) = b.dynamic_forward.clone() {
            self.dynamic_forward = Some(dynamic_forward);
        }
        if let Some(escape_char) = b.escape_char.clone() {
            self.escape_char = Some(escape_char);
        }
        if let Some(exit_on_forward_failure) = b.exit_on_forward_failure.clone() {
            self.exit_on_forward_failure = Some(exit_on_forward_failure);
        }
        if let Some(forward_agent) = b.forward_agent.clone() {
            self.forward_agent = Some(forward_agent);
        }
        if let Some(forward_x11) = b.forward_x11.clone() {
            self.forward_x11 = Some(forward_x11);
        }
        if let Some(forward_x11_trusted) = b.forward_x11_trusted.clone() {
            self.forward_x11_trusted = Some(forward_x11_trusted);
        }
        if let Some(gateway_ports) = b.gateway_ports.clone() {
            self.gateway_ports = Some(gateway_ports);
        }
        if let Some(global_known_hosts_file) = b.global_known_hosts_file.clone() {
            self.global_known_hosts_file = Some(global_known_hosts_file);
        }
        if let Some(gssapi_authentication) = b.gssapi_authentication.clone() {
            self.gssapi_authentication = Some(gssapi_authentication);
        }
        if let Some(gssapi_key_exchange) = b.gssapi_key_exchange.clone() {
            self.gssapi_key_exchange = Some(gssapi_key_exchange);
        }
        if let Some(gssapi_client_identity) = b.gssapi_client_identity.clone() {
            self.gssapi_client_identity = Some(gssapi_client_identity);
        }
        if let Some(gssapi_delegate_credentials) = b.gssapi_delegate_credentials.clone() {
            self.gssapi_delegate_credentials = Some(gssapi_delegate_credentials);
        }
        if let Some(gssapi_renewal_forces_rekey) = b.gssapi_renewal_forces_rekey.clone() {
            self.gssapi_renewal_forces_rekey = Some(gssapi_renewal_forces_rekey);
        }
        if let Some(gssapi_trust_dns) = b.gssapi_trust_dns.clone() {
            self.gssapi_trust_dns = Some(gssapi_trust_dns);
        }
        if let Some(hash_known_hosts) = b.hash_known_hosts.clone() {
            self.hash_known_hosts = Some(hash_known_hosts);
        }
        if let Some(hostbased_authentication) = b.hostbased_authentication.clone() {
            self.hostbased_authentication = Some(hostbased_authentication);
        }
        if let Some(host_key_algorithms) = b.host_key_algorithms.clone() {
            self.host_key_algorithms = Some(host_key_algorithms);
        }
        if let Some(host_key_alias) = b.host_key_alias.clone() {
            self.host_key_alias = Some(host_key_alias);
        }
        if let Some(host_name) = b.host_name.clone() {
            self.host_name = Some(host_name);
        }
        if let Some(identities_only) = b.identities_only.clone() {
            self.identities_only = Some(identities_only);
        }
        if let Some(identity_file) = b.identity_file.clone() {
            self.identity_file = Some(identity_file);
        }
        if let Some(kbd_interactive_authentication) = b.kbd_interactive_authentication.clone() {
            self.kbd_interactive_authentication = Some(kbd_interactive_authentication);
        }
        if let Some(kbd_interactive_devices) = b.kbd_interactive_devices.clone() {
            self.kbd_interactive_devices = Some(kbd_interactive_devices);
        }
        if let Some(kex_algorithms) = b.kex_algorithms.clone() {
            self.kex_algorithms = Some(kex_algorithms);
        }
        if let Some(local_command) = b.local_command.clone() {
            self.local_command = Some(local_command);
        }
        if let Some(local_forward) = b.local_forward.clone() {
            self.local_forward = Some(local_forward);
        }
        if let Some(log_level) = b.log_level.clone() {
            self.log_level = Some(log_level);
        }
        if let Some(mac) = b.mac.clone() {
            self.mac = Some(mac);
        }
        if let Some(no_host_authentication_for_localhost) =
            b.no_host_authentication_for_localhost.clone()
        {
            self.no_host_authentication_for_localhost = Some(no_host_authentication_for_localhost);
        }
        if let Some(preferred_authentications) = b.preferred_authentications.clone() {
            self.preferred_authentications = Some(preferred_authentications);
        }
        if let Some(protocol) = b.protocol.clone() {
            self.protocol = Some(protocol);
        }
        if let Some(proxy_command) = b.proxy_command.clone() {
            self.proxy_command = Some(proxy_command);
        }
        if let Some(pubkey_accepted_algorithms) = b.pubkey_accepted_algorithms.clone() {
            self.pubkey_accepted_algorithms = Some(pubkey_accepted_algorithms);
        }
        if let Some(pubkey_authentication) = b.pubkey_authentication.clone() {
            self.pubkey_authentication = Some(pubkey_authentication);
        }
        if let Some(remote_forward) = b.remote_forward.clone() {
            self.remote_forward = Some(remote_forward);
        }
        if let Some(send_env) = b.send_env.clone() {
            self.send_env = Some(send_env);
        }
        if let Some(server_alive_count_max) = b.server_alive_count_max.clone() {
            self.server_alive_count_max = Some(server_alive_count_max);
        }
        if let Some(server_alive_interval) = b.server_alive_interval.clone() {
            self.server_alive_interval = Some(server_alive_interval);
        }
        if let Some(smartcard_device) = b.smartcard_device.clone() {
            self.smartcard_device = Some(smartcard_device);
        }
        if let Some(strict_host_key_checking) = b.strict_host_key_checking.clone() {
            self.strict_host_key_checking = Some(strict_host_key_checking);
        }
        if let Some(tcp_keep_alive) = b.tcp_keep_alive.clone() {
            self.tcp_keep_alive = Some(tcp_keep_alive);
        }
        if let Some(tunnel) = b.tunnel.clone() {
            self.tunnel = Some(tunnel);
        }
        if let Some(tunnel_device) = b.tunnel_device.clone() {
            self.tunnel_device = Some(tunnel_device);
        }
        if let Some(user_known_hosts_file) = b.user_known_hosts_file.clone() {
            self.user_known_hosts_file = Some(user_known_hosts_file);
        }
        if let Some(verify_host_key_dns) = b.verify_host_key_dns.clone() {
            self.verify_host_key_dns = Some(verify_host_key_dns);
        }
        if let Some(visual_host_key) = b.visual_host_key.clone() {
            self.visual_host_key = Some(visual_host_key);
        }
    }
}
