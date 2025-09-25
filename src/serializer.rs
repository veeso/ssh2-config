//! SSH Config serializer

use std::fmt;

use crate::{Host, HostClause, HostParams, SshConfig};

pub struct SshConfigSerializer<'a>(&'a SshConfig);

impl SshConfigSerializer<'_> {
    pub fn serialize(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.hosts.is_empty() {
            return Ok(());
        }

        // serialize first host
        let root = self.0.hosts.first().unwrap();
        // check if first host is the default host
        if root.pattern == vec![HostClause::new(String::from("*"), false)] {
            Self::serialize_host_params(f, &root.params, false)?;
        } else {
            Self::serialize_host(f, root)?;
        }

        // serialize other hosts
        for host in self.0.hosts.iter().skip(1) {
            Self::serialize_host(f, host)?;
        }

        Ok(())
    }

    fn serialize_host(f: &mut fmt::Formatter<'_>, host: &Host) -> fmt::Result {
        let patterns = &host
            .pattern
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(f, "Host {patterns}",)?;
        Self::serialize_host_params(f, &host.params, true)?;
        writeln!(f,)?;

        Ok(())
    }

    fn serialize_host_params(
        f: &mut fmt::Formatter<'_>,
        params: &HostParams,
        nested: bool,
    ) -> fmt::Result {
        let padding = if nested { "    " } else { "" };

        if let Some(value) = params.bind_address.as_ref() {
            writeln!(f, "{padding}Hostname {value}",)?;
        }
        if let Some(value) = params.bind_interface.as_ref() {
            writeln!(f, "{padding}BindAddress {value}",)?;
        }
        if !params.ca_signature_algorithms.is_default() {
            writeln!(
                f,
                "{padding}CASignatureAlgorithms {ca_signature_algorithms}",
                padding = padding,
                ca_signature_algorithms = params.ca_signature_algorithms
            )?;
        }
        if let Some(certificate_file) = params.certificate_file.as_ref() {
            writeln!(f, "{padding}CertificateFile {}", certificate_file.display())?;
        }
        if !params.ciphers.is_default() {
            writeln!(
                f,
                "{padding}Ciphers {ciphers}",
                padding = padding,
                ciphers = params.ciphers
            )?;
        }
        if let Some(value) = params.compression.as_ref() {
            writeln!(
                f,
                "{padding}Compression {}",
                if *value { "yes" } else { "no" }
            )?;
        }
        if let Some(connection_attempts) = params.connection_attempts {
            writeln!(f, "{padding}ConnectionAttempts {connection_attempts}",)?;
        }
        if let Some(connect_timeout) = params.connect_timeout {
            writeln!(f, "{padding}ConnectTimeout {}", connect_timeout.as_secs())?;
        }
        if !params.host_key_algorithms.is_default() {
            writeln!(
                f,
                "{padding}HostKeyAlgorithms {host_key_algorithms}",
                padding = padding,
                host_key_algorithms = params.host_key_algorithms
            )?;
        }
        if let Some(host_name) = params.host_name.as_ref() {
            writeln!(f, "{padding}HostName {host_name}",)?;
        }
        if let Some(identity_file) = params.identity_file.as_ref() {
            writeln!(
                f,
                "{padding}IdentityFile {}",
                identity_file
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }
        if let Some(ignore_unknown) = params.ignore_unknown.as_ref() {
            writeln!(
                f,
                "{padding}IgnoreUnknown {}",
                ignore_unknown
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }
        if !params.kex_algorithms.is_default() {
            writeln!(
                f,
                "{padding}KexAlgorithms {kex_algorithms}",
                padding = padding,
                kex_algorithms = params.kex_algorithms
            )?;
        }
        if !params.mac.is_default() {
            writeln!(
                f,
                "{padding}MACs {mac}",
                padding = padding,
                mac = params.mac
            )?;
        }
        if let Some(port) = params.port {
            writeln!(f, "{padding}Port {port}", port = port)?;
        }
        if !params.pubkey_accepted_algorithms.is_default() {
            writeln!(
                f,
                "{padding}PubkeyAcceptedAlgorithms {pubkey_accepted_algorithms}",
                padding = padding,
                pubkey_accepted_algorithms = params.pubkey_accepted_algorithms
            )?;
        }
        if let Some(pubkey_authentication) = params.pubkey_authentication.as_ref() {
            writeln!(
                f,
                "{padding}PubkeyAuthentication {}",
                if *pubkey_authentication { "yes" } else { "no" }
            )?;
        }
        if let Some(remote_forward) = params.remote_forward.as_ref() {
            writeln!(f, "{padding}RemoteForward {remote_forward}",)?;
        }
        if let Some(server_alive_interval) = params.server_alive_interval {
            writeln!(
                f,
                "{padding}ServerAliveInterval {}",
                server_alive_interval.as_secs()
            )?;
        }
        if let Some(tcp_keep_alive) = params.tcp_keep_alive.as_ref() {
            writeln!(
                f,
                "{padding}TCPKeepAlive {}",
                if *tcp_keep_alive { "yes" } else { "no" }
            )?;
        }
        #[cfg(target_os = "macos")]
        if let Some(use_keychain) = params.use_keychain.as_ref() {
            writeln!(
                f,
                "{padding}UseKeychain {}",
                if *use_keychain { "yes" } else { "no" }
            )?;
        }
        if let Some(user) = params.user.as_ref() {
            writeln!(f, "{padding}User {user}",)?;
        }
        for (field, value) in &params.ignored_fields {
            writeln!(
                f,
                "{padding}{field} {value}",
                field = field,
                value = value
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )?;
        }
        for (field, value) in &params.unsupported_fields {
            writeln!(
                f,
                "{padding}{field} {value}",
                field = field,
                value = value
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )?;
        }

        Ok(())
    }
}

impl<'a> From<&'a SshConfig> for SshConfigSerializer<'a> {
    fn from(config: &'a SshConfig) -> Self {
        SshConfigSerializer(config)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{DefaultAlgorithms, HostClause};

    #[test]
    fn are_host_patterns_combined() {
        let mut host_params = HostParams::new(&DefaultAlgorithms::empty());
        host_params.host_name = Some("bastion.example.com".to_string());

        let host = Host::new(
            vec![
                HostClause::new(String::from("*.example.com"), false),
                HostClause::new(String::from("foo.example.com"), true),
            ],
            host_params,
        );

        let output = SshConfig::from_hosts(vec![/*default_host,*/ host]).to_string();
        assert!(&output.contains("Host *.example.com !foo.example.com"));
    }

    #[test]
    fn is_default_host_serialized_without_host() {
        let mut root_params = HostParams::new(&DefaultAlgorithms::empty());
        root_params.server_alive_interval = Some(Duration::from_secs(60));
        let root = Host::new(vec![HostClause::new(String::from("*"), false)], root_params);

        let mut host_params = HostParams::new(&DefaultAlgorithms::empty());
        host_params.user = Some("example".to_string());
        let host = Host::new(
            vec![HostClause::new(String::from("*.example.com"), false)],
            host_params,
        );

        let output = SshConfig::from_hosts(vec![root, host]).to_string();
        assert!(&output.starts_with("ServerAliveInterval 60"));
    }
}
