//! # parser
//!
//! Ssh config parser

use std::io::{BufRead, Error as IoError};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bitflags::bitflags;
use thiserror::Error;

use super::{Host, HostClause, HostParams, SshConfig};

// modules
mod field;
use field::Field;

pub type SshParserResult<T> = Result<T, SshParserError>;

/// Ssh config parser error
#[derive(Debug, Error)]
pub enum SshParserError {
    #[error("expected boolean value ('yes', 'no')")]
    ExpectedBoolean,
    #[error("expected port number")]
    ExpectedPort,
    #[error("expected unsigned value")]
    ExpectedUnsigned,
    #[error("expected path")]
    ExpectedPath,
    #[error("missing argument")]
    MissingArgument,
    #[error("unknown field: {0}")]
    UnknownField(String, Vec<String>),
    #[error("IO error: {0}")]
    Io(IoError),
}

bitflags! {
    /// The parsing mode
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ParseRule: u8 {
        /// Don't allow any invalid field or value
        const STRICT = 0b00000000;
        /// Allow unknown field
        const ALLOW_UNKNOWN_FIELDS = 0b00000001;
    }
}

// -- parser

/// Ssh config parser
pub struct SshConfigParser;

impl SshConfigParser {
    /// Parse reader lines and apply parameters to configuration
    pub fn parse(
        config: &mut SshConfig,
        reader: &mut impl BufRead,
        rules: ParseRule,
    ) -> SshParserResult<()> {
        // Current host pointer
        let mut current_host = config.hosts.last_mut().unwrap();
        let mut lines = reader.lines();
        // iter lines
        loop {
            let line = match lines.next() {
                None => break,
                Some(Err(err)) => return Err(SshParserError::Io(err)),
                Some(Ok(line)) => Self::strip_comments(line.trim()),
            };
            if line.is_empty() {
                continue;
            }
            // tokenize
            let (field, args) = match Self::tokenize(&line) {
                Ok((field, args)) => (field, args),
                Err(SshParserError::UnknownField(field, args))
                    if rules.intersects(ParseRule::ALLOW_UNKNOWN_FIELDS)
                        || current_host.params.ignored(&field) =>
                {
                    current_host.params.ignored_fields.insert(field, args);
                    continue;
                }
                Err(SshParserError::UnknownField(field, args)) => {
                    return Err(SshParserError::UnknownField(field, args))
                }
                Err(err) => return Err(err),
            };
            // If field is block, init a new block
            if field == Field::Host {
                // Get default params
                let params = config.default_params();
                // Parse arguments
                let clause = Self::parse_host(args)?;
                // Save
                config.hosts.push(Host::new(clause, params));
                // Update host
                current_host = config.hosts.last_mut().unwrap();
            } else {
                // Update field
                Self::update_host(field, args, &mut current_host.params)?;
            }
        }
        // sort hosts
        config.hosts.sort();

        Ok(())
    }

    /// Strip comments from line
    fn strip_comments(s: &str) -> String {
        if let Some(pos) = s.find('#') {
            s[..pos].to_string()
        } else {
            s.to_string()
        }
    }

    /// Update current given host with field argument
    fn update_host(
        field: Field,
        args: Vec<String>,
        params: &mut HostParams,
    ) -> SshParserResult<()> {
        match field {
            Field::BindAddress => {
                params.bind_address = Some(Self::parse_string(args)?);
            }
            Field::BindInterface => {
                params.bind_interface = Some(Self::parse_string(args)?);
            }
            Field::CaSignatureAlgorithms => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.ca_signature_algorithms.is_none() {
                    params.ca_signature_algorithms = Some(Vec::new());
                }
                Self::resolve_algorithms(params.ca_signature_algorithms.as_mut().unwrap(), algos);
            }
            Field::CertificateFile => {
                params.certificate_file = Some(Self::parse_path(args)?);
            }
            Field::Ciphers => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.ciphers.is_none() {
                    params.ciphers = Some(Vec::new());
                }
                Self::resolve_algorithms(params.ciphers.as_mut().unwrap(), algos);
            }
            Field::Compression => {
                params.compression = Some(Self::parse_boolean(args)?);
            }
            Field::ConnectTimeout => {
                params.connect_timeout = Some(Self::parse_duration(args)?);
            }
            Field::ConnectionAttempts => {
                params.connection_attempts = Some(Self::parse_unsigned(args)?);
            }
            Field::Host => { /* already handled before */ }
            Field::HostKeyAlgorithms => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.host_key_algorithms.is_none() {
                    params.host_key_algorithms = Some(Vec::new());
                }
                Self::resolve_algorithms(params.host_key_algorithms.as_mut().unwrap(), algos);
            }
            Field::HostName => {
                params.host_name = Some(Self::parse_string(args)?);
            }
            Field::IdentityFile => {
                params.identity_file = Some(Self::parse_path_list(args)?);
            }
            Field::IgnoreUnknown => {
                params.ignore_unknown = Some(Self::parse_comma_separated_list(args)?);
            }
            Field::KexAlgorithms => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.kex_algorithms.is_none() {
                    params.kex_algorithms = Some(Vec::new());
                }
                Self::resolve_algorithms(params.kex_algorithms.as_mut().unwrap(), algos);
            }
            Field::Mac => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.mac.is_none() {
                    params.mac = Some(Vec::new());
                }
                Self::resolve_algorithms(params.mac.as_mut().unwrap(), algos);
            }
            Field::Port => {
                params.port = Some(Self::parse_port(args)?);
            }
            Field::PubkeyAcceptedAlgorithms => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.pubkey_accepted_algorithms.is_none() {
                    params.pubkey_accepted_algorithms = Some(Vec::new());
                }
                Self::resolve_algorithms(
                    params.pubkey_accepted_algorithms.as_mut().unwrap(),
                    algos,
                );
            }
            Field::PubkeyAuthentication => {
                params.pubkey_authentication = Some(Self::parse_boolean(args)?);
            }
            Field::RemoteForward => {
                params.remote_forward = Some(Self::parse_port(args)?);
            }
            Field::ServerAliveInterval => {
                params.server_alive_interval = Some(Self::parse_duration(args)?);
            }
            Field::TcpKeepAlive => {
                params.tcp_keep_alive = Some(Self::parse_boolean(args)?);
            }
            #[cfg(target_os = "macos")]
            Field::UseKeychain => {
                params.use_keychain = Some(Self::parse_boolean(args)?);
            }
            Field::User => {
                params.user = Some(Self::parse_string(args)?);
            }
            // -- unimplemented fields
            Field::AddKeysToAgent
            | Field::AddressFamily
            | Field::BatchMode
            | Field::CanonicalDomains
            | Field::CanonicalizeFallbackLock
            | Field::CanonicalizeHostname
            | Field::CanonicalizeMaxDots
            | Field::CanonicalizePermittedCNAMEs
            | Field::CheckHostIP
            | Field::ClearAllForwardings
            | Field::ControlMaster
            | Field::ControlPath
            | Field::ControlPersist
            | Field::DynamicForward
            | Field::EnableSSHKeysign
            | Field::EscapeChar
            | Field::ExitOnForwardFailure
            | Field::FingerprintHash
            | Field::ForkAfterAuthentication
            | Field::ForwardAgent
            | Field::ForwardX11
            | Field::ForwardX11Timeout
            | Field::ForwardX11Trusted
            | Field::GatewayPorts
            | Field::GlobalKnownHostsFile
            | Field::GSSAPIAuthentication
            | Field::GSSAPIDelegateCredentials
            | Field::HashKnownHosts
            | Field::HostbasedAcceptedAlgorithms
            | Field::HostbasedAuthentication
            | Field::HostKeyAlias
            | Field::HostbasedKeyTypes
            | Field::IdentitiesOnly
            | Field::IdentityAgent
            | Field::Include
            | Field::IPQoS
            | Field::KbdInteractiveAuthentication
            | Field::KbdInteractiveDevices
            | Field::KnownHostsCommand
            | Field::LocalCommand
            | Field::LocalForward
            | Field::LogLevel
            | Field::LogVerbose
            | Field::NoHostAuthenticationForLocalhost
            | Field::NumberOfPasswordPrompts
            | Field::PasswordAuthentication
            | Field::PermitLocalCommand
            | Field::PermitRemoteOpen
            | Field::PKCS11Provider
            | Field::PreferredAuthentications
            | Field::ProxyCommand
            | Field::ProxyJump
            | Field::ProxyUseFdpass
            | Field::PubkeyAcceptedKeyTypes
            | Field::RekeyLimit
            | Field::RequestTTY
            | Field::RevokedHostKeys
            | Field::SecruityKeyProvider
            | Field::SendEnv
            | Field::ServerAliveCountMax
            | Field::SessionType
            | Field::SetEnv
            | Field::StdinNull
            | Field::StreamLocalBindMask
            | Field::StrictHostKeyChecking
            | Field::SyslogFacility
            | Field::UpdateHostKeys
            | Field::UserKnownHostsFile
            | Field::VerifyHostKeyDNS
            | Field::VisualHostKey
            | Field::XAuthLocation => { /* Ignore fields */ }
        }
        Ok(())
    }

    /// Resolve algorithms list.
    /// if the first argument starts with `+`, then the provided algorithms are PUSHED onto existing list
    /// if the first argument starts with `-`, then the provided algorithms are REMOVED from existing list
    /// otherwise the provided list will JUST replace the existing list
    fn resolve_algorithms(current_list: &mut Vec<String>, mut algos: Vec<String>) {
        let first = algos.first_mut().unwrap();
        if first.starts_with('+') {
            // Concat
            let new_first = first.replacen('+', "", 1);
            algos[0] = new_first;
            for algo in algos.into_iter() {
                if !current_list.contains(&algo) {
                    current_list.push(algo);
                }
            }
        } else if first.starts_with('-') {
            // Remove
            let new_first = first.replacen('-', "", 1);
            algos[0] = new_first;
            // Remove algos from current_list
            current_list.retain(|x| !algos.contains(x));
        } else {
            *current_list = algos;
        }
    }

    /// Tokenize line if possible. Returns field name and args
    fn tokenize(line: &str) -> SshParserResult<(Field, Vec<String>)> {
        let mut tokens = line.split_whitespace();
        let field = match tokens.next().map(Field::from_str) {
            Some(Ok(field)) => field,
            Some(Err(field)) => {
                return Err(SshParserError::UnknownField(
                    field,
                    tokens.map(|x| x.to_string()).collect(),
                ))
            }
            None => return Err(SshParserError::MissingArgument),
        };
        let args = tokens
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        Ok((field, args))
    }

    // -- value parsers

    /// parse boolean value
    fn parse_boolean(args: Vec<String>) -> SshParserResult<bool> {
        match args.get(0).map(|x| x.as_str()) {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            Some(_) => Err(SshParserError::ExpectedBoolean),
            None => Err(SshParserError::MissingArgument),
        }
    }

    /// Parse comma separated list arguments
    fn parse_comma_separated_list(args: Vec<String>) -> SshParserResult<Vec<String>> {
        match args
            .get(0)
            .map(|x| x.split(',').map(|x| x.to_string()).collect())
        {
            Some(args) => Ok(args),
            _ => Err(SshParserError::MissingArgument),
        }
    }

    /// Parse duration argument
    fn parse_duration(args: Vec<String>) -> SshParserResult<Duration> {
        let value = Self::parse_unsigned(args)?;
        Ok(Duration::from_secs(value as u64))
    }

    /// Parse host argument
    fn parse_host(args: Vec<String>) -> SshParserResult<Vec<HostClause>> {
        if args.is_empty() {
            return Err(SshParserError::MissingArgument);
        }
        // Collect hosts
        Ok(args
            .into_iter()
            .map(|x| {
                let tokens: Vec<&str> = x.split('!').collect();
                if tokens.len() == 2 {
                    HostClause::new(tokens[1].to_string(), true)
                } else {
                    HostClause::new(tokens[0].to_string(), false)
                }
            })
            .collect())
    }

    /// Parse a list of paths
    fn parse_path_list(args: Vec<String>) -> SshParserResult<Vec<PathBuf>> {
        if args.is_empty() {
            return Err(SshParserError::MissingArgument);
        }
        args.iter()
            .map(|x| Self::parse_path_arg(x.as_str()))
            .collect()
    }

    /// Parse path argument
    fn parse_path(args: Vec<String>) -> SshParserResult<PathBuf> {
        if let Some(s) = args.get(0) {
            Self::parse_path_arg(s)
        } else {
            Err(SshParserError::MissingArgument)
        }
    }

    /// Parse path argument
    fn parse_path_arg(s: &str) -> SshParserResult<PathBuf> {
        // Remove tilde
        let s = if s.starts_with('~') {
            let home_dir = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("~"))
                .to_string_lossy()
                .to_string();
            s.replacen('~', &home_dir, 1)
        } else {
            s.to_string()
        };
        Ok(PathBuf::from(s))
    }

    /// Parse port number argument
    fn parse_port(args: Vec<String>) -> SshParserResult<u16> {
        match args.get(0).map(|x| u16::from_str(x)) {
            Some(Ok(val)) => Ok(val),
            Some(Err(_)) => Err(SshParserError::ExpectedPort),
            None => Err(SshParserError::MissingArgument),
        }
    }

    /// Parse string argument
    fn parse_string(args: Vec<String>) -> SshParserResult<String> {
        if let Some(s) = args.into_iter().next() {
            Ok(s)
        } else {
            Err(SshParserError::MissingArgument)
        }
    }

    /// Parse unsigned argument
    fn parse_unsigned(args: Vec<String>) -> SshParserResult<usize> {
        match args.get(0).map(|x| usize::from_str(x)) {
            Some(Ok(val)) => Ok(val),
            Some(Err(_)) => Err(SshParserError::ExpectedUnsigned),
            None => Err(SshParserError::MissingArgument),
        }
    }
}

#[cfg(test)]
mod test {

    use std::fs::File;
    use std::io::{BufReader, Write};
    use std::path::Path;

    use pretty_assertions::assert_eq;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn should_parse_configuration() {
        let temp = create_ssh_config();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .unwrap();
        // Query
        let params = config.default_params();
        assert_eq!(
            params.ignore_unknown.as_deref().unwrap(),
            &["Pippo", "Pluto"]
        );
        assert_eq!(params.compression.unwrap(), true);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(
            params.server_alive_interval.unwrap(),
            Duration::from_secs(40)
        );
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
        );
        assert_eq!(
            params.ciphers.as_deref().unwrap(),
            &["a-manella", "blowfish"]
        );
        assert_eq!(
            params.host_key_algorithms.as_deref().unwrap(),
            &["luigi", "mario",]
        );
        assert_eq!(
            params.kex_algorithms.as_deref().unwrap(),
            &["desu", "gigi",]
        );
        assert_eq!(params.mac.as_deref().unwrap(), &["concorde"]);
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["desu", "omar-crypt", "fast-omar-crypt"]
        );
        assert!(params.bind_address.is_none());
        // Query 172.26.104.4
        let params = config.query("172.26.104.4");
        assert_eq!(params.compression.unwrap(), true);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
        );
        assert_eq!(
            params.ciphers.as_deref().unwrap(),
            &[
                "a-manella",
                "blowfish",
                "coi-piedi",
                "cazdecan",
                "triestin-stretto"
            ]
        );
        assert_eq!(params.mac.as_deref().unwrap(), &["spyro", "deoxys"]);
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["desu", "fast-omar-crypt"]
        );
        assert_eq!(params.bind_address.as_deref().unwrap(), "10.8.0.10");
        assert_eq!(params.bind_interface.as_deref().unwrap(), "tun0");
        assert_eq!(params.port.unwrap(), 2222);
        assert_eq!(
            params.identity_file.as_deref().unwrap(),
            vec![
                Path::new("/home/root/.ssh/pippo.key"),
                Path::new("/home/root/.ssh/pluto.key")
            ]
        );
        assert_eq!(params.user.as_deref().unwrap(), "omar");
        // Query tostapane
        let params = config.query("tostapane");
        assert_eq!(params.compression.unwrap(), false);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
        );
        assert_eq!(
            params.ciphers.as_deref().unwrap(),
            &["a-manella", "blowfish",]
        );
        assert_eq!(params.mac.as_deref().unwrap(), &["concorde"]);
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["desu", "omar-crypt", "fast-omar-crypt"]
        );
        assert_eq!(params.remote_forward.unwrap(), 88);
        assert_eq!(params.user.as_deref().unwrap(), "ciro-esposito");
        // query 192.168.1.30
        let params = config.query("192.168.1.30");
        assert_eq!(params.compression.unwrap(), true);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
        );
        assert_eq!(
            params.ciphers.as_deref().unwrap(),
            &["a-manella", "blowfish"]
        );
        assert_eq!(params.mac.as_deref().unwrap(), &["concorde"]);
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["desu", "omar-crypt", "fast-omar-crypt"]
        );
        assert_eq!(params.user.as_deref().unwrap(), "nutellaro");
        assert_eq!(params.remote_forward.unwrap(), 123);
    }

    #[test]
    fn should_allow_unknown_field() {
        let temp = create_ssh_config_with_unknown_fields();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        assert!(SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .is_ok());
    }

    #[test]
    fn should_not_allow_unknown_field() {
        let temp = create_ssh_config_with_unknown_fields();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        assert!(SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .is_err());
    }

    #[test]
    fn should_store_unknown_fields() {
        let temp = create_ssh_config_with_unknown_fields();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .unwrap();

        let host = config.query("cross-platform");
        assert_eq!(
            host.ignored_fields.get("Piropero").unwrap(),
            &vec![String::from("yes")]
        );
    }

    #[test]
    fn should_parse_inversed_ssh_config() {
        let temp = create_inverted_ssh_config();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .unwrap();

        let home_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("~"))
            .to_string_lossy()
            .to_string();

        assert_eq!(
            config.query("remote_host").identity_file.unwrap()[0].as_path(),
            Path::new(format!("{home_dir}/.ssh/id_rsa_good").as_str())
        );
    }

    #[test]
    fn should_parse_configuration_with_hosts() {
        let temp = create_ssh_config_with_comments();

        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .unwrap();

        let hostname = config.query("cross-platform").host_name.unwrap();
        assert_eq!(&hostname, "hostname.com");

        assert!(config.query("this").host_name.is_none());
    }

    #[test]
    fn should_update_host_bind_address() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::BindAddress,
            vec![String::from("127.0.0.1")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.bind_address.as_deref().unwrap(), "127.0.0.1");
    }

    #[test]
    fn should_update_host_bind_interface() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::BindInterface,
            vec![String::from("aaa")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.bind_interface.as_deref().unwrap(), "aaa");
    }

    #[test]
    fn should_update_host_ca_signature_algos() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::CaSignatureAlgorithms,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
    }

    #[test]
    fn should_update_host_certificate_file() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::CertificateFile,
            vec![String::from("/tmp/a.crt")],
            &mut params
        )
        .is_ok());
        assert_eq!(
            params.certificate_file.as_deref().unwrap(),
            Path::new("/tmp/a.crt")
        );
    }

    #[test]
    fn should_update_host_ciphers() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::Ciphers,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.ciphers.as_deref().unwrap(), &["a", "b", "c"]);
    }

    #[test]
    fn should_update_host_compression() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::Compression,
            vec![String::from("yes")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.compression.unwrap(), true);
    }

    #[test]
    fn should_update_host_connection_attempts() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::ConnectionAttempts,
            vec![String::from("4")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.connection_attempts.unwrap(), 4);
    }

    #[test]
    fn should_update_host_connection_timeout() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::ConnectTimeout,
            vec![String::from("10")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn should_update_host_key_algorithms() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::HostKeyAlgorithms,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(
            params.host_key_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
    }

    #[test]
    fn should_update_host_host_name() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::HostName,
            vec![String::from("192.168.1.1")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.host_name.as_deref().unwrap(), "192.168.1.1");
    }

    #[test]
    fn should_update_host_ignore_unknown() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::IgnoreUnknown,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.ignore_unknown.as_deref().unwrap(), &["a", "b", "c"]);
    }

    #[test]
    fn should_update_kex_algorithms() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::KexAlgorithms,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.kex_algorithms.as_deref().unwrap(), &["a", "b", "c"]);
    }

    #[test]
    fn should_update_host_mac() {
        let mut params = HostParams::default();
        assert!(
            SshConfigParser::update_host(Field::Mac, vec![String::from("a,b,c")], &mut params)
                .is_ok()
        );
        assert_eq!(params.mac.as_deref().unwrap(), &["a", "b", "c"]);
    }

    #[test]
    fn should_update_host_port() {
        let mut params = HostParams::default();
        assert!(
            SshConfigParser::update_host(Field::Port, vec![String::from("2222")], &mut params)
                .is_ok()
        );
        assert_eq!(params.port.unwrap(), 2222);
    }

    #[test]
    fn should_update_host_pubkey_accepted_algos() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::PubkeyAcceptedAlgorithms,
            vec![String::from("a,b,c")],
            &mut params
        )
        .is_ok());
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
    }

    #[test]
    fn should_update_host_pubkey_authentication() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::PubkeyAuthentication,
            vec![String::from("yes")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.pubkey_authentication.unwrap(), true);
    }

    #[test]
    fn should_update_host_remote_forward() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::RemoteForward,
            vec![String::from("3005")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.remote_forward.unwrap(), 3005);
    }

    #[test]
    fn should_update_host_server_alive_interval() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::ServerAliveInterval,
            vec![String::from("40")],
            &mut params
        )
        .is_ok());
        assert_eq!(
            params.server_alive_interval.unwrap(),
            Duration::from_secs(40)
        );
    }

    #[test]
    fn should_update_host_tcp_keep_alive() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::TcpKeepAlive,
            vec![String::from("no")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.tcp_keep_alive.unwrap(), false);
    }

    #[test]
    fn should_update_host_user() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::User,
            vec![String::from("pippo")],
            &mut params
        )
        .is_ok());
        assert_eq!(params.user.as_deref().unwrap(), "pippo");
    }

    #[test]
    fn should_not_update_host_if_unknown() {
        let mut params = HostParams::default();
        assert!(SshConfigParser::update_host(
            Field::AddKeysToAgent,
            vec![String::from("yes")],
            &mut params
        )
        .is_ok());
        assert_eq!(params, HostParams::default());
    }

    #[test]
    fn should_resolve_algorithms_list_when_preceeded_by_plus() {
        let mut list = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let algos = vec![
            "+1".to_string(),
            "a".to_string(),
            "b".to_string(),
            "3".to_string(),
            "d".to_string(),
        ];
        SshConfigParser::resolve_algorithms(&mut list, algos);
        assert_eq!(
            list,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string(),
                "1".to_string(),
                "3".to_string(),
            ]
        );
    }

    #[test]
    fn should_resolve_algorithms_list_when_preceeded_by_minus() {
        let mut list = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let algos = vec!["-a".to_string(), "b".to_string(), "3".to_string()];
        SshConfigParser::resolve_algorithms(&mut list, algos);
        assert_eq!(
            list,
            vec!["c".to_string(), "d".to_string(), "e".to_string(),]
        );
    }

    #[test]
    fn should_resolve_algorithm_list_when_replacing() {
        let mut list = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ];
        let algos = vec![
            "1".to_string(),
            "a".to_string(),
            "b".to_string(),
            "3".to_string(),
            "d".to_string(),
        ];
        SshConfigParser::resolve_algorithms(&mut list, algos);
        assert_eq!(
            list,
            vec![
                "1".to_string(),
                "a".to_string(),
                "b".to_string(),
                "3".to_string(),
                "d".to_string(),
            ]
        );
    }

    #[test]
    fn should_tokenize_line() {
        assert_eq!(
            SshConfigParser::tokenize("HostName 192.168.*.* 172.26.*.*")
                .ok()
                .unwrap(),
            (
                Field::HostName,
                vec![String::from("192.168.*.*"), String::from("172.26.*.*")]
            )
        );
        // Tokenize line with spaces
        assert_eq!(
            SshConfigParser::tokenize(
                "      HostName        192.168.*.*        172.26.*.*        "
            )
            .ok()
            .unwrap(),
            (
                Field::HostName,
                vec![String::from("192.168.*.*"), String::from("172.26.*.*")]
            )
        );
    }

    #[test]
    fn should_not_tokenize_line() {
        assert!(SshConfigParser::tokenize("Omar     yes").is_err());
    }

    #[test]
    fn should_fail_parsing_field() {
        assert!(SshConfigParser::tokenize("                  ").is_err());
    }

    #[test]
    fn should_parse_boolean() {
        assert_eq!(
            SshConfigParser::parse_boolean(vec![String::from("yes")])
                .ok()
                .unwrap(),
            true
        );
        assert_eq!(
            SshConfigParser::parse_boolean(vec![String::from("no")])
                .ok()
                .unwrap(),
            false
        );
    }

    #[test]
    fn should_fail_parsing_boolean() {
        assert!(SshConfigParser::parse_boolean(vec!["boh".to_string()]).is_err());
        assert!(SshConfigParser::parse_boolean(vec![]).is_err());
    }

    #[test]
    fn should_parse_comma_separated_list() {
        assert_eq!(
            SshConfigParser::parse_comma_separated_list(vec![String::from("a,b,c,d")])
                .ok()
                .unwrap(),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ]
        );
        assert_eq!(
            SshConfigParser::parse_comma_separated_list(vec![String::from("a")])
                .ok()
                .unwrap(),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn should_fail_parsing_comma_separated_list() {
        assert!(SshConfigParser::parse_comma_separated_list(vec![]).is_err());
    }

    #[test]
    fn should_parse_duration() {
        assert_eq!(
            SshConfigParser::parse_duration(vec![String::from("60")])
                .ok()
                .unwrap(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn should_fail_parsing_duration() {
        assert!(SshConfigParser::parse_duration(vec![String::from("AAA")]).is_err());
        assert!(SshConfigParser::parse_duration(vec![]).is_err());
    }

    #[test]
    fn should_parse_host() {
        assert_eq!(
            SshConfigParser::parse_host(vec![
                String::from("192.168.*.*"),
                String::from("!192.168.1.1"),
                String::from("172.26.104.*"),
                String::from("!172.26.104.10"),
            ])
            .ok()
            .unwrap(),
            vec![
                HostClause::new(String::from("192.168.*.*"), false),
                HostClause::new(String::from("192.168.1.1"), true),
                HostClause::new(String::from("172.26.104.*"), false),
                HostClause::new(String::from("172.26.104.10"), true),
            ]
        );
    }

    #[test]
    fn should_fail_parsing_host() {
        assert!(SshConfigParser::parse_host(vec![]).is_err())
    }

    #[test]
    fn should_parse_path() {
        assert_eq!(
            SshConfigParser::parse_path(vec![String::from("/tmp/a.txt")])
                .ok()
                .unwrap(),
            PathBuf::from("/tmp/a.txt")
        );
    }

    #[test]
    fn should_parse_path_and_resolve_tilde() {
        let mut expected = dirs::home_dir().unwrap();
        expected.push(".ssh/id_dsa");
        assert_eq!(
            SshConfigParser::parse_path(vec![String::from("~/.ssh/id_dsa")])
                .ok()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn should_parse_path_list() {
        assert_eq!(
            SshConfigParser::parse_path_list(vec![
                String::from("/tmp/a.txt"),
                String::from("/tmp/b.txt")
            ])
            .ok()
            .unwrap(),
            vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/b.txt")]
        );
    }

    #[test]
    fn should_fail_parse_path_list() {
        assert!(SshConfigParser::parse_path_list(vec![]).is_err());
    }

    #[test]
    fn should_fail_parsing_path() {
        assert!(SshConfigParser::parse_path(vec![]).is_err());
    }

    #[test]
    fn should_parse_port() {
        assert_eq!(
            SshConfigParser::parse_port(vec![String::from("22")])
                .ok()
                .unwrap(),
            22
        );
    }

    #[test]
    fn should_fail_parsing_port() {
        assert!(SshConfigParser::parse_port(vec![String::from("1234567")]).is_err());
        assert!(SshConfigParser::parse_port(vec![]).is_err());
    }

    #[test]
    fn should_parse_string() {
        assert_eq!(
            SshConfigParser::parse_string(vec![String::from("foobar")])
                .ok()
                .unwrap(),
            String::from("foobar")
        );
    }

    #[test]
    fn should_fail_parsing_string() {
        assert!(SshConfigParser::parse_string(vec![]).is_err());
    }

    #[test]
    fn should_parse_unsigned() {
        assert_eq!(
            SshConfigParser::parse_unsigned(vec![String::from("43")])
                .ok()
                .unwrap(),
            43
        );
    }

    #[test]
    fn should_fail_parsing_unsigned() {
        assert!(SshConfigParser::parse_unsigned(vec![String::from("abc")]).is_err());
        assert!(SshConfigParser::parse_unsigned(vec![]).is_err());
    }

    #[test]
    fn should_strip_comments() {
        assert_eq!(
            SshConfigParser::strip_comments("host my_host # this is my fav host").as_str(),
            "host my_host "
        );
        assert_eq!(
            SshConfigParser::strip_comments("# this is a comment").as_str(),
            ""
        );
    }

    fn create_ssh_config() -> NamedTempFile {
        let mut tmpfile: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().expect("Failed to create tempfile");
        let config = r##"
# ssh config
# written by veeso


        # I put a comment here just to annoy

IgnoreUnknown Pippo,Pluto

Compression yes
ConnectionAttempts          10
ConnectTimeout 60
ServerAliveInterval 40
TcpKeepAlive    yes

CaSignatureAlgorithms   random
Ciphers     a-manella,blowfish
HostKeyAlgorithms   luigi,mario
KexAlgorithms   desu,gigi
Macs     concorde
PubkeyAcceptedAlgorithms    desu,omar-crypt,fast-omar-crypt


# Let's start defining some hosts

Host 192.168.*.*    172.26.*.*      !192.168.1.30
    User    omar
    # Forward agent is actually not supported; I just want to see that it wont' fail parsing
    ForwardAgent    yes
    BindAddress     10.8.0.10
    BindInterface   tun0
    Ciphers     +coi-piedi,cazdecan,triestin-stretto
    IdentityFile    /home/root/.ssh/pippo.key /home/root/.ssh/pluto.key
    Macs     spyro,deoxys
    Port 2222
    PubkeyAcceptedAlgorithms    -omar-crypt

Host tostapane
    User    ciro-esposito
    HostName    192.168.24.32
    RemoteForward   88
    Compression no
    Pippo yes
    Pluto 56

Host    192.168.1.30
    User    nutellaro
    RemoteForward   123

"##;
        tmpfile.write_all(config.as_bytes()).unwrap();
        tmpfile
    }

    fn create_inverted_ssh_config() -> NamedTempFile {
        let mut tmpfile: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().expect("Failed to create tempfile");
        let config = r##"
Host remote_host
    HostName hostname.com
    User user
    IdentityFile ~/.ssh/id_rsa_good

Host remote_*
    IdentityFile ~/.ssh/id_mid

Host *
    AddKeysToAgent yes
    IdentityFile ~/.ssh/id_rsa_bad
    "##;
        tmpfile.write_all(config.as_bytes()).unwrap();
        tmpfile
    }

    fn create_ssh_config_with_comments() -> NamedTempFile {
        let mut tmpfile: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().expect("Failed to create tempfile");
        let config = r##"
Host cross-platform # this is my fav host
    HostName hostname.com
    User user
    IdentityFile ~/.ssh/id_rsa_good

Host *
    AddKeysToAgent yes
    IdentityFile ~/.ssh/id_rsa_bad
    "##;
        tmpfile.write_all(config.as_bytes()).unwrap();
        tmpfile
    }

    fn create_ssh_config_with_unknown_fields() -> NamedTempFile {
        let mut tmpfile: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().expect("Failed to create tempfile");
        let config = r##"
Host cross-platform # this is my fav host
    HostName hostname.com
    User user
    IdentityFile ~/.ssh/id_rsa_good
    Piropero yes

Host *
    AddKeysToAgent yes
    IdentityFile ~/.ssh/id_rsa_bad
    "##;
        tmpfile.write_all(config.as_bytes()).unwrap();
        tmpfile
    }
}
