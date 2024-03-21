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
    #[error("unknown field: {0}")]
    UnsupportedField(String, Vec<String>),
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
        const ALLOW_UNSUPPORTED_FIELDS = 0b00000010;
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
        // Options preceding the first `Host` section
        // are parsed as command line options;
        // overriding all following host-specific options.
        //
        // See https://github.com/openssh/openssh-portable/blob/master/readconf.c#L1051-L1054
        config.hosts.push(Host::new(
            vec![HostClause::new(String::from("*"), false)],
            HostParams::default(),
        ));

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
                // Pass `ignore_unknown` from global overrides down into the tokenizer.
                let mut params = HostParams::default();
                params.ignore_unknown = config.hosts[0].params.ignore_unknown.clone();

                // Add a new host
                config
                    .hosts
                    .push(Host::new(Self::parse_host(args)?, params));
                // Update current host pointer
                current_host = config.hosts.last_mut().unwrap();
            } else {
                // Update field
                match Self::update_host(field, args, &mut current_host.params) {
                    Ok(()) => Ok(()),
                    // If we're allowing unsupported fields to be parsed, add them to the map
                    Err(SshParserError::UnsupportedField(field, args))
                        if rules.intersects(ParseRule::ALLOW_UNSUPPORTED_FIELDS) =>
                    {
                        current_host.params.unsupported_fields.insert(field, args);
                        Ok(())
                    }
                    // Eat the error here to not break the API with this change
                    // Also it'd be weird to error on correct ssh_config's just because they're
                    // not supported by this library
                    Err(SshParserError::UnsupportedField(_, _)) => Ok(()),
                    e => e,
                }?;
            }
        }

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
                params.ca_signature_algorithms = Some(Self::parse_comma_separated_list(args)?);
            }
            Field::CertificateFile => {
                params.certificate_file = Some(Self::parse_path(args)?);
            }
            Field::Ciphers => {
                params.ciphers = Some(Self::parse_comma_separated_list(args)?);
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
                params.host_key_algorithms = Some(Self::parse_comma_separated_list(args)?);
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
                params.kex_algorithms = Some(Self::parse_comma_separated_list(args)?);
            }
            Field::Mac => {
                params.mac = Some(Self::parse_comma_separated_list(args)?);
            }
            Field::Port => {
                params.port = Some(Self::parse_port(args)?);
            }
            Field::PubkeyAcceptedAlgorithms => {
                params.pubkey_accepted_algorithms = Some(Self::parse_comma_separated_list(args)?);
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
            | Field::XAuthLocation => {
                return Err(SshParserError::UnsupportedField(field.to_string(), args))
            }
        }
        Ok(())
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
    fn should_parse_configuration() -> Result<(), SshParserError> {
        let temp = create_ssh_config();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let config = SshConfig::default().parse(&mut reader, ParseRule::STRICT)?;

        // Query openssh cmdline overrides (options preceding the first `Host` section,
        // overriding all following options)
        let params = config.query("*");
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
            params.ciphers.as_deref().unwrap(),
            &["a-manella", "blowfish"]
        );
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["desu", "omar-crypt", "fast-omar-crypt"]
        );

        // Query explicit all-hosts fallback options (`Host *`)
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
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
        assert!(params.bind_address.is_none());

        // Query 172.26.104.4, yielding cmdline overrides,
        // explicit `Host 192.168.*.* 172.26.*.* !192.168.1.30` options,
        // and all-hosts fallback options.
        let params = config.query("172.26.104.4");

        // cmdline overrides
        assert_eq!(params.compression.unwrap(), true);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);

        // all-hosts fallback options, merged with host-specific options
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["random"]
        );
        assert_eq!(
            params.ciphers.as_deref().unwrap(),
            &[
                "coi-piedi",
                "cazdecan",
                "triestin-stretto",
                "a-manella",
                "blowfish",
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
        assert_eq!(params.compression.unwrap(), true); // cmdline override over host-specific option
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);
        assert_eq!(params.remote_forward.unwrap(), 88);
        assert_eq!(params.user.as_deref().unwrap(), "ciro-esposito");

        // all-hosts fallback options
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

        // query 192.168.1.30
        let params = config.query("192.168.1.30");

        // host-specific options
        assert_eq!(params.user.as_deref().unwrap(), "nutellaro");
        assert_eq!(params.remote_forward.unwrap(), 123);

        // cmdline overrides
        assert_eq!(params.compression.unwrap(), true);
        assert_eq!(params.connection_attempts.unwrap(), 10);
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(60));
        assert_eq!(params.tcp_keep_alive.unwrap(), true);

        // all-hosts fallback options
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

        Ok(())
    }

    #[test]
    fn should_allow_unknown_field() -> Result<(), SshParserError> {
        let temp = create_ssh_config_with_unknown_fields();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        let _config = SshConfig::default().parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;

        Ok(())
    }

    #[test]
    fn should_not_allow_unknown_field() {
        let temp = create_ssh_config_with_unknown_fields();
        let file = File::open(temp.path()).expect("Failed to open tempfile");
        let mut reader = BufReader::new(file);
        assert!(matches!(
            SshConfig::default()
                .parse(&mut reader, ParseRule::STRICT)
                .unwrap_err(),
            SshParserError::UnknownField(..)
        ));
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

        let host_params = config.query("remote-host");

        // From `*-host`
        assert_eq!(
            host_params.identity_file.unwrap()[0].as_path(),
            Path::new(format!("{home_dir}/.ssh/id_rsa_good").as_str())
        );

        // From `remote-*`
        assert_eq!(host_params.host_name.unwrap(), "hostname.com");
        assert_eq!(host_params.user.unwrap(), "user");

        // From `*`
        assert_eq!(
            host_params.connect_timeout.unwrap(),
            Duration::from_secs(15)
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
    fn should_update_host_bind_address() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::BindAddress,
            vec![String::from("127.0.0.1")],
            &mut params,
        )?;
        assert_eq!(params.bind_address.as_deref().unwrap(), "127.0.0.1");
        Ok(())
    }

    #[test]
    fn should_update_host_bind_interface() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::BindInterface, vec![String::from("aaa")], &mut params)?;
        assert_eq!(params.bind_interface.as_deref().unwrap(), "aaa");
        Ok(())
    }

    #[test]
    fn should_update_host_ca_signature_algos() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::CaSignatureAlgorithms,
            vec![String::from("a,b,c")],
            &mut params,
        )?;
        assert_eq!(
            params.ca_signature_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
        Ok(())
    }

    #[test]
    fn should_update_host_certificate_file() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::CertificateFile,
            vec![String::from("/tmp/a.crt")],
            &mut params,
        )?;
        assert_eq!(
            params.certificate_file.as_deref().unwrap(),
            Path::new("/tmp/a.crt")
        );
        Ok(())
    }

    #[test]
    fn should_update_host_ciphers() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::Ciphers, vec![String::from("a,b,c")], &mut params)?;
        assert_eq!(params.ciphers.as_deref().unwrap(), &["a", "b", "c"]);
        Ok(())
    }

    #[test]
    fn should_update_host_compression() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::Compression, vec![String::from("yes")], &mut params)?;
        assert_eq!(params.compression.unwrap(), true);
        Ok(())
    }

    #[test]
    fn should_update_host_connection_attempts() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::ConnectionAttempts,
            vec![String::from("4")],
            &mut params,
        )?;
        assert_eq!(params.connection_attempts.unwrap(), 4);
        Ok(())
    }

    #[test]
    fn should_update_host_connection_timeout() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::ConnectTimeout, vec![String::from("10")], &mut params)?;
        assert_eq!(params.connect_timeout.unwrap(), Duration::from_secs(10));
        Ok(())
    }

    #[test]
    fn should_update_host_key_algorithms() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::HostKeyAlgorithms,
            vec![String::from("a,b,c")],
            &mut params,
        )?;
        assert_eq!(
            params.host_key_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
        Ok(())
    }

    #[test]
    fn should_update_host_host_name() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::HostName,
            vec![String::from("192.168.1.1")],
            &mut params,
        )?;
        assert_eq!(params.host_name.as_deref().unwrap(), "192.168.1.1");
        Ok(())
    }

    #[test]
    fn should_update_host_ignore_unknown() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::IgnoreUnknown,
            vec![String::from("a,b,c")],
            &mut params,
        )?;
        assert_eq!(params.ignore_unknown.as_deref().unwrap(), &["a", "b", "c"]);
        Ok(())
    }

    #[test]
    fn should_update_kex_algorithms() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::KexAlgorithms,
            vec![String::from("a,b,c")],
            &mut params,
        )?;
        assert_eq!(params.kex_algorithms.as_deref().unwrap(), &["a", "b", "c"]);
        Ok(())
    }

    #[test]
    fn should_update_host_mac() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::Mac, vec![String::from("a,b,c")], &mut params)?;
        assert_eq!(params.mac.as_deref().unwrap(), &["a", "b", "c"]);
        Ok(())
    }

    #[test]
    fn should_update_host_port() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::Port, vec![String::from("2222")], &mut params)?;
        assert_eq!(params.port.unwrap(), 2222);
        Ok(())
    }

    #[test]
    fn should_update_host_pubkey_accepted_algos() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::PubkeyAcceptedAlgorithms,
            vec![String::from("a,b,c")],
            &mut params,
        )?;
        assert_eq!(
            params.pubkey_accepted_algorithms.as_deref().unwrap(),
            &["a", "b", "c"]
        );
        Ok(())
    }

    #[test]
    fn should_update_host_pubkey_authentication() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::PubkeyAuthentication,
            vec![String::from("yes")],
            &mut params,
        )?;
        assert_eq!(params.pubkey_authentication.unwrap(), true);
        Ok(())
    }

    #[test]
    fn should_update_host_remote_forward() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::RemoteForward,
            vec![String::from("3005")],
            &mut params,
        )?;
        assert_eq!(params.remote_forward.unwrap(), 3005);
        Ok(())
    }

    #[test]
    fn should_update_host_server_alive_interval() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(
            Field::ServerAliveInterval,
            vec![String::from("40")],
            &mut params,
        )?;
        assert_eq!(
            params.server_alive_interval.unwrap(),
            Duration::from_secs(40)
        );
        Ok(())
    }

    #[test]
    fn should_update_host_tcp_keep_alive() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::TcpKeepAlive, vec![String::from("no")], &mut params)?;
        assert_eq!(params.tcp_keep_alive.unwrap(), false);
        Ok(())
    }

    #[test]
    fn should_update_host_user() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        SshConfigParser::update_host(Field::User, vec![String::from("pippo")], &mut params)?;
        assert_eq!(params.user.as_deref().unwrap(), "pippo");
        Ok(())
    }

    #[test]
    fn should_not_update_host_if_unknown() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        let result = SshConfigParser::update_host(
            Field::AddKeysToAgent,
            vec![String::from("yes")],
            &mut params,
        );

        match result {
            Ok(()) | Err(SshParserError::UnsupportedField(_, _)) => Ok(()),
            e => e,
        }?;

        assert_eq!(params, HostParams::default());
        Ok(())
    }

    #[test]
    fn should_update_host_if_unsupported() -> Result<(), SshParserError> {
        let mut params = HostParams::default();
        let result = SshConfigParser::update_host(
            Field::AddKeysToAgent,
            vec![String::from("yes")],
            &mut params,
        );

        match result {
            Err(SshParserError::UnsupportedField(field, _)) => {
                assert_eq!(field, "addkeystoagent");
                Ok(())
            }
            e => e,
        }?;

        assert_eq!(params, HostParams::default());
        Ok(())
    }

    #[test]
    fn should_tokenize_line() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::tokenize("HostName 192.168.*.* 172.26.*.*")?,
            (
                Field::HostName,
                vec![String::from("192.168.*.*"), String::from("172.26.*.*")]
            )
        );
        // Tokenize line with spaces
        assert_eq!(
            SshConfigParser::tokenize(
                "      HostName        192.168.*.*        172.26.*.*        "
            )?,
            (
                Field::HostName,
                vec![String::from("192.168.*.*"), String::from("172.26.*.*")]
            )
        );
        Ok(())
    }

    #[test]
    fn should_not_tokenize_line() {
        assert!(matches!(
            SshConfigParser::tokenize("Omar     yes").unwrap_err(),
            SshParserError::UnknownField(..)
        ));
    }

    #[test]
    fn should_fail_parsing_field() {
        assert!(matches!(
            SshConfigParser::tokenize("                  ").unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_boolean() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_boolean(vec![String::from("yes")])?,
            true
        );
        assert_eq!(
            SshConfigParser::parse_boolean(vec![String::from("no")])?,
            false
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_boolean() {
        assert!(matches!(
            SshConfigParser::parse_boolean(vec!["boh".to_string()]).unwrap_err(),
            SshParserError::ExpectedBoolean
        ));
        assert!(matches!(
            SshConfigParser::parse_boolean(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_comma_separated_list() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_comma_separated_list(vec![String::from("a,b,c,d")])?,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ]
        );
        assert_eq!(
            SshConfigParser::parse_comma_separated_list(vec![String::from("a")])?,
            vec!["a".to_string()]
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_comma_separated_list() {
        assert!(matches!(
            SshConfigParser::parse_comma_separated_list(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_duration() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_duration(vec![String::from("60")])?,
            Duration::from_secs(60)
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_duration() {
        assert!(matches!(
            SshConfigParser::parse_duration(vec![String::from("AAA")]).unwrap_err(),
            SshParserError::ExpectedUnsigned
        ));
        assert!(matches!(
            SshConfigParser::parse_duration(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_host() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_host(vec![
                String::from("192.168.*.*"),
                String::from("!192.168.1.1"),
                String::from("172.26.104.*"),
                String::from("!172.26.104.10"),
            ])?,
            vec![
                HostClause::new(String::from("192.168.*.*"), false),
                HostClause::new(String::from("192.168.1.1"), true),
                HostClause::new(String::from("172.26.104.*"), false),
                HostClause::new(String::from("172.26.104.10"), true),
            ]
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_host() {
        assert!(matches!(
            SshConfigParser::parse_host(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_path() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_path(vec![String::from("/tmp/a.txt")])?,
            PathBuf::from("/tmp/a.txt")
        );
        Ok(())
    }

    #[test]
    fn should_parse_path_and_resolve_tilde() -> Result<(), SshParserError> {
        let mut expected = dirs::home_dir().unwrap();
        expected.push(".ssh/id_dsa");
        assert_eq!(
            SshConfigParser::parse_path(vec![String::from("~/.ssh/id_dsa")])?,
            expected
        );
        Ok(())
    }

    #[test]
    fn should_parse_path_list() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_path_list(vec![
                String::from("/tmp/a.txt"),
                String::from("/tmp/b.txt")
            ])?,
            vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/b.txt")]
        );
        Ok(())
    }

    #[test]
    fn should_fail_parse_path_list() {
        assert!(matches!(
            SshConfigParser::parse_path_list(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_fail_parsing_path() {
        assert!(matches!(
            SshConfigParser::parse_path(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_port() -> Result<(), SshParserError> {
        assert_eq!(SshConfigParser::parse_port(vec![String::from("22")])?, 22);
        Ok(())
    }

    #[test]
    fn should_fail_parsing_port() {
        assert!(matches!(
            SshConfigParser::parse_port(vec![String::from("1234567")]).unwrap_err(),
            SshParserError::ExpectedPort
        ));
        assert!(matches!(
            SshConfigParser::parse_port(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_string() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_string(vec![String::from("foobar")])?,
            String::from("foobar")
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_string() {
        assert!(matches!(
            SshConfigParser::parse_string(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
    }

    #[test]
    fn should_parse_unsigned() -> Result<(), SshParserError> {
        assert_eq!(
            SshConfigParser::parse_unsigned(vec![String::from("43")])?,
            43
        );
        Ok(())
    }

    #[test]
    fn should_fail_parsing_unsigned() {
        assert!(matches!(
            SshConfigParser::parse_unsigned(vec![String::from("abc")]).unwrap_err(),
            SshParserError::ExpectedUnsigned
        ));
        assert!(matches!(
            SshConfigParser::parse_unsigned(vec![]).unwrap_err(),
            SshParserError::MissingArgument
        ));
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
Ciphers     +a-manella,blowfish

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

Host *
    CaSignatureAlgorithms   random
    HostKeyAlgorithms   luigi,mario
    KexAlgorithms   desu,gigi
    Macs     concorde
    PubkeyAcceptedAlgorithms    desu,omar-crypt,fast-omar-crypt
"##;
        tmpfile.write_all(config.as_bytes()).unwrap();
        tmpfile
    }

    fn create_inverted_ssh_config() -> NamedTempFile {
        let mut tmpfile: tempfile::NamedTempFile =
            tempfile::NamedTempFile::new().expect("Failed to create tempfile");
        let config = r##"
Host *-host
    IdentityFile ~/.ssh/id_rsa_good

Host remote-*
    HostName hostname.com
    User user
    IdentityFile ~/.ssh/id_rsa_bad

Host *
    ConnectTimeout 15
    IdentityFile ~/.ssh/id_rsa_ugly
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
