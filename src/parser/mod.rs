//! # parser
//!
//! Ssh config parser

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
use super::{Host, HostClause, HostParams, SshConfig};

use std::{
    io::{BufRead, Error as IoError},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

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
    #[error("IO error: {0}")]
    Io(IoError),
}

// -- parser

/// Ssh config parser
pub struct SshConfigParser;

impl SshConfigParser {
    /// Parse reader lines and apply parameters to configuration
    pub fn parse(config: &mut SshConfig, reader: &mut impl BufRead) -> SshParserResult<()> {
        // Current host pointer
        let mut current_host = config.hosts.last_mut().unwrap();
        let mut lines = reader.lines();
        // iter lines
        loop {
            let line = match lines.next() {
                None => break,
                Some(Err(err)) => return Err(SshParserError::Io(err)),
                Some(Ok(line)) => line.trim().to_string(),
            };
            // skip comments
            if line.starts_with('#') {
                continue;
            }
            // tokenize
            let (field, args) = match Self::tokenize(&line) {
                Ok(Some((field, args))) => (field, args),
                Ok(None) => continue, // Unsupported field
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
        Ok(())
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
                Self::resolve_algorithms(
                    &mut params.ca_signature_algorithms.as_mut().unwrap(),
                    algos,
                );
            }
            Field::CertificateFile => {
                params.certificate_file = Some(Self::parse_path(args)?);
            }
            Field::Ciphers => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.ciphers.is_none() {
                    params.ciphers = Some(Vec::new());
                }
                Self::resolve_algorithms(&mut params.ciphers.as_mut().unwrap(), algos);
            }
            Field::Compression => {
                params.compression = Some(Self::parse_boolean(args)?);
            }
            Field::ConnectTimeout => {
                params.connect_timeout = Some(Self::parse_duration(args)?);
            }
            Field::ConnectionAttemps => {
                params.connection_attemps = Some(Self::parse_unsigned(args)?);
            }
            Field::Host => { /* already handled before */ }
            Field::HostName => {
                params.host_name = Some(Self::parse_string(args)?);
            }
            Field::Mac => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.mac.is_none() {
                    params.mac = Some(Vec::new());
                }
                Self::resolve_algorithms(&mut params.mac.as_mut().unwrap(), algos);
            }
            Field::PubkeyAcceptedAlgorithms => {
                let algos = Self::parse_comma_separated_list(args)?;
                if params.pubkey_accepted_algorithms.is_none() {
                    params.pubkey_accepted_algorithms = Some(Vec::new());
                }
                Self::resolve_algorithms(
                    &mut params.pubkey_accepted_algorithms.as_mut().unwrap(),
                    algos,
                );
            }
            Field::PubkeyAuthentication => {
                params.pubkey_authentication = Some(Self::parse_boolean(args)?);
            }
            Field::RemoteForward => {
                params.remote_forward = Some(Self::parse_port(args)?);
            }
            Field::TcpKeepAlive => {
                params.tcp_keep_alive = Some(Self::parse_boolean(args)?);
            }
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
            let mut i = 0;
            while i < current_list.len() {
                if algos.contains(&current_list[i]) {
                    current_list.remove(i);
                }
                i += 1;
            }
        } else {
            *current_list = algos;
        }
    }

    /// Tokenize line if possible. Returns field name and args
    fn tokenize(line: &str) -> SshParserResult<Option<(Field, Vec<String>)>> {
        let mut tokens = line.trim().split_whitespace();
        let field = match tokens.next().map(|x| Field::from_str(x)) {
            Some(Ok(field)) => field,
            Some(Err(_)) => return Ok(None),
            None => return Err(SshParserError::MissingArgument),
        };
        let args = tokens
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        Ok(Some((field, args)))
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

    /// Parse path argument
    fn parse_path(args: Vec<String>) -> SshParserResult<PathBuf> {
        if let Some(s) = args.get(0) {
            Ok(PathBuf::from(s))
        } else {
            Err(SshParserError::MissingArgument)
        }
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
        if let Some(s) = args.get(0) {
            Ok(s.to_string())
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

    use super::*;

    use pretty_assertions::assert_eq;
    use tempfile::NamedTempFile;

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
    fn should_tokenize_line() {
        assert_eq!(
            SshConfigParser::tokenize("HostName 192.168.*.* 172.26.*.*")
                .ok()
                .unwrap()
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
            .unwrap()
            .unwrap(),
            (
                Field::HostName,
                vec![String::from("192.168.*.*"), String::from("172.26.*.*")]
            )
        );
    }

    #[test]
    fn should_not_tokenize_line() {
        assert!(SshConfigParser::tokenize("Omar     yes")
            .ok()
            .unwrap()
            .is_none());
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
}
