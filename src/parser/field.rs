//! # field
//!
//! Ssh config fields

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
use std::str::FromStr;

/// Configuration field.
/// This enum defines ALL THE SUPPORTED fields in ssh config,
/// as described at <http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5>.
/// Only a few of them are implemented, as described in `HostParams` struct.
#[derive(Debug, Eq, PartialEq)]
pub enum Field {
    Host,
    BindAddress,
    BindInterface,
    CaSignatureAlgorithms,
    CertificateFile,
    Ciphers,
    Compression,
    ConnectionAttempts,
    ConnectTimeout,
    HostName,
    KexAlgorithms,
    Mac,
    PubkeyAcceptedAlgorithms,
    PubkeyAuthentication,
    RemoteForward,
    TcpKeepAlive,
    User,
    // -- not implemented
    AddKeysToAgent,
    AddressFamily,
    BatchMode,
    CanonicalDomains,
    CanonicalizeFallbackLock,
    CanonicalizeHostname,
    CanonicalizeMaxDots,
    CanonicalizePermittedCNAMEs,
    CheckHostIP,
    ClearAllForwardings,
    ControlMaster,
    ControlPath,
    ControlPersist,
    DynamicForward,
    EnableSSHKeysign,
    EscapeChar,
    ExitOnForwardFailure,
    FingerprintHash,
    ForkAfterAuthentication,
    ForwardAgent,
    ForwardX11,
    ForwardX11Timeout,
    GatewayPorts,
    GlobalKnownHostsFile,
    GSSAPIAuthentication,
    GSSAPIDelegateCredentials,
    HashKnownHosts,
    HostbasedAcceptedAlgorithms,
    HostbasedAuthentication,
    HostKeyAlgorithms,
    HostKeyAlias,
    IdentitiesOnly,
    IdentityAgent,
    IdentityFile,
    IgnoreUnknown,
    Include,
    IPQoS,
    KbdInteractiveAuthentication,
    KbdInteractiveDevices,
    KnownHostsCommand,
    LocalCommand,
    LocalForward,
    LogLevel,
    LogVerbose,
    NoHostAuthenticationForLocalhost,
    NumberOfPasswordPrompts,
    PasswordAuthentication,
    PermitLocalCommand,
    PermitRemoteOpen,
    PKCS11Provider,
    Port,
    PreferredAuthentications,
    ProxyCommand,
    ProxyJump,
    ProxyUseFdpass,
    RekeyLimit,
    RequestTTY,
    RevokedHostKeys,
    SecruityKeyProvider,
    SendEnv,
    ServerAliveCountMax,
    ServerAliveInterval,
    SessionType,
    SetEnv,
    StdinNull,
    StreamLocalBindMask,
    StrictHostKeyChecking,
    SyslogFacility,
    UpdateHostKeys,
    UserKnownHostsFile,
    VerifyHostKeyDNS,
    VisualHostKey,
    XAuthLocation,
}

impl FromStr for Field {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "bindaddress" => Ok(Self::BindAddress),
            "bindinterface" => Ok(Self::BindInterface),
            "casignaturealgorithms" => Ok(Self::CaSignatureAlgorithms),
            "certificatefile" => Ok(Self::CertificateFile),
            "ciphers" => Ok(Self::Ciphers),
            "compression" => Ok(Self::Compression),
            "connectionattempts" => Ok(Self::ConnectionAttempts),
            "connecttimeout" => Ok(Self::ConnectTimeout),
            "hostname" => Ok(Self::HostName),
            "kexalgorithms" => Ok(Self::KexAlgorithms),
            "mac" | "macs" => Ok(Self::Mac),
            "pubkeyacceptedalgorithms" => Ok(Self::PubkeyAcceptedAlgorithms),
            "pubkeyauthentication" => Ok(Self::PubkeyAuthentication),
            "remoteforward" => Ok(Self::RemoteForward),
            "tcpkeepalive" => Ok(Self::TcpKeepAlive),
            "user" => Ok(Self::User),
            // -- not implemented fields
            "addkeystoagent" => Ok(Self::AddKeysToAgent),
            "addressfamily" => Ok(Self::AddressFamily),
            "batchmode" => Ok(Self::BatchMode),
            "canonicaldomains" => Ok(Self::CanonicalDomains),
            "canonicalizefallbacklock" => Ok(Self::CanonicalizeFallbackLock),
            "canonicalizehostname" => Ok(Self::CanonicalizeHostname),
            "canonicalizemaxdots" => Ok(Self::CanonicalizeMaxDots),
            "canonicalizepermittedcnames" => Ok(Self::CanonicalizePermittedCNAMEs),
            "checkhostip" => Ok(Self::CheckHostIP),
            "clearallforwardings" => Ok(Self::ClearAllForwardings),
            "controlmaster" => Ok(Self::ControlMaster),
            "controlpath" => Ok(Self::ControlPath),
            "controlpersist" => Ok(Self::ControlPersist),
            "dynamicforward" => Ok(Self::DynamicForward),
            "enablesshkeysign" => Ok(Self::EnableSSHKeysign),
            "escapechar" => Ok(Self::EscapeChar),
            "exitonforwardfailure" => Ok(Self::ExitOnForwardFailure),
            "fingerprinthash" => Ok(Self::FingerprintHash),
            "forkafterauthentication" => Ok(Self::ForkAfterAuthentication),
            "forwardagent" => Ok(Self::ForwardAgent),
            "forwardx11" => Ok(Self::ForwardX11),
            "forwardx11timeout" => Ok(Self::ForwardX11Timeout),
            "gatewayports" => Ok(Self::GatewayPorts),
            "globalknownhostsfile" => Ok(Self::GlobalKnownHostsFile),
            "gssapiauthentication" => Ok(Self::GSSAPIAuthentication),
            "gssapidelegatecredentials" => Ok(Self::GSSAPIDelegateCredentials),
            "hashknownhosts" => Ok(Self::HashKnownHosts),
            "hostbasedacceptedalgorithms" => Ok(Self::HostbasedAcceptedAlgorithms),
            "hostbasedauthentication" => Ok(Self::HostbasedAuthentication),
            "hostkeyalgorithms" => Ok(Self::HostKeyAlgorithms),
            "hostkeyalias" => Ok(Self::HostKeyAlias),
            "identitiesonly" => Ok(Self::IdentitiesOnly),
            "identityagent" => Ok(Self::IdentityAgent),
            "identityfile" => Ok(Self::IdentityFile),
            "ignoreunknown" => Ok(Self::IgnoreUnknown),
            "include" => Ok(Self::Include),
            "ipqos" => Ok(Self::IPQoS),
            "kbdinteractiveauthentication" => Ok(Self::KbdInteractiveAuthentication),
            "kbdinteractivedevices" => Ok(Self::KbdInteractiveDevices),
            "knownhostscommand" => Ok(Self::KnownHostsCommand),
            "localcommand" => Ok(Self::LocalCommand),
            "localforward" => Ok(Self::LocalForward),
            "loglevel" => Ok(Self::LogLevel),
            "logverbose" => Ok(Self::LogVerbose),
            "nohostauthenticationforlocalhost" => Ok(Self::NoHostAuthenticationForLocalhost),
            "numberofpasswordprompts" => Ok(Self::NumberOfPasswordPrompts),
            "passwordauthentication" => Ok(Self::PasswordAuthentication),
            "permitlocalcommand" => Ok(Self::PermitLocalCommand),
            "permitremoteopen" => Ok(Self::PermitRemoteOpen),
            "pkcs11provider" => Ok(Self::PKCS11Provider),
            "port" => Ok(Self::Port),
            "preferredauthentications" => Ok(Self::PreferredAuthentications),
            "proxycommand" => Ok(Self::ProxyCommand),
            "proxyjump" => Ok(Self::ProxyJump),
            "proxyusefdpass" => Ok(Self::ProxyUseFdpass),
            "rekeylimit" => Ok(Self::RekeyLimit),
            "requesttty" => Ok(Self::RequestTTY),
            "revokedhostkeys" => Ok(Self::RevokedHostKeys),
            "secruitykeyprovider" => Ok(Self::SecruityKeyProvider),
            "sendenv" => Ok(Self::SendEnv),
            "serveralivecountmax" => Ok(Self::ServerAliveCountMax),
            "serveraliveinterval" => Ok(Self::ServerAliveInterval),
            "sessiontype" => Ok(Self::SessionType),
            "setenv" => Ok(Self::SetEnv),
            "stdinnull" => Ok(Self::StdinNull),
            "streamlocalbindmask" => Ok(Self::StreamLocalBindMask),
            "stricthostkeychecking" => Ok(Self::StrictHostKeyChecking),
            "syslogfacility" => Ok(Self::SyslogFacility),
            "updatehostkeys" => Ok(Self::UpdateHostKeys),
            "userknownhostsfile" => Ok(Self::UserKnownHostsFile),
            "verifyhostkeydns" => Ok(Self::VerifyHostKeyDNS),
            "visualhostkey" => Ok(Self::VisualHostKey),
            "xauthlocation" => Ok(Self::XAuthLocation),
            // -- unknwon field
            _ => Err(s.to_string()),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_parse_field_from_string() {
        assert_eq!(Field::from_str("Host").ok().unwrap(), Field::Host);
        assert_eq!(
            Field::from_str("BindAddress").ok().unwrap(),
            Field::BindAddress
        );
        assert_eq!(
            Field::from_str("BindInterface").ok().unwrap(),
            Field::BindInterface
        );
        assert_eq!(
            Field::from_str("CaSignatureAlgorithms").ok().unwrap(),
            Field::CaSignatureAlgorithms
        );
        assert_eq!(
            Field::from_str("CertificateFile").ok().unwrap(),
            Field::CertificateFile
        );
        assert_eq!(Field::from_str("Ciphers").ok().unwrap(), Field::Ciphers);
        assert_eq!(
            Field::from_str("Compression").ok().unwrap(),
            Field::Compression
        );
        assert_eq!(
            Field::from_str("ConnectionAttempts").ok().unwrap(),
            Field::ConnectionAttempts
        );
        assert_eq!(
            Field::from_str("ConnectTimeout").ok().unwrap(),
            Field::ConnectTimeout
        );
        assert_eq!(Field::from_str("HostName").ok().unwrap(), Field::HostName);
        assert_eq!(Field::from_str("Mac").ok().unwrap(), Field::Mac);
        assert_eq!(
            Field::from_str("PubkeyAcceptedAlgorithms").ok().unwrap(),
            Field::PubkeyAcceptedAlgorithms
        );
        assert_eq!(
            Field::from_str("PubkeyAuthentication").ok().unwrap(),
            Field::PubkeyAuthentication
        );
        assert_eq!(
            Field::from_str("RemoteForward").ok().unwrap(),
            Field::RemoteForward
        );
        assert_eq!(
            Field::from_str("TcpKeepAlive").ok().unwrap(),
            Field::TcpKeepAlive
        );
    }

    #[test]
    fn should_fail_parsing_field() {
        assert!(Field::from_str("CristinaDavena").is_err());
    }
}
