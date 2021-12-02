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

/// Configuration field
#[derive(Eq, PartialEq)]
pub enum Field {
    Host,
    AddKeysToAgent,
    AddressFamily,
    BatchMode,
    BindAddress,
    BindInterface,
    CaSignatureAlgorithms,
    CertificateFile,
    CheckHostIp,
    Ciphers,
    ClearAllForwardings,
    Compression,
    ConnectionAttemps,
    ConnectTimeout,
    ControlMaster,
    ControlPath,
    DynamicForward,
    EscapeChar,
    ExitOnForwardFailure,
    ForwardAgent,
    ForwardX11,
    ForwardX11Trusted,
    GatewayPorts,
    GlobalKnownHostsFile,
    GSSAPIAuthentication,
    GSSAPIKeyExchange,
    GSSAPIClientIdentity,
    GSSAPIDelegateCredentials,
    GSSAPIRenewalForcesRekey,
    GSSAPITrustDns,
    HashKnownHosts,
    HostbasedAuthentication,
    HostKeyAlgorithms,
    HostKeyAlias,
    HostName,
    IdentitiesOnly,
    IdentityFile,
    KbdInteractiveAuthentication,
    KbdInteractiveDevices,
    KexAlgorithms,
    LocalCommand,
    LocalForward,
    LogLevel,
    Mac,
    NoHostAuthenticationForLocalhost,
    PreferredAuthentications,
    Protocol,
    ProxyCommand,
    PubkeyAcceptedAlgorithms,
    PubkeyAuthentication,
    RemoteForward,
    SendEnv,
    ServerAliveCountMax,
    ServerAliveInterval,
    SmartcardDevice,
    StrictHostKeyChecking,
    TcpKeepAlive,
    Tunnel,
    TunnelDevice,
    UserKnownHostsFile,
    VerifyHostKeyDns,
    VisualHostKey,
}

/// Syntax for a configuration field
#[derive(Eq, PartialEq)]
pub enum FieldSyntax {
    Boolean,
    BooleanOrString,
    Char,
    CommaSeparatedList,
    HostBlock,
    LogLevel,
    /// syntax is `a[:b]`
    OptionalSemicolonTuple,
    Path,
    Port,
    ProtocolVersion,
    SpaceSeparatedList,
    String,
    Unsigned,
}

// -- impl

impl Field {
    /// Get field syntax for given field
    pub fn syntax(&self) -> FieldSyntax {
        match self {
            Self::Host => FieldSyntax::HostBlock,
            Self::AddKeysToAgent => FieldSyntax::Boolean,
            Self::AddressFamily => FieldSyntax::BooleanOrString,
            Self::BatchMode => FieldSyntax::Boolean,
            Self::BindAddress => FieldSyntax::String,
            Self::BindInterface => FieldSyntax::String,
            Self::CaSignatureAlgorithms => FieldSyntax::CommaSeparatedList,
            Self::CertificateFile => FieldSyntax::Path,
            Self::CheckHostIp => FieldSyntax::Boolean,
            Self::Ciphers => FieldSyntax::CommaSeparatedList,
            Self::ClearAllForwardings => FieldSyntax::Boolean,
            Self::Compression => FieldSyntax::Boolean,
            Self::ConnectionAttemps => FieldSyntax::Unsigned,
            Self::ConnectTimeout => FieldSyntax::Unsigned,
            Self::ControlMaster => FieldSyntax::Boolean,
            Self::ControlPath => FieldSyntax::Path,
            Self::DynamicForward => FieldSyntax::Port,
            Self::EscapeChar => FieldSyntax::Char,
            Self::ExitOnForwardFailure => FieldSyntax::Boolean,
            Self::ForwardAgent => FieldSyntax::Boolean,
            Self::ForwardX11 => FieldSyntax::Boolean,
            Self::ForwardX11Trusted => FieldSyntax::Boolean,
            Self::GatewayPorts => FieldSyntax::Boolean,
            Self::GlobalKnownHostsFile => FieldSyntax::Path,
            Self::GSSAPIAuthentication => FieldSyntax::Boolean,
            Self::GSSAPIKeyExchange => FieldSyntax::Boolean,
            Self::GSSAPIClientIdentity => FieldSyntax::String,
            Self::GSSAPIDelegateCredentials => FieldSyntax::Boolean,
            Self::GSSAPIRenewalForcesRekey => FieldSyntax::Boolean,
            Self::GSSAPITrustDns => FieldSyntax::Boolean,
            Self::HashKnownHosts => FieldSyntax::Boolean,
            Self::HostbasedAuthentication => FieldSyntax::Boolean,
            Self::HostKeyAlgorithms => FieldSyntax::CommaSeparatedList,
            Self::HostKeyAlias => FieldSyntax::String,
            Self::HostName => FieldSyntax::String,
            Self::IdentitiesOnly => FieldSyntax::Boolean,
            Self::IdentityFile => FieldSyntax::Path,
            Self::KbdInteractiveAuthentication => FieldSyntax::Boolean,
            Self::KbdInteractiveDevices => FieldSyntax::CommaSeparatedList,
            Self::KexAlgorithms => FieldSyntax::CommaSeparatedList,
            Self::LocalCommand => FieldSyntax::String,
            Self::LocalForward => FieldSyntax::Port,
            Self::LogLevel => FieldSyntax::LogLevel,
            Self::Mac => FieldSyntax::CommaSeparatedList,
            Self::NoHostAuthenticationForLocalhost => FieldSyntax::Boolean,
            Self::PreferredAuthentications => FieldSyntax::CommaSeparatedList,
            Self::Protocol => FieldSyntax::ProtocolVersion,
            Self::ProxyCommand => FieldSyntax::String,
            Self::PubkeyAcceptedAlgorithms => FieldSyntax::CommaSeparatedList,
            Self::PubkeyAuthentication => FieldSyntax::Boolean,
            Self::RemoteForward => FieldSyntax::Port,
            Self::SendEnv => FieldSyntax::String,
            Self::ServerAliveCountMax => FieldSyntax::Unsigned,
            Self::ServerAliveInterval => FieldSyntax::Unsigned,
            Self::SmartcardDevice => FieldSyntax::String,
            Self::StrictHostKeyChecking => FieldSyntax::Boolean,
            Self::TcpKeepAlive => FieldSyntax::Boolean,
            Self::Tunnel => FieldSyntax::Boolean,
            Self::TunnelDevice => FieldSyntax::OptionalSemicolonTuple,
            Self::UserKnownHostsFile => FieldSyntax::Path,
            Self::VerifyHostKeyDns => FieldSyntax::Boolean,
            Self::VisualHostKey => FieldSyntax::Boolean,
        }
    }
}

impl FromStr for Field {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "addkeystoagent" => Ok(Self::AddKeysToAgent),
            "addressfamily" => Ok(Self::AddressFamily),
            "batchmode" => Ok(Self::BatchMode),
            "bindaddress" => Ok(Self::BindAddress),
            "bindinterface" => Ok(Self::BindInterface),
            "casignaturealgorithms" => Ok(Self::CaSignatureAlgorithms),
            "certificatefile" => Ok(Self::CertificateFile),
            "checkhostip" => Ok(Self::CheckHostIp),
            "ciphers" => Ok(Self::Ciphers),
            "clearallforwardings" => Ok(Self::ClearAllForwardings),
            "compression" => Ok(Self::Compression),
            "connectionattemps" => Ok(Self::ConnectionAttemps),
            "connecttimeout" => Ok(Self::ConnectTimeout),
            "controlmaster" => Ok(Self::ControlMaster),
            "controlpath" => Ok(Self::ControlPath),
            "dynamicforward" => Ok(Self::DynamicForward),
            "escapechar" => Ok(Self::EscapeChar),
            "exitonforwardfailure" => Ok(Self::ExitOnForwardFailure),
            "forwardagent" => Ok(Self::ForwardAgent),
            "forwardx11" => Ok(Self::ForwardX11),
            "forwardx11trusted" => Ok(Self::ForwardX11Trusted),
            "gatewayports" => Ok(Self::GatewayPorts),
            "globalknownhostsfile" => Ok(Self::GlobalKnownHostsFile),
            "gssapiauthentication" => Ok(Self::GSSAPIAuthentication),
            "gssapikeyexchange" => Ok(Self::GSSAPIKeyExchange),
            "gssapiclientidentity" => Ok(Self::GSSAPIClientIdentity),
            "gssapidelegatecredentials" => Ok(Self::GSSAPIDelegateCredentials),
            "gssapirenewalforcesrekey" => Ok(Self::GSSAPIRenewalForcesRekey),
            "gssapitrustdns" => Ok(Self::GSSAPITrustDns),
            "hashknownhosts" => Ok(Self::HashKnownHosts),
            "hostbasedauthentication" => Ok(Self::HostbasedAuthentication),
            "hostkeyalgorithms" => Ok(Self::HostKeyAlgorithms),
            "hostkeyalias" => Ok(Self::HostKeyAlias),
            "hostname" => Ok(Self::HostName),
            "identitiesonly" => Ok(Self::IdentitiesOnly),
            "identityfile" => Ok(Self::IdentityFile),
            "kbdinteractiveauthentication" => Ok(Self::KbdInteractiveAuthentication),
            "kbdinteractivedevices" => Ok(Self::KbdInteractiveDevices),
            "kexalgorithms" => Ok(Self::KexAlgorithms),
            "localcommand" => Ok(Self::LocalCommand),
            "localforward" => Ok(Self::LocalForward),
            "loglevel" => Ok(Self::LogLevel),
            "mac" => Ok(Self::Mac),
            "nohostauthenticationforlocalhost" => Ok(Self::NoHostAuthenticationForLocalhost),
            "preferredauthentications" => Ok(Self::PreferredAuthentications),
            "protocol" => Ok(Self::Protocol),
            "proxycommand" => Ok(Self::ProxyCommand),
            "pubkeyacceptedalgorithms" => Ok(Self::PubkeyAcceptedAlgorithms),
            "pubkeyauthentication" => Ok(Self::PubkeyAuthentication),
            "remoteforward" => Ok(Self::RemoteForward),
            "sendenv" => Ok(Self::SendEnv),
            "serveralivecountmax" => Ok(Self::ServerAliveCountMax),
            "serveraliveinterval" => Ok(Self::ServerAliveInterval),
            "smartcarddevice" => Ok(Self::SmartcardDevice),
            "stricthostkeychecking" => Ok(Self::StrictHostKeyChecking),
            "tcpkeepalive" => Ok(Self::TcpKeepAlive),
            "tunnel" => Ok(Self::Tunnel),
            "tunneldevice" => Ok(Self::TunnelDevice),
            "userknownhostsfile" => Ok(Self::UserKnownHostsFile),
            "verifyhostkeydns" => Ok(Self::VerifyHostKeyDns),
            "visualhostkey" => Ok(Self::VisualHostKey),
            _ => Err("Bad field name"),
        }
    }
}
