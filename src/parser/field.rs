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
    BindAddress,
    BindInterface,
    CaSignatureAlgorithms,
    CertificateFile,
    Ciphers,
    Compression,
    ConnectionAttemps,
    ConnectTimeout,
    HostName,
    Mac,
    PubkeyAcceptedAlgorithms,
    PubkeyAuthentication,
    RemoteForward,
    TcpKeepAlive,
}

impl FromStr for Field {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "bindaddress" => Ok(Self::BindAddress),
            "bindinterface" => Ok(Self::BindInterface),
            "casignaturealgorithms" => Ok(Self::CaSignatureAlgorithms),
            "certificatefile" => Ok(Self::CertificateFile),
            "ciphers" => Ok(Self::Ciphers),
            "compression" => Ok(Self::Compression),
            "connectionattemps" => Ok(Self::ConnectionAttemps),
            "connecttimeout" => Ok(Self::ConnectTimeout),
            "hostname" => Ok(Self::HostName),
            "mac" => Ok(Self::Mac),
            "pubkeyacceptedalgorithms" => Ok(Self::PubkeyAcceptedAlgorithms),
            "pubkeyauthentication" => Ok(Self::PubkeyAuthentication),
            "remoteforward" => Ok(Self::RemoteForward),
            "tcpkeepalive" => Ok(Self::TcpKeepAlive),
            _ => Err("Bad field name"),
        }
    }
}
