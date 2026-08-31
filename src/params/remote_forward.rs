//! Typed values for remote forwarding directives.

use std::fmt;
use std::path::{Path, PathBuf};

/// Describes a complete `RemoteForward` directive.
///
/// A missing destination represents SOCKS proxy mode.
///
/// # Examples
///
/// ```rust
/// use ssh2_config::{RemoteForward, RemoteForwardDestination, RemoteForwardListen};
///
/// let forward = RemoteForward::new(
///     RemoteForwardListen::Port(8080),
///     Some(RemoteForwardDestination::Host {
///         host: "localhost".to_string(),
///         port: 80,
///     }),
/// );
///
/// assert_eq!(forward.to_string(), "8080 localhost:80");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForward {
    /// Listening endpoint on the remote machine.
    pub listen: RemoteForwardListen,
    /// Optional destination on the local machine.
    pub destination: Option<RemoteForwardDestination>,
}

impl RemoteForward {
    /// Creates a remote forwarding specification.
    pub fn new(listen: RemoteForwardListen, destination: Option<RemoteForwardDestination>) -> Self {
        Self {
            listen,
            destination,
        }
    }
}

impl fmt::Display for RemoteForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{listen}", listen = self.listen)?;
        if let Some(destination) = &self.destination {
            write!(f, " {destination}")?;
        }
        Ok(())
    }
}

/// Describes the listening endpoint of a remote forwarding directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteForwardListen {
    /// Listen on a port using the server's default bind address.
    Port(u16),
    /// Listen on a host and port.
    Host {
        /// Bind host, address, wildcard, or empty string.
        host: String,
        /// Bind port.
        port: u16,
    },
    /// Listen on a Unix-domain socket.
    UnixSocket(PathBuf),
}

impl fmt::Display for RemoteForwardListen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(port) => write!(f, "{port}"),
            Self::Host { host, port } => write_host_port(f, host, *port),
            Self::UnixSocket(path) => write_socket_path(f, path),
        }
    }
}

/// Describes the destination endpoint of a remote forwarding directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteForwardDestination {
    /// Connect to a host and port.
    Host {
        /// Destination host or address.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// Connect to a Unix-domain socket.
    UnixSocket(PathBuf),
}

impl fmt::Display for RemoteForwardDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host { host, port } => write_host_port(f, host, *port),
            Self::UnixSocket(path) => write_socket_path(f, path),
        }
    }
}

fn write_host_port(f: &mut fmt::Formatter<'_>, host: &str, port: u16) -> fmt::Result {
    if host.contains(':') {
        write!(f, "[{host}]:{port}")
    } else {
        write!(f, "{host}:{port}")
    }
}

fn write_socket_path(f: &mut fmt::Formatter<'_>, path: &Path) -> fmt::Result {
    let path = path.display().to_string();
    if path.chars().any(char::is_whitespace) {
        write!(
            f,
            "\"{path}\"",
            path = path.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        write!(f, "{path}")
    }
}
