# SSH_CONFIG(5) - OpenSSH Client Configuration File

## Overview

The `ssh_config` file is the OpenSSH client configuration file that allows users to configure SSH connection behavior
through various keywords and parameters.

## Configuration Priority

SSH obtains configuration data in the following order (first value wins):

1. Command-line options
2. User's configuration file (~/.ssh/config)
3. System-wide configuration file (/etc/ssh/ssh_config)

## File Format

- Sections separated by `Host` or `Match` specifications
- Keyword-argument pairs, one per line
- Comments begin with '#'
- Arguments may be enclosed in double quotes to represent spaces
- Keywords are case-insensitive; arguments are case-sensitive

## Core Sections

### Host and Match

**Host**: Restricts declarations to hosts matching specified patterns. Supports wildcards (*) and negation (!). A
single * provides global defaults.

**Match**: Restricts declarations based on conditions like `canonical`, `final`, `exec`, `localnetwork`, `host`,
`originalhost`, `tagged`, `command`, `user`, `localuser`, `version`, and `sessiontype`.

## Authentication Options

### AddKeysToAgent

Automatically add keys to `ssh-agent`. Options: `yes`, `ask`, `confirm`, `no`, or time interval. Default: `no`.

### IdentityFile

Specifies authentication identity files. Supports ECDSA, Ed25519, and RSA keys. Default: ~/.ssh/id_rsa, ~
/.ssh/id_ecdsa, ~/.ssh/id_ed25519, and security key variants.

### IdentitiesOnly

Use only configured identity files, even if `ssh-agent` offers additional identities. Default: `no`.

### IdentityAgent

Specifies Unix-domain socket for authentication agent communication. Overrides SSH_AUTH_SOCK environment variable.

### CertificateFile

Specifies user certificate file. Requires corresponding private key.

### PubkeyAuthentication

Enable public key authentication. Options: `yes` (default), `no`, `unbound`, or `host-bound`.

### PasswordAuthentication

Enable password authentication. Default: `yes`.

### KbdInteractiveAuthentication

Enable keyboard-interactive authentication. Default: `yes`.

### HostbasedAuthentication

Enable rhosts-based authentication with public keys. Default: `no`.

### GSSAPIAuthentication

Enable GSSAPI-based authentication. Default: `no`.

### PreferredAuthentications

Specifies authentication method order. Default: "gssapi-with-mic,hostbased,publickey,keyboard-interactive,password"

## Host Key Management

### StrictHostKeyChecking

Controls host key verification. Options:

- `yes`: Never auto-add keys; refuse changed keys
- `accept-new`: Auto-add new keys; refuse changed keys
- `no`/`off`: Auto-add and allow changed keys
- `ask`: Prompt user (default)

### CheckHostIP

Additionally check host IP in known_hosts file. Default: `no`.

### HostKeyAlgorithms

Specifies preferred host key signature algorithms with modifiers (+, -, ^).

### VerifyHostKeyDNS

Verify remote key using DNS SSHFP records. Default: `no`.

### UpdateHostKeys

Accept additional hostkeys from server after authentication. Default: `yes` (conditionally).

### RevokedHostKeys

Specifies revoked host public keys file (text or KRL format).

### GlobalKnownHostsFile

Global host key database files. Default: /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2

### UserKnownHostsFile

User host key database files. Default: ~/.ssh/known_hosts, ~/.ssh/known_hosts2

### HashKnownHosts

Hash hostnames in known_hosts file. Default: `no`.

### NoHostAuthenticationForLocalhost

Disable host authentication for localhost. Default: `no`.

## Cryptography Options

### Ciphers

Allowed ciphers and preference order. Supports modifiers (+, -, ^). Default includes chacha20-poly1305, AES-GCM
variants, and AES-CTR.

### MACs

Message authentication code algorithms in preference order. Default prioritizes encrypt-then-mac (-etm) variants.

### KexAlgorithms

Key exchange algorithms. Default includes post-quantum variants (mlkem768x25519, sntrup761x25519), elliptic curve, and
Diffie-Hellman options.

### PubkeyAcceptedAlgorithms

Signature algorithms for public key authentication.

### HostbasedAcceptedAlgorithms

Signature algorithms for hostbased authentication.

### CASignatureAlgorithms

Allowed certificate authority signature algorithms.

### RequiredRSASize

Minimum RSA key size in bits. Default: 1024.

## Connection Options

### Hostname

Real hostname to connect to. Supports tokens and IP addresses.

### Port

Remote port number. Default: 22.

### AddressFamily

Address family preference: `any` (default), `inet` (IPv4 only), or `inet6` (IPv6 only).

### BindAddress

Source address for local machine connections.

### BindInterface

Source interface for local machine connections.

### ConnectTimeout

Timeout in seconds for establishing connection. Applies to TCP and SSH protocol handshake.

### ConnectionAttempts

Number of connection attempts (one per second). Default: 1.

### ProxyCommand

Command to execute for connection. Supports token expansion.

### ProxyJump

Jump proxies as [user@]host[:port] or SSH URI. Enables sequential proxy connections.

### ProxyUseFdpass

ProxyCommand passes connected file descriptor. Default: `no`.

### BatchMode

Disable user interaction (passwords, host key confirmation). Default: `no`.

### StdinNull

Redirect stdin from /dev/null. Default: `no`.

### RequestTTY

TTY request behavior: `no`, `yes`, `force`, or `auto`.

### SessionType

Session type: `none` (no remote command), `subsystem`, or `default`.

## Port Forwarding

### LocalForward

Forward TCP port or Unix-domain socket from local machine over secure channel. Syntax: [bind_address:]port or Unix
socket path.

### RemoteForward

Forward TCP port or Unix-domain socket on remote machine. Supports SOCKS proxy mode.

### DynamicForward

Forward TCP port with dynamic application-level determination of destination. Supports SOCKS4/SOCKS5.

### GatewayPorts

Allow remote hosts to connect to forwarded ports. Default: `no`.

### ClearAllForwardings

Clear all configured port forwardings. Default: `no`.

### ExitOnForwardFailure

Terminate if unable to establish all requested forwardings. Default: `no`.

### PermitRemoteOpen

Restrict remote forwarding destinations. Syntax: host:port or IPv6 [address]:port.

### Tunnel

Request tun device forwarding. Options: `yes`, `point-to-point`, `ethernet`, or `no` (default).

### TunnelDevice

Specify tun devices: local_tun[:remote_tun]. Default: `any:any`.

## Session Management

### RemoteCommand

Command to execute on remote machine after successful connection.

### LocalCommand

Command to execute on local machine after successful connection.

### PermitLocalCommand

Allow local command execution. Default: `no`.

### ControlMaster

Enable session multiplexing. Options: `yes`, `no` (default), `ask`, `auto`, or `autoask`.

### ControlPath

Control socket path for connection sharing. Supports tokens and environment variables.

### ControlPersist

Keep master connection open in background. Default: `no`.

### ServerAliveInterval

Timeout in seconds after which keepalive message is sent. Default: 0.

### ServerAliveCountMax

Maximum keepalive messages without response before disconnect. Default: 3.

### TCPKeepAlive

Send TCP keepalive messages. Default: `yes`.

### ChannelTimeout

Inactivity timeout for channels. Syntax: type=interval pairs.

## Logging and Debugging

### LogLevel

Verbosity level: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, DEBUG3. Default: INFO.

### LogVerbose

Override LogLevel for specific source files and functions.

### FingerprintHash

Hash algorithm for key fingerprints: `md5` or `sha256` (default).

### VisualHostKey

Print ASCII art fingerprint representation. Default: `no`.

## Proxy and Connection Behavior

### CanonicalizeHostname

Enable explicit hostname canonicalization. Options: `no` (default), `yes`, or `always`.

### CanonicalDomains

Domain suffixes for hostname canonicalization search.

### CanonicalizeMaxDots

Maximum dots in hostname before canonicalization disabled. Default: 1.

### CanonicalizePermittedCNAMEs

Rules for CNAME following during canonicalization. Syntax: source_domain_list:target_domain_list.

### CanonicalizeFallbackLocal

Fail if hostname canonicalization fails. Default: `yes`.

## Environment and Variables

### SendEnv

Variables to send from local environment to server. Supports wildcards and negation.

### SetEnv

Directly specify environment variables for server: NAME=VALUE format.

### User

Remote login username.

### KnownHostsCommand

Command to obtain additional host keys beyond file-based sources.

## X11 and Agent Forwarding

### ForwardAgent

Forward authentication agent connection. Options: `yes`, `no` (default), explicit socket path, or environment variable.

### ForwardX11

Automatically redirect X11 connections. Default: `no`.

### ForwardX11Trusted

Grant remote X11 clients full display access. Default: `no`.

### ForwardX11Timeout

Timeout for untrusted X11 forwarding. Default: 20 minutes.

### XAuthLocation

Full pathname to xauth program. Default: /usr/X11R6/bin/xauth.

## Miscellaneous Options

### CompressionLevel

Compression level (1-9). Only used with Compression=yes.

### Compression

Enable compression. Default: `no`.

### EscapeChar

Escape character for interactive sessions. Default: '~'. Use `none` to disable.

### EnableEscapeCommandline

Enable command-line option in escape menu. Default: disabled.

### ForkAfterAuthentication

Background process after authentication. Default: `no`.

### ObscureKeystrokeTiming

Obscure keystroke timing from observers. Default: enabled with 20ms interval.

### NumberOfPasswordPrompts

Password prompts before giving up. Default: 3.

### RekeyLimit

Data/time limits before session key renegotiation. Default: cipher-dependent/none.

### EnableSSHKeysign

Enable ssh-keysign helper for hostbased authentication. Default: `no`.

### IPQoS

Differentiated Services Field Codepoint (DSCP) values. Default: `ef` (interactive), `none` (non-interactive).

### RefuseConnection

Refuse connection with error message via configuration.

### SyslogFacility

Syslog facility code: DAEMON, USER, AUTH, LOCAL0-7. Default: USER.

### Tag

Configuration tag name for Match directive reference.

### VersionAddendum

Additional text appended to SSH protocol banner.

### WarnWeakCrypto

Warn about weak cryptographic algorithms. Default: `yes`.

## Token Expansion

Available tokens for various directives:

- `%%`: Literal '%'
- `%C`: Hash of %l%h%p%r%j
- `%d`: Local user's home directory
- `%f`: Server host key fingerprint
- `%H`: Known hosts hostname/address
- `%h`: Remote hostname
- `%I`: KnownHostsCommand execution reason
- `%i`: Local user ID
- `%j`: ProxyJump option contents
- `%K`: Base64 encoded host key
- `%k`: Host key alias or remote hostname
- `%L`: Local hostname
- `%l`: Local hostname with domain
- `%n`: Original remote hostname
- `%p`: Remote port
- `%r`: Remote username
- `%T`: Tunnel interface or "NONE"
- `%t`: Server host key type
- `%u`: Local username

## Pattern Syntax

Patterns support:

- `*`: Wildcard matching zero or more characters
- `?`: Wildcard matching exactly one character
- `!`: Negation prefix

Pattern-lists use comma separation and support negation. Negated matches don't produce positive results alone; include a
positive term like `*`.

## Files

- **~/.ssh/config**: Per-user configuration file (requires strict permissions: read/write for user only)
- **/etc/ssh/ssh_config**: System-wide configuration file (must be world-readable)
