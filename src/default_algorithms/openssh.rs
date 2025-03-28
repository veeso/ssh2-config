//! This file is autogenerated at build-time when `RELOAD_SSH_ALGO` is set to environment.

use crate::DefaultAlgorithms;

/// Default algorithms for ssh.
pub fn defaults() -> DefaultAlgorithms {
    DefaultAlgorithms {
        ca_signature_algorithms: vec![
            "ssh-ed25519".to_string(),
            "ecdsa-sha2-nistp256".to_string(),
            "ecdsa-sha2-nistp384".to_string(),
            "ecdsa-sha2-nistp521".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256@openssh.com".to_string(),
            "rsa-sha2-512".to_string(),
            "rsa-sha2-256".to_string(),
        ],
        ciphers: vec![
            "chacha20-poly1305@openssh.com".to_string(),
            "aes128-ctr,aes192-ctr,aes256-ctr".to_string(),
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com".to_string(),
        ],
        host_key_algorithms: vec![
            "ssh-ed25519-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp384-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp521-cert-v01@openssh.com".to_string(),
            "sk-ssh-ed25519-cert-v01@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "rsa-sha2-512-cert-v01@openssh.com".to_string(),
            "rsa-sha2-256-cert-v01@openssh.com".to_string(),
            "ssh-ed25519".to_string(),
            "ecdsa-sha2-nistp256".to_string(),
            "ecdsa-sha2-nistp384".to_string(),
            "ecdsa-sha2-nistp521".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256@openssh.com".to_string(),
            "rsa-sha2-512".to_string(),
            "rsa-sha2-256".to_string(),
        ],
        kex_algorithms: vec![
            "sntrup761x25519-sha512".to_string(),
            "sntrup761x25519-sha512@openssh.com".to_string(),
            "mlkem768x25519-sha256".to_string(),
            "curve25519-sha256".to_string(),
            "curve25519-sha256@libssh.org".to_string(),
            "ecdh-sha2-nistp256".to_string(),
            "ecdh-sha2-nistp384".to_string(),
            "ecdh-sha2-nistp521".to_string(),
            "diffie-hellman-group-exchange-sha256".to_string(),
            "diffie-hellman-group16-sha512".to_string(),
            "diffie-hellman-group18-sha512".to_string(),
            "diffie-hellman-group14-sha256".to_string(),
            "ssh-ed25519-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp384-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp521-cert-v01@openssh.com".to_string(),
            "sk-ssh-ed25519-cert-v01@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "rsa-sha2-512-cert-v01@openssh.com".to_string(),
            "rsa-sha2-256-cert-v01@openssh.com".to_string(),
            "ssh-ed25519".to_string(),
            "ecdsa-sha2-nistp256".to_string(),
            "ecdsa-sha2-nistp384".to_string(),
            "ecdsa-sha2-nistp521".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256@openssh.com".to_string(),
            "rsa-sha2-512".to_string(),
            "rsa-sha2-256".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
            "aes128-ctr,aes192-ctr,aes256-ctr".to_string(),
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
            "aes128-ctr,aes192-ctr,aes256-ctr".to_string(),
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com".to_string(),
            "umac-64-etm@openssh.com".to_string(),
            "umac-128-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha1-etm@openssh.com".to_string(),
            "umac-64@openssh.com".to_string(),
            "umac-128@openssh.com".to_string(),
            "hmac-sha2-256".to_string(),
            "hmac-sha2-512".to_string(),
            "hmac-sha1".to_string(),
            "umac-64-etm@openssh.com".to_string(),
            "umac-128-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha1-etm@openssh.com".to_string(),
            "umac-64@openssh.com".to_string(),
            "umac-128@openssh.com".to_string(),
            "hmac-sha2-256".to_string(),
            "hmac-sha2-512".to_string(),
            "hmac-sha1".to_string(),
            "none,zlib@openssh.com".to_string(),
            "none,zlib@openssh.com".to_string(),
        ],
        mac: vec![
            "umac-64-etm@openssh.com".to_string(),
            "umac-128-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha1-etm@openssh.com".to_string(),
            "umac-64@openssh.com".to_string(),
            "umac-128@openssh.com".to_string(),
            "hmac-sha2-256".to_string(),
            "hmac-sha2-512".to_string(),
            "hmac-sha1".to_string(),
        ],
        pubkey_accepted_algorithms: vec![
            "ssh-ed25519-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp384-cert-v01@openssh.com".to_string(),
            "ecdsa-sha2-nistp521-cert-v01@openssh.com".to_string(),
            "sk-ssh-ed25519-cert-v01@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string(),
            "rsa-sha2-512-cert-v01@openssh.com".to_string(),
            "rsa-sha2-256-cert-v01@openssh.com".to_string(),
            "ssh-ed25519".to_string(),
            "ecdsa-sha2-nistp256".to_string(),
            "ecdsa-sha2-nistp384".to_string(),
            "ecdsa-sha2-nistp521".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ecdsa-sha2-nistp256@openssh.com".to_string(),
            "rsa-sha2-512".to_string(),
            "rsa-sha2-256".to_string(),
        ],
    }
}
