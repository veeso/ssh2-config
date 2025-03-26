/// Default algorithms for ssh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultAlgorithms {
    pub ca_signature_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub kex_algorithms: Vec<String>,
    pub mac: Vec<String>,
    pub pubkey_accepted_algorithms: Vec<String>,
}

impl Default for DefaultAlgorithms {
    fn default() -> Self {
        // TODO: read from build
        Self {
            ca_signature_algorithms: vec![],
            ciphers: vec![],
            host_key_algorithms: vec![],
            kex_algorithms: vec![],
            mac: vec![],
            pubkey_accepted_algorithms: vec![],
        }
    }
}

impl DefaultAlgorithms {
    /// Create a new instance of [`DefaultAlgorithms`] with empty fields.
    pub fn empty() -> Self {
        Self {
            ca_signature_algorithms: vec![],
            ciphers: vec![],
            host_key_algorithms: vec![],
            kex_algorithms: vec![],
            mac: vec![],
            pubkey_accepted_algorithms: vec![],
        }
    }
}
