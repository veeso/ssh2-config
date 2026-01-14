use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::define_parser::parse_defines;

const OPENSSH_TAG: &str = "V_10_2_P1";

/// Default algorithms for ssh.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MyPrefs {
    pub ca_signature_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub kex_algorithms: Vec<String>,
    pub mac: Vec<String>,
    pub pubkey_accepted_algorithms: Vec<String>,
}

pub fn get_my_prefs() -> anyhow::Result<MyPrefs> {
    let out_dir = std::env::var_os("OUT_DIR")
        .map(|s| PathBuf::from(s).join("openssh"))
        .ok_or_else(|| anyhow::anyhow!("OUT_DIR not set"))?;
    let build_dir = out_dir.join("build");
    let inner_dir = build_dir.join("src");

    std::fs::remove_dir_all(&build_dir).ok();
    std::fs::create_dir_all(&inner_dir).ok();

    clone_openssh(&inner_dir)?;

    let my_proposal_path = inner_dir.join("myproposal.h");

    let reader = std::io::BufReader::new(std::fs::File::open(my_proposal_path)?);
    let defines = parse_defines(reader)?;

    let ca_signature_algorithms = defines
        .get("SSH_ALLOWED_CA_SIGALGS")
        .map(|s| get_algos_for(s, AlgoType::Pubkey))
        .unwrap_or_default();

    let ciphers = defines
        .get("KEX_CLIENT_ENCRYPT")
        .map(|s| get_algos_for(s, AlgoType::Cipher))
        .unwrap_or_default();

    let host_key_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(|s| get_algos_for(s, AlgoType::Pubkey))
        .unwrap_or_default();

    let kex_algorithms = defines
        .get("KEX_CLIENT_KEX")
        .map(|s| get_algos_for(s, AlgoType::Kex))
        .unwrap_or_default();

    let mac = defines
        .get("KEX_CLIENT_MAC")
        .map(|s| get_algos_for(s, AlgoType::Mac))
        .unwrap_or_default();

    let pubkey_accepted_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(|s| get_algos_for(s, AlgoType::Pubkey))
        .unwrap_or_default();

    Ok(MyPrefs {
        ca_signature_algorithms,
        ciphers,
        host_key_algorithms,
        kex_algorithms,
        mac,
        pubkey_accepted_algorithms,
    })
}

fn clone_openssh(path: &Path) -> anyhow::Result<()> {
    let repo_url = "https://github.com/openssh/openssh-portable.git";
    let repo = git2::Repository::clone(repo_url, path)?;

    let obj = repo.revparse_single(OPENSSH_TAG)?;

    let commit = obj.peel_to_commit()?;

    repo.checkout_tree(&obj, None)?;

    repo.set_head_detached(commit.id())?;

    Ok(())
}

/// Split algorithms string into vector of quoted strings
fn get_algos_for(s: impl AsRef<str>, algo_type: AlgoType) -> Vec<String> {
    let mut seen = HashSet::new();
    s.as_ref()
        .replace(',', " ")
        .split_whitespace()
        .filter_map(|s| {
            let algo = s.trim().to_string();
            if !seen.contains(&algo) && is_algo_valid_for(&algo, algo_type) {
                seen.insert(algo.clone());
                Some(algo)
            } else {
                seen.insert(algo.clone());
                None
            }
        })
        .collect()
}

/// Types of algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum AlgoType {
    Kex,
    Cipher,
    Mac,
    Pubkey,
}

impl AlgoType {
    /// Returns the possible prefixes for each algorithm type
    fn valid_prefix(&self) -> &'static [&'static str] {
        match self {
            AlgoType::Kex => &["curve25519", "diffie-hellman", "ecdh", "sntrup", "mlkem"],
            AlgoType::Cipher => &["aes", "chacha20", "twofish", "blowfish", "cast"],
            AlgoType::Mac => &["hmac", "umac"],
            AlgoType::Pubkey => &["ssh-", "ecdsa-", "sk-", "rsa-"],
        }
    }
}

/// Check whether an algo must be kept by applying the following rules
fn is_algo_valid_for(algo: &str, algo_type: AlgoType) -> bool {
    algo_type
        .valid_prefix()
        .iter()
        .any(|prefix| algo.starts_with(*prefix))
}
