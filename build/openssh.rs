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
        .map(split_algos)
        .unwrap_or_default();

    let ciphers = defines
        .get("KEX_CLIENT_ENCRYPT")
        .map(split_algos)
        .unwrap_or_default();

    let host_key_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(split_algos)
        .unwrap_or_default();

    let kex_algorithms = defines
        .get("KEX_CLIENT")
        .map(split_algos)
        .unwrap_or_default();

    let mac = defines
        .get("KEX_CLIENT_MAC")
        .map(split_algos)
        .unwrap_or_default();

    let pubkey_accepted_algorithms = defines
        .get("KEX_DEFAULT_PK_ALG")
        .map(split_algos)
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
fn split_algos(s: &String) -> Vec<String> {
    s.replace(',', " ")
        .split_whitespace()
        .map(|s| format!(r#""{s}""#))
        .collect()
}
