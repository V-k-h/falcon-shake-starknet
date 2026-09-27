//! `falcon-signer`: key generation and signing for the falcon-shake-starknet accounts.
//!
//!     falcon-signer keygen --out KEY.json
//!     falcon-signer public-key --key KEY.json
//!     falcon-signer sign --key KEY.json --hash TX_HASH [--direct]
//!
//! Every command prints JSON. `keygen` writes the PQClean key bytes as hex to a new file
//! (never overwriting, owner-only permissions on Unix) and prints the account's 29-felt
//! constructor key. `sign` prints the 60-felt hint signature, or with `--direct` the 31-felt
//! direct signature, plus the SHAKE-256 blocks its hash-to-point consumes on-chain.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use falcon_shake_signer::{Felt, Keypair};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct KeyFile {
    scheme: String,
    public_key: String,
    secret_key: String,
}

const SCHEME: &str = "falcon-512 (PQClean, round-3 hash-to-point)";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn felts(values: &[Felt]) -> Vec<String> {
    values.iter().map(Felt::to_hex).collect()
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn load(path: &str) -> Result<Keypair, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let file: KeyFile = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    if file.scheme != SCHEME {
        return Err(format!("{path}: unsupported scheme {:?}", file.scheme));
    }
    Keypair::from_bytes(&unhex(&file.public_key)?, &unhex(&file.secret_key)?)
        .map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<serde_json::Value, String> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let path = flag(args, "--out")?;
            let key = Keypair::generate();
            let file = KeyFile {
                scheme: SCHEME.into(),
                public_key: hex(key.public_bytes()),
                secret_key: hex(key.secret_bytes()),
            };
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut out = options.open(path).map_err(|e| format!("{path}: {e}"))?;
            out.write_all(serde_json::to_string_pretty(&file).unwrap().as_bytes())
                .map_err(|e| format!("{path}: {e}"))?;
            Ok(json!({ "public_key": felts(&key.public_key_felts().map_err(|e| e.to_string())?) }))
        }
        Some("public-key") => {
            let key = load(flag(args, "--key")?)?;
            Ok(json!({ "public_key": felts(&key.public_key_felts().map_err(|e| e.to_string())?) }))
        }
        Some("sign") => {
            let key = load(flag(args, "--key")?)?;
            let hash = Felt::from_hex(flag(args, "--hash")?).map_err(|e| e.to_string())?;
            let sig = key.sign(hash).map_err(|e| e.to_string())?;
            let layout = if args.iter().any(|a| a == "--direct") {
                sig.direct()
            } else {
                sig.hint()
            };
            Ok(json!({ "signature": felts(layout), "blocks": sig.blocks }))
        }
        _ => Err(
            "usage: falcon-signer keygen --out KEY.json | public-key --key KEY.json | \
                  sign --key KEY.json --hash TX_HASH [--direct]"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("falcon-signer: {e}");
            ExitCode::FAILURE
        }
    }
}
