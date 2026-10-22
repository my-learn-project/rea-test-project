//! Keep this tool and its encrypted private key off machines receiving the client.
#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use license_core::{signing_message, validate_fields, License, PRODUCT, VERSION};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const KEY_AAD: &[u8] = b"card-demo/issuer-key/v1\0";
const MAX_KEY_BYTES: u64 = 16 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 1024;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    version,
    about = "Independent offline license issuer. Never ship this tool with clients."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a random signing key, encrypted at rest, and its public trust anchor.
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        /// Read one UTF-8 passphrase line from stdin, for controlled automation.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Issue a device-bound license; prints only the token to stdout.
    Issue {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        license_id: String,
        #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u32).range(1..=8784))]
        valid_hours: u32,
        #[arg(long)]
        passphrase_stdin: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedKey {
    version: u8,
    kdf: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(passphrase).map_err(|_| "Passphrase must be UTF-8")?;
    if text.chars().count() < 12 || passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(
            "Passphrase must have at least 12 characters and at most 1024 UTF-8 bytes".into(),
        );
    }
    if text.chars().any(char::is_control) {
        return Err("Passphrase cannot contain control characters".into());
    }
    Ok(())
}

fn read_passphrase(from_stdin: bool, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = if from_stdin {
        let mut bytes = Zeroizing::new(Vec::new());
        let stdin = io::stdin();
        let mut input = stdin.lock().take((MAX_PASSPHRASE_BYTES + 3) as u64);
        input.read_until(b'\n', &mut bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        bytes
    } else {
        let text = Zeroizing::new(rpassword::prompt_password("Private key passphrase: ")?);
        Zeroizing::new(text.as_bytes().to_vec())
    };
    validate_passphrase(&passphrase)?;
    if confirm && !from_stdin {
        let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
        if confirmation.as_bytes() != passphrase.as_slice() {
            return Err("Passphrases did not match".into());
        }
    }
    Ok(passphrase)
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
        .map_err(|_| "Invalid fixed KDF parameters")?;
    // Clear Argon2's password-dependent working memory as well as the derived key.
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    kdf.hash_password_into_with_memory(passphrase, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|_| "Key derivation failed")?;
    Ok(key)
}

fn encrypt_key(seed: &[u8; 32], passphrase: &[u8]) -> Result<EncryptedKey> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| "OS random source unavailable")?;
    getrandom::fill(&mut nonce).map_err(|_| "OS random source unavailable")?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Cipher initialization failed")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: KEY_AAD,
            },
        )
        .map_err(|_| "Private key encryption failed")?;
    Ok(EncryptedKey {
        version: 1,
        kdf: "argon2id-v19".into(),
        memory_kib: MEMORY_KIB,
        iterations: ITERATIONS,
        parallelism: PARALLELISM,
        cipher: "chacha20poly1305".into(),
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

fn decrypt_key(envelope: &EncryptedKey, passphrase: &[u8]) -> Result<SigningKey> {
    // Reject attacker-controlled resource costs and oversized encodings BEFORE running Argon2.
    if envelope.version != 1
        || envelope.kdf != "argon2id-v19"
        || envelope.memory_kib != MEMORY_KIB
        || envelope.iterations != ITERATIONS
        || envelope.parallelism != PARALLELISM
        || envelope.cipher != "chacha20poly1305"
        || envelope.salt.len() != 22
        || envelope.nonce.len() != 16
        || envelope.ciphertext.len() != 64
    {
        return Err("Unsupported or malformed encrypted key envelope".into());
    }
    let salt = URL_SAFE_NO_PAD.decode(&envelope.salt)?;
    let nonce = URL_SAFE_NO_PAD.decode(&envelope.nonce)?;
    let ciphertext = URL_SAFE_NO_PAD.decode(&envelope.ciphertext)?;
    if salt.len() != 16 || nonce.len() != 12 || ciphertext.len() != 48 {
        return Err("Invalid encrypted key field lengths".into());
    }
    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Cipher initialization failed")?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: KEY_AAD,
                },
            )
            .map_err(|_| "Wrong passphrase or encrypted key has been modified")?,
    );
    let seed: &[u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid decrypted key size")?;
    Ok(SigningKey::from_bytes(seed))
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn load_key(path: &Path, passphrase: &[u8]) -> Result<SigningKey> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err("Encrypted key exceeds 16 KiB limit".into());
    }
    let envelope: EncryptedKey = serde_json::from_slice(&bytes)?;
    decrypt_key(&envelope, passphrase)
}

fn keygen(private_key: &Path, public_key: &Path, passphrase_stdin: bool) -> Result<()> {
    if private_key == public_key || private_key.exists() || public_key.exists() {
        return Err(
            "Key paths must differ and neither key file may already exist; refusing overwrite"
                .into(),
        );
    }
    let passphrase = read_passphrase(passphrase_stdin, true)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "OS random source unavailable")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let envelope = encrypt_key(&seed, &passphrase)?;
    let encrypted = serde_json::to_vec_pretty(&envelope)?;
    let public_hex: String = signing_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    write_new(private_key, &encrypted)?;
    // If this second write fails, the encrypted private key is retained for recovery.
    write_new(public_key, format!("{public_hex}\n").as_bytes())?;
    eprintln!("Created encrypted private key: {}", private_key.display());
    eprintln!("Created public trust anchor: {}", public_key.display());
    eprintln!("Rebuild license-client whenever the public trust anchor changes.");
    Ok(())
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            private_key,
            public_key,
            passphrase_stdin,
        } => {
            keygen(&private_key, &public_key, passphrase_stdin)?;
        }
        Command::Issue {
            private_key,
            subject,
            device_id,
            license_id,
            valid_hours,
            passphrase_stdin,
        } => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let license = License {
                version: VERSION,
                product: PRODUCT.into(),
                license_id,
                subject,
                device_id,
                issued_at: now,
                expires_at: now
                    .checked_add(u64::from(valid_hours) * 3600)
                    .ok_or("License expiry overflow")?,
            };
            validate_fields(&license)?;
            let passphrase = read_passphrase(passphrase_stdin, false)?;
            let key = load_key(&private_key, &passphrase)?;
            let payload = serde_json::to_vec(&license)?;
            let signature = key.sign(&signing_message(&payload));
            println!(
                "L1.{}.{}",
                URL_SAFE_NO_PAD.encode(payload),
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("license-issuer: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_key_roundtrip_wrong_password_and_tampering() {
        let seed = [0x31; 32];
        let mut envelope = encrypt_key(&seed, b"test-passphrase-only").unwrap();
        assert_eq!(
            decrypt_key(&envelope, b"test-passphrase-only")
                .unwrap()
                .verifying_key(),
            SigningKey::from_bytes(&seed).verifying_key()
        );
        assert!(decrypt_key(&envelope, b"incorrect-passphrase").is_err());
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        envelope.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        assert!(decrypt_key(&envelope, b"test-passphrase-only").is_err());
    }

    #[test]
    fn rejects_resource_cost_changes_before_kdf() {
        let envelope = EncryptedKey {
            version: 1,
            kdf: "argon2id-v19".into(),
            memory_kib: u32::MAX,
            iterations: u32::MAX,
            parallelism: 1,
            cipher: "chacha20poly1305".into(),
            salt: "A".repeat(22),
            nonce: "A".repeat(16),
            ciphertext: "A".repeat(64),
        };
        assert!(decrypt_key(&envelope, b"test-passphrase-only").is_err());
    }

    #[test]
    fn passphrase_limits_are_enforced() {
        assert!(validate_passphrase(b"short").is_err());
        assert!(validate_passphrase(b"long-enough\npassword").is_err());
        assert!(validate_passphrase(&vec![b'a'; MAX_PASSPHRASE_BYTES + 1]).is_err());
        assert!(validate_passphrase(b"a strong demo password").is_ok());
    }

    #[test]
    fn encrypted_key_envelope_rejects_unknown_and_duplicate_fields() {
        let envelope = EncryptedKey {
            version: 1,
            kdf: "argon2id-v19".into(),
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            parallelism: PARALLELISM,
            cipher: "chacha20poly1305".into(),
            salt: "A".repeat(22),
            nonce: "A".repeat(16),
            ciphertext: "A".repeat(64),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        for modified in [
            json.replace("\"version\":1", "\"version\":1,\"allow_plaintext\":true"),
            json.replace("\"version\":1", "\"version\":1,\"version\":1"),
        ] {
            assert!(serde_json::from_str::<EncryptedKey>(&modified).is_err());
        }
    }

    #[test]
    fn exclusive_creation_does_not_overwrite() {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("card-demo-key-test-{name}.json"));
        write_new(&path, b"original").unwrap();
        assert!(write_new(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        fs::remove_file(path).unwrap();
    }
}
