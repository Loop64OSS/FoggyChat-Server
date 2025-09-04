#![allow(dead_code)]
use aes_gcm::aead::rand_core::RngCore;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret, x25519};

pub const VERSION: u8 = 1;

/// Generates a new X25519 keypair.
pub fn keypairgen() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

/// Derives a key from the shared secret using HKDF with SHA-256.
fn derive_key(shared_secret: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"chacha20poly1305 key", &mut okm)
        .expect("HKDF expand should never fail with 32 bytes output");
    okm
}

pub fn encrypt(
    public: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&ephemeral);

    let shared = x25519(ephemeral.to_bytes(), public.to_bytes());

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(&shared, &salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;

    let mut nonce = XNonce::default();
    OsRng.fill_bytes(nonce.as_mut());

    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("Encrypt error: {:?}", e).into()
        },
    )?;
    // Format:
    // [version (1) | eph_pub (32) | nonce (24) | salt (16) | ciphertext (...)]
    let mut msg = Vec::with_capacity(1 + 32 + 24 + 16 + ciphertext.len());
    msg.push(VERSION);
    msg.extend_from_slice(eph_pub.as_bytes());
    msg.extend_from_slice(nonce.as_slice());
    msg.extend_from_slice(&salt);
    msg.extend_from_slice(&ciphertext);

    Ok(msg)
}

pub fn decrypt(
    secret: &StaticSecret,
    message: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // minimal length: 1 (ver) + 32 (eph_pub) + 24 (nonce) + 16 (salt) + 1 (ciphertext)
    if message.len() < 74 {
        return Err("Message too short".into());
    }

    let version = message[0];
    if version != VERSION {
        return Err(format!("Unsupported version: {}", version).into());
    }

    let eph_bytes: [u8; 32] = message[1..33].try_into()?;
    let eph_pub = PublicKey::from(eph_bytes);

    let nonce = XNonce::from_slice(&message[33..57]);

    let salt: [u8; 16] = message[57..73].try_into()?;

    let ciphertext = &message[73..];

    let shared = x25519(secret.to_bytes(), eph_pub.to_bytes());
    let key = derive_key(&shared, &salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        Box::<dyn std::error::Error + Send + Sync>::from(format!("Decrypt error: {:?}", e))
    })?;

    Ok(plaintext)
}

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose};
mod tests {
    #[allow(unused_imports)] // zamknięcie walonego rust analyzera
    use super::*;

    #[test]
    fn keypair_and_crypto_roundtrip() {
        let (rec_sec_bytes, rec_pub_bytes) = keypairgen();
        let rec_sec = StaticSecret::from(rec_sec_bytes);
        let rec_pub = PublicKey::from(rec_pub_bytes);

        let msg = "TEST TEST TEST 123 ąęðąśðąśðąś".as_bytes();

        let encrypted = encrypt(&rec_pub, msg).expect("Encryption failed");
        let decrypted = decrypt(&rec_sec, &encrypted).expect("Decryption failed");

        let base64_encoded = general_purpose::STANDARD.encode(&encrypted);

        println!(
            "Public key: {}",
            general_purpose::STANDARD.encode(rec_pub.as_bytes())
        );
        println!(
            "Private key: {}",
            general_purpose::STANDARD.encode(rec_sec.as_bytes())
        );

        println!("Encrypted message: {}", base64_encoded);
        println!(
            "Decrypted message: {:?}",
            String::from_utf8_lossy(&decrypted)
        );

        assert_eq!(&decrypted, msg);
    }
}
