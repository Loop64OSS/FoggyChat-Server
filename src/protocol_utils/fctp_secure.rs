use std::sync::RwLock;

use lazy_static::lazy_static;
use tokio::io::AsyncWriteExt;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypt::{self, asymmetric},
    protocol_utils::{
        fctp::{FctpError, FctpMessage},
        fctp_client::{self, Clients},
    },
};

/* Certificate storage (server cert used during key exchange) */
lazy_static! {
    static ref CERT_PUB: RwLock<PublicKey> = RwLock::new(PublicKey::from([0u8; 32]));
    static ref CERT_SEC: RwLock<StaticSecret> = RwLock::new(StaticSecret::from([0u8; 32]));
}

/* Set server certificate keypair */
pub fn set_cert(new_pubkey: PublicKey, new_sec: StaticSecret) {
    let mut pubkey = CERT_PUB.write().expect("Lock poisoned");
    *pubkey = new_pubkey;
    let mut sec = CERT_SEC.write().expect("Lock poisoned");
    *sec = new_sec;
}

/* Return server certificate public key */
pub fn get_cert_pub() -> PublicKey {
    CERT_PUB.read().expect("Lock poisoned").clone()
}

/* Return server certificate secret */
pub fn get_cert_sec() -> StaticSecret {
    CERT_SEC.read().expect("Lock poisoned").clone()
}

/* Handle client's exchange message: decrypt client's exchange pubkey and
respond with encrypted session key. */
pub async fn handle_key_exchange(
    msg: &[u8],
    client_id: &str,
    clients: &Clients,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg_str = std::str::from_utf8(msg)?.trim();
    let decoded = crypt::utils::base64_decode(msg_str)?;
    let decrypted = asymmetric::decrypt(&get_cert_sec(), &decoded)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    if decrypted.len() != 32 {
        return Err("Invalid exchange key length".into());
    }

    let mut exchange_pubkey_bytes = [0u8; 32];
    exchange_pubkey_bytes.copy_from_slice(&decrypted);
    let exchange_pubkey = PublicKey::from(exchange_pubkey_bytes);

    println!("Received exchange key from client: {}", client_id);

    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        client_info.conn_session_key = crypt::symmetric::keygen();

        let encrypted = asymmetric::encrypt(&exchange_pubkey, &client_info.conn_session_key)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        let encrypted_b64 = crypt::utils::base64_encode(&encrypted);

        let mut writer = client_info.socket.lock().await;
        writer
            .write_all(format!("{}\r\n\r\n", encrypted_b64).as_bytes())
            .await?;

        println!("Sent session key to client: {}", client_id);
    }

    Ok(())
}

/* Handle a client's PublicKeyExchange message (store client's E2EE public key) */
pub async fn handle_public_key_exchange(
    fctp_message: FctpMessage,
    client_id: &str,
    clients: &fctp_client::Clients,
) -> Result<(), FctpError> {
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        let decoded = crypt::utils::base64_decode(fctp_message.body.trim())
            .map_err(|e| FctpError::MalformedMessage(format!("Base64 decode error: {:?}", e)))?;

        let pk_bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| FctpError::MalformedMessage("Invalid public key length".to_string()))?;

        client_info.conn_e2ee_public = PublicKey::from(pk_bytes);
    }
    Ok(())
}
