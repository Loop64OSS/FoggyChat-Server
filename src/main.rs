#![allow(unused_imports)]
mod crypt;
mod protocol_utils;
use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use crypt::asymmetric;
use crypt::symmetric;
use protocol_utils::fctp;
use std::collections::HashMap;
use std::default;
use std::process::exit;
use std::ptr::null;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol_utils::fctp::FctpCode;
use crate::protocol_utils::fctp::FctpMessage;
use crate::protocol_utils::fctp::send_fctp_message;
use crate::protocol_utils::fctp_client::ClientInfo;
use crate::protocol_utils::fctp_client::Clients;
use crate::protocol_utils::fctp_secure::get_cert_pub;
use crate::protocol_utils::fctp_secure::get_cert_sec;
use crate::protocol_utils::fctp_secure::set_cert;

const BUFFER_SIZE: usize = 8096;

static ID: OnceLock<String> = OnceLock::new();

pub fn set_id(new_id: &str) {
    ID.set(new_id.to_owned()).unwrap_or_else(|_| {
        eprintln!("Unauthorized action: Cannot reregister server!");
    })
}

pub fn get_id() -> &'static str {
    ID.get().map(|s| s.as_str()).unwrap_or_else(|| {
        eprintln!("Unauthorized action: Unregistered server! Halting execution.");
        exit(1005);
    })
}

fn generate_id() -> uuid::Uuid {
    let uuid = Uuid::new_v4();
    uuid
}

async fn handle_client(
    socket: tokio::net::TcpStream,
    clients: Clients,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = generate_id().to_string();
    let (mut reader, writer) = socket.into_split();

    let client_info = ClientInfo {
        socket: Arc::new(Mutex::new(writer)),
        conn_session_key: Key::<Aes256Gcm>::default(),
        conn_e2ee_public: PublicKey::from([0u8; 32]),
        ext_connected_at: std::time::Instant::now(),
        ext_session_username: id.clone(),
        ext_rate_limit_last_packet: std::time::Instant::now(),
        ext_rate_limit_ignore_packet_count: 5,
        ext_rate_limit_burst_count: 2,
    };

    {
        let mut map = clients.lock().await;
        map.insert(id.clone(), client_info.clone());
    }

    {
        let mut map = clients.lock().await;
        if let Some(client_info) = map.get_mut(&id) {
            let mut writer = client_info.socket.lock().await;
            let public_key_b64 = crypt::utils::base64_encode(get_cert_pub().as_bytes());

            if let Err(e) = writer
                .write_all(format!("{}\r\n\r\n", public_key_b64).as_bytes())
                .await
            {
                eprintln!("Failed to send public key to {}: {}", id, e);
                return Err(e.into());
            }
            println!("Sent public key to client: {}", id);
        }
    }

    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                println!("Client {} disconnected", id);
                break;
            }
            Ok(n) => {
                let message = &buf[..n];

                if message.len() > BUFFER_SIZE - 1 {
                    break;
                }
                let session_key = {
                    let map = clients.lock().await;
                    map.get(&id).map(|c| c.conn_session_key).unwrap_or_default()
                };

                if session_key == Key::<Aes256Gcm>::default() {
                    if let Err(e) =
                        protocol_utils::fctp_secure::handle_key_exchange(message, &id, &clients)
                            .await
                    {
                        eprintln!("Key exchange error for {}: {}", id, e);
                        break;
                    }
                } else {
                    let process_message = {
                        let mut map = clients.lock().await;
                        if let Some(client_info) = map.get_mut(&id) {
                            let elapsed = client_info.ext_rate_limit_last_packet.elapsed();
                            if client_info.ext_rate_limit_ignore_packet_count > 0 {
                                client_info.ext_rate_limit_ignore_packet_count -= 1;
                                true
                            } else if client_info.ext_rate_limit_burst_count > 0 {
                                client_info.ext_rate_limit_burst_count -= 1;
                                true
                            } else if elapsed >= std::time::Duration::from_millis(500) {
                                client_info.ext_rate_limit_last_packet = std::time::Instant::now();
                                client_info.ext_rate_limit_burst_count = 1;
                                true
                            } else {
                                let id_msg = FctpMessage::new(
                                    FctpCode::MethodNotAllowed,
                                    get_id(),
                                    "You are being rate limited, slow down! Your message has been dropped.",
                                    &id,
                                );
                                send_fctp_message(client_info, &id_msg).await?;
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if process_message {
                        if let Err(e) =
                            fctp::handle_fctp_message(message, &id, session_key, &clients).await
                        {
                            eprintln!("Message handling error for {}: {}", id, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from client {}: {}", id, e);
                break;
            }
        }
    }

    // Cleanup
    let mut map = clients.lock().await;
    map.remove(&id);
    println!("Cleaned up client: {}", id);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));

    //Server attribute setting
    set_id("00000000-0000-0000-0000-000000000000");

    let (rec_sec_bytes, rec_pub_bytes) = asymmetric::keypairgen();
    let rec_sec = StaticSecret::from(rec_sec_bytes);
    let rec_pub = PublicKey::from(rec_pub_bytes);
    set_cert(rec_pub, rec_sec);

    //welcome message and info
    println!(
        "© Loop64 / FOG64 | Launching FoggyChat™ FCTP protocol server | SERVER_ID: {} | FINGERPRINT: {}",
        get_id(),
        crypt::utils::blake3_hash(rec_pub.as_bytes())
    );

    //Incoming connection handling
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                println!("New connection from: {}", addr);
                let clients = clients.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, clients).await {
                        eprintln!("Error handling client {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

/*
    TESTS
*/
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_encryption() {
        let key = symmetric::keygen();

        match symmetric::encrypt_binary("test", &key) {
            Ok(encrypted) => match symmetric::decrypt_binary(&encrypted, &key) {
                Ok(decrypted) => {
                    assert_eq!(String::from_utf8_lossy(&decrypted), "test");
                }
                Err(e) => panic!("Decryption error: {}", e),
            },
            Err(e) => panic!("Encryption error: {}", e),
        }
    }

    #[test]
    fn asymmetric() {
        let (rec_sec_bytes, rec_pub_bytes) = asymmetric::keypairgen();
        let rec_sec = StaticSecret::from(rec_sec_bytes);
        let rec_pub = PublicKey::from(rec_pub_bytes);

        match asymmetric::encrypt(&rec_pub, "test".as_bytes()) {
            Ok(encrypted) => match asymmetric::decrypt(&rec_sec, &encrypted) {
                Ok(decrypted) => println!("Decrypted: {}", String::from_utf8_lossy(&decrypted)),
                Err(e) => eprintln!("Decryption error: {}", e),
            },
            Err(e) => eprintln!("Encryption error: {}", e),
        }
    }

    #[test]
    fn test_generate_id() {
        let id = generate_id();
        assert!(!id.is_nil(), "Generated ID should not be nil");
        println!("Generated ID: {}", id);
    }
}
