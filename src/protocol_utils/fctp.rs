use aes_gcm::{Aes256Gcm, Key};
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use crate::{
    crypt::{self, symmetric},
    get_id,
    protocol_utils::{fctp_client, fctp_operations::kick_client},
};

pub struct FctpMessage {
    pub code: i32,
    pub from: String,
    pub body: String,
    pub to: String,
}

/*
    FCTP message processing with binary encryption
*/
pub fn encapsulate_to_fctp(
    code: i32,
    from: &str,
    body: &str,
    to: &str,
    session_key: Key<Aes256Gcm>,
) -> Vec<u8> {
    let message = format!(
        "FoggyChat Transfer Protocol 0.1\r\n{}\r\nFrom: {}\r\nBody: {}\r\nTo: {}\r\n\r\n",
        code, from, body, to
    );

    match symmetric::encrypt_binary(&message, &session_key) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            eprintln!("Encryption failed: {:?}", e);
            Vec::new()
        }
    }
}

pub fn decapsulate_fctp_message(msg: &[u8], session_key: Key<Aes256Gcm>) -> Option<FctpMessage> {
    if session_key == Key::<Aes256Gcm>::default() {
        let decrypted_str = String::from_utf8(msg.to_vec()).ok()?;
        return parse_fctp_message(&decrypted_str);
    }

    let decrypted_bytes = symmetric::decrypt_binary(msg, &session_key).ok()?;
    let decrypted_str = String::from_utf8(decrypted_bytes).ok()?;

    parse_fctp_message(&decrypted_str)
}

fn parse_fctp_message(message: &str) -> Option<FctpMessage> {
    let mut lines = message.lines();

    if lines.next()? != "FoggyChat Transfer Protocol 0.1" {
        return None;
    }

    let code = lines.next()?.trim().parse::<i32>().ok()?;
    let from = lines.next()?.strip_prefix("From: ")?.trim().to_string();
    let body = lines.next()?.strip_prefix("Body: ")?.trim().to_string();
    let to = lines.next()?.strip_prefix("To: ")?.trim().to_string();

    Some(FctpMessage {
        code,
        from,
        body,
        to,
    })
}
pub async fn send_fctp_message(
    client_info: &mut fctp_client::ClientInfo,
    code: i32,
    from: &str,
    body: &str,
    to: &str,
) {
    let mut writer = client_info.socket.lock().await;

    let encrypted_msg = encapsulate_to_fctp(code, from, body, to, client_info.conn_session_key);

    if !encrypted_msg.is_empty() {
        if let Err(e) = writer.write_all(&encrypted_msg).await {
            eprintln!("Failed to send FCTP message: {:?}", e);
        }
    } else {
        eprintln!("Failed to encrypt FCTP message - empty result");
    }
}
//Finding ... by nick
async fn find_key_by_nick(clients: &fctp_client::Clients, nick: &str) -> Option<PublicKey> {
    let map = clients.lock().await;
    map.iter()
        .find(|(_, client)| client.ext_session_username == nick)
        .map(|(_, client)| client.conn_e2ee_public)
}

async fn find_id_by_nick(clients: &fctp_client::Clients, nick: &str) -> Option<String> {
    let map = clients.lock().await;
    map.iter()
        .find(|(_, client)| client.ext_session_username == nick)
        .map(|(id, _)| id.clone())
}
//Nick taken checker
async fn is_nick_taken(clients: &fctp_client::Clients, nick: &str, current_id: &str) -> bool {
    let map = clients.lock().await;
    map.iter()
        .any(|(id, client)| id != current_id && client.ext_session_username == nick)
}
//encrypted message handler
pub async fn handle_fctp_message(
    msg: &[u8],
    client_id: &str,
    session_key: Key<Aes256Gcm>,
    clients: &fctp_client::Clients,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(fctp_message) = decapsulate_fctp_message(msg, session_key) {
        println!(
            "{},{},{},{}",
            fctp_message.code, fctp_message.from, fctp_message.body, fctp_message.to
        );
        match fctp_message.code {
            200 => {
                //default message route code
                let recipient = fctp_message.to.trim();
                let recipient_id = if let Some(id) = find_id_by_nick(clients, recipient).await {
                    id
                } else {
                    recipient.to_string()
                };

                let sender_nick = {
                    let map = clients.lock().await;
                    map.get(client_id)
                        .map(|c| c.ext_session_username.clone())
                        .unwrap_or_else(|| client_id.to_string())
                };

                let mut map = clients.lock().await;
                if let Some(recipient_info) = map.get_mut(&recipient_id) {
                    send_fctp_message(
                        recipient_info,
                        200,
                        &sender_nick,
                        &fctp_message.body,
                        &recipient_id,
                    )
                    .await;
                } else {
                    if let Some(sender_info) = map.get_mut(client_id) {
                        send_fctp_message(
                            sender_info,
                            405,
                            get_id(),
                            "Recipient not found",
                            client_id,
                        )
                        .await;
                    }
                }
            }
            10 => {
                // Ping
                let mut map = clients.lock().await;
                if let Some(client_info) = map.get_mut(client_id) {
                    send_fctp_message(client_info, 11, get_id(), "pong", client_id).await;
                }
            }
            900 => {
                let mut map = clients.lock().await;
                if let Some(client_info) = map.get_mut(client_id) {
                    //send id information
                    send_fctp_message(client_info, 900, get_id(), "id", client_id).await;
                    //MOTD
                    send_fctp_message(
                        client_info,
                        201,
                        get_id(),
                        &format!("Welcome to Loop64.com FoggyChat server."),
                        client_id,
                    )
                    .await;
                }
            }
            901 => {
                let mut map = clients.lock().await;
                if let Some(client_info) = map.get_mut(client_id) {
                    let decoded = crypt::utils::base64_decode(&fctp_message.body.trim())
                        .expect("Failed decoding message");
                    let pk_bytes: [u8; 32] = match TryInto::<[u8; 32]>::try_into(decoded) {
                        Ok(val) => val,
                        Err(_) => {
                            kick_client(clients, client_id).await;
                            [0u8; 32]
                        }
                    };
                    //set public key of the user
                    client_info.conn_e2ee_public = PublicKey::from(pk_bytes);
                }
            }
            902 => {
                let found_pk = find_key_by_nick(clients, &fctp_message.body.trim()).await;

                let mut map = clients.lock().await;
                if let Some(client_info) = map.get_mut(client_id) {
                    //find key by nick in fctp message body and respond with it

                    //TODO: no key message handling
                    if let Some(pk) = found_pk {
                        send_fctp_message(
                            client_info,
                            902,
                            get_id(),
                            &crypt::utils::base64_encode(pk.as_bytes()),
                            client_id,
                        )
                        .await;
                    } else {
                        send_fctp_message(
                            client_info,
                            505,
                            get_id(),
                            "Couldn't find user key",
                            client_id,
                        )
                        .await;
                    }
                }
            }
            201 => {
                let mut clients_guard = clients.lock().await;
                if let Some(client_info) = clients_guard.get_mut(client_id) {
                    let mut client_info_clone = client_info.clone();
                    drop(clients_guard);
                    //handle user commands on code 201

                    command_handler(
                        fctp_message,
                        &mut client_id.to_string(),
                        &mut client_info_clone,
                        clients,
                    )
                    .await;

                    let mut clients_guard = clients.lock().await;
                    if let Some(client_info) = clients_guard.get_mut(client_id) {
                        client_info.ext_session_username = client_info_clone.ext_session_username;
                    }
                }
            }
            _ => {
                //unsupported code
                let mut map = clients.lock().await;
                if let Some(client_info) = map.get_mut(client_id) {
                    send_fctp_message(
                        client_info,
                        405,
                        get_id(),
                        "Unsupported header code",
                        client_id,
                    )
                    .await;
                }
            }
        }
    } else {
        let mut map = clients.lock().await;
        if let Some(client_info) = map.get_mut(client_id) {
            send_fctp_message(client_info, 505, get_id(), "Malformed message", client_id).await;
        }
    }

    Ok(())
}
pub async fn command_handler(
    fctp_message: FctpMessage,
    id_clone: &mut String,
    client_info: &mut fctp_client::ClientInfo,
    clients: &fctp_client::Clients,
) {
    let body = fctp_message.body.trim();
    let mut parts = body.split_whitespace();
    let command = parts.next().unwrap_or("");

    match command {
        "help" => {
            let msg = format!(
                "Welcome to server! ServerID: {} / Available commands: help, whoami, setnick <name>",
                get_id()
            );
            send_fctp_message(client_info, 201, get_id(), &msg, id_clone).await;
        }

        "whoami" => {
            let msg = format!(
                "You are connected as: {} / Your session nick: {} / ServerID: {} / Connected for: {} seconds / Your E2EE public key (base64): {}",
                id_clone,
                client_info.ext_session_username,
                get_id(),
                client_info.ext_connected_at.elapsed().as_secs(),
                crypt::utils::base64_encode(client_info.conn_e2ee_public.as_bytes())
            );
            send_fctp_message(client_info, 201, get_id(), &msg, id_clone).await;
        }
        "setnick" => {
            if let Some(new_name) = parts.next() {
                if is_nick_taken(clients, new_name, id_clone).await {
                    let msg = format!(
                        "Nick '{}' is already taken. Choose a different one.",
                        new_name
                    );
                    send_fctp_message(client_info, 405, get_id(), &msg, id_clone).await;
                } else {
                    if new_name.len() < 3 || new_name.len() > 20 {
                        let msg = "Nick must be between 3 and 20 characters long.".to_string();
                        send_fctp_message(client_info, 405, get_id(), &msg, id_clone).await;
                    } else if !new_name
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                    {
                        let msg =
                            "Nick can only contain letters, numbers, underscores and hyphens."
                                .to_string();
                        send_fctp_message(client_info, 405, get_id(), &msg, id_clone).await;
                    } else {
                        client_info.ext_session_username = new_name.to_owned();
                        let msg = format!(
                            "Nick changed to: {} / ServerID: {}",
                            client_info.ext_session_username,
                            get_id()
                        );
                        send_fctp_message(client_info, 201, get_id(), &msg, id_clone).await;
                    }
                }
            } else {
                let msg = "Usage: setnick <new_name>".to_string();
                send_fctp_message(client_info, 400, get_id(), &msg, id_clone).await;
            }
        }

        _ => {
            let msg = format!(
                "Unknown command: {}. Type 'help' for available commands.",
                body
            );
            send_fctp_message(client_info, 405, get_id(), &msg, id_clone).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, Key};

    #[test]
    fn test_fctp_encapsulation_and_decapsulation_binary() {
        let code = 200;
        let from = "user123";
        let body = "Hello, world!";
        let to = "user456";

        let real_key = crate::crypt::symmetric::keygen();
        let encrypted_message = encapsulate_to_fctp(code, from, body, to, real_key);

        assert!(!encrypted_message.is_empty());

        let decoded = decapsulate_fctp_message(&encrypted_message, real_key)
            .expect("Failed to parse FCTP message");

        assert_eq!(decoded.code, code);
        assert_eq!(decoded.from, from);
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.to, to);
    }

    #[test]
    fn test_fctp_decapsulation_invalid_binary() {
        let real_key = crate::crypt::symmetric::keygen();
        let bad_message = b"This is not a valid encrypted FCTP message";
        assert!(decapsulate_fctp_message(bad_message, real_key).is_none());

        let empty_message = b"";
        assert!(decapsulate_fctp_message(empty_message, real_key).is_none());
    }

    #[test]
    fn test_parse_fctp_message_direct() {
        let valid_message = "FoggyChat Transfer Protocol 0.1\r\n200\r\nFrom: test\r\nBody: hello\r\nTo: user\r\n\r\n";
        let parsed = parse_fctp_message(valid_message).expect("Should parse valid message");

        assert_eq!(parsed.code, 200);
        assert_eq!(parsed.from, "test");
        assert_eq!(parsed.body, "hello");
        assert_eq!(parsed.to, "user");
    }
}
