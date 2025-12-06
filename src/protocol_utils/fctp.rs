use aes_gcm::{Aes256Gcm, Key};
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use crate::{
    crypt::{self, symmetric},
    get_id,
    protocol_utils::fctp_client,
};

/* Error types used by FCTP handlers */
#[derive(Error, Debug)]
pub enum FctpError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Malformed message: {0}")]
    MalformedMessage(String),
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Invalid nickname: {0}")]
    InvalidNickname(String),
}
/* Local result alias */
type Result<T> = std::result::Result<T, FctpError>;

/* Protocol constants */
const PROTOCOL_VERSION: &str = "FoggyChat Transfer Protocol 0.1";
const MIN_NICK_LENGTH: usize = 3;
const MAX_NICK_LENGTH: usize = 20;

/* FCTP message codes */
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FctpCode {
    Ping = 10,
    Pong = 11,
    Message = 200,
    Command = 201,
    BadRequest = 400,
    MethodNotAllowed = 405,
    InternalServerError = 500,
    ServiceUnavailable = 505,
    Hello = 900,
    PublicKeyExchange = 901,
    KeyRequest = 902,
}

/* conversion helper for numeric codes */
impl FctpCode {
    fn from_i32(code: i32) -> Option<Self> {
        match code {
            10 => Some(Self::Ping),
            11 => Some(Self::Pong),
            200 => Some(Self::Message),
            201 => Some(Self::Command),
            400 => Some(Self::BadRequest),
            405 => Some(Self::MethodNotAllowed),
            500 => Some(Self::InternalServerError),
            505 => Some(Self::ServiceUnavailable),
            900 => Some(Self::Hello),
            901 => Some(Self::PublicKeyExchange),
            902 => Some(Self::KeyRequest),
            _ => None,
        }
    }
}

/* In-memory representation of an FCTP message */
#[derive(Debug, Clone, PartialEq)]
pub struct FctpMessage {
    pub code: FctpCode,
    pub from: String,
    pub body: String,
    pub to: String,
}

impl FctpMessage {
    /* constructor helper */
    pub fn new(
        code: FctpCode,
        from: impl Into<String>,
        body: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self {
            code,
            from: from.into(),
            body: body.into(),
            to: to.into(),
        }
    }
    #[allow(dead_code)]
    pub fn ping(to: impl Into<String>) -> Self {
        Self::new(FctpCode::Ping, get_id(), "ping", to)
    }

    #[allow(dead_code)]
    pub fn pong(to: impl Into<String>) -> Self {
        Self::new(FctpCode::Pong, get_id(), "pong", to)
    }

    #[allow(dead_code)]
    pub fn error(code: FctpCode, message: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(code, get_id(), message, to)
    }
}
/* Header tools: encapsulate/decapsulate FCTP messages */
pub fn encapsulate_to_fctp(message: &FctpMessage, session_key: &Key<Aes256Gcm>) -> Result<Vec<u8>> {
    let formatted_message = format!(
        "{}\r\n{}\r\nFrom: {}\r\nBody: {}\r\nTo: {}\r\n\r\n",
        PROTOCOL_VERSION, message.code as i32, message.from, message.body, message.to
    );

    symmetric::encrypt_binary(&formatted_message, session_key)
        .map_err(|e| FctpError::EncryptionFailed(format!("{:?}", e)))
}
/* Decrypt and parse an FCTP frame */
pub fn decapsulate_fctp_message(msg: &[u8], session_key: &Key<Aes256Gcm>) -> Result<FctpMessage> {
    let decrypted_str = if *session_key == Key::<Aes256Gcm>::default() {
        // Unencrypted message!
        String::from_utf8(msg.to_vec())
            .map_err(|e| FctpError::DecryptionFailed(format!("UTF-8 decode error: {}", e)))?
    } else {
        let decrypted_bytes = symmetric::decrypt_binary(msg, session_key)
            .map_err(|e| FctpError::DecryptionFailed(format!("{:?}", e)))?;
        String::from_utf8(decrypted_bytes)
            .map_err(|e| FctpError::DecryptionFailed(format!("UTF-8 decode error: {}", e)))?
    };

    parse_fctp_message(&decrypted_str)
}
/* Parse a plaintext FCTP message into an FctpMessage struct */
fn parse_fctp_message(message: &str) -> Result<FctpMessage> {
    let mut lines = message.lines();

    // Check protocol
    let protocol_line = lines
        .next()
        .ok_or_else(|| FctpError::MalformedMessage("Missing protocol line".to_string()))?;

    if protocol_line != PROTOCOL_VERSION {
        return Err(FctpError::InvalidProtocolVersion(protocol_line.to_string()));
    }

    // parse status code
    let code_str = lines
        .next()
        .ok_or_else(|| FctpError::MalformedMessage("Missing code line".to_string()))?
        .trim();

    let code_int = code_str
        .parse::<i32>()
        .map_err(|_| FctpError::MalformedMessage(format!("Invalid code: {}", code_str)))?;

    let code = FctpCode::from_i32(code_int)
        .ok_or_else(|| FctpError::MalformedMessage(format!("Unknown code: {}", code_int)))?;

    // Parse other attributes
    let from = parse_header_field(lines.next(), "From")?;
    let body = parse_header_field(lines.next(), "Body")?;
    let to = parse_header_field(lines.next(), "To")?;

    Ok(FctpMessage {
        code,
        from,
        body,
        to,
    })
}
/* Helper to parse a single header field like 'From: ...' */
fn parse_header_field(line: Option<&str>, field_name: &str) -> Result<String> {
    let line =
        line.ok_or_else(|| FctpError::MalformedMessage(format!("Missing {} line", field_name)))?;

    let prefix = format!("{}: ", field_name);
    line.strip_prefix(&prefix)
        .map(|s| s.trim().to_string())
        .ok_or_else(|| {
            FctpError::MalformedMessage(format!("Invalid {} format: {}", field_name, line))
        })
}
/* Send an FCTP message over the client's socket */
pub async fn send_fctp_message(
    client_info: &mut fctp_client::ClientInfo,
    message: &FctpMessage,
) -> Result<()> {
    let mut writer = client_info.socket.lock().await;
    let encrypted_msg = encapsulate_to_fctp(message, &client_info.conn_session_key)?;

    writer
        .write_all(&encrypted_msg)
        .await
        .map_err(|e| FctpError::NetworkError(format!("Failed to send message: {}", e)))?;

    Ok(())
}
/* Helper: find a client by session nickname */
async fn find_client_by_nick(
    clients: &fctp_client::Clients,
    nick: &str,
) -> Option<(String, PublicKey)> {
    let map = clients.lock().await;
    map.iter()
        .find(|(_, client)| client.ext_session_username == nick)
        .map(|(id, client)| (id.clone(), client.conn_e2ee_public))
}
/* Check if a nickname is already used by another session */
async fn is_nick_taken(clients: &fctp_client::Clients, nick: &str, current_id: &str) -> bool {
    let map = clients.lock().await;
    map.iter()
        .any(|(id, client)| id != current_id && client.ext_session_username == nick)
}
/* Validate nickname length and allowed characters */
fn validate_nickname(nick: &str) -> Result<()> {
    if nick.len() < MIN_NICK_LENGTH || nick.len() > MAX_NICK_LENGTH {
        return Err(FctpError::InvalidNickname(format!(
            "Nickname must be between {} and {} characters",
            MIN_NICK_LENGTH, MAX_NICK_LENGTH
        )));
    }

    if !nick
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(FctpError::InvalidNickname(
            "Nickname can only contain letters, numbers, underscores and hyphens".to_string(),
        ));
    }

    Ok(())
}
/* -------------------- Handlers -------------------- */

/* Main FCTP message dispatcher */
pub async fn handle_fctp_message(
    msg: &[u8],
    client_id: &str,
    session_key: Key<Aes256Gcm>,
    clients: &fctp_client::Clients,
) -> Result<()> {
    let fctp_message = decapsulate_fctp_message(msg, &session_key)?;

    println!(
        "FCTP: {} -> {} [{}]: {}",
        fctp_message.from, fctp_message.to, fctp_message.code as i32, fctp_message.body
    );

    match fctp_message.code {
        FctpCode::Message => handle_message_routing(fctp_message, client_id, clients).await,
        FctpCode::Ping => handle_ping(client_id, clients).await,
        FctpCode::Hello => handle_client_join(client_id, clients).await,
        FctpCode::PublicKeyExchange => {
            crate::protocol_utils::fctp_secure::handle_public_key_exchange(
                fctp_message,
                client_id,
                clients,
            )
            .await
        }
        FctpCode::KeyRequest => handle_e2ee_key_request(fctp_message, client_id, clients).await,
        FctpCode::Command => handle_command(fctp_message, client_id, clients).await,
        _ => {
            send_error_to_client(
                client_id,
                clients,
                FctpCode::MethodNotAllowed,
                "Unsupported message code",
            )
            .await
        }
    }
}
/* Route an incoming chat message to a recipient */
async fn handle_message_routing(
    fctp_message: FctpMessage,
    sender_id: &str,
    clients: &fctp_client::Clients,
) -> Result<()> {
    let recipient_nick = fctp_message.to.trim();

    //Find recipient ID
    let recipient_id = if let Some((id, _)) = find_client_by_nick(clients, recipient_nick).await {
        id
    } else {
        recipient_nick.to_string()
    };

    //Get sender nick
    let sender_nick = {
        let map = clients.lock().await;
        map.get(sender_id)
            .map(|c| c.ext_session_username.clone())
            .unwrap_or_else(|| sender_id.to_string())
    };

    //Send message to recipient
    let mut map = clients.lock().await;
    if let Some(_recipient_info) = map.get_mut(&recipient_id) {
        let message = FctpMessage::new(
            FctpCode::Message,
            sender_nick,
            fctp_message.body,
            recipient_id.clone(),
        );
        drop(map); //DROP A LOCK!

        let mut map = clients.lock().await;
        if let Some(recipient_info) = map.get_mut(&recipient_id) {
            send_fctp_message(recipient_info, &message).await?;
        }
    } else {
        //Recipient does not exist
        if let Some(sender_info) = map.get_mut(sender_id) {
            let error_msg =
                FctpMessage::error(FctpCode::MethodNotAllowed, "Recipient not found", sender_id);
            send_fctp_message(sender_info, &error_msg).await?;
        }
    }

    Ok(())
}
/* Reply to ping with pong */
async fn handle_ping(client_id: &str, clients: &fctp_client::Clients) -> Result<()> {
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        let pong_msg = FctpMessage::pong(client_id);
        send_fctp_message(client_info, &pong_msg).await?;
    }
    Ok(())
}
/* Handle client join/hello: send ID and MOTD */
async fn handle_client_join(client_id: &str, clients: &fctp_client::Clients) -> Result<()> {
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        // tell a client his id
        let id_msg = FctpMessage::new(FctpCode::Hello, get_id(), "id", client_id);
        send_fctp_message(client_info, &id_msg).await?;

        // MOTD
        let motd_msg = FctpMessage::new(
            FctpCode::Command,
            get_id(),
            "Welcome to Loop64.com FoggyChat server!",
            client_id,
        );
        send_fctp_message(client_info, &motd_msg).await?;
    }
    Ok(())
}
/* Handle E2EE public key request for a given nickname */
async fn handle_e2ee_key_request(
    fctp_message: FctpMessage,
    client_id: &str,
    clients: &fctp_client::Clients,
) -> Result<()> {
    let requested_nick = fctp_message.body.trim();
    let found_key = find_client_by_nick(clients, requested_nick).await;

    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        if let Some((_, pk)) = found_key {
            let key_response = FctpMessage::new(
                FctpCode::KeyRequest,
                get_id(),
                crypt::utils::base64_encode(pk.as_bytes()),
                client_id,
            );
            send_fctp_message(client_info, &key_response).await?;
        } else {
            let error_msg = FctpMessage::error(
                FctpCode::ServiceUnavailable,
                "User key not found",
                client_id,
            );
            send_fctp_message(client_info, &error_msg).await?;
        }
    }
    Ok(())
}
/* Handle textual commands from clients (help, whoami, setnick) */
async fn handle_command(
    fctp_message: FctpMessage,
    client_id: &str,
    clients: &fctp_client::Clients,
) -> Result<()> {
    let body = fctp_message.body.trim();
    let mut parts = body.split_whitespace();
    let command = parts.next().unwrap_or("");

    match command {
        "help" => {
            let msg = format!(
                "Welcome to server! ServerID: {} / Available commands: help, whoami, setnick <name>",
                get_id()
            );
            send_command_response(client_id, clients, &msg).await
        }
        "whoami" => handle_whoami_command(client_id, clients).await,
        "setnick" => handle_setnick_command(parts.next(), client_id, clients).await,
        _ => {
            let msg = format!(
                "Unknown command: {}. Type 'help' for available commands.",
                command
            );
            send_error_to_client(client_id, clients, FctpCode::MethodNotAllowed, &msg).await
        }
    }
}
/* Implementation of 'whoami' command */
async fn handle_whoami_command(client_id: &str, clients: &fctp_client::Clients) -> Result<()> {
    let map = clients.lock().await;
    if let Some(client_info) = map.get(client_id) {
        let msg = format!(
            "You are connected as: {} / Your session nick: {} / ServerID: {} / Connected for: {} seconds / Your E2EE public key (base64): {}",
            client_id,
            client_info.ext_session_username,
            get_id(),
            client_info.ext_connected_at.elapsed().as_secs(),
            crypt::utils::base64_encode(client_info.conn_e2ee_public.as_bytes())
        );
        drop(map);
        send_command_response(client_id, clients, &msg).await?;
    }
    Ok(())
}
/* Implementation of 'setnick' command */
async fn handle_setnick_command(
    new_nick: Option<&str>,
    client_id: &str,
    clients: &fctp_client::Clients,
) -> Result<()> {
    let Some(new_nick) = new_nick else {
        return send_error_to_client(
            client_id,
            clients,
            FctpCode::BadRequest,
            "Usage: setnick <new_name>",
        )
        .await;
    };

    // Validate nickname regex
    if let Err(e) = validate_nickname(new_nick) {
        return send_error_to_client(
            client_id,
            clients,
            FctpCode::MethodNotAllowed,
            &e.to_string(),
        )
        .await;
    }

    // Check nick availability
    if is_nick_taken(clients, new_nick, client_id).await {
        let msg = format!(
            "Nick '{}' is already taken. Choose a different one.",
            new_nick
        );
        return send_error_to_client(client_id, clients, FctpCode::MethodNotAllowed, &msg).await;
    }

    // Set nick
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        client_info.ext_session_username = new_nick.to_string();
        let msg = format!(
            "Nick changed to: {} / ServerID: {}",
            client_info.ext_session_username,
            get_id()
        );
        drop(map);
        send_command_response(client_id, clients, &msg).await?;
    }

    Ok(())
}
/* Sending helpers (create Command/Error messages and send) */

async fn send_command_response(
    client_id: &str,
    clients: &fctp_client::Clients,
    message: &str,
) -> Result<()> {
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        let response = FctpMessage::new(FctpCode::Command, get_id(), message, client_id);
        send_fctp_message(client_info, &response).await?;
    }
    Ok(())
}
/* Send an error response to a client */
async fn send_error_to_client(
    client_id: &str,
    clients: &fctp_client::Clients,
    error_code: FctpCode,
    message: &str,
) -> Result<()> {
    let mut map = clients.lock().await;
    if let Some(client_info) = map.get_mut(client_id) {
        let error_msg = FctpMessage::error(error_code, message, client_id);
        send_fctp_message(client_info, &error_msg).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fctp_code_conversion() {
        assert_eq!(FctpCode::from_i32(200), Some(FctpCode::Message));
        assert_eq!(FctpCode::from_i32(999), None);
    }

    #[test]
    fn test_message_creation() {
        let msg = FctpMessage::new(FctpCode::Message, "alice", "hello", "bob");
        assert_eq!(msg.code, FctpCode::Message);
        assert_eq!(msg.from, "alice");
        assert_eq!(msg.body, "hello");
        assert_eq!(msg.to, "bob");
    }

    #[test]
    fn test_nickname_validation() {
        assert!(validate_nickname("alice").is_ok());
        assert!(validate_nickname("alice_123").is_ok());
        assert!(validate_nickname("ab").is_err()); // short
        assert!(validate_nickname("a".repeat(25).as_str()).is_err()); // long
        assert!(validate_nickname("alice@bob").is_err()); //illegal characters
    }

    #[test]
    fn test_fctp_encapsulation_and_decapsulation() {
        let msg = FctpMessage::new(FctpCode::Message, "alice", "hello world", "bob");
        let key = crate::crypt::symmetric::keygen();

        let encrypted = encapsulate_to_fctp(&msg, &key).expect("Should encrypt");
        assert!(!encrypted.is_empty());

        let decrypted = decapsulate_fctp_message(&encrypted, &key).expect("Should decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_parse_fctp_message() {
        let message_str = format!(
            "{}\r\n{}\r\nFrom: {}\r\nBody: {}\r\nTo: {}\r\n\r\n",
            PROTOCOL_VERSION, 200, "alice", "hello", "bob"
        );

        let parsed = parse_fctp_message(&message_str).expect("Should parse");
        assert_eq!(parsed.code, FctpCode::Message);
        assert_eq!(parsed.from, "alice");
        assert_eq!(parsed.body, "hello");
        assert_eq!(parsed.to, "bob");
    }

    #[test]
    fn test_invalid_protocol_version() {
        let invalid_message =
            "Invalid Protocol 1.0\r\n200\r\nFrom: alice\r\nBody: hello\r\nTo: bob\r\n\r\n";
        assert!(parse_fctp_message(invalid_message).is_err());
    }
}
