#![warn(dead_code)] // Maybe in some time I will use this shit
use super::fctp_client::Clients;

pub async fn send_broadcast(
    clients: &Clients,
    id: &str,
    msg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut map = clients.lock().await;
    for (client_id, client_info) in map.iter_mut() {
        if client_id != id {
            super::fctp::send_fctp_message(client_info, 201, crate::get_id(), msg, client_id).await;
        }
    }
    Ok(())
}
pub async fn kick_client(clients: &Clients, id: &str) {
    let mut map = clients.lock().await;
    if let Some(writer) = map.remove(id) {
        drop(writer);
        println!("User {} got kicked", id);
    } else {
        println!("User {} doesn't exist.", id);
    }
}
