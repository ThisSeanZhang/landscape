use std::io;

use landscape_common::concurrency::{spawn_task, task_label};
use rtnetlink::{new_connection, Handle};

/// Re-export new_connection for observer use.
/// Observers need to bind multicast groups before spawning the connection.
pub use rtnetlink::new_connection as create_connection_with_messages;

/// Create a new netlink connection and return the handle.
/// The connection task is automatically spawned on the current tokio runtime.
pub fn create_handle() -> Result<Handle, io::Error> {
    let (connection, handle, _) = new_connection()?;
    spawn_task(task_label::task::NETLINK_CONN_DRIVER, connection);
    Ok(handle)
}

/// Create a new WiFi (nl80211) connection and return the handle.
/// The connection task is automatically spawned on the current tokio runtime.
pub fn create_wifi_handle() -> Result<wl_nl80211::Nl80211Handle, io::Error> {
    let (connection, handle, _) = wl_nl80211::new_connection()?;
    spawn_task(task_label::task::NETLINK_CONN_WIFI, connection);
    Ok(handle)
}
