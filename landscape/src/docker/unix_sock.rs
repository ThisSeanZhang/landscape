use landscape_common::{NAMESPACE_REGISTER_SOCK, NAMESPACE_REGISTER_SOCK_PATH};
use std::{
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::PathBuf,
};
use tokio::net::UnixListener;
use tracing::{error, info};

pub(crate) async fn listen_unix_sock(home_path: PathBuf) -> UnixListener {
    let dir_path = home_path.join(NAMESPACE_REGISTER_SOCK_PATH);

    // Check Directory Status
    if !dir_path.exists() {
        info!("Socket directory not found, creating: {:?}", dir_path);
        std::fs::create_dir_all(&dir_path).unwrap_or_else(|e| {
            error!("Failed to create socket directory {:?}: {}", dir_path, e);
            panic!("Cannot create socket directory");
        });
    } else {
        info!("Socket directory exists: {:?}", dir_path);
    }

    let socket_path = dir_path.join(NAMESPACE_REGISTER_SOCK);

    // If the old socket file exists, delete it
    if socket_path.exists() {
        info!("Old socket file found, removing: {:?}", socket_path);
        if let Err(e) = std::fs::remove_file(&socket_path) {
            error!("Failed to remove old socket {:?}: {}", socket_path, e);
            panic!("Cannot remove old socket file");
        }
    }

    // Check parent directory permissions
    if let Ok(meta) = std::fs::metadata(&dir_path) {
        info!(
            "Socket directory {:?} permission: {:o}, owner: {:?}",
            dir_path,
            meta.permissions().mode(),
            meta.uid()
        );
    }

    info!("Listening on Unix socket: {:?}", socket_path);

    // Bind socket
    match UnixListener::bind(&socket_path) {
        Ok(listener) => {
            info!("UnixListener successfully bound on {:?}", socket_path);
            listener
        }
        Err(e) => {
            error!("Failed to bind UnixListener on {:?}: {}", socket_path, e);
            panic!("Listen failed: {}", e);
        }
    }
}
