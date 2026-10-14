use std::path::PathBuf;

static RESOLVER_CONF: &str = "/etc/resolv.conf";
static RESOLVER_CONF_LD_BACK: &str = "/etc/resolv.conf.ld_back";

fn check_resolver_conf() -> bool {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);
    let new_content = "nameserver 127.0.0.1\n";

    if resolver_file.is_symlink() {
        // symlink: remove it directly
        if let Err(e) = std::fs::remove_file(&resolver_file) {
            tracing::error!("remove {resolver_file:?} symlink error: {e}");
            return false;
        }
    } else if resolver_file.exists() {
        if resolver_file.is_file() {
            // regular file: check the backup file
            if resolver_file_back.exists() {
                if let Err(e) = std::fs::remove_file(&resolver_file) {
                    tracing::error!("remove {resolver_file:?} error: {e}");
                    return false;
                }
            } else {
                let Ok(()) = std::fs::rename(&resolver_file, &resolver_file_back) else {
                    tracing::error!("move {resolver_file:?} error, Skip it");
                    return false;
                };
            }
        } else {
            tracing::error!("{resolver_file:?} is neither a symlink nor a regular file, Skip it");
            return false;
        }
    }

    // write new content to /etc/resolv.conf
    if let Err(e) = std::fs::write(&resolver_file, new_content) {
        tracing::error!("write {resolver_file:?} error: {e}");
        return false;
    }
    true
}

pub fn prepare_system_dns() -> bool {
    check_resolver_conf()
}

/// restore /etc/resolv.conf on stop
pub fn restore_resolver_conf() {
    let resolver_file = PathBuf::from(RESOLVER_CONF);
    let resolver_file_back = PathBuf::from(RESOLVER_CONF_LD_BACK);

    if resolver_file_back.exists() {
        if let Err(e) = std::fs::rename(&resolver_file_back, &resolver_file) {
            tracing::error!("restore {resolver_file:?} from backup error: {e}");
        } else {
            tracing::info!("restored {resolver_file:?} from backup");
        }
    } else {
        tracing::warn!("no backup file found at {resolver_file_back:?}, skipping restore");
    }
}
