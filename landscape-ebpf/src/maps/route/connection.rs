use crate::maps::{MapCreateSpec, recreate_pinned_map};
use crate::{LandscapeMapPath, bpf_error::LdEbpfResult};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

pub fn init_connection_maps(paths: &LandscapeMapPath) -> LdEbpfResult<()> {
    for (name, path, map_type, key_size, value_size, max_entries) in [
        ("rt_conn_policy", &paths.rt_conn_policy, MapType::Hash, 8, 8, 512),
        ("rt_connections", &paths.rt_connections, MapType::LruHash, 40, 56, 65536),
    ] {
        recreate_pinned_map(
            &MapCreateSpec {
                map_type,
                name,
                key_size,
                value_size,
                max_entries,
                map_flags: 0,
                inner: None,
            },
            path,
        )?;
    }
    Ok(())
}

/// `None` restores the ordinary weighted slot path. Generations invalidate only
/// this flow/family's affinity; other flows and NAT port allocator state survive.
pub fn set_connection_generation(
    paths: &LandscapeMapPath,
    flow_id: u32,
    ipv6: bool,
    generation: Option<u64>,
) {
    let result = (|| -> Result<(), libbpf_rs::Error> {
        let map = MapHandle::from_pinned_path(&paths.rt_conn_policy)?;
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&flow_id.to_ne_bytes());
        key[4..].copy_from_slice(&u32::from(ipv6).to_ne_bytes());
        let existing = map.lookup(&key, MapFlags::ANY)?;
        match generation {
            Some(value) if existing.as_deref() != Some(value.to_ne_bytes().as_slice()) => {
                map.update(&key, &value.to_ne_bytes(), MapFlags::ANY)?
            }
            None if existing.is_some() => map.delete(&key)?,
            _ => {}
        }
        Ok(())
    })();
    if let Err(error) = result {
        tracing::error!(flow_id, ipv6, ?error, "cannot update WAN connection policy");
    }
}
