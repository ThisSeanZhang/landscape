use std::net::Ipv6Addr;

// ── Shell command helpers (ip route / ip addr) ────────────────────────────

pub fn add_route(ip: Ipv6Addr, prefix: u8, iface_name: &str, valid_lifetime: Option<u32>) {
    let mut args = vec![
        "-6".to_string(),
        "route".to_string(),
        "replace".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(lifetime) = valid_lifetime {
        args.push("expires".to_string());
        args.push(lifetime.to_string());
    }

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

pub fn add_route_via(
    prefix: Ipv6Addr,
    prefix_len: u8,
    via: Ipv6Addr,
    iface_name: &str,
    valid_lifetime: Option<u32>,
) {
    let mut args = vec![
        "-6".to_string(),
        "route".to_string(),
        "replace".to_string(),
        format!("{}/{}", prefix, prefix_len),
        "via".to_string(),
        via.to_string(),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(lifetime) = valid_lifetime {
        args.push("expires".to_string());
        args.push(lifetime.to_string());
    }

    tracing::info!("Adding PD route: ip {}", args.join(" "));
    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("add_route_via error: {e:?}");
    }
}

pub fn del_route(prefix: Ipv6Addr, prefix_len: u8, iface_name: &str) {
    let args = vec![
        "-6".to_string(),
        "route".to_string(),
        "del".to_string(),
        format!("{}/{}", prefix, prefix_len),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    tracing::debug!("Deleting PD route: ip {}", args.join(" "));
    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("del_route error: {e:?}");
    }
}

/// Deprecate an existing address without extending or recreating it.
///
/// Uses `ip addr change` (not `replace`) so a disappeared address is not
/// resurrected just to be removed again later.
pub fn deprecate_iface_ip(ip: Ipv6Addr, prefix: u8, iface_name: &str, valid_lifetime: u32) {
    let args = vec![
        "-6".to_string(),
        "addr".to_string(),
        "change".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
        "valid_lft".to_string(),
        valid_lifetime.to_string(),
        "preferred_lft".to_string(),
        "0".to_string(),
    ];

    match std::process::Command::new("ip").args(&args).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            tracing::warn!(
                iface = iface_name,
                %ip,
                prefix,
                valid_lifetime,
                status = ?output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "failed to deprecate IPv6 address"
            );
        }
        Err(e) => tracing::error!(iface = iface_name, %ip, "{e:?}"),
    }
}

pub fn del_iface_ip(ip: Ipv6Addr, prefix: u8, iface_name: &str) {
    let args = vec![
        "-6".to_string(),
        "addr".to_string(),
        "del".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}

pub fn set_iface_ip(
    ip: Ipv6Addr,
    prefix: u8,
    iface_name: &str,
    valid_lifetime: Option<u32>,
    preferred_lft: Option<u32>,
) {
    let mut args = vec![
        "-6".to_string(),
        "addr".to_string(),
        "replace".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ];

    if let Some(valid) = valid_lifetime {
        args.push("valid_lft".to_string());
        args.push(valid.to_string());
    }

    if let Some(preferred) = preferred_lft {
        args.push("preferred_lft".to_string());
        args.push(preferred.to_string());
    }

    let result = std::process::Command::new("ip").args(&args).output();

    if let Err(e) = result {
        tracing::error!("{e:?}");
    }
}
