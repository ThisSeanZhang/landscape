use std::path::PathBuf;

use landscape_common::{error::LdResult, iface::config::IfaceCpuSoftBalance};

pub mod dhcpv4_client;
pub mod firewall;
pub mod ipconfig_service;
pub mod ipv6pd_client;
pub mod ipv6pd_service;
pub mod mss_clamp_service;
pub mod nat_service;
pub mod pppd_service;
pub mod pppoe_client;
pub mod wan_route_service;

pub(crate) fn setting_iface_balance(
    iface_name: &str,
    balance: IfaceCpuSoftBalance,
) -> LdResult<()> {
    let queues_path = PathBuf::from(format!("/sys/class/net/{}/queues", iface_name));
    if !queues_path.exists() {
        return Ok(());
    }

    if let Ok(entries) = std::fs::read_dir(queues_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            if name.starts_with("tx-") {
                let xps_path = entry.path().join("xps_cpus");
                if xps_path.exists() {
                    if let Err(e) = std::fs::write(&xps_path, &balance.xps) {
                        tracing::error!(
                            "setting xps_cpus for {} at {:?} error: {:?}",
                            name,
                            xps_path,
                            e
                        );
                    }
                }
            }

            if name.starts_with("rx-") {
                let rps_path = entry.path().join("rps_cpus");
                if rps_path.exists() {
                    if let Err(e) = std::fs::write(&rps_path, &balance.rps) {
                        tracing::error!(
                            "setting rps_cpus for {} at {:?} error: {:?}",
                            name,
                            rps_path,
                            e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn cpu_nums() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

#[cfg(test)]
mod tests {

    use landscape_common::iface::config::IfaceCpuSoftBalance;

    use super::setting_iface_balance;

    #[test]
    fn test_setting_balance() {
        setting_iface_balance("ens6", IfaceCpuSoftBalance { xps: "6".into(), rps: "6".into() })
            .unwrap();
    }

    #[test]
    fn test_reset_balance() {
        setting_iface_balance("ens6", IfaceCpuSoftBalance { xps: "0".into(), rps: "0".into() })
            .unwrap();
    }
}
