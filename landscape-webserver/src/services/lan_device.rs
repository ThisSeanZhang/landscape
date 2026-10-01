use std::net::{Ipv4Addr, Ipv6Addr};

use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_core::lan_device::{
    AddressSourceV4, AddressSourceV6, DhcpLeaseTimes, LanDeviceEntry,
};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_lan_device_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new().routes(routes!(get_lan_devices))
}

/// How the device's IPv4 address came to be observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LanDeviceIpv4Source {
    Static,
    Lease,
    Arp,
}

impl From<AddressSourceV4> for LanDeviceIpv4Source {
    fn from(source: AddressSourceV4) -> Self {
        match source {
            AddressSourceV4::Static => Self::Static,
            AddressSourceV4::Lease => Self::Lease,
            AddressSourceV4::Arp => Self::Arp,
        }
    }
}

/// How one of the device's IPv6 addresses came to be observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LanDeviceIpv6Source {
    Static,
    Dhcpv6,
    Slaac,
}

impl From<AddressSourceV6> for LanDeviceIpv6Source {
    fn from(source: AddressSourceV6) -> Self {
        match source {
            AddressSourceV6::Static => Self::Static,
            AddressSourceV6::Dhcpv6 => Self::Dhcpv6,
            AddressSourceV6::Slaac => Self::Slaac,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LanDeviceIpv4View {
    #[schema(value_type = String)]
    pub ip: Ipv4Addr,
    pub source: LanDeviceIpv4Source,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LanDeviceIpv6View {
    #[schema(value_type = String)]
    pub ip: Ipv6Addr,
    pub source: LanDeviceIpv6Source,
}

/// DHCPv4 lease clock, folded from `Allocated` events.
#[derive(Debug, PartialEq, Serialize, ToSchema)]
pub struct LanDeviceLeaseView {
    #[schema(value_type = String)]
    pub ip: Ipv4Addr,
    /// Epoch milliseconds of the last request/assignment/renewal.
    pub last_request: f64,
    /// Epoch milliseconds when the lease expires.
    pub expires: f64,
}

/// One LAN device as seen by the directory (live-table cut through the
/// snapshot for a mutually consistent listing).
#[derive(Debug, Serialize, ToSchema)]
pub struct LanDeviceView {
    pub entry_id: Uuid,
    #[schema(nullable = false)]
    pub device_id: Option<Uuid>,
    #[schema(nullable = false)]
    pub mac: Option<MacAddr>,
    #[schema(nullable = false)]
    pub display_name: Option<String>,
    #[schema(nullable = false)]
    pub hostname: Option<String>,
    #[schema(nullable = false)]
    pub ipv4: Option<LanDeviceIpv4View>,
    /// Observed addresses, sorted by address for a stable listing.
    pub ipv6_addrs: Vec<LanDeviceIpv6View>,
    #[schema(nullable = false)]
    pub iface_name: Option<String>,
    /// Online heuristic (recent device contact, unexpired DHCPv4 lease, or
    /// a server-tracked DHCPv6 address; a lingering ARP-observed IPv4 is
    /// inventory, not liveness).
    pub online: bool,
    /// Epoch milliseconds of the last device-side observation; 0 = enrolled
    /// but never observed.
    pub last_active: f64,
    /// ARP liveness trail: 24 scan-interval buckets, oldest first.
    pub arp_presence: Vec<bool>,
    #[schema(nullable = false)]
    pub arp_last_seen: Option<f64>,
    #[schema(nullable = false)]
    pub dhcp_lease: Option<LanDeviceLeaseView>,
}

fn lease_view(lease: DhcpLeaseTimes) -> LanDeviceLeaseView {
    LanDeviceLeaseView {
        ip: lease.ip,
        last_request: lease.last_request,
        expires: lease.expires,
    }
}

fn to_view(entry: &LanDeviceEntry, now: f64) -> LanDeviceView {
    let mut ipv6_addrs: Vec<LanDeviceIpv6View> = entry
        .ipv6_addrs
        .iter()
        .map(|(ip, source)| LanDeviceIpv6View {
            ip: *ip,
            source: LanDeviceIpv6Source::from(*source),
        })
        .collect();
    ipv6_addrs.sort_by_key(|view| view.ip);

    LanDeviceView {
        entry_id: entry.entry_id,
        device_id: entry.device_id,
        mac: entry.mac,
        display_name: entry.display_name.clone(),
        hostname: entry.hostname.clone(),
        ipv4: entry.ipv4.map(|ip| LanDeviceIpv4View {
            ip,
            // A present address without a source tag only occurs behind a
            // stale index; treat it as the weakest evidence.
            source: LanDeviceIpv4Source::from(entry.ipv4_source.unwrap_or(AddressSourceV4::Arp)),
        }),
        ipv6_addrs,
        iface_name: entry.iface_name.clone(),
        online: entry.is_online(),
        last_active: entry.last_active,
        arp_presence: entry.arp_presence.series(now),
        arp_last_seen: entry.arp_last_seen,
        dhcp_lease: entry.dhcp_lease.map(lease_view),
    }
}

fn sort_key(view: &LanDeviceView) -> (String, String, Uuid) {
    let name = view
        .display_name
        .clone()
        .or_else(|| view.hostname.clone())
        .or_else(|| view.mac.map(|mac| mac.to_string()))
        .unwrap_or_default();
    (view.iface_name.clone().unwrap_or_default(), name, view.entry_id)
}

#[utoipa::path(
    get,
    path = "/lan_devices",
    tag = "LAN Devices",
    operation_id = "get_lan_devices",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<LanDeviceView>>))
)]
async fn get_lan_devices(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<LanDeviceView>> {
    let snapshot = state.lan_device_directory.snapshot();
    let now = get_f64_timestamp();
    let mut views: Vec<LanDeviceView> =
        snapshot.entries.values().map(|entry| to_view(entry, now)).collect();
    views.sort_by_key(sort_key);
    LandscapeApiResp::success(views)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use landscape_common::event::hub::{
        IPv6AssignEvent, IPv6AssignInfo, IPv6AssignSource, Ipv6AssignAddress,
    };
    use landscape_core::lan_device::{DirectorySeedDevice, LanDeviceDirectory};

    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::from([0, 0, 0, 0, 0, n])
    }

    fn ipv6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn view_maps_entry_fields() {
        let directory = LanDeviceDirectory::new_seeded_for_test(vec![DirectorySeedDevice {
            mac: mac(9),
            hostname: Some("nas.lan".to_string()),
            ipv4: Some("10.0.0.9".parse().unwrap()),
            ipv6: Some(ipv6("fd00::9")),
        }]);
        // A SLAAC observation whose interface id matches the enrolled suffix
        // upgrades to `static`; a foreign address stays `slaac`.
        directory.apply_ipv6_event_for_test(IPv6AssignEvent::Allocated(IPv6AssignInfo {
            iface_name: "lan0".to_string(),
            mac: mac(9),
            ips: vec![
                Ipv6AssignAddress {
                    ip: ipv6("fd00::9"),
                    source: IPv6AssignSource::Slaac,
                },
                Ipv6AssignAddress {
                    ip: ipv6("fd00::1234"),
                    source: IPv6AssignSource::Slaac,
                },
            ],
            device_id: None,
        }));

        let entry = directory.entry_by_mac(&mac(9)).expect("seeded entry");
        let view = to_view(&entry, entry.last_active);

        assert_eq!(view.mac, Some(mac(9)));
        assert_eq!(view.display_name.as_deref(), Some("seed"));
        assert_eq!(view.hostname.as_deref(), Some("nas.lan"));
        assert_eq!(view.ipv4.as_ref().map(|v| v.source), Some(LanDeviceIpv4Source::Static));
        assert_eq!(view.ipv4.as_ref().map(|v| v.ip.to_string()), Some("10.0.0.9".to_string()));

        let ips: Vec<String> = view.ipv6_addrs.iter().map(|v| v.ip.to_string()).collect();
        assert_eq!(ips, vec!["fd00::9".to_string(), "fd00::1234".to_string()], "sorted by address");
        assert_eq!(view.ipv6_addrs[0].source, LanDeviceIpv6Source::Static);
        assert_eq!(view.ipv6_addrs[1].source, LanDeviceIpv6Source::Slaac);

        assert_eq!(view.iface_name.as_deref(), Some("lan0"));
        assert!(view.online, "fresh observation (now == last_active) reads online");
        assert_eq!(view.arp_presence.len(), 24);
        assert!(view.arp_presence.iter().all(|seen| !seen), "no ARP observation yet");
        assert_eq!(view.arp_last_seen, None);
        assert_eq!(view.dhcp_lease, None);
    }
}
