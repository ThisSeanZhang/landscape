use std::{sync::Arc, time::Duration};

use landscape_common::{
    error::LdResult,
    event::hub::{IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo},
    net::MacAddr,
    service::{ServiceStatus, WatchService},
};
use tokio::sync::Mutex;

use crate::{
    addresses_by_iface_name,
    dhcp_server::v6_v2::{
        connection::{get_dhcpv6_connect, get_icmp_connect},
        dhcpv6, Ipv6LanReplyParams, Ipv6ServerStatus,
    },
};

const LEASE_EXPIRE_INTERVAL: u64 = 60 * 10;

pub async fn start_ipv6_lan_server(
    ifindex: u32,
    iface_name: String,
    mac_addr: MacAddr,
    service_status: WatchService,
    icmp_ad_interval: u32,
    ipv6_assign_sender: &IPv6AssignEventSender,
    share_status: Arc<Mutex<Ipv6ServerStatus>>,
    params: Ipv6LanReplyParams,
    dns_servers: Vec<std::net::Ipv6Addr>,
) -> LdResult<()> {
    let server_duid = gen_server_duid(&mac_addr);

    let setting_result = crate::set_iface_ip_no_limit(
        &iface_name,
        std::net::IpAddr::V6(mac_addr.to_ipv6_link_local()),
        64,
    )
    .await;

    if !setting_result {
        tracing::error!("setting unicast_link_local error");
        service_status.just_change_status(ServiceStatus::Failed);
    }

    let address = addresses_by_iface_name(iface_name.to_string()).await;
    let mut link_ipv6_addr = None;
    let mut link_ifindex = 0;
    for addr in address.iter() {
        match addr.address {
            std::net::IpAddr::V4(_) => continue,
            std::net::IpAddr::V6(ipv6_addr) => {
                if ipv6_addr.is_unicast_link_local() {
                    link_ipv6_addr = Some(ipv6_addr);
                    link_ifindex = addr.ifindex;
                }
            }
        }
    }

    let Some(ipaddr) = link_ipv6_addr else {
        tracing::error!("can not find unicast_link_local");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };
    tracing::info!("address {:?}", ipaddr);
    tracing::info!("link_ifindex {:?}", link_ifindex);

    let Ok((mut dhcp_recv, dhcp_sender)) = get_dhcpv6_connect(ifindex, &iface_name).await else {
        tracing::error!("create dhcpv6 link error");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };

    let Ok((mut icmp_recv, _icmp_sender)) = get_icmp_connect(ifindex, &iface_name).await else {
        tracing::error!("create icmpv6 link error");
        service_status.just_change_status(ServiceStatus::Failed);
        return Ok(());
    };

    service_status.just_change_status(ServiceStatus::Running);

    let icmp_ad_interval = icmp_ad_interval as u64;
    let mut icmp_ra_interval =
        Box::pin(tokio::time::interval(Duration::from_secs(icmp_ad_interval)));
    let mut dhcp_expire_timer =
        Box::pin(tokio::time::interval(Duration::from_secs(LEASE_EXPIRE_INTERVAL)));

    let mut service_status_subscribe = service_status.subscribe();

    loop {
        tokio::select! {
            _ = icmp_ra_interval.tick() => {
                // TODO: SEND ICMP RA PACKET (icmpv6 module)
            },
            icmp_recv_result = icmp_recv.recv() => {
                match icmp_recv_result {
                    Some(_data) => {
                        // TODO: handle_rs_msg (icmpv6 module)
                    }
                    None => break
                }
            },
            dhcp_recv_result = dhcp_recv.recv() => {
                match dhcp_recv_result {
                    Some((msg_bytes, msg_addr)) => {
                        let mut status = share_status.lock().await;
                        let result = dhcpv6::process_dhcpv6_msg(
                            &mut status,
                            &msg_bytes,
                            msg_addr,
                            &server_duid,
                            &params,
                            &dns_servers,
                        );

                        // Send reply
                        if let Some(reply) = result.reply_bytes {
                            let _ = dhcp_sender.send_to(&reply, result.reply_dst).await;
                        }

                        // Emit allocation events
                        for (mac, ip) in &result.allocated_ips {
                            // TODO: eBPF upsert_ipv6_ip_mac(link_ifindex, *ip, *mac, mac_addr)
                            let _ = ipv6_assign_sender.try_send(
                                IPv6AssignEvent::Allocated(IPv6AssignInfo {
                                    iface_name: iface_name.clone(),
                                    mac: *mac,
                                    ip: *ip,
                                    device_id: None,
                                }),
                            );
                        }

                        // Emit expiry events
                        for (mac, ip) in &result.expired_ips {
                            let _ = ipv6_assign_sender.try_send(
                                IPv6AssignEvent::Expired(IPv6AssignInfo {
                                    iface_name: iface_name.clone(),
                                    mac: *mac,
                                    ip: *ip,
                                    device_id: None,
                                }),
                            );
                        }

                        // TODO: PD route management
                        for _change in &result.pd_route_changes {
                            // add_route_via / del_route / route_service
                        }
                    }
                    None => break
                }
            },
            _ = dhcp_expire_timer.tick() => {
                let mut status = share_status.lock().await;
                let expired_na = status.clean_expired_na();
                for na in &expired_na {
                    if let Some(mac) = na.mac {
                        let _ = ipv6_assign_sender.try_send(
                            IPv6AssignEvent::Expired(IPv6AssignInfo {
                                iface_name: iface_name.clone(),
                                mac,
                                ip: na.ip,
                                device_id: None,
                            }),
                        );
                    }
                }

                let expired_pd = status.clean_expired_pd();
                for pd in &expired_pd {
                    // TODO: cleanup PD routes
                    let _ = (pd.prefix, pd.prefix_len, &pd.active_routes);
                }
            },
            change_result = service_status_subscribe.changed() => {
                tracing::debug!("LAN v6 Service change");
                if let Err(_) = change_result {
                    tracing::error!("get change result error. exit loop");
                    break;
                }

                if service_status.is_exit() {
                    service_status.just_change_status(ServiceStatus::Stop);
                    tracing::info!("release send and stop");
                    break;
                }
            }
        }
    }
    return Ok(());
}

fn gen_server_duid(mac: &MacAddr) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&[0x00, 0x03]);
    duid.extend_from_slice(&[0x00, 0x01]);
    duid.extend_from_slice(&mac.octets());
    duid
}
