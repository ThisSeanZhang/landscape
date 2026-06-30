use tokio::time::{sleep, Duration, Instant};

use landscape_common::net_proto::ppp::PointToPoint;
use landscape_common::net_proto::pppoe::PPPoEFrame;
use landscape_common::service::{ServiceStatus, WatchService};

use crate::pppoe_client::PPPoEClientConfig;
use crate::sys_service::route::IpRouteService;

use super::error::PppoeError;
use super::system::EbpfHandle;
use super::{send_pppoe_session_frame, PppoeResult, ETH_P_PPOES, LCP_ECHO_INTERVAL};

async fn shutdown_ebpf_handle(
    ebpf_handle: &mut Option<EbpfHandle>,
    route_service: &IpRouteService,
) {
    if let Some(handle) = ebpf_handle.take() {
        handle.shutdown(route_service).await;
    }
}

pub async fn run(
    config: PPPoEClientConfig,
    status_rx: WatchService,
    route_service: IpRouteService,
) {
    status_rx.just_change_status(ServiceStatus::Staring);

    let Ok((mut tx, mut rx)) = landscape_ebpf::pppoe::start(config.index).await else {
        tracing::error!(
            iface_name = %config.iface_name,
            "PPPoE eBPF channel created fail"
        );
        status_rx.just_change_status(ServiceStatus::Stop);
        return;
    };

    tracing::info!(
        iface_name = %config.iface_name,
        "PPPoE client started, eBPF channel created"
    );

    status_rx.just_change_status(ServiceStatus::Running);

    let mut retry_count: u64 = 0;
    let mut ebpf_handle: Option<EbpfHandle> = None;

    loop {
        if retry_count > 0 {
            let delay = Duration::from_secs((5 * 60 * retry_count).min(30 * 60));
            tokio::select! {
                _ = sleep(delay) => {},
                _ = status_rx.wait_to_stopping() => {
                    shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                    status_rx.just_change_status(ServiceStatus::Stop);
                    break;
                }
            }
        }

        if rx.is_closed() {
            match landscape_ebpf::pppoe::start(config.index).await {
                Ok((new_tx, new_rx)) => {
                    tx = new_tx;
                    rx = new_rx;
                }
                Err(_) => {
                    tracing::error!(
                        iface_name = %config.iface_name,
                        "PPPoE eBPF channel recreate failed"
                    );
                    retry_count += 1;
                    continue;
                }
            }
        }

        let lcp_result = match super::lcp::run(&config, &mut tx, &mut rx, &status_rx).await {
            Ok(r) => {
                retry_count = 0;
                r
            }
            Err(e) if e.is_fatal() => {
                tracing::error!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "LCP phase fatal error, exiting"
                );
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Failed);
                break;
            }
            Err(PppoeError::ServiceStopped) => {
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "LCP phase error, retrying"
                );
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                retry_count += 1;
                continue;
            }
        };

        let nego_result = match super::negotiation::run(
            &config, &lcp_result, &mut tx, &mut rx, &status_rx,
        ).await {
            Ok(r) => r,
            Err(e) if e.is_fatal() => {
                tracing::error!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "Negotiation phase fatal error, exiting"
                );
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Failed);
                break;
            }
            Err(PppoeError::ServiceStopped) => {
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "Negotiation phase error, retrying"
                );
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                retry_count += 1;
                continue;
            }
        };

        tracing::info!(
            iface_name = %config.iface_name,
            client_ip = %nego_result.client_ip,
            server_ip = %nego_result.server_ip,
            session_id = lcp_result.session_id,
            has_ipv6 = nego_result.ipv6cp_server_id.is_some(),
            "PPPoE session established"
        );

        shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;

        match super::system::setup_ebpf(&config, &lcp_result, &nego_result, &route_service).await {
            Ok(handle) => {
                ebpf_handle = Some(handle);
                tracing::info!(
                    iface_name = %config.iface_name,
                    "PPPoE eBPF and system state applied, session is fully established"
                );
            }
            Err(e) => {
                tracing::error!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "Failed to apply eBPF/system state, session cannot proceed"
                );
                // Session negotiated but system setup failed — still need cleanup
                status_rx.just_change_status(ServiceStatus::Failed);
                break;
            }
        }

        retry_count = 0;

        match keepalive(
            &config, &lcp_result, nego_result.echo_req_id,
            &mut tx, &mut rx, &status_rx,
        ).await {
            Ok(()) => {
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(PppoeError::ServiceStopped) => {
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "Keepalive lost, reconnecting"
                );
                shutdown_ebpf_handle(&mut ebpf_handle, &route_service).await;
                retry_count += 1;
                continue;
            }
        }
    }
}

async fn keepalive(
    config: &PPPoEClientConfig,
    lcp: &super::lcp::LcpPhaseResult,
    initial_echo_id: u8,
    tx: &mut tokio::sync::mpsc::Sender<Box<Vec<u8>>>,
    rx: &mut tokio::sync::mpsc::Receiver<Box<Vec<u8>>>,
    status_rx: &WatchService,
) -> PppoeResult<()> {
    let mut echo_req_id: u8 = initial_echo_id;
    let mut echo_failures: u8 = 0;
    const MAX_ECHO_FAILURES: u8 = 5;

    let payload = PointToPoint::gen_echo_request_with_magic(echo_req_id, lcp.magic_number);
    send_pppoe_session_frame(&lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx).await?;
    echo_failures += 1;
    echo_req_id = echo_req_id.wrapping_add(1);

    let echo_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(echo_sleep);
    echo_sleep.as_mut().reset(Instant::now() + Duration::from_secs(LCP_ECHO_INTERVAL));

    loop {
        tokio::select! {
            _ = status_rx.wait_to_stopping() => {
                return Err(PppoeError::ServiceStopped);
            }
            received = rx.recv() => {
                let Some(raw) = received else {
                    return Err(PppoeError::ChannelClosed);
                };

                let Some(ppp) = parse_ppp_packet(&raw, lcp.session_id) else { continue; };

                if ppp.is_lcp_config() {
                    if ppp.is_echo_request() {
                        echo_failures = 0;
                        let reply = ppp.gen_reply_with_magic(lcp.magic_number);
                        send_pppoe_session_frame(
                            &lcp.server_mac, config.iface_mac, lcp.session_id, reply, tx,
                        ).await?;
                    } else if ppp.is_echo_reply() {
                        echo_failures = 0;
                        echo_req_id = echo_req_id.wrapping_add(1);
                    } else if ppp.is_termination() {
                        tracing::warn!(
                            iface_name = %config.iface_name,
                            "peer sent LCP termination request"
                        );
                        let ack = ppp.get_termination_ack();
                        send_pppoe_session_frame(
                            &lcp.server_mac, config.iface_mac, lcp.session_id, ack, tx,
                        ).await?;
                        return Err(PppoeError::PeerTerminated);
                    } else if ppp.is_termination_ack() {
                        return Err(PppoeError::PeerTerminated);
                    }
                }
            }
            _ = &mut echo_sleep => {
                let payload = PointToPoint::gen_echo_request_with_magic(
                    echo_req_id, lcp.magic_number,
                );
                if let Err(e) = send_pppoe_session_frame(
                    &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
                ).await {
                    return Err(e);
                }
                echo_failures += 1;
                if echo_failures > MAX_ECHO_FAILURES {
                    return Err(PppoeError::EchoFailed(echo_failures));
                }
                echo_sleep.as_mut().reset(
                    Instant::now() + Duration::from_secs(LCP_ECHO_INTERVAL)
                );
            }
        }
    }
}

fn parse_ppp_packet(raw: &[u8], session_id: u16) -> Option<PointToPoint> {
    if raw.len() < 16 {
        return None;
    }
    if u16::from_be_bytes([raw[12], raw[13]]) != ETH_P_PPOES {
        return None;
    }
    let frame = PPPoEFrame::new(&raw[14..])?;
    if frame.sid != session_id {
        return None;
    }
    if frame.is_terminate() {
        return None;
    }
    PointToPoint::new(&frame.payload)
}
