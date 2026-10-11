use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{SessionIface, WanV4Lease};
use std::time::Duration;

use super::fsm::{DhcpV4Fsm, FsmAction, FsmEvent};
use super::socket::AdaptiveDhcpV4Socket;
use super::system::{self, AppliedAddr};
use super::{DhcpV4ClientServiceRuntimeConfig, DhcpV4ClientServices};

pub(crate) async fn run(
    config: DhcpV4ClientServiceRuntimeConfig,
    services: DhcpV4ClientServices,
    service_status: ServiceHandle,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    tracing::info!("DHCP V4 Client Starting");

    system::disable_rp_filter(&config.iface_name);

    let mut io = AdaptiveDhcpV4Socket::new(
        &config.iface_name,
        config.ifindex,
        config.mac_addr.octets(),
        config.client_port,
        LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT,
    );
    let mut fsm = DhcpV4Fsm::new(config.mac_addr, config.hostname.clone());

    let mut timer = Box::pin(tokio::time::sleep(Duration::ZERO));
    let mut applied: Option<AppliedAddr> = None;
    let stop_token = service_status.stop_token();

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("DHCP V4 Client Running");

    loop {
        if let Err(e) = io.update_mode(fsm.is_initial_phase()).await {
            tracing::error!("Failed to update adaptive socket mode: {:?}", e);
        }

        let (event, from_recv) = tokio::select! {
            _ = &mut timer => (FsmEvent::TimerFired, false),
            res = io.recv() => match res {
                Ok(msg) => (FsmEvent::Recv(msg), true),
                Err(e) => {
                    tracing::error!("Error receiving packet: {:?}", e);
                    continue;
                }
            },
            () = stop_token.cancelled() => break,
        };

        for action in fsm.on_event(event) {
            match action {
                FsmAction::Send { msg, dest } => {
                    if let Err(e) = io.send(&msg, dest).await {
                        tracing::error!("Error sending DHCP packet: {:?}", e);
                    }
                }
                FsmAction::ScheduleTimer(wait) => {
                    timer.as_mut().set(tokio::time::sleep(wait));
                }
                FsmAction::BindLease(params) => {
                    system::apply_lease(&params, &config, &services, &mut applied).await;
                }
            }
        }

        if from_recv && let Some(session) = services.session.as_ref() {
            match fsm.leased_ip() {
                Some(ip) => session.session_up(
                    SessionIface::new(
                        config.ifindex,
                        config.iface_name.clone(),
                        Some(config.mac_addr),
                    ),
                    Some(WanV4Lease::new(config.ifindex, ip)),
                ),
                None => session.session_down(),
            }
        }
    }

    tracing::info!("DHCPv4 Client Stop: {:#?}", service_status);

    system::release(&applied, &config, &services).await;

    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
}
