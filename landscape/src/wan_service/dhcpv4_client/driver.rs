use arc_swap::ArcSwap;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT;
use landscape_common::net_proto::udp::dhcp::DhcpV4Message;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{
    LinkStateHandle, SessionIface, V4Runtime, WanV4Lease, swap_if_changed,
};
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use super::fsm::{DhcpV4Fsm, FsmAction, FsmEvent, LeaseParams};
use super::socket::AdaptiveDhcpV4Socket;
use super::system::{self, AppliedAddr};
use super::{DhcpV4ClientServiceRuntimeConfig, DhcpV4ClientServices};

#[async_trait::async_trait]
pub(crate) trait DhcpV4Io: Send {
    async fn update_mode(&mut self, is_initial: bool) -> io::Result<()>;
    async fn send(&self, msg: &DhcpV4Message, dest_ip: Ipv4Addr) -> io::Result<()>;
    async fn recv(&mut self) -> io::Result<DhcpV4Message>;
}

#[async_trait::async_trait]
impl DhcpV4Io for AdaptiveDhcpV4Socket {
    async fn update_mode(&mut self, is_initial: bool) -> io::Result<()> {
        AdaptiveDhcpV4Socket::update_mode(self, is_initial).await
    }

    async fn send(&self, msg: &DhcpV4Message, dest_ip: Ipv4Addr) -> io::Result<()> {
        AdaptiveDhcpV4Socket::send(self, msg, dest_ip).await
    }

    async fn recv(&mut self) -> io::Result<DhcpV4Message> {
        AdaptiveDhcpV4Socket::recv(self).await
    }
}

#[async_trait::async_trait]
pub(crate) trait DhcpV4SystemOps: Send {
    async fn setup(&mut self, iface_name: &str);
    async fn apply_lease(&mut self, params: &LeaseParams);
    async fn release(&mut self);
}

struct RealSystemOps {
    config: DhcpV4ClientServiceRuntimeConfig,
    services: DhcpV4ClientServices,
    applied: Option<AppliedAddr>,
}

#[async_trait::async_trait]
impl DhcpV4SystemOps for RealSystemOps {
    async fn setup(&mut self, iface_name: &str) {
        system::disable_rp_filter(iface_name);
    }

    async fn apply_lease(&mut self, params: &LeaseParams) {
        system::apply_lease(params, &self.config, &self.services, &mut self.applied).await;
    }

    async fn release(&mut self) {
        system::release(&self.applied, &self.config, &self.services).await;
        self.applied = None;
    }
}

pub(crate) async fn run(
    config: DhcpV4ClientServiceRuntimeConfig,
    services: DhcpV4ClientServices,
    service_status: ServiceHandle,
) {
    let io = AdaptiveDhcpV4Socket::new(
        &config.iface_name,
        config.ifindex,
        config.mac_addr.octets(),
        config.client_port,
        LANDSCAPE_DEFAULE_DHCP_V4_SERVER_PORT,
    );
    let session = services.session.clone();
    let runtime = services.runtime.clone();
    let ops = RealSystemOps { config: config.clone(), services, applied: None };
    run_with(config, io, ops, session, runtime, service_status).await;
}

pub(crate) async fn run_with<IO, OPS>(
    config: DhcpV4ClientServiceRuntimeConfig,
    mut io: IO,
    mut ops: OPS,
    session: Option<LinkStateHandle>,
    runtime: Arc<ArcSwap<V4Runtime>>,
    service_status: ServiceHandle,
) where
    IO: DhcpV4Io,
    OPS: DhcpV4SystemOps,
{
    service_status.just_change_status(ServiceStatus::Staring);
    tracing::info!("DHCP V4 Client Starting");

    ops.setup(&config.iface_name).await;

    let mut fsm = DhcpV4Fsm::new(config.mac_addr, config.hostname.clone());

    swap_if_changed(&runtime, fsm.runtime_status().into());

    let mut timer = Box::pin(tokio::time::sleep(Duration::ZERO));
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
                    ops.apply_lease(&params).await;
                }
                FsmAction::ReleaseLease => {
                    ops.release().await;
                    if let Some(session) = session.as_ref() {
                        session.session_down();
                    }
                }
            }
        }

        swap_if_changed(&runtime, fsm.runtime_status().into());

        if from_recv && let Some(session) = session.as_ref() {
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

    ops.release().await;

    swap_if_changed(&runtime, V4Runtime::Stopped);

    if !service_status.is_stop() {
        service_status.just_change_status(if service_status.is_exit() {
            ServiceStatus::Stop
        } else {
            ServiceStatus::Failed
        });
    }
}
