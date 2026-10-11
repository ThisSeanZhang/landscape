use landscape_common::net::MacAddr;
use landscape_common::net_proto::dhcp::{
    DhcpV4Message, DhcpV4MessageType as MessageType, DhcpV4OpCode, DhcpV4Option as DhcpOption,
    DhcpV4OptionCode as OptionCode, DhcpV4Options,
};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::Instant;

use super::message::{gen_discover, gen_request};

pub(crate) const DEFAULT_TIME_OUT: u64 = 4;
const MAX_CONNECT_RETRY_BACKOFF_SECS: u64 = 10 * 60;
const DISCOVER_ATTEMPTS_PER_ROUND: u64 = 4;
const REQUEST_ATTEMPTS: u64 = 3;

fn calc_connect_retry_backoff_secs(failure_count: u32) -> u64 {
    let exp = failure_count.saturating_sub(1).min(31);
    let secs = DEFAULT_TIME_OUT.saturating_mul(1u64 << exp);
    secs.min(MAX_CONNECT_RETRY_BACKOFF_SECS)
}

fn get_new_ipv4_xid() -> u32 {
    rand::random()
}

fn retry_wait(attempts: u64) -> Duration {
    Duration::from_secs(DEFAULT_TIME_OUT * attempts.max(1))
}

#[derive(Clone, Debug)]
pub(crate) struct OfferContext {
    pub(crate) ciaddr: Ipv4Addr,
    pub(crate) yiaddr: Ipv4Addr,
    pub(crate) siaddr: Ipv4Addr,
    pub(crate) options: DhcpV4Options,
}

#[derive(Clone, Debug)]
pub(crate) struct LeaseContext {
    pub(crate) xid: u32,
    pub(crate) ciaddr: Ipv4Addr,
    pub(crate) yiaddr: Ipv4Addr,
    pub(crate) siaddr: Ipv4Addr,
    pub(crate) options: DhcpV4Options,
    pub(crate) renew_at: Instant,
    pub(crate) rebind_at: Instant,
    pub(crate) lease_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct LeaseParams {
    pub(crate) yiaddr: Ipv4Addr,
    pub(crate) options: DhcpV4Options,
    pub(crate) prefix: u32,
    pub(crate) renew_time: u64,
    pub(crate) lease_time: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum DhcpState {
    Discovering { xid: u32, requested: Option<Ipv4Addr> },
    Requesting { xid: u32, offer: OfferContext },
    Bound { lease: LeaseContext },
    Renewing { lease: LeaseContext },
    WaitToRebind { lease: LeaseContext },
    Rebind { lease: LeaseContext },
}

impl DhcpState {
    pub(crate) fn init(requested: Option<Ipv4Addr>) -> DhcpState {
        DhcpState::Discovering { xid: get_new_ipv4_xid(), requested }
    }
}

#[derive(Debug)]
pub(crate) enum FsmEvent {
    TimerFired,
    Recv(DhcpV4Message),
}

#[derive(Debug)]
pub(crate) enum FsmAction {
    Send { msg: DhcpV4Message, dest: Ipv4Addr },
    ScheduleTimer(Duration),
    BindLease(LeaseParams),
}

pub(crate) struct DhcpV4Fsm {
    pub(crate) state: DhcpState,
    pub(crate) attempts: u64,
    pub(crate) connect_failure_count: u32,
    mac_addr: MacAddr,
    hostname: String,
}

impl DhcpV4Fsm {
    pub(crate) fn new(mac_addr: MacAddr, hostname: String) -> Self {
        Self {
            state: DhcpState::init(None),
            attempts: 0,
            connect_failure_count: 0,
            mac_addr,
            hostname,
        }
    }

    pub(crate) fn is_initial_phase(&self) -> bool {
        matches!(
            self.state,
            DhcpState::Discovering { .. } | DhcpState::Requesting { .. } | DhcpState::Rebind { .. }
        )
    }

    pub(crate) fn leased_ip(&self) -> Option<Ipv4Addr> {
        match &self.state {
            DhcpState::Bound { lease }
            | DhcpState::Renewing { lease }
            | DhcpState::WaitToRebind { lease }
            | DhcpState::Rebind { lease } => {
                if lease.yiaddr.is_unspecified() {
                    Some(lease.ciaddr)
                } else {
                    Some(lease.yiaddr)
                }
            }
            _ => None,
        }
    }

    pub(crate) fn on_event(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            FsmEvent::TimerFired => self.on_timer(),
            FsmEvent::Recv(msg) => self.on_recv(msg),
        }
    }

    fn on_timer(&mut self) -> Vec<FsmAction> {
        let state = std::mem::replace(&mut self.state, DhcpState::init(None));
        match state {
            DhcpState::Discovering { xid, requested } => {
                if self.attempts >= DISCOVER_ATTEMPTS_PER_ROUND {
                    self.connect_failure_count = self.connect_failure_count.saturating_add(1);
                    let backoff = calc_connect_retry_backoff_secs(self.connect_failure_count);
                    tracing::warn!(
                        "DHCPv4 discover timeout exceeded limit, retry in {}s (failure_count={})",
                        backoff,
                        self.connect_failure_count
                    );
                    self.state = DhcpState::init(None);
                    self.attempts = 0;
                    return vec![FsmAction::ScheduleTimer(Duration::from_secs(backoff))];
                }
                self.attempts += 1;
                let use_broadcast = self.attempts <= 2;
                let msg =
                    gen_discover(xid, self.mac_addr, requested, &self.hostname, use_broadcast);
                self.state = DhcpState::Discovering { xid, requested };
                vec![
                    FsmAction::Send { msg, dest: Ipv4Addr::BROADCAST },
                    FsmAction::ScheduleTimer(retry_wait(self.attempts)),
                ]
            }
            DhcpState::Requesting { xid, offer } => {
                if self.attempts >= REQUEST_ATTEMPTS {
                    tracing::warn!("DHCPv4 request attempts exhausted, restart discover");
                    self.state = DhcpState::init(None);
                    self.attempts = 0;
                    return self.on_timer();
                }
                self.attempts += 1;
                let mut options = offer.options.clone();
                if options.get(OptionCode::ServerIdentifier).is_none()
                    && !offer.siaddr.is_unspecified()
                {
                    options.insert(DhcpOption::ServerIdentifier(offer.siaddr));
                }
                let msg = gen_request(
                    xid,
                    self.mac_addr,
                    offer.ciaddr,
                    offer.yiaddr,
                    options,
                    &self.hostname,
                );
                self.state = DhcpState::Requesting { xid, offer };
                vec![
                    FsmAction::Send { msg, dest: Ipv4Addr::BROADCAST },
                    FsmAction::ScheduleTimer(retry_wait(self.attempts)),
                ]
            }
            DhcpState::Bound { mut lease } => {
                tracing::error!("Time to renew lease, Renewing Strat...");
                lease.xid = get_new_ipv4_xid();
                lease.ciaddr = lease.yiaddr;
                lease.yiaddr = Ipv4Addr::UNSPECIFIED;
                self.state = DhcpState::Renewing { lease };
                self.attempts = 0;
                self.on_timer()
            }
            DhcpState::Renewing { lease } => {
                let dest = if lease.siaddr.is_unspecified() {
                    if let Some(DhcpOption::ServerIdentifier(addr)) =
                        lease.options.get(OptionCode::ServerIdentifier)
                    {
                        *addr
                    } else {
                        Ipv4Addr::BROADCAST
                    }
                } else {
                    lease.siaddr
                };

                let mut request_options = DhcpV4Options::default();
                request_options.insert(DhcpOption::MessageType(MessageType::Request));
                request_options.insert(DhcpOption::Hostname(self.hostname.clone()));

                let msg = gen_request(
                    lease.xid,
                    self.mac_addr,
                    lease.ciaddr,
                    lease.yiaddr,
                    request_options,
                    &self.hostname,
                );
                let send = FsmAction::Send { msg, dest };

                let renew_span =
                    lease.rebind_at.saturating_duration_since(lease.renew_at).as_secs() / 6;
                let rebind_early_at = lease
                    .rebind_at
                    .checked_sub(Duration::from_secs(renew_span))
                    .unwrap_or_else(Instant::now);
                if Instant::now() >= rebind_early_at {
                    let wait = lease.rebind_at.saturating_duration_since(Instant::now());
                    self.state = DhcpState::WaitToRebind { lease };
                    vec![send, FsmAction::ScheduleTimer(wait)]
                } else {
                    let wait = (lease.rebind_at.saturating_duration_since(Instant::now()) / 2)
                        .max(Duration::from_secs(60));
                    self.state = DhcpState::Renewing { lease };
                    vec![send, FsmAction::ScheduleTimer(wait)]
                }
            }
            DhcpState::WaitToRebind { mut lease } => {
                lease.xid = get_new_ipv4_xid();
                lease.yiaddr = Ipv4Addr::UNSPECIFIED;
                self.state = DhcpState::Rebind { lease };
                self.attempts = 0;
                self.on_timer()
            }
            DhcpState::Rebind { lease } => {
                if Instant::now() > lease.lease_at {
                    tracing::warn!("Rebind turn to Discover");
                    self.state = DhcpState::init(None);
                    self.attempts = 0;
                    return self.on_timer();
                }
                let wait = (lease.lease_at.saturating_duration_since(Instant::now()) / 2)
                    .max(Duration::from_secs(60));
                let mut request_options = DhcpV4Options::default();
                request_options.insert(DhcpOption::MessageType(MessageType::Request));
                request_options.insert(DhcpOption::Hostname(self.hostname.clone()));
                let msg = gen_request(
                    lease.xid,
                    self.mac_addr,
                    lease.ciaddr,
                    lease.yiaddr,
                    request_options,
                    &self.hostname,
                );
                self.state = DhcpState::Rebind { lease };
                vec![
                    FsmAction::Send { msg, dest: Ipv4Addr::BROADCAST },
                    FsmAction::ScheduleTimer(wait),
                ]
            }
        }
    }

    fn on_recv(&mut self, dhcp: DhcpV4Message) -> Vec<FsmAction> {
        if dhcp.opcode() != DhcpV4OpCode::BootReply {
            tracing::error!("is not server op");
            return vec![];
        }

        if dhcp.xid() != self.current_xid() {
            return vec![];
        }

        let Some(DhcpOption::MessageType(msg_type)) = dhcp.opts().get(OptionCode::MessageType)
        else {
            return vec![];
        };
        let msg_type = *msg_type;

        if !self.can_handle_message(&msg_type) {
            tracing::error!("self: {:?}", self.state);
            tracing::error!("current status can not handle this status");
            return vec![];
        }

        tracing::debug!("recv msg: {dhcp:?}");

        match (msg_type, &self.state) {
            (MessageType::Offer, DhcpState::Discovering { .. }) => {
                let xid = dhcp.xid();
                let offer = OfferContext {
                    ciaddr: dhcp.ciaddr(),
                    yiaddr: dhcp.yiaddr(),
                    siaddr: dhcp.siaddr(),
                    options: dhcp.opts().clone(),
                };
                self.state = DhcpState::Requesting { xid, offer };
                self.attempts = 0;
                tracing::debug!("current status move to: {:#?}", self.state);
                vec![FsmAction::ScheduleTimer(Duration::ZERO)]
            }
            (
                MessageType::Ack,
                DhcpState::Requesting { .. }
                | DhcpState::Renewing { .. }
                | DhcpState::WaitToRebind { .. }
                | DhcpState::Rebind { .. },
            ) => self.handle_ack(dhcp),
            (
                MessageType::Nak,
                DhcpState::Requesting { .. }
                | DhcpState::Renewing { .. }
                | DhcpState::WaitToRebind { .. }
                | DhcpState::Rebind { .. },
            ) => {
                self.state = DhcpState::init(None);
                self.attempts = 0;
                vec![FsmAction::ScheduleTimer(Duration::ZERO)]
            }
            _ => vec![],
        }
    }

    fn handle_ack(&mut self, dhcp: DhcpV4Message) -> Vec<FsmAction> {
        let expected = self.expected_yiaddr().expect("state checked by can_handle_message");
        if !(expected.is_unspecified() || dhcp.yiaddr() == expected) {
            tracing::error!("IP 地址不符合: new ip: {:?}, old ip: {:?}", dhcp.yiaddr(), expected);
            return vec![];
        }

        let new_ciaddr = dhcp.ciaddr();
        let new_yiaddr = dhcp.yiaddr();
        let new_siaddr = dhcp.siaddr();

        let options = dhcp.opts().clone();
        tracing::debug!("get bound ip, {:?}", new_yiaddr);
        tracing::info!(
            "start Bound ip: {} {} {} {:?}",
            new_ciaddr,
            new_yiaddr,
            new_siaddr,
            options
        );

        let Some((renew_time, rebinding_time, lease_time)) = get_renew_times(&options) else {
            tracing::error!("can not read renew time options");
            return vec![];
        };

        let Some(DhcpOption::SubnetMask(mask)) = options.get(OptionCode::SubnetMask) else {
            tracing::error!("can not read mask in options");
            return vec![];
        };

        let prefix = u32::from_be_bytes(mask.octets()).count_ones();

        let now = Instant::now();
        let lease = LeaseContext {
            xid: get_new_ipv4_xid(),
            ciaddr: new_ciaddr,
            yiaddr: new_yiaddr,
            siaddr: new_siaddr,
            options: options.clone(),
            renew_at: now + Duration::from_secs(renew_time),
            rebind_at: now + Duration::from_secs(rebinding_time),
            lease_at: now + Duration::from_secs(lease_time),
        };

        tracing::debug!("current status move to: {:#?}", DhcpState::Bound { lease: lease.clone() });
        self.state = DhcpState::Bound { lease };
        self.attempts = 0;
        self.connect_failure_count = 0;

        vec![
            FsmAction::BindLease(LeaseParams {
                yiaddr: new_yiaddr,
                options,
                prefix,
                renew_time,
                lease_time,
            }),
            FsmAction::ScheduleTimer(Duration::from_secs(renew_time)),
        ]
    }

    fn current_xid(&self) -> u32 {
        match &self.state {
            DhcpState::Discovering { xid, .. } | DhcpState::Requesting { xid, .. } => *xid,
            DhcpState::Bound { lease }
            | DhcpState::Renewing { lease }
            | DhcpState::WaitToRebind { lease }
            | DhcpState::Rebind { lease } => lease.xid,
        }
    }

    fn expected_yiaddr(&self) -> Option<Ipv4Addr> {
        match &self.state {
            DhcpState::Requesting { offer, .. } => Some(offer.yiaddr),
            DhcpState::Bound { lease }
            | DhcpState::Renewing { lease }
            | DhcpState::WaitToRebind { lease }
            | DhcpState::Rebind { lease } => Some(lease.yiaddr),
            _ => None,
        }
    }

    fn can_handle_message(&self, message_type: &MessageType) -> bool {
        match &self.state {
            DhcpState::Discovering { .. } => matches!(message_type, MessageType::Offer),
            DhcpState::Requesting { .. }
            | DhcpState::Renewing { .. }
            | DhcpState::Rebind { .. }
            | DhcpState::WaitToRebind { .. } => {
                matches!(message_type, MessageType::Ack | MessageType::Nak)
            }
            _ => false,
        }
    }
}

pub(crate) fn get_renew_times(options: &DhcpV4Options) -> Option<(u64, u64, u64)> {
    let lease_time = match options.get(OptionCode::AddressLeaseTime)? {
        DhcpOption::AddressLeaseTime(t) => *t,
        _ => return None,
    };
    let lease = (lease_time as u64).max(2);
    let default_renew = lease / 2;
    let default_rebind = (lease * 7 / 8).max(default_renew + 1);

    let explicit_renew = match options.get(OptionCode::Renewal) {
        Some(DhcpOption::Renewal(t)) if *t > 0 => Some(*t as u64),
        _ => None,
    };
    let explicit_rebind = match options.get(OptionCode::Rebinding) {
        Some(DhcpOption::Rebinding(t)) if *t > 0 => Some(*t as u64),
        _ => None,
    };

    let renew_time = explicit_renew.unwrap_or(default_renew).clamp(1, lease - 1);
    let rebind_time = explicit_rebind.unwrap_or(default_rebind).clamp(renew_time + 1, lease);

    Some((renew_time, rebind_time, lease))
}
