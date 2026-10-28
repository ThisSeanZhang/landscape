use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::time::{Duration, Instant, sleep};

use landscape_common::net_proto::ppp::{PPPOption, PointToPoint};
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::utils::time::now_ms;
use landscape_common::wan_link::{
    LinkStateHandle, PppoeRuntime, SessionIface, V4Runtime, WanV4Lease, swap_if_changed,
};
use landscape_ebpf::chain::wan_link::WanLinkDataplane;

use super::PPPoEClientConfig;
use crate::sys_service::route::IpRouteService;

use super::error::PppoeError;
use super::lcp::{AUTH_PROTO_CHAP, CHAP_ALGORITHM_MD5};
use super::system::SessionHandle;
use super::{
    LCP_ECHO_INTERVAL, MAX_ECHO_FAILURES, MAX_NAK_LOOPS, OPT_AUTH, OPT_MAGIC, OPT_MRU, PppoeResult,
    SessionPacket, echo_reply_is_valid_liveness, send_padt, send_pppoe_session_frame,
};

async fn shutdown_session(
    session_handle: &mut Option<SessionHandle>,
    route_service: &IpRouteService,
    dataplane: &Arc<WanLinkDataplane>,
    session: Option<&LinkStateHandle>,
) {
    if let Some(handle) = session_handle.take() {
        handle.shutdown(route_service, dataplane).await;
    }
    if let Some(session) = session {
        session.session_down();
    }
}

pub async fn run(
    config: PPPoEClientConfig,
    status_rx: ServiceHandle,
    route_service: IpRouteService,
    dataplane: Arc<WanLinkDataplane>,
    session: Option<LinkStateHandle>,
    v4_runtime: Arc<ArcSwap<V4Runtime>>,
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

    let mut retry_count: u64 = 0;
    // Set when the previous attempt lost an *established* session (echo
    // failure / peer hangup / PADT / channel loss): the first redial skips
    // the backoff and dials immediately, because the BR is normally ready to
    // re-establish right away. Dial/negotiation failures keep the linear
    // backoff to avoid hammering a dead line.
    let mut immediate_redial = false;
    let mut session_handle: Option<SessionHandle> = None;
    let stop_token = status_rx.stop_token();

    loop {
        if retry_count > 0 && !(immediate_redial && retry_count == 1) {
            let backoff_base = config.redial_backoff_base_secs.unwrap_or(5 * 60);
            let delay = Duration::from_secs((backoff_base * retry_count).min(30 * 60));
            swap_if_changed(
                &v4_runtime,
                V4Runtime::Pppoe(PppoeRuntime::RedialBackoff {
                    retry_count,
                    retry_in_secs: delay.as_secs(),
                }),
            );
            tokio::select! {
                _ = sleep(delay) => {},
                _ = stop_token.cancelled() => {
                    shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref()).await;
                    status_rx.just_change_status(ServiceStatus::Stop);
                    break;
                }
            }
        } else if retry_count > 0 {
            tracing::info!(
                iface_name = %config.iface_name,
                "redialing immediately after session drop"
            );
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
                    immediate_redial = false;
                    retry_count += 1;
                    continue;
                }
            }
        }

        swap_if_changed(&v4_runtime, V4Runtime::Pppoe(PppoeRuntime::Dialing));
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
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                status_rx.just_change_status(ServiceStatus::Failed);
                break;
            }
            Err(PppoeError::ServiceStopped) => {
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "LCP phase error, retrying"
                );
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                // Same peer-teardown rule as the negotiation phase below:
                // a PADT closing a not-yet-negotiated session is not a
                // line failure either.
                immediate_redial = redial_immediately_after(&e);
                retry_count += 1;
                continue;
            }
        };

        tracing::info!(
            iface_name = %config.iface_name,
            session_id = lcp_result.session_id,
            server_mac = ?lcp_result.server_mac,
            our_mru = lcp_result.mru,
            our_magic = format_args!("0x{:08x}", lcp_result.magic_number),
            peer_mru = lcp_result.peer_mru,
            peer_magic = format_args!("0x{:08x}", lcp_result.peer_magic),
            auth_type = format_args!("0x{:04x}", lcp_result.auth_type),
            "LCP phase completed"
        );

        swap_if_changed(&v4_runtime, V4Runtime::Pppoe(PppoeRuntime::Negotiating));
        let nego_result =
            match super::negotiation::run(&config, &lcp_result, &mut tx, &mut rx, &status_rx).await
            {
                Ok(r) => r,
                Err(e) if e.is_fatal() => {
                    tracing::error!(
                        iface_name = %config.iface_name,
                        error = %e,
                        "Negotiation phase fatal error, exiting"
                    );
                    shutdown_session(
                        &mut session_handle,
                        &route_service,
                        &dataplane,
                        session.as_ref(),
                    )
                    .await;
                    status_rx.just_change_status(ServiceStatus::Failed);
                    break;
                }
                Err(PppoeError::ServiceStopped) => {
                    send_terminate_and_padt(&config, &lcp_result, &mut tx).await;
                    shutdown_session(
                        &mut session_handle,
                        &route_service,
                        &dataplane,
                        session.as_ref(),
                    )
                    .await;
                    status_rx.just_change_status(ServiceStatus::Stop);
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        iface_name = %config.iface_name,
                        error = %e,
                        "Negotiation phase error, retrying"
                    );
                    if should_send_terminate(&e) {
                        send_terminate_and_padt(&config, &lcp_result, &mut tx).await;
                    } else if should_send_padt(&e) {
                        // The peer closed LCP itself (Terminate-Ack was
                        // already sent by the negotiation phase); only the
                        // PPPoE session still needs freeing.
                        let _ = send_padt(
                            &lcp_result.server_mac,
                            config.iface_mac,
                            lcp_result.session_id,
                            &mut tx,
                        )
                        .await;
                    }
                    shutdown_session(
                        &mut session_handle,
                        &route_service,
                        &dataplane,
                        session.as_ref(),
                    )
                    .await;
                    // A peer-initiated teardown (PADT / LCP Terminate) during
                    // negotiation is not a dial failure: the first redial
                    // skips the backoff, same as a dropped established
                    // session.  (The retry_count == 1 gate keeps a BR that
                    // always PADTs new sessions from being hammered.)
                    immediate_redial = redial_immediately_after(&e);
                    retry_count += 1;
                    continue;
                }
            };

        tracing::info!(
            iface_name = %config.iface_name,
            client_ip = %nego_result.client_ip,
            server_ip = %nego_result.server_ip,
            ipv6cp_client_id = ?nego_result.ipv6cp_client_id,
            ipv6cp_server_id = ?nego_result.ipv6cp_server_id,
            session_id = lcp_result.session_id,
            "PPPoE session established, negotiation phase completed"
        );

        shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref()).await;

        match super::system::create_session(
            &config,
            &lcp_result,
            &nego_result,
            &route_service,
            &dataplane,
        )
        .await
        {
            Ok(handle) => {
                session_handle = Some(handle);
                swap_if_changed(
                    &v4_runtime,
                    V4Runtime::Pppoe(PppoeRuntime::Online {
                        local_ip: nego_result.client_ip,
                        peer_ip: nego_result.server_ip,
                        session_id: lcp_result.session_id,
                        connected_at: now_ms(),
                    }),
                );
                if let Some(session) = session.as_ref() {
                    session.session_up(
                        SessionIface::new(
                            config.index,
                            config.iface_name.clone(),
                            Some(config.iface_mac),
                        )
                        .with_v6_linklocal(
                            session_handle
                                .as_ref()
                                .and_then(|handle| handle.ipv6cp_client_linklocal),
                        ),
                        Some(WanV4Lease::new(config.index, nego_result.client_ip)),
                    );
                }
                if !status_rx.is_running() {
                    status_rx.just_change_status(ServiceStatus::Running);
                }
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
                // Session negotiated but system setup failed — tell the BR we
                // are going away before cleaning up.
                send_terminate_and_padt(&config, &lcp_result, &mut tx).await;
                status_rx.just_change_status(ServiceStatus::Failed);
                break;
            }
        }

        retry_count = 0;

        match keepalive(&config, &lcp_result, nego_result.echo_req_id, &mut tx, &mut rx, &status_rx)
            .await
        {
            Ok(()) => {
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(PppoeError::ServiceStopped) => {
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                status_rx.just_change_status(ServiceStatus::Stop);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    iface_name = %config.iface_name,
                    error = %e,
                    "Keepalive lost, reconnecting"
                );
                // pppd's PPPoEDisconnectDevice sends PADT on every teardown
                // path so the BR frees the session; after a received PADT
                // the session is already closed (RFC 2516 §5.6).
                if !matches!(e, PppoeError::PadtReceived) {
                    let _ = send_padt(
                        &lcp_result.server_mac,
                        config.iface_mac,
                        lcp_result.session_id,
                        &mut tx,
                    )
                    .await;
                }
                shutdown_session(&mut session_handle, &route_service, &dataplane, session.as_ref())
                    .await;
                // An established session lost to echo failure / peer hangup
                // / PADT redials immediately (see redial_immediately_after);
                // other keepalive errors (channel loss) keep the existing
                // immediate-retry behaviour.
                immediate_redial =
                    matches!(e, PppoeError::ChannelClosed) || redial_immediately_after(&e);
                retry_count += 1;
                continue;
            }
        }
    }

    swap_if_changed(&v4_runtime, V4Runtime::Stopped);
}

pub(crate) async fn keepalive(
    config: &PPPoEClientConfig,
    lcp: &super::lcp::LcpPhaseResult,
    initial_echo_id: u8,
    tx: &mut tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    status_rx: &ServiceHandle,
) -> PppoeResult<()> {
    let mut echo_req_id: u8 = initial_echo_id;
    let mut echo_failures: u8 = 0;
    // Consecutive unanswered Naks sent while answering peer LCP
    // renegotiation requests (pppd `nakloops`).
    let mut renego_nak_loops: u8 = 0;

    let payload = PointToPoint::gen_echo_request_with_magic(echo_req_id, lcp.magic_number);
    send_pppoe_session_frame(&lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx)
        .await?;
    echo_failures += 1;
    echo_req_id = echo_req_id.wrapping_add(1);

    let echo_interval = config.lcp_echo_interval.unwrap_or(LCP_ECHO_INTERVAL);

    let echo_sleep = sleep(Duration::from_secs(0));
    tokio::pin!(echo_sleep);
    echo_sleep.as_mut().reset(Instant::now() + Duration::from_secs(echo_interval));

    let stop_token = status_rx.stop_token();

    loop {
        tokio::select! {
            _ = stop_token.cancelled() => {
                // Graceful hangup: tell the peer we are going away instead of
                // vanishing silently, then wait (bounded) for the Terminate-Ack
                // so the frame is actually flushed to the wire.
                let term = PointToPoint::get_termination_request(echo_req_id).convert_to_payload();
                if send_pppoe_session_frame(
                    &lcp.server_mac, config.iface_mac, lcp.session_id, term, tx,
                )
                .await
                .is_ok()
                {
                    let ack_wait = sleep(Duration::from_secs(2));
                    tokio::pin!(ack_wait);
                    loop {
                        tokio::select! {
                            _ = &mut ack_wait => break,
                            received = rx.recv() => {
                                let Some(raw) = received else { break };
                                if let Some(SessionPacket::Ppp(ppp)) =
                                    super::parse_session_packet(&raw, lcp.session_id, &lcp.server_mac)
                                    && ppp.is_lcp_config() && ppp.is_termination_ack() {
                                        break;
                                    }
                            }
                        }
                    }
                }
                // Close the PPPoE session itself (RFC 2516 §5.6) so the BR
                // frees it immediately.
                let _ = send_padt(&lcp.server_mac, config.iface_mac, lcp.session_id, tx).await;
                return Err(PppoeError::ServiceStopped);
            }
            received = rx.recv() => {
                let Some(raw) = received else {
                    return Err(PppoeError::ChannelClosed);
                };

                let ppp = match super::parse_session_packet(&raw, lcp.session_id, &lcp.server_mac) {
                    Some(SessionPacket::Padt) => {
                        // RFC 2516 §5.6: the session is terminated — no
                        // point waiting for echo timeouts.
                        tracing::warn!(
                            iface = %config.iface_name,
                            session_id = lcp.session_id,
                            "received PADT, session terminated by peer"
                        );
                        return Err(PppoeError::PadtReceived);
                    }
                    Some(SessionPacket::Ppp(ppp)) => ppp,
                    None => { continue; }
                };

                if ppp.is_lcp_config() {
                    if ppp.is_echo_request() {
                        // A peer Echo-Request is one-way liveness evidence only:
                        // it does not prove the peer can hear us, so it must
                        // not reset the echo failure count (pppd semantics).
                        let reply = ppp.gen_reply_with_magic(lcp.magic_number);
                        send_pppoe_session_frame(
                            &lcp.server_mac, config.iface_mac, lcp.session_id, reply, tx,
                        ).await?;
                    } else if ppp.is_echo_reply() {
                        if echo_reply_is_valid_liveness(&ppp, lcp.magic_number) {
                            echo_failures = 0;
                        } else if echo_reply_has_own_magic(&ppp, lcp.magic_number) {
                            // RFC 1661 §6.4: the peer echoed our own magic
                            // number back — the link is looped, so this
                            // reply must not count as liveness.
                            tracing::error!(
                                iface = %config.iface_name,
                                "echo reply carries our own magic number, link is looped"
                            );
                        } else {
                            // RFC 1661 §5.4: no well-formed Magic-Number —
                            // not liveness evidence.
                            tracing::warn!(
                                iface = %config.iface_name,
                                "malformed echo reply ignored (bad Magic-Number)"
                            );
                        }
                    } else if ppp.is_termination() {
                        tracing::warn!(
                            iface = %config.iface_name,
                            "peer sent LCP termination request"
                        );
                        let ack = ppp.get_termination_ack();
                        send_pppoe_session_frame(
                            &lcp.server_mac, config.iface_mac, lcp.session_id, ack, tx,
                        ).await?;
                        return Err(PppoeError::PeerTerminated);
                    } else if ppp.is_termination_ack() {
                        return Err(PppoeError::PeerTerminated);
                    } else if ppp.is_request() {
                        // The peer wants to (re)negotiate LCP options while
                        // Established — answer instead of ignoring it, so
                        // the peer does not tear the session down.
                        handle_lcp_renegotiation_request(
                            config,
                            lcp,
                            &mut renego_nak_loops,
                            &ppp,
                            tx,
                        )
                        .await?;
                    }
                }
            }
            _ = &mut echo_sleep => {
                let payload = PointToPoint::gen_echo_request_with_magic(
                    echo_req_id, lcp.magic_number,
                );
                send_pppoe_session_frame(
                    &lcp.server_mac, config.iface_mac, lcp.session_id, payload, tx,
                ).await?;
                echo_failures += 1;
                if echo_failures > MAX_ECHO_FAILURES {
                    return Err(PppoeError::EchoFailed(echo_failures));
                }
                echo_req_id = echo_req_id.wrapping_add(1);
                echo_sleep.as_mut().reset(
                    Instant::now() + Duration::from_secs(echo_interval)
                );
            }
        }
    }
}

/// Best-effort goodbye for a session being torn down without the keepalive
/// graceful-stop handshake: an LCP Terminate-Request followed by a PPPoE PADT
/// (RFC 2516 §5.6) so the BR frees the session instead of keeping it around
/// until its own echo timeouts fire.
async fn send_terminate_and_padt(
    config: &PPPoEClientConfig,
    lcp: &super::lcp::LcpPhaseResult,
    tx: &mut tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let term = PointToPoint::get_termination_request(0).convert_to_payload();
    let _ =
        send_pppoe_session_frame(&lcp.server_mac, config.iface_mac, lcp.session_id, term, tx).await;
    let _ = send_padt(&lcp.server_mac, config.iface_mac, lcp.session_id, tx).await;
}

/// Whether the LCP Terminate-Request half of the goodbye is appropriate
/// when the negotiation phase fails with `e`: not after the peer already
/// closed LCP (its Terminate-Request was answered with a Terminate-Ack by
/// the failed phase) and not after a PADT (RFC 2516 §5.6 forbids further
/// traffic on a PADT-terminated session).
fn should_send_terminate(e: &PppoeError) -> bool {
    !matches!(e, PppoeError::PadtReceived | PppoeError::PeerTerminated)
}

/// Whether a PPPoE PADT should still be sent so the BR frees the session:
/// pppd's PPPoEDisconnectDevice sends PADT on every teardown path, so an
/// LCP-terminated session still gets one. Only a received PADT means the
/// PPPoE session is already gone — nothing may follow it.
fn should_send_padt(e: &PppoeError) -> bool {
    !matches!(e, PppoeError::PadtReceived)
}

/// Whether an error from a dial phase (LCP or negotiation) means the
/// session was lost rather than the dial failing: peer teardown (PADT /
/// LCP Terminate) or an established-session echo failure. The BR is
/// normally ready to re-establish right away, so the first redial skips
/// the backoff. The `retry_count == 1` gate at the top of the run loop
/// still keeps a BR that always tears down new sessions from being
/// hammered.
fn redial_immediately_after(e: &PppoeError) -> bool {
    matches!(e, PppoeError::PadtReceived | PppoeError::PeerTerminated | PppoeError::EchoFailed(_))
}

/// RFC 1661 §6.4: an Echo-Reply whose Magic-Number equals our own indicates
/// a looped link. Returns `true` when the reply is such a loop indication.
fn echo_reply_has_own_magic(ppp: &PointToPoint, own_magic: u32) -> bool {
    ppp.payload.len() >= 4
        && u32::from_be_bytes([ppp.payload[0], ppp.payload[1], ppp.payload[2], ppp.payload[3]])
            == own_magic
}

/// Answer an LCP Config-Request received while Established (RFC 1661
/// renegotiation): Ack when every recognized option matches the values we
/// negotiated; Nak recognized options that differ, suggesting the
/// established values; Reject unrecognized or malformed options outright
/// (RFC 1661 §5.4 — a Reject takes precedence over a Nak).
///
/// Known limitation: `PPPOption::from_bytes` stops at a truncated option at
/// the end of the payload, so trailing garbage beyond the last parseable
/// option is ignored.
async fn handle_lcp_renegotiation_request(
    config: &PPPoEClientConfig,
    lcp: &super::lcp::LcpPhaseResult,
    nak_loops: &mut u8,
    ppp: &PointToPoint,
    tx: &mut tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<(), PppoeError> {
    // pppd-aligned loop avoidance (RFC 1661 §4.5): once MAX_NAK_LOOPS
    // consecutive Naks went unanswered, disagreeing options are escalated
    // to Configure-Reject (pppd's `reject_if_disagree`) so a renegotiation
    // that never converges cannot ping-pong forever. The counter resets on
    // every Ack.
    let reject_if_disagree = *nak_loops >= MAX_NAK_LOOPS;

    let mut nak_options: Vec<u8> = Vec::new();
    let mut reject_options: Vec<u8> = Vec::new();
    for op in PPPOption::from_bytes(&ppp.payload) {
        match op.t {
            // Known options with an illegal length are malformed and are
            // refused like unrecognized ones. The auth option is only
            // malformed when it cannot even carry the protocol (pppd
            // lcp.c:1594-1603 rejects `cilen < CILEN_SHORT` only); CHAP
            // additionally requires its algorithm byte (RFC 1994 §4.1,
            // read by pppd at lcp.c:1647).
            OPT_MRU if op.data.len() != 2 => reject_options.extend(op.convert_to_payload()),
            OPT_AUTH if op.data.len() < 2 => reject_options.extend(op.convert_to_payload()),
            OPT_AUTH
                if u16::from_be_bytes([op.data[0], op.data[1]]) == AUTH_PROTO_CHAP
                    && op.data.len() < 3 =>
            {
                reject_options.extend(op.convert_to_payload())
            }
            OPT_MAGIC if op.data.len() != 4 => reject_options.extend(op.convert_to_payload()),
            OPT_MRU => {
                let mru = u16::from_be_bytes([op.data[0], op.data[1]]);
                if mru != lcp.peer_mru {
                    if reject_if_disagree {
                        reject_options.extend(op.convert_to_payload());
                    } else {
                        nak_options.extend([OPT_MRU, 4]);
                        nak_options.extend(lcp.peer_mru.to_be_bytes());
                    }
                }
            }
            // pppd semantics (lcp.c:1618-1663): a well-formed request for
            // the established auth is Acked. A mid-session change of the
            // protocol — or, for CHAP, of the algorithm — cannot be
            // honored (authentication already ran), so it is Naked with
            // the established values. CHAP is suggested in its 5-byte
            // form including the algorithm (pppd's `CILEN_CHAP`),
            // falling back to MD5 when the established option omitted it.
            OPT_AUTH => {
                let auth = u16::from_be_bytes([op.data[0], op.data[1]]);
                let algorithm = op.data.get(2).copied();
                let differs = auth != lcp.auth_type
                    || (auth == AUTH_PROTO_CHAP && algorithm != lcp.auth_algorithm);
                if differs {
                    if reject_if_disagree {
                        reject_options.extend(op.convert_to_payload());
                    } else if lcp.auth_type == AUTH_PROTO_CHAP {
                        nak_options.extend([OPT_AUTH, 5]);
                        nak_options.extend(lcp.auth_type.to_be_bytes());
                        nak_options.push(lcp.auth_algorithm.unwrap_or(CHAP_ALGORITHM_MD5));
                    } else {
                        nak_options.extend([OPT_AUTH, 4]);
                        nak_options.extend(lcp.auth_type.to_be_bytes());
                    }
                }
            }
            // pppd semantics (lcp.c:1727-1749): any peer magic different
            // from our own is fine and must be Acked — the peer picks a
            // fresh random magic on every renegotiation. Only a magic
            // equal to ours means the link is looped (RFC 1661 §6.4) and
            // is Naked with a different suggestion. Magic is exempt from
            // the reject_if_disagree escalation (lcp.c:1824-1826).
            OPT_MAGIC => {
                let magic = u32::from_be_bytes([op.data[0], op.data[1], op.data[2], op.data[3]]);
                if magic == lcp.magic_number {
                    // The `| 1` keeps the suggestion non-zero: a zero
                    // Magic-Number means the option is not negotiated.
                    nak_options.extend([OPT_MAGIC, 6]);
                    nak_options.extend((!lcp.magic_number | 1).to_be_bytes());
                }
            }
            // Unrecognized options must be refused (RFC 1661 §5.4).
            _ => reject_options.extend(op.convert_to_payload()),
        }
    }

    let reply = if !reject_options.is_empty() {
        tracing::warn!(
            iface = %config.iface_name,
            "refusing peer LCP renegotiation options (unrecognized/malformed or Nak cap reached)"
        );
        ppp.gen_reject(reject_options)
    } else if nak_options.is_empty() {
        tracing::info!(
            iface = %config.iface_name,
            "acknowledged peer LCP renegotiation request"
        );
        *nak_loops = 0;
        ppp.gen_ack()
    } else {
        tracing::warn!(
            iface = %config.iface_name,
            "peer LCP renegotiation differs from established config, sending Nak"
        );
        *nak_loops = nak_loops.saturating_add(1);
        ppp.gen_nak(nak_options)
    };
    send_pppoe_session_frame(&lcp.server_mac, config.iface_mac, lcp.session_id, reply, tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goodbye_terminate_is_not_sent_after_peer_initiated_teardown() {
        assert!(!should_send_terminate(&PppoeError::PadtReceived));
        assert!(!should_send_terminate(&PppoeError::PeerTerminated));
    }

    #[test]
    fn goodbye_terminate_is_sent_for_other_negotiation_failures() {
        assert!(should_send_terminate(&PppoeError::ServiceStopped));
        assert!(should_send_terminate(&PppoeError::LcpTimeout));
        assert!(should_send_terminate(&PppoeError::EchoFailed(6)));
        assert!(should_send_terminate(&PppoeError::ChannelClosed));
        assert!(should_send_terminate(&PppoeError::Ipv6cpRejected));
        assert!(should_send_terminate(&PppoeError::SendError("x".into())));
    }

    #[test]
    fn goodbye_padt_is_sent_after_lcp_termination_but_not_after_padt() {
        // pppd sends PADT on every teardown path; only a received PADT has
        // already closed the PPPoE session.
        assert!(should_send_padt(&PppoeError::PeerTerminated));
        assert!(!should_send_padt(&PppoeError::PadtReceived));
        assert!(should_send_padt(&PppoeError::EchoFailed(6)));
        assert!(should_send_padt(&PppoeError::ChannelClosed));
    }

    #[test]
    fn session_drops_skip_the_first_backoff() {
        assert!(redial_immediately_after(&PppoeError::PadtReceived));
        assert!(redial_immediately_after(&PppoeError::PeerTerminated));
        assert!(redial_immediately_after(&PppoeError::EchoFailed(6)));
    }

    #[test]
    fn dial_failures_keep_the_backoff() {
        assert!(!redial_immediately_after(&PppoeError::LcpTimeout));
        assert!(!redial_immediately_after(&PppoeError::DiscoveryTimeout));
        assert!(!redial_immediately_after(&PppoeError::DiscoveryRejected("x".into())));
        assert!(!redial_immediately_after(&PppoeError::AuthFailed("x".into())));
        assert!(!redial_immediately_after(&PppoeError::ChannelClosed));
    }
}
