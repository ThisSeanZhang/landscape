use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::wan_link::{GatewayArpTarget, GatewayNsTarget};
use landscape_ebpf::chain::wan_link::WanLinkDataplane;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::arp::{probe_gateway_mac, probe_gateway_mac6};

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub(super) async fn run(dataplane: Arc<WanLinkDataplane>, stop: CancellationToken) {
    let arp = {
        let dataplane = dataplane.clone();
        run_probes(
            dataplane.subscribe_gateway_arp(),
            |target: GatewayArpTarget| {
                probe_gateway_mac(
                    target.ifindex,
                    target.local_mac,
                    target.local_ip,
                    target.gateway_ip,
                    PROBE_TIMEOUT,
                )
            },
            move |target: &Arc<GatewayArpTarget>, mac| {
                if dataplane.confirm_gateway_mac(target, mac) {
                    tracing::info!(chain = dataplane.id(), ifindex = target.ifindex, gateway = %target.gateway_ip, %mac, "confirmed WAN gateway MAC");
                }
            },
        )
    };
    let ns = {
        let dataplane = dataplane.clone();
        run_probes(
            dataplane.subscribe_gateway_ns(),
            |target: GatewayNsTarget| {
                probe_gateway_mac6(
                    target.ifindex,
                    target.local_mac,
                    target.gateway_ip,
                    PROBE_TIMEOUT,
                )
            },
            move |target: &Arc<GatewayNsTarget>, mac| {
                if dataplane.confirm_gateway_mac6(target, mac) {
                    tracing::info!(chain = dataplane.id(), ifindex = target.ifindex, gateway = %target.gateway_ip, %mac, "confirmed WAN gateway MAC over NS");
                }
            },
        )
    };
    tokio::select! {
        biased;
        _ = stop.cancelled() => {},
        _ = arp => {},
        _ = ns => {},
    }
    dataplane.clear_gateway_arp();
}

async fn run_probes<T, F: Future<Output = io::Result<Option<MacAddr>>>>(
    mut targets: watch::Receiver<Option<Arc<T>>>,
    probe: impl Fn(T) -> F,
    confirm: impl Fn(&Arc<T>, MacAddr),
) where
    T: Copy + Send + Sync + std::fmt::Debug + 'static,
{
    loop {
        let target = targets.wait_for(Option::is_some).await.ok().and_then(|t| t.clone());
        let Some(target) = target else { return };
        let maintain = async {
            loop {
                let delay = match probe(*target).await {
                    Ok(Some(mac)) => {
                        confirm(&target, mac);
                        REFRESH_INTERVAL
                    }
                    Ok(None) => RETRY_INTERVAL,
                    Err(err) => {
                        tracing::debug!(target = ?*target, %err, "WAN gateway probe failed");
                        RETRY_INTERVAL
                    }
                };
                tokio::time::sleep(delay).await;
            }
        };
        // A new binding interrupts both the socket wait and the refresh timer.
        tokio::select! {
            biased;
            changed = targets.changed() => if changed.is_err() { return; },
            _ = maintain => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::Instant;

    #[tokio::test(start_paused = true)]
    async fn probes_on_bind_refreshes_retries_and_cancels_on_rebind() {
        let (bindings, targets) = watch::channel(None);
        let (requests, mut attempts) = mpsc::unbounded_channel();
        let (confirmed, mut confirmations) = mpsc::unbounded_channel();
        let probe = move |target| {
            let (reply, result) = oneshot::channel();
            requests.send((Instant::now(), target, reply)).unwrap();
            async move { result.await.unwrap() }
        };
        let worker = tokio::spawn(run_probes(targets, probe, move |target, mac| {
            confirmed.send((**target, mac)).unwrap();
        }));
        tokio::task::yield_now().await;
        assert!(attempts.try_recv().is_err());

        let first = GatewayArpTarget {
            ifindex: 7,
            local_mac: MacAddr(2, 0, 0, 0, 0, 7),
            local_ip: Ipv4Addr::new(192, 0, 2, 10),
            gateway_ip: Ipv4Addr::new(192, 0, 2, 1),
        };
        let start = Instant::now();
        bindings.send_replace(Some(Arc::new(first)));
        let (at, target, reply) = attempts.recv().await.unwrap();
        assert_eq!((at, target), (start, first));
        let peer = MacAddr(2, 1, 2, 3, 4, 5);
        reply.send(Ok(Some(peer))).unwrap();
        assert_eq!(confirmations.recv().await, Some((first, peer)));

        let (refresh, _, reply) = attempts.recv().await.unwrap();
        assert_eq!(refresh - start, REFRESH_INTERVAL);
        reply.send(Ok(None)).unwrap();
        let (retry, _, reply) = attempts.recv().await.unwrap();
        assert_eq!(retry - refresh, RETRY_INTERVAL);
        reply.send(Err(io::Error::other("interface unavailable"))).unwrap();
        let (again, _, old_reply) = attempts.recv().await.unwrap();
        assert_eq!(again - retry, RETRY_INTERVAL);
        assert!(confirmations.try_recv().is_err());

        let next = GatewayArpTarget { gateway_ip: Ipv4Addr::new(192, 0, 2, 2), ..first };
        bindings.send_replace(Some(Arc::new(next)));
        let (at, target, reply) = attempts.recv().await.unwrap();
        assert_eq!((at, target), (again, next));
        assert!(old_reply.send(Ok(Some(peer))).is_err());
        reply.send(Ok(Some(peer))).unwrap();
        assert_eq!(confirmations.recv().await, Some((next, peer)));

        bindings.send_replace(None);
        tokio::time::advance(REFRESH_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(attempts.try_recv().is_err());
        drop(bindings);
        worker.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn ns_worker_probes_refreshes_and_confirms_like_arp() {
        let (bindings, targets) = watch::channel(None);
        let (requests, mut attempts) = mpsc::unbounded_channel();
        let (confirmed, mut confirmations) = mpsc::unbounded_channel();
        let probe = move |target| {
            let (reply, result) = oneshot::channel();
            requests.send((Instant::now(), target, reply)).unwrap();
            async move { result.await.unwrap() }
        };
        let worker = tokio::spawn(run_probes(targets, probe, move |target, mac| {
            confirmed.send((**target, mac)).unwrap();
        }));
        tokio::task::yield_now().await;
        assert!(attempts.try_recv().is_err());

        let first = GatewayNsTarget {
            ifindex: 7,
            local_mac: MacAddr(2, 0, 0, 0, 0, 7),
            gateway_ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        };
        let start = Instant::now();
        bindings.send_replace(Some(Arc::new(first)));
        let (at, target, reply) = attempts.recv().await.unwrap();
        assert_eq!((at, target), (start, first));
        let peer = MacAddr(2, 1, 2, 3, 4, 5);
        reply.send(Ok(Some(peer))).unwrap();
        assert_eq!(confirmations.recv().await, Some((first, peer)));

        let (refresh, _, reply) = attempts.recv().await.unwrap();
        assert_eq!(refresh - start, REFRESH_INTERVAL);
        reply.send(Ok(None)).unwrap();
        let (retry, _, reply) = attempts.recv().await.unwrap();
        assert_eq!(retry - refresh, RETRY_INTERVAL);
        reply.send(Ok(Some(peer))).unwrap();
        assert_eq!(confirmations.recv().await, Some((first, peer)));

        drop(bindings);
        worker.await.unwrap();
    }
}
