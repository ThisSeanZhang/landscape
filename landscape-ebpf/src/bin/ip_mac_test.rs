use tokio_util::sync::CancellationToken;

// cargo run --package landscape-ebpf --bin ip_mac_test
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let done = tokio::spawn(async move {
        if let Err(e) = landscape_ebpf::base::ip_mac::neigh_update(cancel_clone).await {
            tracing::warn!("neigh_update test exited with error: {e}");
        }
    });

    let _ = tokio::signal::ctrl_c().await;

    cancel.cancel();
    let _ = done.await;
}
