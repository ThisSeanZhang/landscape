use std::time::Duration;

use landscape::{dhcp_client::v6::dhcp_v6_pd_client, macaddr::MacAddr};
use landscape_common::{
    service::{DefaultServiceStatus, DefaultWatchServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use tracing::Level;

// cargo run --package landscape --bin dhcp_v6_test
// dhclient -6 -d -v -1 -P -lf /dev/null ens6
#[tokio::main]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    let mac_addr = MacAddr::new(00, 0xa0, 0x98, 0x39, 0x32, 0xf0);

    let service_status = DefaultWatchServiceStatus::new();
    let status = service_status.clone();
    tokio::spawn(async move {
        dhcp_v6_pd_client("ens6".into(), mac_addr, LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT, status)
            .await;
    });

    tokio::time::sleep(Duration::from_secs(30)).await;

    let timeout_timer = tokio::time::sleep(tokio::time::Duration::from_secs(10000));
    timeout_timer.await;
    service_status.send_replace(DefaultServiceStatus::Stopping);

    let _ = service_status
        .subscribe()
        .wait_for(|s| matches!(s, DefaultServiceStatus::Stop { .. }))
        .await;
}
