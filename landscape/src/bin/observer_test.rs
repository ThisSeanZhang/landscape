use tracing::Level;

use landscape::observer::ip_observer;

// cargo run --package landscape --bin observer_test
#[tokio::main]
async fn main() -> Result<(), String> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    ip_observer().await;

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    Ok(())
}
