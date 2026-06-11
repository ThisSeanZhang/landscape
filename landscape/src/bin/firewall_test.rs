use clap::Parser;
use landscape::iface::get_iface_by_name;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "veth0")]
    pub iface_name: String,
}

// cargo run --package landscape --bin firewall_test
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let firewall = if let Some(iface) = get_iface_by_name(&args.iface_name).await {
        println!("Starting firewall on ifindex: {:?}", iface.index);
        match landscape_ebpf::stages::firewall::init_firewall(
            iface.index as u32,
            iface.mac.is_some(),
        ) {
            Ok(handle) => Some(handle),
            Err(err) => {
                tracing::debug!("error: {err:?}");
                None
            }
        }
    } else {
        None
    };

    let _ = tokio::signal::ctrl_c().await;

    drop(firewall);
}
