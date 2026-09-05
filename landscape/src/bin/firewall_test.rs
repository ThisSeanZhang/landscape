use clap::Parser;
use landscape::get_iface_by_name;
use landscape_ebpf::runtime::EbpfRuntime;
use std::sync::Arc;

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

    let rt = Arc::new(EbpfRuntime::init("firewall_test", None).expect("init ebpf maps"));
    let firewall = if let Some(iface) = get_iface_by_name(&args.iface_name).await {
        println!("Starting firewall on ifindex: {:?}", iface.index);
        match rt.firewall().attach(iface.index, iface.mac.is_some()) {
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
