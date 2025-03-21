use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use landscape::iface::get_iface_by_name;
use landscape_common::{
    firewall::{FirewallRuleItem, FirewallRuleMark},
    mark::PacketMark,
    network::LandscapeIpProtocolCode,
};
use landscape_ebpf::map_setting::add_firewall_rule;
use tokio::{sync::oneshot, time::sleep};
use tracing::Level;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "veth0")]
    pub iface_name: String,
}

// cargo run --package landscape --bin firewall_test
#[tokio::main]
pub async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    landscape_ebpf::setting_libbpf_log();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    add_firewall_rule(get_allow_icmp_echo());
    if let Some(iface) = get_iface_by_name(&args.iface_name).await {
        std::thread::spawn(move || {
            println!("启动 firewall 在 ifindex: {:?}", iface.index);
            if let Err(e) =
                landscape_ebpf::firewall::new_firewall(iface.index as i32, iface.mac.is_some(), rx)
            {
                tracing::debug!("error: {e:?}");
            }
            println!("向外部线程发送解除阻塞信号");
            let _ = other_tx.send(());
        });
    } else {
        let _ = other_tx.send(());
    }

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0)).await;
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}

fn get_allow_icmp_echo() -> Vec<FirewallRuleMark> {
    vec![
        FirewallRuleMark {
            item: FirewallRuleItem {
                ip_protocol: Some(LandscapeIpProtocolCode::ICMPV6),
                local_port: Some(128),
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ip_prefixlen: 0,
            },
            mark: PacketMark::default(),
        },
        FirewallRuleMark {
            item: FirewallRuleItem {
                ip_protocol: Some(LandscapeIpProtocolCode::ICMPV6),
                local_port: Some(129),
                address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ip_prefixlen: 0,
            },
            mark: PacketMark::default(),
        },
        FirewallRuleMark {
            item: FirewallRuleItem {
                ip_protocol: Some(LandscapeIpProtocolCode::ICMP),
                local_port: Some(0),
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ip_prefixlen: 0,
            },
            mark: PacketMark::default(),
        },
        FirewallRuleMark {
            item: FirewallRuleItem {
                ip_protocol: Some(LandscapeIpProtocolCode::ICMP),
                local_port: Some(8),
                address: IpAddr::V4(Ipv4Addr::BROADCAST),
                ip_prefixlen: 0,
            },
            mark: PacketMark::default(),
        },
    ]
}
