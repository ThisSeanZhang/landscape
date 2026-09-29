use futures::stream::TryStreamExt;
use landscape_common::dev::LandscapeInterface;
use rtnetlink::Handle;

use super::convert::parse_link_message;
use super::handle::create_handle;

pub async fn get_iface_by_name(name: &str) -> Option<LandscapeInterface> {
    let handle = create_handle().ok()?;
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Ok(Some(msg)) = links.try_next().await { parse_link_message(msg) } else { None }
}

pub async fn get_iface_by_name_with_handle(
    handle: &Handle,
    name: &str,
) -> Option<LandscapeInterface> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Ok(Some(msg)) = links.try_next().await { parse_link_message(msg) } else { None }
}

pub async fn get_all_devices() -> Vec<LandscapeInterface> {
    let handle = match create_handle() {
        Ok(h) => h,
        Err(_) => return vec![],
    };
    let mut links = handle.link().get().execute();
    let mut result = vec![];
    while let Some(msg) = links.try_next().await.unwrap() {
        if let Some(data) = parse_link_message(msg) {
            if data.is_lo() {
                continue;
            }
            result.push(data);
        }
    }
    result
}

pub async fn create_bridge(name: String) -> bool {
    use rtnetlink::LinkBridge;

    let handle = match create_handle() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let create_result = handle.link().add(LinkBridge::new(&name).build()).execute().await;
    create_result.is_ok()
}

pub async fn delete_bridge(name: String) -> bool {
    let handle = match create_handle() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut result = handle.link().get().match_name(name).execute();
    loop {
        match result.try_next().await {
            Ok(link) => match link {
                Some(link) => {
                    let del_result = handle.link().del(link.header.index).execute().await;
                    if del_result.is_ok() {
                        return true;
                    }
                }
                None => {
                    return false;
                }
            },
            Err(e) => {
                tracing::error!("delete bridge error: {e:?}");
                return false;
            }
        }
    }
}

/// Attach the link to a bridge (its controller).
/// This is equivalent to ip link set LINK master BRIDGE.
/// To succeed, both the bridge and the link that is being attached must be UP.
pub async fn set_controller(
    link_name: &str,
    master_index: Option<u32>,
) -> Option<LandscapeInterface> {
    if let Some(dev) = get_iface_by_name(link_name).await {
        use netlink_packet_route::link::{LinkAttribute, LinkMessage};

        let handle = create_handle().ok()?;
        let mut msg = LinkMessage::default();
        msg.header.index = dev.index;
        msg.attributes = vec![LinkAttribute::Controller(master_index.unwrap_or(0))];

        let create_result = handle.link().change(msg).execute().await;
        if create_result.is_ok() { Some(dev) } else { None }
    } else {
        None
    }
}

pub async fn change_dev_status(iface_name: &str, up: bool) -> Option<LandscapeInterface> {
    if let Some(dev) = get_iface_by_name(iface_name).await {
        let status = if up { "up" } else { "down" };
        let result =
            std::process::Command::new("ip").args(["link", "set", iface_name, status]).output();
        if result.is_ok() { Some(dev) } else { None }
    } else {
        None
    }
}
