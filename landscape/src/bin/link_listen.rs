use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::nsid::NsidAttribute;
use netlink_packet_route::nsid::NsidHeader;
use netlink_packet_route::nsid::NsidMessage;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{constants::RTMGRP_LINK, new_connection, Handle};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Open the netlink socket

    // // Listen for link changes

    // dump_addresses(&handle, "ens3".to_string()).await;

    // dump_addresses(&handle, "ens5".to_string()).await;
    // dump_addresses(&handle, "ens4".to_string()).await;
    // flush_addresses(handle, "veth-host".to_string()).await;
    Ok(())
}

#[allow(dead_code)]
async fn lookup_nsid() -> Result<(), String> {
    let (_, mut handle, _) = new_connection().map_err(|e| format!("{e}"))?;

    let mut nsid_msg = NsidMessage::default();
    nsid_msg.header = NsidHeader { family: AddressFamily::Netlink };
    nsid_msg.attributes = vec![
        NsidAttribute::Id(-1),
        NsidAttribute::Pid(0),
        NsidAttribute::Fd(4026532359),
        NsidAttribute::TargetNsid(-1),
        NsidAttribute::CurrentNsid(-1),
    ];
    let message = RouteNetlinkMessage::GetNsId(nsid_msg);
    let mut req = NetlinkMessage::from(message);
    req.header.flags = netlink_packet_core::NLM_F_REQUEST | netlink_packet_core::NLM_F_ACK;
    // req.header.sequence_number = 1;
    req.finalize();

    println!("{:#?}", req);
    match handle.request(req) {
        Ok(mut response) => {
            //
            while let Some(msg) = response.next().await {
                println!("{:#?}", msg);
            }
        }
        Err(_) => todo!(),
    }

    Ok(())
}

#[allow(dead_code)]
async fn observer_listen() -> Result<(), String> {
    let (mut connection, _, mut messages) = new_connection().map_err(|e| format!("{e}"))?;

    let mgroup_flags = RTMGRP_LINK
        | rtnetlink::constants::RTMGRP_IPV4_IFADDR
        | rtnetlink::constants::RTMGRP_IPV4_ROUTE
        | rtnetlink::constants::RTMGRP_IPV6_IFADDR
        | rtnetlink::constants::RTMGRP_IPV6_ROUTE;

    let addr = SocketAddr::new(0, mgroup_flags);
    connection.socket_mut().socket_mut().bind(&addr).expect("failed to bind");
    tokio::spawn(connection);

    while let Some((message, _)) = messages.next().await {
        // println!("Route change message - {message:?}");
        let result = landscape::observer::filter_message_status(message);
        println!("result - {result:?}");
        // match message.payload {
        //     NetlinkPayload::InnerMessage(inner_message) => {
        //         // 处理 InnerMessage
        //         println!("Received Inner message: {:?}", inner_message);
        //     }
        //     _ => todo!(),
        // }
    }

    Ok(())
}

#[allow(dead_code)]
async fn flush_addresses(handle: &Handle, link: String) -> () {
    let mut links = handle.link().get().match_name(link.clone()).execute();
    if let Some(link) = links.try_next().await.unwrap() {
        // We should have received only one message
        assert!(links.try_next().await.unwrap().is_none());

        let mut addresses =
            handle.address().get().set_link_index_filter(link.header.index).execute();
        while let Some(addr) = addresses.try_next().await.unwrap() {
            handle.address().del(addr).execute().await.unwrap();
        }
        ()
    } else {
        eprintln!("link {link} not found");
        ()
    }
}

#[allow(dead_code)]
async fn dump_addresses(handle: &Handle, link: String) {
    println!("dumping address for link \"{link}\"");
    let mut links = handle.link().get().match_name(link.clone()).execute();
    if let Some(link) = links.try_next().await.unwrap() {
        let mut addresses =
            handle.address().get().set_link_index_filter(link.header.index).execute();
        while let Some(msg) = addresses.try_next().await.unwrap() {
            println!("{msg:?}");
        }
    } else {
        eprintln!("link {link} not found");
    }
}
