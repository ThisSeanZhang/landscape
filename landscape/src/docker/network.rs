use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use bollard::{
    query_parameters::ListNetworksOptions,
    secret::{Ipam, Network, NetworkContainer},
    Docker,
};
use landscape_common::{
    docker::{
        network::{LandscapeDockerIpInfo, LandscapeDockerNetwork, LandscapeDockerNetworkContainer},
        DOCKER_NETWORK_BRIDGE_NAME_OPTION_KEY,
    },
    net::MacAddr,
};

pub async fn inspect_all_networks(
    docker: &Docker,
) -> Result<Vec<LandscapeDockerNetwork>, bollard::errors::Error> {
    let query: Option<ListNetworksOptions> = None;
    let networks = docker.list_networks(query).await?;

    let mut result = Vec::with_capacity(networks.len());
    for networks in networks {
        if let Some(net) = convert_network(networks) {
            result.push(net);
        }
    }

    Ok(result)
}

pub fn convert_network(net: Network) -> Option<LandscapeDockerNetwork> {
    match (net.name, net.id) {
        (Some(name), Some(id)) => {
            //
            let mut containers = HashMap::new();
            if let Some(old_containers) = net.containers {
                for (key, value) in old_containers.into_iter() {
                    if let Some(container) = convert_container(value) {
                        containers.insert(key, container);
                    }
                }
            }

            let options = net.options.unwrap_or_default();

            let iface_name = if let Some(name) = options.get(DOCKER_NETWORK_BRIDGE_NAME_OPTION_KEY)
            {
                name.to_string()
            } else {
                format!("br-{}", id.get(..12).unwrap_or(&id))
            };

            let ip_info = net.ipam.map(convert_ipam).flatten();

            Some(LandscapeDockerNetwork {
                name,
                iface_name,
                id,
                containers,
                options,
                driver: net.driver,
                ip_info,
            })
        }
        _ => None,
    }
}

fn convert_container(container: NetworkContainer) -> Option<LandscapeDockerNetworkContainer> {
    if let Some(container_name) = container.name {
        let mac = container.mac_address.and_then(|mac_str| MacAddr::from_str(&mac_str));
        Some(LandscapeDockerNetworkContainer { name: container_name, mac })
    } else {
        None
    }
}

fn convert_ipam(ipam: Ipam) -> Option<LandscapeDockerIpInfo> {
    let Some(config) = ipam.config.as_ref().map(|c| c.get(0)).flatten() else {
        return None;
    };

    let Some(subnet) = config.subnet.as_ref() else {
        return None;
    };
    let Ok(subnet) = cidr::Ipv4Inet::from_str(subnet) else {
        return None;
    };

    Some(LandscapeDockerIpInfo {
        subnet_ip: IpAddr::V4(subnet.address()),
        prefix: subnet.network_length(),
        gateway: IpAddr::V4(
            config
                .gateway
                .as_ref()
                .and_then(|gw| gw.parse::<Ipv4Addr>().ok())
                .unwrap_or_else(|| subnet.overflowing_add_u32(1).0.address()),
        ),
    })
}
