use std::collections::HashMap;

use bollard::{
    secret::{Network, NetworkContainer},
    Docker,
};
use landscape_common::{
    docker::{
        network::{LandscapeDockerNetwork, LandscapeDockerNetworkContainer},
        DOCKER_NETWORK_BRIDGE_NAME_OPTION_KEY,
    },
    net::MacAddr,
};

pub async fn inspect_all_networks() -> Vec<LandscapeDockerNetwork> {
    let docker = Docker::connect_with_socket_defaults();
    let docker = docker.unwrap();

    let networks = docker.list_networks::<String>(None).await.unwrap();

    let mut result = Vec::with_capacity(networks.len());
    for networks in networks {
        if let Some(net) = convert_network(networks) {
            result.push(net);
        }
    }

    result
}

fn convert_network(net: Network) -> Option<LandscapeDockerNetwork> {
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

            Some(LandscapeDockerNetwork {
                name,
                iface_name,
                id,
                containers,
                options,
                driver: net.driver,
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
