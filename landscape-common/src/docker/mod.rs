use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{NAMESPACE_REGISTER_SOCK_PATH, NAMESPACE_REGISTER_SOCK_PATH_IN_DOCKER};

pub mod image;
/// This file is to prepare for the future migration
/// of the docker api library to avoid large-scale modification of the API
///
///
pub mod network;

pub const DOCKER_NETWORK_BRIDGE_NAME_OPTION_KEY: &str = "com.docker.network.bridge.name";

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DockerTargetEnroll {
    pub id: String,
    pub ifindex: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DockerCmd {
    pub image_name: String,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub restart: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub restart_max_retries: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub container_name: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub ports: Option<Vec<KeyValuePair>>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub environment: Option<Vec<KeyValuePair>>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub volumes: Option<Vec<KeyValuePair>>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub labels: Option<Vec<KeyValuePair>>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub entrypoint: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub params: Option<String>,
}

impl DockerCmd {
    // 生成 Docker 命令
    pub fn generate_docker_command(&self, home_path: &PathBuf) -> Vec<String> {
        let mut command = vec!["docker".to_string(), "run".to_string(), "-d".to_string()];

        if let Some(container_name) = &self.container_name {
            command.push("--name".to_string());
            command.push(container_name.clone());
        }
        if let Some(restart) = &self.restart {
            command.push("--restart".to_string());
            let restart_str = if restart == "on-failure:<max-retries>" {
                format!("on-failure:{}", self.restart_max_retries.unwrap_or(3))
            } else {
                restart.clone()
            };
            command.push(restart_str);
        }
        if let Some(ports) = &self.ports {
            for port in ports {
                command.push("-p".to_string());
                command.push(port.separator(":"));
            }
        }

        if let Some(environments) = &self.environment {
            for environment in environments {
                command.push("-e".to_string());
                command.push(environment.separator("="));
            }
        }

        if let Some(volumes) = &self.volumes {
            for volume in volumes {
                command.push("-v".to_string());
                command.push(volume.separator(":"));
            }
        }

        if let Some(entrypoint) = &self.entrypoint {
            command.push("--entrypoint".to_string());
            command.push(entrypoint.clone());
        }

        let mut accept_local = false;
        if let Some(labels) = &self.labels {
            for label in labels {
                if label.key == "ld_flow_edge" {
                    accept_local = true;
                }
                command.push("--label".to_string());
                command.push(label.separator("="));
            }
        }

        if accept_local {
            command.push("--sysctl".to_string());
            command.push("net.ipv4.conf.lo.accept_local=1".to_string());
            command.push("--cap-add=NET_ADMIN".to_string());
            command.push("--cap-add=BPF".to_string());
            command.push("--cap-add=PERFMON".to_string());
            command.push("--volume".to_string());
            // /root/.landscape-router/unix_link/:/ld_unix_link/
            let mapping_volume = format!(
                "{}/:/{}/:ro",
                home_path.join(NAMESPACE_REGISTER_SOCK_PATH).display(),
                NAMESPACE_REGISTER_SOCK_PATH_IN_DOCKER
            );
            command.push(mapping_volume);
        }

        command.push(self.image_name.clone());

        if let Some(params) = &self.params {
            command.push(params.clone());
        }

        tracing::info!("command: {:?}", command);
        command
    }

    // 执行 Docker 命令
    pub async fn execute_docker_command(&self, home_path: &PathBuf) -> Result<(), ()> {
        let command = self.generate_docker_command(home_path);
        if let Ok(status) =
            tokio::process::Command::new(&command[0]).args(&command[1..]).status().await
        {
            if status.success() {
                tracing::info!("Docker command executed successfully.");
            } else {
                tracing::error!("Docker command failed with status: {:?}", status);
                return Err(());
            }
        } else {
            return Err(());
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

impl KeyValuePair {
    pub fn separator(&self, separator: &str) -> String {
        format!("{}{separator}{}", self.key, self.value)
    }
}
