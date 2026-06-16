use crate::LdApiError;

#[derive(Debug, thiserror::Error, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DockerError {
    #[error("Docker client not available")]
    #[api_error(id = "docker.client_unavailable", status = 503)]
    DockerClientNotAvailable,

    #[error("Create container error")]
    #[api_error(id = "docker.create_failed", status = 500)]
    CreateContainerError,

    #[error("Start container error")]
    #[api_error(id = "docker.start_failed", status = 500)]
    StartContainerError,

    #[error("Stop container error")]
    #[api_error(id = "docker.stop_failed", status = 500)]
    StopContainerError,

    #[error("Remove container error")]
    #[api_error(id = "docker.remove_failed", status = 500)]
    FailToRemoveContainer,

    #[error("Run container by cmd error")]
    #[api_error(id = "docker.run_cmd_failed", status = 500)]
    FailToRunContainerByCmd,

    #[error("List containers error")]
    #[api_error(id = "docker.list_containers_failed", status = 500)]
    ListContainersError,

    #[error("List images error")]
    #[api_error(id = "docker.list_images_failed", status = 500)]
    ListImagesError,

    #[error("List networks error")]
    #[api_error(id = "docker.list_networks_failed", status = 500)]
    ListNetworksError,

    #[error("Delete image error")]
    #[api_error(id = "docker.delete_image_failed", status = 500)]
    DeleteImageError,
}
