use landscape_common::LdApiError;

#[derive(Debug, thiserror::Error, LdApiError)]
pub enum DockerError {
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
}
