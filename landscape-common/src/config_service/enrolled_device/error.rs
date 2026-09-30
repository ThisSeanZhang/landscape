use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum EnrolledDeviceError {
    #[error("Invalid enrolled device data: {0}")]
    #[api_error(id = "enrolled_device.invalid", status = 400)]
    InvalidData(String),
}
