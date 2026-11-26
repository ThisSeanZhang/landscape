/// Shared conversion contract for system configuration sections.
///
/// Startup uses `build_runtime` to repair invalid input according to each module's policy.
/// Online updates use `to_runtime` to reject invalid input before persistence.
pub trait RuntimeConfigSource {
    type Runtime;
    type Error: std::error::Error;

    fn validate(&self) -> Result<(), Self::Error>;

    /// Fill omitted values and repair invalid input by clamping, defaulting or disabling,
    /// according to the module policy. Log each repair.
    /// Must use the same field rules as `validate` and leave the source unchanged.
    fn build_runtime(&self) -> Self::Runtime;

    fn to_runtime(&self) -> Result<Self::Runtime, Self::Error> {
        self.validate()?;
        Ok(self.build_runtime())
    }
}

pub(super) fn warn_repair(
    section: &str,
    field: &str,
    error: impl std::fmt::Display,
    action: &str,
    effective: impl std::fmt::Display,
) {
    tracing::warn!(section, field, %error, action, %effective, "configuration repaired");
    // Startup constructs runtime config before initializing its logging subscriber.
    if !tracing::dispatcher::has_been_set() {
        eprintln!("invalid {section}.{field}: {error}; {action}; effective={effective}");
    }
}

pub(super) fn repair_on_error<T: std::fmt::Display, E: std::fmt::Display>(
    section: &str,
    field: &str,
    value: Result<T, E>,
    repaired: T,
    action: &str,
) -> T {
    value.unwrap_or_else(|error| {
        warn_repair(section, field, error, action, &repaired);
        repaired
    })
}
