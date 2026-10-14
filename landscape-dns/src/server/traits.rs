pub trait DohAdvertiseProvider: Send + Sync {
    fn advertise_domains(&self) -> Vec<String>;
}

impl DohAdvertiseProvider for landscape_core::cert::SharedSniResolver {
    fn advertise_domains(&self) -> Vec<String> {
        self.advertised_domains()
    }
}
