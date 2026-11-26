use std::borrow::Cow;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use super::config::LandscapeTimeConfig;
use crate::sys_config::{RuntimeConfigSource, runtime::warn_repair};
use crate::{
    DEFAULT_TIME_ENABLE, DEFAULT_TIME_SAMPLES_PER_SERVER, DEFAULT_TIME_SERVERS,
    DEFAULT_TIME_STEP_THRESHOLD_MS, DEFAULT_TIME_SYNC_INTERVAL_SECS, DEFAULT_TIME_TIMEOUT_SECS,
};

/// Parse a configured NTP host and optional port without resolving it.
pub fn ntp_server_endpoint(server: &str) -> Option<(Cow<'_, str>, u16)> {
    let server = server.trim();
    let (host, port) = match server.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') || host.ends_with(']') => {
            if !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (host, port.parse().ok()?)
        }
        _ => (server, 123),
    };
    let host = match host.strip_prefix('[') {
        Some(literal) => literal.strip_suffix(']').filter(|ip| ip.contains(':'))?,
        None => host,
    };
    if port == 0
        || host.is_empty()
        || host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '[' | ']'))
    {
        return None;
    }
    let host = if host.contains(':') {
        let ip = match host.split_once('%') {
            Some((_, "")) => return None,
            Some((_, interface)) if interface.contains(':') => return None,
            Some((ip, _interface)) => ip,
            None => host,
        };
        ip.parse::<std::net::Ipv6Addr>().ok()?;
        Cow::Borrowed(host)
    } else {
        // Let the resolver see the same validated ASCII labels, including a
        // trailing root dot when the operator requested an absolute name.
        Uts46::new()
            .to_ascii(
                host.as_bytes(),
                AsciiDenyList::STD3,
                Hyphens::CheckFirstLast,
                DnsLength::VerifyAllowRootDot,
            )
            .ok()?
    };
    Some((host, port))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeRuntimeConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub sync_interval_secs: u64,
    pub timeout_secs: u64,
    pub step_threshold_ms: u64,
    pub samples_per_server: u8,
}

impl Default for TimeRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_TIME_ENABLE,
            servers: DEFAULT_TIME_SERVERS.iter().map(|server| (*server).to_string()).collect(),
            sync_interval_secs: DEFAULT_TIME_SYNC_INTERVAL_SECS,
            timeout_secs: DEFAULT_TIME_TIMEOUT_SECS,
            step_threshold_ms: DEFAULT_TIME_STEP_THRESHOLD_MS,
            samples_per_server: DEFAULT_TIME_SAMPLES_PER_SERVER,
        }
    }
}

impl TimeRuntimeConfig {
    /// Defend all service entrypoints, including callers that construct runtime directly.
    pub fn normalized(mut self) -> Self {
        for (field, value) in [
            ("sync_interval_secs", self.sync_interval_secs),
            ("timeout_secs", self.timeout_secs),
            ("samples_per_server", u64::from(self.samples_per_server)),
        ] {
            if value == 0 {
                warn_repair("time", field, "0 must be at least 1", "raised to minimum", 1);
            }
        }
        if self.enabled {
            let count = self.servers.len();
            self.servers.retain(|server| ntp_server_endpoint(server).is_some());
            if !self.servers.is_empty() && count != self.servers.len() {
                warn_repair(
                    "time",
                    "servers",
                    "invalid server address",
                    "keeping usable addresses",
                    self.servers.len(),
                );
            }
            if self.servers.is_empty() {
                warn_repair(
                    "time",
                    "servers",
                    "no usable server addresses",
                    "using defaults",
                    DEFAULT_TIME_SERVERS.len(),
                );
                self.servers =
                    DEFAULT_TIME_SERVERS.iter().map(|server| (*server).to_owned()).collect();
            }
        }
        self.sync_interval_secs = self.sync_interval_secs.max(1);
        self.timeout_secs = self.timeout_secs.max(1);
        self.samples_per_server = self.samples_per_server.max(1);
        self
    }
}

impl RuntimeConfigSource for LandscapeTimeConfig {
    type Runtime = TimeRuntimeConfig;
    type Error = crate::sys_service::time_sync::TimeSyncError;

    fn validate(&self) -> Result<(), Self::Error> {
        if self.enabled.unwrap_or(DEFAULT_TIME_ENABLE)
            && self.servers.as_ref().is_some_and(|servers| {
                servers.is_empty()
                    || servers.iter().any(|server| ntp_server_endpoint(server).is_none())
            })
        {
            return Err(crate::sys_service::time_sync::TimeSyncError::InvalidServers);
        }
        // Zero timing values have historically been normalized to one.
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        let defaults = TimeRuntimeConfig::default();
        TimeRuntimeConfig {
            enabled: self.enabled.unwrap_or(defaults.enabled),
            servers: self.servers.clone().unwrap_or(defaults.servers),
            sync_interval_secs: self.sync_interval_secs.unwrap_or(defaults.sync_interval_secs),
            timeout_secs: self.timeout_secs.unwrap_or(defaults.timeout_secs),
            step_threshold_ms: self.step_threshold_ms.unwrap_or(defaults.step_threshold_ms),
            samples_per_server: self.samples_per_server.unwrap_or(defaults.samples_per_server),
        }
        .normalized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_endpoints_are_rejected_online_and_repaired_individually_at_startup() {
        let long_label = "a".repeat(64);
        let label = "a".repeat(63);
        let long_name = [label.as_str(); 4].join(".");
        for invalid in [
            "host:0",
            "host:65536",
            "host:ntp",
            "host:+123",
            "[::1",
            "bad::ip",
            "ntp://host",
            "ntp..example",
            "ntp.example?port=123",
            "-ntp.example",
            "ntp-.example",
            "ntp.example..",
            ".",
            "_ntp.example",
            &long_label,
            &long_name,
        ] {
            let config = LandscapeTimeConfig {
                enabled: Some(true),
                servers: Some(vec!["pool.ntp.org".into(), invalid.into()]),
                ..Default::default()
            };
            assert!(config.to_runtime().is_err(), "{invalid}");
            assert_eq!(config.build_runtime().servers, ["pool.ntp.org"]);
        }
    }

    #[test]
    fn enabled_time_accepts_local_names_absolute_names_and_internationalized_names() {
        for (server, expected, port) in [
            ("clock", "clock", 123),
            ("time-1.lan.:124", "time-1.lan.", 124),
            ("bücher.example", "xn--bcher-kva.example", 123),
            ("192.0.2.1:125", "192.0.2.1", 125),
        ] {
            let config = LandscapeTimeConfig {
                enabled: Some(true),
                servers: Some(vec![server.into()]),
                ..Default::default()
            };
            let runtime = config.to_runtime().unwrap();
            assert_eq!(runtime, config.build_runtime());
            let (host, actual_port) = ntp_server_endpoint(&runtime.servers[0]).unwrap();
            assert_eq!((host.as_ref(), actual_port), (expected, port));
        }
    }

    #[test]
    fn enabled_time_requires_servers_but_disabled_time_accepts_an_empty_list() {
        let mut config = LandscapeTimeConfig {
            enabled: Some(true),
            servers: Some(vec![]),
            ..Default::default()
        };
        assert!(config.to_runtime().is_err());
        assert_eq!(config.build_runtime().servers, TimeRuntimeConfig::default().servers);
        config.enabled = Some(false);
        assert!(config.to_runtime().unwrap().servers.is_empty());
    }

    #[test]
    fn clearing_fields_restores_defaults_after_file_round_trip() {
        let mut file_config = LandscapeTimeConfig {
            enabled: Some(true),
            servers: Some(vec!["custom:123".into()]),
            sync_interval_secs: Some(123),
            timeout_secs: Some(10),
            step_threshold_ms: Some(0),
            samples_per_server: Some(5),
        };
        let customized = file_config.to_runtime().unwrap();
        file_config = LandscapeTimeConfig::default();
        let updated = file_config.to_runtime().unwrap();
        let saved = toml::to_string(&file_config).unwrap();
        let reloaded: LandscapeTimeConfig = toml::from_str(&saved).unwrap();
        let restarted = reloaded.to_runtime().unwrap();
        assert_eq!(updated, restarted);
        assert_ne!(customized, updated);
        assert_eq!(updated.servers, TimeRuntimeConfig::default().servers);
        assert_eq!(
            (LandscapeTimeConfig { samples_per_server: Some(0), ..Default::default() })
                .to_runtime()
                .unwrap()
                .samples_per_server,
            1
        );
    }
    #[test]
    fn conversion_normalizes_all_zero_timing_fields() {
        let config = LandscapeTimeConfig {
            sync_interval_secs: Some(0),
            timeout_secs: Some(0),
            samples_per_server: Some(0),
            step_threshold_ms: Some(0),
            ..Default::default()
        };
        let runtime = config.to_runtime().unwrap();
        assert_eq!(runtime.sync_interval_secs, 1);
        assert_eq!(runtime.timeout_secs, 1);
        assert_eq!(runtime.samples_per_server, 1);
        assert_eq!(runtime.step_threshold_ms, 0);
    }
    #[test]
    fn normalization_is_idempotent_and_preserves_other_fields() {
        let runtime = TimeRuntimeConfig {
            enabled: false,
            servers: vec!["custom:123".into()],
            sync_interval_secs: 0,
            timeout_secs: 0,
            samples_per_server: 0,
            step_threshold_ms: 0,
        }
        .normalized();
        assert_eq!(runtime.clone().normalized(), runtime);
        assert_eq!(runtime.sync_interval_secs, 1);
        assert_eq!(runtime.timeout_secs, 1);
        assert_eq!(runtime.samples_per_server, 1);
        assert!(!runtime.enabled);
        assert_eq!(runtime.servers, vec!["custom:123"]);
        assert_eq!(runtime.step_threshold_ms, 0);
    }
}
