use crate::domain::ParsedDomain;

use super::LocalResolver;

/// mDNS zone, always answered locally regardless of the configured LAN suffix.
const MDNS_LOCAL_ZONE: &str = "local";

/// Which local zone a query landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalZone {
    /// The operator-configured LAN suffix (`lan`, `home.arpa`, ...).
    LanSuffix,
    /// `local.`, reserved for mDNS.
    MdnsLocal,
}

/// A query that falls inside one of the local zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalZoneMatch<'a> {
    pub zone: LocalZone,
    /// Labels left of the zone suffix, `None` for the zone apex itself.
    pub hostname: Option<&'a str>,
}

/// Splits `name` at `suffix`, ASCII-case-insensitively. Returns `None` when
/// `name` is outside the zone, `Some(None)` for the zone apex itself and
/// `Some(Some(host))` for a name below it.
fn strip_zone_suffix<'a>(name: &'a str, suffix: &str) -> Option<Option<&'a str>> {
    if suffix.is_empty() || name.len() < suffix.len() {
        return None;
    }
    let (rest, tail) = name.split_at(name.len() - suffix.len());
    if !tail.eq_ignore_ascii_case(suffix) {
        return None;
    }
    match rest {
        "" => Some(None),
        _ => rest.strip_suffix('.').filter(|host| !host.is_empty()).map(Some),
    }
}

impl LocalResolver {
    /// Matches `name` against the local zones this resolver is authoritative
    /// for. A configured suffix may contain multiple labels.
    pub fn match_local_zone<'a>(&self, name: &'a str) -> Option<LocalZoneMatch<'a>> {
        let config = self.hostname_config.load();
        if config.enable
            && !config.lan_suffix.is_empty()
            && let Some(hostname) = strip_zone_suffix(name, &config.lan_suffix)
        {
            return Some(LocalZoneMatch { zone: LocalZone::LanSuffix, hostname });
        }
        strip_zone_suffix(name, MDNS_LOCAL_ZONE)
            .map(|hostname| LocalZoneMatch { zone: LocalZone::MdnsLocal, hostname })
    }

    /// Matches a name against the live LAN-hostname config or the mDNS `.local`
    /// zone. Keeping this decision in one place makes normal
    /// queries, `.arpa` queries, config checks, and cache refreshes agree after
    /// a runtime config change.
    pub(super) fn matching_local_zone<'a>(
        &self,
        domain: &'a ParsedDomain,
    ) -> Option<LocalZoneMatch<'a>> {
        let mut zone = self.match_local_zone(domain.name())?;

        // `.local` remains mDNS territory even if a legacy or hand-edited
        // config incorrectly chooses `local` as the LAN suffix.
        if domain.tld() == "local" {
            zone.zone = LocalZone::MdnsLocal;
        }

        Some(zone)
    }
}
