use std::collections::BTreeMap;

use crate::domain::ParsedDomain;
use crate::server::rule::DNSResolveRuntime;

#[derive(Debug, Default)]
pub struct ResolveEngine {
    rules: BTreeMap<u32, DNSResolveRuntime>,
}

impl ResolveEngine {
    pub fn new(rules: BTreeMap<u32, DNSResolveRuntime>) -> Self {
        Self { rules }
    }

    pub fn find_match(&self, domain: &ParsedDomain) -> Option<&DNSResolveRuntime> {
        self.rules.values().find(|rule| rule.is_match(domain))
    }

    pub fn get(&self, order: u32) -> Option<&DNSResolveRuntime> {
        self.rules.get(&order)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u32, &DNSResolveRuntime)> {
        self.rules.iter()
    }
}
