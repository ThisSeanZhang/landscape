use sea_orm_migration::prelude::*;

#[derive(Iden)]
pub enum DNSRuleConfigs {
    Table,
    Id,
    Index,
    Name,
    Enable,
    Filter,
    ResolveMode,
    Mark,
    Source,
    FlowId,
    UpdateAt,
}

#[derive(Iden)]
pub enum DNSRedirectRuleConfigs {
    Table,
    Id,
    Remark,
    Enable,
    MatchRules,
    ResultInfo,
    ApplyFlows,
    UpdateAt,
}

#[derive(Iden)]
pub enum DNSUpstreamConfigs {
    Table,
    Id,
    Remark,
    Mode,
    Ips,
    Port,
    UpdateAt,
}
