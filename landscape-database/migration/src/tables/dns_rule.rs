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
    UpstreamId,
    Mark,
    Source,
    BindConfig,
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
    AnswerMode,
    ResultInfo,
    ApplyFlows,
    /// Append at 0.x: whether metadata queries are intercepted by this rule
    BlockMetadataQueries,
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
    /// Append at 0.8.0
    EnableIpValidation,
    /// Append at 0.8.x: source-address binding moved here from the rule config
    BindConfig,
    UpdateAt,
}
