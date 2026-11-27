use sea_orm_migration::prelude::*;

#[derive(Iden)]
pub enum FlowConfigs {
    Table,
    Id,
    Enable,
    FlowId,
    FlowMatchRules,
    PacketHandleIfaceName,
    BalanceMode,
    Name,
    Remark,
    UpdateAt,
}
