use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum DHCPv4ServerConfigs {
    #[sea_orm(iden = "dhcp_v4_server_configs")]
    Table,
    IfaceName,
    Enable,
    IpRangeStart,
    IpRangeEnd,
    ServerIpAddr,
    NetworkMask,
    NetworkStart,
    NetworkEnd,
    AddressLeaseTime,
    MacBindingRecords,
    UpdateAt,
}
