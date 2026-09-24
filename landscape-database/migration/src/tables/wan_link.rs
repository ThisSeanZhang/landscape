use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum WanLinks {
    #[sea_orm(iden = "wan_links")]
    Table,
    Id,
    Name,
    AttachIfaceName,
    LinkChainId,
    Kind,
    V4,
    Pd,
    Nat,
    Firewall,
    Mss,
    UpdateAt,
}
