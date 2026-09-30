use crate::service::ServiceConfigError;

/// 纯内容校验(config 侧,无 IO):`f(config)`。
///
/// 由 `impl_repository!` 宏在 checked 写路径(`checked_upsert`/
/// `checked_upsert_many`)中**首先**调用;每个入库的 config 类型必须
/// 实现(required),纯通过的用 [`impl_trivial_validatable!`] 显式声明。
///
/// 需要与其他表交互的校验不属于这里 —— 它们挂在 Repository 的
/// [`StoreValidator`] 上(zone / 跨域)。
pub trait ValidatableConfig {
    fn validate(&self) -> Result<(), ServiceConfigError>;
}

/// DB 依赖校验(repo 侧):zone 检查 + 跨域冲突检查。
///
/// 由 `impl_repository!` 宏在 checked 写路径中于
/// [`ValidatableConfig::validate`] 之后调用,实现挂在 Repository 上:
///
/// - `check_zone`:zone-aware 服务域委托共享 `ZoneChecker`;非 zone 域
///   显式返回 `Ok(())`("显式放弃"而非"静默遗漏")
/// - `validate_cross`:跨域/跨行冲突检查(读写其他表、本表旧行);
///   无跨域检查的域显式返回 `Ok(())`
///
/// 盲写路径(`upsert`/`upsert_many`)不做校验:可信系统路径(首启播种、
/// ACME、geo 数据更新、网关运行时、设备注册)。
///
/// # 约束
///
/// - validator 只做 `f(config, DB)` 的检查;依赖运行时状态(netlink 实时
///   iface、PD 实际下发前缀等)的检查留在 handler/服务层。
/// - 对外域 repo 只允许**读**:读方法不触发宏注入的校验,不会递归。
/// - DB 读失败映射为 [`ServiceConfigError::internal`](500),
///   不伪装成 422 "配置不合法"。
///
/// # 语义
///
/// 校验是**存在性保证而非原子性保证**:校验读与写入之间存在窗口,
/// 并发写的跨域不变量可能在双方都过校验后落库(与旧 handler 层校验
/// 的窗口相同)。可选加固是把校验移入写事务体,代价是写锁持有变长。
#[async_trait::async_trait]
pub trait StoreValidator<D> {
    /// zone 检查:zone-aware 域委托 `ZoneChecker`;非 zone 域显式 `Ok(())`。
    async fn check_zone(&self, config: &D) -> Result<(), ServiceConfigError>;

    /// 跨域冲突检查:无跨域检查的域显式 `Ok(())`。
    async fn validate_cross(&self, config: &D) -> Result<(), ServiceConfigError>;
}

/// 显式"无纯内容校验"声明:该 config 的入库内容没有 `f(config)` 级别的
/// 检查需求(内容合法性由 repo 侧的 zone/跨域校验或服务层保证)。
#[macro_export]
macro_rules! impl_trivial_validatable {
    ($data:ty) => {
        impl $crate::database::validator::ValidatableConfig for $data {
            fn validate(&self) -> ::std::result::Result<(), $crate::service::ServiceConfigError> {
                Ok(())
            }
        }
    };
}
