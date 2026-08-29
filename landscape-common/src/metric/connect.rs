use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

/// IP 协议类型编码,与 landscape-ebpf 的 LANDSCAPE_IPV4_TYPE 一致
pub const LANDSCAPE_IPV4_TYPE: u8 = 0;
pub const LANDSCAPE_IPV6_TYPE: u8 = 1;

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectKey {
    #[serde(with = "crate::utils::serde_helper")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub create_time: u64,
    pub cpu_id: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ConnectStatusType {
    #[default]
    Unknow,
    Active,
    Disabled,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Default)]
pub enum MetricResolution {
    #[serde(rename = "second")]
    #[default]
    Second,
    #[serde(rename = "minute")]
    Minute,
    #[serde(rename = "hour")]
    Hour,
    #[serde(rename = "day")]
    Day,
}

impl From<u8> for ConnectStatusType {
    fn from(value: u8) -> Self {
        match value {
            1 => ConnectStatusType::Active,
            2 => ConnectStatusType::Disabled,
            _ => ConnectStatusType::Unknow,
        }
    }
}

impl From<ConnectStatusType> for u8 {
    fn from(val: ConnectStatusType) -> Self {
        match val {
            ConnectStatusType::Unknow => 0,
            ConnectStatusType::Active => 1,
            ConnectStatusType::Disabled => 2,
        }
    }
}

/// 与 ebpf 侧 `nat_conn_metric_event` 逐字节一致的 wire 布局(104 字节,零 padding)。
///
/// 布局约束(黄金测试 `landscape-ebpf/src/tests/metric.rs` 用 offset_of! 对照 skel 类型):
/// - `src_addr`/`dst_addr` 为 16 字节原始地址字节,等价于 C 的 `union u_inet_addr`
/// - `pad` 对应 C 中 `u16 dst_port` 与 `u64 create_time` 之间的对齐 padding
/// - `pad_tail` 对应 C 结构体尾部对齐 padding(102 -> 104)
#[derive(Debug, Serialize, Deserialize, Clone, KnownLayout, FromBytes, IntoBytes)]
#[repr(C)]
pub struct ConnectMetric {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    /// 网络序,`fixup()` 转为主机序
    pub src_port: u16,
    /// 网络序,`fixup()` 转为主机序
    pub dst_port: u16,
    pub pad: [u8; 4],
    /// 连接创建时间(ns)
    pub create_time: u64,
    /// 上报时间(wire 为 ns,`fixup()` 转为 ms)
    pub report_time: u64,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub l4_proto: u8,
    pub l3_proto: u8,
    pub flow_id: u8,
    pub trace_id: u8,
    pub cpu_id: u32,
    pub ifindex: u32,
    /// wire 原始值,用 `status_type()` 读取
    pub status: u8,
    pub gress: u8,
    pub pad_tail: [u8; 2],
}

/// 从 ringbuf 读回的原始字节构造 metric,并完成 wire -> 域语义修正。
impl<'a> TryFrom<&'a [u8]> for ConnectMetric {
    type Error = zerocopy::SizeError<&'a [u8], Self>;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let mut metric = ConnectMetric::read_from_bytes(bytes)?;
        metric.fixup();
        Ok(metric)
    }
}

impl ConnectMetric {
    /// 将 wire 值原地修正为域语义(wire ns -> ms,网络序端口 -> 主机序)。
    /// 仅由 [`TryFrom<&[u8]>`] 内部调用,避免重复修正。
    fn fixup(&mut self) {
        self.report_time /= 1_000_000;
        self.src_port = self.src_port.to_be();
        self.dst_port = self.dst_port.to_be();
        self.pad = [0; 4];
        self.pad_tail = [0; 2];
    }

    pub fn key(&self) -> ConnectKey {
        ConnectKey { create_time: self.create_time, cpu_id: self.cpu_id }
    }

    pub fn create_time_ms(&self) -> u64 {
        self.create_time / 1_000_000
    }

    pub fn src_ip(&self) -> IpAddr {
        match self.l3_proto {
            LANDSCAPE_IPV4_TYPE => IpAddr::V4(Ipv4Addr::from([
                self.src_addr[0],
                self.src_addr[1],
                self.src_addr[2],
                self.src_addr[3],
            ])),
            LANDSCAPE_IPV6_TYPE => IpAddr::V6(Ipv6Addr::from(self.src_addr)),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED), // fallback
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self.l3_proto {
            LANDSCAPE_IPV4_TYPE => IpAddr::V4(Ipv4Addr::from([
                self.dst_addr[0],
                self.dst_addr[1],
                self.dst_addr[2],
                self.dst_addr[3],
            ])),
            LANDSCAPE_IPV6_TYPE => IpAddr::V6(Ipv6Addr::from(self.dst_addr)),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED), // fallback
        }
    }

    pub fn status_type(&self) -> ConnectStatusType {
        ConnectStatusType::from(self.status)
    }

    /// 将域名 IP 编码为 wire 布局的 16 字节地址(与 [`ConnectMetric::src_ip`]/[`ConnectMetric::dst_ip`] 互为逆操作)
    #[doc(hidden)]
    pub fn ip_bytes(ip: IpAddr) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => bytes[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => bytes.copy_from_slice(&v6.octets()),
        }
        bytes
    }

    /// 从域语义值构造一个等价于 [`TryFrom<&[u8]>`] 之后状态的 metric。
    /// - `create_time_ms` 为 ms,内部换算为 wire 的 ns 存入 `create_time`
    /// - `report_time` 为 ms,与 [`TryFrom<&[u8]>`] 修正后的域语义一致(直接存入,不做换算)
    /// - 端口为主机序
    /// - `l3_proto` 由 `src_ip` 推导,`l4_proto` 固定为 TCP,`gress` 固定为 0
    /// - 返回值的 `key()` 可直接用于查询(create_time 为 ns)
    /// - 注意:结果**不能**经 `IntoBytes` 回写为 wire 数据(时间单位与 wire 的 ns 语义不一致)
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_domain(
        create_time_ms: u64,
        cpu_id: u32,
        report_time: u64,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        flow_id: u8,
        trace_id: u8,
        ifindex: u32,
        ingress_bytes: u64,
        ingress_packets: u64,
        egress_bytes: u64,
        egress_packets: u64,
        status: ConnectStatusType,
    ) -> ConnectMetric {
        ConnectMetric {
            src_addr: Self::ip_bytes(src_ip),
            dst_addr: Self::ip_bytes(dst_ip),
            src_port,
            dst_port,
            pad: [0; 4],
            create_time: create_time_ms * 1_000_000,
            report_time,
            ingress_bytes,
            ingress_packets,
            egress_bytes,
            egress_packets,
            l4_proto: 6,
            l3_proto: match src_ip {
                IpAddr::V4(_) => LANDSCAPE_IPV4_TYPE,
                IpAddr::V6(_) => LANDSCAPE_IPV6_TYPE,
            },
            flow_id,
            trace_id,
            cpu_id,
            ifindex,
            status: status.into(),
            gress: 0,
            pad_tail: [0; 2],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectMetricPoint {
    pub report_time: u64,

    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,

    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq, Clone)]
pub struct ConnectAgg {
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectRealtimeStatus {
    pub key: ConnectKey,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,
    pub gress: u8,
    pub ifindex: u32,

    pub create_time_ms: u64,

    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
    pub last_report_time: u64,
    pub status: ConnectStatusType,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectGlobalStats {
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub total_connect_count: u64,
    pub last_calculate_time: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct GetConnectGlobalStatsParams {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub force_refresh: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ConnectSortKey {
    #[default]
    Time,
    Port,
    Ingress,
    Egress,
    Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct ConnectHistoryQueryParams {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub start_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub end_time: Option<u64>,
    /// 单页条数上限(1..=200 会被服务端 clamp);`0` 表示不限制、返回全部匹配行
    /// 缺省不传时服务端按 100 兜底分页。
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub limit: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub offset: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub src_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub dst_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port_start: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port_end: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub l3_proto: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub l4_proto: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_key: Option<ConnectSortKey>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_order: Option<SortOrder>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub status: Option<u8>, // 0: Unknow, 1: Active, 2: Disabled
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub gress: Option<u8>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub ifindex: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectHistoryStatus {
    pub key: ConnectKey,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    pub l4_proto: u8,
    pub l3_proto: u8,

    pub flow_id: u8,
    pub trace_id: u8,
    pub gress: u8,
    pub ifindex: u32,

    pub create_time_ms: u64,

    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub last_report_time: u64,

    pub status: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectHistoryResponse {
    pub items: Vec<ConnectHistoryStatus>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpAggregatedStats {
    pub ingress_bps: u64,
    pub egress_bps: u64,
    pub ingress_pps: u64,
    pub egress_pps: u64,
    pub active_conns: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpRealtimeStat {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub stats: IpAggregatedStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceRealtimeStat {
    pub ifindex: u32,
    pub stats: IpAggregatedStats,
    pub last_report_time: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IpHistoryStat {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: IpAddr,
    pub flow_id: u8,
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
    pub connect_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MetricChartRequest {
    pub key: ConnectKey,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub resolution: Option<MetricResolution>,
}
