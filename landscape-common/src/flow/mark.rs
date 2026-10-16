use serde::{Deserialize, Serialize};

/// FlowMark payload bit layout (bits 0-15, mirrored by `bpf/base/mark.h`):
///   bits 0-7   flow_id
///   bits 8-14  action
///   bit  15    allow_reuse_port
const FLOW_ID_MASK: u16 = 0x00FF;
const FLOW_ACTION_MASK: u16 = 0x7F00;
const FLOW_ALLOW_REUSE_PORT_MASK: u16 = 0x8000;

const FLOW_KEEP_GOING: u8 = 0;
const FLOW_DIRECT: u8 = 1;
const FLOW_DROP: u8 = 2;
const FLOW_REDIRECT: u8 = 3;

/// Full SocketMark bit layout (32 bits):
///   bits 24-31  mark layout-type tag (Normal = 0, HostDirect = 1)
///   bits 16-23  trace_mark (reserved for observability, carried by both
///               layouts, always 0 for now)
///   bits 0-15   payload (Normal: FlowMark | HostDirect: chain_id)
const MARK_TYPE_MASK: u32 = 0xFF00_0000;
const TRACE_MARK_MASK: u32 = 0x00FF_0000;
const MARK_TYPE_HOST_DIRECT: u32 = 1;

/// The full socket mark (the `skb->mark` / `SO_MARK` field).
///
/// The single Rust-side entry point for the u32 wire value: a raw u32 is
/// decoded through [`SocketMark::from`], and the payload field (low 16 bits)
/// is represented by [`FlowMark`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketMark {
    mark_type: MarkType,

    /// bits 16-23, reserved for observability, always 0 for now
    trace_mark: u8,
}

/// Mark layout type, discriminated by the bits 24-31 tag; the two layouts
/// are mutually exclusive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkType {
    /// tag = [`MARK_TYPE_NORMAL`](0): bits 0-15 are the standard FlowMark layout
    Normal(FlowMark),
    /// tag = 1: bits 0-15 are the chain_id as a whole
    HostDirect { chain_id: u16 },
}

impl SocketMark {
    pub const fn new(mark_type: MarkType, trace_mark: u8) -> Self {
        SocketMark { mark_type, trace_mark }
    }

    /// Compute the SO_MARK for a DNS upstream socket: always the Normal
    /// layout with the action bits left empty; upstream selection is carried
    /// only by the flow_id bits, and the NAT port-reuse bit is always set.
    pub fn get_dns_mark(mark: FlowMark, default_flow_id: u32) -> u32 {
        let mut mark_value = match mark.action {
            // Forwarding: tag the DNS request with the target flow
            FlowMarkAction::Redirect => mark.flow_id as u32,
            // Ignore the flow configuration
            FlowMarkAction::Direct => 0,
            // Otherwise: tag with the flow the current rule belongs to
            _ => default_flow_id,
        };

        // DNS Allow Reuse Port
        mark_value |= FLOW_ALLOW_REUSE_PORT_MASK as u32;

        tracing::debug!("dns mark_value: {mark_value}");
        mark_value
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Copy, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowMark {
    /// Action
    action: FlowMarkAction,

    /// 允许 NAT 端口共享
    allow_reuse_port: bool,

    /// Flow Id
    flow_id: u8,
}

impl FlowMark {
    pub const fn new(action: FlowMarkAction, flow_id: u8, allow_reuse_port: bool) -> Self {
        FlowMark { action, allow_reuse_port, flow_id }
    }

    /// Whether a DNS answer carrying this mark should be registered with the
    /// datapath. `KeepGoing` flows only register when reuse-port is allowed;
    /// the addressed action types (Direct/Drop/Redirect) always register.
    pub fn should_insert_dns_mark(&self) -> bool {
        match self.action {
            FlowMarkAction::KeepGoing => self.allow_reuse_port,
            _ => true,
        }
    }

    pub fn set_reuseport(&mut self, value: bool) {
        self.allow_reuse_port = value;
    }
}

impl From<u16> for FlowMark {
    fn from(value: u16) -> Self {
        let raw_action = ((value & FLOW_ACTION_MASK) >> 8) as u8;
        let flow_id = (value & FLOW_ID_MASK) as u8;
        let allow_reuse_port = (value & FLOW_ALLOW_REUSE_PORT_MASK) != 0;

        let action: FlowMarkAction = raw_action.into();
        FlowMark { action, allow_reuse_port, flow_id }
    }
}

impl From<FlowMark> for u16 {
    fn from(val: FlowMark) -> Self {
        let raw_action: u8 = val.action.into();
        let mut value = (raw_action as u16) << 8;

        // Only Redirect packs the flow_id: for other actions eBPF does not
        // decode this field, so it is zeroed on encode to keep round-trips
        // deterministic
        if raw_action == FLOW_REDIRECT {
            value |= val.flow_id as u16;
        }

        if val.allow_reuse_port {
            value |= FLOW_ALLOW_REUSE_PORT_MASK;
        }

        value
    }
}

/// Zero-extension delegate: used when the payload is written into the u32
/// wire field of an eBPF map
impl From<FlowMark> for u32 {
    fn from(val: FlowMark) -> Self {
        u16::from(val) as u32
    }
}

impl From<u32> for SocketMark {
    fn from(value: u32) -> Self {
        let trace_mark = ((value & TRACE_MARK_MASK) >> 16) as u8;
        // Unknown tags (>1) fall back to Normal, matching FlowMarkAction's
        // lenient style
        let mark_type = if (value & MARK_TYPE_MASK) >> 24 == MARK_TYPE_HOST_DIRECT {
            MarkType::HostDirect { chain_id: value as u16 }
        } else {
            MarkType::Normal(FlowMark::from(value as u16))
        };
        SocketMark { mark_type, trace_mark }
    }
}

impl From<SocketMark> for u32 {
    fn from(v: SocketMark) -> Self {
        let raw = (v.trace_mark as u32) << 16;
        match v.mark_type {
            MarkType::Normal(fm) => raw | u32::from(fm),
            // HostDirect encoding writes the tag unconditionally; the type
            // guarantees no other layout is possible
            MarkType::HostDirect { chain_id } => {
                raw | (MARK_TYPE_HOST_DIRECT << 24) | chain_id as u32
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Copy, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum FlowMarkAction {
    /// 按照当前 Flow 的配置继续
    #[default]
    KeepGoing,
    /// 忽略 Flow 转发配置, 直接发送
    /// 对于默认 flow 无效果
    Direct,
    /// 丢弃匹配的数据包
    Drop,
    /// 转发到指定的流
    Redirect,
}

impl From<u8> for FlowMarkAction {
    fn from(value: u8) -> Self {
        match value {
            FLOW_KEEP_GOING => FlowMarkAction::KeepGoing,
            FLOW_DIRECT => FlowMarkAction::Direct,
            FLOW_DROP => FlowMarkAction::Drop,
            FLOW_REDIRECT => FlowMarkAction::Redirect,
            _ => FlowMarkAction::KeepGoing,
        }
    }
}

impl From<FlowMarkAction> for u8 {
    fn from(val: FlowMarkAction) -> Self {
        match val {
            FlowMarkAction::KeepGoing => FLOW_KEEP_GOING,
            FlowMarkAction::Direct => FLOW_DIRECT,
            FlowMarkAction::Drop => FLOW_DROP,
            FlowMarkAction::Redirect => FLOW_REDIRECT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u16() {
        assert_eq!(
            FlowMark::from(0x0100),
            FlowMark {
                action: FlowMarkAction::Direct,
                allow_reuse_port: false,
                flow_id: 0
            }
        );
        assert_eq!(
            FlowMark::from(0x0305),
            FlowMark {
                action: FlowMarkAction::Redirect,
                allow_reuse_port: false,
                flow_id: 5
            }
        );
        assert_eq!(
            FlowMark::from(0x8300), // 0x8000 | 0x0300
            FlowMark {
                action: FlowMarkAction::Redirect,
                allow_reuse_port: true,
                flow_id: 0
            }
        );
    }

    #[test]
    fn test_into_u16() {
        let mark: u16 = FlowMark {
            action: FlowMarkAction::Direct,
            allow_reuse_port: false,
            flow_id: 0,
        }
        .into();
        assert_eq!(mark, 0x0100);

        let mark: u16 = FlowMark {
            action: FlowMarkAction::Redirect,
            allow_reuse_port: false,
            flow_id: 5,
        }
        .into();
        assert_eq!(mark, 0x0305);

        let mark: u16 = FlowMark {
            action: FlowMarkAction::Redirect,
            allow_reuse_port: true,
            flow_id: 0,
        }
        .into();
        assert_eq!(mark, 0x8000 | 0x0300); // 0x8000 | 0x0300
    }

    #[test]
    fn test_into_normalizes_stray_flow_id() {
        // Direct with stray flow_id bits -> zeroed on encode
        let mark: u16 = FlowMark::from(0x0105).into();
        assert_eq!(mark, 0x0100);
    }

    #[test]
    fn test_flow_mark_zero_extends_to_u32() {
        let fm = FlowMark::new(FlowMarkAction::Redirect, 5, true);
        assert_eq!(u32::from(fm), 0x8305);
        // Legacy DB / map values (high 16 bits zero) decode as SocketMark
        assert_eq!(SocketMark::from(0x8305), SocketMark::new(MarkType::Normal(fm), 0));
    }

    #[test]
    fn test_socket_mark_host_direct_roundtrip() {
        let sm = SocketMark::new(MarkType::HostDirect { chain_id: 0xBEEF }, 7);
        let raw = u32::from(sm);
        assert_eq!(raw, (1 << 24) | (7 << 16) | 0xBEEF);
        assert_eq!(SocketMark::from(raw), sm);
    }

    #[test]
    fn test_socket_mark_unknown_tag_falls_back_to_normal() {
        // tag = 2 is undefined -> fall back to the Normal layout, decoding
        // the low 16 bits
        let sm = SocketMark::from(0x0200_0305);
        assert_eq!(
            sm,
            SocketMark::new(MarkType::Normal(FlowMark::new(FlowMarkAction::Redirect, 5, false)), 0)
        );
    }

    #[test]
    fn dns_mark_stays_in_normal_layout() {
        let cases = [
            (FlowMark::default(), 5u32), // KeepGoing → 0x8005
            (FlowMark::new(FlowMarkAction::Direct, 9, false), 7), // Direct    → 0x8000
            (FlowMark::new(FlowMarkAction::Redirect, 3, false), 7), // Redirect  → 0x8003
        ];

        for (fm, flow) in cases {
            match SocketMark::from(SocketMark::get_dns_mark(fm, flow)) {
                SocketMark { trace_mark: 0, mark_type: MarkType::Normal(inner) } => {
                    // the action bits are always empty; upstream selection is
                    // carried only by the flow_id bits
                    assert_eq!(inner.action, FlowMarkAction::KeepGoing);
                    // the NAT port-reuse bit is always set
                    assert!(inner.allow_reuse_port);
                }
                other => panic!("dns mark must be Normal layout, got {other:?}"),
            }
        }
    }
}
