use serde::{Deserialize, Serialize};
use ts_rs::TS;

const FLOW_ID_MASK: u32 = 0x000000FF;
const FLOW_ACTION_MASK: u32 = 0x00007F00;
const FLOW_ALLOW_REUSE_PORT_MASK: u32 = 0x00008000;

const FLOW_KEEP_GOING: u8 = 0;
const FLOW_DIRECT: u8 = 1;
const FLOW_DROP: u8 = 2;
const FLOW_REDIRECT: u8 = 3;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Copy, Eq, Hash, TS)]
#[ts(export, export_to = "common/flow.d.ts")]
pub struct FlowMark {
    /// Action
    action: FlowMarkAction,

    /// 允许 NAT 端口共享
    allow_reuse_port: bool,

    /// Flow Id
    flow_id: u8,
}

impl FlowMark {
    pub fn need_insert_in_ebpf_map(&self) -> bool {
        match self.action {
            FlowMarkAction::KeepGoing => self.allow_reuse_port,
            _ => true,
        }
    }

    pub fn get_dns_mark(&self, default_flow_id: u32) -> u32 {
        let mut mark_value = match self.action {
            // 转发时候使用目标 flow 进行标记 DNS 请求
            FlowMarkAction::Redirect => self.flow_id as u32,
            // 忽略流的配置
            FlowMarkAction::Direct => 0,
            // 其余情况使用 当前规则所属的 flow 进行标记
            _ => default_flow_id,
        };

        // DNS Allow Reuse Port
        mark_value |= FLOW_ALLOW_REUSE_PORT_MASK;

        tracing::debug!("dns mark_value: {mark_value}");
        mark_value
    }

    pub fn set_reuseport(&mut self, value: bool) {
        self.allow_reuse_port = value;
    }
}

impl From<u32> for FlowMark {
    fn from(value: u32) -> Self {
        let raw_action = ((value & FLOW_ACTION_MASK) >> 8) as u8;
        let flow_id = (value & FLOW_ID_MASK) as u8;
        let allow_reuse_port = (value & FLOW_ALLOW_REUSE_PORT_MASK) != 0;

        let action: FlowMarkAction = raw_action.into();
        FlowMark { action, allow_reuse_port, flow_id }
    }
}

impl Into<u32> for FlowMark {
    fn into(self) -> u32 {
        let raw_action: u8 = self.action.into();
        let mut value = (raw_action as u32) << 8;

        if raw_action == FLOW_REDIRECT {
            value |= self.flow_id as u32;
        }

        if self.allow_reuse_port {
            value |= FLOW_ALLOW_REUSE_PORT_MASK;
        }

        value
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Copy, Eq, Hash, TS)]
#[ts(export, export_to = "common/flow.d.ts")]
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

impl Into<u8> for FlowMarkAction {
    fn into(self) -> u8 {
        match self {
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
    fn test_from_u32() {
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
    fn test_into_u32() {
        let mark: u32 = FlowMark {
            action: FlowMarkAction::Direct,
            allow_reuse_port: false,
            flow_id: 0,
        }
        .into();
        assert_eq!(mark, 0x0100);

        let mark: u32 = FlowMark {
            action: FlowMarkAction::Redirect,
            allow_reuse_port: false,
            flow_id: 5,
        }
        .into();
        assert_eq!(mark, 0x0305);

        let mark: u32 = FlowMark {
            action: FlowMarkAction::Redirect,
            allow_reuse_port: true,
            flow_id: 0,
        }
        .into();
        assert_eq!(mark, 0x8000 | 0x0300); // 0x8000 | 0x0300
    }
}
