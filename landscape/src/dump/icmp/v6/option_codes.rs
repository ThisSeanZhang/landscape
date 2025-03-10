use paste::paste;

/// 二分查找第一个匹配条件的元素的索引
fn first<T, F>(slice: &[T], mut compare: F) -> Option<usize>
where
    F: FnMut(&T) -> std::cmp::Ordering,
{
    let mut left = 0;
    let mut right = slice.len();

    while left < right {
        let mid = left + (right - left) / 2;
        match compare(&slice[mid]) {
            std::cmp::Ordering::Equal => {
                // 找到匹配项后，继续向左查找第一个
                if mid == 0 || compare(&slice[mid - 1]) != std::cmp::Ordering::Equal {
                    return Some(mid);
                }
                right = mid;
            }
            std::cmp::Ordering::Greater => right = mid,
            std::cmp::Ordering::Less => left = mid + 1,
        }
    }
    None
}

/// 二分查找所有匹配条件的元素的范围
fn range_binsearch<T, F>(slice: &[T], mut compare: F) -> Option<std::ops::Range<usize>>
where
    F: FnMut(&T) -> std::cmp::Ordering,
{
    let first = first(slice, &mut compare)?;

    // 找到最后一个匹配的元素
    let mut last = first;
    while last + 1 < slice.len() && compare(&slice[last + 1]) == std::cmp::Ordering::Equal {
        last += 1;
    }

    Some(first..last + 1)
}

/// 这是一个更完善的声明式宏实现
#[macro_export]
macro_rules! define_options {
    ($name:ident, $code_type:ty, $len_type:ty, {
        $(
            {$code:expr, $variant:ident, $desc:expr, $data_type:ty},
        )*
    }) => {
        paste! {
            // 选项类型
            #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
            pub enum $name {
                $(
                    #[doc = $desc]
                    $variant($data_type),
                )*
                UnknownOption($code_type, Vec<u8>),
            }

            // 选项代码
            #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub enum [<$name Code>] {
                $(
                    #[doc = $desc]
                    $variant,
                )*
                Unknown($code_type),
            }

            // 实现Code到u8/u16的转换
            impl From<$code_type> for [<$name Code>] {
                fn from(value: $code_type) -> Self {
                    match value {
                        $(
                            $code => [<$name Code>]::$variant,
                        )*
                        value => [<$name Code>]::Unknown(value),
                    }
                }
            }

            impl From<[<$name Code>]> for $code_type {
                fn from(value: [<$name Code>]) -> Self {
                    match value {
                        $(
                            [<$name Code>]::$variant => $code,
                        )*
                        [<$name Code>]::Unknown(n) => n,
                    }
                }
            }

            // 添加从 Option 到 OptionCode 的转换
            impl From<&$name> for [<$name Code>] {
                fn from(option: &$name) -> Self {
                    match option {
                        $(
                            $name::$variant(_) => [<$name Code>]::$variant,
                        )*
                        $name::UnknownOption(code, _) => [<$name Code>]::Unknown(*code)
                    }
                }
            }

            // 另外添加从 Option 到 code_type (u8/u16) 的转换
            // impl From<&$name> for $code_type {
            //     fn from(option: &$name) -> Self {
            //         match option {
            //             $(
            //                 $name::$variant(_) => $code,
            //             )*
            //         }
            //     }
            // }

            // 实现PartialEq, Eq, PartialOrd, Ord等特性以支持排序
            impl PartialEq for $name {
                fn eq(&self, other: &Self) -> bool {
                    let self_code: $code_type = match self {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    let other_code: $code_type = match other {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    self_code == other_code
                }
            }

            impl Eq for $name {}

            impl PartialOrd for $name {
                fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                    let self_code: $code_type = match self {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    let other_code: $code_type = match other {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    Some(self_code.cmp(&other_code))
                }
            }

            impl Ord for $name {
                fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                    let self_code: $code_type = match self {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    let other_code: $code_type = match other {
                        $(
                            $name::$variant(_) => $code,
                        )*
                        $name::UnknownOption(code, _) => *code
                    };

                    self_code.cmp(&other_code)
                }
            }

            // 选项集合结构体
            #[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
            pub struct [<$name s>](Vec<$name>); // vec maintains sorted on OptionCode

            impl [<$name s>] {
                /// construct empty Options
                pub fn new() -> Self {
                    Self::default()
                }

                /// get the first element matching this option code
                pub fn get(&self, code: [<$name Code>]) -> Option<&$name> {
                    let first = first(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    self.0.get(first)
                }

                /// get all elements matching this option code
                pub fn get_all(&self, code: [<$name Code>]) -> Option<&[$name]> {
                    let range = range_binsearch(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    Some(&self.0[range])
                }

                /// get the first element matching this option code
                pub fn get_mut(&mut self, code: [<$name Code>]) -> Option<&mut $name> {
                    let first = first(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    self.0.get_mut(first)
                }

                /// get all elements matching this option code
                pub fn get_mut_all(&mut self, code: [<$name Code>]) -> Option<&mut [$name]> {
                    let range = range_binsearch(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    Some(&mut self.0[range])
                }

                /// remove the first element with a matching option code
                pub fn remove(&mut self, code: [<$name Code>]) -> Option<$name> {
                    let first = first(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    Some(self.0.remove(first))
                }

                /// remove all elements with a matching option code
                pub fn remove_all(
                    &mut self,
                    code: [<$name Code>],
                ) -> Option<impl Iterator<Item = $name> + '_> {
                    let range = range_binsearch(&self.0, |x| {
                        let x_code: $code_type = match x {
                            $(
                                $name::$variant(_) => $code,
                            )*
                            $name::UnknownOption(code, _) => *code
                        };
                        let code_val: $code_type = code.into();
                        x_code.cmp(&code_val)
                    })?;
                    Some(self.0.drain(range))
                }

                /// insert a new option into the list of opts
                pub fn insert(&mut self, opt: $name) {
                    let i = self.0.partition_point(|x| x < &opt);
                    self.0.insert(i, opt)
                }

                /// return a reference to an iterator
                pub fn iter(&self) -> impl Iterator<Item = &$name> {
                    self.0.iter()
                }

                /// return a mutable ref to an iterator
                pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut $name> {
                    self.0.iter_mut()
                }
            }

            impl IntoIterator for [<$name s>] {
                type Item = $name;

                type IntoIter = std::vec::IntoIter<Self::Item>;

                fn into_iter(self) -> Self::IntoIter {
                    self.0.into_iter()
                }
            }

            impl FromIterator<$name> for [<$name s>] {
                fn from_iter<T: IntoIterator<Item = $name>>(iter: T) -> Self {
                    let mut opts = iter.into_iter().collect::<Vec<_>>();
                    opts.sort_unstable();
                    [<$name s>](opts)
                }
            }
        }
    };
}

// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
define_options!(IcmpV6Option, u8, u8, {
    {1,   SourceLinkLayerAddress, "Source Link-layer Address", Vec<u8>},
    {2,   TargetLinkLayerAddress, "Target Link-layer Address", Vec<u8>},
    {3,   PrefixInformation, "Prefix Information", Vec<u8>},
    {4,   RedirectedHeader, "Redirected Header", Vec<u8>},
    {5,   MTU, "MTU", Vec<u8>},
    {6,   NBMAShortcutLimit, "NBMA Shortcut Limit Option", Vec<u8>},
    {7,   AdvertisementInterval, "Advertisement Interval Option - ms \n\n https://www.rfc-editor.org/rfc/rfc6275.html#section-7.3", Vec<u8>},
    {8,   HomeAgentInformation, "Home Agent Information Option", Vec<u8>},
    {9,   SourceAddressList, "Source Address List", Vec<u8>},
    {10,  TargetAddressList, "Target Address List", Vec<u8>},
    {11,  CGAOption, "CGA option", Vec<u8>},
    {12,  RSASignature, "RSA Signature option", Vec<u8>},
    {13,  Timestamp, "Timestamp option", Vec<u8>},
    {14,  Nonce, "Nonce option", Vec<u8>},
    {15,  TrustAnchor, "Trust Anchor option", Vec<u8>},
    {16,  Certificate, "Certificate option", Vec<u8>},
    {17,  IPAddressPrefix, "IP Address/Prefix Option", Vec<u8>},
    {18,  NewRouterPrefixInformation, "New Router Prefix Information Option", Vec<u8>},
    {19,  LinkLayerAddress, "Link-layer Address Option", Vec<u8>},
    {20,  NeighborAdvertisementAcknowledgment, "Neighbor Advertisement Acknowledgment Option", Vec<u8>},
    {21,  PvDIDRouterAdvertisement, "PvD ID Router Advertisement Option", Vec<u8>},
    {23,  MAP, "MAP Option", Vec<u8>},
    {24,  RouteInformation, "Route Information Option", Vec<u8>},
    {25,  RecursiveDNSServer, "Recursive DNS Server Option", Vec<u8>},
    {26,  RAFlagsExtension, "RA Flags Extension Option", Vec<u8>},
    {27,  HandoverKeyRequest, "Handover Key Request Option", Vec<u8>},
    {28,  HandoverKeyReply, "Handover Key Reply Option", Vec<u8>},
    {29,  HandoverAssistInformation, "Handover Assist Information Option", Vec<u8>},
    {30,  MobileNodeIdentifier, "Mobile Node Identifier Option", Vec<u8>},
    {31,  DNSSearchList, "DNS Search List Option", Vec<u8>},
    {32,  ProxySignature, "Proxy Signature (PS)", Vec<u8>},
    {33,  AddressRegistration, "Address Registration Option", Vec<u8>},
    {34,  LowPANContext, "6LoWPAN Context Option", Vec<u8>},
    {35,  AuthoritativeBorderRouter, "Authoritative Border Router Option", Vec<u8>},
    {36,  LowPANCapabilityIndication, "6LoWPAN Capability Indication Option (6CIO)", Vec<u8>},
    {37,  DHCPCaptivePortal, "DHCP Captive-Portal", Vec<u8>},
    {38,  PREF64, "PREF64 option", Vec<u8>},
    {39,  CryptoIDParameters, "Crypto-ID Parameters Option (CIPO)", Vec<u8>},
    {40,  NDPSignature, "NDP Signature Option (NDPSO)", Vec<u8>},
    {41,  ResourceDirectoryAddress, "Resource Directory Address Option", Vec<u8>},
    {42,  ConsistentUptime, "Consistent Uptime Option", Vec<u8>},
    {138, CARDRequest, "CARD Request option", Vec<u8>},
    {139, CARDReply, "CARD Reply option", Vec<u8>},
    {144, EncryptedDNS, "Encrypted DNS Option", Vec<u8>},
    {253, RFC3692Experiment1, "RFC3692-style Experiment 1", Vec<u8>},
    {254, RFC3692Experiment2, "RFC3692-style Experiment 2", Vec<u8>},
});

impl dhcproto::Decodable for IcmpV6Options {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        let mut opts = Vec::new();
        while let Ok(opt) = IcmpV6Option::decode(decoder) {
            opts.push(opt);
        }
        // sorts by OptionCode
        opts.sort_unstable();
        Ok(IcmpV6Options(opts))
    }
}

impl dhcproto::Decodable for IcmpV6Option {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        let code = decoder.read_u8()?.into();
        let len = decoder.read_u8()? as usize;

        let result = match code {
            IcmpV6OptionCode::SourceLinkLayerAddress => {
                IcmpV6Option::SourceAddressList(decoder.read_slice(len)?.to_vec())
            }
            code => IcmpV6Option::UnknownOption(code.into(), decoder.read_slice(len)?.to_vec()),
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dump::udp_packet::dhcp::options::OptionDefined;

    /// 这部分是额外用户定义的, 不需要宏中实现
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
    pub struct Test;

    /// 这部分是额外用户定义的, 不需要宏中实现
    impl OptionDefined for Test {
        fn encode(&self) -> Vec<u8> {
            todo!()
        }

        fn decode(data: &[u8]) -> Option<Self>
        where
            Self: Sized,
        {
            todo!()
        }
    }

    define_options!(AOption, u8,u8,{
        {1,   A1, "描述 A1", Test },
        {2,   A2, "描述 A1", Test },
    });

    define_options!(BOption, u16,u16,{
        {1,   B1, "描述 B1", Test },
        {2,   B2, "描述 B1", Test },
    });

    // pub enum AOptionCode {
    //     /// 描述 A1
    //     A1,
    //     /// 描述 A2
    //     A2,
    //     Unknown(u8),
    // }

    // pub enum AOption {
    //     /// 描述 A1
    //     A1(Test),
    //     /// 描述 A2
    //     A2(Test),
    // }

    // impl From<u8> for AOptionCode {
    //     fn from(value: u8) -> Self {
    //         match value {
    //             1 => AOptionCode::A1,
    //             2 => AOptionCode::A2,
    //             value => AOptionCode::Unknown(value),
    //         }
    //     }
    // }

    // impl From<AOptionCode> for u8 {
    //     fn from(value: AOptionCode) -> Self {
    //         match value {
    //             AOptionCode::A1 => 1,
    //             AOptionCode::A2 => 2,
    //             AOptionCode::Unknown(n) => n,
    //         }
    //     }
    // }
    // });

    // 首先创建一些测试数据
    fn create_test_data() -> Vec<AOption> {
        vec![
            AOption::A1(Test::default()),
            AOption::A2(Test::default()),
            AOption::A1(Test::default()), // 重复的选项，用于测试多个相同代码的选项
        ]
    }

    #[test]
    fn test_option_code_conversion() {
        // 测试从 u8 到 AOptionCode 的转换
        assert!(matches!(AOptionCode::from(1u8), AOptionCode::A1));
        assert!(matches!(AOptionCode::from(2u8), AOptionCode::A2));
        assert!(matches!(AOptionCode::from(255u8), AOptionCode::Unknown(255)));

        // 测试从 AOptionCode 到 u8 的转换
        assert_eq!(u8::from(AOptionCode::A1), 1);
        assert_eq!(u8::from(AOptionCode::A2), 2);
        assert_eq!(u8::from(AOptionCode::Unknown(255)), 255);
    }

    #[test]
    fn test_option_ordering() {
        let a1 = AOption::A1(Test::default());
        let a2 = AOption::A2(Test::default());

        // 测试选项比较
        assert!(a1 < a2);
        assert!(a2 > a1);
        assert_eq!(a1, AOption::A1(Test::default()));
    }

    #[test]
    fn test_options_new() {
        let options = AOptions::new();
        assert!(options.0.is_empty());
    }

    #[test]
    fn test_options_insert() {
        let mut options = AOptions::new();

        // 插入选项
        options.insert(AOption::A1(Test::default()));
        assert_eq!(options.0.len(), 1);

        // 插入另一个选项
        options.insert(AOption::A2(Test::default()));
        assert_eq!(options.0.len(), 2);

        // 验证排序
        assert!(matches!(options.0[0], AOption::A1(_)));
        assert!(matches!(options.0[1], AOption::A2(_)));
    }

    #[test]
    fn test_options_get() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));

        // 测试获取选项
        let a1 = options.get(AOptionCode::A1);
        assert!(a1.is_some());
        assert!(matches!(a1.unwrap(), AOption::A1(_)));

        let a2 = options.get(AOptionCode::A2);
        assert!(a2.is_some());
        assert!(matches!(a2.unwrap(), AOption::A2(_)));

        // 测试获取不存在的选项
        let unknown = options.get(AOptionCode::Unknown(3));
        assert!(unknown.is_none());
    }

    #[test]
    fn test_options_get_all() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试获取所有匹配的选项
        let all_a1 = options.get_all(AOptionCode::A1);
        assert!(all_a1.is_some());
        assert_eq!(all_a1.unwrap().len(), 2);

        let all_a2 = options.get_all(AOptionCode::A2);
        assert!(all_a2.is_some());
        assert_eq!(all_a2.unwrap().len(), 1);
    }

    #[test]
    fn test_options_remove() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试删除单个选项
        let removed = options.remove(AOptionCode::A1);
        assert!(removed.is_some());
        assert!(matches!(removed.unwrap(), AOption::A1(_)));

        // 验证仍然有一个A1和一个A2
        assert_eq!(options.0.len(), 2);

        // 获取并检查剩余的选项
        let all_a1 = options.get_all(AOptionCode::A1);
        assert!(all_a1.is_some());
        assert_eq!(all_a1.unwrap().len(), 1);
    }

    #[test]
    fn test_options_remove_all() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试删除所有匹配的选项
        let removed = options.remove_all(AOptionCode::A1);
        assert!(removed.is_some());
        let removed_vec: Vec<_> = removed.unwrap().collect();
        assert_eq!(removed_vec.len(), 2);

        // 验证只剩下A2
        assert_eq!(options.0.len(), 1);
        assert!(matches!(options.0[0], AOption::A2(_)));
    }

    #[test]
    fn test_options_iter() {
        let options = create_test_data().into_iter().collect::<AOptions>();

        // 测试迭代器
        let items: Vec<_> = options.iter().collect();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn test_options_from_iterator() {
        let data = create_test_data();
        let options = data.into_iter().collect::<AOptions>();

        // 验证排序和收集
        assert_eq!(options.0.len(), 3);
        assert!(matches!(options.0[0], AOption::A1(_)));
        assert!(matches!(options.0[1], AOption::A1(_)));
        assert!(matches!(options.0[2], AOption::A2(_)));
    }

    #[test]
    fn test_options_into_iterator() {
        let options = create_test_data().into_iter().collect::<AOptions>();

        // 测试将选项集合转换为迭代器
        let items: Vec<_> = options.into_iter().collect();
        assert_eq!(items.len(), 3);
    }
}
