pub mod error;
pub mod icmpv6;
pub mod options;
pub mod udp;

/// 定义通用数据包 Option 序列化 trait
pub trait EthFrameOption {
    /// 编码为字节数组
    fn encode(&self) -> Vec<u8>;

    /// 解码成对应的类型
    fn decode(data: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

/// 统一的网络协议解析接口
pub trait NetProtoCodec: Sized {
    /// 从原始字节流中解析出消息 (适配 Decoder)
    /// 返回 Ok(Some(Self)) 表示解析成功，Ok(None) 表示长度不足
    fn decode(src: &mut bytes::BytesMut) -> Result<Option<Self>, error::NetProtoError>;

    /// 将消息编码到字节流中 (适配 Encoder)
    fn encode(&self, dst: &mut bytes::BytesMut) -> Result<(), error::NetProtoError>;
}

pub struct LandscapeCodec<T>(pub std::marker::PhantomData<T>);

impl<T> LandscapeCodec<T> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<T: NetProtoCodec> tokio_util::codec::Decoder for LandscapeCodec<T> {
    type Item = T;
    type Error = error::NetProtoError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<T>, Self::Error> {
        T::decode(src)
    }
}

impl<T: NetProtoCodec> tokio_util::codec::Encoder<T> for LandscapeCodec<T> {
    type Error = error::NetProtoError;

    fn encode(&mut self, item: T, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}

/// 暂时 pub 后续将所有协议的定义移动到 common
/// 二分查找第一个匹配条件的元素的索引
pub fn first<T, F>(slice: &[T], mut compare: F) -> Option<usize>
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

/// 暂时 pub 后续将所有协议的定义移动到 common
/// 二分查找所有匹配条件的元素的范围
pub fn range_binsearch<T, F>(slice: &[T], mut compare: F) -> Option<std::ops::Range<usize>>
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

#[macro_export]
macro_rules! define_options {
    ($name:ident, $code_type:ty, $len_type:ty, {
        $(
            {$code:expr, $variant:ident, $desc:expr, $data_type:ty},
        )*
    }) => {


    paste::paste! {
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

            #[allow(dead_code)]
            impl [<$name s>] {
                /// construct empty Options
                pub fn new() -> Self {
                    Self::default()
                }

                /// get the first element matching this option code
                pub fn get(&self, code: [<$name Code>]) -> Option<&$name> {
                    let first = crate::net_proto::first(&self.0, |x| {
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
                    let range = crate::net_proto::range_binsearch(&self.0, |x| {
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
                    let first = crate::net_proto::first(&self.0, |x| {
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
                    let range = crate::net_proto::range_binsearch(&self.0, |x| {
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
                    let first = crate::net_proto::first(&self.0, |x| {
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
                    let range = crate::net_proto::range_binsearch(&self.0, |x| {
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
