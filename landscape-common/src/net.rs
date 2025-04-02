use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// The number of bytes in an ethernet (MAC) address.
pub const ETHER_ADDR_LEN: usize = 6;

/// Structure of a 48-bit Ethernet address.
type EtherAddr = [u8; ETHER_ADDR_LEN];

const LOCAL_ADDR_BIT: u8 = 0x02;
const MULTICAST_ADDR_BIT: u8 = 0x01;

#[derive(Clone, Copy, Default, Hash, PartialOrd, Eq)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new `MacAddr` instance.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }

    /// Construct an all-zero `MacAddr` instance.
    pub fn zero() -> MacAddr {
        Default::default()
    }

    /// Construct a broadcast `MacAddr` instance.
    pub fn broadcast() -> MacAddr {
        [0xff; ETHER_ADDR_LEN].into()
    }

    /// Returns true if a `MacAddr` is an all-zero address.
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    /// Returns true if the MacAddr is a universally administered addresses (UAA).
    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }

    /// Returns true if the MacAddr is a locally administered addresses (LAA).
    pub fn is_local(&self) -> bool {
        (self.0 & LOCAL_ADDR_BIT) == LOCAL_ADDR_BIT
    }

    /// Returns true if the MacAddr is a unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true if the MacAddr is a multicast address.
    pub fn is_multicast(&self) -> bool {
        (self.0 & MULTICAST_ADDR_BIT) == MULTICAST_ADDR_BIT
    }

    /// Returns true if the MacAddr is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::broadcast()
    }

    /// Returns the six eight-bit integers that make up this address
    pub fn octets(&self) -> [u8; 6] {
        [self.0, self.1, self.2, self.3, self.4, self.5]
    }

    pub fn u32_ckecksum(&self) -> u32 {
        let mut sum = ((self.0 as u32) << 24)
            + ((self.1 as u32) << 16)
            + ((self.2 as u32) << 8)
            + self.3 as u32;
        sum += (((self.4 as u32) << 24) + (self.5 as u32)) << 16;
        sum
    }

    // TODO: Use Result instead
    pub fn from_str(value: &str) -> Option<MacAddr> {
        let parts: Vec<&str> = value.split(|c| c == ':' || c == '-').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if let Ok(num) = u8::from_str_radix(part, 16) {
                bytes[i] = num;
            } else {
                return None;
            }
        }

        Some(MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
    }
}

impl From<EtherAddr> for MacAddr {
    fn from(addr: EtherAddr) -> MacAddr {
        MacAddr(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }
}

impl From<MacAddr> for EtherAddr {
    fn from(addr: MacAddr) -> Self {
        [addr.0, addr.1, addr.2, addr.3, addr.4, addr.5]
    }
}

impl PartialEq<EtherAddr> for MacAddr {
    fn eq(&self, other: &EtherAddr) -> bool {
        *self == MacAddr::from(*other)
    }
}

impl PartialEq<MacAddr> for MacAddr {
    fn eq(&self, other: &MacAddr) -> bool {
        self.0 == other.0
            && self.1 == other.1
            && self.2 == other.2
            && self.3 == other.3
            && self.4 == other.4
            && self.5 == other.5
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}
impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MacAddrVisitor;

        impl<'de> serde::de::Visitor<'de> for MacAddrVisitor {
            type Value = MacAddr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string in the format 'xx:xx:xx:xx:xx:xx'")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parts: Vec<_> = s.split(':').collect();
                if parts.len() != 6 {
                    return Err(serde::de::Error::invalid_length(parts.len(), &"6"));
                }
                let mut bytes = [0; 6];
                for (i, part) in parts.iter().enumerate() {
                    bytes[i] = u8::from_str_radix(part, 16)
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?;
                }
                Ok(MacAddr(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
            }
        }

        deserializer.deserialize_str(MacAddrVisitor)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}
