// SNI Proxy module — TLS passthrough based on ClientHello SNI
//
// This module will implement:
// 1. Peeking the TLS ClientHello to extract the SNI extension
// 2. Matching the SNI domain against SniProxy rules
// 3. Connecting to the matched upstream backend
// 4. Splicing the TLS connection bidirectionally (without decryption)
//
// Implementation will be added when Pingora's TCP proxy support is integrated.
// For now, this module serves as a placeholder for the SNI proxy architecture.

use landscape_common::config::gateway::{HttpUpstreamMatchRule, HttpUpstreamRuleConfig};

/// Extract SNI proxy rules from the full rule set.
pub fn filter_sni_rules(rules: &[HttpUpstreamRuleConfig]) -> Vec<&HttpUpstreamRuleConfig> {
    rules
        .iter()
        .filter(|r| r.enable && matches!(r.match_rule, HttpUpstreamMatchRule::SniProxy { .. }))
        .collect()
}

/// Parse the SNI (Server Name Indication) extension from a TLS ClientHello message.
///
/// The function peeks at the raw bytes without consuming them.
/// Returns `Some(hostname)` if a valid SNI extension is found, `None` otherwise.
pub fn parse_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    // TLS record header: ContentType(1) + Version(2) + Length(2)
    if buf.len() < 5 {
        return None;
    }
    // ContentType must be Handshake (0x16)
    if buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }

    let handshake = &buf[5..5 + record_len];
    // Handshake type must be ClientHello (0x01)
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }
    if handshake.len() < 4 {
        return None;
    }
    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    // Skip: Version(2) + Random(32) = 34 bytes
    if ch.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID
    if pos >= ch.len() {
        return None;
    }
    let session_id_len = ch[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher Suites
    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression Methods
    if pos >= ch.len() {
        return None;
    }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(&ch[pos..pos + ext_data_len]);
        }
        pos += ext_data_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let mut pos = 2;
    let end = 2 + list_len;
    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if name_type == 0x00 && pos + name_len <= end {
            // HostName type
            return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
        }
        pos += name_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_sni_rules_empty() {
        let rules: Vec<HttpUpstreamRuleConfig> = vec![];
        assert!(filter_sni_rules(&rules).is_empty());
    }
}
