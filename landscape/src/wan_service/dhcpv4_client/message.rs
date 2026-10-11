use landscape_common::net::MacAddr;
use landscape_common::net_proto::dhcp::{
    DhcpV4Flags, DhcpV4Message, DhcpV4MessageType as MessageType, DhcpV4OpCode,
    DhcpV4Option as DhcpOption, DhcpV4OptionCode as OptionCode, DhcpV4Options,
};
use std::net::Ipv4Addr;

const REQUEST_PARAMS: [OptionCode; 10] = [
    OptionCode::SubnetMask,
    OptionCode::Router,
    OptionCode::DomainNameServer,
    OptionCode::DomainName,
    OptionCode::InterfaceMtu,
    OptionCode::BroadcastAddr,
    OptionCode::Hostname,
    OptionCode::NtpServers,
    OptionCode::AddressLeaseTime,
    OptionCode::DomainSearch,
];

pub(crate) fn gen_discover(
    xid: u32,
    mac_addr: MacAddr,
    requested_ip: Option<Ipv4Addr>,
    hostname: &str,
    use_broadcast: bool,
) -> DhcpV4Message {
    let mut msg = DhcpV4Message::default();
    msg.set_opcode(DhcpV4OpCode::BootRequest);
    msg.set_xid(xid);
    let mut flags = DhcpV4Flags::default();
    if use_broadcast || requested_ip.is_none() {
        flags = flags.set_broadcast();
    }
    msg.set_flags(flags);
    // RFC 2131 Table 5: DHCPDISCOVER 'ciaddr' must be 0; a remembered
    // address travels only in the 'requested IP address' option.
    msg.set_ciaddr(Ipv4Addr::UNSPECIFIED);
    msg.set_chaddr(&mac_addr.octets());

    msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
    if let Some(ip) = requested_ip {
        msg.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
    }
    msg.opts_mut().insert(DhcpOption::Hostname(hostname.to_string()));
    msg.opts_mut().insert(DhcpOption::ParameterRequestList(REQUEST_PARAMS.to_vec()));
    msg
}

pub(crate) fn gen_request(
    xid: u32,
    mac_addr: MacAddr,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    mut options: DhcpV4Options,
    hostname: &str,
) -> DhcpV4Message {
    let mut msg = DhcpV4Message::default();
    msg.set_opcode(DhcpV4OpCode::BootRequest);
    msg.set_xid(xid);

    msg.set_chaddr(&mac_addr.octets());

    msg.set_ciaddr(ciaddr);

    options.insert(DhcpOption::ClassIdentifier(b"MSFT 5.0".to_vec()));
    let mut client_id = vec![1u8];
    client_id.extend_from_slice(&mac_addr.octets());
    options.insert(DhcpOption::ClientIdentifier(client_id));

    options.insert(DhcpOption::MessageType(MessageType::Request));
    options.insert(DhcpOption::Hostname(hostname.to_string()));
    options.insert(DhcpOption::ParameterRequestList(REQUEST_PARAMS.to_vec()));

    if ciaddr.is_unspecified() {
        options.insert(DhcpOption::RequestedIpAddress(yiaddr));
        msg.set_flags(DhcpV4Flags::default().set_broadcast());
    } else {
        msg.set_flags(DhcpV4Flags::default());
    }

    *msg.opts_mut() = options;
    msg
}
