use landscape_common::net_proto::udp::dhcp::v6::{DhcpOption, DhcpOptions, OptionCode, IAPD, ORO};

pub fn get_solicit_options() -> DhcpOptions {
    let mut options = DhcpOptions::new();
    let oro = ORO {
        opts: vec![OptionCode::IAPrefix, OptionCode::DomainNameServers],
    };

    let iapd = IAPD { id: 1, t1: 0, t2: 0, opts: DhcpOptions::new() };
    options.insert(DhcpOption::ORO(oro));
    options.insert(DhcpOption::IAPD(iapd));
    options.insert(DhcpOption::ReconfAccept);
    options
}
