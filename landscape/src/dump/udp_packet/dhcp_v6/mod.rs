use dhcproto::v6::{DhcpOption, DhcpOptions, OptionCode, ORO};

pub fn get_solicit_options() -> DhcpOptions {
    let mut options = DhcpOptions::new();
    let oro = ORO {
        opts: vec![OptionCode::DomainSearchList, OptionCode::IAPrefix],
    };

    // let iapd = IAPD { id: 0, t1: 0, t2: 0, opts: vec![] };
    options.insert(DhcpOption::ORO(oro));
    // options.insert(DhcpOption::IAPD(iapd));
    options.insert(DhcpOption::ReconfAccept);
    options
}
