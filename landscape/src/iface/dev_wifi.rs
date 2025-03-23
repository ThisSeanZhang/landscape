use serde::{Deserialize, Serialize};
use wl_nl80211::Nl80211Message;

/// 当前硬件状态结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LandScapeWifiInterface {
    pub name: String,
    pub index: u32,
    pub wifi_type: WLANType,
}

impl LandScapeWifiInterface {
    pub fn new(msg: Nl80211Message) -> Option<LandScapeWifiInterface> {
        let mut name = None;
        let mut index = None;
        let mut wifi_type = None;
        for nla in msg.attributes.into_iter() {
            match nla {
                wl_nl80211::Nl80211Attr::IfIndex(i) => index = Some(i),
                wl_nl80211::Nl80211Attr::IfName(n) => name = Some(n),
                // wl_nl80211::Nl80211Attr::Mac(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Wiphy(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyName(_) => todo!(),
                wl_nl80211::Nl80211Attr::IfType(nl80211_interface_type) => {
                    wifi_type = Some(nl80211_interface_type.into())
                }
                // wl_nl80211::Nl80211Attr::IfTypeExtCap(nl80211_if_type_ext_capas) => todo!(),
                // wl_nl80211::Nl80211Attr::MacAddrs(items) => todo!(),
                // wl_nl80211::Nl80211Attr::Wdev(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Generation(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Use4Addr(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyFreq(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyFreqOffset(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyChannelType(nl80211_ht_wiphy_channel_type) => todo!(),
                // wl_nl80211::Nl80211Attr::ChannelWidth(nl80211_channel_width) => todo!(),
                // wl_nl80211::Nl80211Attr::CenterFreq1(_) => todo!(),
                // wl_nl80211::Nl80211Attr::CenterFreq2(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyTxPowerLevel(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Ssid(_) => todo!(),
                // wl_nl80211::Nl80211Attr::StationInfo(nl80211_station_infos) => todo!(),
                // wl_nl80211::Nl80211Attr::TransmitQueueStats(nl80211_transmit_queue_stats) => {
                //     todo!()
                // }
                // wl_nl80211::Nl80211Attr::TransmitQueueLimit(_) => todo!(),
                // wl_nl80211::Nl80211Attr::TransmitQueueMemoryLimit(_) => todo!(),
                // wl_nl80211::Nl80211Attr::TransmitQueueQuantum(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MloLinks(nl80211_mlo_links) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyRetryShort(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyRetryLong(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyFragThreshold(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyRtsThreshold(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyCoverageClass(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxNumScanSsids(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxNumSchedScanSsids(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxScanIeLen(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxSchedScanIeLen(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxMatchSets(_) => todo!(),
                // wl_nl80211::Nl80211Attr::SupportIbssRsn => todo!(),
                // wl_nl80211::Nl80211Attr::SupportMeshAuth => todo!(),
                // wl_nl80211::Nl80211Attr::SupportApUapsd => todo!(),
                // wl_nl80211::Nl80211Attr::RoamSupport => todo!(),
                // wl_nl80211::Nl80211Attr::TdlsSupport => todo!(),
                // wl_nl80211::Nl80211Attr::TdlsExternalSetup => todo!(),
                // wl_nl80211::Nl80211Attr::CipherSuites(nl80211_cipher_suits) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxNumPmkids(_) => todo!(),
                // wl_nl80211::Nl80211Attr::ControlPortEthertype => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyAntennaAvailTx(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyAntennaAvailRx(_) => todo!(),
                // wl_nl80211::Nl80211Attr::ApProbeRespOffload(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyAntennaTx(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyAntennaRx(_) => todo!(),
                // wl_nl80211::Nl80211Attr::SupportedIftypes(nl80211_if_modes) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphyBands(nl80211_bands) => todo!(),
                // wl_nl80211::Nl80211Attr::SplitWiphyDump => todo!(),
                // wl_nl80211::Nl80211Attr::SupportedCommand(nl80211_commands) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxRemainOnChannelDuration(_) => todo!(),
                // wl_nl80211::Nl80211Attr::OffchannelTxOk => todo!(),
                // wl_nl80211::Nl80211Attr::WowlanTrigersSupport(nl80211_wowlan_trigers_supports) => {
                //     todo!()
                // }
                // wl_nl80211::Nl80211Attr::SoftwareIftypes(nl80211_interface_types) => todo!(),
                // wl_nl80211::Nl80211Attr::Features(nl80211_features) => todo!(),
                // wl_nl80211::Nl80211Attr::ExtFeatures(nl80211_ext_features) => todo!(),
                // wl_nl80211::Nl80211Attr::InterfaceCombination(nl80211_iface_combs) => todo!(),
                // wl_nl80211::Nl80211Attr::HtCapabilityMask(nl80211_ht_capability_mask) => todo!(),
                // wl_nl80211::Nl80211Attr::TxFrameTypes(nl80211_iface_frame_types) => todo!(),
                // wl_nl80211::Nl80211Attr::RxFrameTypes(nl80211_iface_frame_types) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxNumSchedScanPlans(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxScanPlanInterval(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxScanPlanIterations(_) => todo!(),
                // wl_nl80211::Nl80211Attr::ExtCap(nl80211_extended_capability) => todo!(),
                // wl_nl80211::Nl80211Attr::ExtCapMask(nl80211_extended_capability) => todo!(),
                // wl_nl80211::Nl80211Attr::VhtCap(nl80211_vht_capability) => todo!(),
                // wl_nl80211::Nl80211Attr::VhtCapMask(nl80211_vht_capability) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxCsaCounters(_) => todo!(),
                // wl_nl80211::Nl80211Attr::WiphySelfManagedReg => todo!(),
                // wl_nl80211::Nl80211Attr::SchedScanMaxReqs(_) => todo!(),
                // wl_nl80211::Nl80211Attr::EmlCapability(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MldCapaAndOps(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Bands(nl80211_band_types) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxNumAkmSuites(_) => todo!(),
                // wl_nl80211::Nl80211Attr::MaxHwTimestampPeers(_) => todo!(),
                // wl_nl80211::Nl80211Attr::Other(default_nla) => todo!(),
                _ => {}
            }
            // println!("{:?}", nla);
        }

        match (index, name, wifi_type) {
            (Some(index), Some(name), Some(wifi_type)) => {
                Some(LandScapeWifiInterface { name, index, wifi_type })
            }
            _ => None,
        }
    }
}

/// 无线接口类型
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t")]
pub enum WLANType {
    Unspecified,
    Adhoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u32),
}

impl Into<WLANType> for wl_nl80211::Nl80211InterfaceType {
    fn into(self) -> WLANType {
        match self {
            wl_nl80211::Nl80211InterfaceType::Unspecified => WLANType::Unspecified,
            wl_nl80211::Nl80211InterfaceType::Adhoc => WLANType::Adhoc,
            wl_nl80211::Nl80211InterfaceType::Station => WLANType::Station,
            wl_nl80211::Nl80211InterfaceType::Ap => WLANType::Ap,
            wl_nl80211::Nl80211InterfaceType::ApVlan => WLANType::ApVlan,
            wl_nl80211::Nl80211InterfaceType::Wds => WLANType::Wds,
            wl_nl80211::Nl80211InterfaceType::Monitor => WLANType::Monitor,
            wl_nl80211::Nl80211InterfaceType::MeshPoint => WLANType::MeshPoint,
            wl_nl80211::Nl80211InterfaceType::P2pClient => WLANType::P2pClient,
            wl_nl80211::Nl80211InterfaceType::P2pGo => WLANType::P2pGo,
            wl_nl80211::Nl80211InterfaceType::P2pDevice => WLANType::P2pDevice,
            wl_nl80211::Nl80211InterfaceType::Ocb => WLANType::Ocb,
            wl_nl80211::Nl80211InterfaceType::Nan => WLANType::Nan,
            wl_nl80211::Nl80211InterfaceType::Other(n) => WLANType::Other(n),
        }
    }
}
