use hickory_proto::rr::{Record, RecordType};
use landscape_common::dns::rule::LandscapeDnsRecordType;

use crate::CommonRecord;

pub fn to_common_records(records: Vec<Record>) -> Vec<CommonRecord> {
    records
        .into_iter()
        .map(|r| {
            let data = format!("{}", r.data);
            CommonRecord {
                name: r.name.to_string(),
                rr_type: r.record_type().to_string(),
                ttl: r.ttl,
                data,
            }
        })
        .collect()
}

pub fn convert_record_type(record_type: LandscapeDnsRecordType) -> RecordType {
    match record_type {
        LandscapeDnsRecordType::A => RecordType::A,
        LandscapeDnsRecordType::AAAA => RecordType::AAAA,
        LandscapeDnsRecordType::HTTPS => RecordType::HTTPS,
    }
}
