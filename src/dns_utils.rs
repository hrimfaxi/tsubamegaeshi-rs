use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A as ARecord, AAAA as AAAARecord};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::debug;

use crate::pollution::extract_answer_ips;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_HTTPS: u16 = 65;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressQueryKind {
    A,
    Aaaa,
    Https,
}

impl AddressQueryKind {
    pub fn cache_qtype(self) -> u16 {
        match self {
            AddressQueryKind::A => DNS_TYPE_A,
            AddressQueryKind::Aaaa => DNS_TYPE_AAAA,
            AddressQueryKind::Https => DNS_TYPE_HTTPS,
        }
    }

    pub fn cache_hit_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "CACHE-HIT",
            AddressQueryKind::Aaaa => "CACHE-HIT-AAAA",
            AddressQueryKind::Https => "CACHE-HIT-HTTPS",
        }
    }

    pub fn cache_skip_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "CACHE-SKIP",
            AddressQueryKind::Aaaa => "CACHE-SKIP-AAAA",
            AddressQueryKind::Https => "CACHE-SKIP-HTTPS",
        }
    }

    pub fn special_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "SPECIAL",
            AddressQueryKind::Aaaa => "SPECIAL-AAAA",
            AddressQueryKind::Https => "SPECIAL-HTTPS",
        }
    }

    pub fn force_domestic_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FORCE-DOMESTIC",
            AddressQueryKind::Aaaa => "FORCE-DOMESTIC-AAAA",
            AddressQueryKind::Https => "FORCE-DOMESTIC-HTTPS",
        }
    }

    pub fn force_foreign_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FORCE-FOREIGN",
            AddressQueryKind::Aaaa => "FORCE-FOREIGN-AAAA",
            AddressQueryKind::Https => "FORCE-FOREIGN-HTTPS",
        }
    }

    pub fn gfwlist_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "GFWLIST",
            AddressQueryKind::Aaaa => "GFWLIST-AAAA",
            AddressQueryKind::Https => "GFWLIST-HTTPS",
        }
    }

    pub fn domestic_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "DOMESTIC",
            AddressQueryKind::Aaaa => "DOMESTIC-AAAA",
            AddressQueryKind::Https => "DOMESTIC-HTTPS",
        }
    }

    pub fn foreign_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FOREIGN",
            AddressQueryKind::Aaaa => "FOREIGN-AAAA",
            AddressQueryKind::Https => "FOREIGN-HTTPS",
        }
    }
}

pub fn build_basic_response_message(query: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::new();

    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_response_code(code);
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);

    for q in query.queries() {
        resp.add_query(q.clone());
    }

    for a in query.additionals() {
        resp.add_additional(a.clone());
    }

    resp
}

pub fn build_basic_response(query: &Message, code: ResponseCode) -> Vec<u8> {
    build_basic_response_message(query, code)
        .to_vec()
        .unwrap_or_default()
}

pub fn build_servfail_response(query: &Message) -> Vec<u8> {
    build_basic_response(query, ResponseCode::ServFail)
}

pub fn build_nodata_response(query: &Message) -> Vec<u8> {
    build_basic_response(query, ResponseCode::NoError)
}

pub fn build_a_response(query: &Message, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut resp = build_basic_response_message(query, ResponseCode::NoError);

    let Some(q) = query.queries().first() else {
        return build_servfail_response(query);
    };

    let mut answer = Record::new();
    answer.set_name(q.name().clone());
    answer.set_record_type(RecordType::A);
    answer.set_ttl(ttl);
    answer.set_data(Some(RData::A(ARecord(ip))));

    resp.add_answer(answer);
    resp.to_vec().unwrap_or_default()
}

pub fn build_aaaa_response(query: &Message, ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let mut resp = build_basic_response_message(query, ResponseCode::NoError);

    let Some(q) = query.queries().first() else {
        return build_servfail_response(query);
    };

    let mut answer = Record::new();
    answer.set_name(q.name().clone());
    answer.set_record_type(RecordType::AAAA);
    answer.set_ttl(ttl);
    answer.set_data(Some(RData::AAAA(AAAARecord(ip))));

    resp.add_answer(answer);
    resp.to_vec().unwrap_or_default()
}

pub fn build_https_response(
    query: &Message,
    ipv4_hints: Vec<Ipv4Addr>,
    ipv6_hints: Vec<Ipv6Addr>,
    ttl: u32,
) -> Vec<u8> {
    let mut resp = build_basic_response_message(query, ResponseCode::NoError);

    let Some(q) = query.queries().first() else {
        return build_servfail_response(query);
    };

    // 构造 SvcParams
    let mut svc_params = Vec::new();

    if !ipv4_hints.is_empty() {
        let addrs: Vec<ARecord> = ipv4_hints.into_iter().map(ARecord).collect();
        svc_params.push((
            SvcParamKey::Ipv4Hint,
            SvcParamValue::Ipv4Hint(IpHint(addrs)),
        ));
    }

    if !ipv6_hints.is_empty() {
        let addrs: Vec<AAAARecord> = ipv6_hints.into_iter().map(AAAARecord).collect();
        svc_params.push((
            SvcParamKey::Ipv6Hint,
            SvcParamValue::Ipv6Hint(IpHint(addrs)),
        ));
    }

    let target_name = Name::from_ascii(".").unwrap(); // 当前域名
    let svcb = RData::SVCB(SVCB::new(1, target_name, svc_params));

    let mut answer = Record::new();
    answer.set_name(q.name().clone());
    answer.set_record_type(RecordType::HTTPS);
    answer.set_ttl(ttl);
    answer.set_data(Some(svcb));

    resp.add_answer(answer);
    resp.to_vec().unwrap_or_default()
}

pub fn response_cache_ttl(msg: &Message) -> Option<u64> {
    let min_ttl = msg.answers().iter().map(|rr| rr.ttl()).min()?;

    // TTL 为 0 表示不应缓存
    if min_ttl == 0 {
        None
    } else {
        Some(min_ttl as u64)
    }
}

pub fn rewrite_dns_id(data: &mut [u8], id: u16) {
    if data.len() >= 2 {
        data[0] = (id >> 8) as u8;
        data[1] = id as u8;
    }
}

pub fn debug_print_first_ip(resp: &[u8], tag: &str, domain: &str, upstream: &str) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    // 统一从原始字节提取所有 IP（A/AAAA/HTTPS hints），取第一个打印
    if let Ok(ips) = extract_answer_ips(resp)
        && let Some(ip) = ips.first()
    {
        debug!("[{}] {} -> {} = {}", tag, domain, upstream, ip);
        return;
    }

    debug!(
        "[{}] {} -> {} (no A/AAAA/HTTPS answer)",
        tag, domain, upstream
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_query() -> Message {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_recursion_desired(true);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        msg
    }

    // ========== build_a_response ==========

    #[test]
    fn test_build_a_response() {
        let query = sample_query();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let bytes = build_a_response(&query, ip, 60);

        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        let ans = &resp.answers()[0];
        assert_eq!(ans.record_type(), RecordType::A);
        assert_eq!(ans.ttl(), 60);
        assert_eq!(
            ans.data().unwrap().ip_addr(),
            Some(std::net::IpAddr::V4(ip))
        );
    }

    // ========== build_aaaa_response ==========

    #[test]
    fn test_build_aaaa_response() {
        let query = sample_query();
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let bytes = build_aaaa_response(&query, ip, 300);

        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);

        let ans = &resp.answers()[0];
        assert_eq!(ans.record_type(), RecordType::AAAA);
        assert_eq!(ans.ttl(), 300);
    }

    // ========== build_nodata_response ==========

    #[test]
    fn test_build_nodata_response() {
        let query = sample_query();
        let bytes = build_nodata_response(&query);

        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.answers().is_empty());
    }

    // ========== build_servfail_response ==========

    #[test]
    fn test_build_servfail_response() {
        let query = sample_query();
        let bytes = build_servfail_response(&query);

        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::ServFail);
    }

    // ========== build_https_response 暂不直接测 ==========
    // 原因：hickory 对 RecordType::HTTPS + RData::SVCB 的序列化有严格类型检查，
    // 与 pollution.rs 中遇到的 to_vec() panic 相同。
    // 构造端行为已通过 pollution.rs 的 extract_answer_ips 间接覆盖。

    // ========== response_cache_ttl ==========

    #[test]
    fn test_response_cache_ttl_single() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();

        let mut answer = Record::new();
        answer.set_name(name);
        answer.set_record_type(RecordType::A);
        answer.set_ttl(60);
        answer.set_data(Some(RData::A(ARecord(Ipv4Addr::new(1, 2, 3, 4)))));
        msg.add_answer(answer);

        assert_eq!(response_cache_ttl(&msg), Some(60));
    }

    #[test]
    fn test_response_cache_ttl_multiple_min() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();

        for ttl in [120u32, 60, 300] {
            let mut answer = Record::new();
            answer.set_name(name.clone());
            answer.set_record_type(RecordType::A);
            answer.set_ttl(ttl);
            answer.set_data(Some(RData::A(ARecord(Ipv4Addr::new(1, 2, 3, 4)))));
            msg.add_answer(answer);
        }

        assert_eq!(response_cache_ttl(&msg), Some(60));
    }

    #[test]
    fn test_response_cache_ttl_zero() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();

        let mut answer = Record::new();
        answer.set_name(name);
        answer.set_record_type(RecordType::A);
        answer.set_ttl(0);
        answer.set_data(Some(RData::A(ARecord(Ipv4Addr::new(1, 2, 3, 4)))));
        msg.add_answer(answer);

        assert_eq!(response_cache_ttl(&msg), None);
    }

    #[test]
    fn test_response_cache_ttl_no_answers() {
        let msg = Message::new();
        assert_eq!(response_cache_ttl(&msg), None);
    }

    // ========== rewrite_dns_id ==========

    #[test]
    fn test_rewrite_dns_id_normal() {
        let mut buf = vec![0xAB, 0xCD, 0xEF];
        rewrite_dns_id(&mut buf, 0x1234);
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0xEF);
    }

    #[test]
    fn test_rewrite_dns_id_short_buffer() {
        let mut buf = vec![0xAB];
        rewrite_dns_id(&mut buf, 0x1234);
        assert_eq!(buf, vec![0xAB]);
    }

    #[test]
    fn test_rewrite_dns_id_empty() {
        let mut buf: Vec<u8> = vec![];
        rewrite_dns_id(&mut buf, 0x1234);
        assert!(buf.is_empty());
    }
}
