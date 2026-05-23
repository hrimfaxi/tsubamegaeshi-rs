use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A as ARecord, AAAA as AAAARecord};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

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

    pub fn foreign_timeout_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FOREIGN-TIMEOUT",
            AddressQueryKind::Aaaa => "FOREIGN-TIMEOUT-AAAA",
            AddressQueryKind::Https => "FOREIGN-TIMEOUT-HTTPS",
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

/// 检测 IPv6 地址是否为已知 GFW 污染地址，例如 `2001::xxxx:yyyy`
pub fn is_ipv6_polluted(ip: &Ipv6Addr) -> bool {
    let bytes = ip.octets();

    if bytes[0] != 0x20 || bytes[1] != 0x01 {
        return false;
    }

    bytes[2..12].iter().all(|&b| b == 0)
}

pub fn extract_https_hints(answer: &Record) -> Vec<IpAddr> {
    if answer.record_type() != RecordType::HTTPS {
        return vec![];
    }
    if let Some(RData::SVCB(svcb)) = answer.data() {
        let mut ips = Vec::new();
        for (key, value) in svcb.svc_params() {
            match key {
                SvcParamKey::Ipv4Hint => {
                    if let SvcParamValue::Ipv4Hint(addrs) = value {
                        for a in addrs.0.iter() {
                            ips.push(IpAddr::V4(a.0));
                        }
                    }
                }
                SvcParamKey::Ipv6Hint => {
                    if let SvcParamValue::Ipv6Hint(addrs) = value {
                        for a in addrs.0.iter() {
                            ips.push(IpAddr::V6(a.0));
                        }
                    }
                }
                _ => {}
            }
        }
        ips
    } else {
        vec![]
    }
}

pub fn print_first_ip(resp: &[u8], tag: &str, domain: &str, upstream: &str) {
    if let Ok(msg) = Message::from_vec(resp) {
        // 优先打印 A/AAAA
        if let Some(rr) = msg
            .answers()
            .iter()
            .find(|rr| rr.record_type() == RecordType::A || rr.record_type() == RecordType::AAAA)
            .and_then(|rr| rr.data().and_then(|d| d.ip_addr()))
        {
            info!("[{}] {} -> {} = {}", tag, domain, upstream, rr);
            return;
        }
        // 否则打印 HTTPS 的第一个 hint
        if let Some(rr) = msg
            .answers()
            .iter()
            .find(|rr| rr.record_type() == RecordType::HTTPS)
        {
            let hints = extract_https_hints(rr);
            if let Some(ip) = hints.first() {
                info!("[{}] {} -> {} HTTPS hint: {}", tag, domain, upstream, ip);
                return;
            }
        }
    }
    warn!(
        "[{}] {} -> {} (no A/AAAA/HTTPS answer)",
        tag, domain, upstream
    );
}
