use anyhow::{Result, anyhow, bail};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PollutionChecker {
    pub v4: HashSet<Ipv4Addr>,
    pub v6: HashSet<Ipv6Addr>,
    pub max_packets: usize,
}

#[derive(Debug, PartialEq)]
pub enum PollutionResult {
    Clean,
    Polluted,
    Invalid,
}

impl PollutionChecker {
    /// 完整检查：从原始字节提取所有 IP（A / AAAA / HTTPS hints）
    pub fn check(&self, resp: &[u8]) -> PollutionResult {
        match extract_answer_ips(resp) {
            Ok(ips) => {
                for ip in ips {
                    match ip {
                        IpAddr::V4(v4) => {
                            if self.v4.contains(&v4) {
                                return PollutionResult::Polluted;
                            }
                        }
                        IpAddr::V6(v6) => {
                            if is_gfw_ipv6(&v6) || self.v6.contains(&v6) {
                                return PollutionResult::Polluted;
                            }
                        }
                    }
                }
                PollutionResult::Clean
            }
            Err(_) => PollutionResult::Invalid,
        }
    }

    /// 检查单个 IPv4 是否在污染列表中
    #[allow(dead_code)]
    pub fn is_ipv4_polluted(&self, ip: &Ipv4Addr) -> bool {
        self.v4.contains(ip)
    }

    /// 检查单个 IPv6 是否命中 GFW 硬编码特征或污染列表
    pub fn is_ipv6_polluted(&self, ip: &Ipv6Addr) -> bool {
        is_gfw_ipv6(ip) || self.v6.contains(ip)
    }
}

/// 检测 IPv6 地址是否为已知 GFW 污染地址（前缀 2001:: 且中间 10 字节全零）
fn is_gfw_ipv6_legacy(ip: &Ipv6Addr) -> bool {
    let bytes = ip.octets();
    bytes.starts_with(&[0x20, 0x01]) && bytes[2..12].iter().all(|&b| b == 0)
}

/// 新式 GFW 污染：借用 Meta 前缀 2a03:2880，但后 64 位固定为 face:b00c:0:25de
/// 中间两段 (seg[2] << 16 | seg[3]) 必须是以下 30 个精确值之一。
/// 数组已按升序排列，供 binary_search 直接使用。
/// 加入新的地址一定要排序
const FB_COMBOS: [u32; 30] = [
    0xf102_0183,
    0xf107_0083,
    0xf10a_0083,
    0xf10c_0083,
    0xf10c_0283,
    0xf10d_0083,
    0xf10d_0183,
    0xf10e_0083,
    0xf10f_0083,
    0xf111_0083,
    0xf112_0083,
    0xf117_0083,
    0xf11a_0083,
    0xf11b_0083,
    0xf11c_8083,
    0xf11c_8183,
    0xf11f_0083,
    0xf126_0083,
    0xf127_0083,
    0xf127_0283,
    0xf129_0083,
    0xf12a_0083,
    0xf12c_0083,
    0xf12c_0183,
    0xf12d_0083,
    0xf130_0083,
    0xf131_0083,
    0xf134_0083,
    0xf134_0183,
    0xf136_0083,
];

fn is_gfw_ipv6_facebook(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    if s[0] != 0x2a03
        || s[1] != 0x2880
        || s[4] != 0xface
        || s[5] != 0xb00c
        || s[6] != 0x0000
        || s[7] != 0x25de
    {
        return false;
    }
    let key = ((s[2] as u32) << 16) | (s[3] as u32);
    FB_COMBOS.binary_search(&key).is_ok()
}

pub fn is_gfw_ipv6(ip: &Ipv6Addr) -> bool {
    is_gfw_ipv6_facebook(ip) || is_gfw_ipv6_legacy(ip)
}

// === DNS 类型常量 ===
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_HTTPS: u16 = 65;

// === SvcParam Key 常量 ===
const SVC_PARAM_IPV4HINT: u16 = 4;
const SVC_PARAM_IPV6HINT: u16 = 6;

const DNS_HEADER_LEN: usize = 12;

fn parse_dns_header(buf: &[u8]) -> Option<(u16, u16, u16, u16)> {
    if buf.len() < DNS_HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    Some((id, flags, qdcount, ancount))
}

fn skip_dns_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut p = start;
    loop {
        let len = *buf.get(p)?;
        match len {
            0 => return Some(p + 1),
            len if (len & 0xC0) == 0xC0 => {
                buf.get(p + 1)?;
                return Some(p + 2);
            }
            len if len <= 63 => {
                p = p.checked_add(1 + len as usize)?;
            }
            _ => return None,
        }
    }
}

fn skip_question(buf: &[u8], start: usize) -> Option<usize> {
    let mut p = skip_dns_name(buf, start)?;
    p = p.checked_add(4)?;
    buf.get(..p)?;
    Some(p)
}

/// 解析一个 answer RR，返回 (rr_type, rdata_offset, rdlen)
fn parse_answer(buf: &[u8], start: usize) -> Option<(u16, usize, usize)> {
    let p = skip_dns_name(buf, start)?;

    // 保证 TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 字节都在包内
    let fixed_end = p.checked_add(10)?;
    if fixed_end > buf.len() {
        return None;
    }

    let rr_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
    let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;

    let rdata_offset = fixed_end;
    let end = rdata_offset.checked_add(rdlen)?;
    if end > buf.len() {
        return None;
    }

    Some((rr_type, rdata_offset, rdlen))
}

/// 解析 HTTPS/SVCB RR 中的 ipv4hint / ipv6hint
fn parse_https_rr_hints(buf: &[u8], svcparams_start: usize, rdlen: usize) -> Result<Vec<IpAddr>> {
    let mut p = svcparams_start;
    let end = p
        .checked_add(rdlen)
        .ok_or_else(|| anyhow!("rdlen overflow"))?;

    if end > buf.len() {
        bail!("svcparams exceeds packet boundary");
    }

    let mut ips = Vec::new();

    while p.checked_add(4).is_some_and(|next| next <= end) {
        let key = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p = p.checked_add(4).ok_or_else(|| anyhow!("offset overflow"))?;

        if p.checked_add(len).is_none_or(|next| next > end) {
            bail!("svcparam length exceeds rdata");
        }

        let value_start = p;
        match key {
            SVC_PARAM_IPV4HINT => {
                if !len.is_multiple_of(4) {
                    bail!("invalid ipv4hint length {}", len);
                }
                for chunk in buf[value_start..value_start + len].chunks_exact(4) {
                    let addr = Ipv4Addr::from(<[u8; 4]>::try_from(chunk)?);
                    ips.push(IpAddr::V4(addr));
                }
            }
            SVC_PARAM_IPV6HINT => {
                if !len.is_multiple_of(16) {
                    bail!("invalid ipv6hint length {}", len);
                }
                for chunk in buf[value_start..value_start + len].chunks_exact(16) {
                    let addr = Ipv6Addr::from(<[u8; 16]>::try_from(chunk)?);
                    ips.push(IpAddr::V6(addr));
                }
            }
            _ => {}
        }
        p = p
            .checked_add(len)
            .ok_or_else(|| anyhow!("offset overflow"))?;
    }
    Ok(ips)
}

/// 从 DNS 响应的 Answer section 中提取 IP（A / AAAA / HTTPS hints）
/// Ok([]) 表示解析成功但 Answer 中无 IP（如 NODATA/NXDOMAIN）
/// Err(...) 表示包格式损坏
pub fn extract_answer_ips(resp: &[u8]) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();

    let (_, _, qdcount, ancount) =
        parse_dns_header(resp).ok_or_else(|| anyhow!("dns header too short"))?;

    let mut p = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        p = skip_question(resp, p).ok_or_else(|| anyhow!("invalid question section"))?;
    }

    for _ in 0..ancount {
        let (rr_type, rdata_offset, rdlen) =
            parse_answer(resp, p).ok_or_else(|| anyhow!("invalid answer section"))?;

        match rr_type {
            DNS_TYPE_A if rdlen == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::from([
                    resp[rdata_offset],
                    resp[rdata_offset + 1],
                    resp[rdata_offset + 2],
                    resp[rdata_offset + 3],
                ])));
            }
            DNS_TYPE_AAAA if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&resp[rdata_offset..rdata_offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            DNS_TYPE_HTTPS if rdlen >= 2 => {
                let rdata_end = rdata_offset + rdlen;
                let targetname_start = rdata_offset + 2;

                let targetname_end = match skip_dns_name(resp, targetname_start) {
                    Some(v) if v <= rdata_end => v,
                    _ => {
                        p = rdata_end;
                        continue;
                    }
                };

                let svcparams_len = rdata_end - targetname_end;

                if svcparams_len > 0
                    && let Ok(hints) = parse_https_rr_hints(resp, targetname_end, svcparams_len)
                {
                    ips.extend(hints);
                }
            }
            _ => {}
        }

        p = rdata_offset + rdlen;
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A as ARecord, AAAA as AAAARecord};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ========== helpers: 用 hickory 构造 A/AAAA/空答案包 ==========

    fn a_packet(ip: Ipv4Addr) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));

        let mut answer = Record::new();
        answer.set_name(name);
        answer.set_record_type(RecordType::A);
        answer.set_ttl(300);
        answer.set_data(Some(RData::A(ARecord(ip))));
        msg.add_answer(answer);

        msg.to_vec().unwrap()
    }

    fn aaaa_packet(ip: Ipv6Addr) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::AAAA));

        let mut answer = Record::new();
        answer.set_name(name);
        answer.set_record_type(RecordType::AAAA);
        answer.set_ttl(300);
        answer.set_data(Some(RData::AAAA(AAAARecord(ip))));
        msg.add_answer(answer);

        msg.to_vec().unwrap()
    }

    fn empty_answers_packet() -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_vec().unwrap()
    }

    // ========== helper: 手写 HTTPS/SVCB 响应字节数组 ==========
    // hickory 序列化时拒绝 RecordType::HTTPS + RData::SVCB，故直接手写 wire format

    fn https_raw_packet(v4s: &[Ipv4Addr], v6s: &[Ipv6Addr]) -> Vec<u8> {
        let mut buf = Vec::new();

        // DNS Header (12 bytes)
        buf.extend_from_slice(&[
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: Response, NoError
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ]);

        // Question: example.com
        buf.push(7);
        buf.extend_from_slice(b"example");
        buf.push(3);
        buf.extend_from_slice(b"com");
        buf.push(0);
        buf.extend_from_slice(&[0x00, 65, 0x00, 0x01]); // Type HTTPS(65), Class IN

        // Answer
        // Name: pointer to question name at offset 12 (0x0C)
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0x00, 65, 0x00, 0x01]); // Type HTTPS, Class IN
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300

        // RData: SVCB
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[0x00, 0x01]); // SvcPriority 1
        rdata.push(0); // TargetName root (0x00)

        for ip in v4s {
            rdata.extend_from_slice(&[0x00, 0x04]); // key = ipv4hint
            rdata.extend_from_slice(&[0x00, 0x04]); // len = 4
            rdata.extend_from_slice(&ip.octets());
        }

        for ip in v6s {
            rdata.extend_from_slice(&[0x00, 0x06]); // key = ipv6hint
            rdata.extend_from_slice(&[0x00, 0x10]); // len = 16
            rdata.extend_from_slice(&ip.octets());
        }

        let rdlen = rdata.len() as u16;
        buf.extend_from_slice(&rdlen.to_be_bytes());
        buf.extend_from_slice(&rdata);

        buf
    }

    // ========== is_gfw_ipv6 ==========

    #[test]
    fn test_is_gfw_ipv6_hit() {
        let ip = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1); // 2001::1
        assert!(is_gfw_ipv6(&ip));
    }

    #[test]
    fn test_is_gfw_ipv6_miss() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        assert!(!is_gfw_ipv6(&ip));
    }

    // ========== extract_answer_ips 正常路径 ==========

    #[test]
    fn test_extract_a_record() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let bytes = a_packet(ip);
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(result, vec![IpAddr::V4(ip)]);
    }

    #[test]
    fn test_extract_aaaa_record() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let bytes = aaaa_packet(ip);
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(result, vec![IpAddr::V6(ip)]);
    }

    #[test]
    fn test_extract_multiple_a_records() {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));

        for ip in [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)] {
            let mut answer = Record::new();
            answer.set_name(name.clone());
            answer.set_record_type(RecordType::A);
            answer.set_ttl(300);
            answer.set_data(Some(RData::A(ARecord(ip))));
            msg.add_answer(answer);
        }

        let bytes = msg.to_vec().unwrap();
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(
            result,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ]
        );
    }

    #[test]
    fn test_extract_https_ipv4hint() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let bytes = https_raw_packet(&[ip], &[]);
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(result, vec![IpAddr::V4(ip)]);
    }

    #[test]
    fn test_extract_https_ipv6hint() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let bytes = https_raw_packet(&[], &[ip]);
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(result, vec![IpAddr::V6(ip)]);
    }

    #[test]
    fn test_extract_https_both_hints() {
        let v4 = Ipv4Addr::new(1, 2, 3, 4);
        let v6 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let bytes = https_raw_packet(&[v4], &[v6]);
        let result = extract_answer_ips(&bytes).unwrap();
        assert_eq!(result, vec![IpAddr::V4(v4), IpAddr::V6(v6)]);
    }

    #[test]
    fn test_extract_empty_answers() {
        let bytes = empty_answers_packet();
        let result = extract_answer_ips(&bytes).unwrap();
        assert!(result.is_empty());
    }

    // ========== extract_answer_ips 异常路径 ==========

    #[test]
    fn test_extract_header_too_short() {
        let result = extract_answer_ips(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_invalid_question() {
        let mut buf = vec![0u8; 12];
        buf[4] = 0;
        buf[5] = 1; // qdcount = 1, but no question data
        let result = extract_answer_ips(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_invalid_answer() {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        let mut buf = msg.to_vec().unwrap();
        buf[6] = 0;
        buf[7] = 1; // ancount = 1, but no actual answer
        let result = extract_answer_ips(&buf);
        assert!(result.is_err());
    }

    // ========== PollutionChecker::check ==========

    #[test]
    fn test_checker_polluted_ipv4() {
        let v4 = HashSet::from([Ipv4Addr::new(1, 2, 3, 4)]);
        let checker = PollutionChecker {
            v4,
            v6: HashSet::new(),
            max_packets: 5,
        };
        let resp = a_packet(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(checker.check(&resp), PollutionResult::Polluted);
    }

    #[test]
    fn test_checker_polluted_ipv6_list() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let v6 = HashSet::from([ip]);
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6,
            max_packets: 5,
        };
        let resp = aaaa_packet(ip);
        assert_eq!(checker.check(&resp), PollutionResult::Polluted);
    }

    #[test]
    fn test_checker_polluted_ipv6_gfw() {
        let ip = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1); // GFW 特征地址
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        };
        let resp = aaaa_packet(ip);
        assert_eq!(checker.check(&resp), PollutionResult::Polluted);
    }

    #[test]
    fn test_checker_clean() {
        let checker = PollutionChecker {
            v4: HashSet::from([Ipv4Addr::new(9, 9, 9, 9)]),
            v6: HashSet::new(),
            max_packets: 5,
        };
        let resp = a_packet(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(checker.check(&resp), PollutionResult::Clean);
    }

    #[test]
    fn test_checker_invalid_packet() {
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        };
        assert_eq!(checker.check(&[0u8; 10]), PollutionResult::Invalid);
    }

    // ========== is_ipv4_polluted / is_ipv6_polluted ==========

    #[test]
    fn test_is_ipv4_polluted_hit() {
        let v4 = HashSet::from([Ipv4Addr::new(1, 2, 3, 4)]);
        let checker = PollutionChecker {
            v4,
            v6: HashSet::new(),
            max_packets: 5,
        };
        assert!(checker.is_ipv4_polluted(&Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_is_ipv4_polluted_miss() {
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        };
        assert!(!checker.is_ipv4_polluted(&Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_is_ipv6_polluted_list_hit() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::from([ip]),
            max_packets: 5,
        };
        assert!(checker.is_ipv6_polluted(&ip));
    }

    #[test]
    fn test_is_ipv6_polluted_gfw_hit() {
        let ip = Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1);
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        };
        assert!(checker.is_ipv6_polluted(&ip));
    }

    #[test]
    fn test_is_ipv6_polluted_miss() {
        let ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let checker = PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        };
        assert!(!checker.is_ipv6_polluted(&ip));
    }

    #[test]
    fn test_is_gfw_ipv6_facebook_exact_match() {
        let known = vec![
            "2a03:2880:f102:183:face:b00c:0:25de",
            "2a03:2880:f107:83:face:b00c:0:25de",
            "2a03:2880:f10a:83:face:b00c:0:25de",
            "2a03:2880:f10c:283:face:b00c:0:25de",
            "2a03:2880:f10c:83:face:b00c:0:25de",
            "2a03:2880:f10d:183:face:b00c:0:25de",
            "2a03:2880:f10d:83:face:b00c:0:25de",
            "2a03:2880:f10e:83:face:b00c:0:25de",
            "2a03:2880:f10f:83:face:b00c:0:25de",
            "2a03:2880:f111:83:face:b00c:0:25de",
            "2a03:2880:f112:83:face:b00c:0:25de",
            "2a03:2880:f117:83:face:b00c:0:25de",
            "2a03:2880:f11a:83:face:b00c:0:25de",
            "2a03:2880:f11b:83:face:b00c:0:25de",
            "2a03:2880:f11c:8083:face:b00c:0:25de",
            "2a03:2880:f11c:8183:face:b00c:0:25de",
            "2a03:2880:f11f:83:face:b00c:0:25de",
            "2a03:2880:f126:83:face:b00c:0:25de",
            "2a03:2880:f127:283:face:b00c:0:25de",
            "2a03:2880:f127:83:face:b00c:0:25de",
            "2a03:2880:f129:83:face:b00c:0:25de",
            "2a03:2880:f12a:83:face:b00c:0:25de",
            "2a03:2880:f12c:183:face:b00c:0:25de",
            "2a03:2880:f12c:83:face:b00c:0:25de",
            "2a03:2880:f12d:83:face:b00c:0:25de",
            "2a03:2880:f130:83:face:b00c:0:25de",
            "2a03:2880:f131:83:face:b00c:0:25de",
            "2a03:2880:f134:183:face:b00c:0:25de",
            "2a03:2880:f134:83:face:b00c:0:25de",
            "2a03:2880:f136:83:face:b00c:0:25de",
        ];
        for s in known {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert!(is_gfw_ipv6_facebook(&ip), "Failed to match {}", s);
        }

        // 额外测试附近但不在列表中的地址
        let near_misses = vec![
            "2a03:2880:f101:83:face:b00c:0:25de",  // seg2=f101 (比f102小)
            "2a03:2880:f102:83:face:b00c:0:25de", // seg2正确，但seg3=83（应匹配f102:183，不匹配83）
            "2a03:2880:f103:83:face:b00c:0:25de", // f103:83
            "2a03:2880:f104:183:face:b00c:0:25de", // 完全不在列表
            "2a03:2880:f11c:83:face:b00c:0:25de", // f11c:83 (列表中是f11c:8083和8183)
            "2a03:2880:f11c:183:face:b00c:0:25de", // 不在列表
            "2a03:2880:f12f:83:face:b00c:0:25de", // f12f不在列表 (f130是最小)
        ];
        for miss in near_misses {
            let ip: Ipv6Addr = miss.parse().unwrap();
            assert!(!is_gfw_ipv6_facebook(&ip), "Should not match {}", miss);
        }
    }
}
