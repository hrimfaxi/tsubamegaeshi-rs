use anyhow::{Result, anyhow, bail};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PollutionChecker {
    pub v4: HashSet<Ipv4Addr>,
    pub v6: HashSet<Ipv6Addr>,
    pub max_packets: usize,
}

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
fn is_gfw_ipv6(ip: &Ipv6Addr) -> bool {
    let bytes = ip.octets();
    bytes.starts_with(&[0x20, 0x01]) && bytes[2..12].iter().all(|&b| b == 0)
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
