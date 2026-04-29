use anyhow::{Context, Result};
use bloomfilter::Bloom;
use clap::Parser;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A as ARecord;
use hickory_proto::rr::rdata::AAAA as AAAARecord;
use hickory_proto::rr::{RData, Record, RecordType};
use maxminddb::geoip2::City;
use maxminddb::Reader;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressQueryKind {
    A,
    Aaaa,
}

impl AddressQueryKind {
    fn cache_qtype(self) -> u16 {
        match self {
            AddressQueryKind::A => DNS_TYPE_A,
            AddressQueryKind::Aaaa => DNS_TYPE_AAAA,
        }
    }

    fn cache_hit_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "CACHE-HIT",
            AddressQueryKind::Aaaa => "CACHE-HIT-AAAA",
        }
    }

    fn cache_skip_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "CACHE-SKIP",
            AddressQueryKind::Aaaa => "CACHE-SKIP-AAAA",
        }
    }

    fn special_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "SPECIAL",
            AddressQueryKind::Aaaa => "SPECIAL-AAAA",
        }
    }

    fn force_domestic_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FORCE-DOMESTIC",
            AddressQueryKind::Aaaa => "FORCE-DOMESTIC-AAAA",
        }
    }

    fn force_foreign_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FORCE-FOREIGN",
            AddressQueryKind::Aaaa => "FORCE-FOREIGN-AAAA",
        }
    }

    fn gfwlist_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "GFWLIST",
            AddressQueryKind::Aaaa => "GFWLIST-AAAA",
        }
    }

    fn domestic_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "DOMESTIC",
            AddressQueryKind::Aaaa => "DOMESTIC-AAAA",
        }
    }

    fn foreign_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FOREIGN",
            AddressQueryKind::Aaaa => "FOREIGN-AAAA",
        }
    }

    fn foreign_timeout_tag(self) -> &'static str {
        match self {
            AddressQueryKind::A => "FOREIGN-TIMEOUT",
            AddressQueryKind::Aaaa => "FOREIGN-TIMEOUT-AAAA",
        }
    }
}

#[derive(Parser)]
#[command(name = "tsubamegaeshi-rs", about = "燕返 - Lightweight DNS splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
}

#[derive(Deserialize, Default)]
struct HostsTables {
    #[serde(default)]
    ipv4: Option<HashMap<String, String>>,
    #[serde(default)]
    ipv6: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct Config {
    listen: String,
    special_suffixes: Vec<String>,
    special_upstream: String,
    domestic_upstream: String,
    foreign_upstream: String,
    mmdb_path: String,
    cache_size: usize,
    query_timeout_sec: u64,
    enable_ipv6_aaaa: bool,
    log_level: Option<String>,

    // GFWList 相关配置
    gfwlist_path: Option<String>,
    gfbloom_fp_rate: Option<f64>, // 默认 0.001 (0.1%)

    #[serde(default)]
    force_foreign_domains: Option<Vec<String>>,

    #[serde(default)]
    force_domestic_domains: Option<Vec<String>>,

    #[serde(default)]
    hosts: Option<HostsTables>,
}

struct CacheEntry {
    data: Vec<u8>,
    expire: Instant,
}

struct DnsServer {
    socket: UdpSocket,
    special_upstream: SocketAddr,
    domestic_upstream: SocketAddr,
    foreign_upstream: SocketAddr,
    mmdb: Reader<Vec<u8>>,
    special_suffixes: Vec<String>,
    cache: Option<tokio::sync::Mutex<lru::LruCache<(String, u16), CacheEntry>>>,
    timeout: Duration,
    enable_ipv6_aaaa: bool,
    gfw_checker: Option<BloomDomainChecker>,
    force_foreign: Option<Vec<String>>,
    force_domestic: Option<Vec<String>>,
    hosts_v4: Option<HashMap<String, Ipv4Addr>>,
    hosts_v6: Option<HashMap<String, Ipv6Addr>>,
}

/// 域名后缀匹配。
///
/// 匹配：
/// - `example.com` == `example.com`
/// - `www.example.com` ends with `.example.com`
///
/// 不匹配：
/// - `badexample.com` 不应匹配 `example.com`
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    domain == suffix || domain.ends_with(&format!(".{}", suffix))
}

/// 检查域名是否匹配强制列表中的任一条目。
fn is_forced(domain: &str, list: &Option<Vec<String>>) -> bool {
    if let Some(items) = list {
        for pattern in items {
            if domain_matches_suffix(domain, pattern) {
                return true;
            }
        }
    }

    false
}

/// GFWList 解码器：负责读取、解码、解析规则并提取域名
pub struct GfwlistDecoder {
    file_path: String,
}

impl GfwlistDecoder {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }

    pub fn extract_domains(&self) -> Result<Vec<String>> {
        let raw_content = fs::read_to_string(&self.file_path)
            .with_context(|| format!("无法读取文件: {}", self.file_path))?;

        let base64_str: String = raw_content.chars().filter(|c| !c.is_whitespace()).collect();

        if base64_str.is_empty() {
            anyhow::bail!("文件内容为空");
        }

        let decoded_bytes = STANDARD
            .decode(&base64_str)
            .with_context(|| "Base64 解码失败，请确认文件内容为合法的 Base64 编码")?;

        let decoded_text = String::from_utf8(decoded_bytes)
            .with_context(|| "解码后的内容不是有效的 UTF-8 文本")?;

        let mut raw_domains = Vec::new();

        for line in decoded_text.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('!') {
                continue;
            }

            if line.starts_with("@@") {
                continue;
            }

            if line.starts_with("||") {
                let rest = &line[2..];

                let domain = rest
                    .split(|c| c == '/' || c == '^' || c == '?' || c == '#')
                    .next()
                    .unwrap_or(rest);

                let domain = domain.trim_end_matches('^').to_lowercase();

                if !domain.is_empty() && !domain.contains('*') {
                    tracing::debug!("gfwlist domain: {}", domain);
                    raw_domains.push(domain);
                }
            }
        }

        let unique_domains: HashSet<String> = raw_domains.into_iter().collect();
        Ok(unique_domains.into_iter().collect())
    }
}

/// 基于布隆过滤器的域名检测器
pub struct BloomDomainChecker {
    filter: Bloom<Vec<u8>>,
}

impl BloomDomainChecker {
    pub fn new(domains: &[String], fp_rate: f64) -> Result<Self> {
        let num_items = domains.len();

        if num_items == 0 {
            anyhow::bail!("没有提供任何域名，无法构建布隆过滤器");
        }

        let mut filter = Bloom::<Vec<u8>>::new_for_fp_rate(num_items, fp_rate)
            .map_err(|e| anyhow::anyhow!("创建布隆过滤器失败: {}", e))?;

        for domain in domains {
            filter.set(&domain.as_bytes().to_vec());
        }

        Ok(Self { filter })
    }

    pub fn check(&self, domain: &str) -> bool {
        let mut parts: Vec<&str> = domain.split('.').collect();
        // 至少保留 2 段（例如 google.com）
        while parts.len() >= 2 {
            let key = parts.join(".");
            if self.filter.check(&key.to_lowercase().as_bytes().to_vec()) {
                return true;
            }
            parts.remove(0); // 去掉最左侧子域名
        }
        false
    }
}

fn build_basic_response_message(query: &Message, code: ResponseCode) -> Message {
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

fn build_basic_response(query: &Message, code: ResponseCode) -> Vec<u8> {
    build_basic_response_message(query, code)
        .to_vec()
        .unwrap_or_default()
}

fn build_servfail_response(query: &Message) -> Vec<u8> {
    build_basic_response(query, ResponseCode::ServFail)
}

fn build_nodata_response(query: &Message) -> Vec<u8> {
    build_basic_response(query, ResponseCode::NoError)
}

fn build_a_response(query: &Message, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
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

fn build_aaaa_response(query: &Message, ip: Ipv6Addr, ttl: u32) -> Vec<u8> {
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

fn response_cache_ttl(msg: &Message) -> Option<u64> {
    let min_ttl = msg.answers().iter().map(|rr| rr.ttl()).min()?;

    // TTL 为 0 表示不应缓存
    if min_ttl == 0 {
        None
    } else {
        Some(min_ttl as u64)
    }
}

fn rewrite_dns_id(data: &mut [u8], id: u16) {
    if data.len() >= 2 {
        data[0] = (id >> 8) as u8;
        data[1] = id as u8;
    }
}

/// 检测 IPv6 地址是否为已知 GFW 污染地址，例如 `2001::xxxx:yyyy`
fn is_ipv6_polluted(ip: &std::net::Ipv6Addr) -> bool {
    let bytes = ip.octets();

    // 前缀必须是 2001
    if bytes[0] != 0x20 || bytes[1] != 0x01 {
        return false;
    }

    // 中间 10 字节必须全为 0
    bytes[2..12].iter().all(|&b| b == 0)
}

fn print_first_ip(resp: &[u8], tag: &str, domain: &str, upstream: &str) {
    if let Ok(msg) = Message::from_vec(resp) {
        if let Some(rr) = msg
            .answers()
            .iter()
            .find(|rr| rr.record_type() == RecordType::A || rr.record_type() == RecordType::AAAA)
        {
            if let Some(ip) = rr.data().and_then(|d| d.ip_addr()) {
                info!("[{}] {} -> {} = {}", tag, domain, upstream, ip);
                return;
            }
        }
    }
    error!("[{}] {} -> {} (no A/AAAA answer)", tag, domain, upstream);
}

impl DnsServer {
    async fn handle_hosts_override(
        &self,
        kind: AddressQueryKind,
        query_msg: &Message,
        clean_domain: &str,
        src: SocketAddr,
    ) -> bool {
        match kind {
            AddressQueryKind::A => {
                if let Some(ip) = self.hosts_v4.as_ref().and_then(|h| h.get(clean_domain)) {
                    let resp = build_a_response(query_msg, *ip, 60);
                    info!("[HOSTS-A] {} -> {}", clean_domain, ip);
                    let _ = self.socket.send_to(&resp, src).await;
                    return true;
                }
                // 检查是否仅存在于 v6 表中
                if self
                    .hosts_v6
                    .as_ref()
                    .map_or(false, |h| h.contains_key(clean_domain))
                {
                    info!("[HOSTS-NO-A] {} (v6 only)", clean_domain);
                    let nodata = build_nodata_response(query_msg);
                    let _ = self.socket.send_to(&nodata, src).await;
                    return true;
                }
                false
            }
            AddressQueryKind::Aaaa => {
                if let Some(ip) = self.hosts_v6.as_ref().and_then(|h| h.get(clean_domain)) {
                    let resp = build_aaaa_response(query_msg, *ip, 60);
                    info!("[HOSTS-AAAA] {} -> {}", clean_domain, ip);
                    let _ = self.socket.send_to(&resp, src).await;
                    return true;
                }
                if self
                    .hosts_v4
                    .as_ref()
                    .map_or(false, |h| h.contains_key(clean_domain))
                {
                    info!("[HOSTS-NO-AAAA] {} (v4 only)", clean_domain);
                    let nodata = build_nodata_response(query_msg);
                    let _ = self.socket.send_to(&nodata, src).await;
                    return true;
                }
                false
            }
        }
    }

    async fn forward_to_upstream_and_get(
        &self,
        request: &[u8],
        query: &Message,
        upstream: &SocketAddr,
        client: &SocketAddr,
    ) -> Vec<u8> {
        let data = self
            .query_upstream_or_servfail(request, query, upstream, None)
            .await;

        let _ = self.socket.send_to(&data, client).await;
        data
    }

    async fn forward_by_static_rules(
        &self,
        kind: AddressQueryKind,
        request: &[u8],
        query_msg: &Message,
        clean_domain: &str,
        src: SocketAddr,
    ) -> bool {
        // 特殊后缀检查：直接走 special_upstream
        for suffix in &self.special_suffixes {
            if domain_matches_suffix(clean_domain, suffix) {
                info!("[{}] {} -> dnsmasq", kind.special_tag(), clean_domain);

                let resp = self
                    .forward_to_upstream_and_get(request, query_msg, &self.special_upstream, &src)
                    .await;

                print_first_ip(
                    &resp,
                    kind.special_tag(),
                    clean_domain,
                    &self.special_upstream.to_string(),
                );
                return true;
            }
        }

        // 强制走国内上游
        if is_forced(clean_domain, &self.force_domestic) {
            info!(
                "[{}] {} -> {}",
                kind.force_domestic_tag(),
                clean_domain,
                self.domestic_upstream
            );

            let resp = self
                .forward_to_upstream_and_get(request, query_msg, &self.domestic_upstream, &src)
                .await;

            print_first_ip(
                &resp,
                kind.force_domestic_tag(),
                clean_domain,
                &self.domestic_upstream.to_string(),
            );
            return true;
        }

        // 强制走国外上游
        if is_forced(clean_domain, &self.force_foreign) {
            info!(
                "[{}] {} -> {}",
                kind.force_foreign_tag(),
                clean_domain,
                self.foreign_upstream
            );

            let resp = self
                .forward_to_upstream_and_get(request, query_msg, &self.foreign_upstream, &src)
                .await;

            print_first_ip(
                &resp,
                kind.force_foreign_tag(),
                clean_domain,
                &self.foreign_upstream.to_string(),
            );
            return true;
        }

        // GFWList 检查：命中则直接走 foreign_upstream
        if let Some(ref gfw) = self.gfw_checker {
            if gfw.check(clean_domain) {
                trace!(
                    "[{}] {} in gfwlist, direct to foreign",
                    kind.gfwlist_tag(),
                    clean_domain
                );

                let resp = self
                    .forward_to_upstream_and_get(request, query_msg, &self.foreign_upstream, &src)
                    .await;

                print_first_ip(
                    &resp,
                    kind.gfwlist_tag(),
                    clean_domain,
                    &self.foreign_upstream.to_string(),
                );
                return true;
            }
        }

        false
    }

    fn should_use_domestic_a_response(
        &self,
        clean_domain: &str,
        domestic_resp: &Option<Vec<u8>>,
    ) -> bool {
        match domestic_resp {
            Some(resp_bytes) => match Message::from_vec(resp_bytes) {
                Ok(msg) => {
                    match msg.answers().iter().find_map(|rr| {
                        if rr.record_type() == RecordType::A {
                            rr.data().and_then(|d| d.ip_addr())
                        } else {
                            None
                        }
                    }) {
                        Some(ip) => {
                            let is_cn = self.is_china_ip(ip);

                            if is_cn {
                                debug!("[DOMESTIC-KEEP] {} ({} - China)", clean_domain, ip);
                                true
                            } else {
                                info!(
                                    "[DOMESTIC-REJECT] {} ({} - not China) -> foreign",
                                    clean_domain, ip
                                );

                                false
                            }
                        }
                        None => {
                            info!("[DOMESTIC-NO-IP] {} -> foreign", clean_domain);
                            false
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to parse domestic response for {}: {}",
                        clean_domain, e
                    );

                    false
                }
            },
            None => {
                error!("[DOMESTIC-TIMEOUT] {} -> foreign", clean_domain);
                false
            }
        }
    }

    fn should_use_domestic_aaaa_response(
        &self,
        clean_domain: &str,
        domestic_resp: &Option<Vec<u8>>,
    ) -> bool {
        match domestic_resp {
            Some(data) => {
                if let Ok(msg) = Message::from_vec(data) {
                    let first_ipv6 = msg.answers().iter().find_map(|rr| {
                        if rr.record_type() == RecordType::AAAA {
                            rr.data().and_then(|d| d.ip_addr())
                        } else {
                            None
                        }
                    });

                    match first_ipv6 {
                        Some(IpAddr::V6(ipv6)) => {
                            if is_ipv6_polluted(&ipv6) {
                                info!(
                                    "[DOMESTIC-POLLUTED-AAAA] {} ({}) -> foreign",
                                    clean_domain, ipv6
                                );

                                false
                            } else {
                                debug!("[DOMESTIC-KEEP-AAAA] {} ({})", clean_domain, ipv6);
                                true
                            }
                        }
                        Some(_) => {
                            // 理论上 AAAA 查询不应返回非 IPv6 地址，这里保守使用国内结果
                            true
                        }
                        None => {
                            info!("[DOMESTIC-NO-IP-AAAA] {} -> foreign", clean_domain);
                            false
                        }
                    }
                } else {
                    info!("[DOMESTIC-PARSE-ERR-AAAA] {} -> foreign", clean_domain);
                    false
                }
            }
            None => {
                error!("[DOMESTIC-TIMEOUT-AAAA] {} -> foreign", clean_domain);
                false
            }
        }
    }

    fn should_use_domestic_response(
        &self,
        kind: AddressQueryKind,
        clean_domain: &str,
        domestic_resp: &Option<Vec<u8>>,
    ) -> bool {
        match kind {
            AddressQueryKind::A => self.should_use_domestic_a_response(clean_domain, domestic_resp),
            AddressQueryKind::Aaaa => {
                self.should_use_domestic_aaaa_response(clean_domain, domestic_resp)
            }
        }
    }

    async fn handle_address_request(
        &self,
        kind: AddressQueryKind,
        request: &[u8],
        query_msg: &Message,
        clean_domain: &str,
        src: SocketAddr,
    ) {
        // hosts 处理：
        // - A：返回 hosts 里的 IPv4
        // - AAAA：如果 hosts 里存在该域名，则返回 NODATA
        if self
            .handle_hosts_override(kind, query_msg, clean_domain, src)
            .await
        {
            return;
        }

        // 如果禁用了 AAAA，则不查缓存、不查上游，直接返回 NODATA
        if kind == AddressQueryKind::Aaaa && !self.enable_ipv6_aaaa {
            let nodata = build_nodata_response(query_msg);
            let _ = self.socket.send_to(&nodata, src).await;
            return;
        }

        // 缓存检查
        if self
            .send_cached_response(
                clean_domain,
                kind.cache_qtype(),
                query_msg.id(),
                src,
                kind.cache_hit_tag(),
            )
            .await
        {
            return;
        }

        // special suffix / force domestic / force foreign / gfwlist
        if self
            .forward_by_static_rules(kind, request, query_msg, clean_domain, src)
            .await
        {
            return;
        }

        // 普通域名：先查国内，根据 A/AAAA 各自规则判断是否使用国内结果
        debug!(
            "[{}] {} -> {}",
            kind.domestic_tag(),
            clean_domain,
            self.domestic_upstream
        );

        let domestic_resp = self.send_dns_query(request, &self.domestic_upstream).await;

        let use_domestic = self.should_use_domestic_response(kind, clean_domain, &domestic_resp);

        let (final_resp, chosen_tag, chosen_upstream) = if use_domestic {
            let resp = domestic_resp.expect("domestic_rep must be Some");
            (
                resp,
                kind.domestic_tag(),
                self.domestic_upstream.to_string(),
            )
        } else {
            let resp = self
                .query_upstream_or_servfail(
                    request,
                    query_msg,
                    &self.foreign_upstream,
                    Some((kind.foreign_timeout_tag(), clean_domain)),
                )
                .await;
            (resp, kind.foreign_tag(), self.foreign_upstream.to_string())
        };

        // 打印解析结果
        if let Ok(msg) = Message::from_vec(&final_resp) {
            if let Some(rr) = msg.answers().iter().find(|rr| {
                rr.record_type() == RecordType::A || rr.record_type() == RecordType::AAAA
            }) {
                if let Some(ip) = rr.data().and_then(|d| d.ip_addr()) {
                    info!(
                        "[{}] {} -> {} resolved to {}",
                        chosen_tag, clean_domain, chosen_upstream, ip
                    );
                } else {
                    error!(
                        "[{}] {} -> {} (no A/AAAA answer)",
                        chosen_tag, clean_domain, chosen_upstream
                    );
                }
            } else {
                error!(
                    "[{}] {} -> {} (no A/AAAA answer)",
                    chosen_tag, clean_domain, chosen_upstream
                );
            }
        }

        // 只缓存 NOERROR 且有答案，TTL 为 0 不缓存
        self.cache_response(
            clean_domain,
            kind.cache_qtype(),
            &final_resp,
            kind.cache_skip_tag(),
        )
        .await;

        let _ = self.socket.send_to(&final_resp, src).await;
    }

    async fn send_cached_response(
        &self,
        domain: &str,
        qtype_num: u16,
        req_id: u16,
        src: SocketAddr,
        hit_tag: &str,
    ) -> bool {
        let Some(cache_ref) = &self.cache else {
            return false;
        };

        let key = (domain.to_string(), qtype_num);

        let cached_data = {
            let mut cache = cache_ref.lock().await;
            let now = Instant::now();

            let mut expired = false;

            let data = if let Some(entry) = cache.get(&key) {
                if entry.expire > now {
                    Some(entry.data.clone())
                } else {
                    expired = true;
                    None
                }
            } else {
                None
            };

            if expired {
                cache.pop(&key);
            }

            data
        };

        let Some(mut data) = cached_data else {
            return false;
        };

        debug!("[{}] {}", hit_tag, domain);

        rewrite_dns_id(&mut data, req_id);

        let _ = self.socket.send_to(&data, src).await;
        true
    }

    async fn cache_response(&self, domain: &str, qtype_num: u16, response: &[u8], skip_tag: &str) {
        let Some(cache_ref) = &self.cache else {
            return;
        };

        let Ok(msg) = Message::from_vec(response) else {
            return;
        };

        if msg.response_code() != ResponseCode::NoError || msg.answers().is_empty() {
            return;
        }

        let Some(effective_ttl) = response_cache_ttl(&msg) else {
            tracing::debug!("[{}] {} ttl=0", skip_tag, domain);
            return;
        };

        let expire = Instant::now() + Duration::from_secs(effective_ttl);

        let mut cache = cache_ref.lock().await;
        cache.put(
            (domain.to_string(), qtype_num),
            CacheEntry {
                data: response.to_vec(),
                expire,
            },
        );
    }

    async fn query_upstream_or_servfail(
        &self,
        request: &[u8],
        query: &Message,
        upstream: &SocketAddr,
        timeout_log: Option<(&str, &str)>,
    ) -> Vec<u8> {
        match self.send_dns_query(request, upstream).await {
            Some(resp) => resp,
            None => {
                if let Some((tag, domain)) = timeout_log {
                    error!("[{}] {} -> SERVFAIL", tag, domain);
                }

                build_servfail_response(query)
            }
        }
    }

    async fn run(self: Arc<Self>) {
        let mut buf = [0u8; 4096];

        loop {
            let (len, src) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("recv_from error: {}", e);
                    continue;
                }
            };

            let request = buf[..len].to_vec();
            let server = self.clone();

            tokio::spawn(async move {
                server.handle_request(request, src).await;
            });
        }
    }

    async fn handle_request(&self, request: Vec<u8>, src: SocketAddr) {
        // 解析查询
        let query_msg = match Message::from_vec(&request) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to parse DNS request from {}: {}", src, e);
                return;
            }
        };

        if query_msg.queries().len() != 1 {
            // 多问题报文极少见，直接返回 SERVFAIL
            let servfail = build_servfail_response(&query_msg);
            let _ = self.socket.send_to(&servfail, src).await;
            return;
        }

        let query = &query_msg.queries()[0];
        let qtype = query.query_type();
        let raw_domain = query.name().to_utf8().to_string();
        let clean_domain = raw_domain.trim_end_matches('.').to_string();

        match qtype {
            RecordType::A => {
                self.handle_address_request(
                    AddressQueryKind::A,
                    &request,
                    &query_msg,
                    &clean_domain,
                    src,
                )
                .await;
            }

            RecordType::AAAA => {
                self.handle_address_request(
                    AddressQueryKind::Aaaa,
                    &request,
                    &query_msg,
                    &clean_domain,
                    src,
                )
                .await;
            }

            _ => {
                // 非 A / AAAA 查询直接给国内上游
                tracing::debug!("[NON-A] {} type={:?} -> domestic", clean_domain, qtype);

                let _ = self
                    .forward_to_upstream(&request, &query_msg, &self.domestic_upstream, &src)
                    .await;
            }
        }
    }
    async fn send_dns_query(&self, request: &[u8], upstream: &SocketAddr) -> Option<Vec<u8>> {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind ephemeral socket: {}", e);
                return None;
            }
        };

        if let Err(e) = socket.send_to(request, upstream).await {
            error!("Failed to send to {}: {}", upstream, e);
            return None;
        }

        let mut buf = [0u8; 4096];

        match tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            Ok(Err(e)) => {
                error!("recv error from {}: {}", upstream, e);
                None
            }
            Err(_) => {
                error!("Timeout waiting for response from {}", upstream);
                None
            }
        }
    }

    async fn forward_to_upstream(
        &self,
        request: &[u8],
        query: &Message,
        upstream: &SocketAddr,
        client: &SocketAddr,
    ) -> anyhow::Result<()> {
        let data = self
            .query_upstream_or_servfail(request, query, upstream, None)
            .await;

        self.socket.send_to(&data, client).await?;

        Ok(())
    }

    fn is_china_ip(&self, ip: IpAddr) -> bool {
        let city: City = match self.mmdb.lookup(ip) {
            Ok(city) => city,
            Err(_) => return false,
        };

        city.country
            .and_then(|c| c.iso_code)
            .map(|code| code == "CN")
            .unwrap_or(false)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .expect("Failed to read config.toml");

    let config: Config = toml::from_str(&config_str).expect("Invalid config.toml");

    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .without_time()
        .init();

    // 加载 mmdb
    let mmdb_data = tokio::fs::read(&config.mmdb_path)
        .await
        .expect("Failed to read MMDB database");

    let mmdb = Reader::from_source(mmdb_data).expect("Invalid MMDB database");

    // 加载 GFWList 并构建布隆过滤器
    let gfw_checker = if let Some(path) = &config.gfwlist_path {
        info!("Loading GFWList from {}", path);

        match GfwlistDecoder::new(path).extract_domains() {
            Ok(domains) => {
                info!("Extracted {} unique domains from GFWList", domains.len());

                let fp_rate = config.gfbloom_fp_rate.unwrap_or(0.001);

                match BloomDomainChecker::new(&domains, fp_rate) {
                    Ok(checker) => {
                        info!("Bloom filter built with fp_rate={:.2}%", fp_rate * 100.0);
                        Some(checker)
                    }
                    Err(e) => {
                        error!("Failed to build bloom filter: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse GFWList: {}", e);
                None
            }
        }
    } else {
        info!("No GFWList path provided, skipping GFW filter");
        None
    };

    // 绑定 UDP socket
    let addr: SocketAddr = config.listen.parse()?;

    let socket = match addr {
        SocketAddr::V4(_) => {
            // 显式 IPv4 地址则仅绑定 IPv4
            UdpSocket::bind(addr).await?
        }
        SocketAddr::V6(_) => {
            // IPv6 地址：同时兼容 IPv4
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(false)?;
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            UdpSocket::from_std(socket.into())?
        }
    };

    let special_upstream: SocketAddr = config.special_upstream.parse()?;
    let domestic_upstream: SocketAddr = config.domestic_upstream.parse()?;
    let foreign_upstream: SocketAddr = config.foreign_upstream.parse()?;

    let cache = std::num::NonZeroUsize::new(config.cache_size)
        .map(|size| tokio::sync::Mutex::new(lru::LruCache::new(size)));

    fn parse_hosts<A: FromStr<Err = std::net::AddrParseError>>(
        map: &HashMap<String, String>,
    ) -> HashMap<String, A> {
        map.iter()
            .map(|(k, v)| {
                let addr = v
                    .parse::<A>()
                    .unwrap_or_else(|e| panic!("invalid IP for {k}: {e}"));
                (k.clone(), addr)
            })
            .collect()
    }

    let (hosts_v4, hosts_v6) = config.hosts.as_ref().map_or((None, None), |h| {
        let v4 = h.ipv4.as_ref().map(|m| parse_hosts::<Ipv4Addr>(m));
        let v6 = h.ipv6.as_ref().map(|m| parse_hosts::<Ipv6Addr>(m));
        (v4, v6)
    });

    let server = Arc::new(DnsServer {
        socket,
        special_upstream,
        domestic_upstream,
        foreign_upstream,
        mmdb,
        special_suffixes: config.special_suffixes,
        cache,
        timeout: Duration::from_secs(config.query_timeout_sec),
        enable_ipv6_aaaa: config.enable_ipv6_aaaa,
        gfw_checker,
        force_foreign: config.force_foreign_domains,
        force_domestic: config.force_domestic_domains,
        hosts_v4,
        hosts_v6,
    });

    info!("tsubamegaeshi-rs started on {}", config.listen);

    server.run().await;

    Ok(())
}
