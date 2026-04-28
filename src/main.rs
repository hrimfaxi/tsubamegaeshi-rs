use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use maxminddb::geoip2::City;
use maxminddb::Reader;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{error, info};

use clap::Parser;

#[derive(Parser)]
#[command(name = "tsubamegaeshi-rs", about = "燕返 - Lightweight DNS splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
}

#[derive(Deserialize)]
struct Config {
    listen: String,
    special_suffixes: Vec<String>,
    special_upstream: String,
    domestic_upstream: String,
    foreign_upstream: String,
    geoip_db: String,
    cache_size: usize,
    query_timeout_sec: u64,
    enable_ipv6_aaaa: bool,
    log_level: Option<String>,
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
    geoip: Reader<Vec<u8>>,
    special_suffixes: Vec<String>,
    cache: Option<tokio::sync::Mutex<lru::LruCache<(String, u16), CacheEntry>>>,
    timeout: Duration,
    enable_ipv6_aaaa: bool,
}

fn build_nodata_response(query: &Message) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(hickory_proto::op::MessageType::Response);
    resp.set_response_code(ResponseCode::NoError);
    resp.set_recursion_available(true);

    // 复制问题段（询问的域名、类型）
    for q in query.queries() {
        resp.add_query(q.clone());
    }

    // 复制附加段，**尤其是 OPT 伪记录**（systemd-resolved 依赖此记录）
    for a in query.additionals() {
        resp.add_additional(a.clone());
    }

    resp.to_vec().unwrap_or_default()
}

/// 检测 IPv6 地址是否为已知 GFW 污染地址（例如 2001::xxxx:yyyy）
fn is_ipv6_polluted(ip: &std::net::Ipv6Addr) -> bool {
    let bytes = ip.octets();
    // 前缀必须是 2001
    if bytes[0] != 0x20 || bytes[1] != 0x01 {
        return false;
    }
    // 中间 10 字节必须全为 0
    bytes[2..12].iter().all(|&b| b == 0)
}

impl DnsServer {
    async fn run(self: Arc<Self>) {
        let mut buf = [0u8; 512];
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
            let mut servfail = Message::new();
            servfail.set_id(query_msg.id());
            servfail.set_response_code(ResponseCode::ServFail);
            let _ = self.socket.send_to(&servfail.to_vec().unwrap(), src).await;
            return;
        }

        let qtype = query_msg.queries()[0].query_type();

        // 处理 AAAA 查询
        if qtype == RecordType::AAAA {
            if self.enable_ipv6_aaaa {
                // 开启 IPv6 解析：沿用 A 记录的分流逻辑（先内后外）
                // 注意：需要确保 geoip 数据包含 IPv6 地址，否则会误判
                let raw_domain = query_msg.queries()[0].name().to_utf8().to_string();
                let domain = raw_domain.trim_end_matches('.').to_string();

                // 特殊后缀检查（如果你希望 .h 支持 IPv6）
                for suffix in &self.special_suffixes {
                    if domain.ends_with(suffix) {
                        info!("[SPECIAL-AAAA] {} -> dnsmasq", domain);
                        let _ = self.forward_to_upstream(&request, &self.special_upstream, &src).await;
                        return;
                    }
                }

                if self.enable_ipv6_aaaa {
                    let raw_domain = query_msg.queries()[0].name().to_utf8().to_string();
                    let domain = raw_domain.trim_end_matches('.').to_string();

                    // 特殊后缀直接转发
                    for suffix in &self.special_suffixes {
                        if domain.ends_with(suffix) {
                            info!("[SPECIAL-AAAA] {} -> dnsmasq", domain);
                            let _ = self.forward_to_upstream(&request, &self.special_upstream, &src).await;
                            return;
                        }
                    }

                    // 先查国内上游
                    let domestic_resp = self.send_dns_query(&request, &self.domestic_upstream).await;
                    let use_domestic = match &domestic_resp {
                        Some(data) => {
                            // 尝试提取第一个 IPv6 地址
                            if let Ok(msg) = Message::from_vec(data) {
                                let first_ipv6 = msg.answers().iter().find_map(|rr| {
                                    if rr.record_type() == RecordType::AAAA {
                                        rr.data().and_then(|d| d.ip_addr())
                                    } else {
                                        None
                                    }
                                });
                                match first_ipv6 {
                                    Some(std::net::IpAddr::V6(ipv6)) => {
                                        if is_ipv6_polluted(&ipv6) {
                                            info!("[DOMESTIC-POLLUTED] {} ({}) -> foreign", domain, ipv6);
                                            false
                                        } else {
                                            // 目前没有 IPv6 GeoIP，暂且信任非污染 IPv6
                                            info!("[DOMESTIC-KEEP] {} ({})", domain, ipv6);
                                            true
                                        }
                                    }
                                    Some(v4) => {
                                        // 理论上不会出现，但保留判断
                                        info!("[DOMESTIC-A] {} (v4 in AAAA?) {:?}", domain, v4);
                                        true
                                    }
                                    None => {
                                        info!("[DOMESTIC-NO-IP] {} -> foreign", domain);
                                        false
                                    }
                                }
                            } else {
                                info!("[DOMESTIC-PARSE-ERR] {} -> foreign", domain);
                                false
                            }
                        }
                        None => {
                            info!("[DOMESTIC-TIMEOUT] {} -> foreign", domain);
                            false
                        }
                    };

                    let final_resp = if use_domestic {
                        domestic_resp.unwrap()
                    } else {
                        info!("[FOREIGN] {} -> {}", domain, self.foreign_upstream);
                        match self.send_dns_query(&request, &self.foreign_upstream).await {
                            Some(resp) => resp,
                            None => {
                                info!("[FOREIGN-TIMEOUT] {} -> SERVFAIL", domain);
                                let mut servfail = Message::new();
                                servfail.set_id(query_msg.id());
                                servfail.set_response_code(ResponseCode::ServFail);
                                servfail.to_vec().unwrap_or_default()
                            }
                        }
                    };

                    // 缓存成功的 AAAA 应答（与 A 记录缓存策略一致）
                    if let Some(cache) = &self.cache {
                        if let Ok(msg) = Message::from_vec(&final_resp) {
                            if msg.response_code() == ResponseCode::NoError && !msg.answers().is_empty() {
                                let mut cache = cache.lock().await;
                                let min_ttl = msg.answers().iter().map(|rr| rr.ttl()).min().unwrap_or(60);
                                let effective_ttl = std::cmp::max(min_ttl, 60);
                                let expire = Instant::now() + Duration::from_secs(effective_ttl as u64);
                                cache.put(
                                    (domain.clone(), 28), // 28 = AAAA 的 QTYPE 编号
                                    CacheEntry {
                                        data: final_resp.clone(),
                                        expire,
                                    },
                                );
                            }
                        }
                    }
                    let _ = self.socket.send_to(&final_resp, src).await;
                    return;
                }
            } else {
                // 关闭 IPv6：返回标准 NODATA
                let nodata = build_nodata_response(&query_msg);
                let _ = self.socket.send_to(&nodata, src).await;
                return;
            }
        }

        // 其他非 A 查询（包括 NS、MX、TXT 等）直接转发给国内上游
        if qtype != RecordType::A {
            let raw_domain = query_msg.queries()[0].name().to_utf8().to_string();
            let clean_domain = raw_domain.trim_end_matches('.').to_string();
            tracing::debug!("[NON-A] {} type={:?} -> domestic", clean_domain, qtype);
            let _ = self
                .forward_to_upstream(&request, &self.domestic_upstream, &src)
                .await;
            return;
        }

        let raw_domain = query_msg.queries()[0].name().to_utf8().to_string();
        let clean_domain = raw_domain.trim_end_matches('.').to_string();
        tracing::debug!(
            "raw_domain='{}' clean_domain='{}' suffixes={:?}",
            raw_domain,
            clean_domain,
            self.special_suffixes
        );

        // 检查缓存（键用 clean_domain）
        if let Some(cache_ref) = &self.cache {
            let mut cache = cache_ref.lock().await;
            if let Some(entry) = cache.get(&(clean_domain.clone(), 1)) {
                if entry.expire > Instant::now() {
                    info!("[CACHE-HIT] {}", clean_domain);
                    let mut data = entry.data.clone();
                    // 将缓存应答的事务 ID 改为当前请求的 ID
                    let req_id = query_msg.id();
                    if data.len() >= 2 {
                        data[0] = (req_id >> 8) as u8;
                        data[1] = req_id as u8;
                    }
                    let _ = self.socket.send_to(&data, src).await;
                    return;
                }
            }
        }

        // 特殊后缀直接转发 dnsmasq（用 clean_domain 匹配）
        for suffix in &self.special_suffixes {
            if clean_domain.ends_with(suffix) {
                info!("[SPECIAL] {} -> dnsmasq", clean_domain);
                let _ = self
                    .forward_to_upstream(&request, &self.special_upstream, &src)
                    .await;
                return;
            }
        }

        // 第一阶段：查询国内上游
        info!("[DOMESTIC] {} -> {}", clean_domain, self.domestic_upstream);
        let domestic_resp = self.send_dns_query(&request, &self.domestic_upstream).await;

        let keep_domestic = match &domestic_resp {
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
                                info!("[DOMESTIC-KEEP] {} ({} - China)", clean_domain, ip);
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
                info!("[DOMESTIC-TIMEOUT] {} -> foreign", clean_domain);
                false
            }
        };

        let final_resp = if keep_domestic {
            domestic_resp.unwrap()
        } else {
            info!("[FOREIGN] {} -> {}", clean_domain, self.foreign_upstream);
            match self.send_dns_query(&request, &self.foreign_upstream).await {
                Some(resp) => resp,
                None => {
                    info!("[FOREIGN-TIMEOUT] {} -> SERVFAIL", clean_domain);
                    let mut servfail = Message::new();
                    servfail.set_id(query_msg.id());
                    servfail.set_response_code(ResponseCode::ServFail);
                    servfail.to_vec().unwrap_or_default()
                }
            }
        };

        // 仅缓存成功的应答（NOERROR 且有答案）
        if let Some(cache) = &self.cache {
            if let Ok(msg) = Message::from_vec(&final_resp) {
                if msg.response_code() == ResponseCode::NoError && !msg.answers().is_empty() {
                    let mut cache = cache.lock().await;
                    let min_ttl = msg.answers().iter().map(|rr| rr.ttl()).min().unwrap_or(60);
                    let effective_ttl = std::cmp::max(min_ttl, 60);
                    let expire = Instant::now() + Duration::from_secs(effective_ttl as u64);
                    cache.put(
                        (clean_domain.clone(), 1),
                        CacheEntry {
                            data: final_resp.clone(),
                            expire,
                        },
                    );
                }
            }
        }

        let _ = self.socket.send_to(&final_resp, src).await;
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

        let mut buf = [0u8; 512];
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
        upstream: &SocketAddr,
        client: &SocketAddr,
    ) -> anyhow::Result<()> {
        match self.send_dns_query(request, upstream).await {
            Some(resp) => {
                self.socket.send_to(&resp, client).await?;
            }
            None => {
                let mut servfail = Message::new();
                servfail.set_response_code(ResponseCode::ServFail);
                let data = servfail.to_vec().unwrap_or_default();
                self.socket.send_to(&data, client).await?;
            }
        }
        Ok(())
    }

    fn is_china_ip(&self, ip: IpAddr) -> bool {
        let city: City = match self.geoip.lookup(ip) {
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

    // Load configuration
    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .expect("Failed to read config.toml");
    let config: Config = toml::from_str(&config_str).expect("Invalid config.toml");

    // 构建 EnvFilter：优先使用配置文件中的 log_level
    let env_filter = if let Some(ref level) = config.log_level {
        tracing_subscriber::EnvFilter::new(level)
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // Load GeoIP database
    let geoip_data = tokio::fs::read(&config.geoip_db)
        .await
        .expect("Failed to read GeoIP database");
    let geoip = Reader::from_source(geoip_data).expect("Invalid GeoIP database");

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
            socket.bind(&addr.into())?;
            UdpSocket::from_std(socket.into())?
        }
    };
    let special_upstream: SocketAddr = config.special_upstream.parse()?;
    let domestic_upstream: SocketAddr = config.domestic_upstream.parse()?;
    let foreign_upstream: SocketAddr = config.foreign_upstream.parse()?;

    let cache = if config.cache_size > 0 {
        Some(tokio::sync::Mutex::new(lru::LruCache::new(
            config.cache_size.try_into().unwrap(),
        )))
    } else {
        None
    };

    let server = Arc::new(DnsServer {
        socket,
        special_upstream,
        domestic_upstream,
        foreign_upstream,
        geoip,
        special_suffixes: config.special_suffixes,
        cache,
        timeout: Duration::from_secs(config.query_timeout_sec),
        enable_ipv6_aaaa: config.enable_ipv6_aaaa,
    });

    info!("tsubamegaeshi-rs started on {}", config.listen);
    server.run().await;
    Ok(())
}
