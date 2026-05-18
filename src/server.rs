use crate::adblock::AdblockChecker;
use crate::cache::DnsCache;
use crate::dns_utils::{
    AddressQueryKind, build_a_response, build_aaaa_response, build_nodata_response,
    build_servfail_response, is_ipv6_polluted, print_first_ip,
};
use crate::domain_utils::{canonical_domain, domain_matches_suffix, is_forced};
use crate::gfwlist::BloomDomainChecker;
use crate::mark_sites::{CommandNftManager, MarkSites, NFT_SEM, NftManager};
use anyhow::Context;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use maxminddb::Reader;
use maxminddb::geoip2::Country;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

pub struct RequestContext<'a> {
    pub kind: AddressQueryKind,
    pub request: &'a [u8],
    pub query_msg: &'a Message,
    pub clean_domain: &'a str,
    pub src: SocketAddr,
}

pub struct DnsServer {
    pub socket: UdpSocket,
    pub special_upstream: SocketAddr,
    pub domestic_upstream: SocketAddr,
    pub foreign_upstream: SocketAddr,
    pub mmdb: Reader<Vec<u8>>,
    pub special_suffixes: Vec<String>,
    pub cache: Option<DnsCache>,
    pub timeout: Duration,
    pub enable_ipv6_aaaa: bool,
    pub gfw_checker: Option<BloomDomainChecker>,
    pub force_foreign: Option<Vec<String>>,
    pub force_domestic: Option<Vec<String>>,
    pub hosts_v4: Option<HashMap<String, Ipv4Addr>>,
    pub hosts_v6: Option<HashMap<String, Ipv6Addr>>,
    pub mark_sites: Option<MarkSites>,
    pub nft_manager: Option<Arc<CommandNftManager>>,
    pub adblock_checker: Option<Arc<AdblockChecker>>,
    pub domestic_countries: Vec<String>,
}

async fn bind_ephemeral_udp_for(upstream: &SocketAddr) -> std::io::Result<UdpSocket> {
    match upstream {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await,
    }
}

impl DnsServer {
    pub async fn apply_mark_sites(&self, final_resp: &[u8], clean_domain: &str) {
        let Some(mark_sites) = &self.mark_sites else {
            return;
        };

        let Some(nft) = &self.nft_manager else {
            return;
        };

        let matched_groups: Vec<&crate::mark_sites::MarkGroup> =
            mark_sites.match_groups(clean_domain).collect();

        if matched_groups.is_empty() {
            return;
        }

        info!(
            "[MARK_SITES] domain '{}' matched {} group(s): {:?}",
            clean_domain,
            matched_groups.len(),
            matched_groups
                .iter()
                .map(|g| &g.nft_table)
                .collect::<Vec<_>>()
        );

        let ips: Vec<IpAddr> = match Message::from_vec(final_resp) {
            Ok(msg) => msg
                .answers()
                .iter()
                .filter_map(|rr| {
                    if rr.record_type() == RecordType::A || rr.record_type() == RecordType::AAAA {
                        rr.data().and_then(|d| d.ip_addr())
                    } else {
                        None
                    }
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            Err(_) => vec![],
        };

        if ips.is_empty() {
            return;
        }

        let nft_manager = nft.clone();
        let tables: Vec<String> = matched_groups.iter().map(|g| g.nft_table.clone()).collect();

        let mut entries = Vec::new();

        for ip in &ips {
            for table in &tables {
                entries.push((table.clone(), *ip));
            }
        }

        let Ok(permit) = NFT_SEM.acquire().await else {
            warn!("[mark_sites] failed to acquire nft semaphore");
            return;
        };

        tokio::task::spawn_blocking(move || {
            let _permit = permit;

            for (table, ip) in entries {
                if let Err(e) = nft_manager.as_ref().add_ip_to_group(&table, ip) {
                    error!(
                        "[mark_sites] Failed to add {} to table {}: {}",
                        ip, table, e
                    );
                } else {
                    debug!("[mark_sites] Added {} to table {}", ip, table);
                }
            }
        });
    }

    pub async fn handle_hosts_override(&self, ctx: &RequestContext<'_>) -> bool {
        // hosts 处理：
        // - A：返回 hosts 里的 IPv4
        // - AAAA：如果 hosts 里存在该域名但无对应类型，则返回 NODATA
        match ctx.kind {
            AddressQueryKind::A => {
                if let Some(ip) = self.hosts_v4.as_ref().and_then(|h| h.get(ctx.clean_domain)) {
                    let resp = build_a_response(ctx.query_msg, *ip, 60);
                    info!("[HOSTS-A] {} -> {}", ctx.clean_domain, ip);
                    let _ = self.socket.send_to(&resp, ctx.src).await;
                    return true;
                }

                if self
                    .hosts_v6
                    .as_ref()
                    .is_some_and(|h| h.contains_key(ctx.clean_domain))
                {
                    info!("[HOSTS-NO-A] {} (v6 only)", ctx.clean_domain);
                    let nodata = build_nodata_response(ctx.query_msg);
                    let _ = self.socket.send_to(&nodata, ctx.src).await;
                    return true;
                }

                false
            }

            AddressQueryKind::Aaaa => {
                if let Some(ip) = self.hosts_v6.as_ref().and_then(|h| h.get(ctx.clean_domain)) {
                    let resp = build_aaaa_response(ctx.query_msg, *ip, 60);
                    info!("[HOSTS-AAAA] {} -> {}", ctx.clean_domain, ip);
                    let _ = self.socket.send_to(&resp, ctx.src).await;
                    return true;
                }

                if self
                    .hosts_v4
                    .as_ref()
                    .is_some_and(|h| h.contains_key(ctx.clean_domain))
                {
                    info!("[HOSTS-NO-AAAA] {} (v4 only)", ctx.clean_domain);
                    let nodata = build_nodata_response(ctx.query_msg);
                    let _ = self.socket.send_to(&nodata, ctx.src).await;
                    return true;
                }

                false
            }
        }
    }

    pub async fn forward_to_upstream_and_get(
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

    pub async fn forward_and_cache(
        &self,
        ctx: &RequestContext<'_>,
        upstream: &SocketAddr,
        tag: &str,
    ) {
        let resp = self
            .forward_to_upstream_and_get(ctx.request, ctx.query_msg, upstream, &ctx.src)
            .await;

        let upstream_str = upstream.to_string();

        print_first_ip(&resp, tag, ctx.clean_domain, &upstream_str);

        self.apply_mark_sites(&resp, ctx.clean_domain).await;

        self.cache_response(
            ctx.clean_domain,
            ctx.kind.cache_qtype(),
            &resp,
            ctx.kind.cache_skip_tag(),
        )
        .await;
    }

    pub async fn forward_by_static_rules(&self, ctx: &RequestContext<'_>) -> bool {
        for suffix in &self.special_suffixes {
            if domain_matches_suffix(ctx.clean_domain, suffix) {
                info!(
                    "[{}] {} -> dnsmasq",
                    ctx.kind.special_tag(),
                    ctx.clean_domain
                );

                let upstream = self.special_upstream;
                self.forward_and_cache(ctx, &upstream, ctx.kind.special_tag())
                    .await;

                return true;
            }
        }

        if is_forced(ctx.clean_domain, &self.force_domestic) {
            debug!(
                "[{}] {} -> {}",
                ctx.kind.force_domestic_tag(),
                ctx.clean_domain,
                self.domestic_upstream
            );

            let upstream = self.domestic_upstream;
            self.forward_and_cache(ctx, &upstream, ctx.kind.force_domestic_tag())
                .await;

            return true;
        }

        if is_forced(ctx.clean_domain, &self.force_foreign) {
            info!(
                "[{}] {} -> {}",
                ctx.kind.force_foreign_tag(),
                ctx.clean_domain,
                self.foreign_upstream
            );

            let upstream = self.foreign_upstream;
            self.forward_and_cache(ctx, &upstream, ctx.kind.force_foreign_tag())
                .await;

            return true;
        }

        if let Some(ref gfw) = self.gfw_checker
            && gfw.check(ctx.clean_domain)
        {
            trace!(
                "[{}] {} in gfwlist, direct to foreign",
                ctx.kind.gfwlist_tag(),
                ctx.clean_domain
            );

            let upstream = self.foreign_upstream;
            self.forward_and_cache(ctx, &upstream, ctx.kind.gfwlist_tag())
                .await;

            return true;
        }

        false
    }

    pub fn should_use_domestic_a_response(
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
                            let is_cn = self.is_domestic_country_ip(ip);

                            if is_cn {
                                debug!("[DOMESTIC-KEEP] {} ({} - China)", clean_domain, ip);
                                true
                            } else {
                                debug!(
                                    "[DOMESTIC-REJECT] {} ({} - not China) -> foreign",
                                    clean_domain, ip
                                );
                                false
                            }
                        }

                        None => {
                            debug!("[DOMESTIC-NO-IP] {} -> foreign", clean_domain);
                            false
                        }
                    }
                }

                Err(e) => {
                    warn!(
                        "Failed to parse domestic response for {}: {}",
                        clean_domain, e
                    );
                    false
                }
            },

            None => {
                warn!("[DOMESTIC-TIMEOUT] {} -> foreign", clean_domain);
                false
            }
        }
    }

    pub fn should_use_domestic_aaaa_response(
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
                                debug!(
                                    "[DOMESTIC-POLLUTED-AAAA] {} ({}) -> foreign",
                                    clean_domain, ipv6
                                );
                                false
                            } else {
                                debug!("[DOMESTIC-KEEP-AAAA] {} ({})", clean_domain, ipv6);
                                true
                            }
                        }

                        Some(_) => true,

                        None => {
                            debug!("[DOMESTIC-NO-IP-AAAA] {} -> foreign", clean_domain);
                            false
                        }
                    }
                } else {
                    debug!("[DOMESTIC-PARSE-ERR-AAAA] {} -> foreign", clean_domain);
                    false
                }
            }

            None => {
                debug!("[DOMESTIC-TIMEOUT-AAAA] {} -> foreign", clean_domain);
                false
            }
        }
    }

    pub fn should_use_domestic_response(
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

    pub async fn handle_address_request(&self, ctx: RequestContext<'_>) {
        if self.handle_hosts_override(&ctx).await {
            return;
        }

        // 如果禁用了 AAAA，则不查缓存、不查上游，直接返回 NODATA
        if ctx.kind == AddressQueryKind::Aaaa && !self.enable_ipv6_aaaa {
            let nodata = build_nodata_response(ctx.query_msg);
            let _ = self.socket.send_to(&nodata, ctx.src).await;
            return;
        }

        // 2. 广告屏蔽（新增）
        if let Some(ref adblock) = self.adblock_checker
            && adblock.check(ctx.clean_domain)
        {
            let blocked_response = match ctx.kind {
                AddressQueryKind::A => {
                    info!("[ADBLOCK-A] {} -> 0.0.0.0", ctx.clean_domain);
                    build_a_response(ctx.query_msg, Ipv4Addr::new(0, 0, 0, 0), 60)
                }
                AddressQueryKind::Aaaa => {
                    info!("[ADBLOCK-AAAA] {} -> ::", ctx.clean_domain);
                    build_aaaa_response(ctx.query_msg, Ipv6Addr::UNSPECIFIED, 60)
                }
            };
            let _ = self.socket.send_to(&blocked_response, ctx.src).await;
            return;
        }

        // 缓存检查
        if self
            .send_cached_response(
                ctx.clean_domain,
                ctx.kind.cache_qtype(),
                ctx.query_msg.id(),
                ctx.src,
                ctx.kind.cache_hit_tag(),
            )
            .await
        {
            return;
        }

        // special suffix / force domestic / force foreign / gfwlist
        if self.forward_by_static_rules(&ctx).await {
            return;
        }

        // 普通域名：先查国内，根据 A/AAAA 各自规则判断是否使用国内结果
        debug!(
            "[{}] {} -> {}",
            ctx.kind.domestic_tag(),
            ctx.clean_domain,
            self.domestic_upstream
        );

        let domestic_resp = self
            .send_dns_query(ctx.request, &self.domestic_upstream)
            .await;

        let use_domestic =
            self.should_use_domestic_response(ctx.kind, ctx.clean_domain, &domestic_resp);

        let (final_resp, chosen_tag, chosen_upstream) = if use_domestic {
            let resp = domestic_resp.expect("domestic_resp must be Some when use_domestic is true");
            (
                resp,
                ctx.kind.domestic_tag(),
                self.domestic_upstream.to_string(),
            )
        } else {
            let resp = self
                .query_upstream_or_servfail(
                    ctx.request,
                    ctx.query_msg,
                    &self.foreign_upstream,
                    Some((ctx.kind.foreign_timeout_tag(), ctx.clean_domain)),
                )
                .await;

            (
                resp,
                ctx.kind.foreign_tag(),
                self.foreign_upstream.to_string(),
            )
        };

        print_first_ip(&final_resp, chosen_tag, ctx.clean_domain, &chosen_upstream);

        self.cache_response(
            ctx.clean_domain,
            ctx.kind.cache_qtype(),
            &final_resp,
            ctx.kind.cache_skip_tag(),
        )
        .await;

        let _ = self.socket.send_to(&final_resp, ctx.src).await;

        self.apply_mark_sites(&final_resp, ctx.clean_domain).await;
    }

    pub async fn send_cached_response(
        &self,
        domain: &str,
        qtype_num: u16,
        req_id: u16,
        src: SocketAddr,
        hit_tag: &str,
    ) -> bool {
        let Some(cache) = &self.cache else {
            return false;
        };

        let Some(data) = cache.get_response(domain, qtype_num, req_id).await else {
            return false;
        };

        debug!("[{}] {}", hit_tag, domain);

        let _ = self.socket.send_to(&data, src).await;

        true
    }

    pub async fn cache_response(
        &self,
        domain: &str,
        qtype_num: u16,
        response: &[u8],
        skip_tag: &str,
    ) {
        let Some(cache) = &self.cache else {
            return;
        };

        cache
            .put_response(domain, qtype_num, response, skip_tag)
            .await;
    }

    pub async fn query_upstream_or_servfail(
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
                    warn!("[{}] {} -> SERVFAIL", tag, domain);
                }

                build_servfail_response(query)
            }
        }
    }

    pub async fn run(self: Arc<Self>) {
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

    pub async fn handle_request(&self, request: Vec<u8>, src: SocketAddr) {
        let started_at = Instant::now();

        let query_msg = match Message::from_vec(&request) {
            Ok(m) => m,

            Err(e) => {
                let elapsed_ms = started_at.elapsed().as_secs_f64() * 1000.0;

                error!(
                    "Failed to parse DNS request from {}: {}, cost={:.3}ms",
                    src, e, elapsed_ms
                );

                return;
            }
        };

        if query_msg.queries().len() != 1 {
            let servfail = build_servfail_response(&query_msg);
            let _ = self.socket.send_to(&servfail, src).await;

            let elapsed_ms = started_at.elapsed().as_secs_f64() * 1000.0;

            debug!(
                "[DONE] {} multi-query -> SERVFAIL, cost={:.3}ms",
                src, elapsed_ms
            );

            return;
        }

        let query = &query_msg.queries()[0];
        let qtype = query.query_type();
        let raw_domain = query.name().to_utf8().to_string();
        let clean_domain = canonical_domain(&raw_domain);

        match qtype {
            RecordType::A => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::A,
                    request: &request,
                    query_msg: &query_msg,
                    clean_domain: &clean_domain,
                    src,
                };

                self.handle_address_request(ctx).await;
            }

            RecordType::AAAA => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::Aaaa,
                    request: &request,
                    query_msg: &query_msg,
                    clean_domain: &clean_domain,
                    src,
                };

                self.handle_address_request(ctx).await;
            }

            _ => {
                debug!("[NON-A] {} type={:?} -> domestic", clean_domain, qtype);

                let _ = self
                    .forward_to_upstream(&request, &query_msg, &self.domestic_upstream, &src)
                    .await;
            }
        }

        let elapsed_ms = started_at.elapsed().as_secs_f64() * 1000.0;

        debug!(
            "[DONE] {} type={:?} from={} cost={:.3}ms",
            clean_domain, qtype, src, elapsed_ms
        );
    }

    pub async fn send_dns_query(&self, request: &[u8], upstream: &SocketAddr) -> Option<Vec<u8>> {
        const MAX_RETRIES: u32 = 5;
        let mut last_error: Option<(u32, String)> = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                debug!(
                    "Retrying DNS query to {} (attempt {}/{})",
                    upstream, attempt, MAX_RETRIES
                );
            }

            match self.try_send_query_once(request, upstream).await {
                Ok(resp) => return Some(resp),
                Err(e) => {
                    debug!(
                        "DNS query to {} failed (attempt {}/{}): {}",
                        upstream,
                        attempt + 1,
                        MAX_RETRIES + 1,
                        e
                    );
                    last_error = Some((attempt + 1, e));
                }
            }
        }

        if let Some((attempts, err)) = last_error {
            warn!(
                "DNS query to {} failed after {} attempt(s): {}",
                upstream, attempts, err
            );
        }
        None
    }

    pub async fn try_send_query_once(
        &self,
        request: &[u8],
        upstream: &SocketAddr,
    ) -> Result<Vec<u8>, String> {
        let socket = bind_ephemeral_udp_for(upstream)
            .await
            .map_err(|e| format!("bind ephemeral socket failed: {e}"))?;

        if let Err(e) = socket.connect(upstream).await {
            return Err(format!("connect (UDP) unexpectedly failed: {e}"));
        }

        if let Err(e) = socket.send(request).await {
            return Err(format!("send failed: {e}"));
        }

        let mut buf = [0u8; 4096];
        let recv_result = tokio::time::timeout(self.timeout, socket.recv(&mut buf)).await;

        match recv_result {
            Ok(Ok(len)) => {
                let resp = buf[..len].to_vec();
                if request.len() >= 2 && resp.len() >= 2 && request[0..2] != resp[0..2] {
                    return Err("response ID mismatch".to_string());
                }
                Ok(resp)
            }
            Ok(Err(e)) => Err(format!("recv failed: {e}")),
            Err(_elapsed) => Err("timeout waiting for response".to_string()),
        }
    }

    pub async fn forward_to_upstream(
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

    pub fn is_domestic_country_ip(&self, ip: IpAddr) -> bool {
        let lookup_result = match self.mmdb.lookup(ip) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let country = match lookup_result.decode::<Country>() {
            Ok(Some(c)) => c,
            _ => return false,
        };

        country
            .country
            .iso_code
            .map(|code| {
                self.domestic_countries
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(code))
            })
            .unwrap_or(false)
    }
}

pub async fn bind_listen_socket(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    match addr {
        SocketAddr::V4(_) => Ok(UdpSocket::bind(addr).await?),

        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            socket.set_only_v6(false)?;
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;

            Ok(UdpSocket::from_std(socket.into())?)
        }
    }
}

pub fn parse_hosts<A: FromStr<Err = std::net::AddrParseError>>(
    map: &HashMap<String, String>,
) -> HashMap<String, A> {
    map.iter()
        .map(|(k, v)| {
            let addr = v
                .parse::<A>()
                .unwrap_or_else(|e| panic!("invalid IP for {k}: {e}"));

            (canonical_domain(k), addr)
        })
        .collect()
}

pub fn parse_upstream(s: &str, field_name: &str) -> anyhow::Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .with_context(|| format!("Invalid {}: {}", field_name, s))
}
