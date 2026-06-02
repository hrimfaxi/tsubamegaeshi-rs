use anyhow::Context;
use hickory_proto::op::{Message, ResponseCode};
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
use tokio::time::{sleep, timeout_at};
use tracing::{debug, error, info, trace, warn};

use crate::adblock::AdblockChecker;
use crate::cache::DnsCache;
use crate::dns_utils::{
    AddressQueryKind, build_a_response, build_aaaa_response, build_nodata_response,
    build_servfail_response, print_first_ip,
};
use crate::domain_utils::{canonical_domain, domain_matches_suffix, is_forced};
use crate::gfwlist::BloomDomainChecker;
use crate::mark_sites::{CommandNftManager, MarkGroup, MarkSites, NFT_SEM, NftManager};
use crate::pollution::{PollutionChecker, PollutionResult, extract_answer_ips};
use crate::task_guard::TaskGuard;

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
    pub pollution_checker: Option<PollutionChecker>,
    pub task_guard: Arc<TaskGuard>,
    pub trust_domestic_nodata_reply: bool,
}

async fn bind_ephemeral_udp_for(upstream: &SocketAddr) -> std::io::Result<UdpSocket> {
    match upstream {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await,
    }
}

impl DnsServer {
    /// 国外上游专用：一次发送，循环接收，污染检测
    /// 语义：最多丢弃 `checker.max_packets` 个污染包，遇到干净包立刻返回
    /// ID 不匹配或解析失败的包直接丢弃，不计入污染额度
    async fn foreign_query(
        &self,
        request: &[u8],
        query: &Message,
        upstream: &SocketAddr,
        timeout: Duration,
    ) -> Vec<u8> {
        let checker = match self.pollution_checker.as_ref() {
            Some(c) if c.max_packets > 0 => c,
            _ => {
                return self
                    .query_upstream_or_servfail(request, query, upstream, None)
                    .await;
            }
        };

        if request.len() < 2 {
            error!("Foreign multiple recv: request too short (< 2 bytes)");
            return build_servfail_response(query);
        }

        let socket = match bind_ephemeral_udp_for(upstream).await {
            Ok(s) => s,
            Err(e) => {
                error!("Foreign multiple recv: bind failed: {}", e);
                return build_servfail_response(query);
            }
        };
        if let Err(e) = socket.connect(upstream).await {
            error!("Foreign multiple recv: connect failed: {}", e);
            return build_servfail_response(query);
        }
        if let Err(e) = socket.send(request).await {
            error!("Foreign multiple recv: send failed: {}", e);
            return build_servfail_response(query);
        }

        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + timeout;
        let req_id = u16::from_be_bytes([request[0], request[1]]);
        let mut polluted_count = 0;
        let mut recv_count = 0;
        let max_total_packets = checker.max_packets.saturating_mul(4).max(16);

        loop {
            let recv_fut = socket.recv(&mut buf);
            match timeout_at(deadline, recv_fut).await {
                Ok(Ok(len)) => {
                    recv_count += 1;
                    if recv_count > max_total_packets {
                        warn!(
                            "recv max total {} reached, returning SERVFAIL",
                            max_total_packets
                        );
                        return build_servfail_response(query);
                    }

                    if len < 2 {
                        debug!("recv #{}: too short", recv_count);
                        continue;
                    }

                    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if resp_id != req_id {
                        debug!("recv #{}: id mismatch", recv_count);
                        continue;
                    }

                    let data = buf[..len].to_vec();
                    match checker.check(&data) {
                        PollutionResult::Clean => {
                            debug!(
                                "recv #{}: clean (after {} polluted)",
                                recv_count, polluted_count
                            );
                            return data;
                        }
                        PollutionResult::Invalid => {
                            warn!("recv #{}: invalid packet", recv_count);
                            continue;
                        }
                        PollutionResult::Polluted => {
                            polluted_count += 1;
                            if polluted_count >= checker.max_packets {
                                warn!(
                                    "recv #{}: polluted (max {} reached), returning SERVFAIL",
                                    recv_count, checker.max_packets
                                );
                                return build_servfail_response(query);
                            }
                            debug!(
                                "recv #{}: polluted ({}/{})",
                                recv_count, polluted_count, checker.max_packets
                            );
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("recv error after {} packets: {}", recv_count, e);
                    return build_servfail_response(query);
                }
                Err(_) => {
                    warn!("timeout after {} packets, returning SERVFAIL", recv_count);
                    return build_servfail_response(query);
                }
            }
        }
    }

    pub async fn apply_mark_sites(&self, final_resp: &[u8], clean_domain: &str) {
        let Some(mark_sites) = &self.mark_sites else {
            return;
        };
        let Some(nft) = &self.nft_manager else { return };

        let matched_groups: Vec<&MarkGroup> = mark_sites.match_groups(clean_domain).collect();
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

        let mut ips = HashSet::new();
        if let Ok(_msg) = Message::from_vec(final_resp)
            && let Ok(all_ips) = extract_answer_ips(final_resp)
        {
            for ip in all_ips {
                ips.insert(ip);
            }
        }

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

        self.task_guard.spawn_blocking(move || {
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

            AddressQueryKind::Https => {
                let v4_hints: Vec<Ipv4Addr> = self
                    .hosts_v4
                    .as_ref()
                    .and_then(|h| h.get(ctx.clean_domain))
                    .into_iter()
                    .copied()
                    .collect();

                let v6_hints: Vec<Ipv6Addr> = self
                    .hosts_v6
                    .as_ref()
                    .and_then(|h| h.get(ctx.clean_domain))
                    .into_iter()
                    .copied()
                    .collect();

                if !v4_hints.is_empty() || !v6_hints.is_empty() {
                    info!(
                        "[HOSTS-HTTPS] {} -> custom hints IPv4: {:?}, IPv6: {:?}",
                        ctx.clean_domain, v4_hints, v6_hints
                    );
                    let resp = crate::dns_utils::build_https_response(
                        ctx.query_msg,
                        v4_hints,
                        v6_hints,
                        60,
                    );
                    let _ = self.socket.send_to(&resp, ctx.src).await;
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

    /// 向国外上游查询，打印日志，并按条件缓存和打标，最后回复客户端
    async fn forward_foreign_cached(&self, ctx: &RequestContext<'_>, tag: &str) {
        let upstream = &self.foreign_upstream;
        let resp = self
            .foreign_query(ctx.request, ctx.query_msg, upstream, self.timeout)
            .await;

        print_first_ip(&resp, tag, ctx.clean_domain, &upstream.to_string());

        // 只有 NoError 的响应才缓存和打标
        self.cache_and_mark_if_ok(
            &resp,
            ctx.clean_domain,
            ctx.kind.cache_qtype(),
            ctx.kind.cache_skip_tag(),
        )
        .await;

        let _ = self.socket.send_to(&resp, ctx.src).await;
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

            self.forward_foreign_cached(ctx, ctx.kind.force_foreign_tag())
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

            self.forward_foreign_cached(ctx, ctx.kind.gfwlist_tag())
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
            Some(resp_bytes) => {
                let msg = match Message::from_vec(resp_bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(
                            "Failed to parse domestic response for {}: {}",
                            clean_domain, e
                        );
                        return false;
                    }
                };

                // 如果是 NOERROR 且没有任何 A 记录，视为 NODATA
                if msg.response_code() == ResponseCode::NoError
                    && !msg
                        .answers()
                        .iter()
                        .any(|rr| rr.record_type() == RecordType::A)
                {
                    if self.trust_domestic_nodata_reply {
                        debug!("[DOMESTIC-NODATA-A] {} trusted, NODATA", clean_domain);
                        return true;
                    } else {
                        debug!(
                            "[DOMESTIC-NODATA-A] {} not trusted, fallback to foreign",
                            clean_domain
                        );
                        return false;
                    }
                }

                match msg.answers().iter().find_map(|rr| {
                    if rr.record_type() == RecordType::A {
                        rr.data().and_then(|d| d.ip_addr())
                    } else {
                        None
                    }
                }) {
                    Some(ip) => {
                        if let IpAddr::V4(v4) = ip {
                            let v4_polluted = self
                                .pollution_checker
                                .as_ref()
                                .map(|c| c.is_ipv4_polluted(&v4))
                                .unwrap_or(false);
                            if v4_polluted {
                                debug!("[DOMESTIC-POLLUTED] {} {} -> foreign", clean_domain, ip);
                                return false;
                            }
                        }
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
                        // 如果 NOERROR 但无 A 记录的处理已在上面分支，这里应该不会到达，
                        // 但为安全仍返回 false
                        debug!("[DOMESTIC-NO-IP] {} -> foreign", clean_domain);
                        false
                    }
                }
            }
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
                let msg = match Message::from_vec(data) {
                    Ok(m) => m,
                    Err(_) => {
                        debug!("[DOMESTIC-PARSE-ERR-AAAA] {} -> foreign", clean_domain);
                        return false;
                    }
                };

                // 如果是 NOERROR 且没有任何 AAAA 记录，视为 NODATA
                if msg.response_code() == ResponseCode::NoError
                    && !msg
                        .answers()
                        .iter()
                        .any(|rr| rr.record_type() == RecordType::AAAA)
                {
                    if self.trust_domestic_nodata_reply {
                        debug!("[DOMESTIC-NODATA-AAAA] {} trusted, NODATA", clean_domain);
                        return true;
                    } else {
                        debug!(
                            "[DOMESTIC-NODATA-AAAA] {} not trusted, fallback to foreign",
                            clean_domain
                        );
                        return false;
                    }
                }

                let first_ipv6 = msg.answers().iter().find_map(|rr| {
                    if rr.record_type() == RecordType::AAAA {
                        rr.data().and_then(|d| d.ip_addr())
                    } else {
                        None
                    }
                });

                match first_ipv6 {
                    Some(IpAddr::V6(ipv6)) => {
                        let ipv6_polluted = self
                            .pollution_checker
                            .as_ref()
                            .map(|c| c.is_ipv6_polluted(&ipv6))
                            .unwrap_or(false);
                        if ipv6_polluted {
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
            AddressQueryKind::Https => {
                self.should_use_domestic_https_response(clean_domain, domestic_resp)
            }
        }
    }

    pub async fn handle_address_request(&self, ctx: RequestContext<'_>) {
        // 如果禁用了 AAAA，则不查缓存、不查上游，直接返回 NODATA
        if ctx.kind == AddressQueryKind::Aaaa && !self.enable_ipv6_aaaa {
            let nodata = build_nodata_response(ctx.query_msg);
            let _ = self.socket.send_to(&nodata, ctx.src).await;
            return;
        }

        // Hosts 覆盖
        if self.handle_hosts_override(&ctx).await {
            return;
        }

        // 广告屏蔽：HTTPS 查询返回 NODATA
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
                AddressQueryKind::Https => {
                    info!("[ADBLOCK-HTTPS] {} -> NODATA", ctx.clean_domain);
                    build_nodata_response(ctx.query_msg)
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
                .foreign_query(
                    ctx.request,
                    ctx.query_msg,
                    &self.foreign_upstream,
                    self.timeout,
                )
                .await;
            (
                resp,
                ctx.kind.foreign_tag(),
                self.foreign_upstream.to_string(),
            )
        };

        print_first_ip(&final_resp, chosen_tag, ctx.clean_domain, &chosen_upstream);

        self.cache_and_mark_if_ok(
            &final_resp,
            ctx.clean_domain,
            ctx.kind.cache_qtype(),
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

            self.task_guard.spawn(|_| async move {
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

            RecordType::HTTPS => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::Https,
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
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut attempt = 0;
        let mut last_error: Option<String> = None;

        loop {
            let now = Instant::now();
            // 如果已经超过截止时间，直接退出
            if now >= deadline {
                break;
            }

            if attempt > 0 {
                // 计算剩余可用时间（饱和到非负）
                let remaining = deadline.saturating_duration_since(now);
                // 等待至多 2 秒，但不超过剩余时间
                let wait = std::cmp::min(remaining, Duration::from_secs(2));
                sleep(wait).await;
            }

            attempt += 1;
            debug!("Sending DNS query to {} (attempt {})", upstream, attempt);

            match self.try_send_query_once(request, upstream).await {
                Ok(resp) => return Some(resp),
                Err(e) => {
                    debug!(
                        "DNS query to {} failed (attempt {}): {}",
                        upstream, attempt, e
                    );
                    last_error = Some(e);
                }
            }
        }

        if let Some(err) = last_error {
            warn!(
                "DNS query to {} failed after {} attempt(s) within 10 seconds: {}",
                upstream, attempt, err
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

    pub fn should_use_domestic_https_response(
        &self,
        clean_domain: &str,
        domestic_resp: &Option<Vec<u8>>,
    ) -> bool {
        match domestic_resp {
            Some(data) => {
                if let Ok(_msg) = Message::from_vec(data) {
                    let all_hints = extract_answer_ips(data).unwrap_or_default();
                    if all_hints.is_empty() {
                        debug!("[DOMESTIC-HTTPS] {} no hints -> keep", clean_domain);
                        return true;
                    } else {
                        debug!(
                            "[HTTPS-DEBUG] {} domestic hints: {:?}",
                            clean_domain, all_hints
                        );
                    }
                    for ip in all_hints {
                        match ip {
                            IpAddr::V4(v4) => {
                                let v4_polluted = self
                                    .pollution_checker
                                    .as_ref()
                                    .map(|c| c.is_ipv4_polluted(&v4))
                                    .unwrap_or(false);
                                if v4_polluted || !self.is_domestic_country_ip(ip) {
                                    debug!(
                                        "[DOMESTIC-HTTPS-REJECT] {} IPv4 {} not domestic -> foreign",
                                        clean_domain, v4
                                    );
                                    return false;
                                }
                            }
                            IpAddr::V6(v6) => {
                                let v6_polluted = self
                                    .pollution_checker
                                    .as_ref()
                                    .map(|c| c.is_ipv6_polluted(&v6))
                                    .unwrap_or(false);
                                if v6_polluted || !self.is_domestic_country_ip(ip) {
                                    debug!(
                                        "[DOMESTIC-HTTPS-REJECT] {} IPv6 {} polluted/not domestic -> foreign",
                                        clean_domain, v6
                                    );
                                    return false;
                                }
                            }
                        }
                    }
                    debug!("[DOMESTIC-HTTPS-KEEP] {} all hints domestic", clean_domain);
                    true
                } else {
                    debug!("[DOMESTIC-HTTPS-PARSE-ERR] {} -> foreign", clean_domain);
                    false
                }
            }
            None => {
                debug!("[DOMESTIC-HTTPS-TIMEOUT] {} -> foreign", clean_domain);
                false
            }
        }
    }

    /// 如果响应成功，则写入缓存并执行 mark_sites
    async fn cache_and_mark_if_ok(&self, resp: &[u8], domain: &str, qtype: u16, skip_tag: &str) {
        if let Ok(msg) = Message::from_vec(resp)
            && msg.response_code() == ResponseCode::NoError
        {
            self.cache_response(domain, qtype, resp, skip_tag).await;
            self.apply_mark_sites(resp, domain).await;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    // ========== parse_hosts ==========

    #[test]
    fn test_parse_hosts_ipv4() {
        let mut map = HashMap::new();
        map.insert("Example.COM".to_string(), "1.2.3.4".to_string());
        let result = parse_hosts::<Ipv4Addr>(&map);
        assert_eq!(result.get("example.com"), Some(&Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_parse_hosts_ipv6() {
        let mut map = HashMap::new();
        map.insert("Example.COM".to_string(), "::1".to_string());
        let result = parse_hosts::<Ipv6Addr>(&map);
        assert_eq!(
            result.get("example.com"),
            Some(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_parse_hosts_key_normalization() {
        let mut map = HashMap::new();
        map.insert(".Test.ORG.".to_string(), "1.2.3.4".to_string());
        let result = parse_hosts::<Ipv4Addr>(&map);
        assert!(result.contains_key("test.org"));
        assert!(!result.contains_key(".Test.ORG."));
    }

    #[test]
    #[should_panic(expected = "invalid IP for bad.example.com")]
    fn test_parse_hosts_invalid_ip_panics() {
        let mut map = HashMap::new();
        map.insert("bad.example.com".to_string(), "not-an-ip".to_string());
        let _: HashMap<String, Ipv4Addr> = parse_hosts(&map);
    }

    // ========== parse_upstream ==========

    #[test]
    fn test_parse_upstream_ipv4_with_port() {
        let result = parse_upstream("8.8.8.8:53", "test").unwrap();
        assert_eq!(
            result,
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53)
        );
    }

    #[test]
    fn test_parse_upstream_ipv4_without_port() {
        let result = parse_upstream("8.8.8.8", "test").unwrap();
        assert_eq!(
            result,
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53)
        );
    }

    #[test]
    fn test_parse_upstream_ipv6_with_port() {
        let result = parse_upstream("[2001:4860:4860::8888]:53", "test").unwrap();
        assert_eq!(
            result,
            SocketAddr::new(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into(),
                53
            )
        );
    }

    #[test]
    fn test_parse_upstream_ipv6_without_port() {
        let result = parse_upstream("2001:4860:4860::8888", "test").unwrap();
        assert_eq!(
            result,
            SocketAddr::new(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into(),
                53
            )
        );
    }

    #[test]
    fn test_parse_upstream_invalid() {
        let result = parse_upstream("not-a-host", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_upstream_invalid_ipv6_no_brackets_with_port() {
        // "2001::1:53" 会被解析为 IPv6 + 端口 53，但 IPv6 里含 :53 是合法的地址部分
        // 实际上 "2001::1:53" 作为 SocketAddr::from_str 会成功（IPv6 地址 2001::1:53）
        // 但 parse_upstream 会先尝试 s.parse::<SocketAddr>()，这能解析
        // 所以这里测一个明确非法的
        let result = parse_upstream(":::53", "test");
        assert!(result.is_err());
    }
}
