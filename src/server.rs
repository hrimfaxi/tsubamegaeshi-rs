use anyhow::Context;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
use maxminddb::Reader;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout_at};
use tracing::{debug, error, trace, warn};

use crate::adblock::AdblockChecker;
use crate::cache::DnsCache;
use crate::config::OneOrMany;
use crate::dns_utils::{
    AddressQueryKind, build_a_multi_response, build_a_response, build_aaaa_multi_response,
    build_aaaa_response, build_nodata_response, build_servfail_response, debug_print_first_ip,
    response_cache_ttl,
};
use crate::domain_utils::{canonical_domain, domain_matches_suffix_canonical, is_forced_canonical};
use crate::gfwlist::BloomDomainChecker;
use crate::mark_sites::{CommandNftManager, MarkGroup, MarkSites, NFT_SEM, NftManager};
use crate::pollution::{PollutionChecker, PollutionResult, extract_answer_ips};
use crate::task_guard::TaskGuard;

#[derive(Deserialize)]
struct MinimalMmdb<'a> {
    #[serde(borrow, default)]
    country: MinimalCountry<'a>,
}

#[derive(Deserialize, Default)]
struct MinimalCountry<'a> {
    #[serde(borrow, default)]
    iso_code: Option<&'a str>,
}

pub struct RequestContext<'a> {
    pub kind: AddressQueryKind,
    pub request: &'a [u8],
    pub query_msg: &'a Message,
    pub clean_domain: &'a str,
    pub src: SocketAddr,
}

pub struct DnsServer {
    pub socket: UdpSocket,
    pub special_upstream: Option<Vec<SocketAddr>>,
    pub domestic_upstream: Vec<SocketAddr>,
    pub foreign_upstream: Vec<SocketAddr>,
    pub mmdb: Reader<Vec<u8>>,
    pub special_suffixes: Option<Vec<String>>,
    pub cache: Option<DnsCache>,
    pub timeout: Duration,
    pub enable_ipv6_aaaa: bool,
    pub gfw_checker: Option<BloomDomainChecker>,
    pub force_foreign: Option<Vec<String>>,
    pub force_domestic: Option<Vec<String>>,
    pub hosts_v4: Option<HashMap<String, Vec<Ipv4Addr>>>,
    pub hosts_v6: Option<HashMap<String, Vec<Ipv6Addr>>>,
    pub mark_sites: Option<MarkSites>,
    pub nft_manager: Option<Arc<CommandNftManager>>,
    pub adblock_checker: Option<Arc<AdblockChecker>>,
    pub domestic_countries: Vec<String>,
    pub pollution_checker: Option<PollutionChecker>,
    pub task_guard: Arc<TaskGuard>,
    pub trust_domestic_nodata_reply: bool,
    pub max_in_flight: usize,
    pub in_flight: AtomicUsize,
}

async fn bind_ephemeral_udp_for(upstream: &SocketAddr) -> std::io::Result<UdpSocket> {
    match upstream {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await,
    }
}

/// 竞速中一个上游应答的裁决结果
#[derive(Debug, PartialEq)]
enum RaceVerdict {
    /// 有资格胜出
    Usable,
    /// 与请求对得上、但 RCODE 为 SERVFAIL / REFUSED：该上游自身有问题
    SoftFailure,
    /// 无法解析、不是应答、ID 对不上、问题段（QNAME/QTYPE/QCLASS）与请求不符
    Unusable,
}

/// 判定上游应答是否"有资格"赢得竞速。
///
/// 只有完整、可解析、确为应答、且 ID 与问题段（QNAME/QTYPE/QCLASS）都与请求一致的
/// 报文才算有效应答；SERVFAIL / REFUSED 与各类畸形包都只是兜底候选，不打断其它上游。
/// 关联性校验先于 RCODE 分类：ID 或问题段对不上的 SERVFAIL 是无关报文，不是软失败。
fn classify_answer(request: &[u8], resp: &[u8]) -> RaceVerdict {
    let Ok(msg) = Message::from_vec(resp) else {
        return RaceVerdict::Unusable;
    };

    if msg.message_type() != MessageType::Response {
        return RaceVerdict::Unusable;
    }

    if request.len() < 2 || msg.id() != u16::from_be_bytes([request[0], request[1]]) {
        return RaceVerdict::Unusable;
    }

    // 请求本身解析不出来时不做问题段比对，避免误伤
    if let Ok(req) = Message::from_vec(request) {
        match (req.queries().first(), msg.queries().first()) {
            (Some(a), Some(b)) => {
                if a.query_type() != b.query_type()
                    || a.query_class() != b.query_class()
                    || a.name().to_lowercase() != b.name().to_lowercase()
                {
                    return RaceVerdict::Unusable;
                }
            }
            (Some(_), None) => return RaceVerdict::Unusable,
            _ => {}
        }
    }

    if matches!(
        msg.response_code(),
        ResponseCode::ServFail | ResponseCode::Refused
    ) {
        return RaceVerdict::SoftFailure;
    }

    RaceVerdict::Usable
}

/// 并发竞速：同时轮询多个上游查询 future，第一个返回有效应答（Some）者胜出，
/// 其余 future 直接丢弃，等于 abort（底层临时 socket 随之关闭）。
///
/// 软失败（SERVFAIL / REFUSED）与畸形包不判胜，继续等其它上游；它们只作为兜底候选，
/// 只有没有任何上游给出有效应答时才把第一个兜底候选交回客户端（保留上游原始报文），
/// 一个兜底候选都没有（全部超时/socket 错误）则返回 None。
async fn race_queries<Fut: Future<Output = Option<Vec<u8>>>>(
    request: &[u8],
    candidates: Vec<(SocketAddr, Fut)>,
) -> Option<Vec<u8>> {
    let mut inflight: FuturesUnordered<_> = candidates
        .into_iter()
        .map(|(upstream, fut)| async move { (upstream, fut.await) })
        .collect();

    let mut fallback: Option<Vec<u8>> = None;

    while let Some((upstream, result)) = inflight.next().await {
        let Some(resp) = result else { continue };

        match classify_answer(request, &resp) {
            RaceVerdict::Usable => {
                debug!(
                    "race: {} won, aborted {} loser(s)",
                    upstream,
                    inflight.len()
                );
                return Some(resp);
            }
            verdict => {
                debug!(
                    "race: {} answer unusable ({:?}), still waiting {} other(s)",
                    upstream,
                    verdict,
                    inflight.len()
                );
                if fallback.is_none() {
                    fallback = Some(resp);
                }
            }
        }
    }

    fallback
}

/// 向单个上游发一次查询并等待首个应答（不重试）。
/// 使用独立临时 socket（不是共享监听 socket），地址族跟随上游。
async fn query_upstream_once(
    request: &[u8],
    upstream: &SocketAddr,
    timeout: Duration,
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
    let recv_result = tokio::time::timeout(timeout, socket.recv(&mut buf)).await;

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

/// 单个国外上游：一次发送，循环接收，污染检测
/// 语义：最多丢弃 `checker.max_packets` 个污染包，遇到干净包立刻返回
/// ID 不匹配或解析失败的包直接丢弃，不计入污染额度
/// 超时、socket 错误或污染额度耗尽返回 None（交给竞速的其他上游）
async fn foreign_query_filtered(
    request: &[u8],
    upstream: &SocketAddr,
    timeout: Duration,
    domain: &str,
    checker: &PollutionChecker,
) -> Option<Vec<u8>> {
    if request.len() < 2 {
        error!("Foreign multiple recv: request too short (< 2 bytes)");
        return None;
    }

    let socket = match bind_ephemeral_udp_for(upstream).await {
        Ok(s) => s,
        Err(e) => {
            error!("Foreign multiple recv: bind failed: {}", e);
            return None;
        }
    };
    if let Err(e) = socket.connect(upstream).await {
        error!("Foreign multiple recv: connect failed: {}", e);
        return None;
    }
    if let Err(e) = socket.send(request).await {
        error!("Foreign multiple recv: send failed: {}", e);
        return None;
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
                    warn!("recv max total {} reached, giving up", max_total_packets);
                    return None;
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
                        return Some(data);
                    }
                    PollutionResult::Invalid => {
                        warn!("recv #{}: invalid packet", recv_count);
                        continue;
                    }
                    PollutionResult::Polluted => {
                        polluted_count += 1;
                        if polluted_count >= checker.max_packets {
                            warn!(
                                "recv #{}: polluted (max {} reached), giving up",
                                recv_count, checker.max_packets
                            );
                            return None;
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
                return None;
            }
            Err(_) => {
                warn!(
                    "[FOREIGN-TIMEOUT] {} -> {} timeout after {} packets ({:?})",
                    domain, upstream, recv_count, timeout
                );
                return None;
            }
        }
    }
}

impl DnsServer {
    /// 单个国外上游查询：污染检测开启时走多接收过滤循环，否则退化为普通单次查询
    async fn foreign_query_inner(
        &self,
        request: &[u8],
        upstream: &SocketAddr,
        timeout: Duration,
        domain: &str,
    ) -> Option<Vec<u8>> {
        match self
            .pollution_checker
            .as_ref()
            .filter(|c| c.max_packets > 0)
        {
            Some(checker) => {
                foreign_query_filtered(request, upstream, timeout, domain, checker).await
            }
            None => self.send_dns_query(request, upstream).await,
        }
    }

    /// 向多个国外上游并发查询，第一个拿到干净应答的胜出；
    /// 全部失败（超时/污染）则回 SERVFAIL
    async fn foreign_query(
        &self,
        request: &[u8],
        query: &Message,
        upstreams: &[SocketAddr],
        timeout: Duration,
        domain: &str,
    ) -> Vec<u8> {
        let futures = upstreams
            .iter()
            .map(|upstream| {
                (
                    *upstream,
                    self.foreign_query_inner(request, upstream, timeout, domain),
                )
            })
            .collect();

        match race_queries(request, futures).await {
            Some(resp) => resp,
            None => build_servfail_response(query),
        }
    }

    pub async fn apply_mark_sites(&self, final_resp: &[u8], clean_domain: &str) {
        self.apply_mark_sites_inner(final_resp, clean_domain, None)
            .await;
    }

    async fn apply_mark_sites_inner(
        &self,
        final_resp: &[u8],
        clean_domain: &str,
        precomputed_ips: Option<Vec<IpAddr>>,
    ) {
        let Some(mark_sites) = &self.mark_sites else {
            return;
        };
        let Some(nft) = &self.nft_manager else { return };

        let matched_groups: Vec<&MarkGroup> = mark_sites.match_groups(clean_domain).collect();
        if matched_groups.is_empty() {
            return;
        }

        debug!(
            "[MARK_SITES] domain '{}' matched {} group(s): {:?}",
            clean_domain,
            matched_groups.len(),
            matched_groups
                .iter()
                .map(|g| &g.nft_table)
                .collect::<Vec<_>>()
        );

        let all_ips = match precomputed_ips {
            Some(ips) if !ips.is_empty() => ips,
            _ => match extract_answer_ips(final_resp) {
                Ok(ips) if !ips.is_empty() => ips,
                _ => return,
            },
        };

        let ips: HashSet<IpAddr> = all_ips.into_iter().collect();

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

    pub async fn handle_hosts_override(&self, ctx: &RequestContext<'_>) -> Option<Vec<u8>> {
        // hosts 处理：
        // - A/AAAA：返回 hosts 里的 IP 列表（随机顺序，负载均衡）
        // - HTTPS：返回 hosts 里的 IP 作为 hints
        // - 若域名在 hosts 中但无对应类型，返回 NODATA
        match ctx.kind {
            AddressQueryKind::A => {
                if let Some(ips) = self.hosts_v4.as_ref().and_then(|h| h.get(ctx.clean_domain)) {
                    let mut shuffled = ips.clone();
                    fastrand::shuffle(&mut shuffled);
                    let resp = build_a_multi_response(ctx.query_msg, &shuffled, 60);
                    debug!("[HOSTS-A] {} -> {:?}", ctx.clean_domain, shuffled);
                    let _ = self.socket.send_to(&resp, ctx.src).await;
                    return Some(resp);
                }

                if self
                    .hosts_v6
                    .as_ref()
                    .is_some_and(|h| h.contains_key(ctx.clean_domain))
                {
                    debug!("[HOSTS-NO-A] {} (v6 only)", ctx.clean_domain);
                    let nodata = build_nodata_response(ctx.query_msg);
                    let _ = self.socket.send_to(&nodata, ctx.src).await;
                    return Some(nodata);
                }

                None
            }

            AddressQueryKind::Aaaa => {
                if let Some(ips) = self.hosts_v6.as_ref().and_then(|h| h.get(ctx.clean_domain)) {
                    let mut shuffled = ips.clone();
                    fastrand::shuffle(&mut shuffled);
                    let resp = build_aaaa_multi_response(ctx.query_msg, &shuffled, 60);
                    debug!("[HOSTS-AAAA] {} -> {:?}", ctx.clean_domain, shuffled);
                    let _ = self.socket.send_to(&resp, ctx.src).await;
                    return Some(resp);
                }

                if self
                    .hosts_v4
                    .as_ref()
                    .is_some_and(|h| h.contains_key(ctx.clean_domain))
                {
                    debug!("[HOSTS-NO-AAAA] {} (v4 only)", ctx.clean_domain);
                    let nodata = build_nodata_response(ctx.query_msg);
                    let _ = self.socket.send_to(&nodata, ctx.src).await;
                    return Some(nodata);
                }

                None
            }

            AddressQueryKind::Https => {
                let mut v4_hints: Vec<Ipv4Addr> = self
                    .hosts_v4
                    .as_ref()
                    .and_then(|h| h.get(ctx.clean_domain))
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect();

                let mut v6_hints: Vec<Ipv6Addr> = self
                    .hosts_v6
                    .as_ref()
                    .and_then(|h| h.get(ctx.clean_domain))
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect();

                fastrand::shuffle(&mut v4_hints);
                fastrand::shuffle(&mut v6_hints);

                if !v4_hints.is_empty() || !v6_hints.is_empty() {
                    debug!(
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
                    return Some(resp);
                }
                None
            }
        }
    }

    pub async fn forward_to_upstream_and_get(
        &self,
        request: &[u8],
        query: &Message,
        upstreams: &[SocketAddr],
        client: &SocketAddr,
    ) -> Vec<u8> {
        let data = self
            .race_upstreams_or_servfail(request, query, upstreams)
            .await;

        let _ = self.socket.send_to(&data, client).await;

        data
    }

    pub async fn forward_and_cache(
        &self,
        ctx: &RequestContext<'_>,
        upstreams: &[SocketAddr],
        tag: &str,
    ) -> Vec<u8> {
        let resp = self
            .forward_to_upstream_and_get(ctx.request, ctx.query_msg, upstreams, &ctx.src)
            .await;

        debug_print_first_ip(&resp, tag, ctx.clean_domain, upstreams, None);

        self.apply_mark_sites(&resp, ctx.clean_domain).await;

        self.cache_response(
            ctx.clean_domain,
            ctx.kind.cache_qtype(),
            &resp,
            ctx.kind.cache_skip_tag(),
        )
        .await;

        resp
    }

    /// 向国外上游查询，打印日志，并按条件缓存和打标，最后回复客户端
    async fn forward_foreign_cached(&self, ctx: &RequestContext<'_>, tag: &str) -> Vec<u8> {
        let upstreams = &self.foreign_upstream;
        let resp = self
            .foreign_query(
                ctx.request,
                ctx.query_msg,
                upstreams,
                self.timeout,
                ctx.clean_domain,
            )
            .await;

        debug_print_first_ip(&resp, tag, ctx.clean_domain, upstreams, None);

        // 只有 NoError 的响应才缓存和打标
        self.cache_and_mark_if_ok(&resp, ctx.clean_domain, ctx.kind.cache_qtype())
            .await;

        let _ = self.socket.send_to(&resp, ctx.src).await;

        resp
    }

    pub async fn forward_by_static_rules(&self, ctx: &RequestContext<'_>) -> Option<Vec<u8>> {
        if let (Some(suffixes), Some(upstreams)) = (&self.special_suffixes, &self.special_upstream)
        {
            for suffix in suffixes {
                if domain_matches_suffix_canonical(ctx.clean_domain, suffix) {
                    debug!(
                        "[{}] {} -> dnsmasq",
                        ctx.kind.special_tag(),
                        ctx.clean_domain
                    );

                    let resp = self
                        .forward_and_cache(ctx, upstreams, ctx.kind.special_tag())
                        .await;

                    return Some(resp);
                }
            }
        }

        if is_forced_canonical(ctx.clean_domain, &self.force_domestic) {
            debug!(
                "[{}] {} -> {:?}",
                ctx.kind.force_domestic_tag(),
                ctx.clean_domain,
                self.domestic_upstream
            );

            let resp = self
                .forward_and_cache(ctx, &self.domestic_upstream, ctx.kind.force_domestic_tag())
                .await;

            return Some(resp);
        }

        if is_forced_canonical(ctx.clean_domain, &self.force_foreign) {
            debug!(
                "[{}] {} -> {:?}",
                ctx.kind.force_foreign_tag(),
                ctx.clean_domain,
                self.foreign_upstream
            );

            let resp = self
                .forward_foreign_cached(ctx, ctx.kind.force_foreign_tag())
                .await;

            return Some(resp);
        }

        if let Some(ref gfw) = self.gfw_checker
            && gfw.check(ctx.clean_domain)
        {
            trace!(
                "[{}] {} in gfwlist, direct to foreign",
                ctx.kind.gfwlist_tag(),
                ctx.clean_domain
            );

            let resp = self
                .forward_foreign_cached(ctx, ctx.kind.gfwlist_tag())
                .await;
            return Some(resp);
        }

        None
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

    pub async fn handle_address_request(&self, ctx: RequestContext<'_>) -> Vec<u8> {
        // 如果禁用了 AAAA，则不查缓存、不查上游，直接返回 NODATA
        if ctx.kind == AddressQueryKind::Aaaa && !self.enable_ipv6_aaaa {
            let nodata = build_nodata_response(ctx.query_msg);
            let _ = self.socket.send_to(&nodata, ctx.src).await;
            return nodata;
        }

        // Hosts 覆盖
        if let Some(resp) = self.handle_hosts_override(&ctx).await {
            return resp;
        }

        // 广告屏蔽：HTTPS 查询返回 NODATA
        if let Some(ref adblock) = self.adblock_checker
            && adblock.check(ctx.clean_domain)
        {
            let blocked_response = match ctx.kind {
                AddressQueryKind::A => {
                    debug!("[ADBLOCK-A] {} -> 0.0.0.0", ctx.clean_domain);
                    build_a_response(ctx.query_msg, Ipv4Addr::new(0, 0, 0, 0), 60)
                }
                AddressQueryKind::Aaaa => {
                    debug!("[ADBLOCK-AAAA] {} -> ::", ctx.clean_domain);
                    build_aaaa_response(ctx.query_msg, Ipv6Addr::UNSPECIFIED, 60)
                }
                AddressQueryKind::Https => {
                    debug!("[ADBLOCK-HTTPS] {} -> NODATA", ctx.clean_domain);
                    build_nodata_response(ctx.query_msg)
                }
            };
            let _ = self.socket.send_to(&blocked_response, ctx.src).await;
            return blocked_response;
        }

        // 缓存检查
        if let Some(resp) = self
            .send_cached_response(
                ctx.clean_domain,
                ctx.kind.cache_qtype(),
                ctx.query_msg.id(),
                ctx.src,
                ctx.kind.cache_hit_tag(),
            )
            .await
        {
            return resp;
        }

        // special suffix / force domestic / force foreign / gfwlist
        if let Some(resp) = self.forward_by_static_rules(&ctx).await {
            return resp;
        }

        // 普通域名：先查国内，根据 A/AAAA 各自规则判断是否使用国内结果
        debug!(
            "[{}] {} -> {:?}",
            ctx.kind.domestic_tag(),
            ctx.clean_domain,
            self.domestic_upstream
        );

        let domestic_resp = self
            .race_dns_query(ctx.request, &self.domestic_upstream)
            .await;

        let use_domestic =
            self.should_use_domestic_response(ctx.kind, ctx.clean_domain, &domestic_resp);

        let (final_resp, chosen_tag, chosen_upstream) = if use_domestic {
            let resp = domestic_resp.expect("domestic_resp must be Some when use_domestic is true");
            // 复用已解析的 Message 做缓存和打标，避免重复解析
            if let Ok(msg) = Message::from_vec(&resp) {
                self.cache_and_mark_if_ok_msg(
                    &msg,
                    &resp,
                    ctx.clean_domain,
                    ctx.kind.cache_qtype(),
                )
                .await;
            }
            (resp, ctx.kind.domestic_tag(), &self.domestic_upstream)
        } else {
            let resp = self
                .foreign_query(
                    ctx.request,
                    ctx.query_msg,
                    &self.foreign_upstream,
                    self.timeout,
                    ctx.clean_domain,
                )
                .await;
            self.cache_and_mark_if_ok(&resp, ctx.clean_domain, ctx.kind.cache_qtype())
                .await;
            (resp, ctx.kind.foreign_tag(), &self.foreign_upstream)
        };

        debug_print_first_ip(
            &final_resp,
            chosen_tag,
            ctx.clean_domain,
            chosen_upstream,
            None,
        );

        let _ = self.socket.send_to(&final_resp, ctx.src).await;
        final_resp
    }

    pub async fn send_cached_response(
        &self,
        domain: &str,
        qtype_num: u16,
        req_id: u16,
        src: SocketAddr,
        hit_tag: &str,
    ) -> Option<Vec<u8>> {
        let cache = self.cache.as_ref()?;

        let data = cache.get_response(domain, qtype_num, req_id).await?;

        debug!("[{}] {}", hit_tag, domain);

        let _ = self.socket.send_to(&data, src).await;

        Some(data)
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

    /// 并发向多个上游查询，第一个成功应答者胜出；
    /// 全部失败返回 SERVFAIL
    pub async fn race_upstreams_or_servfail(
        &self,
        request: &[u8],
        query: &Message,
        upstreams: &[SocketAddr],
    ) -> Vec<u8> {
        match self.race_dns_query(request, upstreams).await {
            Some(resp) => resp,
            None => build_servfail_response(query),
        }
    }

    /// 并发向多个上游发送同一查询，先返回有效应答的胜出，其余 future 被丢弃（abort）
    pub async fn race_dns_query(
        &self,
        request: &[u8],
        upstreams: &[SocketAddr],
    ) -> Option<Vec<u8>> {
        match upstreams {
            [] => None,
            [single] => self.send_dns_query(request, single).await,
            _ => {
                let futures = upstreams
                    .iter()
                    .map(|upstream| (*upstream, self.send_dns_query(request, upstream)))
                    .collect();

                race_queries(request, futures).await
            }
        }
    }

    pub async fn run(self: Arc<Self>) {
        let mut buf = [0u8; 4096];

        struct Guard(Arc<DnsServer>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
            }
        }

        loop {
            let (len, src) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,

                Err(e) => {
                    error!("recv_from error: {}", e);
                    continue;
                }
            };

            let prev = self.in_flight.fetch_add(1, Ordering::Relaxed);
            if prev >= self.max_in_flight {
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
                debug!("IN_FLIGHT full, dropping packet from {}", src);
                continue;
            }

            let request = buf[..len].to_vec();
            let server = self.clone();

            self.task_guard.spawn(|_| async move {
                let _guard = Guard(server.clone());
                let _ =
                    tokio::time::timeout(server.timeout * 3, server.handle_request(request, src))
                        .await;
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

        let final_resp = match qtype {
            RecordType::A => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::A,
                    request: &request,
                    query_msg: &query_msg,
                    clean_domain: &clean_domain,
                    src,
                };

                Some(self.handle_address_request(ctx).await)
            }

            RecordType::AAAA => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::Aaaa,
                    request: &request,
                    query_msg: &query_msg,
                    clean_domain: &clean_domain,
                    src,
                };

                Some(self.handle_address_request(ctx).await)
            }

            RecordType::HTTPS => {
                let ctx = RequestContext {
                    kind: AddressQueryKind::Https,
                    request: &request,
                    query_msg: &query_msg,
                    clean_domain: &clean_domain,
                    src,
                };
                Some(self.handle_address_request(ctx).await)
            }

            _ => {
                debug!("[NON-A] {} type={:?} -> domestic", clean_domain, qtype);

                let _ = self
                    .forward_to_upstream(&request, &query_msg, &self.domestic_upstream, &src)
                    .await;
                None
            }
        };

        let elapsed_ms = started_at.elapsed().as_secs_f64() * 1000.0;

        // 提取第一个 IP 用于日志
        let first_ip = final_resp.as_ref().and_then(|resp| {
            extract_answer_ips(resp)
                .ok()
                .and_then(|ips| ips.into_iter().next())
        });

        match (qtype, first_ip) {
            (_, Some(ip)) => {
                debug!(
                    "[DONE] {} type={:?} from={} cost={:.3}ms ip={}",
                    clean_domain, qtype, src, elapsed_ms, ip
                );
            }
            (RecordType::A | RecordType::AAAA | RecordType::HTTPS, None) => {
                // 检查 RCODE：SERVFAIL 才告警，NoError/NXDOMAIN 是正常结果
                let rcode = final_resp
                    .as_ref()
                    .and_then(|resp| Message::from_vec(resp).ok().map(|m| m.response_code()));
                match rcode {
                    Some(ResponseCode::NoError) => {
                        debug!(
                            "[DONE] {} type={:?} from={} cost={:.3}ms (NODATA)",
                            clean_domain, qtype, src, elapsed_ms
                        );
                    }
                    Some(ResponseCode::NXDomain) => {
                        debug!(
                            "[DONE] {} type={:?} from={} cost={:.3}ms (NXDOMAIN)",
                            clean_domain, qtype, src, elapsed_ms
                        );
                    }
                    _ => {
                        warn!(
                            "[DONE] {} type={:?} from={} cost={:.3}ms (no answer, rcode={:?})",
                            clean_domain, qtype, src, elapsed_ms, rcode
                        );
                    }
                }
            }
            _ => {
                debug!(
                    "[DONE] {} type={:?} from={} cost={:.3}ms (non-A/AAAA response)",
                    clean_domain, qtype, src, elapsed_ms
                );
            }
        }
    }

    pub async fn send_dns_query(&self, request: &[u8], upstream: &SocketAddr) -> Option<Vec<u8>> {
        let deadline = Instant::now() + self.timeout;
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

            match query_upstream_once(request, upstream, self.timeout).await {
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
                "DNS query to {} failed after {} attempt(s) within {:?}: {}",
                upstream, attempt, self.timeout, err
            );
        }
        None
    }

    pub async fn forward_to_upstream(
        &self,
        request: &[u8],
        query: &Message,
        upstreams: &[SocketAddr],
        client: &SocketAddr,
    ) -> anyhow::Result<()> {
        let data = self
            .race_upstreams_or_servfail(request, query, upstreams)
            .await;

        self.socket.send_to(&data, client).await?;

        Ok(())
    }

    pub fn is_domestic_country_ip(&self, ip: IpAddr) -> bool {
        let lookup_result = match self.mmdb.lookup(ip) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let record = match lookup_result.decode::<MinimalMmdb<'_>>() {
            Ok(Some(r)) => r,
            _ => return false,
        };

        record
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
            }
            None => {
                debug!("[DOMESTIC-HTTPS-TIMEOUT] {} -> foreign", clean_domain);
                false
            }
        }
    }

    /// 如果响应成功，则写入缓存并执行 mark_sites
    async fn cache_and_mark_if_ok(&self, resp: &[u8], domain: &str, qtype: u16) {
        if let Ok(msg) = Message::from_vec(resp)
            && msg.response_code() == ResponseCode::NoError
        {
            let ips = extract_answer_ips(resp).ok();
            if let Some(cache) = &self.cache
                && let Some(ttl) = response_cache_ttl(&msg)
            {
                cache.put_with_ttl(domain, qtype, resp, ttl).await;
            }
            self.apply_mark_sites_inner(resp, domain, ips).await;
        }
    }

    /// 同 cache_and_mark_if_ok，但接受已解析的 Message 避免重复解析
    async fn cache_and_mark_if_ok_msg(&self, msg: &Message, resp: &[u8], domain: &str, qtype: u16) {
        if msg.response_code() == ResponseCode::NoError {
            let ips = extract_answer_ips(resp).ok();
            if let Some(cache) = &self.cache
                && let Some(ttl) = response_cache_ttl(msg)
            {
                cache.put_with_ttl(domain, qtype, resp, ttl).await;
            }
            self.apply_mark_sites_inner(resp, domain, ips).await;
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

pub fn parse_hosts<A: Clone + FromStr<Err = std::net::AddrParseError> + Eq + std::hash::Hash>(
    map: &HashMap<String, OneOrMany>,
) -> HashMap<String, Vec<A>> {
    map.iter()
        .map(|(k, v)| {
            let mut seen = HashSet::new();
            let addrs: Vec<A> = v
                .clone()
                .into_vec()
                .into_iter()
                .map(|s| {
                    s.parse::<A>()
                        .unwrap_or_else(|e| panic!("invalid IP for {k}: {e}"))
                })
                .filter(|addr| seen.insert(addr.clone()))
                .collect();

            (canonical_domain(k), addrs)
        })
        .collect()
}

pub fn parse_upstream(s: &str, field_name: &str) -> anyhow::Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .with_context(|| format!("Invalid {}: {}", field_name, s))
}

/// 单点写法（字符串）与列表写法（字符串数组）都归一化为非空的 Vec，
/// 重复项去重，保持首次出现的顺序
pub fn parse_upstreams(
    one_or_many: &OneOrMany,
    field_name: &str,
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let addrs: Vec<SocketAddr> = one_or_many
        .0
        .iter()
        .map(|s| parse_upstream(s, field_name))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter(|addr| seen.insert(*addr))
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("{} cannot be empty", field_name);
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OneOrMany;
    use crate::pollution::{PollutionChecker, PollutionResult};
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::collections::{HashMap, HashSet};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;

    // ========== parse_hosts ==========

    #[test]
    fn test_parse_hosts_ipv4_single() {
        let mut map = HashMap::new();
        map.insert(
            "Example.COM".to_string(),
            OneOrMany(vec!["1.2.3.4".to_string()]),
        );
        let result = parse_hosts::<Ipv4Addr>(&map);
        assert_eq!(
            result.get("example.com"),
            Some(&vec![Ipv4Addr::new(1, 2, 3, 4)])
        );
    }

    #[test]
    fn test_parse_hosts_ipv4_multi() {
        let mut map = HashMap::new();
        map.insert(
            "multi.example.com".to_string(),
            OneOrMany(vec![
                "1.2.3.4".to_string(),
                "5.6.7.8".to_string(),
                "9.10.11.12".to_string(),
            ]),
        );
        let result = parse_hosts::<Ipv4Addr>(&map);
        assert_eq!(
            result.get("multi.example.com"),
            Some(&vec![
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(5, 6, 7, 8),
                Ipv4Addr::new(9, 10, 11, 12),
            ])
        );
    }

    #[test]
    fn test_parse_hosts_ipv6_multi() {
        let mut map = HashMap::new();
        map.insert(
            "dual.example.com".to_string(),
            OneOrMany(vec!["::1".to_string(), "fe80::1".to_string()]),
        );
        let result = parse_hosts::<Ipv6Addr>(&map);
        assert_eq!(
            result.get("dual.example.com"),
            Some(&vec![
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            ])
        );
    }

    #[test]
    fn test_parse_hosts_dedup() {
        let mut map = HashMap::new();
        map.insert(
            "dup.example.com".to_string(),
            OneOrMany(vec![
                "1.2.3.4".to_string(),
                "5.6.7.8".to_string(),
                "1.2.3.4".to_string(),
            ]),
        );
        let result = parse_hosts::<Ipv4Addr>(&map);
        let addrs = result.get("dup.example.com").unwrap();
        // 去重后保持首次出现顺序
        assert_eq!(
            addrs,
            &vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]
        );
    }

    #[test]
    fn test_parse_hosts_key_normalization() {
        let mut map = HashMap::new();
        map.insert(
            ".Test.ORG.".to_string(),
            OneOrMany(vec!["1.2.3.4".to_string()]),
        );
        let result = parse_hosts::<Ipv4Addr>(&map);
        assert!(result.contains_key("test.org"));
        assert!(!result.contains_key(".Test.ORG."));
    }

    #[test]
    #[should_panic(expected = "invalid IP for bad.example.com")]
    fn test_parse_hosts_invalid_ip_panics() {
        let mut map = HashMap::new();
        map.insert(
            "bad.example.com".to_string(),
            OneOrMany(vec!["not-an-ip".to_string()]),
        );
        let _: HashMap<String, Vec<Ipv4Addr>> = parse_hosts(&map);
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

    // ========== parse_upstreams ==========

    #[test]
    fn test_parse_upstreams_single_compat() {
        let result = parse_upstreams(&OneOrMany(vec!["8.8.8.8".to_string()]), "test").unwrap();
        assert_eq!(
            result,
            vec![SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53)]
        );
    }

    #[test]
    fn test_parse_upstreams_list() {
        let result = parse_upstreams(
            &OneOrMany(vec![
                "223.5.5.5".to_string(),
                "8.8.8.8:5353".to_string(),
                "[2001:4860:4860::8888]:53".to_string(),
            ]),
            "test",
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                SocketAddr::new(Ipv4Addr::new(223, 5, 5, 5).into(), 53),
                SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 5353),
                SocketAddr::new(
                    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into(),
                    53
                ),
            ]
        );
    }

    #[test]
    fn test_parse_upstreams_dedup() {
        let result = parse_upstreams(
            &OneOrMany(vec![
                "8.8.8.8".to_string(),
                "8.8.8.8:53".to_string(),
                "1.1.1.1".to_string(),
            ]),
            "test",
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53),
                SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 53),
            ]
        );
    }

    #[test]
    fn test_parse_upstreams_empty_rejected() {
        assert!(parse_upstreams(&OneOrMany(vec![]), "test").is_err());
    }

    #[test]
    fn test_parse_upstreams_invalid_entry_rejected() {
        let result = parse_upstreams(
            &OneOrMany(vec!["8.8.8.8".to_string(), "not-a-host".to_string()]),
            "test",
        );
        assert!(result.is_err());
    }

    // ========== race_queries ==========

    type BoxedQuery = (SocketAddr, Pin<Box<dyn Future<Output = Option<Vec<u8>>>>>);

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, last).into(), 53)
    }

    /// 与 a_query() 完全对应的合法 A 应答（ID / 问题段一致）
    fn a_answer(ip: Ipv4Addr) -> Vec<u8> {
        build_a_response(&a_query(), ip, 60)
    }

    /// 把包延迟 delay 后返回的竞速候选
    fn delayed(packet: Vec<u8>, delay: Duration) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>>>> {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Some(packet)
        })
    }

    /// 与 a_query() 同 ID 但内容畸形的包（截断报文）
    fn malformed_same_id() -> Vec<u8> {
        let mut pkt = a_query().to_vec().unwrap();
        pkt.truncate(15);
        pkt
    }

    #[tokio::test]
    async fn test_race_queries_empty_returns_none() {
        let futs: Vec<(SocketAddr, std::future::Ready<Option<Vec<u8>>>)> = Vec::new();
        assert!(
            race_queries(&a_query().to_vec().unwrap(), futs)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_race_queries_first_success_wins_even_after_failures() {
        let request = a_query().to_vec().unwrap();
        let answer = a_answer(Ipv4Addr::new(1, 2, 3, 4));

        let futs: Vec<BoxedQuery> = vec![
            (addr(1), Box::pin(async { None })),
            (addr(2), delayed(answer.clone(), Duration::from_millis(30))),
        ];

        // 先失败者不能让竞速提前结束，必须等成功者返回
        assert_eq!(race_queries(&request, futs).await, Some(answer));
    }

    #[tokio::test]
    async fn test_race_queries_all_fail_returns_none() {
        let futs: Vec<BoxedQuery> = vec![
            (addr(1), Box::pin(async { None })),
            (addr(2), Box::pin(async { None })),
        ];
        assert!(
            race_queries(&a_query().to_vec().unwrap(), futs)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_race_queries_fastest_success_wins() {
        let request = a_query().to_vec().unwrap();
        let fast_answer = a_answer(Ipv4Addr::new(2, 2, 2, 2));
        let slow_answer = a_answer(Ipv4Addr::new(3, 3, 3, 3));

        let futs: Vec<BoxedQuery> = vec![
            (addr(1), delayed(slow_answer, Duration::from_secs(30))),
            (
                addr(2),
                delayed(fast_answer.clone(), Duration::from_millis(5)),
            ),
        ];

        // 慢的 30s 请求不应该拖慢整体
        let started = Instant::now();
        assert_eq!(race_queries(&request, futs).await, Some(fast_answer));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    // ========== 应答资格判定（软失败 / 畸形包不判胜） ==========

    fn a_query() -> Message {
        let mut msg = Message::new();
        msg.set_id(4321);
        msg.add_query(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn aaaa_query() -> Message {
        let mut msg = Message::new();
        msg.set_id(4321);
        msg.add_query(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::AAAA,
        ));
        msg
    }

    fn servfail_packet() -> Vec<u8> {
        build_servfail_response(&a_query())
    }

    fn refused_packet() -> Vec<u8> {
        let mut msg = a_query();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::Refused);
        msg.to_vec().unwrap()
    }

    fn ok_packet() -> Vec<u8> {
        a_answer(Ipv4Addr::new(93, 184, 216, 34))
    }

    /// ID / QNAME / QTYPE 都与 a_query() 一致，但 QCLASS=CH 的"应答"
    fn wrong_class_answer() -> Vec<u8> {
        let mut query = Message::new();
        query.set_id(4321);
        let mut q = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        q.set_query_class(DNSClass::CH);
        query.add_query(q);

        build_a_response(&query, Ipv4Addr::new(1, 1, 1, 1), 60)
    }

    /// ID 对不上的 SERVFAIL
    fn servfail_wrong_id() -> Vec<u8> {
        let mut query = a_query();
        query.set_id(999);
        build_servfail_response(&query)
    }

    /// 问题段对不上的 SERVFAIL
    fn servfail_wrong_question() -> Vec<u8> {
        let mut query = Message::new();
        query.set_id(4321);
        query.add_query(Query::query(
            Name::from_ascii("evil.example.net").unwrap(),
            RecordType::A,
        ));
        build_servfail_response(&query)
    }

    #[test]
    fn test_classify_answer_usable() {
        let request = a_query().to_vec().unwrap();
        assert_eq!(classify_answer(&request, &ok_packet()), RaceVerdict::Usable);
        // NXDOMAIN 是权威正常答案，有资格胜出
        let mut nx = a_query();
        nx.set_message_type(MessageType::Response);
        nx.set_response_code(ResponseCode::NXDomain);
        assert_eq!(
            classify_answer(&request, &nx.to_vec().unwrap()),
            RaceVerdict::Usable
        );
    }

    #[test]
    fn test_classify_answer_soft_failure() {
        let request = a_query().to_vec().unwrap();
        assert_eq!(
            classify_answer(&request, &servfail_packet()),
            RaceVerdict::SoftFailure
        );
        assert_eq!(
            classify_answer(&request, &refused_packet()),
            RaceVerdict::SoftFailure
        );
    }

    #[test]
    fn test_classify_answer_mismatched_soft_failure_is_unusable() {
        let request = a_query().to_vec().unwrap();

        // 关联性校验先于 RCODE 分类：ID / 问题段对不上的 SERVFAIL 不是"这个上游的软失败"
        assert_eq!(
            classify_answer(&request, &servfail_wrong_id()),
            RaceVerdict::Unusable
        );
        assert_eq!(
            classify_answer(&request, &servfail_wrong_question()),
            RaceVerdict::Unusable
        );
    }

    #[test]
    fn test_classify_answer_unusable() {
        let request = a_query().to_vec().unwrap();

        // 无法解析的包
        assert_eq!(
            classify_answer(&request, &[0u8, 1, 2, 3]),
            RaceVerdict::Unusable
        );
        assert_eq!(classify_answer(&request, &[]), RaceVerdict::Unusable);

        // 同 ID 但被截断的应答
        assert_eq!(
            classify_answer(&request, &malformed_same_id()),
            RaceVerdict::Unusable
        );

        // 不是应答（把请求原样发回来）
        assert_eq!(classify_answer(&request, &request), RaceVerdict::Unusable);

        // ID 对不上
        let mut other_id = a_query();
        other_id.set_id(99);
        assert_eq!(
            classify_answer(
                &request,
                &build_a_response(&other_id, Ipv4Addr::new(1, 1, 1, 1), 60)
            ),
            RaceVerdict::Unusable
        );

        // 问题段与请求不符（答的是别的域名/别的类型）
        let mut other_q = Message::new();
        other_q.set_id(4321);
        other_q.add_query(Query::query(
            Name::from_ascii("evil.example.net").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            classify_answer(
                &request,
                &build_a_response(&other_q, Ipv4Addr::new(1, 1, 1, 1), 60)
            ),
            RaceVerdict::Unusable
        );

        let aaaa_answer = build_aaaa_response(
            &aaaa_query(),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111),
            60,
        );
        assert_eq!(
            classify_answer(&request, &aaaa_answer),
            RaceVerdict::Unusable
        );

        // 问题段 QCLASS 不符（QNAME/QTYPE 都一致）
        assert_eq!(
            classify_answer(&request, &wrong_class_answer()),
            RaceVerdict::Unusable
        );
    }

    #[tokio::test]
    async fn test_race_queries_servfail_does_not_beat_later_clean_answer() {
        let request = a_query().to_vec().unwrap();
        let ok = ok_packet();

        let futs: Vec<BoxedQuery> = vec![
            (
                addr(1),
                delayed(servfail_packet(), Duration::from_millis(5)),
            ),
            (addr(2), delayed(ok.clone(), Duration::from_millis(50))),
        ];

        // 快速 SERVFAIL 不能杀掉稍后返回正常答案的上游
        assert_eq!(race_queries(&request, futs).await, Some(ok));
    }

    #[tokio::test]
    async fn test_race_queries_refused_does_not_beat_later_clean_answer() {
        let request = a_query().to_vec().unwrap();
        let ok = ok_packet();

        let futs: Vec<BoxedQuery> = vec![
            (addr(1), delayed(refused_packet(), Duration::from_millis(5))),
            (addr(2), delayed(ok.clone(), Duration::from_millis(30))),
        ];

        assert_eq!(race_queries(&request, futs).await, Some(ok));
    }

    #[tokio::test]
    async fn test_race_queries_malformed_packet_does_not_beat_later_clean_answer() {
        let request = a_query().to_vec().unwrap();
        let ok = ok_packet();

        // 先到的同 ID 畸形包不能杀掉稍后返回正常答案的上游
        let futs: Vec<BoxedQuery> = vec![
            (
                addr(1),
                delayed(malformed_same_id(), Duration::from_millis(5)),
            ),
            (addr(2), delayed(ok.clone(), Duration::from_millis(50))),
        ];

        assert_eq!(race_queries(&request, futs).await, Some(ok));
    }

    #[tokio::test]
    async fn test_race_queries_wrong_class_answer_does_not_beat_later_clean_answer() {
        let request = a_query().to_vec().unwrap();
        let ok = ok_packet();

        // 先到的应答 QCLASS=CH，不能杀掉稍后返回正确 QCLASS 的上游
        let futs: Vec<BoxedQuery> = vec![
            (
                addr(1),
                delayed(wrong_class_answer(), Duration::from_millis(5)),
            ),
            (addr(2), delayed(ok.clone(), Duration::from_millis(50))),
        ];

        assert_eq!(race_queries(&request, futs).await, Some(ok));
    }

    /// drop 时计数的哨兵：用来直接断言输家 future 被 drop（而不是只看耗时）
    struct DropFlag(Arc<AtomicUsize>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// 永不完成、但持有 DropFlag 的候选
    async fn pending_with_flag(flag: Arc<AtomicUsize>) -> Option<Vec<u8>> {
        let _flag = DropFlag(flag);
        std::future::pending::<()>().await;
        None
    }

    #[tokio::test]
    async fn test_race_queries_drops_losing_futures() {
        let request = a_query().to_vec().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));

        // 两个永不完成的候选（等价于两个悬着的上游查询）+ 一个 5ms 后正常应答的赢家
        let futs: Vec<BoxedQuery> = vec![
            (addr(1), Box::pin(pending_with_flag(dropped.clone()))),
            (addr(2), Box::pin(pending_with_flag(dropped.clone()))),
            (addr(3), delayed(ok_packet(), Duration::from_millis(5))),
        ];

        let resp = race_queries(&request, futs)
            .await
            .expect("must get an answer");

        assert_eq!(classify_answer(&request, &resp), RaceVerdict::Usable);
        // 竞速返回的那一刻，两个悬着的候选必须已经被 drop（abort）
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    /// 当前进程打开的 fd 数（Linux /proc）
    fn open_fd_count() -> Option<usize> {
        std::fs::read_dir("/proc/self/fd").ok().map(|d| d.count())
    }

    /// abort 掉的输家必须立刻归还它绑定的临时 UDP socket，不能每轮攒一个 fd。
    ///
    /// 输家用真实的 `query_upstream_once`（bind → connect → send → 挂在 30s 的 recv 上），
    /// 赢家 20ms 后给出有效应答，此时输家必然已经绑定并阻塞在 recv。
    #[tokio::test]
    async fn test_race_abort_releases_loser_udp_socket() {
        // 黑洞上游：真实端口，永不应答
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bh = blackhole.local_addr().unwrap();

        let iterations = 40usize;

        // 预热一轮，让 tokio IO driver 完成惰性初始化，避免首帧 fd 抖动计入差值
        {
            let request = a_query().to_vec().unwrap();
            let loser_req = request.clone();
            let futs: Vec<BoxedQuery> = vec![
                (
                    bh,
                    Box::pin(async move {
                        query_upstream_once(&loser_req, &bh, Duration::from_secs(30))
                            .await
                            .ok()
                    }),
                ),
                (
                    addr(3),
                    delayed(
                        a_answer(Ipv4Addr::new(9, 9, 9, 9)),
                        Duration::from_millis(20),
                    ),
                ),
            ];
            assert!(race_queries(&request, futs).await.is_some());
        }

        let baseline = open_fd_count().expect("/proc/self/fd available on Linux");

        for _ in 0..iterations {
            let request = a_query().to_vec().unwrap();
            let loser_req = request.clone();
            let winner = a_answer(Ipv4Addr::new(9, 9, 9, 9));
            let futs: Vec<BoxedQuery> = vec![
                (
                    bh,
                    Box::pin(async move {
                        query_upstream_once(&loser_req, &bh, Duration::from_secs(30))
                            .await
                            .ok()
                    }),
                ),
                (addr(3), delayed(winner.clone(), Duration::from_millis(20))),
            ];

            let resp = race_queries(&request, futs)
                .await
                .expect("winner must answer");
            assert_eq!(classify_answer(&request, &resp), RaceVerdict::Usable);
        }

        let after = open_fd_count().unwrap();
        let growth = after.saturating_sub(baseline);

        // 每轮 loser 都会新建一个临时 socket；若 abort 后没关闭，这里会涨 40。
        // 阈值放宽到 10 以容忍同进程其它测试的 fd 抖动。
        assert!(
            growth < iterations / 4,
            "loser UDP sockets leaked: baseline={baseline} after={after} growth={growth} over {iterations} races"
        );
    }

    #[tokio::test]
    async fn test_race_queries_all_unusable_returns_fallback_packet() {
        let request = a_query().to_vec().unwrap();
        let malformed = malformed_same_id();

        let futs: Vec<BoxedQuery> = vec![
            (
                addr(1),
                delayed(malformed.clone(), Duration::from_millis(5)),
            ),
            (addr(2), Box::pin(async { None })),
        ];

        // 没有任何有效应答时，仍把畸形包交回客户端（保持旧的"收到即转发"行为）
        assert_eq!(race_queries(&request, futs).await, Some(malformed));
    }

    #[tokio::test]
    async fn test_race_queries_all_soft_failure_returns_first_soft_failure() {
        let request = a_query().to_vec().unwrap();
        let first = servfail_packet();
        let second = refused_packet();

        let futs: Vec<BoxedQuery> = vec![
            (addr(1), delayed(first.clone(), Duration::from_millis(5))),
            (addr(2), delayed(second, Duration::from_millis(10))),
        ];

        // 全部软失败时返回第一个软失败应答（保留上游原始报文，而不是合成 SERVFAIL）
        assert_eq!(race_queries(&request, futs).await, Some(first));
    }

    #[tokio::test]
    async fn test_race_queries_soft_failure_with_all_others_failed_returns_soft_failure() {
        let request = a_query().to_vec().unwrap();
        let soft = servfail_packet();

        let futs: Vec<BoxedQuery> = vec![
            (addr(1), delayed(soft.clone(), Duration::from_millis(5))),
            (addr(2), Box::pin(async { None })),
        ];

        // 只有一个软失败、其余全部超时/报错时，仍然把软失败应答交回去
        assert_eq!(race_queries(&request, futs).await, Some(soft));
    }

    // ========== 真实 UDP socket 的竞速 ==========

    /// 启动一个真实 UDP 上游 mock：收到一次查询后按顺序回多个包（各自带延迟），
    /// 响应 ID 跟随请求 ID。用于模拟"先污染包、后干净包"这类多包上游。
    async fn spawn_mock_upstream_seq(responses: Vec<(Vec<u8>, Duration)>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if len < 2 {
                    continue;
                }

                for (response, delay) in &responses {
                    if response.len() < 2 {
                        continue;
                    }

                    let mut resp = response.clone();
                    resp[0] = buf[0];
                    resp[1] = buf[1];

                    if !delay.is_zero() {
                        tokio::time::sleep(*delay).await;
                    }

                    let _ = socket.send_to(&resp, peer).await;
                }
            }
        });

        addr
    }

    /// 只回一个包的 mock
    async fn spawn_mock_upstream(response: Vec<u8>, delay: Duration) -> SocketAddr {
        spawn_mock_upstream_seq(vec![(response, delay)]).await
    }

    fn make_race_fut(request: Vec<u8>, upstream: SocketAddr, timeout: Duration) -> BoxedQuery {
        (
            upstream,
            Box::pin(async move { query_upstream_once(&request, &upstream, timeout).await.ok() }),
        )
    }

    #[tokio::test]
    async fn test_race_real_udp_clean_answer_beats_fast_servfail_and_aborts_loser() {
        let request = a_query().to_vec().unwrap();
        let timeout = Duration::from_secs(2);

        // 上游1：立刻回 SERVFAIL
        let fast_servfail = spawn_mock_upstream(servfail_packet(), Duration::ZERO).await;
        // 上游2：60ms 后回正常答案
        let slow_clean = spawn_mock_upstream(ok_packet(), Duration::from_millis(60)).await;
        // 上游3：黑洞，30s 后才回
        let black_hole = spawn_mock_upstream(ok_packet(), Duration::from_secs(30)).await;

        let futs = vec![
            make_race_fut(request.clone(), fast_servfail, timeout),
            make_race_fut(request.clone(), slow_clean, timeout),
            make_race_fut(request.clone(), black_hole, timeout),
        ];

        let started = Instant::now();
        let resp = race_queries(&request, futs)
            .await
            .expect("must get an answer");
        let elapsed = started.elapsed();

        assert_eq!(
            Message::from_vec(&resp).unwrap().response_code(),
            ResponseCode::NoError
        );
        // 黑洞上游被 abort，不能被它的 30s 拖住
        assert!(elapsed < Duration::from_secs(1), "elapsed={elapsed:?}");
    }

    #[tokio::test]
    async fn test_race_real_udp_all_soft_failure_returns_soft_failure() {
        let request = a_query().to_vec().unwrap();
        let timeout = Duration::from_secs(2);

        let servfail = spawn_mock_upstream(servfail_packet(), Duration::ZERO).await;
        let refused = spawn_mock_upstream(refused_packet(), Duration::from_millis(20)).await;

        let futs = vec![
            make_race_fut(request.clone(), servfail, timeout),
            make_race_fut(request.clone(), refused, timeout),
        ];

        let resp = race_queries(&request, futs)
            .await
            .expect("soft failure still yields a packet");

        assert_eq!(classify_answer(&request, &resp), RaceVerdict::SoftFailure);
    }

    #[tokio::test]
    async fn test_race_real_udp_malformed_packet_does_not_beat_later_clean_answer() {
        let request = a_query().to_vec().unwrap();
        let timeout = Duration::from_secs(2);

        // 上游1：立刻回同 ID 的畸形包；上游2：60ms 后回正常答案
        let fast_malformed = spawn_mock_upstream(malformed_same_id(), Duration::ZERO).await;
        let slow_clean = spawn_mock_upstream(ok_packet(), Duration::from_millis(60)).await;

        let futs = vec![
            make_race_fut(request.clone(), fast_malformed, timeout),
            make_race_fut(request.clone(), slow_clean, timeout),
        ];

        let resp = race_queries(&request, futs)
            .await
            .expect("must get an answer");

        assert_eq!(classify_answer(&request, &resp), RaceVerdict::Usable);
        assert_eq!(resp, ok_packet());
    }

    /// 国外路径的污染过滤循环必须与竞速协同：
    /// 一个上游先发污染包、后发干净包，另一个上游直接回干净包
    #[tokio::test]
    async fn test_foreign_query_filtered_races_with_pollution_checking() {
        let request = aaaa_query().to_vec().unwrap();
        let timeout = Duration::from_secs(2);

        let checker = std::sync::Arc::new(PollutionChecker {
            v4: HashSet::new(),
            v6: HashSet::new(),
            max_packets: 5,
        });

        // GFW 特征污染包：2001::/16 且中间 10 字节全零
        let polluted = build_aaaa_response(
            &aaaa_query(),
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            60,
        );
        assert_eq!(checker.check(&polluted), PollutionResult::Polluted);

        // 上游1：先污染包，40ms 后再回干净包
        let clean_a = build_aaaa_response(
            &aaaa_query(),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111),
            60,
        );
        let upstream_a = spawn_mock_upstream_seq(vec![
            (polluted, Duration::ZERO),
            (clean_a, Duration::from_millis(40)),
        ])
        .await;

        // 上游2：10ms 后回另一个干净包，应该由它胜出
        let clean_b = build_aaaa_response(
            &aaaa_query(),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x2222),
            60,
        );
        let upstream_b = spawn_mock_upstream(clean_b.clone(), Duration::from_millis(10)).await;

        async fn probe(
            request: Vec<u8>,
            upstream: SocketAddr,
            checker: std::sync::Arc<PollutionChecker>,
            timeout: Duration,
        ) -> Option<Vec<u8>> {
            foreign_query_filtered(&request, &upstream, timeout, "example.com", &checker).await
        }

        let futs = vec![
            (
                upstream_a,
                probe(request.clone(), upstream_a, checker.clone(), timeout),
            ),
            (
                upstream_b,
                probe(request.clone(), upstream_b, checker.clone(), timeout),
            ),
        ];

        let resp = race_queries(&request, futs)
            .await
            .expect("must get an answer");

        // 污染包既不能判胜，也不能成为兜底结果；胜者是更快的干净应答
        assert_eq!(resp, clean_b);
        assert_eq!(classify_answer(&request, &resp), RaceVerdict::Usable);
    }

    #[tokio::test]
    async fn test_race_real_udp_all_timeout_returns_none() {
        let request = a_query().to_vec().unwrap();
        let timeout = Duration::from_millis(150);

        let black_hole = spawn_mock_upstream(ok_packet(), Duration::from_secs(30)).await;
        let futs = vec![make_race_fut(request.clone(), black_hole, timeout)];

        let started = Instant::now();
        assert!(race_queries(&request, futs).await.is_none());
        assert!(started.elapsed() >= Duration::from_millis(120));
    }
}
