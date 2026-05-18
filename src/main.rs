mod adblock;
mod cache;
mod config;
mod dns_utils;
mod domain_utils;
mod gfwlist;
mod mark_sites;
mod server;

use anyhow::Context;
use clap::Parser;
use maxminddb::Reader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::config::{Config, validate_config};
use adblock::{AdblockChecker, AdblockDecoder};
use cache::DnsCache;
use domain_utils::{canonical_domain, normalize_domain_list};
use gfwlist::{BloomDomainChecker, GfwlistDecoder};
use mark_sites::{CommandNftManager, MarkGroup, MarkRule, MarkSites, NFT_TABLE_PREFIX};
use server::{DnsServer, bind_listen_socket, parse_hosts, parse_upstream};

#[derive(Parser)]
#[command(name = "tsubamegaeshi-rs", about = "燕返 - Lightweight DNS splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("Failed to read config file: {}", cli.config))?;

    let config: Config = toml::from_str(&config_str).context("Invalid config.toml")?;

    validate_config(&config)?;

    let base = config
        .log_level
        .as_deref()
        .unwrap_or("info,tsubamegaeshi_rs=debug");

    let env_filter = tracing_subscriber::EnvFilter::new(format!("{},maxminddb=warn", base));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .without_time()
        .init();

    let listen_text = config.listen.clone();

    let mmdb_data = tokio::fs::read(&config.mmdb_path).await?;
    let mmdb = Reader::from_source(mmdb_data).context("Invalid MMDB database")?;

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

    let adblock_checker = if let Some(path) = &config.adblock_path {
        info!("Loading AdBlock list from {}", path);
        match AdblockDecoder::new(path).extract_domains() {
            Ok(domains) => {
                info!("Extracted {} adblock domains", domains.len());
                let fp_rate = config.adblock_fp_rate.unwrap_or(0.001);
                match AdblockChecker::new(&domains, fp_rate) {
                    Ok(checker) => {
                        info!("AdBlock checker built (fp={:.2}%)", fp_rate * 100.0);
                        Some(Arc::new(checker))
                    }
                    Err(e) => {
                        error!("Failed to build AdBlock checker: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse AdBlock file: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 绑定 UDP socket
    let addr: SocketAddr = config
        .listen
        .parse()
        .with_context(|| format!("Invalid listen address: {}", config.listen))?;

    let socket = bind_listen_socket(addr).await?;

    let special_upstream = parse_upstream(&config.special_upstream, "special_upstream")?;
    let domestic_upstream = parse_upstream(&config.domestic_upstream, "domestic_upstream")?;
    let foreign_upstream = parse_upstream(&config.foreign_upstream, "foreign_upstream")?;
    let cache = NonZeroUsize::new(config.cache_size).map(DnsCache::new);

    let (hosts_v4, hosts_v6) = config.hosts.as_ref().map_or((None, None), |h| {
        let v4 = h.ipv4.as_ref().map(parse_hosts::<Ipv4Addr>);
        let v6 = h.ipv6.as_ref().map(parse_hosts::<Ipv6Addr>);
        (v4, v6)
    });

    let special_suffixes: Vec<String> = config
        .special_suffixes
        .iter()
        .map(|s| canonical_domain(s))
        .filter(|s| !s.is_empty())
        .collect();

    let force_foreign = normalize_domain_list(config.force_foreign_domains);
    let force_domestic = normalize_domain_list(config.force_domestic_domains);

    let mark_sites = config.marksite.as_ref().map(|map| {
        let groups: Vec<MarkGroup> = map
            .iter()
            .map(|(table, domains)| {
                let nft_table = format!("{}{}", NFT_TABLE_PREFIX, table);

                let rules: Vec<MarkRule> = domains
                    .iter()
                    .map(|d| MarkRule {
                        pattern: canonical_domain(d),
                    })
                    .filter(|r| !r.pattern.is_empty())
                    .collect();

                MarkGroup { nft_table, rules }
            })
            .collect();

        MarkSites { groups }
    });

    // 打印每个表的规则数量
    if let Some(ref ms) = mark_sites {
        for group in &ms.groups {
            info!(
                "marksite table '{}' loaded with {} rules",
                group.nft_table,
                group.rules.len()
            );
        }
    }

    let nft_manager = mark_sites.as_ref().map(|_| Arc::new(CommandNftManager));

    // 初始化 nft 表与集合
    if let Some(ref ms) = mark_sites
        && let Some(ref nft) = nft_manager
    {
        for group in &ms.groups {
            if let Err(e) = nft.ensure_table(&group.nft_table) {
                error!("Failed to ensure nft table '{}': {}", group.nft_table, e);
            }
        }
    }

    let server = Arc::new(DnsServer {
        socket,
        special_upstream,
        domestic_upstream,
        foreign_upstream,
        mmdb,
        special_suffixes,
        cache,
        timeout: Duration::from_secs(config.query_timeout_sec),
        enable_ipv6_aaaa: config.enable_ipv6_aaaa,
        gfw_checker,
        force_foreign,
        force_domestic,
        hosts_v4,
        hosts_v6,
        mark_sites,
        nft_manager,
        adblock_checker,
        domestic_countries: config.domestic_countries,
    });

    info!("tsubamegaeshi-rs started on {}", listen_text);

    server.run().await;

    Ok(())
}
