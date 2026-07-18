mod adblock;
mod cache;
mod config;
mod dns_utils;
mod domain_utils;
mod gfwlist;
mod mark_sites;
mod pollution;
mod server;
mod task_guard;

use anyhow::{Context, anyhow};
use clap::Parser;
use maxminddb::Reader;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tracing::{error, info, warn};

use adblock::{AdblockChecker, AdblockDecoder};
use cache::DnsCache;
use config::Config;
use domain_utils::{canonical_domain, normalize_domain_list};
use gfwlist::{BloomDomainChecker, GfwlistDecoder};
use mark_sites::{CommandNftManager, MarkGroup, MarkRule, MarkSites, NFT_TABLE_PREFIX};
use pollution::PollutionChecker;
use server::{DnsServer, bind_listen_socket, parse_hosts, parse_upstream};
use task_guard::TaskGuard;

#[derive(Parser)]
#[command(name = "tsubamegaeshi-rs", about = "燕返 - Lightweight DNS splitter")]
struct Cli {
    /// 配置文件路径
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,

    /// 只检查配置合法性，然后退出（返回 0 表示合法）
    #[arg(short = 'T', long = "check")]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_str = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("Failed to read config file: {}", cli.config))?;

    let config: Config = toml::from_str(&config_str).context("Invalid config.toml")?;

    config.validate()?;

    if cli.check {
        print!(
            "{}",
            toml::to_string_pretty(&config).expect("failed to serialize config")
        );
        return Ok(());
    }

    let task_guard = Arc::new(TaskGuard::new());

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

    // 构造污染检测器：max_polluted_packets = 0 表示关闭
    let pollution_checker = if config.max_polluted_packets > 0 {
        // 加载污染IP 列表
        let ipv4_path = config.ipv4_list.clone();
        let ipv6_path = config.ipv6_list.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        task_guard.spawn_blocking(move || {
            let v4 = load_ip_set(&ipv4_path, |s| s.parse::<Ipv4Addr>().ok());
            let v6 = load_ip_set(&ipv6_path, |s| s.parse::<Ipv6Addr>().ok());
            info!(
                "Pollution ipset loaded. ipv4={}, ipv6={}",
                v4.len(),
                v6.len()
            );
            let _ = tx.send((v4, v6));
        });

        let (polluted_v4, polluted_v6) = rx
            .await
            .map_err(|_| anyhow!("pollution load channel closed"))?;

        Some(PollutionChecker {
            v4: polluted_v4,
            v6: polluted_v6,
            max_packets: config.max_polluted_packets,
        })
    } else {
        None
    };

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

    let special_upstream = config
        .special_upstream
        .as_deref()
        .map(|s| parse_upstream(s, "special_upstream"))
        .transpose()?;
    let domestic_upstream = parse_upstream(&config.domestic_upstream, "domestic_upstream")?;
    let foreign_upstream = parse_upstream(&config.foreign_upstream, "foreign_upstream")?;
    let cache = NonZeroUsize::new(config.cache_size).map(DnsCache::new);

    let (hosts_v4, hosts_v6) = config.hosts.as_ref().map_or((None, None), |h| {
        let v4 = h.ipv4.as_ref().map(parse_hosts::<Ipv4Addr>);
        let v6 = h.ipv6.as_ref().map(parse_hosts::<Ipv6Addr>);
        (v4, v6)
    });

    let special_suffixes: Option<Vec<String>> = config.special_suffixes.map(|v| {
        v.iter()
            .map(|s| canonical_domain(s))
            .filter(|s| !s.is_empty())
            .collect()
    });

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
        pollution_checker,
        task_guard: task_guard.clone(),
        trust_domestic_nodata_reply: config.trust_domestic_nodata_reply,
        max_in_flight: config.max_in_flight,
        in_flight: AtomicUsize::new(0),
    });

    info!("tsubamegaeshi-rs started on {}", listen_text);

    tokio::select! {
        _ = server.run() => {},
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        },
    }

    info!("Shutting down task guard...");
    let clean = task_guard.shutdown(Duration::from_secs(5)).await;
    if !clean {
        warn!("Some tasks did not finish within shutdown timeout");
    }

    Ok(())
}

/// 从文件中逐行加载 IP 集合（取首 token，支持 # 注释）
fn load_ip_set<F, T>(path: &str, parser: F) -> HashSet<T>
where
    F: Fn(&str) -> Option<T>,
    T: Eq + std::hash::Hash,
{
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Cannot open IP list {}: {}", path, e);
            return HashSet::new();
        }
    };
    let reader = BufReader::new(file);
    let mut set = HashSet::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let no_comment = trimmed.split('#').next().unwrap_or("").trim();
        let token = no_comment.split_whitespace().next().unwrap_or("");
        if let Some(ip) = parser(token) {
            set.insert(ip);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn temp_ip_file(content: &str) -> (std::path::PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "tsubame_ipset_test_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, content).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        (path, path_str)
    }

    // ========== load_ip_set ==========

    #[test]
    fn test_load_ip_set_normal() {
        let (path, path_str) = temp_ip_file("1.2.3.4\n5.6.7.8\n");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(set.contains(&Ipv4Addr::new(5, 6, 7, 8)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_skip_empty_lines() {
        let (path, path_str) = temp_ip_file("\n\n1.2.3.4\n\n");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_skip_full_line_comment() {
        let (path, path_str) = temp_ip_file("# comment\n1.2.3.4\n# another");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 1);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_trailing_comment() {
        let (path, path_str) = temp_ip_file("1.2.3.4 # comment\n5.6.7.8\t# tab comment");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(set.contains(&Ipv4Addr::new(5, 6, 7, 8)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_first_token_only() {
        let (path, path_str) = temp_ip_file("1.2.3.4 extra garbage\n5.6.7.8");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(set.contains(&Ipv4Addr::new(5, 6, 7, 8)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_skip_invalid_ip() {
        let (path, path_str) = temp_ip_file("1.2.3.4\nnot-an-ip\n5.6.7.8\n");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv4Addr>().ok());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(set.contains(&Ipv4Addr::new(5, 6, 7, 8)));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_load_ip_set_file_not_found() {
        let set = load_ip_set("/nonexistent/path/ipset.txt", |s| {
            s.parse::<Ipv4Addr>().ok()
        });
        assert!(set.is_empty());
    }

    #[test]
    fn test_load_ip_set_ipv6() {
        let (path, path_str) = temp_ip_file("::1\n2001:4860::8888\n");
        let set = load_ip_set(&path_str, |s| s.parse::<Ipv6Addr>().ok());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert!(set.contains(&Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)));
        fs::remove_file(path).unwrap();
    }
}
