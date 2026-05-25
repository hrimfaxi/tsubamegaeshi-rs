use crate::domain_utils::canonical_domain;
use std::io;
use std::net::IpAddr;
use std::process::Command;
use tokio::sync::Semaphore;

pub static NFT_SEM: Semaphore = Semaphore::const_new(4);

pub const NFT_TABLE_PREFIX: &str = "tsubamegaeshi_";

pub trait NftManager: Send + Sync {
    fn add_ip_to_group(&self, table: &str, addr: IpAddr) -> io::Result<()>;
}

pub struct CommandNftManager;

impl CommandNftManager {
    #[rustfmt::skip]
    pub fn ensure_table(&self, table: &str) -> io::Result<()> {
        run_nft_ignore_existing(&["add", "table", "inet", table])?;

        run_nft_ignore_existing(&[
            "add", "set", "inet", table, "spam_ips",
            "{", "type", "ipv4_addr;", "timeout", "1h;", "flags", "timeout,dynamic;", "}",
        ])?;

        run_nft_ignore_existing(&[
            "add", "set", "inet", table, "spam_ips6",
            "{", "type", "ipv6_addr;", "timeout", "1h;", "flags", "timeout,dynamic;", "}",
        ])?;

        Ok(())
    }
}

impl NftManager for CommandNftManager {
    fn add_ip_to_group(&self, table: &str, addr: IpAddr) -> io::Result<()> {
        let set_name = match addr {
            IpAddr::V4(_) => "spam_ips",
            IpAddr::V6(_) => "spam_ips6",
        };

        let elem = format!("{{ {} }}", addr);

        let output = Command::new("/usr/sbin/nft")
            .args(["add", "element", "inet", table, set_name, &elem])
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            // nft 重复创建 table/set 时一般会报 already exists。
            // 这里保留幂等行为，但其他错误返回。
            let stderr = String::from_utf8_lossy(&output.stderr);

            Err(io::Error::other(format!(
                "nft add element failed: table={table}, set={set_name}, addr={addr}: {stderr}"
            )))
        }
    }
}

fn run_nft_ignore_existing(args: &[&str]) -> io::Result<()> {
    let output = Command::new("/usr/sbin/nft").args(args).output()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);

    if stderr.contains("File exists") || stderr.contains("exists") {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "nft command failed: nft {}: {}",
        args.join(" "),
        stderr
    )))
}

#[derive(Debug)]
pub struct MarkRule {
    pub pattern: String,
}

#[derive(Debug)]
pub struct MarkGroup {
    pub nft_table: String,
    pub rules: Vec<MarkRule>,
}

#[derive(Debug)]
pub struct MarkSites {
    pub groups: Vec<MarkGroup>,
}

impl MarkSites {
    pub fn match_groups(&self, domain: &str) -> impl Iterator<Item = &MarkGroup> {
        let domain = canonical_domain(domain);

        self.groups.iter().filter(move |group| {
            // 子串匹配：domain 中包含 rule.pattern 即命中
            group
                .rules
                .iter()
                .any(|rule| domain.contains(&rule.pattern))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mark_sites(rules: Vec<(&str, Vec<&str>)>) -> MarkSites {
        let groups = rules
            .into_iter()
            .map(|(table, patterns)| MarkGroup {
                nft_table: format!("{}{}", NFT_TABLE_PREFIX, table),
                rules: patterns
                    .into_iter()
                    .map(|p| MarkRule {
                        pattern: canonical_domain(p),
                    })
                    .collect(),
            })
            .collect();
        MarkSites { groups }
    }

    #[test]
    fn test_match_single_group() {
        let ms = make_mark_sites(vec![("ads", vec!["google.com"])]);
        let matched: Vec<&str> = ms
            .match_groups("www.google.com")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert_eq!(matched, vec!["tsubamegaeshi_ads"]);
    }

    #[test]
    fn test_match_multiple_groups() {
        let ms = make_mark_sites(vec![
            ("ads", vec!["google.com"]),
            ("video", vec!["youtube"]),
        ]);
        // 这个域名同时包含 "google.com" 和 "youtube" 两个子串
        let matched: Vec<&str> = ms
            .match_groups("youtube.google.com")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert_eq!(matched, vec!["tsubamegaeshi_ads", "tsubamegaeshi_video"]);
    }

    #[test]
    fn test_match_no_hit() {
        let ms = make_mark_sites(vec![("ads", vec!["google.com"])]);
        let matched: Vec<&str> = ms
            .match_groups("example.org")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert!(matched.is_empty());
    }

    #[test]
    fn test_match_case_insensitive() {
        let ms = make_mark_sites(vec![("ads", vec!["GOOGLE.COM"])]);
        let matched: Vec<&str> = ms
            .match_groups("WWW.google.COM")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert_eq!(matched, vec!["tsubamegaeshi_ads"]);
    }

    #[test]
    fn test_match_substring_behavior() {
        let ms = make_mark_sites(vec![("track", vec!["google"])]);
        let matched: Vec<&str> = ms
            .match_groups("notgoogle.com")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert_eq!(matched, vec!["tsubamegaeshi_track"]);
    }

    #[test]
    fn test_match_empty_rules_no_hit() {
        let ms = make_mark_sites(vec![("empty", vec![])]);
        let matched: Vec<&str> = ms
            .match_groups("anything.com")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert!(matched.is_empty());
    }

    #[test]
    fn test_match_multiple_rules_in_one_group() {
        let ms = make_mark_sites(vec![("mixed", vec!["google.com", "github.com"])]);
        let matched: Vec<&str> = ms
            .match_groups("api.github.com")
            .map(|g| g.nft_table.as_str())
            .collect();
        assert_eq!(matched, vec!["tsubamegaeshi_mixed"]);
    }
}
