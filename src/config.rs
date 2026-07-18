use anyhow::bail;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// TOML 中接受单个字符串或字符串数组，统一归一化为 Vec。
///
/// **含 `.` 的域名 key 需加引号**，否则 TOML 会解析为嵌套表。
///
/// ```toml
/// [hosts.ipv4]
/// "example.com"       = "1.2.3.4"
/// "multi.example.com" = ["1.2.3.4", "5.6.7.8"]
/// localhost           = "127.0.0.1"  # 无点号可不加引号
/// ```
#[derive(Clone, Debug, Serialize)]
pub struct OneOrMany(pub Vec<String>);

impl OneOrMany {
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }
}

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OneOrManyVisitor;

        impl<'de> Visitor<'de> for OneOrManyVisitor {
            type Value = OneOrMany;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or an array of strings")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(OneOrMany(vec![v.to_owned()]))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
                let vec: Vec<String> =
                    Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(OneOrMany(vec))
            }
        }

        deserializer.deserialize_any(OneOrManyVisitor)
    }
}

#[derive(Deserialize, Serialize)]
pub struct HostsTables {
    #[serde(default)]
    pub ipv4: Option<HashMap<String, OneOrMany>>,

    #[serde(default)]
    pub ipv6: Option<HashMap<String, OneOrMany>>,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub listen: String,
    #[serde(default)]
    pub special_suffixes: Option<Vec<String>>,
    #[serde(default)]
    pub special_upstream: Option<String>,
    pub domestic_upstream: String,
    pub foreign_upstream: String,
    pub mmdb_path: String,
    pub cache_size: usize,
    #[serde(default = "default_query_timeout_sec")]
    pub query_timeout_sec: u64,
    pub enable_ipv6_aaaa: bool,
    pub log_level: Option<String>,

    // GFWList
    pub gfwlist_path: Option<String>,
    pub gfbloom_fp_rate: Option<f64>,

    #[serde(default)]
    pub force_foreign_domains: Option<Vec<String>>,

    #[serde(default)]
    pub force_domestic_domains: Option<Vec<String>>,

    #[serde(default)]
    pub hosts: Option<HostsTables>,

    #[serde(default)]
    pub marksite: Option<HashMap<String, Vec<String>>>,

    // AdBlock
    pub adblock_path: Option<String>,
    pub adblock_fp_rate: Option<f64>,

    #[serde(default = "default_domestic_countries")]
    pub domestic_countries: Vec<String>,

    /// 污染 IPv4 地址列表文件路径
    #[serde(default = "default_ipv4_list_path")]
    pub ipv4_list: String,

    /// 污染 IPv6 地址列表文件路径
    #[serde(default = "default_ipv6_list_path")]
    pub ipv6_list: String,

    /// 国外 DNS 查询时最多丢弃多少个污染包后才放弃，默认 5
    /// 0 表示放弃污染检查
    #[serde(default = "default_max_polluted_packets")]
    pub max_polluted_packets: usize,

    /// 是否信任国内上游返回的 NODATA（NOERROR 且无对应记录）为真实结果，
    /// 不再转查国外。默认 false。
    #[serde(default)]
    pub trust_domestic_nodata_reply: bool,

    /// 最大并发请求数, 防止tproxy成环用, 默认 128
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
}

fn default_domestic_countries() -> Vec<String> {
    vec!["CN".to_string()]
}

fn default_ipv4_list_path() -> String {
    "/etc/tsubamegaeshi-rs/ipv4.txt".to_string()
}

fn default_ipv6_list_path() -> String {
    "/etc/tsubamegaeshi-rs/ipv6.txt".to_string()
}

fn default_max_polluted_packets() -> usize {
    5
}

fn default_max_in_flight() -> usize {
    128
}

fn default_query_timeout_sec() -> u64 {
    10
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_in_flight == 0 {
            bail!("max_in_flight must be > 0");
        }

        if self.query_timeout_sec == 0 {
            bail!("query_timeout_sec must be greater than 0");
        }

        if let Some(rate) = self.gfbloom_fp_rate
            && !(rate > 0.0 && rate < 1.0)
        {
            bail!("gfbloom_fp_rate must be greater than 0.0 and less than 1.0");
        }

        if let Some(marksite) = &self.marksite {
            for table in marksite.keys() {
                if table.is_empty() {
                    bail!("marksite table suffix cannot be empty");
                }
                if !table
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    bail!(
                        "invalid marksite table suffix '{}': only ASCII letters, digits, '_' and '-' are allowed",
                        table
                    );
                }
            }
        }

        if let Some(rate) = self.adblock_fp_rate
            && !(rate > 0.0 && rate < 1.0)
        {
            bail!("adblock_fp_rate must be greater than 0.0 and less than 1.0");
        }

        if let Some(hosts) = &self.hosts {
            let check_hosts = |table: &HashMap<String, OneOrMany>,
                               label: &str|
             -> anyhow::Result<()> {
                let mut seen = HashSet::new();
                for (domain, entry) in table {
                    if entry.0.is_empty() {
                        bail!("{label}.{domain}: IP list cannot be empty");
                    }
                    let canonical = crate::domain_utils::canonical_domain(domain);
                    if !seen.insert(canonical.clone()) {
                        bail!("{label}: duplicate domain '{domain}' (canonical: '{canonical}')");
                    }
                }
                Ok(())
            };
            if let Some(ipv4) = &hosts.ipv4 {
                check_hosts(ipv4, "hosts.ipv4")?;
            }
            if let Some(ipv6) = &hosts.ipv6 {
                check_hosts(ipv6, "hosts.ipv6")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// 构造一个“基础合法”的 Config，各测试在此基础上只改要测的字段
    fn valid_config() -> Config {
        Config {
            listen: "0.0.0.0:53".to_string(),
            special_suffixes: None,
            special_upstream: None,
            domestic_upstream: "127.0.0.1:53".to_string(),
            foreign_upstream: "127.0.0.1:53".to_string(),
            mmdb_path: "/dev/null".to_string(),
            cache_size: 100,
            query_timeout_sec: 5,
            enable_ipv6_aaaa: true,
            log_level: None,
            gfwlist_path: None,
            gfbloom_fp_rate: None,
            force_foreign_domains: None,
            force_domestic_domains: None,
            hosts: None,
            marksite: None,
            adblock_path: None,
            adblock_fp_rate: None,
            domestic_countries: default_domestic_countries(),
            ipv4_list: default_ipv4_list_path(),
            ipv6_list: default_ipv6_list_path(),
            max_polluted_packets: default_max_polluted_packets(),
            trust_domestic_nodata_reply: false,
            max_in_flight: 128,
        }
    }

    // ========== query_timeout_sec ==========

    #[test]
    fn test_validate_query_timeout_zero() {
        let mut cfg = valid_config();
        cfg.query_timeout_sec = 0;
        assert!(cfg.validate().is_err());
    }

    // ========== gfbloom_fp_rate ==========

    #[test]
    fn test_validate_gfbloom_fp_rate_valid() {
        let mut cfg = valid_config();
        cfg.gfbloom_fp_rate = Some(0.001);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_gfbloom_fp_rate_zero() {
        let mut cfg = valid_config();
        cfg.gfbloom_fp_rate = Some(0.0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_gfbloom_fp_rate_one() {
        let mut cfg = valid_config();
        cfg.gfbloom_fp_rate = Some(1.0);
        assert!(cfg.validate().is_err());
    }

    // ========== adblock_fp_rate ==========

    #[test]
    fn test_validate_adblock_fp_rate_valid() {
        let mut cfg = valid_config();
        cfg.adblock_fp_rate = Some(0.001);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_adblock_fp_rate_zero() {
        let mut cfg = valid_config();
        cfg.adblock_fp_rate = Some(0.0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_adblock_fp_rate_one() {
        let mut cfg = valid_config();
        cfg.adblock_fp_rate = Some(1.0);
        assert!(cfg.validate().is_err());
    }

    // ========== marksite table suffix ==========

    #[test]
    fn test_validate_marksite_empty_key() {
        let mut cfg = valid_config();
        let mut map = HashMap::new();
        map.insert("".to_string(), vec!["example.com".to_string()]);
        cfg.marksite = Some(map);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_marksite_invalid_char_space() {
        let mut cfg = valid_config();
        let mut map = HashMap::new();
        map.insert("bad table".to_string(), vec!["example.com".to_string()]);
        cfg.marksite = Some(map);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_marksite_invalid_char_special() {
        let mut cfg = valid_config();
        let mut map = HashMap::new();
        map.insert("table@123".to_string(), vec!["example.com".to_string()]);
        cfg.marksite = Some(map);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_marksite_valid_chars() {
        let mut cfg = valid_config();
        let mut map = HashMap::new();
        map.insert("table_123-abc".to_string(), vec!["example.com".to_string()]);
        cfg.marksite = Some(map);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_marksite_valid_alphanumeric() {
        let mut cfg = valid_config();
        let mut map = HashMap::new();
        map.insert("abc123".to_string(), vec!["example.com".to_string()]);
        cfg.marksite = Some(map);
        assert!(cfg.validate().is_ok());
    }

    // ========== hosts ==========

    #[test]
    fn test_validate_hosts_empty_ipv4_list() {
        let mut cfg = valid_config();
        let mut ipv4 = HashMap::new();
        ipv4.insert("empty.example.com".to_string(), OneOrMany(vec![]));
        cfg.hosts = Some(HostsTables {
            ipv4: Some(ipv4),
            ipv6: None,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_hosts_empty_ipv6_list() {
        let mut cfg = valid_config();
        let mut ipv6 = HashMap::new();
        ipv6.insert("empty.example.com".to_string(), OneOrMany(vec![]));
        cfg.hosts = Some(HostsTables {
            ipv4: None,
            ipv6: Some(ipv6),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_hosts_non_empty_list_ok() {
        let mut cfg = valid_config();
        let mut ipv4 = HashMap::new();
        ipv4.insert(
            "ok.example.com".to_string(),
            OneOrMany(vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]),
        );
        cfg.hosts = Some(HostsTables {
            ipv4: Some(ipv4),
            ipv6: None,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_hosts_canonical_collision() {
        let mut cfg = valid_config();
        let mut ipv4 = HashMap::new();
        ipv4.insert(
            "Example.COM".to_string(),
            OneOrMany(vec!["1.1.1.1".to_string()]),
        );
        ipv4.insert(
            "example.com.".to_string(),
            OneOrMany(vec!["2.2.2.2".to_string()]),
        );
        cfg.hosts = Some(HostsTables {
            ipv4: Some(ipv4),
            ipv6: None,
        });
        assert!(cfg.validate().is_err());
    }

    // ========== TOML 反序列化 ==========

    #[test]
    fn test_toml_hosts_single_string() {
        let toml_str = r#"
            listen = "0.0.0.0:53"
            domestic_upstream = "127.0.0.1:53"
            foreign_upstream = "127.0.0.1:53"
            mmdb_path = "/dev/null"
            cache_size = 100
            enable_ipv6_aaaa = true
            domestic_countries = ["CN"]

            [hosts.ipv4]
            "example.com" = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let hosts = cfg.hosts.unwrap();
        let ipv4 = hosts.ipv4.unwrap();
        assert_eq!(
            ipv4.get("example.com").unwrap().0,
            vec!["1.2.3.4".to_string()]
        );
    }

    #[test]
    fn test_toml_hosts_array() {
        let toml_str = r#"
            listen = "0.0.0.0:53"
            domestic_upstream = "127.0.0.1:53"
            foreign_upstream = "127.0.0.1:53"
            mmdb_path = "/dev/null"
            cache_size = 100
            enable_ipv6_aaaa = true
            domestic_countries = ["CN"]

            [hosts.ipv4]
            "multi.example.com" = ["1.2.3.4", "5.6.7.8"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let hosts = cfg.hosts.unwrap();
        let ipv4 = hosts.ipv4.unwrap();
        assert_eq!(
            ipv4.get("multi.example.com").unwrap().0,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
    }

    #[test]
    fn test_toml_hosts_canonical_collision_rejected() {
        let toml_str = r#"
            listen = "0.0.0.0:53"
            domestic_upstream = "127.0.0.1:53"
            foreign_upstream = "127.0.0.1:53"
            mmdb_path = "/dev/null"
            cache_size = 100
            enable_ipv6_aaaa = true
            domestic_countries = ["CN"]

            [hosts.ipv4]
            "Example.COM" = "1.1.1.1"
            "example.com." = "2.2.2.2"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    // ========== 合法基线 ==========

    #[test]
    fn test_validate_baseline_ok() {
        assert!(valid_config().validate().is_ok());
    }
}
