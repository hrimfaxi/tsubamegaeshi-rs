use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct HostsTables {
    #[serde(default)]
    pub ipv4: Option<HashMap<String, String>>,

    #[serde(default)]
    pub ipv6: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct Config {
    pub listen: String,
    pub special_suffixes: Vec<String>,
    pub special_upstream: String,
    pub domestic_upstream: String,
    pub foreign_upstream: String,
    pub mmdb_path: String,
    pub cache_size: usize,
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

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.query_timeout_sec == 0 {
            anyhow::bail!("query_timeout_sec must be greater than 0");
        }

        if let Some(rate) = self.gfbloom_fp_rate
            && !(rate > 0.0 && rate < 1.0)
        {
            anyhow::bail!("gfbloom_fp_rate must be greater than 0.0 and less than 1.0");
        }

        if let Some(marksite) = &self.marksite {
            for table in marksite.keys() {
                if table.is_empty() {
                    anyhow::bail!("marksite table suffix cannot be empty");
                }
                if !table
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    anyhow::bail!(
                        "invalid marksite table suffix '{}': only ASCII letters, digits, '_' and '-' are allowed",
                        table
                    );
                }
            }
        }

        if let Some(rate) = self.adblock_fp_rate
            && !(rate > 0.0 && rate < 1.0)
        {
            anyhow::bail!("adblock_fp_rate must be between 0.0 and 1.0");
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
            special_suffixes: vec![],
            special_upstream: "127.0.0.1:53".to_string(),
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

    // ========== 合法基线 ==========

    #[test]
    fn test_validate_baseline_ok() {
        assert!(valid_config().validate().is_ok());
    }
}
