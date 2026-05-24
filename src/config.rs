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
