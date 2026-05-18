use crate::domain_utils::canonical_domain;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bloomfilter::Bloom;
use std::collections::HashSet;
use std::fs;
use tracing::debug;

/// GFWList 解码器：负责读取、解码、解析规则并提取域名
pub struct GfwlistDecoder {
    file_path: String,
}

impl GfwlistDecoder {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }

    pub fn extract_domains(&self) -> Result<Vec<String>> {
        let raw_content = fs::read_to_string(&self.file_path)
            .with_context(|| format!("无法读取文件: {}", self.file_path))?;

        let base64_str: String = raw_content.chars().filter(|c| !c.is_whitespace()).collect();

        if base64_str.is_empty() {
            anyhow::bail!("文件内容为空");
        }

        let decoded_bytes = STANDARD
            .decode(&base64_str)
            .with_context(|| "Base64 解码失败，请确认文件内容为合法的 Base64 编码")?;

        let decoded_text = String::from_utf8(decoded_bytes)
            .with_context(|| "解码后的内容不是有效的 UTF-8 文本")?;

        let mut raw_domains = Vec::new();

        for line in decoded_text.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('!') {
                continue;
            }

            if line.starts_with("@@") {
                continue;
            }

            if let Some(rest) = line.strip_prefix("||") {
                let domain = rest.split(['/', '^', '?', '#']).next().unwrap_or(rest);

                let domain = canonical_domain(domain.trim_end_matches('^'));

                if !domain.is_empty() && !domain.contains('*') {
                    debug!("gfwlist domain: {}", domain);
                    raw_domains.push(domain);
                }
            }
        }

        let unique_domains: HashSet<String> = raw_domains.into_iter().collect();
        Ok(unique_domains.into_iter().collect())
    }
}

/// 基于布隆过滤器的域名检测器
pub struct BloomDomainChecker {
    filter: Bloom<Vec<u8>>,
}

impl BloomDomainChecker {
    pub fn new(domains: &[String], fp_rate: f64) -> Result<Self> {
        let num_items = domains.len();

        if num_items == 0 {
            anyhow::bail!("没有提供任何域名，无法构建布隆过滤器");
        }

        let mut filter = Bloom::<Vec<u8>>::new_for_fp_rate(num_items, fp_rate)
            .map_err(|e| anyhow::anyhow!("创建布隆过滤器失败: {}", e))?;

        for domain in domains {
            let domain = canonical_domain(domain);
            filter.set(&domain.as_bytes().to_vec());
        }

        Ok(Self { filter })
    }

    pub fn check(&self, domain: &str) -> bool {
        let domain = canonical_domain(domain);
        let mut parts: Vec<&str> = domain.split('.').collect();

        // 至少保留 2 段，例如 google.com
        while parts.len() >= 2 {
            let key = parts.join(".");
            if self.filter.check(&key.as_bytes().to_vec()) {
                return true;
            }

            // 去掉最左侧子域名
            parts.remove(0);
        }

        false
    }
}
