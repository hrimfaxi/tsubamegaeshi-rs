use crate::domain_utils::canonical_domain;
use anyhow::{Context, Result, anyhow, bail};
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
            bail!("文件内容为空");
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
    filter: Bloom<str>,
}

impl BloomDomainChecker {
    pub fn new(domains: &[String], fp_rate: f64) -> Result<Self> {
        let num_items = domains.len();

        if num_items == 0 {
            bail!("没有提供任何域名，无法构建布隆过滤器");
        }

        let mut filter = Bloom::<str>::new_for_fp_rate(num_items, fp_rate)
            .map_err(|e| anyhow!("创建布隆过滤器失败: {}", e))?;

        for domain in domains {
            let domain = canonical_domain(domain);
            filter.set(&domain);
        }

        Ok(Self { filter })
    }

    pub fn check(&self, domain: &str) -> bool {
        let domain = canonical_domain(domain);
        let parts: Vec<&str> = domain.split('.').collect();

        for i in 0..parts.len().saturating_sub(1) {
            let key = parts[i..].join(".");
            if self.filter.check(&key) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use std::fs;

    fn temp_gfwlist_file(plaintext: &str) -> (std::path::PathBuf, String) {
        let encoded = STANDARD.encode(plaintext);
        let path = std::env::temp_dir().join(format!(
            "tsubame_gfwlist_test_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, encoded).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        (path, path_str)
    }

    // ========== GfwlistDecoder::extract_domains 正常路径 ==========

    #[test]
    fn test_extract_pipe_domain() {
        let (path, path_str) = temp_gfwlist_file("||google.com\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"google.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_with_caret() {
        let (path, path_str) = temp_gfwlist_file("||youtube.com^\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"youtube.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_with_path() {
        let (path, path_str) = temp_gfwlist_file("||github.com/path\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"github.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_comment() {
        let (path, path_str) = temp_gfwlist_file("! comment\n||google.com\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"comment".to_string()));
        assert!(domains.contains(&"google.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_whitelist() {
        let (path, path_str) = temp_gfwlist_file("@@||white.example.com\n||google.com\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"white.example.com".to_string()));
        assert!(domains.contains(&"google.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_non_pipe() {
        let (path, path_str) = temp_gfwlist_file("|http://not-supported.com\n||google.com\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"not-supported.com".to_string()));
        assert!(domains.contains(&"google.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_dedup_and_normalize() {
        let (path, path_str) = temp_gfwlist_file("||Google.COM\n||google.com\n||Google.COM\n");
        let decoder = GfwlistDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert_eq!(domains.len(), 1);
        assert!(domains.contains(&"google.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    // ========== Base64 / UTF-8 异常路径 ==========

    #[test]
    fn test_extract_empty_file() {
        let path = std::env::temp_dir().join("tsubame_gfwlist_empty.txt");
        fs::write(&path, "").unwrap();
        let decoder = GfwlistDecoder::new(path.to_str().unwrap());
        assert!(decoder.extract_domains().is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_invalid_base64() {
        let path = std::env::temp_dir().join("tsubame_gfwlist_bad64.txt");
        fs::write(&path, "%%%not-base64%%%").unwrap();
        let decoder = GfwlistDecoder::new(path.to_str().unwrap());
        assert!(decoder.extract_domains().is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_non_utf8() {
        let bytes = vec![0x80u8, 0x81, 0x82];
        let encoded = STANDARD.encode(&bytes);
        let path = std::env::temp_dir().join("tsubame_gfwlist_nonutf8.txt");
        fs::write(&path, encoded).unwrap();
        let decoder = GfwlistDecoder::new(path.to_str().unwrap());
        assert!(decoder.extract_domains().is_err());
        fs::remove_file(path).unwrap();
    }

    // ========== BloomDomainChecker::new ==========

    #[test]
    fn test_bloom_new_empty() {
        let result = BloomDomainChecker::new(&[], 0.001);
        assert!(result.is_err());
    }

    #[test]
    fn test_bloom_new_ok() {
        let result = BloomDomainChecker::new(&["google.com".to_string()], 0.001);
        assert!(result.is_ok());
    }

    // ========== BloomDomainChecker::check — 只测命中，不测 miss ==========

    #[test]
    fn test_bloom_exact_hit() {
        let checker = BloomDomainChecker::new(&["google.com".to_string()], 0.001).unwrap();
        assert!(checker.check("google.com"));
    }

    #[test]
    fn test_bloom_subdomain_hit() {
        let checker = BloomDomainChecker::new(&["google.com".to_string()], 0.001).unwrap();
        assert!(checker.check("www.google.com"));
    }

    #[test]
    fn test_bloom_deep_subdomain_hit() {
        let checker = BloomDomainChecker::new(&["github.com".to_string()], 0.001).unwrap();
        assert!(checker.check("a.b.github.com"));
    }
}
