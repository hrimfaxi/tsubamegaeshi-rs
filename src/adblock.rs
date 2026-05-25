use crate::domain_utils::canonical_domain;
use anyhow::Result;
use bloomfilter::Bloom;
use std::collections::HashSet;
use std::fs;

fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || !s.contains('.') || s.starts_with('.') || s.ends_with('.') {
        return false;
    }

    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

pub struct AdblockDecoder {
    file_path: String,
}

impl AdblockDecoder {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.into(),
        }
    }

    pub fn extract_domains(&self) -> Result<Vec<String>> {
        let content = fs::read_to_string(&self.file_path)?;
        let mut domains = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                continue;
            }

            // 处理 ||domain^ 形式
            if let Some(rest) = line.strip_prefix("||") {
                let domain = rest.split(['^', '/', '?', '#', '*']).next().unwrap_or(rest);
                let domain = domain.trim();
                if looks_like_domain(domain) {
                    domains.push(canonical_domain(domain));
                }
            }
            // 处理 .example.com 形式
            else if let Some(rest) = line.strip_prefix('.') {
                let domain = rest.split(['^', '/', '?', '#', '*']).next().unwrap_or(rest);
                let domain = domain.trim();
                if looks_like_domain(domain) {
                    domains.push(canonical_domain(domain));
                }
            }
            // 纯域名（无修饰符），忽略带 $ 的选项规则
            else if !line.starts_with('@') && !line.contains('$') {
                let domain = line.split(['^', '/', '?', '#']).next().unwrap_or(line);
                let domain = domain.trim();
                if looks_like_domain(domain) {
                    domains.push(canonical_domain(domain));
                }
            }
        }

        let unique: HashSet<String> = domains.into_iter().collect();
        Ok(unique.into_iter().collect())
    }
}

pub struct AdblockChecker {
    bloom: Bloom<Vec<u8>>,
    exact: HashSet<String>,
}

impl AdblockChecker {
    pub fn new(domains: &[String], fp_rate: f64) -> Result<Self> {
        let num = domains.len();
        if num == 0 {
            anyhow::bail!("No adblock domains");
        }
        let mut bloom = Bloom::<Vec<u8>>::new_for_fp_rate(num, fp_rate)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut exact = HashSet::with_capacity(num);
        for domain in domains {
            let domain = canonical_domain(domain);
            bloom.set(&domain.as_bytes().to_vec());
            exact.insert(domain);
        }

        Ok(Self { bloom, exact })
    }

    pub fn check(&self, domain: &str) -> bool {
        let domain = canonical_domain(domain);
        let mut parts: Vec<&str> = domain.split('.').collect();

        while parts.len() >= 2 {
            let candidate = parts.join(".");
            let key = candidate.as_bytes().to_vec();

            if self.bloom.check(&key) && self.exact.contains(&candidate) {
                return true;
            }

            parts.remove(0);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 把规则内容写入临时文件，返回文件路径；测试结束后由调用方清理
    fn temp_rules_file(content: &str) -> (std::path::PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "tsubame_adblock_test_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, content).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        (path, path_str)
    }

    // ========== looks_like_domain ==========

    #[test]
    fn test_looks_like_domain_normal() {
        assert!(looks_like_domain("example.com"));
    }

    #[test]
    fn test_looks_like_domain_subdomain() {
        assert!(looks_like_domain("sub.example.com"));
    }

    #[test]
    fn test_looks_like_domain_hyphen() {
        assert!(looks_like_domain("a-b.example.com"));
    }

    #[test]
    fn test_looks_like_domain_empty() {
        assert!(!looks_like_domain(""));
    }

    #[test]
    fn test_looks_like_domain_no_dot() {
        assert!(!looks_like_domain("localhost"));
    }

    #[test]
    fn test_looks_like_domain_leading_dot() {
        assert!(!looks_like_domain(".example.com"));
    }

    #[test]
    fn test_looks_like_domain_trailing_dot() {
        assert!(!looks_like_domain("example.com."));
    }

    #[test]
    fn test_looks_like_domain_underscore() {
        assert!(!looks_like_domain("exa_mple.com"));
    }

    #[test]
    fn test_looks_like_domain_url() {
        assert!(!looks_like_domain("http://example.com"));
    }

    // ========== AdblockDecoder::extract_domains ==========

    #[test]
    fn test_extract_pipe_domain() {
        let (path, path_str) = temp_rules_file("||ads.example.com^\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"ads.example.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_with_path() {
        let (path, path_str) = temp_rules_file("||tracker.example.org/path\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"tracker.example.org".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_dot_prefix() {
        let (path, path_str) = temp_rules_file(".example.net\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"example.net".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_plain_domain() {
        let (path, path_str) = temp_rules_file("plain-domain.com\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(domains.contains(&"plain-domain.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_comment() {
        let (path, path_str) = temp_rules_file("! comment\nexample.com\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"comment".to_string()));
        assert!(domains.contains(&"example.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_section() {
        let (path, path_str) = temp_rules_file("[Adblock Plus 2.0]\nexample.com\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"Adblock Plus 2.0".to_string()));
        assert!(domains.contains(&"example.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_whitelist() {
        let (path, path_str) = temp_rules_file("@@allow.example.com\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"allow.example.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_dollar_rule() {
        let (path, path_str) = temp_rules_file("plain-domain.com$script\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"plain-domain.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_skips_invalid() {
        let (path, path_str) = temp_rules_file("invalid rule\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert!(!domains.contains(&"invalid".to_string()));
        assert!(!domains.contains(&"rule".to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_extract_dedup_and_normalize() {
        let (path, path_str) =
            temp_rules_file("||Example.COM^\n||example.com^\n.sub.example.com\n");
        let decoder = AdblockDecoder::new(&path_str);
        let domains = decoder.extract_domains().unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"sub.example.com".to_string()));
        fs::remove_file(path).unwrap();
    }

    // ========== AdblockChecker::new ==========

    #[test]
    fn test_checker_new_empty() {
        let result = AdblockChecker::new(&[], 0.001);
        assert!(result.is_err());
    }

    #[test]
    fn test_checker_new_ok() {
        let result = AdblockChecker::new(&["example.com".to_string()], 0.001);
        assert!(result.is_ok());
    }

    // ========== AdblockChecker::check ==========

    #[test]
    fn test_checker_exact_hit() {
        let checker = AdblockChecker::new(&["example.com".to_string()], 0.001).unwrap();
        assert!(checker.check("example.com"));
    }

    #[test]
    fn test_checker_subdomain_hit() {
        let checker = AdblockChecker::new(&["example.com".to_string()], 0.001).unwrap();
        assert!(checker.check("www.example.com"));
    }

    #[test]
    fn test_checker_deep_subdomain_hit() {
        let checker = AdblockChecker::new(&["example.com".to_string()], 0.001).unwrap();
        assert!(checker.check("a.b.example.com"));
    }

    #[test]
    fn test_checker_another_rule_hit() {
        let checker = AdblockChecker::new(&["ads.test.org".to_string()], 0.001).unwrap();
        assert!(checker.check("sub.ads.test.org"));
    }

    #[test]
    fn test_checker_false_suffix_miss() {
        let checker = AdblockChecker::new(&["example.com".to_string()], 0.001).unwrap();
        assert!(!checker.check("badexample.com"));
    }

    #[test]
    fn test_checker_different_tld_miss() {
        let checker = AdblockChecker::new(&["example.com".to_string()], 0.001).unwrap();
        assert!(!checker.check("example.org"));
    }

    #[test]
    fn test_checker_parent_not_hit() {
        let checker = AdblockChecker::new(&["ads.test.org".to_string()], 0.001).unwrap();
        assert!(!checker.check("test.org"));
    }
}
