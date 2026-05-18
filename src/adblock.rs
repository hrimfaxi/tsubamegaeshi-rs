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
