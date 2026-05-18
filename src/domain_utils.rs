/// 规范化域名：去除首尾点号，转小写
pub fn canonical_domain(domain: &str) -> String {
    domain
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// 规范化域名列表，空列表返回 None
pub fn normalize_domain_list(items: Option<Vec<String>>) -> Option<Vec<String>> {
    let items: Vec<String> = items
        .unwrap_or_default()
        .into_iter()
        .map(|s| canonical_domain(&s))
        .filter(|s| !s.is_empty())
        .collect();

    if items.is_empty() { None } else { Some(items) }
}

/// 域名后缀匹配。
///
/// 匹配：
/// - `example.com` == `example.com`
/// - `www.example.com` ends with `.example.com`
///
/// 不匹配：
/// - `badexample.com` 不应匹配 `example.com`
pub fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let d_norm = canonical_domain(domain);
    let s_norm = canonical_domain(suffix);

    let d_len = d_norm.len();
    let s_len = s_norm.len();

    // 2. 长度边界短路
    if d_len < s_len {
        return false;
    }

    // 3. 规范化后完全相等 (例如 domain: "google.com", suffix: "google.com")
    if d_len == s_len {
        return d_norm == s_norm;
    }

    // 4. 处理子域名后缀匹配 (例如 domain: "www.google.com", suffix: "google.com")
    if d_norm.ends_with(&s_norm) {
        let prev_char_idx = d_len - s_len - 1;
        if let Some(c) = d_norm.as_bytes().get(prev_char_idx) {
            return *c == b'.';
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matches_suffix() {
        // 1. 完全相等的情况
        assert!(domain_matches_suffix("google.com", "google.com"));
        assert!(
            domain_matches_suffix("Google.Com", "google.com"),
            "应该忽略大小写"
        );

        // 2. 标准子域名匹配
        assert!(domain_matches_suffix("www.google.com", "google.com"));
        assert!(domain_matches_suffix("mail.www.google.com", "google.com"));
        assert!(domain_matches_suffix("a.b.c.d.google.com", "google.com"));

        // 3. 相似但【不应该】匹配的情况（经典边界漏洞）
        assert!(
            !domain_matches_suffix("notgoogle.com", "google.com"),
            "防止字符串部分包含的伪匹配"
        );
        assert!(!domain_matches_suffix("fakegoogle.com", "google.com"));
        assert!(
            !domain_matches_suffix("google.com.cn", "google.com"),
            "后缀不同不应匹配"
        );
        assert!(
            !domain_matches_suffix("com", "google.com"),
            "长度不够不应匹配"
        );

        // 4. 各种恶心的 FQDN 尾部点（Trailing Dot）情况
        // 因为入口进来了 canonical_domain，所以这些行为必须表现一致且安全
        assert!(domain_matches_suffix("google.com.", "google.com"));
        assert!(domain_matches_suffix("google.com", "google.com."));
        assert!(domain_matches_suffix("google.com.", "google.com."));
        assert!(domain_matches_suffix("www.google.com.", "google.com"));
        assert!(domain_matches_suffix("www.google.com", "google.com."));
        assert!(domain_matches_suffix("www.google.com.", "google.com."));

        // 5. 空字符或非法边界防御
        assert!(!domain_matches_suffix("", "google.com"));
        assert!(!domain_matches_suffix("google.com", ""));
        assert!(domain_matches_suffix("", ""));
    }
}

/// 检查域名是否匹配强制列表中的任一条目。
pub fn is_forced(domain: &str, list: &Option<Vec<String>>) -> bool {
    let Some(items) = list else {
        return false;
    };

    items
        .iter()
        .any(|pattern| domain_matches_suffix(domain, pattern))
}
