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

    // ========== canonical_domain ==========

    #[test]
    fn test_canonical_domain_lowercase() {
        assert_eq!(canonical_domain("Example.COM"), "example.com");
    }

    #[test]
    fn test_canonical_domain_leading_dot() {
        assert_eq!(canonical_domain(".example.com"), "example.com");
    }

    #[test]
    fn test_canonical_domain_trailing_dot() {
        assert_eq!(canonical_domain("example.com."), "example.com");
    }

    #[test]
    fn test_canonical_domain_both_dots_and_case() {
        assert_eq!(canonical_domain(".Example.COM."), "example.com");
    }

    #[test]
    fn test_canonical_domain_empty() {
        assert_eq!(canonical_domain(""), "");
    }

    #[test]
    fn test_canonical_domain_only_dot() {
        assert_eq!(canonical_domain("."), "");
    }

    // ========== normalize_domain_list ==========

    #[test]
    fn test_normalize_domain_list_none() {
        assert_eq!(normalize_domain_list(None), None);
    }

    #[test]
    fn test_normalize_domain_list_empty() {
        assert_eq!(normalize_domain_list(Some(vec![])), None);
    }

    #[test]
    fn test_normalize_domain_list_normalizes_and_filters() {
        let input = Some(vec![
            "Example.COM".to_string(),
            ".test.org.".to_string(),
            "".to_string(),
        ]);
        let expected = Some(vec!["example.com".to_string(), "test.org".to_string()]);
        assert_eq!(normalize_domain_list(input), expected);
    }

    #[test]
    fn test_normalize_domain_list_all_empty_items() {
        let input = Some(vec!["".to_string(), ".".to_string(), "..".to_string()]);
        assert_eq!(normalize_domain_list(input), None);
    }

    // ========== domain_matches_suffix ==========

    #[test]
    fn test_domain_matches_suffix_exact() {
        assert!(domain_matches_suffix("google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_case_insensitive() {
        assert!(domain_matches_suffix("Google.Com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_single_subdomain() {
        assert!(domain_matches_suffix("www.google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_deep_subdomain() {
        assert!(domain_matches_suffix("a.b.c.google.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_not_a_subdomain_1() {
        assert!(!domain_matches_suffix("notgoogle.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_not_a_subdomain_2() {
        assert!(!domain_matches_suffix("fakegoogle.com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_longer_tld() {
        assert!(!domain_matches_suffix("google.com.cn", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_shorter_domain() {
        assert!(!domain_matches_suffix("com", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_trailing_dot_domain() {
        assert!(domain_matches_suffix("google.com.", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_trailing_dot_suffix() {
        assert!(domain_matches_suffix("google.com", "google.com."));
    }

    #[test]
    fn test_domain_matches_suffix_both_trailing_dots() {
        assert!(domain_matches_suffix("www.google.com.", "google.com."));
    }

    #[test]
    fn test_domain_matches_suffix_empty_domain() {
        assert!(!domain_matches_suffix("", "google.com"));
    }

    #[test]
    fn test_domain_matches_suffix_empty_suffix() {
        assert!(!domain_matches_suffix("google.com", ""));
    }

    #[test]
    fn test_domain_matches_suffix_both_empty() {
        // 与当前实现保持一致：空字符串视为相等
        assert!(domain_matches_suffix("", ""));
    }

    // ========== is_forced ==========

    #[test]
    fn test_is_forced_none_list() {
        assert!(!is_forced("google.com", &None));
    }

    #[test]
    fn test_is_forced_exact_match() {
        let list = Some(vec!["google.com".to_string()]);
        assert!(is_forced("google.com", &list));
    }

    #[test]
    fn test_is_forced_subdomain_match() {
        let list = Some(vec!["google.com".to_string()]);
        assert!(is_forced("www.google.com", &list));
    }

    #[test]
    fn test_is_forced_multi_rule_hit_one() {
        let list = Some(vec!["google.com".to_string(), "github.com".to_string()]);
        assert!(is_forced("api.github.com", &list));
    }

    #[test]
    fn test_is_forced_no_match() {
        let list = Some(vec!["google.com".to_string(), "github.com".to_string()]);
        assert!(!is_forced("example.org", &list));
    }

    #[test]
    fn test_is_forced_case_insensitive() {
        let list = Some(vec!["Google.COM".to_string()]);
        assert!(is_forced("www.google.com", &list));
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
