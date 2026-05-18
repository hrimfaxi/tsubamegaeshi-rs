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
    let domain = canonical_domain(domain);
    let suffix = canonical_domain(suffix);

    if suffix.is_empty() {
        return false;
    }

    domain == suffix || domain.ends_with(&format!(".{}", suffix))
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
