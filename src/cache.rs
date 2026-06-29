use crate::dns_utils::response_cache_ttl;
use hickory_proto::op::Message;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

pub struct CacheEntry {
    pub data: Arc<Vec<u8>>,
    pub expire: Instant,
}

pub struct DnsCache {
    inner: Mutex<LruCache<(String, u16), CacheEntry>>,
}

impl DnsCache {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(size)),
        }
    }

    pub async fn get_response(&self, domain: &str, qtype_num: u16, req_id: u16) -> Option<Vec<u8>> {
        let key = (domain.to_string(), qtype_num);

        let cached_data = {
            let mut cache = self.inner.lock().await;
            let now = Instant::now();

            let mut expired = false;

            let data = if let Some(entry) = cache.get(&key) {
                if entry.expire > now {
                    Some(entry.data.clone())
                } else {
                    expired = true;
                    None
                }
            } else {
                None
            };

            if expired {
                cache.pop(&key);
            }

            data
        };

        let data = cached_data?;
        let mut data = Arc::try_unwrap(data).unwrap_or_else(|arc| (*arc).clone());
        crate::dns_utils::rewrite_dns_id(&mut data, req_id);
        Some(data)
    }

    pub async fn put_response(
        &self,
        domain: &str,
        qtype_num: u16,
        response: &[u8],
        skip_tag: &str,
    ) {
        let Ok(msg) = Message::from_vec(response) else {
            return;
        };

        if msg.response_code() != hickory_proto::op::ResponseCode::NoError
            || msg.answers().is_empty()
        {
            return;
        }

        let Some(effective_ttl) = response_cache_ttl(&msg) else {
            debug!("[{}] {} ttl=0", skip_tag, domain);
            return;
        };

        self.put_with_ttl(domain, qtype_num, response, effective_ttl)
            .await;
    }

    /// 直接以给定 TTL 写入缓存，跳过响应解析和校验。
    /// 调用方必须确保 response 是 NoError 且 answers 非空。
    pub async fn put_with_ttl(&self, domain: &str, qtype_num: u16, response: &[u8], ttl_secs: u64) {
        if ttl_secs == 0 {
            return;
        }

        let expire = Instant::now() + Duration::from_secs(ttl_secs);

        let mut cache = self.inner.lock().await;
        cache.put(
            (domain.to_string(), qtype_num),
            CacheEntry {
                data: Arc::new(response.to_vec()),
                expire,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::A as ARecord;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::num::NonZeroUsize;
    use std::time::{Duration, Instant};

    /// 测试专用：直接往内部缓存插一条数据（可控制过期时间）
    #[cfg(test)]
    impl DnsCache {
        async fn insert_test_entry(
            &self,
            domain: &str,
            qtype: u16,
            data: Vec<u8>,
            expire: Instant,
        ) {
            let mut cache = self.inner.lock().await;
            cache.put(
                (domain.to_string(), qtype),
                CacheEntry {
                    data: Arc::new(data),
                    expire,
                },
            );
        }
    }

    /// 构造一个合法 A 记录响应，TTL = `ttl_sec`
    fn a_response_bytes(id: u16, ttl_sec: u32) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));

        let mut answer = Record::new();
        answer.set_name(name);
        answer.set_record_type(RecordType::A);
        answer.set_ttl(ttl_sec);
        answer.set_data(Some(RData::A(ARecord(Ipv4Addr::new(1, 2, 3, 4)))));
        msg.add_answer(answer);

        msg.to_vec().unwrap()
    }

    // ========== 基本 put / get ==========

    #[tokio::test]
    async fn test_cache_put_and_get() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        let resp = a_response_bytes(100, 300);

        cache.put_response("example.com", 1, &resp, "SKIP").await;

        let got = cache.get_response("example.com", 1, 999).await;
        assert!(got.is_some());

        let bytes = got.unwrap();
        // ID 应该被重写成 999
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(id, 999);
        // 其余内容不变
        assert_eq!(bytes[2..], resp[2..]);
    }

    // ========== DNS ID 重写 ==========

    #[tokio::test]
    async fn test_cache_rewrites_id() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        let resp = a_response_bytes(1234, 300);

        cache.put_response("example.com", 1, &resp, "SKIP").await;

        let got = cache.get_response("example.com", 1, 0xBEEF).await.unwrap();
        assert_eq!(&got[0..2], &[0xBE, 0xEF]);
    }

    // ========== 不存在的 key ==========

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        let got = cache.get_response("notfound.com", 1, 1).await;
        assert!(got.is_none());
    }

    // ========== TTL 为 0 不缓存 ==========

    #[tokio::test]
    async fn test_cache_ttl_zero_not_cached() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        let resp = a_response_bytes(1, 0);

        cache.put_response("example.com", 1, &resp, "SKIP").await;

        let got = cache.get_response("example.com", 1, 1).await;
        assert!(got.is_none());
    }

    // ========== 非 NoError 不缓存 ==========

    #[tokio::test]
    async fn test_cache_servfail_not_cached() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::ServFail);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let resp = msg.to_vec().unwrap();

        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        cache.put_response("example.com", 1, &resp, "SKIP").await;

        let got = cache.get_response("example.com", 1, 1).await;
        assert!(got.is_none());
    }

    // ========== 空 answer 不缓存 ==========

    #[tokio::test]
    async fn test_cache_empty_answers_not_cached() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_ascii("example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let resp = msg.to_vec().unwrap();

        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        cache.put_response("example.com", 1, &resp, "SKIP").await;

        let got = cache.get_response("example.com", 1, 1).await;
        assert!(got.is_none());
    }

    // ========== 非法 DNS 响应不缓存 ==========

    #[tokio::test]
    async fn test_cache_invalid_dns_not_cached() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        cache
            .put_response("example.com", 1, &[0u8; 10], "SKIP")
            .await;

        let got = cache.get_response("example.com", 1, 1).await;
        assert!(got.is_none());
    }

    // ========== 过期条目 ==========

    #[tokio::test]
    async fn test_cache_expired_entry_removed() {
        let cache = DnsCache::new(NonZeroUsize::new(10).unwrap());
        let resp = a_response_bytes(1, 300);

        // 直接插入一个已经过期的条目
        cache
            .insert_test_entry(
                "example.com",
                1,
                resp,
                Instant::now() - Duration::from_secs(1),
            )
            .await;

        let got = cache.get_response("example.com", 1, 1).await;
        assert!(got.is_none());

        // 确认条目已被移除（再次 get 仍为 None，且内部 size 为 0）
        let got2 = cache.get_response("example.com", 1, 1).await;
        assert!(got2.is_none());
    }

    // ========== LRU 淘汰 ==========

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let cache = DnsCache::new(NonZeroUsize::new(2).unwrap());
        let resp1 = a_response_bytes(1, 300);
        let resp2 = a_response_bytes(2, 300);
        let resp3 = a_response_bytes(3, 300);

        cache.put_response("a.com", 1, &resp1, "SKIP").await;
        cache.put_response("b.com", 1, &resp2, "SKIP").await;

        // 访问 a.com，使其比 b.com 更新
        let _ = cache.get_response("a.com", 1, 1).await;

        // 插入 c.com，应淘汰最久未访问的 b.com
        cache.put_response("c.com", 1, &resp3, "SKIP").await;

        assert!(cache.get_response("a.com", 1, 1).await.is_some());
        assert!(cache.get_response("b.com", 1, 1).await.is_none());
        assert!(cache.get_response("c.com", 1, 1).await.is_some());
    }
}
