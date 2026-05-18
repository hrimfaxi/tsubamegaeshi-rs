use crate::dns_utils::response_cache_ttl;
use hickory_proto::op::Message;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

pub struct CacheEntry {
    pub data: Vec<u8>,
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

        let mut data = cached_data?;
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

        let expire = Instant::now() + Duration::from_secs(effective_ttl);

        let mut cache = self.inner.lock().await;
        cache.put(
            (domain.to_string(), qtype_num),
            CacheEntry {
                data: response.to_vec(),
                expire,
            },
        );
    }
}
