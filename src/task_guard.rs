use std::sync::Mutex;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub struct TaskGuard {
    cancel: CancellationToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl TaskGuard {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            handles: Mutex::new(Vec::new()),
        }
    }

    pub fn child_token(&self) -> CancellationToken {
        self.cancel.child_token()
    }

    /// 异步 spawn，guard 不跨 await，完全安全
    pub fn spawn<F>(&self, build: impl FnOnce(CancellationToken) -> F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let token = self.child_token();
        let mut handles = self.handles.lock().expect("bad taskguard lock");
        // 自动清理已结束任务，避免动态 spawn 场景下无限增长
        handles.retain(|h| !h.is_finished());
        handles.push(tokio::spawn(build(token)));
    }

    /// spawn_blocking 包装，统一生命周期管理
    pub fn spawn_blocking<F, R>(&self, f: F)
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let mut handles = self.handles.lock().expect("bad taskguard lock");
        handles.retain(|h| !h.is_finished());
        let inner = tokio::task::spawn_blocking(f);
        handles.push(tokio::spawn(async move {
            let _ = inner.await;
        }));
    }

    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.cancel.cancel();

        let handles: Vec<_> = {
            let mut h = self.handles.lock().expect("bad taskguard lock");
            h.drain(..).collect()
        };

        let deadline = tokio::time::Instant::now() + timeout;
        let mut ok = true;

        for mut handle in handles {
            let now = tokio::time::Instant::now();

            if now >= deadline {
                handle.abort();
                let _ = handle.await;
                ok = false;
                continue;
            }

            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!("task exited with JoinError: {}", e);
                }
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    ok = false;
                }
            }
        }

        ok
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
