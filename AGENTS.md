# AGENTS.md

## 概述

燕返 (Tsubame Gaeshi) — 轻量级 DNS 分流工具，专为 OpenWrt 设计，Rust 实现。单二进制，无 C 依赖，无 OpenSSL。

## 构建与测试

```bash
cargo build                          # debug 构建
cargo build --release                # 体积优化 (opt-level "z", LTO, strip, panic=abort)
cargo test                           # 运行所有单元测试（各模块内联 #[cfg(test)]）
cargo test -- <module_name>          # 运行单个模块的测试，如 `cargo test -- cache`
cargo clippy                         # lint
cargo fmt -- --check                 # 格式检查
```

OpenWrt MIPS 目标交叉编译使用 `cross`（见 `Cross.toml`），日常开发不需要。

## Rust 工具链

- **Edition 2024**（`Cargo.toml` 第 4 行）— 要求 rustc >= 1.85
- 稳定版工具链，不使用 nightly 特性

## 架构

单线程 accept + tokio 逐请求 spawn 模型。所有源码在 `src/`。

| 模块 | 职责 |
|---|---|
| `main.rs` | CLI、配置加载、组装、启动/关闭 |
| `server.rs` | 核心 DNS 服务器：接收循环、路由逻辑、上游查询、GeoIP 判断 |
| `dns_utils.rs` | DNS 报文构造（A、AAAA、HTTPS/SVCB、NODATA、SERVFAIL）、TTL 提取、ID 重写 |
| `cache.rs` | LRU 缓存，TTL 感知过期，异步 mutex |
| `domain_utils.rs` | 域名规范化（`canonical_domain`）、后缀匹配、强制列表检查 |
| `pollution.rs` | DNS 污染检测：GFW IPv6 特征（2001::、Facebook 2a03:2880）、自定义 IP 列表、原始包 IP 提取 |
| `gfwlist.rs` | GFWList Base64 解码 → 布隆过滤器域名检查 |
| `adblock.rs` | AdBlock Plus 规则解码 → 布隆过滤器 + 精确集合双重检查 |
| `mark_sites.rs` | nftables 自动标记：已解析 IP 通过 `/usr/sbin/nft` CLI 添加到 nft set |
| `task_guard.rs` | 任务生命周期管理，CancellationToken，带超时的优雅关闭 |
| `config.rs` | TOML 配置结构体，校验规则 |

### 请求流程（server.rs:846 `handle_request`）

1. 解析 DNS 报文，提取查询类型（A/AAAA/HTTPS/其他）
2. AAAA 被禁用？→ NODATA
3. Hosts 覆盖？→ 返回预设 IP
4. AdBlock 命中？→ 0.0.0.0 / :: / NODATA
5. 缓存命中？→ 返回缓存结果（ID 重写）
6. 静态规则：special_suffixes → force_domestic → force_foreign → GFWList 布隆
7. 默认路径：查国内上游 → 检查结果（污染/GeoIP）→ 回退到国外上游（带污染检测）

## 关键注意事项

- **hickory-proto HTTPS/SVCB 序列化问题**：`RecordType::HTTPS` + `RData::SVCB` 调用 `to_vec()` 会 panic。`pollution.rs` 中的测试使用手写原始字节数组（`https_raw_packet()`）。不要尝试用 hickory 的 `Record` API 构造 HTTPS 响应来测试。
- **MarkSites 使用子串匹配**，不是后缀匹配（`mark_sites.rs:108`）。`"google"` 模式会匹配 `"notgoogle.com"`，这是有意设计。
- **nft 二进制路径硬编码**为 `/usr/sbin/nft`（`mark_sites.rs:45,64`）。
- **`pollution.rs:65` 的 `FB_COMBOS` 数组必须保持有序**——使用 `binary_search` 查找。添加新的 Facebook 污染前缀时，按升序插入。
- **缓存 key** 为 `(domain: String, qtype: u16)` — domain 必须已经规范化（小写、无尾部点号）。
- **`foreign_query`**（server.rs:86）每次查询使用独立的临时 UDP socket（不是共享监听 socket），以支持多接收污染过滤循环。
- **`in_flight` 计数器**（server.rs:827）使用 relaxed 原子序 + RAII guard 递减——防止 tproxy 成环时打满服务器。
- **IPv6 双栈绑定**（server.rs:1126）使用 `socket2` 的 `set_only_v6(false)` 在同一 socket 上同时接受 v4 和 v6。

## 配置

TOML 配置文件（默认 `config.toml`）。所有字段见 `config.rs`，校验规则见 `config::Config::validate()`。`contrib/` 目录包含示例配置和 OpenWrt init 脚本。

## 开发纪律

- 补丁按难度从低到高排序，逐个修复，**必须用户说「继续」才能进入下一个**
- 每个功能/修复必须附带对应的单元测试
- 提交前必须保证 `cargo fmt && cargo clippy && cargo test` 全部通过
- **绝对禁止** `git commit -A` / `git commit -am`——必须显式 `git add` 指定文件后再提交，避免无关改动混入

## 不存在的内容

- 无 CI 工作流（无 `.github/`）
- 无集成测试（所有测试为模块内联单元测试）
- 无 `rustfmt.toml` 或 `clippy.toml`——使用默认配置
- 无 benchmark
