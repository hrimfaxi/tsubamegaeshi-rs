# 燕返 (Tsubame Gaeshi)

> 佐々木小次郎の秘剣——一撃必殺。

一个轻量级 DNS 分流工具，专为 OpenWrt 设计。二进制体积约 600KB。

---

## 背景

在 OpenWrt 上做 DNS 分流，[mosdns](https://github.com/IrineSistiana/mosdns) 是常见的选择，功能全面、插件丰富。不过它的二进制体积在 20MB 左右，对于 flash 空间紧张的设备不太友好。

燕返采用 Rust 实现，裁剪到实际需要的功能，UPX 压缩后约 600KB。它不追求大而全，只覆盖日常分流场景中最常用的那部分。

---

## 工作流程

每条 DNS 查询按以下顺序处理，命中即返回：

```
查询进入
  │
  ├─ 非 A/AAAA 类型？ ────────► 直接转发国内上游
  │
  ├─ 命中 hosts？ ────────────► 返回预设 IP（地址族不匹配则返回 NODATA）
  │
  ├─ AAAA 被禁用？ ───────────► 返回 NODATA
  │
  ├─ 命中缓存？ ──────────────► 返回缓存结果
  │
  ├─ 匹配 special_suffixes？ ─► 转发 special 上游
  │
  ├─ 命中 force_domestic？ ───► 转发国内上游
  │
  ├─ 命中 force_foreign？ ────► 转发国外上游
  │
  ├─ GFWList 命中？ ──────────► 转发国外上游（布隆过滤器）
  │
  └─ 默认路径（无规则命中）：
       │
       ├─ 1. 查询国内上游
       │
       └─ 2. 检查结果：
            ├─ 返回的是中国 IP？ ──► 采用国内结果
            ├─ 返回 GFW 污染地址？ ► 改用国外上游
            └─ 都不是 ───────────► 查询国外上游
```

大部分查询在缓存或静态规则阶段就解决了。只有无缓存、无规则命中的域名才会走两次上游查询，GeoIP 判断也只在国内上游确实返回 IP 时才执行。

---

## 功能概览

### 分流路由

- **Special 后缀匹配**：匹配指定后缀的域名走独立上游，适合把 `.lan`、`.home` 等本地域名交给 dnsmasq 或内网 DNS
- **强制国内 / 强制国外**：基于后缀的域名列表，命中后跳过所有其他判断
- **GFWList 布隆过滤器**：读取 Base64 编码的 GFWList，使用布隆过滤器做内存高效的域名匹配，误判率可配置
- **GeoIP 兜底**：默认路径下先查国内上游，如果返回的 IP 属于中国大陆（通过 MaxMind GeoLite2 判断）则直接采用；否则再查国外上游

### IPv6

- 完整支持 AAAA 查询，A 和 AAAA 路由独立决策
- **污染地址检测**：识别 `2001::xxxx:yyyy` 格式的 GFW 污染地址，自动丢弃并回退到国外上游
- 可通过配置完全关闭 AAAA 查询

### 缓存

- 基于 LRU 的内存缓存，条目数可配置
- 尊重 DNS TTL，到期自动淘汰；TTL 为 0 的应答不会被缓存

### Hosts

- 支持静态 IPv4 / IPv6 覆盖，写在配置文件中
- 域名存在于 hosts 但找不到对应地址族时，返回 NODATA（而非 SERVFAIL）

### Marksite（nftables 自动标记）

- 将已解析的 IP 自动添加到 nftables set 中，可用于防火墙标记或策略路由
- 支持按域名子串匹配，分组对应不同的 nft 表
- nft set 使用 1 小时超时 + dynamic 标志，IP 到期自动清理
- 并发 nft 调用受信号量限制（最多 4 个），避免阻塞主循环

---

## 配置文件

```toml
# config.toml

listen = "0.0.0.0:53"

# ---------- 上游服务器 ----------
# 支持完整 ip:port，也支持省略端口（默认 53）
special_upstream   = "127.0.0.1:5353"   # 通常指向本地 dnsmasq
domestic_upstream  = "223.5.5.5"
foreign_upstream   = "8.8.8.8"

# ---------- Special 后缀 ----------
# 以这些后缀结尾的域名转发到 special_upstream
special_suffixes = [
    ".lan",
    ".home",
    ".local",
]

# ---------- GeoIP ----------
mmdb_path = "/etc/tsubamegaeshi/GeoLite2-Country.mmdb"

# ---------- 缓存 ----------
cache_size        = 4096       # 缓存条目数
query_timeout_sec = 5          # 上游查询超时（秒）

# ---------- IPv6 ----------
enable_ipv6_aaaa = false       # 设为 true 启用 AAAA 查询

# ---------- 日志 ----------
log_level = "info"

# ---------- GFWList ----------
gfwlist_path     = "/etc/tsubamegaeshi/gfwlist.txt"   # Base64 编码
gfbloom_fp_rate  = 0.001                              # 误判率 0.1%

# ---------- 强制路由 ----------
force_foreign_domains = [
    "google.com",
    "twitter.com",
    "youtube.com",
]

force_domestic_domains = [
    "bilibili.com",
    "jd.com",
]

# ---------- Hosts ----------
[hosts.ipv4]
"nas.home"    = "192.168.1.100"
"printer.lan" = "192.168.1.200"

[hosts.ipv6]
"nas.home"    = "fd00::100"

# ---------- Marksite（nftables 自动标记）----------
[marksite]
social = ["facebook.com", "instagram.com", "tiktok.com"]
ads    = ["doubleclick.net", "googlesyndication.com"]
```

---

## 编译

```bash
# 体积优化的 release 构建
RUSTFLAGS="-C panic=abort" cargo build --release

# 压缩
upx --lzma target/release/tsubamegaeshi-rs

# 结果约 600KB
```

建议的 `Cargo.toml` profile：

```toml
[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
strip         = true
panic         = "abort"
```

---

## 命令行

```
燕返 - Lightweight DNS splitter

用法: tsubamegaeshi-rs [OPTIONS]

选项:
  -c, --config <CONFIG>  配置文件路径 [默认: config.toml]
```

---

## 依赖

| Crate | 用途 |
|---|---|
| `tokio` | 异步运行时、UDP I/O |
| `hickory-proto` | DNS 报文解析与构造 |
| `maxminddb` | GeoIP2 国家查询 |
| `bloomfilter` | GFWList 域名匹配 |
| `lru` | DNS 响应缓存 |
| `socket2` | IPv6 双栈 socket 绑定 |
| `clap` | 命令行参数解析 |
| `toml` + `serde` | 配置文件反序列化 |
| `tracing` | 结构化日志 |
| `base64` | GFWList Base64 解码 |


无 C 依赖，无 OpenSSL。纯静态链接。

---

## 名字

**燕返（つばめがえし）**——佐々木小次郎的传说剑技，据说快到来得及斩落空中的燕子。

这个工具也是同样的思路：只做一件事，干净利落。

---

## 许可

MIT
