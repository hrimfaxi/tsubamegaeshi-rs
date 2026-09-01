#!/bin/sh
# 本地更新 contrib/etc/tsubamegaeshi-rs/ 下的预置数据文件（发布前准备）。
# 上游源与 contrib/usr/libexec/update_tsubamegaeshi_files.sh 保持一致，
# 区别仅在于更新仓库内的 contrib 拷贝，不触碰 /etc，也不重启服务。
# 仅当下载内容与现有文件不同才替换，保持 git diff 干净。
# 用法：scripts/update_contrib_files.sh
set -e

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DATA_DIR="$REPO_ROOT/contrib/etc/tsubamegaeshi-rs"

MMDB_NAME="Country-only-cn-private.mmdb"
MMDB_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb"
MMDB_SHA_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb.sha256sum"

GFW_NAME="gfwlist.txt"
GFW_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/gfwlist.txt"

ADBLOCK_NAME="adblockdomainlite.txt"
ADBLOCK_URL="https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt"

UPDATED=""

# -----------------------
# 下载（wget 优先，回退 curl）
# -----------------------
fetch() {
  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    curl -fsSL -o "$2" "$1"
  fi
}

# -----------------------
# trap 自动清理临时目录
# -----------------------
TMP_DIR="$(mktemp -d /tmp/update-contrib.XXXXXX)"

cleanup() {
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if [ ! -d "$DATA_DIR" ]; then
  echo "[x] missing $DATA_DIR"
  exit 1
fi

echo "[*] updating mmdb..."

# =======================
# MMDB 更新逻辑（sha 校验）
# =======================
fetch "$MMDB_SHA_URL" "$TMP_DIR/mmdb.sha"
REMOTE_SHA="$(awk '{print $1}' "$TMP_DIR/mmdb.sha")"

if [ -f "$DATA_DIR/$MMDB_NAME" ]; then
  LOCAL_SHA="$(sha256sum "$DATA_DIR/$MMDB_NAME" | awk '{print $1}')"
else
  LOCAL_SHA=""
fi

if [ "$REMOTE_SHA" != "$LOCAL_SHA" ]; then
  echo "[!] mmdb changed"

  fetch "$MMDB_URL" "$TMP_DIR/$MMDB_NAME"
  DOWNLOADED_SHA="$(sha256sum "$TMP_DIR/$MMDB_NAME" | awk '{print $1}')"

  if [ "$DOWNLOADED_SHA" = "$REMOTE_SHA" ]; then
    mv "$TMP_DIR/$MMDB_NAME" "$DATA_DIR/$MMDB_NAME"
    chmod 644 "$DATA_DIR/$MMDB_NAME"
    UPDATED="$UPDATED mmdb"
    echo "[+] mmdb updated"
  else
    echo "[x] mmdb sha mismatch"
    exit 1
  fi
else
  echo "[=] mmdb unchanged"
fi

echo "[*] updating gfwlist..."

# =======================
# GFW 更新逻辑（diff 判断）
# =======================
fetch "$GFW_URL" "$TMP_DIR/$GFW_NAME"

if [ ! -s "$TMP_DIR/$GFW_NAME" ]; then
  echo "[x] gfwlist download failed"
  exit 1
fi

if [ -f "$DATA_DIR/$GFW_NAME" ] && cmp -s "$TMP_DIR/$GFW_NAME" "$DATA_DIR/$GFW_NAME"; then
  echo "[=] gfwlist unchanged"
else
  mv "$TMP_DIR/$GFW_NAME" "$DATA_DIR/$GFW_NAME"
  chmod 644 "$DATA_DIR/$GFW_NAME"
  UPDATED="$UPDATED gfwlist"
  echo "[+] gfwlist updated"
fi

echo "[*] updating adblock..."

# =======================
# ADBLOCK 更新逻辑
# =======================
fetch "$ADBLOCK_URL" "$TMP_DIR/$ADBLOCK_NAME"

if [ ! -s "$TMP_DIR/$ADBLOCK_NAME" ]; then
  echo "[x] adblock download failed"
  exit 1
fi

if [ -f "$DATA_DIR/$ADBLOCK_NAME" ] && cmp -s "$TMP_DIR/$ADBLOCK_NAME" "$DATA_DIR/$ADBLOCK_NAME"; then
  echo "[=] adblock unchanged"
else
  mv "$TMP_DIR/$ADBLOCK_NAME" "$DATA_DIR/$ADBLOCK_NAME"
  chmod 644 "$DATA_DIR/$ADBLOCK_NAME"
  UPDATED="$UPDATED adblock"
  echo "[+] adblock updated"
fi

# -----------------------
# 结果
# -----------------------
if [ -n "$UPDATED" ]; then
  echo "[✓] contrib files updated:$UPDATED"
  echo "[i] 发布前请先 git diff 复查"
else
  echo "[✓] no changes"
fi

exit 0

# vim: set sw=2 ts=2 et:
