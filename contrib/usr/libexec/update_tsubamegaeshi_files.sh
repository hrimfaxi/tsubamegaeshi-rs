#!/bin/sh
set -e

MMDB_PATH="/etc/tsubamegaeshi-rs/Country-only-cn-private.mmdb"
MMDB_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb"
MMDB_SHA_URL="https://raw.githubusercontent.com/kkkgo/Country-only-cn-private.mmdb/main/Country-only-cn-private.mmdb.sha256sum"

GFW_PATH="/etc/tsubamegaeshi-rs/gfwlist.txt"
GFW_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/refs/heads/master/gfwlist.txt"

ADBLOCK_PATH="/etc/tsubamegaeshi-rs/adblockadminlite.txt"
ADBLOCK_URL="https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt"

LOCK="/tmp/update_tsubamegaeshi.lock"

UPDATED=0

# -----------------------
# 防并发锁
# -----------------------
if [ -f "$LOCK" ]; then
  echo "[x] another update running"
  exit 0
fi

touch "$LOCK"

# -----------------------
# trap 自动清理
# -----------------------
MMDB_TMP=""
MMDB_SHA_TMP=""
GFW_TMP=""
ADBLOCK_TMP=""

cleanup() {
  rm -f "$LOCK"
  [ -n "$MMDB_TMP" ] && rm -f "$MMDB_TMP"
  [ -n "$MMDB_SHA_TMP" ] && rm -f "$MMDB_SHA_TMP"
  [ -n "$GFW_TMP" ] && rm -f "$GFW_TMP"
  [ -n "$ADBLOCK_TMP" ] && rm -f "$ADBLOCK_TMP"
}

trap cleanup EXIT INT TERM

echo "[*] updating mmdb..."

# =======================
# MMDB 更新逻辑（sha 校验）
# =======================
MMDB_TMP="$(mktemp /tmp/mmdb.XXXXXX)"
MMDB_SHA_TMP="$(mktemp /tmp/mmdb-sha.XXXXXX)"

wget -q -O "$MMDB_SHA_TMP" "$MMDB_SHA_URL"
REMOTE_SHA="$(awk '{print $1}' "$MMDB_SHA_TMP")"

if [ -f "$MMDB_PATH" ]; then
  LOCAL_SHA="$(sha256sum "$MMDB_PATH" | awk '{print $1}')"
else
  LOCAL_SHA=""
fi

if [ "$REMOTE_SHA" != "$LOCAL_SHA" ]; then
  echo "[!] mmdb changed"

  wget -q -O "$MMDB_TMP" "$MMDB_URL"
  DOWNLOADED_SHA="$(sha256sum "$MMDB_TMP" | awk '{print $1}')"

  if [ "$DOWNLOADED_SHA" = "$REMOTE_SHA" ]; then
    mv "$MMDB_TMP" "$MMDB_PATH"
    chmod 644 "$MMDB_PATH"
    UPDATED=1
    MMDB_TMP=""
    echo "[+] mmdb updated"
  else
    echo "[x] mmdb sha mismatch"
    exit 1
  fi
else
  echo "[=] mmdb unchanged"
fi

rm -f "$MMDB_SHA_TMP"
MMDB_SHA_TMP=""

echo "[*] updating gfwlist..."

# =======================
# GFW 更新逻辑（diff 判断）
# =======================
GFW_TMP="$(mktemp /tmp/gfw.XXXXXX)"

wget -q -O "$GFW_TMP" "$GFW_URL"

if [ ! -s "$GFW_TMP" ]; then
  echo "[x] gfwlist download failed"
  exit 1
fi

if [ -f "$GFW_PATH" ]; then
  if cmp -s "$GFW_TMP" "$GFW_PATH"; then
    echo "[=] gfwlist unchanged"
  else
    mv "$GFW_TMP" "$GFW_PATH"
    chmod 644 "$GFW_PATH"
    UPDATED=1
    GFW_TMP=""
    echo "[+] gfwlist updated"
  fi
else
  mv "$GFW_TMP" "$GFW_PATH"
  chmod 644 "$GFW_PATH"
  UPDATED=1
  GFW_TMP=""
  echo "[+] gfwlist created"
fi

echo "[*] updating adblock..."

# =======================
# ADBLOCK 更新逻辑
# =======================
ADBLOCK_TMP="$(mktemp /tmp/adblock.XXXXXX)"

wget -q -O "$ADBLOCK_TMP" "$ADBLOCK_URL"

if [ ! -s "$ADBLOCK_TMP" ]; then
  echo "[x] adblock download failed"
  exit 1
fi

if [ -f "$ADBLOCK_PATH" ]; then
  if cmp -s "$ADBLOCK_TMP" "$ADBLOCK_PATH"; then
    echo "[=] adblock unchanged"
  else
    mv "$ADBLOCK_TMP" "$ADBLOCK_PATH"
    chmod 644 "$ADBLOCK_PATH"
    UPDATED=1
    ADBLOCK_TMP=""
    echo "[+] adblock updated"
  fi
else
  mv "$ADBLOCK_TMP" "$ADBLOCK_PATH"
  chmod 644 "$ADBLOCK_PATH"
  UPDATED=1
  ADBLOCK_TMP=""
  echo "[+] adblock created"
fi

# -----------------------
# 结果
# -----------------------
if [ "$UPDATED" -eq 1 ]; then
  echo "[✓] updated, need restart"
  service tsubamegaeshi-rs restart
  exit 0
else
  echo "[✓] no changes"
  exit 1
fi

# vim: set sw=2 ts=2 et:
