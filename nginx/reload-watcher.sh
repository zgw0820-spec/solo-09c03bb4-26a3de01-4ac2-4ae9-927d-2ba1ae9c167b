#!/bin/sh
# 与 web 侧约定：web 向 $RELOAD_DIR/REQUEST 追加一行令牌，
# 本脚本检测到新行后执行 nginx -t && nginx -s reload（平滑重载，旧连接自然完成），
# 并把结果以 "令牌 ok|fail 原因" 追加到 $RELOAD_DIR/RESULT。
#
# 仅用于演练/自测的故障注入（生产目录留空即完全不生效）：
#   $RELOAD_DIR/FAULT_FAIL_PREFIX   令牌前缀命中：标记文件存活期间该前缀的
#                                   每一批令牌都回执 fail 且不重载；出现不匹配
#                                   前缀的令牌后自动失效（避免误伤后续无关操作）
#   $RELOAD_DIR/FAULT_CONTAINS      令牌包含该子串即回执 fail 且不重载；
#                                   出现不含该子串的令牌后自动失效
#   $RELOAD_DIR/FAULT_FAIL_TOKEN    完整令牌命中：仅该令牌回执 fail 且不重载（一次性）
set -u

RELOAD_DIR="${RELOAD_DIR:-/reload}"
LIVE_DIR="${LIVE_DIR:-/etc/nginx/certs/live}"
NGINX_BIN="${NGINX_BIN:-nginx}"
NGINX_ARGS="${NGINX_ARGS:-}"
REQ="$RELOAD_DIR/REQUEST"
RES="$RELOAD_DIR/RESULT"
FAULT_FAIL_PREFIX="$RELOAD_DIR/FAULT_FAIL_PREFIX"
FAULT_CONTAINS="$RELOAD_DIR/FAULT_CONTAINS"
FAULT_FAIL_TOKEN="$RELOAD_DIR/FAULT_FAIL_TOKEN"

mkdir -p "$RELOAD_DIR"
touch "$REQ" "$RES"
# 启动时清除任何遗留的故障注入标记，避免污染本次运行
rm -f "$FAULT_FAIL_PREFIX" "$FAULT_CONTAINS" "$FAULT_FAIL_TOKEN" \
  "$RELOAD_DIR/.need-reload" 2>/dev/null || true

# 首次启动时等待 web 侧生成证书文件
n=0
while [ ! -s "$LIVE_DIR/fullchain.pem" ] || [ ! -s "$LIVE_DIR/privkey.pem" ]; do
  n=$((n + 1))
  if [ "$n" -gt 600 ]; then
    echo "reload-watcher: 等待证书文件超时" >&2
    exit 1
  fi
  sleep 0.5
done

# shellcheck disable=SC2086
$NGINX_BIN $NGINX_ARGS || exit 1
echo "reload-watcher: nginx started, watching $REQ" >&2

last_count=$(wc -l < "$REQ" | tr -d ' ')
sticky_prefix=""
sticky_contains=""
while :; do
  sleep 0.3
  cur_count=$(wc -l < "$REQ" 2>/dev/null | tr -d ' ' || echo 0)
  case "$cur_count" in ''|*[!0-9]*) cur_count=0 ;; esac
  [ "$cur_count" -le "$last_count" ] && continue

  # 故障注入：
  # - FAULT_FAIL_TOKEN 精确命中一个令牌（读取即移除，一次性）
  # - FAULT_FAIL_PREFIX 粘性前缀：标记存活期间同前缀令牌强制 fail
  # - FAULT_CONTAINS 粘性子串：标记存活期间含该子串的令牌强制 fail
  #   两类粘性标记在本批出现不匹配令牌时自动失效，避免误伤后续无关操作
  fail_token=""
  if [ -s "$FAULT_FAIL_TOKEN" ]; then
    fail_token=$(cat "$FAULT_FAIL_TOKEN" 2>/dev/null)
    rm -f "$FAULT_FAIL_TOKEN"
  fi
  if [ -z "$sticky_prefix" ] && [ -s "$FAULT_FAIL_PREFIX" ]; then
    sticky_prefix=$(cat "$FAULT_FAIL_PREFIX" 2>/dev/null)
  fi
  if [ -z "$sticky_contains" ] && [ -s "$FAULT_CONTAINS" ]; then
    sticky_contains=$(cat "$FAULT_CONTAINS" 2>/dev/null)
  fi

  sed -n "$((last_count + 1)),${cur_count}p" "$REQ" | while read -r token _; do
    [ -z "$token" ] && continue
    if [ -n "$fail_token" ] && [ "$token" = "$fail_token" ]; then
      echo "$token fail test: injected failure for token $fail_token" >> "$RES"
      continue
    fi
    if [ -n "$sticky_prefix" ]; then
      case "$token" in
        "$sticky_prefix"*)
          echo "$token fail test: injected failure for prefix $sticky_prefix" >> "$RES"
          continue
          ;;
      esac
    fi
    if [ -n "$sticky_contains" ]; then
      case "$token" in
        *"$sticky_contains"*)
          echo "$token fail test: injected failure containing $sticky_contains" >> "$RES"
          continue
          ;;
      esac
    fi
    echo "$token" >> "$RELOAD_DIR/.need-reload"
  done

  # 本批出现不匹配粘性标记的令牌：故障注入结束，删除对应标记文件
  batch_tokens=$(sed -n "$((last_count + 1)),${cur_count}p" "$REQ" | cut -d' ' -f1)
  if [ -n "$sticky_prefix" ] && echo "$batch_tokens" \
      | grep -v "^$sticky_prefix" | grep -q .; then
    rm -f "$FAULT_FAIL_PREFIX"
    sticky_prefix=""
  fi
  if [ -n "$sticky_contains" ] && echo "$batch_tokens" \
      | grep -v ".*$sticky_contains.*" | grep -q .; then
    rm -f "$FAULT_CONTAINS"
    sticky_contains=""
  fi

  if [ -s "$RELOAD_DIR/.need-reload" ]; then
    # shellcheck disable=SC2086
    if $NGINX_BIN $NGINX_ARGS -t >/tmp/nginx-t.err 2>&1; then
      # shellcheck disable=SC2086
      if $NGINX_BIN $NGINX_ARGS -s reload >/tmp/nginx-r.err 2>&1; then
        result="ok"
      else
        result="fail reload: $(tail -n 1 /tmp/nginx-r.err)"
      fi
    else
      result="fail test: $(tail -n 1 /tmp/nginx-t.err)"
    fi
    while read -r token; do
      [ -n "$token" ] && echo "$token $result" >> "$RES"
    done < "$RELOAD_DIR/.need-reload"
    rm -f "$RELOAD_DIR/.need-reload"
  fi
  last_count=$cur_count
done
