#!/usr/bin/env bash
# 真实 nginx 端到端：事故场景"迟到生效 + 回退不可核实"与修复后的状态机。
#
# 启动方式（干净栈 + 较短超时 + 拦截重载的 nginx 包装器）：
#   bash scripts/local_stack.sh down && rm -rf "${LOCAL_WORK:-/tmp/certops-local}"
#   W=/tmp/certops-local
#   NGINX_BIN="$PWD/scripts/nginx-hold-wrapper.sh" \
#   REAL_NGINX_BIN=/tmp/nginxpkg/root/usr/sbin/nginx \
#   NGINX_HOLD="$W/hold" NGINX_HOLD_QUEUE="$W/hold-queue" \
#   RECEIPT_TIMEOUT=2 VERIFY_TIMEOUT=2 PENDING_TTL=10 \
#   ROLLBACK_CONFIRM_TIMEOUT=2 ROLLBACK_RETRY_INTERVAL=2 \
#     bash scripts/local_stack.sh up
#
# 故障手法（确定性）：
#   - HOLD 文件存在时，包装器把 nginx -s reload 暂存并立即回执 ok，
#     即"首次重载回执 ok 但实际未落地"（迟到生效）
#   - SIGSTOP nginx 使握手不可达（无法核实），回退因此不能凭回执结案
#
# 覆盖：
#  场景 1 启用 -> 回退待核实、锁定启用；随后让新证书迟到生效
#        -> 新建握手确认成功，锁定解除
#  场景 2 启用 -> 回退待核实；恢复后 nginx 服务回退后的旧证书
#        -> 新建握手确认旧证书，失败结案
#  场景 3 回退待核实期间下一笔启用被拒（页面版号规则之外的第二道闸）
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${LOCAL_WORK:-/tmp/certops-local}"
WEB="${WEB:-http://127.0.0.1:8080}"
PY="${PYTHON:-python3}"
HOLD="${NGINX_HOLD:-$WORK/hold}"
HOLD_QUEUE="${NGINX_HOLD_QUEUE:-$WORK/hold-queue}"
PIDF="$WORK/run/nginx.pid"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL  $1 ${2:-}"; }

jv()  { "$PY" -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
served_fp() { openssl s_client -connect 127.0.0.1:8443 -servername demo.internal </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
mkcert() { "$PY" "$ROOT/scripts/make_cert.py" --data-dir "$WORK/data" --out-dir "$1" >/dev/null; }
upload() { curl -s -F "cert_file=@$1/chain.pem" -F "key_file=@$1/key.pem" "$WEB/upload" | jv "d['version_id']"; }
post_activate() { curl -s -o /tmp/fault_act.json -w '%{http_code}' \
  -F "version_id=$1" -F "base_version_id=$2" "$WEB/activate"; }
wait_state() { # seq state timeout
  local seq="$1" want="$2" deadline=$(( $(date +%s) + ${3:-40} )) state
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(curl -s "$WEB/api/op/$seq" | jv "d.get('state','')")
    [ "$state" = "$want" ] && return 0
    sleep 0.5
  done
  return 1
}
wait_served_stable() { # 期望指纹 连续命中次数
  local want="$1" times="$2" hits=0
  for _ in $(seq 1 80); do
    if [ "$(served_fp)" = "$want" ]; then
      hits=$((hits + 1))
      [ "$hits" -ge "$times" ] && return 0
    else
      hits=0
    fi
    sleep 0.5
  done
  return 1
}
hold_on()  { : > "$HOLD"; }
hold_off() { rm -f "$HOLD"; }
stop_nginx() { kill -STOP "$(cat "$PIDF")"; pkill -STOP -f "nginx: worker" 2>/dev/null || true; }
cont_nginx() { kill -CONT "$(cat "$PIDF")"; pkill -CONT -f "nginx: worker" 2>/dev/null || true; }
stop_web()   { kill -STOP "$(cat "$WORK/run/web.pid")"; }
cont_web()   { kill -CONT "$(cat "$WORK/run/web.pid")"; }
real_reload() { echo "flush-$1" >> "$WORK/reload/REQUEST"; }

# 前置自检：包装器必须在起栈时已生效
if [ ! -e "$HOLD_QUEUE" ] && [ ! -d "$WORK/reload" ]; then
  echo "前置失败：$WORK 不存在，请按脚本头注释的方式起栈" >&2
  exit 2
fi

echo "=== 场景 1：重载迟到 + 握手不可核实，恢复时新证书迟到生效 -> 确认成功 ==="
V1FP=$(served_fp)
mkcert /tmp/fault-1; V2=$(upload /tmp/fault-1)
V2FP=$(openssl x509 -in /tmp/fault-1/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
hold_on
stop_nginx                                          # 重载被暂存、握手不可达
CODE=$(post_activate "$V2" 1)
ST=$(curl -s "$WEB/api/status")
SEQ=$(echo "$ST" | jv "d['latest_op']['seq']")
STATE=$(echo "$ST" | jv "d['latest_op']['state']")
[ "$STATE" = "rollback_pending" ] && ok "1: 回退不可核实 -> 回退待核实（HTTP $CODE）" \
  || bad "1: 操作状态" "state=$STATE want=rollback_pending"
[ -n "$(echo "$ST" | jv "d['activation_blocked'] or ''")" ] && ok "1: 页面/API 显示启用已锁定" \
  || bad "1: 缺少锁定标记"
[ "$(wc -l < "$HOLD_QUEUE")" -ge 2 ] && ok "1: 首次/回退重载均被暂存（回执 ok 但未落地）" \
  || bad "1: 重载暂存队列" "lines=$(wc -l < "$HOLD_QUEUE")"
# 回退待核实期间下一笔启用必须被拒（场景 3）
mkcert /tmp/fault-1b; V2B=$(upload /tmp/fault-1b)
CODE2=$(post_activate "$V2B" 1)
[ "$CODE2" = "409" ] && ok "3: 回退待核实期间下一笔启用被拒(409)" || bad "3: 启用闸口" "code=$CODE2"
# 冻结 web，防止后台核实循环改写 live；先让 nginx 完成迟到重载并稳定
# 服务新证书，再恢复 web —— 等价于真实事故中新证书由 nginx 侧迟到生效
stop_web
cp /tmp/fault-1/chain.pem "$WORK/live/fullchain.pem"
cp /tmp/fault-1/key.pem  "$WORK/live/privkey.pem"
hold_off
cont_nginx
real_reload "$SEQ"
# 等 nginx 完成迟到重载并连续 4 次新握手稳定返回新证书，再恢复 web
if wait_served_stable "$V2FP" 4; then
  ok "1: nginx 恢复后迟到重载已稳定服务新证书"
else
  bad "1: nginx 迟到重载未稳定" "got=$(served_fp)"
fi
cont_web
if wait_state "$SEQ" succeeded 40; then
  ok "1: 新证书迟到生效，后台经新建 TLS 握手确认 succeeded"
else
  bad "1: 未确认成功" "$(curl -s "$WEB/api/op/$SEQ")"
fi
sleep 1
[ "$(served_fp)" = "$V2FP" ] && ok "1: openssl 实测为新证书" || bad "1: 实测指纹" "got=$(served_fp) want=$V2FP"
ST=$(curl -s "$WEB/api/status")
[ "$(echo "$ST" | jv "d['active_version_id']")" = "$V2" ] && ok "1: 在用版本切换为 #$V2" \
  || bad "1: 在用版本" "$(echo "$ST" | jv "d['active_version_id']")"
[ "$(echo "$ST" | jv "d['activation_blocked'] or ''")" = "" ] && ok "1: 锁定已解除" || bad "1: 锁定未解除"

echo "=== 场景 2：回退待核实后握手确认旧证书 -> 失败结案 ==="
mkcert /tmp/fault-2; V3=$(upload /tmp/fault-2)
BASE=$(curl -s "$WEB/api/status" | jv "d['active_version_id']")
BASEFP=$(served_fp)
: > "$HOLD_QUEUE"
hold_on
stop_nginx
CODE=$(post_activate "$V3" "$BASE")
SEQ2=$(curl -s "$WEB/api/status" | jv "d['latest_op']['seq']")
[ "$(curl -s "$WEB/api/status" | jv "d['latest_op']['state']")" = "rollback_pending" ] \
  && ok "2: 回退待核实已建立（HTTP $CODE）" || bad "2: 状态建立失败" "$(cat /tmp/fault_act.json)"
# live 已被回退写回旧证书：不替换文件，解除拦截并恢复 nginx，重载旧配置
stop_web
hold_off
cont_nginx
real_reload "$SEQ2"
if wait_served_stable "$BASEFP" 4; then
  ok "2: nginx 恢复后稳定服务回退留存的旧证书"
else
  bad "2: nginx 恢复后实测指纹异常" "got=$(served_fp)"
fi
cont_web
if wait_state "$SEQ2" failed 40; then
  ok "2: 新建 TLS 握手确认旧证书在用 -> failed 结案"
else
  bad "2: 未结案" "$(curl -s "$WEB/api/op/$SEQ2")"
fi
sleep 1
[ "$(served_fp)" = "$BASEFP" ] && ok "2: openssl 实测仍为旧证书" || bad "2: 实测指纹" "got=$(served_fp) want=$BASEFP"
DETAIL=$(curl -s "$WEB/api/op/$SEQ2" | jv "d['detail']")
echo "$DETAIL" | grep -q "握手确认" && ok "2: 结案依据写明握手确认" || bad "2: 结案依据" "$DETAIL"
[ "$(curl -s "$WEB/api/status" | jv "d['activation_blocked'] or ''")" = "" ] && ok "2: 结案后锁定解除" \
  || bad "2: 锁定未解除"

echo ""
echo "== fault: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
