#!/bin/sh
# 自测专用 nginx 包装器（仅 local_stack 演练使用，Docker 镜像不包含本文件）。
#
# 行为：当 HOLD 文件存在时，把所有 `nginx -s reload` 调用暂存到 QUEUE 文件并
# 直接返回成功（等价于"重载回执 ok 但重载尚未真正发生"），其余调用原样透传。
# 删除 HOLD 后由外部触发一次 reload，即可让重载按当前磁盘证书落地，
# 用于确定性复现"首次重载迟到生效"。
#
# 环境变量（未设置时完全等价于直接调用真实 nginx）：
#   REAL_NGINX_BIN   真实 nginx 二进制（启用拦截时必填）
#   NGINX_HOLD       HOLD 标记文件路径
#   NGINX_HOLD_QUEUE 暂存队列文件路径
set -u

REAL="${REAL_NGINX_BIN:-}"
HOLD="${NGINX_HOLD:-}"
QUEUE="${NGINX_HOLD_QUEUE:-}"

if [ -n "$HOLD" ] && [ -n "$REAL" ]; then
  case " $* " in
    *" -s reload "*)
      if [ -e "$HOLD" ]; then
        printf '%s\n' "$*" >> "$QUEUE"
        exit 0
      fi
      ;;
  esac
fi
exec "${REAL:-nginx}" "$@"
