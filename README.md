# 单站点 TLS 证书启用管理

机房运维在网页上为内网站点（演示域名 `demo.internal`）替换 TLS 证书。
启用结果以 **Nginx 新建 TLS 连接实际返回的证书指纹** 为唯一判据。

## 架构

```
┌────────────┐   共享卷 certs/live    ┌──────────────────────────┐
│  web       │ ───────────────────▶ │  nginx（站点 :443）       │
│  FastAPI   │   共享卷 reload       │  + reload-watcher.sh     │
│  + SQLite  │ ◀─────────────────── │  （检测 REQUEST →        │
└────────────┘   REQUEST/RESULT 回执 │   nginx -t && -s reload） │
      │ 新建 TLS 连接探测指纹         └──────────────────────────┘
      └──────────────────────────────────────▶
```

- **web**（`web/`）：FastAPI + SQLite。上传校验、启用编排、并发控制、
  重启对账、后台核实循环。管理页 `:8080`。
- **nginx**（`nginx/`）：提供 TLS 站点；旁挂 watcher 脚本按文件令牌执行
  `nginx -t && nginx -s reload`（平滑重载，旧连接自然完成）并写回执。

## 运行

```bash
docker compose up --build
# 管理页  http://localhost:8080
# 站点    https://localhost:8443  （建议 /etc/hosts 加 127.0.0.1 demo.internal）
```

首次启动自动生成演示 CA 与"旧证书"（版本 #1，在用）。
用 `scripts/make_cert.py --data-dir <数据目录> --out-dir /tmp/newcert`
可签发演示新证书用于上传（生产环境上传真实 CA 签发的证书即可）。

无 Docker 时本地验证：`bash scripts/local_stack.sh up`（需 nginx 二进制，
见 `NGINX_BIN` 环境变量）。

## 关键规则实现

| 需求 | 实现 |
| --- | --- |
| 上传校验 | `certutil.validate_upload`：密钥匹配（公钥 DER 对比）、域名（SAN/CN，含单层通配）、有效期、链逐级签发验证 |
| 页面所见版号 | 启用表单携带 `base_version_id`；`BEGIN IMMEDIATE` 事务内比较-交换，不一致即 409「页面版号已过期」 |
| 并发/重复提交 | 同一事务内拒绝已存在 `activating`/`rollback_pending` 操作；重复提交因版号失效被拒；上传按指纹去重 |
| 启用成功判据 | 仅当新建 TLS 连接返回新证书指纹才置 `succeeded`；回执 ok 但握手仍是旧证书时不提前判失败，整个核实窗口持续探测，兼容"重载迟到生效" |
| 回退结案判据 | 文件恢复 + 重载回执**不足以**证明旧版恢复；只有新建 TLS 握手与最终留存证书一致才判 `failed`。确认不了置 `rollback_pending`（回退待核实），页面显示待核实 |
| 回退待核实 | 重启后继续核对：握手为新证书则据实确认成功，为旧证书则失败结案，不可达则仅重试重载、不覆盖磁盘文件（避免抹掉迟到生效的结果）；期间拒绝下一笔启用（409 + 页面按钮锁定） |
| 回执不明/重启 | 操作置 `pending_verify`（页面显示"待核实"）；后台核实循环确认或超时回退；进程重启时按 Nginx 实际服务指纹对账，恢复到可确认的在用版本 |
| 旧操作不覆盖新提交 | 任何落库/写文件前检查 `current_op_seq`；新操作创建时把待核实旧操作置 `superseded` |
| 已有连接 | nginx 平滑重载，旧 worker 服务完旧连接再退出 |

## 验证

```bash
cd web && python3 -m pytest tests/ -q          # 29 项单元/集成测试
bash scripts/local_stack.sh up && python3 scripts/e2e_check.py   # 19 项真实端到端
bash scripts/interrupt_check.sh                # 10 项崩溃/中断恢复实测
# 15 项"迟到重载 + 回退失败/不可核实"事故演练（需重载拦截包装器，见下）
bash scripts/fault_check.sh
```

### 事故演练（迟到生效 + 回退待核实）

`scripts/nginx-hold-wrapper.sh` 是仅用于本地演练的 nginx 包装器：`NGINX_HOLD`
标记存在时把 `nginx -s reload` 暂存并回执 ok（模拟"重载迟到"），配合 SIGSTOP
制造握手不可达。`scripts/fault_check.sh` 用它确定性复现：

1. 首次重载与回退重载均未落地、期间无法握手 → 操作置**回退待核实**、启用入口锁定；
2. nginx 恢复后新证书迟到生效 → 后台以新建握手确认 `succeeded`，锁定解除；
3. 恢复后仍服务旧证书 → 新建握手确认回退，`failed` 结案；
4. 回退待核实期间的下一笔启用一律 409 拒绝。

具体起栈命令见 `fault_check.sh` 文件头注释。Docker 镜像不包含该包装器与故障
注入逻辑（`nginx/reload-watcher.sh` 中的 `FAULT_*` 标记在生产目录留空即完全
不生效，且 watcher 启动时会清除遗留标记）。

## 说明与限制

- 单实例管理进程（SQLite + 进程内锁），不适用于多副本部署。
- 演示用 CA 私钥存于数据目录 `ca/`，仅为签发演示证书；生产应上传外部签发证书。
- nginx 与 web 之间经共享卷文件通信，回执超时（默认 6s）即视为"回执不明"。
- 回退待核实（`rollback_pending`）是一种有意保留的未决状态：只有新建 TLS 握手
  能给出终态，在此之前系统会拒绝新的启用请求并持续核对，重启也不例外。
