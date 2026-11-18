"""证书启用核心逻辑。

设计要点：
- 启用请求带"页面所见版号"(base_version_id)，在 BEGIN IMMEDIATE 事务内
  比较-交换，过期提交与并发重复提交直接拒绝，不会覆盖在用证书。
- 启用成功以"Nginx 新建 TLS 连接返回新证书指纹"为唯一判据；
  重载回执 ok 但握手仍是旧证书时不提前判失败——重载可能迟到生效，
  操作置"待核实"由后台循环继续核实，迟到生效后据实确认成功。
- 回退（回滚）同样以新建 TLS 握手为唯一判据：文件恢复 + 重载回执
  不足以证明旧版恢复；握手确认旧证书仍在用才判失败，
  确认不了置"回退待核实"(rollback_pending)，重启后继续核对。
- 回退待核实期间拒绝下一笔启用，避免未完成的回退覆盖新结果。
- 任何落库/写文件动作前都检查"自己是否仍是最新操作"，
  旧操作不得覆盖后来提交。
- 进程重启时按 Nginx 实际服务的指纹对账，恢复到可确认的在用版本。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass

from . import certutil
from .db import DB

log = logging.getLogger("certops")

UTC = dt.timezone.utc


def now_iso() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


class Conflict(Exception):
    """409：版号过期或已有操作在进行。"""


class BadRequest(Exception):
    """400：请求内容不合法。"""


class NotFound(Exception):
    """404：目标不存在。"""


class ProbeError(Exception):
    """无法与 Nginx 建立 TLS 连接。"""


@dataclass
class Config:
    site_domain: str = "demo.internal"
    data_dir: str = "/data"
    live_dir: str = "/certs/live"
    reload_dir: str = "/reload"
    probe_host: str = "nginx"
    probe_port: int = 443
    receipt_timeout: float = 6.0      # 等待重载回执的秒数
    verify_timeout: float = 10.0      # 启用后探测新证书的秒数
    pending_ttl: float = 45.0         # 待核实操作的宽限秒数，超时发起回退
    probe_interval: float = 0.5
    startup_probe_timeout: float = 15.0
    restore_interval: float = 30.0    # 无在途操作时一致性修复的最小间隔
    rollback_confirm_timeout: float = 6.0   # 回退后等握手确认的秒数
    rollback_retry_interval: float = 5.0    # 回退待核实期间重试重载的最小间隔
    activate_delay_after_write: float = 0.0  # 测试钩子：写完文件后人为延迟

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "certops.db")

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ
        return cls(
            site_domain=e.get("SITE_DOMAIN", "demo.internal"),
            data_dir=e.get("DATA_DIR", "/data"),
            live_dir=e.get("LIVE_DIR", "/certs/live"),
            reload_dir=e.get("RELOAD_DIR", "/reload"),
            probe_host=e.get("NGINX_PROBE_HOST", "nginx"),
            probe_port=int(e.get("NGINX_PROBE_PORT", "443")),
            receipt_timeout=float(e.get("RECEIPT_TIMEOUT", "6")),
            verify_timeout=float(e.get("VERIFY_TIMEOUT", "10")),
            pending_ttl=float(e.get("PENDING_TTL", "45")),
            startup_probe_timeout=float(e.get("STARTUP_PROBE_TIMEOUT", "15")),
            rollback_confirm_timeout=float(e.get("ROLLBACK_CONFIRM_TIMEOUT", "6")),
            rollback_retry_interval=float(e.get("ROLLBACK_RETRY_INTERVAL", "5")),
            activate_delay_after_write=float(e.get("ACTIVATE_DELAY_AFTER_WRITE", "0")),
        )


def tls_fingerprint(host: str, port: int, server_name: str, timeout: float = 3.0) -> str:
    """新建一条 TLS 连接，返回对端叶子证书的 SHA-256 指纹。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except OSError as exc:
        raise ProbeError(str(exc)) from exc
    return hashlib.sha256(der).hexdigest()


class FileReloadChannel:
    """经共享目录与 nginx 侧 watcher 通信：REQUEST 追加令牌，RESULT 回收回执。"""

    def __init__(self, reload_dir: str):
        self.req_path = os.path.join(reload_dir, "REQUEST")
        self.res_path = os.path.join(reload_dir, "RESULT")

    def request(self, token: str) -> None:
        with open(self.req_path, "a", encoding="utf-8") as f:
            f.write(f"{token} {now_iso()}\n")
            f.flush()
            os.fsync(f.fileno())

    def wait(self, token: str, timeout: float) -> str | None:
        """等到 'ok' / 'fail ...'；超时返回 None（回执不明）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(self.res_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(" ", 1)
                        if len(parts) == 2 and parts[0] == token:
                            return parts[1]
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        return None


class RealControl:
    """生产用 Nginx 控制面：文件通道触发平滑重载 + 真实 TLS 探测。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.channel = FileReloadChannel(cfg.reload_dir)

    def probe(self) -> str:
        return tls_fingerprint(
            self.cfg.probe_host, self.cfg.probe_port, self.cfg.site_domain
        )

    def request_reload(self, token: str) -> None:
        self.channel.request(token)

    def wait_receipt(self, token: str, timeout: float) -> str | None:
        return self.channel.wait(token, timeout)


class CertService:
    def __init__(self, cfg: Config, control=None):
        self.cfg = cfg
        for d in (cfg.data_dir, cfg.live_dir, cfg.reload_dir):
            os.makedirs(d, exist_ok=True)
        self.db = DB(cfg.db_path)
        self.control = control or RealControl(cfg)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._probe_cache: tuple[float, str | None] = (0.0, None)
        self._last_restore = 0.0
        self._last_rollback_retry = 0.0

    # ------------------------------------------------------------ 生命周期

    def startup(self, background: bool = True) -> None:
        self.db.init_schema()
        with self.db.txn() as c:
            empty = c.execute("SELECT COUNT(*) n FROM versions").fetchone()["n"] == 0
        if empty:
            self._seed()
        # 上次进程退出时遗留的"启用中"操作一律转为待核实
        with self.db.txn() as c:
            c.execute(
                "UPDATE ops SET state='pending_verify',"
                " detail='进程重启，启用结果待核实', updated_at=?"
                " WHERE state='activating'",
                (now_iso(),),
            )
        served = self._probe_with_grace(self.cfg.startup_probe_timeout)
        with self.db.txn() as c:
            op = self._latest_inflight(c)
        if op:
            if op["state"] == "rollback_pending":
                # 重启只重新断言一次回退（写回在用版本 + 触发重载），不凭单次
                # 探测结案：迟到重载可能在启动瞬间才落地，终态交给后台
                # 核实循环的"新建 TLS 握手"给出。
                self._resume_rollback_pending(op)
            else:
                target = self._version(op["version_id"])
                if served is not None and served == target["fingerprint"]:
                    self._finalize_success(op["seq"], note="重启后核实：新证书已生效")
                elif served is not None:
                    self._recover_to_confirmable(served)
                    self._finalize_fail(
                        op["seq"],
                        "进程重启，启用结果未确认，回退后经新建 TLS 握手确认旧证书在用",
                    )
                else:
                    log.warning("startup: 无法探测 Nginx，操作 #%s 保持待核实", op["seq"])
        else:
            self._ensure_live_matches_active(served)
        if background:
            self._thread = threading.Thread(
                target=self._reconcile_loop, name="reconciler", daemon=True
            )
            self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.db.close()

    def _seed(self) -> None:
        """首次启动：生成演示 CA 与"旧证书"，作为版本 1 在用。"""
        ca_cert, ca_key = certutil.generate_ca()
        chain, key = certutil.generate_server_cert(
            self.cfg.site_domain, ca_cert, ca_key,
            days_valid=330, not_before_days_ago=300,
        )
        info = certutil.validate_upload(chain, key, self.cfg.site_domain)
        ca_dir = os.path.join(self.cfg.data_dir, "ca")
        os.makedirs(ca_dir, exist_ok=True)
        with open(os.path.join(ca_dir, "ca.pem"), "wb") as f:
            f.write(ca_cert)
        with open(os.path.join(ca_dir, "ca-key.pem"), "wb") as f:
            f.write(ca_key)
        with self.db.txn() as c:
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain.decode(), key.decode(),
                    "active", now_iso(),
                ),
            )
            vid = cur.lastrowid
            c.execute("UPDATE state SET active_version_id=?", (vid,))
        self._write_live(self._version(vid))
        log.info("seeded demo cert version #%s fp=%s", vid, info.fingerprint[:16])

    # ------------------------------------------------------------ 上传

    def upload(self, chain_pem: bytes, key_pem: bytes):
        info = certutil.validate_upload(chain_pem, key_pem, self.cfg.site_domain)
        with self.db.txn() as c:
            row = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (info.fingerprint,)
            ).fetchone()
            if row:
                return dict(row), False
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain_pem.decode(), key_pem.decode(),
                    "candidate", now_iso(),
                ),
            )
            vid = cur.lastrowid
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row), True

    # ------------------------------------------------------------ 启用

    def activate(self, version_id: int, base_version_id: int) -> dict:
        """提交启用。比较-交换通过后在请求线程内同步执行，结果有界。"""
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["active_version_id"] != base_version_id:
                raise Conflict(
                    f"页面版号已过期（当前在用版本 #{st['active_version_id']}），"
                    "请刷新后重试"
                )
            blocked = c.execute(
                "SELECT seq, state FROM ops"
                " WHERE state IN ('activating','rollback_pending')"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if blocked:
                if blocked["state"] == "rollback_pending":
                    raise Conflict(
                        f"上一笔操作 (#{blocked['seq']}) 的回退仍待核实，"
                        "请等系统确认旧证书恢复后再启用，避免未完成的回退覆盖新结果"
                    )
                raise Conflict(
                    f"另一启用操作 (#{blocked['seq']}) 正在进行，请稍后"
                )
            v = c.execute("SELECT * FROM versions WHERE id=?", (version_id,)).fetchone()
            if not v:
                raise NotFound(f"版本 #{version_id} 不存在")
            if v["id"] == st["active_version_id"]:
                raise BadRequest(f"版本 #{version_id} 当前已在用")
            if v["status"] not in ("candidate", "failed", "superseded"):
                raise BadRequest(f"版本 #{version_id} 状态为 {v['status']}，不可启用")
            # 新操作取代所有仍待核实的旧操作
            c.execute(
                "UPDATE ops SET state='superseded',"
                " detail=COALESCE(detail,'') || ' 被更新的操作取代', updated_at=?"
                " WHERE state='pending_verify'",
                (now_iso(),),
            )
            seq = st["current_op_seq"] + 1
            ts = now_iso()
            c.execute(
                "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (seq, version_id, base_version_id, "activating", None, ts, ts),
            )
            c.execute("UPDATE state SET current_op_seq=?", (seq,))
        try:
            self._execute(seq)
        except Exception as exc:  # 任何未预期异常都不得让操作悬空
            log.exception("activate op #%s failed unexpectedly", seq)
            self._mark_pending(seq, f"内部错误（{exc!r}），待核实")
        return self.get_op(seq)

    def _execute(self, seq: int) -> None:
        op = self.get_op(seq)
        target = self._version(op["version_id"])
        base = self._version(op["base_version_id"])
        # 1. 落盘新证书文件（原子替换）
        self._write_live(target)
        if self.cfg.activate_delay_after_write:  # 测试钩子：制造崩溃窗口
            time.sleep(self.cfg.activate_delay_after_write)
        # 2. 请求 Nginx 平滑重载并等回执
        token = f"{seq}-{uuid.uuid4().hex[:8]}"
        self.control.request_reload(token)
        receipt = self.control.wait_receipt(token, self.cfg.receipt_timeout)
        # 3. 以新建 TLS 连接的实际握手结果为准。
        #    即使回执已返回 ok，也可能重载迟到生效（握手暂时仍是旧证书），
        #    因此整个核实窗口内持续探测，不凭回执提前判失败。
        served = None
        deadline = time.monotonic() + self.cfg.verify_timeout
        while time.monotonic() < deadline:
            try:
                served = self.control.probe()
            except ProbeError:
                served = None
            if served == target["fingerprint"]:
                break
            time.sleep(self.cfg.probe_interval)
        # 4. 判定
        if served == target["fingerprint"]:
            self._finalize_success(seq, note="新 TLS 连接已返回新证书")
            return
        # 握手未确认新证书：无论回执 ok/fail/超时，先回退文件并尝试回退重载。
        # 回退是否成立同样只能由"新建 TLS 握手 == 旧证书"确认。
        reason = self._activation_miss_reason(receipt, served)
        self._request_rollback(seq, base)
        if self._confirm_rollback(base["fingerprint"], self.cfg.rollback_confirm_timeout):
            self._finalize_fail(
                seq, f"{reason}；已回退，且新建 TLS 握手确认旧证书仍在用"
            )
            return
        # 回退未经握手确认（回执失败/超时、或握手仍是新证书——可能迟到生效）
        self._mark_rollback_pending(seq, f"{reason}；回退已发起但未经新握手确认，待核实")

    @staticmethod
    def _activation_miss_reason(receipt: str | None, served: str | None) -> str:
        if receipt is None:
            return "重载回执超时"
        if receipt.startswith("fail"):
            return f"Nginx 重载失败（{receipt}）"
        if served is None:
            return "重载后无法建立新连接核实"
        return "重载后新连接仍返回旧证书（可能延迟生效）"

    def _request_rollback(self, seq: int, base: dict) -> str:
        """把 live 文件恢复为旧版本并触发一次回退重载，返回回执（可能为 None）。"""
        self._write_live(base)
        token = f"rollback-{seq}-{uuid.uuid4().hex[:8]}"
        self.control.request_reload(token)
        return self.control.wait_receipt(token, self.cfg.receipt_timeout) or ""

    def _confirm_rollback(self, expected_fp: str, timeout: float) -> bool:
        """在 timeout 窗口内反复新建 TLS 连接；握手指纹与留存旧证书一致才确认。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                served = self.control.probe()
            except ProbeError:
                served = None
            if served == expected_fp:
                return True
            time.sleep(min(self.cfg.probe_interval, timeout))
        return False

    # ------------------------------------------------------------ 终态落库

    def _invalidate_probe(self) -> None:
        self._probe_cache = (0.0, None)

    def _finalize_success(self, seq: int, note: str = "") -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in (
                "activating", "pending_verify", "rollback_pending"
            ):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute("UPDATE versions SET status='superseded' WHERE status='active'")
            c.execute(
                "UPDATE versions SET status='active' WHERE id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE state SET active_version_id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE ops SET state='succeeded', detail=?, updated_at=? WHERE seq=?",
                (note or "启用成功", now_iso(), seq),
            )
        self._invalidate_probe()

    def _finalize_fail(self, seq: int, reason: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in (
                "activating", "pending_verify", "rollback_pending"
            ):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='failed', detail=?, updated_at=? WHERE seq=?",
                (reason, now_iso(), seq),
            )
            c.execute(
                "UPDATE versions SET status='failed' WHERE id=? AND status!='active'",
                (op["version_id"],),
            )
        self._invalidate_probe()

    def _mark_pending(self, seq: int, detail: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] != "activating":
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='pending_verify', detail=?, updated_at=?"
                " WHERE seq=?",
                (detail, now_iso(), seq),
            )

    def _mark_rollback_pending(self, seq: int, detail: str) -> None:
        """回退已发起但未经新握手确认：置回退待核实，禁止下一笔启用。"""
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='rollback_pending', detail=?, updated_at=?"
                " WHERE seq=?",
                (detail, now_iso(), seq),
            )
        self._invalidate_probe()

    # ------------------------------------------------------------ 后台核实

    def _reconcile_loop(self) -> None:
        while not self._stop.wait(2.0):
            try:
                self.reconcile_once()
            except Exception:
                log.exception("reconcile tick failed")

    def reconcile_once(self) -> None:
        with self.db.txn() as c:
            activating = c.execute(
                "SELECT COUNT(*) n FROM ops WHERE state='activating'"
            ).fetchone()["n"]
            if activating:
                return  # 前台请求线程 owns 启用中的操作
            rollback_op = c.execute(
                "SELECT * FROM ops WHERE state='rollback_pending'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            op = c.execute(
                "SELECT * FROM ops WHERE state='pending_verify'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        if rollback_op:
            self._handle_rollback_pending(rollback_op, st)
            return
        if op:
            if st["current_op_seq"] != op["seq"]:
                with self.db.txn() as c:
                    c.execute(
                        "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                        " WHERE seq=?",
                        ("已有更新的操作，本操作结果作废", now_iso(), op["seq"]),
                    )
                return
            target = self._version(op["version_id"])
            try:
                served = self.control.probe()
            except ProbeError:
                return  # 无法确认，保持待核实
            if served == target["fingerprint"]:
                self._finalize_success(op["seq"], note="后台核实：新证书已生效")
                return
            created = dt.datetime.fromisoformat(op["created_at"])
            age = (dt.datetime.now(UTC) - created).total_seconds()
            if age > self.cfg.pending_ttl:
                # 宽限期满仍未确认新证书：发起回退。回退结果仍须握手确认，
                # 确认不了转入"回退待核实"并继续核对，绝不凭回执结案。
                active = self._version(st["active_version_id"])
                self._request_rollback(op["seq"], active)
                if self._confirm_rollback(
                    active["fingerprint"], self.cfg.rollback_confirm_timeout
                ):
                    self._finalize_fail(
                        op["seq"],
                        "超过待核实时限仍未生效；已回退，且新建 TLS 握手确认旧证书在用",
                    )
                else:
                    self._mark_rollback_pending(
                        op["seq"], "回退已发起但未经新握手确认，待核实"
                    )
            return
        # 无在途操作：保持"文件/实测/在用"三者一致（限流）
        if time.monotonic() - self._last_restore < self.cfg.restore_interval:
            return
        try:
            served = self.control.probe()
        except ProbeError:
            return
        active = self._version(st["active_version_id"])
        if active and served != active["fingerprint"]:
            self._last_restore = time.monotonic()
            self._ensure_live_matches_active(served)

    def _handle_rollback_pending(self, op: dict, st) -> None:
        """回退待核实：重启/后台继续核对，直到新握手确认结果为止。"""
        if st["current_op_seq"] != op["seq"]:
            with self.db.txn() as c:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), op["seq"]),
                )
            return
        target = self._version(op["version_id"])
        base = self._version(st["active_version_id"])
        try:
            served = self.control.probe()
        except ProbeError:
            # 无法握手 = 无法确认：保持回退待核实。只请求一次（节流的）重载，
            # 绝不重写 live 文件——在无法证伪之前，覆盖磁盘证书可能抹掉
            # 已经迟到生效的新结果。
            self._retry_rollback_reload(base, rewrite=False)
            return
        if served == target["fingerprint"]:
            # 新证书迟到生效：据实确认启用成功（即使回退重载曾失败）
            self._finalize_success(op["seq"], note="后台核实：新证书迟到生效")
            return
        if served == base["fingerprint"]:
            # 新建 TLS 握手与最终留存的旧证书一致：回退确认，结案
            self._finalize_fail(
                op["seq"], "回退后经新建 TLS 握手确认旧证书仍在用，启用失败结案"
            )
            return
        # 握手结果既不是新证书也不是在用旧证书：重新断言回退（节流）
        self._retry_rollback_reload(base, rewrite=True)

    def _retry_rollback_reload(self, base: dict | None, rewrite: bool) -> None:
        """回退待核实期间按节流重试。

        rewrite=True（握手得到第三种不明指纹）：重写 live 为旧版本并请求重载；
        rewrite=False（无法握手）：仅请求重载，不改动 live，避免抹掉迟到生效的结果。
        """
        if not base:
            return
        if time.monotonic() - self._last_rollback_retry < self.cfg.rollback_retry_interval:
            return
        self._last_rollback_retry = time.monotonic()
        if rewrite:
            self._write_live(base)
        self.control.request_reload(f"rollback-retry-{uuid.uuid4().hex[:8]}")
        self._invalidate_probe()

    def _resume_rollback_pending(self, op: dict) -> None:
        """进程重启后恢复回退待核实操作：先按在用版本断言一次回退重载。

        只断言一次且不凭单次探测结案；若重载迟到使新证书随后生效，
        后台核实循环的新建握手会据实确认成功。
        """
        with self.db.txn() as c:
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if active:
            self._write_live(dict(active))
            self.control.request_reload(f"rollback-resume-{uuid.uuid4().hex[:8]}")
            self._invalidate_probe()
        self._last_rollback_retry = time.monotonic()

    # ------------------------------------------------------------ 恢复辅助

    def _recover_to_confirmable(self, served: str) -> None:
        """按 Nginx 实际服务的指纹，把在用版本恢复到可确认的版本。"""
        with self.db.txn() as c:
            known = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (served,)
            ).fetchone()
            if known and known["status"] != "active":
                c.execute(
                    "UPDATE versions SET status='superseded' WHERE status='active'"
                )
                c.execute(
                    "UPDATE versions SET status='active' WHERE id=?", (known["id"],)
                )
                c.execute("UPDATE state SET active_version_id=?", (known["id"],))
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if active:
            self._write_live(dict(active))
            self.control.request_reload(f"recover-{uuid.uuid4().hex[:8]}")
            self._invalidate_probe()

    def _ensure_live_matches_active(self, served: str | None) -> None:
        with self.db.txn() as c:
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if not active:
            return
        live_fp = self.live_fingerprint()
        if live_fp != active["fingerprint"]:
            log.warning("live 文件与在用版本不一致，恢复为版本 #%s", active["id"])
            self._write_live(dict(active))
            self.control.request_reload(f"restore-{uuid.uuid4().hex[:8]}")
        elif served is not None and served != active["fingerprint"]:
            log.warning("Nginx 服务指纹与在用版本不一致，重新触发重载")
            self.control.request_reload(f"restore-{uuid.uuid4().hex[:8]}")

    # ------------------------------------------------------------ 查询

    def get_op(self, seq: int) -> dict:
        with self.db.txn() as c:
            row = self._op(c, seq)
            if not row:
                raise NotFound(f"操作 #{seq} 不存在")
            return dict(row)

    def status(self, probe: bool = True) -> dict:
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            versions = [
                dict(r)
                for r in c.execute(
                    "SELECT id, fingerprint, domain, subject, san, not_before,"
                    " not_after, status, created_at FROM versions ORDER BY id"
                ).fetchall()
            ]
            ops = [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM ops ORDER BY seq DESC LIMIT 10"
                ).fetchall()
            ]
            blocker = c.execute(
                "SELECT seq, state, detail FROM ops"
                " WHERE state IN ('activating','rollback_pending')"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        active = next(
            (v for v in versions if v["id"] == st["active_version_id"]), None
        )
        served = self.probe_cached() if probe else None
        if served is None:
            consistency = "unknown"
        elif active and served == active["fingerprint"]:
            consistency = "match"
        else:
            consistency = "mismatch"
        return {
            "domain": self.cfg.site_domain,
            "served_fingerprint": served,
            "consistency": consistency,
            "active_version_id": st["active_version_id"],
            "current_op_seq": st["current_op_seq"],
            "activation_blocked": dict(blocker) if blocker else None,
            "active": active,
            "versions": versions,
            "ops": ops,
            "latest_op": ops[0] if ops else None,
        }

    def probe_cached(self, ttl: float = 2.0) -> str | None:
        ts, val = self._probe_cache
        if time.monotonic() - ts < ttl:
            return val
        try:
            val = self.control.probe()
        except ProbeError:
            val = None
        self._probe_cache = (time.monotonic(), val)
        return val

    def live_fingerprint(self) -> str | None:
        try:
            with open(os.path.join(self.cfg.live_dir, "fullchain.pem"), "rb") as f:
                return certutil.fingerprint_pem_chain(f.read())
        except (OSError, certutil.CertError):
            return None

    # ------------------------------------------------------------ 内部

    def _version(self, vid: int) -> dict | None:
        if vid is None:
            return None
        with self.db.txn() as c:
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def _op(c, seq: int):
        return c.execute("SELECT * FROM ops WHERE seq=?", (seq,)).fetchone()

    @staticmethod
    def _latest_inflight(c):
        return c.execute(
            "SELECT * FROM ops WHERE state IN "
            "('activating','pending_verify','rollback_pending')"
            " ORDER BY seq DESC LIMIT 1"
        ).fetchone()

    def _write_live(self, version: dict) -> None:
        """原子写入 live 证书文件（先写临时文件再 rename）。"""
        for name, content in (
            ("fullchain.pem", version["cert_pem"]),
            ("privkey.pem", version["key_pem"]),
        ):
            tmp = os.path.join(self.cfg.live_dir, f".{name}.tmp")
            dst = os.path.join(self.cfg.live_dir, name)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dst)

    def _probe_with_grace(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.control.probe()
            except ProbeError:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(0.5)
