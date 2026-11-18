"""单元/集成测试：证书校验、并发控制、回退核实、待核实与重启恢复。

FakeControl 模拟 nginx 行为，支持：
- receipt_mode: ok | fail | timeout（重载回执）
- delayed: 重载效果（served 切换）延迟到 pump() 才落地，模拟"迟到生效"
- fail_prefixes: 令牌前缀命中的重载直接回执 fail 且不切换 served，
  模拟"回退重载失败"
- probe_error: 探测不可用（模拟 nginx 宕机/无法握手）
"""
from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import certutil
from app.certutil import CertError
from app.service import BadRequest, CertService, Config, Conflict, ProbeError

DOMAIN = "demo.internal"


class FakeControl:
    """行为接近真实 nginx：reload 后服务 live 目录中的证书（可延迟/失败）。"""

    def __init__(self, service: CertService):
        self.service = service
        self.receipt_mode = "ok"   # ok | fail | timeout
        self.served: str | None = None
        self.reload_count = 0
        self.probe_error = False
        self.delayed = False
        self.queued: list[tuple[str, str]] = []
        self.fail_prefixes: tuple[str, ...] = ()
        self.receipts: dict[str, str] = {}

    def _live_fp(self):
        return self.service.live_fingerprint()

    def probe(self) -> str:
        if self.probe_error:
            raise ProbeError("fake probe error")
        if self.served is None:
            raise ProbeError("nothing served yet")
        return self.served

    def request_reload(self, token: str) -> None:
        self.reload_count += 1
        fp = self._live_fp()
        if any(token.startswith(p) for p in self.fail_prefixes):
            self.receipts[token] = "fail test: simulated reload failure"
            return  # 回退重载失败：served 保持不变
        self.receipts[token] = (
            "ok" if self.receipt_mode != "fail" else "fail test: simulated reload failure"
        )
        if self.delayed:
            self.queued.append((token, fp))
        elif self.receipts[token] == "ok":
            self.served = fp

    def pump(self) -> None:
        """让所有延迟重载落地（nginx 迟到生效）。"""
        for token, fp in self.queued:
            if self.receipts.get(token) == "ok":
                self.served = fp
        self.queued.clear()

    def wait_receipt(self, token: str, timeout: float):
        if self.receipt_mode == "timeout":
            return None  # 回执通道卡死：令牌已落盘但结果不可见
        return self.receipts.get(token)


@pytest.fixture()
def cfg(tmp_path):
    return Config(
        site_domain=DOMAIN,
        data_dir=str(tmp_path / "data"),
        live_dir=str(tmp_path / "live"),
        reload_dir=str(tmp_path / "reload"),
        receipt_timeout=0.2,
        verify_timeout=0.6,
        pending_ttl=0.5,
        probe_interval=0.05,
        startup_probe_timeout=0.5,
        restore_interval=0.1,
        rollback_confirm_timeout=0.8,
        rollback_retry_interval=0.1,
    )


@pytest.fixture()
def service(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    yield svc
    svc.shutdown()


def make_cert(service, days_valid=365, not_before_days_ago=0, domain=DOMAIN):
    with open(f"{service.cfg.data_dir}/ca/ca.pem", "rb") as f:
        ca_cert = f.read()
    with open(f"{service.cfg.data_dir}/ca/ca-key.pem", "rb") as f:
        ca_key = f.read()
    return certutil.generate_server_cert(
        domain, ca_cert, ca_key,
        days_valid=days_valid, not_before_days_ago=not_before_days_ago,
    )


def upload_new(service, **kw):
    chain, key = make_cert(service, **kw)
    return service.upload(chain, key)[0]


def insert_pending_op(service, version_id: int, base_version_id: int = 1) -> int:
    """模拟进程崩溃遗留的 pending_verify 操作。"""
    with service.db.txn() as c:
        st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        seq = st["current_op_seq"] + 1
        ts = certutil.dt.datetime.now(certutil.dt.timezone.utc).isoformat()
        c.execute(
            "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (seq, version_id, base_version_id, "pending_verify", "崩溃遗留，待核实", ts, ts),
        )
        c.execute("UPDATE state SET current_op_seq=?", (seq,))
    return seq


# ---------------------------------------------------------------- 证书校验


def test_validate_ok(service):
    chain, key = make_cert(service)
    info = certutil.validate_upload(chain, key, DOMAIN)
    assert len(info.fingerprint) == 64


def test_validate_key_mismatch(service):
    chain, _ = make_cert(service)
    _, other_key = make_cert(service)
    with pytest.raises(CertError, match="不匹配"):
        certutil.validate_upload(chain, other_key, DOMAIN)


def test_validate_wrong_domain(service):
    chain, key = make_cert(service, domain="other.internal")
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_expired(service):
    chain, key = make_cert(service, days_valid=-1, not_before_days_ago=10)
    with pytest.raises(CertError, match="已过期"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_not_yet_valid(service):
    chain, key = make_cert(service, days_valid=365, not_before_days_ago=-5)
    with pytest.raises(CertError, match="尚未生效"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_broken_chain(service):
    chain, key = make_cert(service)
    leaf = chain.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    other_ca, _ = certutil.generate_ca("Other CA")
    with pytest.raises(CertError, match="证书链"):
        certutil.validate_upload(leaf + other_ca, key, DOMAIN)


def test_validate_encrypted_key(service):
    chain, _ = make_cert(service)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    with pytest.raises(CertError, match="加密"):
        certutil.validate_upload(chain, enc_key, DOMAIN)


def test_validate_self_signed_ok(service):
    ca, key = certutil.generate_ca("self-signed.demo.internal")
    # 自签名 CA 的 CN 不含站点域名，应被域名检查拒绝
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(ca, key, DOMAIN)


def test_wildcard_match():
    assert certutil.dns_name_matches("*.example.com", "a.example.com")
    assert not certutil.dns_name_matches("*.example.com", "a.b.example.com")
    assert not certutil.dns_name_matches("*.example.com", "example.com")
    assert certutil.dns_name_matches("example.com", "EXAMPLE.com")


# ---------------------------------------------------------------- 上传


def test_upload_and_duplicate(service):
    chain, key = make_cert(service)
    v1, created1 = service.upload(chain, key)
    v2, created2 = service.upload(chain, key)
    assert created1 and not created2
    assert v1["id"] == v2["id"]
    assert v1["status"] == "candidate"


# ---------------------------------------------------------------- 启用流程


def test_activate_happy_path(service):
    v2 = upload_new(service)
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "succeeded"
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.control.served == v2["fingerprint"]
    assert service.live_fingerprint() == v2["fingerprint"]
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[1] == "superseded"
    assert versions[v2["id"]] == "active"
    assert st["activation_blocked"] is None


def test_activate_stale_base_rejected(service):
    v2 = upload_new(service)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=999)
    st = service.status(probe=False)
    assert st["active_version_id"] == 1


def test_activate_already_active(service):
    with pytest.raises(BadRequest):
        service.activate(1, base_version_id=1)


def test_concurrent_activate_only_one_wins(service):
    v2 = upload_new(service)
    results, errors = [], []

    def worker():
        try:
            results.append(service.activate(v2["id"], base_version_id=1))
        except Conflict as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"应有且仅有一个提交成功: {results} {errors}"
    assert results[0]["state"] == "succeeded"
    assert len(errors) == 7
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert len(st["ops"]) == 1  # 只登记了一个操作


def test_duplicate_submit_after_success_rejected(service):
    v2 = upload_new(service)
    service.activate(v2["id"], base_version_id=1)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=1)  # 重复提交同一表单


def test_reload_failure_rolls_back_and_handshake_confirms(service):
    """重载失败 -> 回退；只有新握手确认旧证书在用才判 failed。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp  # nginx 当前服务旧证书
    service.control.receipt_mode = "fail"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "failed"
    assert "重载失败" in op["detail"]
    assert "握手确认" in op["detail"]
    st = service.status(probe=False)
    assert st["active_version_id"] == 1
    assert st["activation_blocked"] is None
    # 文件已回滚，nginx 仍服务旧证书（握手已核实）
    assert service.live_fingerprint() == old_fp
    assert service.control.served == old_fp
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[v2["id"]] == "failed"


def test_receipt_ok_but_handshake_old_then_rollback_confirmed(service):
    """回执 ok 但核实窗口内握手一直是旧证书：回退并经握手确认后判失败。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp
    service.control.receipt_mode = "ok"
    service.control.delayed = True  # 回执已 ok，但重载效果迟迟不落地
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "failed"
    assert "延迟生效" in op["detail"] or "仍返回旧证书" in op["detail"]
    assert "握手确认" in op["detail"]
    assert service.control.served == old_fp
    assert service.live_fingerprint() == old_fp


def test_late_reload_with_failed_rollback_eventually_succeeds(service):
    """事故场景复现：首次重载迟到生效，回退重载失败，核实不可用。

    期望：启用不被判失败，而是 rollback_pending（回退待核实），
    禁止下一笔启用；迟到重载落地后，后台按新握手据实确认成功。
    """
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp
    service.control.delayed = True                 # R1 效果延迟落地
    service.control.fail_prefixes = ("rollback",)  # 回退重载 R2 失败
    service.control.probe_error = True             # 期间无法握手核实
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    st = service.status(probe=False)
    assert st["active_version_id"] == 1            # 未误报切换
    assert st["activation_blocked"] is not None
    assert st["activation_blocked"]["state"] == "rollback_pending"
    # 回退待核实期间拒绝下一笔启用
    v3 = upload_new(service)
    with pytest.raises(Conflict, match="回退仍待核实"):
        service.activate(v3["id"], base_version_id=1)
    # nginx 恢复：迟到重载落地，客户端新建连接拿到新证书
    service.control.probe_error = False
    service.control.pump()
    assert service.control.served == v2["fingerprint"]
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.get_op(op["seq"])["state"] == "succeeded"
    assert st["activation_blocked"] is None


def test_rollback_pending_confirmed_old_closes_as_failed(service):
    """回退待核实后，新握手确认旧证书在用 -> failed 结案。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp
    service.control.receipt_mode = "fail"     # R1 本身失败，新证书从未生效
    service.control.fail_prefixes = ("rollback",)
    service.control.probe_error = True
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    # nginx 恢复，仍服务旧证书
    service.control.probe_error = False
    service.reconcile_once()
    op = service.get_op(op["seq"])
    assert op["state"] == "failed"
    assert "握手确认旧证书" in op["detail"]
    assert service.status(probe=False)["active_version_id"] == 1


def test_rollback_pending_retries_on_unknown_served(service):
    """握手结果既非新也非旧：回退待核实保持，按节流重新断言回退。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.fail_prefixes = ("rollback",)
    service.control.probe_error = True
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    service.control.probe_error = False
    service.control.served = "f" * 64  # 不明证书
    before = service.control.reload_count
    service.reconcile_once()
    assert service.get_op(op["seq"])["state"] == "rollback_pending"
    assert service.control.reload_count > before  # 触发了回退重试重载
    assert service.live_fingerprint() == old_fp
    # 收敛到旧证书后结案
    service.control.served = old_fp
    service.reconcile_once()
    assert service.get_op(op["seq"])["state"] == "failed"


def test_receipt_timeout_then_late_reload_confirmed(service):
    """回执超时、迟到生效且回退重载失败：先回退待核实，后台按新握手确认成功。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp
    service.control.receipt_mode = "timeout"   # R1 回执不可见
    service.control.delayed = True              # R1 效果延迟落地
    service.control.fail_prefixes = ("rollback",)
    service.control.probe_error = True          # 期间无法握手核实
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    # nginx 恢复，迟到重载落地
    service.control.probe_error = False
    service.control.pump()
    assert service.control.served == v2["fingerprint"]
    service.reconcile_once()
    assert service.get_op(op["seq"])["state"] == "succeeded"
    assert service.status(probe=False)["active_version_id"] == v2["id"]


def test_pending_verify_expires_and_rolls_back(service):
    """崩溃遗留的待核实操作超过宽限期：回退并经握手确认后判失败。"""
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    seq = insert_pending_op(service, v2["id"])
    service.control.served = old_fp
    time.sleep(0.6)  # pending_ttl = 0.5
    service.reconcile_once()
    op = service.get_op(seq)
    assert op["state"] == "failed"
    assert "回退" in op["detail"]
    assert service.live_fingerprint() == old_fp
    assert service.status(probe=False)["active_version_id"] == 1


def test_old_pending_op_cannot_overwrite_newer(service):
    """旧的待核实操作被新提交取代后，不得再改动任何状态/文件。"""
    v2 = upload_new(service)
    v3 = upload_new(service)
    seq_a = insert_pending_op(service, v2["id"])
    # 新提交（基于同一在用版号 1）成功，旧操作 A 被取代
    service.control.receipt_mode = "ok"
    op_b = service.activate(v3["id"], base_version_id=1)
    assert op_b["state"] == "succeeded"
    assert service.status(probe=False)["active_version_id"] == v3["id"]
    assert service.get_op(seq_a)["state"] == "superseded"
    # 即使 nginx 稍后开始服务 v2 的证书，旧操作也不得翻盘
    service.control.served = v2["fingerprint"]
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v3["id"]
    assert service.live_fingerprint() == v3["fingerprint"]


# ---------------------------------------------------------------- 重启恢复


def restart(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    return svc


def test_restart_confirms_successful_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 制造回退待核实（回退重载失败 + 无法核实）
    svc.control.served = old_fp
    svc.control.fail_prefixes = ("rollback",)
    svc.control.probe_error = True
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    v2_fp = v2["fingerprint"]
    svc.shutdown()
    # 重启：停机期间迟到重载落地，且回退断言重载再次失败
    svc2 = restart(cfg)
    svc2.control.served = v2_fp
    svc2.control.fail_prefixes = ("rollback",)
    svc2.startup(background=False)
    # 启动不臆断；首个后台核实周期按新握手确认
    svc2.reconcile_once()
    st = svc2.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert svc2.get_op(op["seq"])["state"] == "succeeded"
    svc2.shutdown()


def test_restart_rolls_back_unconfirmed_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    svc.control.served = old_fp
    svc.control.fail_prefixes = ("rollback",)
    svc.control.probe_error = True
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "rollback_pending"
    svc.shutdown()
    # 重启后 nginx 服务旧证书：继续核对，握手确认回退成立
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    assert svc2.get_op(op["seq"])["state"] == "rollback_pending"  # 启动期不臆断
    svc2.reconcile_once()
    st = svc2.status(probe=False)
    assert st["active_version_id"] == 1
    assert svc2.get_op(op["seq"])["state"] == "failed"
    assert svc2.live_fingerprint() == old_fp
    svc2.shutdown()


def test_restart_with_probe_down_keeps_rollback_pending_and_blocks(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    svc.control.served = old_fp
    svc.control.fail_prefixes = ("rollback",)
    svc.control.probe_error = True
    op = svc.activate(v2["id"], base_version_id=1)
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.probe_error = True  # nginx 仍不可用
    svc2.startup(background=False)
    assert svc2.get_op(op["seq"])["state"] == "rollback_pending"
    st = svc2.status(probe=False)
    assert st["activation_blocked"] is not None
    v3 = upload_new(svc2)
    with pytest.raises(Conflict, match="回退仍待核实"):
        svc2.activate(v3["id"], base_version_id=1)
    svc2.shutdown()


def test_restart_with_activating_op_recovered(cfg):
    """进程在操作处于 activating 时崩溃（未留下任何终态）。"""
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 手工制造一个悬空的 activating 操作（等价于崩溃瞬间）
    with svc.db.txn() as c:
        st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        seq = st["current_op_seq"] + 1
        ts = certutil.dt.datetime.now(certutil.dt.timezone.utc).isoformat()
        c.execute(
            "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (seq, v2["id"], 1, "activating", None, ts, ts),
        )
        c.execute("UPDATE state SET current_op_seq=?", (seq,))
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    assert svc2.get_op(seq)["state"] == "failed"
    assert svc2.status(probe=False)["active_version_id"] == 1
    svc2.shutdown()


def test_restart_restores_tampered_live_files(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    active_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 带外篡改 live 文件
    chain, key = make_cert(svc)
    with open(f"{cfg.live_dir}/fullchain.pem", "wb") as f:
        f.write(chain)
    assert svc.live_fingerprint() != active_fp
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = active_fp
    svc2.startup(background=False)
    assert svc2.live_fingerprint() == active_fp
    assert svc2.control.reload_count >= 1  # 触发了恢复重载
    svc2.shutdown()


def test_reconciler_restores_out_of_band_change(service):
    """无在途操作时，nginx 实测指纹与在用版本不一致会被自动修复。"""
    active_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = "0" * 64  # 带外变更
    time.sleep(0.15)  # restore_interval = 0.1
    service.reconcile_once()
    assert service.control.reload_count >= 1
    assert service.live_fingerprint() == active_fp
