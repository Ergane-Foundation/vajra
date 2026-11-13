"""Tests for the firewall writer, its protocol and the engine-side client (issue #95)"""

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

import pytest


class FakeNft:
    """Stands in for subprocess.run: records nft calls and fails those containing any text in fail"""

    def __init__(self, fail=()):
        self.calls = []
        self.fail = fail

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        failed = any(text in " ".join(cmd) for text in self.fail)
        return subprocess.CompletedProcess(cmd, 1 if failed else 0, stdout="", stderr="Error: failed" if failed else "")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A scratch directory with nft as the backend, a fake nft, a fixed clock and a small allowlist"""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import firewall, writer, writer_client

    allowlist = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("192.0.2.1/32")]
    monkeypatch.setattr(firewall.FirewallManager, "_detect_backend", lambda self: "nftables")
    monkeypatch.setattr(firewall, "build_allowlist", lambda extra=None, log=None: allowlist)
    monkeypatch.setattr(writer_client, "build_allowlist", lambda extra=None, log=None: allowlist)
    nft = FakeNft()
    monkeypatch.setattr(firewall.subprocess, "run", nft)
    monkeypatch.setattr(firewall.time, "time", lambda: 1000.0)
    now = [0.0]
    fw = firewall.FirewallManager()
    fw_writer = writer.FirewallWriter(fw, group_gid=os.getgid(), max_per_minute=2, clock=lambda: now[0])
    return {"firewall": firewall, "writer": writer, "client": writer_client, "nft": nft, "now": now,
            "fw": fw, "w": fw_writer}


def block(ip, ttl=0, **extra):
    return dict({"v": 1, "op": "block", "ip": ip, "ttl": ttl}, **extra)


def test_block_returns_expiry_and_sets_a_kernel_timeout(env):
    resp = env["w"].handle(block("198.51.100.9", 60, reason="scan"))
    assert resp == {"v": 1, "ok": True, "expires_at": 1060.0}
    assert env["nft"].calls[-1] == ["nft", "add", "element", "inet", "vajra", "blocked_ips", "{ 198.51.100.9 timeout 66s }"]


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "192.0.2.1", "::ffff:192.0.2.1", "0.0.0.0", "fe80::1", "224.0.0.1", "255.255.255.255",
])
def test_protected_addresses_are_refused(env, ip):
    calls = len(env["nft"].calls)
    resp = env["w"].handle(block(ip))
    assert resp["ok"] is False and resp["error"] == "protected"
    assert len(env["nft"].calls) == calls


@pytest.mark.parametrize("ip", ["not-an-ip", 5, "fe80::1%eth0"])
def test_unparsable_addresses_are_invalid(env, ip):
    assert env["w"].handle(block(ip))["error"] == "invalid_address"


@pytest.mark.parametrize("request_obj,code", [
    ([], "bad_request"),
    ({"op": "list"}, "bad_request"),
    ({"v": 2, "op": "list"}, "unsupported_version"),
    ({"v": 1, "op": "flush"}, "unknown_op"),
    ({"v": 1, "op": "list", "x": 1}, "bad_request"),
    ({"v": 1, "op": "block", "ip": "198.51.100.9"}, "bad_request"),
    ({"v": 1, "op": "block", "ip": "198.51.100.9", "ttl": True}, "bad_request"),
    ({"v": 1, "op": "block", "ip": "198.51.100.9", "ttl": -1}, "bad_request"),
    ({"v": 1, "op": "block", "ip": "198.51.100.9", "ttl": 0, "reason": "x" * 201}, "bad_request"),
    ({"v": 1, "op": "block", "ip": "198.51.100.9", "ttl": 0, "reason": 7}, "bad_request"),
])
def test_malformed_requests(env, request_obj, code):
    calls = len(env["nft"].calls)
    resp = env["w"].handle(request_obj)
    assert resp["ok"] is False and resp["error"] == code
    assert len(env["nft"].calls) == calls


def test_rate_limit_counts_only_new_blocks(env):
    w = env["w"]
    assert w.handle(block("198.51.100.1"))["ok"]
    assert w.handle(block("198.51.100.2"))["ok"]
    assert w.handle(block("198.51.100.3"))["error"] == "rate_limited"
    assert w.handle(block("198.51.100.1"))["ok"]
    env["now"][0] += 61
    assert w.handle(block("198.51.100.3"))["ok"]


def test_unblock_and_list(env):
    w = env["w"]
    w.handle(block("198.51.100.9"))
    w.handle(block("198.51.100.2"))
    resp = w.handle({"v": 1, "op": "list"})
    assert resp["enforcing"] is True and resp["backend"] == "nftables"
    assert [b["ip"] for b in resp["blocks"]] == ["198.51.100.2", "198.51.100.9"]
    assert w.handle({"v": 1, "op": "unblock", "ip": "198.51.100.9"}) == {"v": 1, "ok": True}
    assert env["nft"].calls[-1] == ["nft", "delete", "element", "inet", "vajra", "blocked_ips", "{ 198.51.100.9 }"]
    assert w.handle({"v": 1, "op": "unblock", "ip": "198.51.100.77"}) == {"v": 1, "ok": True}


def test_failed_firewall_call_is_reported(env):
    env["nft"].fail = ["198.51.100.9"]
    assert env["w"].handle(block("198.51.100.9"))["error"] == "failed"


def test_dry_run_writer_never_calls_nft(env):
    fw = env["firewall"].FirewallManager(dry_run=True)
    w = env["writer"].FirewallWriter(fw, group_gid=os.getgid())
    calls = len(env["nft"].calls)
    assert w.handle(block("198.51.100.9"))["error"] == "not_enforced"
    assert len(env["nft"].calls) == calls


def test_peer_allowed(env, monkeypatch):
    foreign_gid = os.getgid() + 4000
    w = env["writer"].FirewallWriter(env["fw"], group_gid=foreign_gid)
    other_uid = os.geteuid() + 1
    monkeypatch.setattr(w, "_peer_groups", lambda pid: [])
    assert w.peer_allowed(1, 0, 0)
    assert w.peer_allowed(1, os.geteuid(), 0)
    assert w.peer_allowed(1, other_uid, foreign_gid)
    assert not w.peer_allowed(1, other_uid, os.getgid())
    monkeypatch.setattr(w, "_peer_groups", lambda pid: [5, foreign_gid])
    assert w.peer_allowed(1, other_uid, os.getgid())


def test_socket_round_trip(env):
    directory = tempfile.mkdtemp(dir="/tmp")
    path = os.path.join(directory, "w.sock")
    writer = env["writer"]
    server = writer.make_server(env["w"], writer.prepare_socket(path, os.getgid()))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = env["client"].WriterClient(path, block_ttl=60)
        assert client.enforcing and client.backend == "writer (nftables)"
        assert client.block_ip("198.51.100.9") is True
        assert client.block_expiry["198.51.100.9"] == 1060.0
        assert client.block_ip("127.0.0.1") is False
        assert client.block_ip("0.0.0.0") is False and client.is_allowlisted("0.0.0.0")
        assert client.expire_blocks() == []
        env["w"].handle({"v": 1, "op": "unblock", "ip": "198.51.100.9"})
        assert client.expire_blocks() == ["198.51.100.9"]
        assert client.block_expiry == {}

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5)
            raw.connect(path)
            raw.sendall(b"x" * 5000)
            assert json.loads(raw.makefile().readline())["error"] == "bad_request"
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(directory, ignore_errors=True)


def test_prepare_socket_works_without_root(env):
    directory = tempfile.mkdtemp(dir="/tmp")
    path = os.path.join(directory, "w.sock")
    try:
        sock = env["writer"].prepare_socket(path, os.getgid())
        sock.close()
        info = os.stat(path)
        assert info.st_mode & 0o777 == 0o660
        assert info.st_gid == os.stat(directory).st_gid == os.getgid()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_client_without_a_writer_fails_quietly(env, monkeypatch):
    monkeypatch.setattr(env["client"].time, "sleep", lambda seconds: None)
    client = env["client"].WriterClient("/tmp/vajra-no-such-writer.sock")
    assert client.backend == "writer (unreachable)"
    assert client.block_ip("198.51.100.9") is False
    assert client.expire_blocks() == []


def test_importing_the_client_leaves_the_writer_alone():
    code = (
        "import logging, sys\n"
        "import vajra.soar.writer_client\n"
        "print('vajra.soar.writer' in sys.modules, len(logging.getLogger('soar_engine.firewall').handlers))"
    )
    child_env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, env=child_env).stdout
    assert out.split() == ["False", "0"]


def test_engine_refuses_dry_run_with_a_writer(env, monkeypatch):
    from vajra.soar import engine

    monkeypatch.setattr(sys, "argv", ["vajra-soar", "--dry-run", "--writer-socket", "/tmp/x.sock"])
    with pytest.raises(SystemExit) as exc:
        engine.main()
    assert exc.value.code == 2


def test_client_truncates_reason_and_folds_mapped_addresses(env, monkeypatch):
    client = env["client"].WriterClient("/tmp/vajra-no-such-writer.sock", block_ttl=0)
    sent = []
    monkeypatch.setattr(client, "_request", lambda payload: sent.append(payload) or {"ok": True, "expires_at": 5.0})
    assert client.block_ip("::ffff:198.51.100.9", "r" * 500, expires_at=1000.0 + 10 ** 9)
    assert len(sent[0]["reason"]) == 200 and sent[0]["ttl"] == 31536000
    assert list(client.block_expiry) == ["198.51.100.9"]


def test_expire_blocks_ignores_blocks_added_during_the_list_request(env, monkeypatch):
    client = env["client"].WriterClient("/tmp/vajra-no-such-writer.sock")
    client.block_expiry = {"198.51.100.1": 1.0}

    def request(payload):
        client.block_expiry["198.51.100.2"] = 2.0
        return {"ok": True, "blocks": []}

    monkeypatch.setattr(client, "_request", request)
    assert client.expire_blocks() == ["198.51.100.1"]
    assert "198.51.100.2" in client.block_expiry


def test_handler_survives_deeply_nested_json(env):
    directory = tempfile.mkdtemp(dir="/tmp")
    path = os.path.join(directory, "w.sock")
    writer = env["writer"]
    server = writer.make_server(env["w"], writer.prepare_socket(path, os.getgid()))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5)
            raw.connect(path)
            raw.sendall(b"[" * 2000 + b"]" * 2000 + b"\n")
            assert json.loads(raw.makefile().readline())["ok"] is False
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(directory, ignore_errors=True)
