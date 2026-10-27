"""Tests for block expiry (issue #4)."""

import ipaddress
import json
import logging
import subprocess
import sys
import threading

import pytest


class FakeNft:
    """Stands in for subprocess.run: records firewall calls and fails those containing any text in fail with code"""

    def __init__(self, fail=(), code=1):
        self.calls = []
        self.fail = fail
        self.code = code

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        failed = any(text in " ".join(cmd) for text in self.fail)
        return subprocess.CompletedProcess(cmd, self.code if failed else 0, stdout="", stderr="Error: failed" if failed else "")


@pytest.fixture
def engine_module(tmp_path, monkeypatch):
    """Import the engine from a scratch directory with nft present, a loopback-only allowlist and a fixed clock."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import engine

    monkeypatch.setattr(engine.FirewallManager, "_detect_backend", lambda self: "nftables")
    monkeypatch.setattr(engine, "build_allowlist", lambda extra=None, log=None: [ipaddress.ip_network("127.0.0.0/8")])
    monkeypatch.setattr(engine.time, "time", lambda: 1000.0)
    return engine


def saved_expiry(tmp_path):
    return json.loads((tmp_path / "logs" / "block_expiry.json").read_text())


def adds(nft):
    return [cmd for cmd in nft.calls if cmd[1] == "add"]


def test_nft_block_gets_timeout_and_saved_expiry(engine_module, tmp_path, monkeypatch):
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    fw = engine_module.FirewallManager(block_ttl=3600)
    assert fw.block_ip("198.51.100.9", "test") is True
    assert nft.calls[-1] == ["nft", "add", "element", "inet", "vajra", "blocked_ips", "{ 198.51.100.9 timeout 3606s }"]
    assert fw.block_expiry == {"198.51.100.9": 4600.0}
    assert saved_expiry(tmp_path) == {"198.51.100.9": 4600.0}


def test_ttl_zero_blocks_permanently(engine_module, monkeypatch):
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    fw = engine_module.FirewallManager(block_ttl=0)
    assert fw.block_ip("198.51.100.9", "test") is True
    assert nft.calls[-1] == ["nft", "add", "element", "inet", "vajra", "blocked_ips", "{ 198.51.100.9 }"]
    assert fw.block_expiry == {}


def test_iptables_block_is_removed_when_it_expires(engine_module, tmp_path, monkeypatch):
    monkeypatch.setattr(engine_module.FirewallManager, "_detect_backend", lambda self: "iptables")
    run = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager(block_ttl=3600)
    ip = "198.51.100.9"
    assert fw.block_ip(ip, "test") is True

    assert fw.expire_blocks(now=4599) == []
    assert not [cmd for cmd in run.calls if "-D" in cmd and ip in cmd]

    assert fw.expire_blocks(now=4600) == [ip]
    assert run.calls[-2:] == [
        ["iptables", "-D", "VAJRA-BLOCK", "-s", ip, "-j", "DROP"],
        ["iptables", "-D", "VAJRA-BLOCK", "-d", ip, "-j", "DROP"],
    ]
    assert ip not in fw.blocked_ips
    assert ip not in (tmp_path / "logs" / "blocked_ips.txt").read_text()
    assert saved_expiry(tmp_path) == {}


def test_failed_unblock_is_retried(engine_module, tmp_path, monkeypatch):
    monkeypatch.setattr(engine_module.FirewallManager, "_detect_backend", lambda self: "iptables")
    run = FakeNft(fail=["-D"], code=4)
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager(block_ttl=3600)
    ip = "198.51.100.9"
    assert fw.block_ip(ip, "test") is True

    assert fw.expire_blocks(now=4600) == []
    assert ip in fw.blocked_ips
    assert fw.block_expiry == {ip: 4600.0}

    run.fail = ()
    assert fw.expire_blocks(now=4600) == [ip]
    assert ip not in fw.blocked_ips


def test_successful_retry_of_unrestored_block_expires(engine_module, tmp_path, monkeypatch):
    ip = "198.51.100.9"
    (tmp_path / "logs" / "blocked_ips.txt").write_text(ip)
    (tmp_path / "logs" / "block_expiry.json").write_text(json.dumps({ip: 1030}))
    monkeypatch.setattr(engine_module.FirewallManager, "_detect_backend", lambda self: "iptables")
    run = FakeNft(fail=[ip])
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager(block_ttl=3600)
    assert fw.unrestored_ips == {ip}

    run.fail = ()
    assert fw.block_ip(ip) is True
    assert fw.expire_blocks(now=4600) == [ip]
    assert run.calls[-2:] == [
        ["iptables", "-D", "VAJRA-BLOCK", "-s", ip, "-j", "DROP"],
        ["iptables", "-D", "VAJRA-BLOCK", "-d", ip, "-j", "DROP"],
    ]
    assert ip not in fw.blocked_ips
    assert ip not in fw.unrestored_ips
    assert ip not in (tmp_path / "logs" / "blocked_ips.txt").read_text()
    assert saved_expiry(tmp_path) == {}


def test_block_waits_for_expiry_then_reblocks(engine_module, tmp_path, monkeypatch):
    ip = "198.51.100.9"
    monkeypatch.setattr(engine_module.FirewallManager, "_detect_backend", lambda self: "iptables")
    calls = []
    threads = []
    finished_during_delete = []
    results = []
    started = threading.Event()

    def reblock():
        started.set()
        results.append(fw.block_ip(ip))

    def run(cmd, **kwargs):
        calls.append(cmd)
        if "-D" in cmd and ip in cmd and not threads:
            thread = threading.Thread(target=reblock, daemon=True)
            threads.append(thread)
            thread.start()
            assert started.wait(timeout=1)
            thread.join(timeout=0.2)
            finished_during_delete.append(not thread.is_alive())
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager(block_ttl=3600)
    assert fw.block_ip(ip) is True
    calls.clear()
    monkeypatch.setattr(engine_module.time, "time", lambda: 4600.0)
    try:
        expired = fw.expire_blocks()
    finally:
        for thread in threads:
            thread.join(timeout=2)

    assert expired == [ip]
    assert finished_during_delete == [False]
    assert all(not thread.is_alive() for thread in threads)
    assert results == [True]
    assert calls == [
        ["iptables", "-D", "VAJRA-BLOCK", "-s", ip, "-j", "DROP"],
        ["iptables", "-D", "VAJRA-BLOCK", "-d", ip, "-j", "DROP"],
        ["iptables", "-A", "VAJRA-BLOCK", "-s", ip, "-j", "DROP"],
        ["iptables", "-A", "VAJRA-BLOCK", "-d", ip, "-j", "DROP"],
    ]
    assert fw.blocked_ips == {ip}
    assert fw.unrestored_ips == set()
    assert fw.block_expiry == {ip: 8200.0}
    assert (tmp_path / "logs" / "blocked_ips.txt").read_text() == ip
    assert saved_expiry(tmp_path) == {ip: 8200.0}



def test_restore_keeps_remaining_time(engine_module, tmp_path, monkeypatch):
    a, b, c = "203.0.113.1", "203.0.113.2", "203.0.113.3"
    (tmp_path / "logs" / "blocked_ips.txt").write_text(f"{a}\n{b}\n{c}")
    (tmp_path / "logs" / "block_expiry.json").write_text(json.dumps({a: 1030, b: 990}))
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    fw = engine_module.FirewallManager(block_ttl=3600)
    assert sorted(adds(nft)) == sorted([
        ["nft", "add", "element", "inet", "vajra", "blocked_ips", f"{{ {a} timeout 36s }}"],
        ["nft", "add", "element", "inet", "vajra", "blocked_ips", f"{{ {c} timeout 3606s }}"],
    ])
    assert b in fw.blocked_ips
    assert fw.expire_blocks() == [b]


def test_unrestored_block_expires(engine_module, tmp_path, monkeypatch):
    ip = "203.0.113.7"
    (tmp_path / "logs" / "blocked_ips.txt").write_text(ip)
    (tmp_path / "logs" / "block_expiry.json").write_text(json.dumps({ip: 1030}))
    monkeypatch.setattr(engine_module.subprocess, "run", FakeNft(fail=[ip]))
    fw = engine_module.FirewallManager(block_ttl=3600)
    assert fw.unrestored_ips == {ip}

    assert fw.expire_blocks(now=1030) == [ip]
    assert ip not in (tmp_path / "logs" / "blocked_ips.txt").read_text()
    assert saved_expiry(tmp_path) == {}



def test_corrupt_expiry_file_gives_saved_blocks_a_new_expiry(engine_module, tmp_path, monkeypatch, caplog):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7")
    (tmp_path / "logs" / "block_expiry.json").write_text("not json")
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    with caplog.at_level(logging.WARNING, logger="soar_engine"):
        fw = engine_module.FirewallManager(block_ttl=3600)
    assert any("block_expiry.json" in r.message for r in caplog.records if r.levelno == logging.WARNING)
    assert adds(nft) == [["nft", "add", "element", "inet", "vajra", "blocked_ips", "{ 203.0.113.7 timeout 3606s }"]]
    assert fw.block_expiry == {"203.0.113.7": 4600.0}


def test_block_record_has_expiry_and_expiry_is_recorded(engine_module, tmp_path, monkeypatch):
    for flag in ("KAFKA_AVAILABLE", "UNIFIED_LOGGER_AVAILABLE", "UBA_AVAILABLE"):
        monkeypatch.setattr(engine_module, flag, False)
    monkeypatch.setattr(engine_module.subprocess, "run", FakeNft())
    monkeypatch.setattr(engine_module.SOAREngine, "_expire_blocks_loop", lambda self: None)
    engine = engine_module.SOAREngine(enable_ml=False, block_ttl=3600)

    engine.process_alert({"src_ip": "198.51.100.9", "signature": "SQL Injection", "severity": "HIGH"})
    log = tmp_path / "logs" / "soar_actions.log"
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[-1]["blocked"] is True
    assert records[-1]["expires_at"] == "1970-01-01T01:16:40+00:00"

    monkeypatch.setattr(engine_module.time, "time", lambda: 4600.0)
    engine.expire_blocks()
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[-1]["action"] == "UNBLOCK_IP"
    assert records[-1]["target_ip"] == "198.51.100.9"
    assert records[-1]["blocked"] is False


@pytest.fixture
def cli(engine_module, monkeypatch):
    """Run main() with the given arguments and return the kwargs passed to SOAREngine"""
    seen = {}

    class FakeEngine:
        ml_enabled = False

        def __init__(self, **kwargs):
            seen.update(kwargs)

        def run(self):
            pass

        def run_file(self, eve):
            pass

    monkeypatch.setattr(engine_module, "SOAREngine", FakeEngine)
    monkeypatch.delenv("VAJRA_BLOCK_TTL", raising=False)

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["engine", "--file-mode", *args])
        engine_module.main()
        return seen

    return run


def test_cli_default_ttl(cli):
    assert cli()["block_ttl"] == 3600


def test_cli_env_ttl(cli, monkeypatch):
    monkeypatch.setenv("VAJRA_BLOCK_TTL", "60")
    assert cli()["block_ttl"] == 60


def test_cli_flag_beats_env(cli, monkeypatch):
    monkeypatch.setenv("VAJRA_BLOCK_TTL", "60")
    assert cli("--block-ttl", "0")["block_ttl"] == 0


@pytest.mark.parametrize("env, args", [("abc", ()), (None, ("--block-ttl", "-1"))], ids=["bad-env", "negative"])
def test_cli_rejects_bad_ttl(cli, monkeypatch, env, args):
    if env is not None:
        monkeypatch.setenv("VAJRA_BLOCK_TTL", env)
    with pytest.raises(SystemExit) as exc:
        cli(*args)
    assert exc.value.code == 2
