"""Tests for the nftables table setup and restoring saved blocks (issue #2)."""

import ipaddress
import subprocess

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


def raises(exc):
    def run(cmd, **kwargs):
        raise exc
    return run


@pytest.fixture
def engine_module(tmp_path, monkeypatch):
    """Import the engine from a scratch directory with nft present and a loopback-only allowlist."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import engine

    monkeypatch.setattr(engine.FirewallManager, "_detect_backend", lambda self: "nftables")
    monkeypatch.setattr(engine, "build_allowlist", lambda extra=None, log=None: [ipaddress.ip_network("127.0.0.0/8")])
    return engine


def saved_lines(tmp_path):
    return set((tmp_path / "logs" / "blocked_ips.txt").read_text().split("\n"))


def test_setup_creates_table_then_restores_saved_blocks(engine_module, tmp_path, monkeypatch):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7\n2001:db8::7")
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    fw = engine_module.FirewallManager()
    assert nft.calls[0] == ["nft", "-f", "-"]
    assert sorted(nft.calls[1:]) == sorted([
        ["nft", "add", "element", "inet", "vajra", "blocked_ips", "{ 203.0.113.7 }"],
        ["nft", "add", "element", "inet", "vajra", "blocked_ips6", "{ 2001:db8::7 }"],
    ])
    assert fw.enforcing
    assert fw.blocked_ips == {"203.0.113.7", "2001:db8::7"}
    assert saved_lines(tmp_path) == {"203.0.113.7", "2001:db8::7"}


@pytest.mark.parametrize("run", [
    FakeNft(fail=["nft -f"]),
    raises(OSError("nft: not found")),
    raises(subprocess.TimeoutExpired("nft", 5)),
], ids=["nft-error", "oserror", "timeout"])
def test_setup_failure_stops_enforcing_and_keeps_saved_file(engine_module, tmp_path, monkeypatch, run):
    path = tmp_path / "logs" / "blocked_ips.txt"
    path.write_text("203.0.113.7")
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager()
    assert not fw.enforcing
    assert fw.blocked_ips == set()
    assert fw.block_ip("198.51.100.9", "test") is False
    assert path.read_text() == "203.0.113.7"


def test_failed_restore_stays_saved_and_is_retried(engine_module, tmp_path, monkeypatch):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7\n198.51.100.8\n127.0.0.5")
    monkeypatch.setattr(engine_module.subprocess, "run", FakeNft(fail=["203.0.113.7"]))
    fw = engine_module.FirewallManager()
    assert fw.blocked_ips == {"198.51.100.8"}
    assert saved_lines(tmp_path) == {"203.0.113.7", "198.51.100.8"}
    assert fw.block_ip("192.0.2.5", "new attack") is True
    assert saved_lines(tmp_path) == {"203.0.113.7", "198.51.100.8", "192.0.2.5"}

    monkeypatch.setattr(engine_module.subprocess, "run", FakeNft())
    fw = engine_module.FirewallManager()
    assert fw.blocked_ips == {"203.0.113.7", "198.51.100.8", "192.0.2.5"}


def test_dry_run_never_runs_nft(engine_module, tmp_path, monkeypatch):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7")
    nft = FakeNft()
    monkeypatch.setattr(engine_module.subprocess, "run", nft)
    fw = engine_module.FirewallManager(dry_run=True)
    assert fw.block_ip("198.51.100.9", "test") is False
    assert nft.calls == []
