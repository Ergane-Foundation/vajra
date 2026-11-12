"""Tests for build_allowlist, the addresses Vajra must never block (issues #46 and #80)."""

import ipaddress
import json
import logging
import subprocess

import pytest

from vajra.common import network


@pytest.fixture
def host(monkeypatch):
    """Fixed host addresses and no resolver files, so results do not depend on this machine."""
    monkeypatch.setattr(network, "get_local_ip", lambda: "192.0.2.10")
    monkeypatch.setattr(network, "get_gateway_ip", lambda: "192.0.2.1")
    monkeypatch.setattr(network, "get_local_addresses", list)
    monkeypatch.setattr(network, "get_default_gateways", list)
    monkeypatch.setattr(network, "get_ssh_clients", list)
    monkeypatch.setattr(network, "RESOLV_CONF_FILES", ())
    monkeypatch.delenv("VAJRA_ALLOWLIST", raising=False)


def net(value):
    return ipaddress.ip_network(value)


def test_loopback_kept_when_address_detection_fails(host, monkeypatch, caplog):
    def fail():
        raise OSError("no route")

    monkeypatch.setattr(network, "get_local_ip", fail)
    with caplog.at_level(logging.WARNING, logger="test_allowlist"):
        allowlist = network.build_allowlist(log=logging.getLogger("test_allowlist"))
    assert allowlist == [net("127.0.0.0/8"), net("::1/128")]
    assert "Could not detect local addresses for the allowlist: no route" in caplog.text


def test_includes_host_gateway_extra_and_env_entries(host, monkeypatch):
    monkeypatch.setenv("VAJRA_ALLOWLIST", " 198.51.100.0/24 , 2001:db8::/32,")
    allowlist = network.build_allowlist(["203.0.113.5"])
    for entry in ("127.0.0.0/8", "::1/128", "192.0.2.10/32", "192.0.2.1/32",
                  "198.51.100.0/24", "2001:db8::/32", "203.0.113.5/32"):
        assert net(entry) in allowlist


def test_invalid_entries_are_rejected_and_logged(host, monkeypatch, caplog):
    monkeypatch.setenv("VAJRA_ALLOWLIST", "not-an-ip,198.51.100.300,10.0.0.0/33")
    with caplog.at_level(logging.WARNING, logger="test_allowlist"):
        allowlist = network.build_allowlist(["; rm -rf /"], log=logging.getLogger("test_allowlist"))
    assert allowlist == [net("127.0.0.0/8"), net("::1/128"), net("192.0.2.10/32"), net("192.0.2.1/32")]
    for bad in ("not-an-ip", "198.51.100.300", "10.0.0.0/33", "; rm -rf /"):
        assert f"Ignoring invalid allowlist entry: {bad}" in caplog.text


def test_duplicates_are_removed(host, monkeypatch):
    monkeypatch.setenv("VAJRA_ALLOWLIST", "192.0.2.10,10.0.0.0/8")
    allowlist = network.build_allowlist(["10.0.0.0/8", "10.1.2.3/8"])
    assert allowlist.count(net("10.0.0.0/8")) == 1
    assert allowlist.count(net("192.0.2.10/32")) == 1


def test_reads_nameservers_and_skips_missing_files(host, monkeypatch, tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("# generated\nnameserver 10.0.2.3\nnameserver fec0::3\nsearch example\n")
    monkeypatch.setattr(network, "RESOLV_CONF_FILES", (str(tmp_path / "missing.conf"), str(conf)))
    allowlist = network.build_allowlist()
    assert net("10.0.2.3/32") in allowlist
    assert net("fec0::3/128") in allowlist


def test_logged_in_ssh_clients_are_protected_and_logged(host, monkeypatch, caplog):
    monkeypatch.setattr(network, "get_ssh_clients", lambda: ["198.51.100.7", "2001:db8::7"])
    with caplog.at_level(logging.INFO, logger="test_allowlist"):
        allowlist = network.build_allowlist(log=logging.getLogger("test_allowlist"))
    assert net("198.51.100.7/32") in allowlist
    assert net("2001:db8::7/128") in allowlist
    assert "Protecting SSH clients: 198.51.100.7, 2001:db8::7" in caplog.text


SS_OUTPUT = """\
0 0 192.0.2.10:22 198.51.100.7:51234 users:(("sshd",pid=1201,fd=4),("sshd",pid=1190,fd=4))
0 0 [::ffff:192.0.2.10]:22 [::ffff:203.0.113.9]:40000 users:(("sshd-session",pid=1300,fd=4))
0 0 [2001:db8::10]:22 [2001:db8::7]:5555 users:(("sshd",pid=1400,fd=4))
0 0 192.0.2.10:22 198.51.100.66:60000 users:(("sshd",pid=1500,fd=4),("sshd",pid=1501,fd=4))
0 0 192.0.2.10:443 198.51.100.8:50000 users:(("nginx",pid=900,fd=12))
0 0 192.0.2.10:22 198.51.100.7:51300 users:(("sshd",pid=1600,fd=4))
0 0 [fe80::10]%eth0:22 [fe80::7]%eth0:6000 users:(("sshd",pid=1700,fd=4))
"""

TITLES = {
    "1201": "sshd: alice@pts/0",
    "1190": "sshd: alice [priv]",
    "1300": "sshd-session: deploy@notty",
    "1400": "sshd: bob@pts/1",
    "1500": "sshd: root [priv]",
    "1501": "sshd: root [net]",
    "900": "nginx: worker process",
    "1600": "sshd: alice@pts/2",
    "1700": "sshd: carol@pts/3",
}


def fake_ss(monkeypatch, output=SS_OUTPUT, error=None):
    def run(cmd, **kwargs):
        if error:
            raise error
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr="")

    monkeypatch.setattr(network.subprocess, "run", run)
    monkeypatch.setattr(network, "_process_title", lambda pid: TITLES.get(pid, ""))


def test_ssh_clients_are_logged_in_sessions_only(monkeypatch):
    fake_ss(monkeypatch)
    assert network.get_ssh_clients() == ["198.51.100.7", "203.0.113.9", "2001:db8::7", "fe80::7"]


@pytest.mark.parametrize("error", [FileNotFoundError("ss"), subprocess.TimeoutExpired("ss", 5)],
                         ids=["no-ss", "timeout"])
def test_no_ssh_clients_when_ss_fails(monkeypatch, error):
    fake_ss(monkeypatch, error=error)
    assert network.get_ssh_clients() == []


ADDR = "ip -j addr show 2>/dev/null"
ROUTE4 = "ip -j -4 route show default 2>/dev/null"
ROUTE6 = "ip -j -6 route show default 2>/dev/null"


def fake_ip(monkeypatch, outputs):
    """Make run_command return canned ip -j output per command, and nothing for others"""
    monkeypatch.setattr(network, "run_command", lambda cmd: outputs.get(cmd, ""))


def test_local_addresses_come_from_every_interface(monkeypatch):
    fake_ip(monkeypatch, {ADDR: json.dumps([
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}, {"family": "inet6", "local": "::1"}]},
        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.10"}, {"family": "inet6", "local": "fe80::5054:ff:fe12:3456"}]},
        {"ifname": "eth1", "addr_info": []},
        {"ifname": "eth2"},
    ])})
    assert network.get_local_addresses() == ["127.0.0.1", "::1", "192.0.2.10", "fe80::5054:ff:fe12:3456"]


def test_default_gateways_include_multipath_nexthops(monkeypatch):
    fake_ip(monkeypatch, {
        ROUTE4: json.dumps([
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "flags": []},
            {"dst": "default", "dev": "wg0", "scope": "link", "flags": []},
        ]),
        ROUTE6: json.dumps([{"dst": "default", "flags": [], "nexthops": [
            {"gateway": "fe80::1", "dev": "eth0", "weight": 1, "flags": []},
            {"gateway": "fe80::2", "dev": "eth1", "weight": 1, "flags": []},
        ]}]),
    })
    assert network.get_default_gateways() == ["192.0.2.1", "fe80::1", "fe80::2"]


@pytest.mark.parametrize("output", ["", "[]"], ids=["command-failed", "no-routes"])
def test_no_addresses_when_ip_output_is_empty(monkeypatch, output):
    fake_ip(monkeypatch, {ADDR: output, ROUTE4: output, ROUTE6: output})
    assert network.get_local_addresses() == []
    assert network.get_default_gateways() == []
