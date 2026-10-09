"""Tests for build_allowlist, the addresses Vajra must never block (issue #46)."""

import ipaddress
import logging

import pytest

from vajra.common import network


@pytest.fixture
def host(monkeypatch):
    """Fixed host addresses and no resolver files, so results do not depend on this machine."""
    monkeypatch.setattr(network, "get_local_ip", lambda: "192.0.2.10")
    monkeypatch.setattr(network, "get_gateway_ip", lambda: "192.0.2.1")
    monkeypatch.setattr(network, "get_local_addresses", lambda: [])
    monkeypatch.setattr(network, "get_default_gateways", lambda: [])
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
