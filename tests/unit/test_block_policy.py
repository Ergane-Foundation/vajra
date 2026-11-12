"""Tests for the block policy: thresholds, cooldown and rate limit (issue #7)."""

import ipaddress
import json
import subprocess

import pytest

from vajra.soar.policy import BELOW_THRESHOLD, BLOCK, COOLDOWN, RATE_LIMITED, BlockPolicy


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


def policy(clock, **kwargs):
    return BlockPolicy(clock=clock, **kwargs)


def test_critical_blocks_on_the_first_alert(clock):
    assert policy(clock).decide("198.51.100.1", critical=True) == BLOCK


def test_high_needs_threshold_alerts_within_the_window(clock):
    p = policy(clock, threshold=3, window=60)
    assert p.decide("198.51.100.1") == BELOW_THRESHOLD
    clock.now += 30
    assert p.decide("198.51.100.1") == BELOW_THRESHOLD
    assert p.decide("198.51.100.2") == BELOW_THRESHOLD
    clock.now += 29
    assert p.decide("198.51.100.1") == BLOCK


def test_alerts_older_than_the_window_do_not_count(clock):
    p = policy(clock, threshold=3, window=60)
    p.decide("198.51.100.1")
    p.decide("198.51.100.1")
    clock.now += 60
    assert p.decide("198.51.100.1") == BELOW_THRESHOLD


def test_blocked_source_is_not_blocked_again_during_cooldown(clock):
    p = policy(clock, threshold=2, cooldown=300)
    assert p.decide("198.51.100.1", critical=True) == BLOCK
    clock.now += 299
    assert p.decide("198.51.100.1", critical=True) == COOLDOWN
    clock.now += 1
    assert p.decide("198.51.100.1") == BELOW_THRESHOLD
    assert p.decide("198.51.100.1") == BLOCK


def test_new_blocks_are_capped_per_minute(clock):
    p = policy(clock, max_per_minute=2)
    assert p.decide("198.51.100.1", critical=True) == BLOCK
    assert p.decide("198.51.100.2", critical=True) == BLOCK
    assert p.decide("198.51.100.3", critical=True) == RATE_LIMITED
    clock.now += 60
    assert p.decide("198.51.100.3", critical=True) == BLOCK


def test_rate_limited_source_keeps_its_evidence(clock):
    p = policy(clock, threshold=2, max_per_minute=1)
    p.decide("198.51.100.9", critical=True)
    p.decide("198.51.100.1")
    assert p.decide("198.51.100.1") == RATE_LIMITED
    clock.now += 50
    assert p.decide("198.51.100.1") == RATE_LIMITED
    clock.now += 10
    assert p.decide("198.51.100.1") == BLOCK


def test_idle_sources_are_forgotten(clock):
    p = policy(clock, window=60, cooldown=300)
    for i in range(100):
        p.decide(f"198.51.100.{i}")
    p.decide("203.0.113.1", critical=True)
    clock.now += 300
    p.decide("203.0.113.2")
    assert set(p._hits) == {"203.0.113.2"}
    assert p._last_block == {}


@pytest.mark.parametrize("kwargs", [
    {"threshold": 0}, {"window": 0}, {"cooldown": -1}, {"max_per_minute": 0},
])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        BlockPolicy(**kwargs)


@pytest.fixture
def engine(tmp_path, monkeypatch, clock):
    """A dry-run engine in a scratch directory with a loopback-only allowlist and the fake clock"""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import engine as engine_module

    for flag in ("KAFKA_AVAILABLE", "UNIFIED_LOGGER_AVAILABLE", "UBA_AVAILABLE"):
        monkeypatch.setattr(engine_module, flag, False)
    monkeypatch.setattr(engine_module.FirewallManager, "_detect_backend", lambda self: "nftables")
    monkeypatch.setattr(engine_module, "build_allowlist",
                        lambda extra=None, log=None: [ipaddress.ip_network("127.0.0.0/8")])
    monkeypatch.setattr(engine_module.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""))
    monkeypatch.setattr(engine_module.SOAREngine, "_expire_blocks_loop", lambda self: None)
    return engine_module.SOAREngine(
        enable_ml=False, block_ttl=3600, policy=BlockPolicy(threshold=3, max_per_minute=1, clock=clock)
    )


def records(tmp_path):
    lines = (tmp_path / "logs" / "soar_actions.log").read_text().splitlines()
    return [(r["action"], r["result"], r["blocked"]) for r in map(json.loads, lines)]


def test_engine_blocks_on_the_third_high_alert(engine, tmp_path):
    for _ in range(3):
        engine.process_alert({"src_ip": "198.51.100.9", "signature": "VAJRA DROP Port Scan", "severity": "HIGH"})
    assert records(tmp_path) == [
        ("LOG_ONLY", "below_threshold", False),
        ("LOG_ONLY", "below_threshold", False),
        ("BLOCK_IP", "success", True),
    ]


def test_allowlisted_source_does_not_use_up_the_rate_limit(engine, tmp_path):
    engine.process_alert({"src_ip": "127.0.0.1", "signature": "VAJRA DROP SSH Brute Force", "severity": "CRITICAL"})
    engine.process_alert({"src_ip": "198.51.100.9", "signature": "VAJRA DROP SSH Brute Force", "severity": "CRITICAL"})
    engine.process_alert({"src_ip": "198.51.100.10", "signature": "VAJRA DROP SSH Brute Force", "severity": "CRITICAL"})
    assert records(tmp_path) == [
        ("BLOCK_IP", "allowlisted", False),
        ("BLOCK_IP", "success", True),
        ("LOG_ONLY", "rate_limited", False),
    ]


def test_low_severity_never_reaches_the_policy(engine, tmp_path):
    for _ in range(5):
        engine.process_alert({"src_ip": "198.51.100.9", "signature": "ET INFO something", "severity": "LOW"})
    assert {r for r in records(tmp_path)} == {("LOG_ONLY", "success", False)}


def test_ml_predictions_go_through_the_policy(engine):
    from vajra.ml.manager import MLPrediction

    def prediction(src):
        return MLPrediction(model_name="m", timestamp="", prediction=1, confidence=0.9, probabilities=None,
                            is_threat=True, threat_type="ddos", features_used={"src_ip": src}, raw_input={},
                            inference_time_ms=0.0)

    for _ in range(2):
        engine._on_ml_prediction(prediction("198.51.100.9"))
    assert engine.firewall.blocked_ips == set()
    engine._on_ml_prediction(prediction("198.51.100.9"))
    assert engine.firewall.blocked_ips == {"198.51.100.9"}
