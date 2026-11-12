import os
import pytest
from vajra.soar.engine import SOAREngine


@pytest.fixture(scope="module")
def soar_engine():
    """Initializes SOAREngine with ML disabled and dry-run mode enabled."""
    os.makedirs("logs", exist_ok=True)
    engine = SOAREngine(enable_ml=False, dry_run=True)
    yield engine
    if getattr(engine, "unified_logger", None):
        engine.unified_logger.stop()
    if getattr(engine, "consumer", None):
        engine.consumer.close()


class TestSOAREngineShouldBlock:
    """Tests for SOAREngine.should_block decision logic."""

    @pytest.mark.parametrize("severity", ["CRITICAL", "HIGH"])
    def test_blocks_on_critical_and_high_severity_regardless_of_signature(self, soar_engine, severity):
        """Critical and High severity alerts should always trigger a block."""
        alert = {
            "severity": severity,
            "signature": "Benign informational message",
        }
        assert soar_engine.should_block(alert) is True

    @pytest.mark.parametrize("severity", ["MEDIUM", "LOW"])
    def test_does_not_block_medium_and_low(self, soar_engine, severity):
        """Medium and Low alerts should not trigger a block."""
        alert = {
            "severity": severity,
            "signature": "Routine connection established",
        }
        assert soar_engine.should_block(alert) is False

    def test_missing_severity_does_not_block(self, soar_engine):
        """Alerts without a severity should not block."""
        alert = {
            "signature": "Routine DNS query",
        }
        assert soar_engine.should_block(alert) is False

    @pytest.mark.parametrize(
        "alert",
        [
            {},
            {"severity": "LOW"},
            {"signature": None, "severity": None},
        ],
    )
    def test_edge_case_alerts_do_not_block(self, soar_engine, alert):
        """Empty alerts, alerts missing signature, and alerts with None values should not block."""
        assert soar_engine.should_block(alert) is False

    @pytest.mark.parametrize(
        "signature",
        [
            "VAJRA DROP Port Scan - SYN",
            "ET SCAN Possible Nmap User-Agent Observed",
            "ET INFO AWS EC2 Instance Metadata Request",
            "SQL Injection, XSS, Command Injection, Traversal, Brute Force, DDoS, Flood, C2, Exfil, Spoof",
        ],
    )
    @pytest.mark.parametrize("severity", ["MEDIUM", "LOW"])
    def test_words_in_the_signature_do_not_decide_a_block(self, soar_engine, severity, signature):
        """Only severity decides; a low priority rule that mentions an attack class is not a ban (#100)."""
        alert = {"severity": severity, "signature": signature}
        assert soar_engine.should_block(alert) is False
