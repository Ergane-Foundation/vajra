import os
import pytest
from vajra.soar.engine import SOAREngine


@pytest.fixture(scope="module")
def soar_engine():
    """Initializes SOAREngine with ML disabled and dry-run mode enabled."""
    os.makedirs("logs", exist_ok=True)
    engine = SOAREngine(enable_ml=False, dry_run=True)
    return engine


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
    def test_does_not_block_medium_and_low_without_keywords(self, soar_engine, severity):
        """Medium and Low alerts without attack keywords should not trigger a block."""
        alert = {
            "severity": severity,
            "signature": "Routine connection established",
        }
        assert soar_engine.should_block(alert) is False

    def test_default_severity_without_keywords_does_not_block(self, soar_engine):
        """Alerts missing severity default to LOW and should not block unless matching a keyword."""
        alert = {
            "signature": "Routine DNS query",
        }
        assert soar_engine.should_block(alert) is False

    @pytest.mark.parametrize(
        "keyword",
        [
            "vajra",
            "sql injection",
            "xss",
            "command injection",
            "traversal",
            "brute force",
            "ddos",
            "flood",
            "c2",
            "exfil",
            "spoof",
            "scan",
        ],
    )
    def test_blocks_every_signature_keyword_even_at_low_severity(self, soar_engine, keyword):
        """Every signature keyword must trigger a block regardless of severity."""
        alert = {
            "severity": "LOW",
            "signature": f"Detected suspicious activity: {keyword} attack pattern",
        }
        assert soar_engine.should_block(alert) is True

    @pytest.mark.parametrize(
        "keyword",
        [
            "vajra",
            "sql injection",
            "xss",
            "command injection",
            "traversal",
            "brute force",
            "ddos",
            "flood",
            "c2",
            "exfil",
            "spoof",
            "scan",
        ],
    )
    def test_keyword_matching_is_case_insensitive(self, soar_engine, keyword):
        """Keyword matching in signatures must be case-insensitive."""
        alert = {
            "severity": "LOW",
            "signature": f"PATTERN MATCH: {keyword.upper()}",
        }
        assert soar_engine.should_block(alert) is True
