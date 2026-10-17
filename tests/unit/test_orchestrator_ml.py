"""Tests for the ML branch of AdvancedThreatOrchestrator."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vajra.experimental.engines.orchestrator import AdvancedThreatOrchestrator

PACKET = {
    "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": 1234,
    "dst_port": 80, "protocol": "TCP", "packet_length": 200,
}


class ThreatManager:
    def predict_all(self, data, data_type="network"):
        return {"fake": SimpleNamespace(
            is_threat=True, threat_type="ml_detected_threat", confidence=0.9)}


class FailingManager:
    def predict_all(self, data, data_type="network"):
        raise RuntimeError("boom")


class TestOrchestratorML(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _make(self, manager):
        o = AdvancedThreatOrchestrator(
            enable_flowprint=False, enable_kitsune=False, enable_etbert=False,
            enable_stratosphere=False, enable_exploit_detection=False,
            enable_ml_models=False,
        )
        o.config["ml_models"] = True
        o.engines["ml_models"] = manager
        o.assessment_log = Path(self._tmp.name) / "assessments.json"
        return o

    def test_threatening_model_ends_up_in_detections(self):
        result = self._make(ThreatManager()).analyze_packet(PACKET)
        self.assertIsNotNone(result)
        self.assertIn("ml_fake", result.detections)

    def test_ml_failure_is_logged_as_warning(self):
        orchestrator = self._make(FailingManager())
        with self.assertLogs("threat_orchestrator", level="WARNING") as cm:
            result = orchestrator.analyze_packet(PACKET)
        self.assertIsNone(result)
        self.assertTrue(any("ML prediction error" in line for line in cm.output))


if __name__ == "__main__":
    unittest.main()
