"""Tests for the ML branch of AdvancedThreatOrchestrator."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vajra.experimental.engines.orchestrator import AdvancedThreatOrchestrator
from vajra.ml.manager import FeatureExtractor, MLModelManager, ModelConfig

PACKET = {
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "src_port": 1234,
    "dst_port": 80,
    "protocol": "TCP",
    "packet_length": 200,
}


class ThreatManager:
    def predict_all(self, data, data_type="network", exclude_types=None):
        return {"fake": SimpleNamespace(
            is_threat=True, threat_type="ml_detected_threat", confidence=0.9)}


class FailingManager:
    def predict_all(self, data, data_type="network", exclude_types=None):
        raise RuntimeError("boom")


class FakeModel:
    def predict(self, X):
        return [1]

    def predict_proba(self, X):
        return [[0.1, 0.9]]


def make_manager(tmp_dir, model_types):
    manager = MLModelManager(
        models_dir=str(Path(tmp_dir) / "models"),
        log_file=str(Path(tmp_dir) / "ml.json"),
    )
    for name, model_type in model_types.items():
        manager.models[name] = FakeModel()
        manager.configs[name] = ModelConfig(name, "", model_type, [], 0.5, True, "")
        manager.stats["by_model"][name] = {"predictions": 0, "threats": 0}
    return manager


class RecordingManager:
    def __init__(self):
        self.received_data = []
        self.received_data_type = []

    def predict_all(self, data, data_type="network", exclude_types=None):
        self.received_data.append(data)
        self.received_data_type.append(data_type)
        return {}


class TestOrchestratorML(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _make(self, manager):
        o = AdvancedThreatOrchestrator(
            enable_flowprint=False,
            enable_kitsune=False,
            enable_etbert=False,
            enable_stratosphere=False,
            enable_exploit_detection=False,
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

    def test_ml_features_forward_packet_fields(self):
        manager = RecordingManager()
        orchestrator = self._make(manager)
        packet = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_length": 512,
            "flags": 2,
            "ttl": 128,
            "payload": b"malicious_payload_data",
        }
        orchestrator.analyze_packet(packet)
        self.assertEqual(len(manager.received_data), 1)
        data = manager.received_data[0]
        self.assertEqual(data["src_ip"], "192.168.1.50")
        self.assertEqual(data["dst_ip"], "10.0.0.1")
        self.assertEqual(data["flags"], 2)
        self.assertEqual(data["ttl"], 128)
        self.assertEqual(data["payload"], b"malicious_payload_data")

        # Verify extract_network_features uses these fields instead of static defaults
        features = MLModelManager.extract_network_features(data)
        self.assertEqual(features["src_ip"], "192.168.1.50")
        self.assertEqual(features["dst_ip"], "10.0.0.1")
        self.assertEqual(features["flags"], 2)
        self.assertEqual(features["ttl"], 128)
        self.assertEqual(features["payload_size"], len(b"malicious_payload_data"))

        # Verify FeatureExtractor gives identical result
        features_fe = FeatureExtractor.extract_network_features(data)
        self.assertEqual(features, features_fe)

    def test_ml_features_fallback_defaults_when_fields_missing(self):
        manager = RecordingManager()
        orchestrator = self._make(manager)
        packet = {
            "packet_length": 256,
            "protocol": "UDP",
        }
        orchestrator.analyze_packet(packet)
        self.assertEqual(len(manager.received_data), 1)
        data = manager.received_data[0]
        self.assertEqual(data["src_ip"], "")
        self.assertEqual(data["dst_ip"], "")
        self.assertEqual(data["flags"], 0)
        self.assertEqual(data["ttl"], 64)
        self.assertEqual(data["payload"], b"")

        # Verify extract_network_features uses fallback defaults
        features = MLModelManager.extract_network_features(data)
        self.assertEqual(features["src_ip"], "")
        self.assertEqual(features["dst_ip"], "")
        self.assertEqual(features["flags"], 0)
        self.assertEqual(features["ttl"], 64)
        self.assertEqual(features["payload_size"], 0)

    def test_ml_features_fallback_defaults_with_none_values(self):
        manager = RecordingManager()
        orchestrator = self._make(manager)
        packet = {
            "src_ip": None,
            "dst_ip": None,
            "flags": None,
            "ttl": None,
            "payload": None,
        }
        orchestrator.analyze_packet(packet)
        self.assertEqual(len(manager.received_data), 1)
        data = manager.received_data[0]
        self.assertEqual(data["src_ip"], "")
        self.assertEqual(data["dst_ip"], "")
        self.assertEqual(data["flags"], 0)
        self.assertEqual(data["ttl"], 64)
        self.assertEqual(data["payload"], b"")

        features = MLModelManager.extract_network_features(data)
        self.assertEqual(features["src_ip"], "")
        self.assertEqual(features["dst_ip"], "")
        self.assertEqual(features["flags"], 0)
        self.assertEqual(features["ttl"], 64)
        self.assertEqual(features["payload_size"], 0)


    def test_insider_threat_model_is_never_run_on_packets(self):
        manager = make_manager(
            self._tmp.name, {"insider": "insider_threat", "net": "anomaly"}
        )
        result = self._make(manager).analyze_packet(PACKET)
        self.assertIsNotNone(result)
        self.assertNotIn("ml_insider", result.detections)
        self.assertEqual(manager.stats["by_model"]["insider"]["predictions"], 0)

    def test_network_models_still_add_detections(self):
        manager = make_manager(self._tmp.name, {"net": "anomaly", "dos": "ddos"})
        result = self._make(manager).analyze_packet(PACKET)
        self.assertIn("ml_net", result.detections)
        self.assertIn("ml_dos", result.detections)


if __name__ == "__main__":
    unittest.main()
