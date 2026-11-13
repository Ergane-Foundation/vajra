"""Unit tests for opt-in Kafka Bridge behavior (#83)."""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_status_module():
    status_path = REPO_ROOT / "scripts" / "status.py"
    spec = importlib.util.spec_from_file_location("vajra_status_script", status_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_status_reports_kafka_as_not_enabled_when_stopped(monkeypatch, capsys):
    status_mod = _load_status_module()
    monkeypatch.setattr(status_mod, "check_process", lambda _proc: False)
    monkeypatch.chdir(Path.cwd())

    status_mod.main()
    out = capsys.readouterr().out

    assert "Suricata: [FAIL] Stopped" in out
    assert "Kafka: [SKIP] Not enabled" in out
    assert "Kafka Bridge: [SKIP] Not enabled" in out
    assert "SOAR Engine: [FAIL] Stopped" in out


def test_status_reports_kafka_bridge_running_when_active(monkeypatch, capsys):
    status_mod = _load_status_module()
    monkeypatch.setattr(
        status_mod,
        "check_process",
        lambda proc: proc in {"kafka.Kafka", "vajra.pipeline.kafka_bridge"},
    )
    monkeypatch.chdir(Path.cwd())

    status_mod.main()
    out = capsys.readouterr().out

    assert "Kafka: [OK] Running" in out
    assert "Kafka Bridge: [OK] Running" in out
