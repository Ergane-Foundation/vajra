"""Guards the command the RC harness builds for tools/attack_simulator.py.

The load phase used to pass ``--quick``, a flag the simulator does not accept.
argparse exited immediately and the output was discarded, so the load phase
sent no attacks at all. These tests run the exact command the harness builds
against the real simulator, so a flag that does not exist fails here.
"""

import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "tests" / "perf" / "resource" / "rc_test_runner.py"


def _load_runner():
    """Import rc_test_runner, which needs psutil and lives outside the package"""
    pytest.importorskip("psutil")
    spec = importlib.util.spec_from_file_location("rc_test_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rc = _load_runner()


def _dry_run(command):
    """Run the harness command safely, with the local interpreter"""
    runnable = list(command)
    runnable[0] = sys.executable  # the venv lookup is environment specific
    runnable.append("--dry-run")  # prove acceptance without sending anything
    return subprocess.run(
        runnable,
        cwd=str(rc.ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_attack_command_targets_the_simulator():
    command = rc.build_attack_command("192.0.2.10")

    assert command[1] == str(rc.ATTACK_SIMULATOR)
    assert command[2:4] == ["--target", "192.0.2.10"]
    assert "--quick" not in command


def test_attack_command_is_accepted_by_the_simulator():
    result = _dry_run(rc.build_attack_command("127.0.0.1"))

    assert "unrecognized arguments" not in result.stderr
    assert result.returncode == 0, result.stderr


def test_attack_command_reaches_the_attack_suite():
    result = _dry_run(rc.build_attack_command("127.0.0.1"))

    assert "[SQL Injection Tests]" in result.stdout
    assert "[XSS Tests]" in result.stdout


@pytest.fixture
def recorded_logs(monkeypatch):
    """Capture what the harness logs, instead of printing it"""
    entries = []
    monkeypatch.setattr(rc, "log", lambda msg, level="INFO": entries.append((level, msg)))
    return entries


def _use_fake_simulator(monkeypatch, tmp_path, script):
    """Point the harness at a stub simulator that runs the given script"""
    passes_file = tmp_path / "passes.txt"
    monkeypatch.setattr(rc, "ATTACK_SIMULATOR_LOG", tmp_path / "attack_simulator.log")
    monkeypatch.setattr(rc, "ATTACK_GAP", 0)
    monkeypatch.setattr(
        rc,
        "build_attack_command",
        lambda target: [sys.executable, "-c", f"open({str(passes_file)!r}, 'a').write('x')\n{script}"],
    )
    return passes_file


def test_attack_traffic_keeps_the_simulator_output(tmp_path, monkeypatch, recorded_logs):
    passes_file = _use_fake_simulator(
        monkeypatch,
        tmp_path,
        "import sys; sys.stderr.write('boom'); sys.exit(2)",
    )

    simulator = rc.LoadSimulator()
    simulator.running = True
    simulator.generate_attack_traffic(1)

    assert "boom" in (tmp_path / "attack_simulator.log").read_text()
    assert passes_file.read_text()
    assert any(level == "WARNING" for level, _ in recorded_logs)


def test_attack_traffic_repeats_for_the_load_window(tmp_path, monkeypatch):
    passes_file = _use_fake_simulator(monkeypatch, tmp_path, "")

    simulator = rc.LoadSimulator()
    simulator.running = True
    simulator.generate_attack_traffic(2)

    assert len(passes_file.read_text()) > 1


def test_attack_traffic_stops_when_asked(tmp_path, monkeypatch, recorded_logs):
    _use_fake_simulator(monkeypatch, tmp_path, "")

    simulator = rc.LoadSimulator()
    simulator.running = False
    simulator.generate_attack_traffic(60)

    assert any(level == "WARNING" and "No attack traffic" in msg for level, msg in recorded_logs)


def test_attack_pass_is_killed_when_load_is_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "ATTACK_POLL_INTERVAL", 0.1)

    simulator = rc.LoadSimulator()
    simulator.running = False  # stopped part way through the load window

    with open(tmp_path / "attack_simulator.log", "w") as log_file:
        returncode = simulator._run_attack_pass(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            log_file,
            time.time() + 300,
        )

    assert returncode is None