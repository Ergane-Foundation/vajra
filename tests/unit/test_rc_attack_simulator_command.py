"""Guards the command the RC harness builds for tools/attack_simulator.py.

The load phase used to pass ``--quick``, a flag the simulator does not accept.
argparse exited immediately and the output was discarded, so the load phase
sent no attacks at all. These tests run the exact command the harness builds
against the real simulator, so a flag that does not exist fails here.
"""

import importlib.util
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "tests" / "perf" / "resource" / "rc_test_runner.py"

# The paths the simulator's web attacks use, so the test can tell an attack
# apart from the plain HTTP load
ATTACK_PATH_PREFIXES = ("/?id=", "/?q=", "/file?path=", "/exec?cmd=")
# Starting the simulator imports the vajra package, which takes a couple of
# seconds and varies by machine, so wait on delivery rather than on a timer
ATTACK_DELIVERY_TIMEOUT = 120


def _load_runner():
    """Import rc_test_runner, which needs psutil and lives outside the package"""
    pytest.importorskip("psutil")
    spec = importlib.util.spec_from_file_location("rc_test_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rc = _load_runner()


def _load_attack_simulator():
    """Import the simulator, which prepends src to sys.path on import"""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    spec = importlib.util.spec_from_file_location(
        "attack_simulator", REPO_ROOT / "tools" / "attack_simulator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


attack_simulator = _load_attack_simulator()


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
    command = rc.build_attack_command("192.0.2.10", 8080)

    assert command[1] == str(rc.ATTACK_SIMULATOR)
    assert command[2:4] == ["--target", "192.0.2.10:8080"]
    assert "--quick" not in command


def test_attack_command_uses_the_same_port_as_the_http_load():
    simulator = rc.LoadSimulator()
    command = rc.build_attack_command(simulator.target_ip, simulator.target_port)

    assert command[2:4] == ["--target", f"{simulator.target_ip}:{simulator.target_port}"]
    assert simulator.target_port == rc.HTTP_PORT


def test_attack_command_is_accepted_by_the_simulator():
    result = _dry_run(rc.build_attack_command("127.0.0.1", 8080))

    assert "unrecognized arguments" not in result.stderr
    assert result.returncode == 0, result.stderr


def test_attack_command_reaches_the_attack_suite():
    result = _dry_run(rc.build_attack_command("127.0.0.1", 8080))

    assert "[SQL Injection Tests]" in result.stdout
    assert "[XSS Tests]" in result.stdout


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.100", ("192.168.1.100", None)),
        ("127.0.0.1:8080", ("127.0.0.1", 8080)),
        ("127.0.0.1:1", ("127.0.0.1", 1)),
        ("::1", ("::1", None)),
        ("[::1]:8080", ("[::1]", 8080)),
        ("[::1]", ("[::1]", None)),
    ],
)
def test_simulator_splits_host_and_port(target, expected):
    assert attack_simulator.split_target(target) == expected


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("example.com:not-a-port", "non-numeric port"),
        ("example.com:", "trailing ':' with no port"),
        ("[::1]:", "trailing ':' with no port"),
        ("[::1]:abc", "non-numeric port"),
        ("127.0.0.1:0", "outside 1-65535"),
        ("127.0.0.1:70000", "outside 1-65535"),
        ("[::1", "no closing ']'"),
        ("[::1]junk", "after the IPv6 literal"),
    ],
)
def test_simulator_rejects_unusable_targets(target, message):
    with pytest.raises(ValueError, match=message):
        attack_simulator.split_target(target)


def test_simulator_reports_an_unusable_target_without_a_traceback():
    result = subprocess.run(
        [sys.executable, str(rc.ATTACK_SIMULATOR), "--target", "example.com:not-a-port", "--sqli"],
        cwd=str(rc.ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 2
    assert "non-numeric port" in result.stderr
    assert "Traceback" not in result.stderr


def test_simulator_uses_the_configured_port_for_http_attacks():
    tester = attack_simulator.AttackTester("127.0.0.1", dry_run=True, port=8080)

    assert tester.target == "127.0.0.1"
    assert tester.port == 8080
    assert tester.base_url == "http://127.0.0.1:8080"


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
        lambda target_ip, target_port: [sys.executable, "-c", f"open({str(passes_file)!r}, 'a').write('x')\n{script}"],
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


def _serve(status=200):
    """Start a local HTTP server on an ephemeral port and return it with its hits"""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            self.send_response(status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


def test_http_load_counts_requests_to_the_target(recorded_logs):
    server, received = _serve()
    try:
        simulator = rc.LoadSimulator(target_ip="127.0.0.1", target_port=server.server_address[1])
        simulator.running = True
        simulator.generate_http_traffic(1)
    finally:
        server.shutdown()

    assert received, "no requests reached the target"
    assert any(level == "INFO" and "HTTP requests to" in msg for level, msg in recorded_logs)


def test_http_load_counts_a_server_error_as_delivered(recorded_logs):
    """A load generator only needs the request to arrive, whatever the status"""
    server, received = _serve(status=503)
    try:
        simulator = rc.LoadSimulator(target_ip="127.0.0.1", target_port=server.server_address[1])
        simulator.running = True
        simulator.generate_http_traffic(1)
    finally:
        server.shutdown()

    assert received
    assert any(level == "INFO" and "HTTP requests to" in msg for level, msg in recorded_logs)


def test_http_load_reports_an_unreachable_target(recorded_logs):
    """Nothing is listening on port 1, so every request fails"""
    simulator = rc.LoadSimulator(target_ip="127.0.0.1", target_port=1)
    simulator.running = True
    simulator.generate_http_traffic(1)

    assert any(
        level == "WARNING" and "No HTTP traffic reached" in msg for level, msg in recorded_logs
    )


def test_http_and_attack_load_reach_the_same_target(monkeypatch, tmp_path):
    """Drive the whole LoadSimulator path against one target and port

    The plain HTTP traffic and the attack simulator have to arrive on the same
    host and port, otherwise the pipeline is loaded on one service and attacked
    on another and the load phase measures the wrong thing.

    The wait is for the first attack request rather than for a fixed slice of
    time: the simulator needs a couple of seconds to start before it sends
    anything, and how long that takes depends on the machine.
    """
    received = []
    first_attack = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            if self.path.startswith(ATTACK_PATH_PREFIXES):
                first_attack.set()
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    monkeypatch.setattr(rc, "find_python_interpreter", lambda: sys.executable)
    monkeypatch.setattr(rc, "ATTACK_SIMULATOR_LOG", tmp_path / "attack_simulator.log")

    simulator = rc.LoadSimulator(target_ip="127.0.0.1", target_port=port)
    simulator.running = True
    simulator.generate_http_traffic(1)

    # A long load window, ended as soon as an attack lands rather than on a timer
    attack_thread = threading.Thread(
        target=simulator.generate_attack_traffic, args=(300,), daemon=True
    )
    attack_thread.start()
    try:
        delivered = first_attack.wait(timeout=ATTACK_DELIVERY_TIMEOUT)
    finally:
        simulator.running = False
        attack_thread.join(timeout=30)
        server.shutdown()

    plain = [p for p in received if p == "/"]
    attacks = [p for p in received if p.startswith(ATTACK_PATH_PREFIXES)]

    assert plain, "no plain HTTP traffic reached the target"
    assert delivered, f"no attack traffic reached the target within {ATTACK_DELIVERY_TIMEOUT}s"
    assert attacks, "no attack traffic reached the target"