"""Regression tests for the eve.json tail loop in SOAREngine.run_file (issue #22)."""

import json
import logging

import pytest


@pytest.fixture
def engine_module(tmp_path, monkeypatch):
    """Import the engine from a scratch directory, since it opens logs/soar_engine.log on import."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import engine

    return engine


@pytest.fixture
def soar_engine(engine_module, monkeypatch):
    """A dry-run engine with Kafka, ML and the other optional integrations switched off."""
    for flag in ("KAFKA_AVAILABLE", "UNIFIED_LOGGER_AVAILABLE", "UBA_AVAILABLE"):
        monkeypatch.setattr(engine_module, flag, False)
    return engine_module.SOAREngine(enable_ml=False, dry_run=True)


@pytest.fixture
def tail(engine_module, soar_engine, tmp_path, monkeypatch):
    """Run run_file over lines appended after it starts watching; return the src_ip of each processed alert."""

    def run(lines, fail_on=None):
        eve_file = tmp_path / "eve.json"
        eve_file.touch()
        processed = []
        written = False

        def process_alert(alert):
            if alert["src_ip"] == fail_on:
                raise RuntimeError("boom")
            processed.append(alert["src_ip"])

        def fake_sleep(_seconds):
            # First poll: append the lines. Second poll: stop the loop the way Ctrl+C would.
            nonlocal written
            if written:
                raise KeyboardInterrupt
            eve_file.write_text("".join(f"{line}\n" for line in lines))
            written = True

        monkeypatch.setattr(soar_engine, "process_alert", process_alert)
        monkeypatch.setattr(engine_module.time, "sleep", fake_sleep)
        soar_engine.run_file(str(eve_file))
        return processed

    return run


def alert(src_ip):
    return json.dumps({"event_type": "alert", "src_ip": src_ip, "alert": {"signature": "test", "severity": 3}})


def test_malformed_line_is_counted_and_logged_at_debug(tail, soar_engine, caplog):
    caplog.set_level(logging.DEBUG, logger="soar_engine")

    processed = tail([alert("10.0.0.1"), "{not json", alert("10.0.0.2")])

    assert processed == ["10.0.0.1", "10.0.0.2"]
    assert soar_engine.malformed_lines == 1
    levels = [r.levelno for r in caplog.records if r.name == "soar_engine" and r.levelno != logging.INFO]
    assert levels == [logging.DEBUG]


@pytest.mark.parametrize("line", ["[1, 2, 3]", '"alert"', "42", "null"])
def test_json_that_is_not_an_object_is_counted_as_malformed(tail, soar_engine, line):
    processed = tail([line, alert("10.0.0.1")])

    assert processed == ["10.0.0.1"]
    assert soar_engine.malformed_lines == 1


def test_process_alert_error_is_logged_with_traceback_and_loop_continues(tail, soar_engine, caplog):
    processed = tail([alert("10.0.0.1"), alert("10.0.0.2")], fail_on="10.0.0.1")

    assert processed == ["10.0.0.2"]
    assert soar_engine.malformed_lines == 0
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert errors[0].exc_info[0] is RuntimeError


def test_non_alert_events_are_skipped_without_being_counted(tail, soar_engine):
    flow = json.dumps({"event_type": "flow", "src_ip": "10.0.0.9"})

    assert tail([flow, alert("10.0.0.1")]) == ["10.0.0.1"]
    assert soar_engine.malformed_lines == 0
