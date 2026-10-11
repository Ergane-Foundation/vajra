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
    """Append records or byte chunks between polls; return the src_ip of each processed alert."""

    def run(lines=(), fail_on=None, *, chunks=None, initial=b"", on_poll=None):
        eve_file = tmp_path / "eve.json"
        eve_file.write_bytes(initial)
        processed = []
        writes = iter(chunks if chunks is not None else ["".join(f"{line}\n" for line in lines).encode("utf-8")])

        def process_alert(alert):
            if alert["src_ip"] == fail_on:
                raise RuntimeError("boom")
            processed.append(alert)

        def fake_sleep(_seconds):
            if on_poll is not None:
                on_poll(processed)
            try:
                chunk = next(writes)
            except StopIteration:
                raise KeyboardInterrupt from None
            with eve_file.open("ab") as writer:
                writer.write(chunk)

        monkeypatch.setattr(soar_engine, "process_alert", process_alert)
        monkeypatch.setattr(engine_module.time, "sleep", fake_sleep)
        soar_engine.run_file(str(eve_file))
        return [record["src_ip"] for record in processed]

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


def record_poll(soar_engine, snapshots):
    def observe(records):
        snapshots.append((tuple(record["src_ip"] for record in records), soar_engine.malformed_lines))

    return observe


def test_partial_record_is_retained_across_polls(tail, soar_engine, caplog):
    caplog.set_level(logging.DEBUG, logger="soar_engine")
    first = alert("10.0.0.1").encode("utf-8")
    second = alert("10.0.0.2").encode("utf-8")
    split = first.index(b"10.0.0.1") + 4
    snapshots = []

    processed = tail(
        chunks=[first[:split], b"", first[split:-1], first[-1:] + b"\n" + second + b"\n"],
        on_poll=record_poll(soar_engine, snapshots),
    )

    assert processed == ["10.0.0.1", "10.0.0.2"]
    assert snapshots == [((), 0)] * 4 + [(("10.0.0.1", "10.0.0.2"), 0)]
    assert not [r for r in caplog.records if r.name == "soar_engine" and r.levelno != logging.INFO]


def test_valid_object_waits_for_its_newline(tail, soar_engine):
    record = alert("10.0.0.1").encode("utf-8")
    snapshots = []

    assert tail(
        chunks=[record, b"", b"\n"],
        on_poll=record_poll(soar_engine, snapshots),
    ) == ["10.0.0.1"]
    assert snapshots == [((), 0)] * 3 + [(("10.0.0.1",), 0)]


def test_utf8_character_split_between_polls_is_preserved(tail, soar_engine):
    record = json.dumps(
        {"event_type": "alert", "src_ip": "10.0.0.1", "alert": {"signature": "café"}},
        ensure_ascii=False,
    ).encode("utf-8")
    split = record.index("\u00e9".encode("utf-8")) + 1
    signatures = []

    assert tail(
        chunks=[record[:split], b"", record[split:] + b"\n"],
        on_poll=lambda records: signatures.append([record["signature"] for record in records]),
    ) == ["10.0.0.1"]
    assert signatures == [[], [], [], ["café"]]
    assert soar_engine.malformed_lines == 0


@pytest.mark.parametrize("bad_record", [b"{not json\n", b"\xff\n", b"\n"])
def test_complete_bad_record_is_counted_once_and_does_not_stop_alerts(tail, soar_engine, caplog, bad_record):
    caplog.set_level(logging.DEBUG, logger="soar_engine")
    snapshots = []
    first = alert("10.0.0.1").encode("utf-8") + b"\n"
    second = alert("10.0.0.2").encode("utf-8") + b"\n"

    assert tail(
        chunks=[bad_record + first, b"", second],
        on_poll=record_poll(soar_engine, snapshots),
    ) == ["10.0.0.1", "10.0.0.2"]
    assert snapshots == [((), 0), (("10.0.0.1",), 1), (("10.0.0.1",), 1), (("10.0.0.1", "10.0.0.2"), 1)]
    diagnostics = [r for r in caplog.records if r.name == "soar_engine" and r.levelno != logging.INFO]
    assert len(diagnostics) == 1
    assert diagnostics[0].levelno == logging.DEBUG
    assert diagnostics[0].exc_info is None


def test_bad_fragment_is_not_counted_until_its_newline_arrives(tail, soar_engine):
    snapshots = []

    assert tail(
        chunks=[b"{not json", b"", b"\n" + alert("10.0.0.1").encode("utf-8") + b"\n"],
        on_poll=record_poll(soar_engine, snapshots),
    ) == ["10.0.0.1"]
    assert snapshots == [((), 0)] * 3 + [(("10.0.0.1",), 1)]


@pytest.mark.parametrize("prefix", [b"", alert("10.0.0.9").encode("utf-8") + b"\n", b"{bad old record\n"])
def test_startup_retains_a_fragment_and_skips_complete_existing_records(tail, soar_engine, prefix):
    record = alert("10.0.0.1").encode("utf-8")
    split = record.index(b"10.0.0.1") + 4
    snapshots = []

    assert tail(
        initial=prefix + record[:split],
        chunks=[record[split:] + b"\n"],
        on_poll=record_poll(soar_engine, snapshots),
    ) == ["10.0.0.1"]
    assert snapshots == [((), 0), (("10.0.0.1",), 0)]


def test_startup_retains_a_large_fragment_with_a_split_utf8_character(tail, soar_engine):
    signature = "x" * 10000 + "café"
    record = json.dumps(
        {"event_type": "alert", "src_ip": "10.0.0.1", "alert": {"signature": signature}},
        ensure_ascii=False,
    ).encode("utf-8")
    split = record.index("\u00e9".encode("utf-8")) + 1
    signatures = []

    assert tail(
        initial=alert("10.0.0.9").encode("utf-8") + b"\n" + record[:split],
        chunks=[record[split:] + b"\n"],
        on_poll=lambda records: signatures.append([record["signature"] for record in records]),
    ) == ["10.0.0.1"]
    assert signatures == [[], [signature]]
    assert soar_engine.malformed_lines == 0


def test_file_truncation_resets_the_position(tail, soar_engine, tmp_path):
    old_records = (alert("10.0.0.9").encode("utf-8") + b"\n") * 3
    new_record = alert("10.0.0.1").encode("utf-8") + b"\n"

    def truncate_before_next_poll(records):
        if not records:
            (tmp_path / "eve.json").write_bytes(new_record)

    assert tail(initial=old_records, chunks=[b""], on_poll=truncate_before_next_poll) == ["10.0.0.1"]
    assert soar_engine.malformed_lines == 0
