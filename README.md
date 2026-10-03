# Vajra

**Vajra is an open-source intrusion prevention system that runs Suricata inline and automatically blocks attacking IPs.**

> [!WARNING]
> **Status: v0 (pre-alpha).** Vajra is experimental and not ready for production.
> Live mode runs as root and changes the host's firewall: it inserts NFQUEUE rules and enables IP forwarding.
> Run it in a disposable VM, never on your daily machine or on a server you need to keep reachable.

## How it works

Suricata inspects traffic inline and writes events to `logs/eve.json`. Several small Python services read that file and react to what they find:

```
traffic ─► iptables NFQUEUE ─► Suricata (inline, rules/local.rules)
                                   │ logs/eve.json
          ┌────────────────────────┼──────────────────────────┬──────────────────────┐
          ▼                        ▼                          ▼                      ▼
   SOAR engine              Unified logger             Event stream (FastAPI)   Kafka bridge
   decide → block IP        logs/unified_events.json   ws://localhost:8000      (optional)
   (iptables / nftables)                               /ws/logs
   logs/reports/
```

## Capabilities

| Capability | Status | Where |
|---|---|---|
| Inline IPS with custom Suricata rules | Implemented | `rules/`, `config/suricata/` |
| Automated IP blocking from Suricata alerts | Implemented | `vajra.soar` |
| Unified event log (Suricata + SOAR + ML) | Implemented | `vajra.pipeline.unified_logger` |
| Real-time event stream over WebSocket | Implemented | `vajra.pipeline.eve_watcher` |
| User behaviour analytics (rule-based) | Implemented | `vajra.detection.uba` |
| Kafka export of alerts | Experimental | `vajra.pipeline.kafka_bridge` |
| ML model management and inference API | Experimental | `vajra.ml`, `vajra.api` |
| Scapy deep packet inspection | Experimental | `vajra.inspection` |
| Encrypted-traffic, anomaly and fingerprinting engines | Experimental (not wired) | `vajra.experimental.engines` |
| AI-generated Suricata rules (Gemini) | Experimental (not wired) | `vajra.experimental.rulegen` |
| Federated learning (Flower) | Experimental (not wired) | `vajra.experimental.federated` |
| DPDK packet capture | Roadmap (does not build yet) | `native/dpdk/` |
| Dashboard | Roadmap | — |

- **Implemented:** the component is started by `scripts/start.sh`.
- **Experimental:** the code exists but is unvalidated or not started by default.
- **Roadmap:** planned work.

## Repository layout

```
.
├── src/vajra/               Python package
│   ├── soar/                SOAR engine: alert → decision → firewall block, reports
│   ├── pipeline/            eve.json consumers: event stream, unified logger, Kafka bridge
│   ├── detection/           Detection engines used by SOAR (UBA)
│   ├── ml/                  Model loading and prediction management
│   ├── inspection/          Packet inspection (Scapy, DPDK feature feed)
│   ├── api/                 Inference REST/WebSocket API and its client
│   ├── common/              Shared helpers (paths, network detection)
│   └── experimental/        Engines, AI rule generation, federated learning (not wired)
├── rules/                   Suricata rules (local.rules)
├── config/suricata/         Suricata configuration
├── models/                  Pre-trained model files
├── scripts/                 Install, start, stop, status and diagnostics
│   └── dpdk/                DPDK setup and run scripts
├── native/dpdk/             DPDK packet processor (C++)
├── tests/perf/              Resource-consumption and load test harnesses
└── tools/                   Attack simulator, live monitor, WebSocket client, benchmark
```

## Requirements

- **Linux** (Ubuntu/Debian tested) for live inline mode. macOS can run Suricata in passive pcap mode, without inline blocking.
- Python 3.10+
- Suricata 7+
- Root access (live mode only)
- About 1 GB RAM for the core pipeline. The optional ML components (TensorFlow) need roughly another 1 GB and 3–5 GB of disk.

## Quickstart (Linux VM)

```bash
git clone <repo-url> vajra && cd vajra

make install   # system packages: Suricata, Kafka (sudo)
make setup     # virtualenv + editable install of vajra
make start     # start the pipeline (sudo; modifies the firewall)
make status    # check what is running
make stop      # stop the pipeline (sudo)
```

On macOS, install Suricata with Homebrew (`brew install suricata`), then run `make setup` and `make start`.

Generate some test traffic from another terminal:

```bash
python3 tools/attack_simulator.py --target <vm-ip>
```

### Services and ports

| Service | Port | Started by default |
|---|---|---|
| Suricata (NFQUEUE 0) | — | yes |
| Event stream: `ws://localhost:8000/ws/logs`, `/health` | 8000 | yes |
| Inference API: `/health`, `/models`, `/predict/{model}` | 8001 | yes (`--no-api` to skip) |
| Demo HTTP target (`python -m http.server`) | 80 (8080 on macOS) | yes (`--no-http` to skip) |
| Kafka bridge → `localhost:9092`, topic `suricata-alerts` | — | yes (idle unless Kafka is running) |

> [!CAUTION]
> The demo HTTP server serves the repository directory and binds to all interfaces. Use `--no-http` on any shared network.

### Logs

| File | Contents |
|---|---|
| `logs/eve.json` | Suricata events |
| `logs/unified_events.json` | Combined Suricata, SOAR and ML events |
| `logs/soar_actions.log` | Every SOAR decision |
| `logs/blocked_ips.txt` | IPs blocked by SOAR |
| `logs/reports/` | Per-attack JSON reports |

## Development

```bash
make setup      # venv + pip install -e ".[dev]"
make lint       # ruff
make test       # pytest
```

Every service can run on its own as a module, for example:

```bash
python -m vajra.soar.engine --file-mode --eve logs/eve.json
python -m vajra.pipeline.unified_logger --stats
```

## Roadmap

- Safe defaults: an IP allowlist, a dry-run mode, and expiring blocks.
- An offline demo (Docker Compose + pcap replay) that needs no root.
- Unit tests and CI.
- Validated ML models with model cards.
- Dashboard.
- DPDK capture path.

## License

To be decided before the first public release.
