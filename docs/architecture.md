# Architecture

Vajra is a set of small processes around Suricata. Suricata does the packet
inspection and inline dropping; the Python services read what Suricata writes
and decide what else to do about it.

## Processes

`scripts/start.sh` starts these, in order:

| Process | Module | What it does |
| --- | --- | --- |
| Suricata | external | Inspects traffic from NFQUEUE 0, drops packets matching `drop` rules, writes `logs/eve.json` |
| Demo HTTP target | `python -m http.server` | Serves `logs/www` so the attack simulator has something to hit |
| Unified logger | `vajra.pipeline.unified_logger` | Tails `eve.json` and `ml_predictions.json` into one event log |
| SOAR engine | `vajra.soar.engine` | Tails `eve.json`, decides whether to block the source, applies the block |
| Inference API | `vajra.api.inference` | Serves model predictions over HTTP on port 8001 |
| Event stream | `vajra.pipeline.eve_watcher` | Streams raw `eve.json` events over WebSocket on port 8000 |
| Kafka bridge | `vajra.pipeline.kafka_bridge` | Publishes alerts to the `suricata-alerts` topic. Started only with `--kafka` |

On macOS, `scripts/start_macos.sh` runs Suricata in passive pcap mode. It
detects but cannot drop packets, and the SOAR engine has no firewall to
enforce blocks with.

## Data flow

```
traffic ─► iptables NFQUEUE ─► Suricata ─► logs/eve.json
                                               │
            ┌──────────────────┬───────────────┼──────────────────┐
            ▼                  ▼               ▼                  ▼
       SOAR engine      Unified logger    Event stream      Kafka bridge
            │                  │               │
            ▼                  ▼               ▼
  iptables / nftables   unified_events    ws://127.0.0.1:8000/ws/logs
  logs/blocked_ips.txt      .json
  logs/reports/
```

Every consumer tails `eve.json` independently. There is no broker between
them in the default setup.

`scripts/start.sh` queues IPv6 as well as IPv4, using ip6tables when it is
available. IPv6 forwarding stays off, because enabling it can drop the
host's IPv6 default route.

## How the SOAR engine decides

For each Suricata alert the engine maps Suricata's numeric severity to a
level (1 critical, 2 high, 3 medium, 4 low) and considers blocking the
alert's source IP when any of these holds:

- the severity is critical or high
- an ML model flags the alert as a threat with confidence of at least 0.75
- user behaviour analytics raises a high or critical alert for the user

That only makes the source a candidate. `vajra.soar.policy` then decides
whether it is blocked now:

| Setting | Default | Effect |
| --- | --- | --- |
| threshold | 3 | Alerts from one source within the window before it is blocked. A critical alert, or a critical UBA alert, blocks on the first |
| window | 60 s | How far back alerts are counted |
| cooldown | 300 s | After a block, the same source isn't blocked again for this long; alerts in that time aren't counted |
| max blocks per minute | 20 | Past this, new blocks are skipped and logged as `rate_limited`, on the assumption that the engine is misfiring |

Blocks the ML models and the packet inspector ask for go through the same
policy as high severity alerts. Allowlisted sources are skipped before the policy, so they never use up the
rate limit. Each decision is written to `logs/soar_actions.log` with its
result: `below_threshold`, `cooldown` and `rate_limited` are logged without
a block. The settings come from the `--block-*` flags or the matching
`VAJRA_*` environment variables listed in the README.

Before anything is applied, the source is checked against the allowlist.
Loopback, every address on the host, its IPv4 and IPv6 default gateways, the
nameservers in `/etc/resolv.conf` and, when it exists, `/run/systemd/resolve/resolv.conf`, every `--allow` network, every entry in
`VAJRA_ALLOWLIST` and the client of every SSH session that is logged in when
the engine starts are never blocked. Connections still authenticating don't
count, so a brute force in progress is not protected.

A block is then applied with nftables if the `nft` binary exists, otherwise
with iptables. In `--dry-run` mode, or when no firewall backend exists, the
decision is logged as `not_enforced` and nothing changes on the host.
The SOAR engine creates the nftables table `inet vajra` with IPv4 and IPv6
block sets on start, restores saved blocks, and `scripts/stop.sh` removes it.
With iptables it creates a `VAJRA-BLOCK` chain in iptables and ip6tables
instead, jumped to from the top of INPUT and OUTPUT so blocks apply before
the NFQUEUE rules. `scripts/stop.sh` removes it as well. It also deletes the
`Vajra:` and `NGFW:` INPUT DROP rules that older versions added, and prints
the `iptables -D` command for their untagged OUTPUT DROP rules.

Every decision is appended to `logs/soar_actions.log`, and each applied block
produces a JSON report in `logs/reports/`.

Blocks carry an expiry. The engine sweeps expired blocks every 5 seconds and
logs each one as an `UNBLOCK_IP` record, and each block record has
`expires_at`. nftables elements also get a kernel timeout a few seconds
longer, so blocks still expire while the engine is stopped.

With `--writer`, the engine does not change the firewall itself. It sends
each block to `vajra.soar.writer`, a small process that listens on
`/run/vajra/writer.sock`. The writer checks the protected set again and caps
new blocks per minute, while the engine runs as the unprivileged `vajra` user.
The writer runs as the `vajra-writer` user with only `CAP_NET_ADMIN`. On hosts
without nft it stays root with `CAP_NET_ADMIN` and `CAP_NET_RAW`, because
iptables-legacy takes the root-owned `/run/xtables.lock`. `logs/` stays owned
by root. Each service owns only the files it writes, and the engine owns
`logs/reports/`. The protocol is described in
[writer-protocol.md](writer-protocol.md).

## Experimental components

Code under `src/vajra/experimental/` is not started by any script:

| Package | What it is |
| --- | --- |
| `engines` | Encrypted-traffic, anomaly, fingerprinting, behavioural and exploit-signature engines, plus an orchestrator that combines them |
| `rulegen` | Generates Suricata rules from alerts using Google Gemini |
| `federated` | Flower server and client for federated training |

The DPDK packet processor in `native/dpdk/` is a separate C++ program and
does not build yet.

## Files written at runtime

| Path | Contents |
| --- | --- |
| `logs/eve.json` | Suricata events |
| `logs/unified_events.json` | Combined Suricata, SOAR and ML events |
| `logs/soar_actions.log` | Every SOAR decision and its result |
| `logs/writer.log` | Requests and firewall changes of the firewall writer, with `--writer` |
| `logs/blocked_ips.txt` | IPs the SOAR engine has blocked |
| `logs/block_expiry.json` | Expiry time of each timed block |
| `logs/reports/` | One JSON report per applied block |
| `logs/ml_predictions.json` | ML predictions |
| `config/suricata/suricata.runtime.yaml` | Suricata configuration generated by the start script |
