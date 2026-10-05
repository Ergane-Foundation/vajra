# API reference

Vajra runs two HTTP services. Both listen on `127.0.0.1` by default; set
`VAJRA_API_HOST` to bind elsewhere. Neither has authentication, so do not
expose them on an untrusted network.

## Event stream (port 8000)

Module: `vajra.pipeline.eve_watcher`. Streams Suricata's `logs/eve.json` as it
is written.

### `GET /health`

```json
{"status": "healthy", "watching": "logs/eve.json"}
```

### `GET /stats`

```json
{"active_connections": 1, "file_position": 48213, "file_exists": true}
```

### `WS /ws/logs`

On connect the server sends:

```json
{"type": "connection", "status": "connected", "message": "Live eve.json stream", "timestamp": "..."}
```

After that, every new `eve.json` line is sent as a JSON message, unchanged
from what Suricata wrote (alerts, flows, DNS, stats and so on). Send
`{"type": "ping"}` to receive `{"type": "pong"}`. The server sends
`{"type": "heartbeat"}` when the connection is idle.

`tools/ws_client.py` is a minimal client.

## Inference API (port 8001)

Module: `vajra.api.inference`. Experimental: see [models/README.md](../models/README.md)
for the state of each model. Interactive documentation is served at `/docs`.

### `GET /health`

```json
{"status": "healthy", "models_loaded": 7, "timestamp": "..."}
```

### `GET /models`

A list of loaded models:

```json
[{"name": "domain", "type": "domain", "loaded": true, "last_updated": "...", "version": 1, "metrics": null}]
```

### `POST /predict/{model_type}`

`model_type` is one of `sqli`, `ddos`, `xss`, `general`, `domain`, `gnn` or
`backdoor`. An unknown type returns 404.

Request:

```json
{
  "features": {"payload_length": 512, "dst_port": 80},
  "src_ip": "198.51.100.7",
  "dst_ip": "192.0.2.10",
  "protocol": "TCP",
  "signature": "VAJRA DROP SQL Injection - UNION SELECT"
}
```

Only `features` is required. Response:

```json
{
  "model_name": "sqli",
  "prediction": 1,
  "confidence": 0.91,
  "probabilities": [0.09, 0.91],
  "is_threat": true,
  "threat_type": "sqli",
  "timestamp": "...",
  "inference_time_ms": 3.2
}
```

`prediction` is 0 for benign and 1 for malicious.

### `POST /reload`

Reloads every model from disk in the background:

```json
{"status": "reloading", "message": "Models are being reloaded in background"}
```

### `WS /ws/logs`

Streams events from the unified logger (Suricata alerts, SOAR actions and ML
predictions) as they are recorded.

### `GET /ws/stats`

```json
{"active_connections": 0, "timestamp": "..."}
```
