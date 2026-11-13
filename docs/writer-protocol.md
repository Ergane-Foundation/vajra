# Firewall writer protocol

The firewall writer (`vajra.soar.writer`) is the only process that changes
the host firewall when Vajra starts with `--writer`. The SOAR engine runs as
an unprivileged user and asks the writer to block or unblock addresses. This
document describes what the two sides say to each other.

## Transport

The writer listens on a unix stream socket, `/run/vajra/writer.sock` by
default. The socket is mode 0660 and group `vajra`, inside `/run/vajra`
(mode 2750, owner root, group `vajra`).

A connection may carry several requests. Each request is one JSON object
ending with a newline, at most 4096 bytes long. The writer answers each
request with one JSON line.

## Requests

Requests use exact keys. A key that is not listed, or a missing required key,
gives `bad_request`.

Block an address:

```json
{"v": 1, "op": "block", "ip": "203.0.113.7", "ttl": 3600, "reason": "ET SCAN ..."}
```

`ttl` is an integer from 0 to 31536000 seconds, where 0 means no expiry.
Booleans are rejected. `reason` is optional and is a string of at most 200
characters. The writer replaces control characters with `?` before logging it.

Unblock an address:

```json
{"v": 1, "op": "unblock", "ip": "203.0.113.7"}
```

List the current blocks:

```json
{"v": 1, "op": "list"}
```

## Responses

A block that succeeds returns the time at which it expires, as a unix time,
or `null` when it does not expire:

```json
{"v": 1, "ok": true, "expires_at": 1730003600.0}
```

An unblock that succeeds returns `{"v": 1, "ok": true}`. Unblocking is
idempotent: an address that is not blocked also gets `ok`.

A list returns the blocks sorted by address:

```json
{"v": 1, "ok": true, "enforcing": true, "backend": "nftables",
 "blocks": [{"ip": "203.0.113.7", "expires_at": 1730003600.0}]}
```

An error has this form:

```json
{"v": 1, "ok": false, "error": "protected", "message": "address cannot be blocked"}
```

The error codes are:

| Code | Meaning |
| --- | --- |
| `forbidden` | The peer credentials were refused. The writer then closes the connection |
| `bad_request` | Bad JSON, not an object, wrong keys or types, or a line that is too long. The connection closes after a line that is too long |
| `unsupported_version` | `v` is not 1 |
| `unknown_op` | `op` is not `block`, `unblock` or `list` |
| `invalid_address` | The address cannot be parsed |
| `protected` | The address must never be blocked |
| `rate_limited` | Too many new blocks in the last minute |
| `not_enforced` | The writer is in dry run, or has no firewall backend |
| `failed` | `nft` or `iptables` reported an error |

## Rules the writer applies

1. The address is parsed with `ipaddress`. An IPv4-mapped IPv6 address is
   folded to IPv4.
2. The writer refuses with `protected` an address that is unspecified,
   loopback, link-local, multicast or reserved, or that lies in the protected
   set. The writer builds that set when it starts from loopback, the
   addresses of the host, its gateways and resolvers, `VAJRA_ALLOWLIST`,
   `--allow` and the current SSH clients.
3. The writer accepts at most a fixed number of new blocks in any rolling 60
   seconds. Blocking an address that is already blocked does not count.
4. The writer owns expiry. It sweeps every 5 seconds, and nftables elements
   also carry a kernel timeout as a backstop.

## Credentials

The writer reads the peer credentials of each connection with `SO_PEERCRED`.
It allows a peer that has uid 0, the same effective uid as the writer, or the
writer's group as its primary group or among its supplementary groups. The
writer reads the supplementary groups from `/proc/<pid>/status`.

## Privileges

`start.sh --writer` runs the writer as the `vajra-writer` user with only
`CAP_NET_ADMIN`, given as an ambient capability. On hosts without nft the
writer stays root, because iptables-legacy takes the root-owned
`/run/xtables.lock`. There, after it has bound the socket, the writer drops
every capability except `CAP_NET_ADMIN` and `CAP_NET_RAW`, which
iptables-legacy needs to open its tables.

`logs/` stays owned by root. The writer owns only `blocked_ips.txt`,
`block_expiry.json` and `writer.log`, which `start.sh` creates for it.

The protected set comes from root through `VAJRA_ALLOWLIST`, because only root
can see the SSH sessions of other users.

## Versioning

`v` is 1. A request with another value gets `unsupported_version`.
