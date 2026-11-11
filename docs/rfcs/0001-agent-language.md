# RFC 0001: Agent language

Status: accepted
Issue: #88

## Decision

The agent stays in Python through v1.0.

The firewall writer becomes the only part that runs as root. It is a separate
process that the engine talks to over a unix socket. The protocol between them
is part of this decision and does not depend on the language, so either side
can be rewritten later, most likely the writer in Go, without touching the
other.

## Why

A Go rewrite would take months and change nothing users can see before the
v0.2 gate. Everything that exists today is Python, and so are most of the
people who contribute to it.

Go was attractive for two reasons, and both can be handled without a rewrite:

- Packaging. The container image (#104) covers the first installs. A deb with
  a bundled virtualenv covers v1.0.
- A small root process that is easy to audit. That depends on how the code is
  split, not on the language. Moving firewall writes out of the engine (#95)
  gets us that in Python. If the writer ever needs to be a static binary, it
  is the obvious piece to port.

## The writer and its protocol

- The engine decides what to block. The writer only applies decisions and
  owns the firewall state.
- The writer does not trust the engine. It checks every address itself and
  refuses anything in the protected set: loopback, the host's addresses,
  gateways, DNS resolvers and the allowlist. A compromised engine must not be
  able to cut the host off.
- Requests are newline-delimited JSON with a protocol version. There are three
  operations: block (address, ttl, reason), unblock (address) and list.
  Anything else is rejected.
- The socket is only reachable by root and the vajra group, and the writer
  checks the caller's credentials on every connection.
- The writer uses the standard library only. Nothing is unpickled, imported
  from models or loaded from a path an unprivileged user can write to.

## When to revisit

- If the benchmarks (#87) show the Python engine can't keep up with eve.json
  on a 1-core server.
- If the deb packaging for v1.0 doesn't work with a bundled virtualenv.

## Not chosen

- Rewriting the agent in Go now: too expensive, and it holds up v0.2.
- Keeping firewall writes inside the engine: the engine stays root and keeps
  loading models as root (#82).
