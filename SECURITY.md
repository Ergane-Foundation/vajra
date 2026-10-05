# Security Policy

## Supported versions

Vajra has not had a stable release yet. Security fixes are made on the
`main` branch only.

## Reporting a vulnerability

Please do not report security problems in public issues, pull requests or
the Discord server.

Report them privately through GitHub instead: open the repository's
**Security** tab and choose **Report a vulnerability**. Only the maintainers
can see the report.

A useful report includes:

- what the problem is and which component it affects (SOAR engine, Suricata
  rules, event stream, inference API, scripts)
- the steps or configuration needed to reproduce it
- what an attacker could do with it
- the commit or version you tested against

Detection gaps are welcome too. If you find traffic that should be blocked
but is not, or a way to make Vajra block the wrong host, report it the same
way.

## What to expect

- We acknowledge a report within 3 working days.
- We confirm or rule out the problem and tell you what we plan to do.
- Once a fix is ready we publish an advisory, and credit you unless you
  would rather stay anonymous.

## Out of scope

- The event stream (port 8000) and inference API (port 8001) have no
  authentication and listen on `127.0.0.1` by default. Exposing them with
  `VAJRA_API_HOST` is a deliberate choice by the operator.
- The demo HTTP target started by `scripts/start.sh` and the tools under
  `tools/` generate attack traffic on purpose, for testing a lab setup.
- Components under `src/vajra/experimental/` are not started by default and
  are documented as unvalidated.
