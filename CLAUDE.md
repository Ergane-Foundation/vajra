# CLAUDE.md

Guidance for working in this repository. The full rules live in
[CONTRIBUTING.md](CONTRIBUTING.md); this is the short version.

## How the pieces fit

Suricata inspects traffic on NFQUEUE and writes alerts to `eve.json`. The
SOAR engine reads `eve.json` and turns the alerts into firewall rules on
the host. See [docs/architecture.md](docs/architecture.md) for the full
picture.

## The one rule that matters

Vajra changes the firewall of the machine it runs on. It must never cut
that machine off from its own network: the SOAR engine never blocks
loopback, the host's own addresses, its gateway, its DNS resolvers or
anything on the allowlist, and a rule must never drop traffic the host
needs to function.

Any change to the blocking path (`src/vajra/soar/`) or to
`rules/local.rules` must keep that true. Say in the pull request how you
checked it, and try `--dry-run` mode first.

Never run `scripts/start.sh`, `scripts/install.sh` or anything with
`sudo` outside a disposable VM.

## Rules

Every rule needs an attack pcap that it fires on, and it must stay quiet
on the benign set (#85).

## Not wired in

`src/vajra/experimental/` exists but is not wired into the pipeline or
into blocking, and it should not be treated as part of the live system.

## Commands

```bash
make setup   # virtualenv + editable install with dev tools
make lint
make test
```

## Commit format

Commits follow [Conventional Commits](https://www.conventionalcommits.org):

```text
type(scope): what the change does, in plain words
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `chore`.
Scopes follow the part of the code: `soar`, `pipeline`, `detection`,
`ml`, `inspection`, `api`, `rules`, `scripts`, `dpdk`, `tools`.
