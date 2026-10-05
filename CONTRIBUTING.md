# Contributing to Vajra

Thanks for helping. This guide covers how to get set up, how changes are
made, and what happens after you open a pull request.

Questions are welcome on the [Vajra Discord](https://discord.gg/gZTJfUujX).
Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Finding something to work on

Issues labelled `good first issue` are small and self-contained, and say which
files are involved. Comment on an issue before starting so two people do not
pick up the same one. If an issue has had no activity for a week after being
claimed, it is open again.

For anything larger than a bug fix, open an issue first and describe what you
want to change, so the approach can be agreed before you write the code.

## The one rule that matters

Vajra changes the firewall of the machine it runs on. It must never cut that
machine off from its own network: the SOAR engine never blocks loopback, the
host's own addresses, its gateway, its DNS resolvers or anything on the
allowlist, and a rule must never drop traffic the host needs to function.

Any change to the blocking path (`src/vajra/soar/`) or to `rules/local.rules`
must keep that true. Say in the pull request how you checked it, and try it in
`--dry-run` mode first.

## Development setup

The repository has these parts:

| Directory | What it is |
| --- | --- |
| `src/vajra/` | The Python package: SOAR engine, event pipeline, ML management, APIs |
| `src/vajra/experimental/` | Components that exist but are not wired into the pipeline |
| `rules/`, `config/suricata/` | Suricata rules and configuration |
| `scripts/` | Install, start, stop and status scripts |
| `native/dpdk/` | DPDK packet processor in C++ (does not build yet) |
| `tests/perf/` | Resource-consumption and load test harnesses |
| `tools/` | Attack simulator, live monitor and other developer tools |

You need Python 3.10 or later. Most of the code can be worked on without root
or a live network:

```bash
make setup                  # virtualenv + editable install with dev tools
source venv/bin/activate
make lint
```

The SOAR engine can replay a Suricata `eve.json` file in dry-run mode, which
logs every decision without touching the firewall:

```bash
python -m vajra.soar.engine --file-mode --eve path/to/eve.json --dry-run --no-ml
```

Optional features are installed as extras, for example `pip install -e ".[ml]"`
for the TensorFlow and PyTorch models. `make setup-full` installs all of them.

### Running the full pipeline

The live pipeline runs as root, inserts NFQUEUE rules and enables IP
forwarding. Use a disposable Linux VM, never your own machine.

```bash
make install                            # Suricata and system packages
make setup
sudo ./scripts/start.sh --dry-run       # start without enforcing blocks
make status
make stop
```

## Making a change

1. Fork the repository and create a branch from `main`. Name it after the
   kind of change, for example `fix/soar-allowlist-ipv6`,
   `feat/rules-ssh-scan` or `docs/configuration`.
2. Keep the change focused on one thing. Two unrelated fixes are two pull
   requests.
3. Test what you changed and describe how in the pull request.
4. Update the README or docs if you changed behaviour or configuration.

### Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org):

```
type(scope): what the change does, in plain words
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `chore`.
Scopes follow the part of the code: `soar`, `pipeline`, `detection`, `ml`,
`inspection`, `api`, `rules`, `scripts`, `dpdk`, `tools`.

```
fix(soar): never block the default gateway
feat(rules): detect SSH scanning from a single source
```

## Pull requests

- Open the pull request against `main` and link the issue it addresses.
- Describe what changed, why, and how you tested it.
- One maintainer approval is needed to merge.
- Pull requests are squash merged, so the title should itself be a valid
  Conventional Commit message.

## What to expect from review

A maintainer will give a first response within 3 working days. If you have
heard nothing after that, a polite nudge on the pull request or on Discord is
welcome.

Review comments are about the code, not about you. If a change is not going to
be accepted, we will say so and explain why rather than leave it open.

## Licence

Vajra is licensed under the [Apache License 2.0](LICENSE). By contributing,
you agree that your contributions are licensed under the same terms.
