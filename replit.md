# SentinelForge

AI-Powered Professional Security Assessment Framework for authorised penetration testing. Modular, extensible, CLI-first.

## Run & Operate

```bash
# Install (from sentinelforge/ directory)
cd sentinelforge && pip install -e "."

# Run a scan
sf scan example.com
sf scan example.com --profile deep --format html json markdown csv

# Check environment
sf doctor

# List plugins
sf plugin list

# View scan history
sf history
```

## Stack

- **Language:** Python 3.11+
- **CLI:** Click + Rich
- **Config:** YAML + `SF_*` environment variable overrides
- **Testing:** pytest (67 tests, all passing)
- **Location:** `sentinelforge/` at workspace root (separate from pnpm monorepo)

## Where things live

```
sentinelforge/
  sentinelforge/          ← Python package
    core/                 ← Engine, Config, Target, Session, Scheduler, Updater
    modules/              ← Recon, Vulnerability, Exploit, PostExploit
    plugins/              ← DNS, HTTP, SSL, Web, OSINT, Cloud, Network
    correlation/          ← De-dup, attack chains, risk scoring
    reporting/            ← HTML, JSON, Markdown, CSV formatters
    logging/              ← Coloured, structured logger
    cli/                  ← `sf` Click CLI
  configs/                ← config.yaml + 6 scan profiles
  tests/                  ← 67 unit tests (core, modules, reporting)
  docs/                   ← architecture, cli-guide, configuration, plugin-dev, troubleshooting
  pyproject.toml          ← `sf` entry point wired here
  Dockerfile              ← Multi-stage, non-root runtime
  docker-compose.yml      ← Scanner + Neo4j + report-viewer
  .env.example            ← All SF_* env vars documented
```

## Architecture decisions

- Every scan passes through `SentinelEngine` — no module or plugin runs directly.
- Modules = full multi-task workflows (recon → vuln → exploit → post-exploit). Plugins = single-purpose protocol checks. Both implement a `initialize → validate/can_run → run → cleanup` lifecycle.
- All credentials via `SF_*` env vars only — zero hard-coded secrets.
- No active exploitation: `ExploitValidationModule` only confirms with harmless probes, never destructive payloads.
- Optional integrations (Shodan, Neo4j) are gated behind config flags; stdlib-only by default.

## Scan Profiles

`fast` · `normal` · `deep` · `stealth` · `web` · `network` · `cloud`

## User preferences

- Pure Python implementation; no Rust rewrite.
- No heavy ML dependencies at runtime.

## Gotchas

- `pip install -e "."` must be run from inside `sentinelforge/` (where `pyproject.toml` lives).
- `sf doctor` shows which optional deps are missing; `dnspython`, `requests`, `jinja2` improve functionality but are not required.
- `configs/` directory must remain alongside the package for profile loading.

## Pointers

- See `sentinelforge/docs/` for architecture, CLI guide, configuration, plugin development, and troubleshooting docs.
- See the `pnpm-workspace` skill for the TypeScript monorepo structure (separate from SentinelForge).
