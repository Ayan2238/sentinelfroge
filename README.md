# SentinelForge

Professional security assessment framework for authorised security research.

The current implementation is in [`sentinelforge/`](sentinelforge/). It provides a modular CLI for passive reconnaissance, active vulnerability scanning, exploit validation, session management, correlation, and multi-format reporting.

## Quick start

```bash
git clone https://github.com/Ayan2238/sentinelfroge
cd sentinelfroge/sentinelforge
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sf doctor
sf scan example.com
```

Optional integrations use environment variables. Copy the safe template before configuring a local environment:

```bash
cp .env.example .env
```

See [`sentinelforge/README.md`](sentinelforge/README.md) and [`sentinelforge/docs/`](sentinelforge/docs/) for installation, configuration, architecture, plugin development, and reporting details.

## Repository layout

```text
sentinelforge/
├── sentinelforge/       # Python package and CLI
├── tests/               # Automated tests
├── configs/             # Scan configuration and profiles
├── docs/                # Architecture and usage documentation
├── pyproject.toml       # Package metadata and dependencies
└── Dockerfile           # Container build
```

## Responsible use

Use SentinelForge only for systems you own or are explicitly authorised to assess. The authors are not responsible for unauthorised or unlawful use.