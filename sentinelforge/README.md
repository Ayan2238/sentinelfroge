# 🛡️ SentinelForge v2.0.0

**Professional Security Assessment Framework**

SentinelForge is a modular, extensible penetration testing and security auditing framework for authorised security assessments. It combines passive reconnaissance, active vulnerability scanning, exploit validation, post-exploitation analysis, and professional reporting into a single cohesive tool.

> ⚠️ **For authorised security assessments only.** Do not use against systems without explicit written permission.

---

## ✨ What's New in v2.0.0

- **Layered architecture** — Core Engine, Module Loader, Plugin Loader, Session Manager, Scheduler, Correlation Engine, Report Engine
- **Standard module interface** — every module implements `initialize → validate → run → cleanup → report`
- **Plugin system** — DNS, HTTP, SSL, Web, OSINT, Cloud, Network plugins; dynamically discoverable
- **Scan profiles** — `fast / normal / deep / stealth / web / network / cloud`
- **Session management** — resume interrupted scans, full history
- **Correlation engine** — de-duplicates findings, detects attack chains, computes risk score (0–100)
- **Multi-format reports** — HTML, JSON, Markdown, CSV, PDF
- **Professional CLI** — `sf scan / report / plugin / profile / history / resume / doctor`
- **Zero hard-coded secrets** — all credentials via environment variables

---

## 🚀 Installation

```bash
# Standard install (CLI + core)
pip install sentinelforge

# With DNS checks
pip install "sentinelforge[dns]"

# With all optional DNS functionality
pip install "sentinelforge[full]"

# Development install
git clone https://github.com/Ayan2238/sentinelfroge
cd sentinelfroge/sentinelforge
pip install -e ".[dev]"
```

---

## ⚡ Quick Start

```bash
# Basic scan
sf scan example.com

# Deep scan with all report formats
sf scan example.com --profile deep --format html json markdown csv pdf

# Web-focused scan
sf scan https://example.com/app --profile web

# Network range scan
sf scan 10.0.0.0/24 --profile network

# Check environment
sf doctor

# View scan history
sf history

# Resume interrupted scan
sf resume <session-id>
```

---

## 📖 CLI Reference

```
sf scan <targets…>       Run a security assessment
  --profile, -p          Scan profile (fast|normal|deep|stealth|web|network|cloud)
  --output, -o           Output directory (default: output/)
  --format, -f           Report format(s): html json markdown csv pdf
  --config, -c           Custom config YAML file
  --verbose, -v          Debug logging
  --quiet, -q            Errors only
  --resume               Resume session by ID

sf report                Re-generate report from session
  --session, -s          Session ID (required)

sf plugin list           List all plugins and their status
sf plugin enable <name>  Enable a plugin
sf plugin disable <name> Disable a plugin

sf profile               List available scan profiles
sf history               Show recent scan history
sf resume <id>           Resume an interrupted scan
sf config --show         Print active configuration
sf doctor                Check environment and dependencies
sf version               Show version
sf update                Check for updates
```

---

## 📄 PDF Reports

PDF reports are built into the reporting engine and require no additional
Python dependency. Select `pdf` with `sf scan` or `sf report`:

```bash
# Generate a PDF during a scan
sf scan example.com --format pdf

# Export a PDF from a completed session
sf report --session <session-id> --format pdf
```

The built-in formatter produces a compact, single-page PDF. Use HTML for
longer reports or richer layout requirements.

---

## 🏗️ Architecture

```
sentinelforge/
├── core/
│   ├── engine.py          ← Central orchestrator (everything passes through here)
│   ├── config.py          ← YAML + env var configuration
│   ├── target.py          ← Target parsing and validation
│   ├── session.py         ← Session lifecycle and persistence
│   ├── module_loader.py   ← Dynamic module discovery
│   ├── plugin_loader.py   ← Dynamic plugin discovery
│   └── scheduler.py       ← Concurrent execution with rate limiting
├── modules/
│   ├── base.py            ← BaseModule interface + Finding + ModuleResult
│   ├── reconnaissance.py  ← DNS, subdomains, ports, CT logs, Wayback
│   ├── vulnerability.py   ← Headers, XSS, SQLi, CORS, cookies, admin paths
│   ├── exploit.py         ← Non-destructive exploit validation
│   └── post_exploit.py    ← Attack paths, data exposure, privesc analysis
├── plugins/
│   ├── base.py            ← BasePlugin interface + PluginResult
│   ├── dns/               ← SPF/DMARC, zone transfer, dangling CNAMEs
│   ├── http/              ← Methods, HTTPS redirect, TRACE
│   ├── ssl/               ← Certificate expiry, weak TLS, hostname mismatch
│   ├── web/               ← Technology fingerprinting, WordPress checks
│   ├── osint/             ← robots.txt, security.txt, API docs
│   ├── cloud/             ← S3 and Azure Blob public access
│   └── network/           ← Banner grabbing, service fingerprinting
├── correlation/
│   └── engine.py          ← De-duplication, attack chains, risk scoring
├── reporting/
│   ├── engine.py          ← Coordinates formatters, writes to disk
│   └── formatters/        ← HTML, JSON, Markdown, CSV, PDF
├── logging/
│   └── logger.py          ← Structured, coloured, session-scoped logging
└── cli/
    └── main.py            ← Click-based CLI (sf command)
configs/
├── config.yaml            ← Base configuration
└── profiles/              ← fast, deep, stealth, web, network, cloud
tests/
├── test_core/             ← Config, Target, Session tests
├── test_modules/          ← Module interface tests
└── test_reporting/        ← Correlation + Report engine tests
```

---

## 🔌 Extending SentinelForge

### Writing a Custom Plugin

```python
from sentinelforge.plugins.base import BasePlugin, PluginResult
from sentinelforge.modules.base import Severity

class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "Does something useful"
    category = "web"

    def initialize(self) -> None:
        # Initialise resources here when the plugin needs them.

    def can_run(self, target) -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind == TargetType.DOMAIN

    def run(self, target) -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        # ... scanning logic ...
        result.add_finding(
            self._finding(
                title="Something Found",
                severity=Severity.MEDIUM,
                target=target,
                description="Details here.",
                recommendation="Fix it.",
            )
        )
        return result

    def cleanup(self) -> None:
        # Release resources here when the plugin needs them.
```

Place the plugin in any Python package and add the path to `configs/config.yaml`:

```yaml
plugins:
  plugin_dir: /path/to/my/plugins
```

---

## ⚙️ Configuration

All settings in `configs/config.yaml`. Override via environment variables:

| Variable | Config Key | Description |
|----------|-----------|-------------|
| `SF_LOG_LEVEL` | `general.log_level` | Logging verbosity |
| `SF_MAX_THREADS` | `general.max_threads` | Concurrent workers |
| `SF_TIMEOUT` | `general.timeout` | Request timeout (s) |
| `SF_PROXY` | `network.proxy` | HTTP proxy URL |
| `SF_PROFILE` | `scanning.profile` | Default scan profile |

---

## 🐳 Docker

```bash
# Build
docker build -t sentinelforge:latest .

# Scan with Docker
docker run --rm -v $(pwd)/output:/output sentinelforge:latest sf scan example.com

# Deep scanner run
docker compose run --rm sf scan example.com --profile deep
docker compose up report-viewer   # view reports at http://localhost:8080
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=sentinelforge --cov-report=html

# Fast tests only (no network)
pytest -m "not network and not slow"
```

---

## 📊 Sample Output

```
[08:31:44] [engine      ] [INFO    ] Scan started  session=a1b2c3d4 targets=['example.com']
[08:31:44] [engine      ] [INFO    ] Scanning target  target=example.com kind=domain
[08:31:47] [engine      ] [SUCCESS ] Scan complete  session=a1b2c3d4 risk_score=42.5 findings=18
[08:31:47] [engine      ] [INFO    ] Report written  format=html path=output/reports/sentinelforge-a1b2c3d4-20260728T083147Z.html
```

Report includes:
- **Executive Summary** with risk score (0–100) and severity distribution
- **Attack Chains** (correlated multi-step paths)
- **All Findings** with evidence, recommendation, references
- **Scan metadata** (session, profile, duration, modules)

---

## 🔑 Security Notes

- Never hard-code API keys — use `.env` or environment variables
- Copy `.env.example` to `.env` and fill in values
- `.env` is in `.gitignore` — never commit it
- Run as a non-root user (Docker image enforces this)

---

## 📜 Legal

This tool is for **authorised penetration testing and security research only**.  
Scanning systems without permission is illegal and unethical.

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-feature`
3. Add tests and ensure `pytest` passes
4. Submit a pull request

---

## 📄 Licence

MIT — see [LICENSE](LICENSE).
