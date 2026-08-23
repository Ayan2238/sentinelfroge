# Configuration Guide

## Configuration Hierarchy

Priority (highest wins):

1. Environment variables (`SF_*`)
2. User config file (`~/.config/sentinelforge/config.yaml`)
3. Project config file (`configs/config.yaml`)
4. Built-in defaults

## Base Config (`configs/config.yaml`)

```yaml
general:
  output_dir: output       # where reports and sessions are stored
  log_level: INFO          # DEBUG|INFO|WARNING|ERROR|CRITICAL
  max_threads: 10          # concurrent workers
  timeout: 30              # seconds per request
  user_agent: "SentinelForge/2.0"

network:
  proxy: null              # http://127.0.0.1:8080
  verify_ssl: true
  rate_limit: 10           # requests/second (0 = unlimited)

plugins:
  enabled: [dns, http, ssl, web, osint, network]
  disabled: []

scanning:
  profile: normal          # fast|normal|deep|stealth|web|cloud
  max_depth: 3
  scope: domain

reporting:
  formats: [html, json]
  include_evidence: true

```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SF_LOG_LEVEL` | INFO | Log verbosity |
| `SF_OUTPUT_DIR` | output | Output directory |
| `SF_MAX_THREADS` | 10 | Concurrent workers |
| `SF_TIMEOUT` | 30 | Request timeout (s) |
| `SF_PROXY` | (none) | HTTP proxy URL |
| `SF_PROFILE` | normal | Default scan profile |

## Scan Profiles

| Profile | Use for | Key settings |
|---------|---------|-------------|
| `fast` | Quick triage | threads=15, timeout=10, depth=1 |
| `normal` | Most assessments | threads=10, timeout=30, depth=3 |
| `deep` | Thorough audit | threads=5, timeout=60, depth=5, all plugins |
| `stealth` | Low-noise | threads=2, rate_limit=2, passive plugins only |
| `web` | Web applications | Web/HTTP/SSL/OSINT plugins |
| `network` | Infrastructure | Network/DNS/SSL plugins |
| `cloud` | Cloud assets | Cloud/DNS/HTTP plugins |

## Using a Custom Config

```bash
sf scan example.com --config /path/to/my-config.yaml
```

Or in Python:

```python
from sentinelforge import SentinelForge
sf = SentinelForge(config_path="/path/to/my-config.yaml", profile="deep")
sf.scan("example.com")
```
