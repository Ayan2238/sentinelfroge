# CLI Guide

## Installation

```bash
pip install sentinelforge
sf --help
```

---

## Commands

### `sf scan`

Run a security assessment against one or more targets.

```
sf scan [OPTIONS] TARGETS...
```

**Options:**

| Flag | Short | Description |
|------|-------|-------------|
| `--profile` | `-p` | Scan profile: `fast` `normal` `deep` `stealth` `web` `network` `cloud` |
| `--output` | `-o` | Output directory (default: `output/`) |
| `--format` | `-f` | One or more report formats: `html` `json` `markdown` `csv` |
| `--config` | `-c` | Custom config YAML file |
| `--verbose` | `-v` | Enable debug logging |
| `--quiet` | `-q` | Errors only |
| `--resume` | | Resume a previous session (provide session ID) |
| `--module` | `-m` | Run specific modules only (repeatable) |
| `--skip-module` | | Skip a module by name (repeatable) |
| `--no-plugins` | | Disable all plugins |

**Examples:**

```bash
# Quick scan
sf scan example.com

# Deep scan, all formats
sf scan example.com -p deep -f html json markdown csv

# Web app with proxy
SF_PROXY=http://127.0.0.1:8080 sf scan https://example.com/app -p web

# Multiple targets
sf scan example.com api.example.com 192.168.1.0/24

# Stealth scan (low-noise)
sf scan example.com -p stealth -q

# Specific modules only
sf scan example.com -m reconnaissance -m vulnerability

# Resume interrupted scan
sf scan --resume a1b2c3d4
```

---

### `sf report`

Re-generate or export a report from a completed session.

```
sf report [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--session, -s` | Session ID (required) |
| `--format, -f` | Report format(s) |
| `--output, -o` | Output directory |

**Example:**

```bash
sf report -s a1b2c3d4 -f html json
```

---

### `sf plugin`

Manage plugins.

```
sf plugin list              List all plugins with status
sf plugin enable <name>     Enable a plugin
sf plugin disable <name>    Disable a plugin
```

**Example:**

```bash
sf plugin list
sf plugin disable cloud
sf plugin enable osint
```

---

### `sf profile`

List all available scan profiles and their settings.

```bash
sf profile
```

---

### `sf history`

Show recent scan history.

```
sf history [--limit N] [--status STATUS]
```

**Example:**

```bash
sf history
sf history --limit 5
sf history --status completed
```

---

### `sf resume`

Resume an interrupted scan.

```
sf resume <session-id>
```

---

### `sf config`

Inspect the active configuration.

```
sf config --show          Print all active config values
sf config --where         Print config file path
```

---

### `sf doctor`

Check the environment, installed dependencies, and configuration.

```bash
sf doctor
```

Output includes:
- Python version
- Required + optional dependencies
- Config file status
- Output directory permissions
- Optional integrations (Shodan, Neo4j)

---

### `sf version`

Print the installed version.

```bash
sf version
```

---

### `sf update`

Check if a newer version is available on PyPI.

```bash
sf update
```

---

## Environment Variables

All options can be set via env vars instead of CLI flags:

```bash
export SF_LOG_LEVEL=DEBUG
export SF_PROFILE=deep
export SF_OUTPUT_DIR=~/results
sf scan example.com
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (scan complete) |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Scan completed with CRITICAL findings |
| `4` | Scan interrupted / cancelled |
