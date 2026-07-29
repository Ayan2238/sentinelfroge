# Troubleshooting

## Common Issues

### `sf: command not found`

The `sf` entry point was not installed. Fix:

```bash
pip install sentinelforge          # standard install
# or for development:
pip install -e .
# ensure pip's scripts dir is on PATH:
export PATH="$HOME/.local/bin:$PATH"
```

---

### `ModuleNotFoundError: No module named 'yaml'`

Install the base dependencies:

```bash
pip install "sentinelforge[full]"
```

---

### `ConnectionRefusedError` during scan

The target is not accepting connections. Verify:
- Target is in scope and accepting requests
- No firewall blocking your IP
- Try with `--profile stealth` to reduce rate

---

### SSL verification errors

Disable SSL verification in config:

```yaml
network:
  verify_ssl: false
```

Or per-scan:

```bash
sf scan https://example.com  # verify_ssl defaults to false
```

---

### `PermissionError` writing reports

Ensure the output directory is writable:

```bash
mkdir -p output && chmod 755 output
sf scan example.com --output output
```

---

### Rate limiting / `429 Too Many Requests`

Lower your rate limit:

```yaml
network:
  rate_limit: 2   # requests per second
```

Or use the stealth profile:

```bash
sf scan example.com --profile stealth
```

---

### Shodan integration not working

1. Set your API key:

```bash
export SF_SHODAN_API_KEY=your_key_here
```

2. Confirm it's picked up:

```bash
sf doctor
```

3. Check your Shodan plan has API access.

---

### Neo4j connection refused

1. Ensure Neo4j is running:

```bash
docker compose up neo4j
```

2. Check the Bolt URI:

```bash
export SF_NEO4J_URI=bolt://localhost:7687
export SF_NEO4J_PASSWORD=your_password
```

3. Run `sf doctor` to confirm connectivity.

---

### Scan hangs / never completes

- Lower `max_threads` to reduce load:

```yaml
general:
  max_threads: 3
  timeout: 15
```

- Use `--profile fast` for a quick triage scan
- Check network connectivity to the target

---

### Session resume fails

Ensure the session file still exists:

```bash
ls output/sessions/
sf history
sf resume <session-id>
```

If the session file is corrupted, start a fresh scan.

---

### `sf doctor` output

Run `sf doctor` to diagnose any environment issue — it checks:

| Check | What it verifies |
|-------|-----------------|
| Python version | >= 3.10 |
| Core dependencies | pyyaml, click, rich |
| Optional dependencies | dnspython, requests, shodan, neo4j |
| Config file | Exists, valid YAML, passes validation |
| Output dir | Exists and is writable |
| Shodan key | Present in env (not validity) |
| Neo4j | TCP connectivity to bolt URI |

---

## Debug Logging

```bash
sf scan example.com --verbose
# or
SF_LOG_LEVEL=DEBUG sf scan example.com
```

Log files are written to `output/logs/sentinelforge-<date>.log`.
