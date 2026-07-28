# Plugin Development Guide

## Overview

Plugins are single-purpose scanning capabilities that integrate into
SentinelForge's plugin loader. They are lighter-weight than full modules —
each plugin typically covers one protocol or service check.

## Quick Start

```python
# my_plugins/my_check.py
from sentinelforge.plugins.base import BasePlugin, PluginResult
from sentinelforge.modules.base import Severity

class MyPlugin(BasePlugin):
    name = "my_check"          # unique, kebab-case
    description = "Checks for X vulnerability"
    category = "web"            # dns|http|ssl|web|osint|cloud|network|auth
    author = "Your Name"
    version = "1.0.0"

    def initialize(self) -> None:
        # Load wordlists, create HTTP clients, etc.
        self.timeout = self._cfg("general.timeout", 10)

    def can_run(self, target) -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind in (TargetType.DOMAIN, TargetType.URL)

    def run(self, target) -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        # ... your check logic ...
        if vulnerability_found:
            result.add_finding(
                self._finding(
                    title="X Vulnerability Detected",
                    severity=Severity.HIGH,
                    target=target,
                    description="Detailed explanation.",
                    evidence=["specific proof string"],
                    recommendation="How to fix it.",
                    references=["https://owasp.org/..."],
                    tags=["web", "x-vuln"],
                    confidence=0.9,
                )
            )
        return result

    def cleanup(self) -> None:
        pass  # close connections, delete temp files
```

## Registering Your Plugin

### Option 1: Drop into built-in plugins directory

Place your plugin file at:
```
sentinelforge/plugins/<category>/plugin.py
```

### Option 2: Custom plugin directory

```yaml
# configs/config.yaml
plugins:
  plugin_dir: /path/to/my/plugins
```

Your package must be importable from that path.

## Plugin Result Fields

```python
PluginResult:
    plugin_name  str         # auto-set from plugin.name
    status       str         # success | partial | failed | skipped
    elapsed      float       # auto-set by engine
    findings     list        # Finding objects
    error        str | None  # auto-set on exception
    metadata     dict        # arbitrary extra data
```

## Finding Severity Guide

| Severity | Use for |
|----------|---------|
| CRITICAL | Remote code execution, auth bypass, credential exposure, LFI |
| HIGH     | XSS confirmed, SQLi, SSRF, default creds, TLS weak |
| MEDIUM   | CORS misconfiguration, missing HSTS, CORS wildcard, open redirect |
| LOW      | Missing minor headers, server version disclosure, self-signed cert |
| INFO     | Informational: subdomains found, tech fingerprint, open ports |

## Confidence Score

Set `confidence` between 0.0 and 1.0:
- `1.0` — confirmed, no false positive possible
- `0.9` — very high confidence (response-based)
- `0.75` — heuristic (pattern match on body)
- `0.5` — possible, requires manual verification

## Accessing Configuration

```python
# Access any config value with a default
timeout = self._cfg("general.timeout", 10)
ua = self._cfg("general.user_agent", "SentinelForge")
proxy = self._cfg("network.proxy")
```

## Testing Your Plugin

```python
from sentinelforge.core.config import ConfigManager
from sentinelforge.core.target import TargetManager

cfg = ConfigManager()
target = TargetManager(resolve=False).add("example.com")

plugin = MyPlugin(cfg)
result = plugin.execute(target)   # use execute(), not run()
print(result.status, result.findings)
```
