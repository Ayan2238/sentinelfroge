# SentinelForge Architecture

## Overview

SentinelForge follows a layered, clean architecture where every component
communicates through well-defined interfaces. No module executes
independently — everything passes through the central engine.

## Layers

```
┌─────────────────────────────────────────────────────────┐
│                      CLI  (sf)                          │
├─────────────────────────────────────────────────────────┤
│                   Core Engine                            │
│   Config · Session · Target · Scheduler · Updater        │
├───────────────────────────┬─────────────────────────────┤
│       Module Layer        │       Plugin Layer           │
│  Recon · Vuln · Exploit   │  DNS · HTTP · SSL · Web …   │
│  PostExploit              │  OSINT · Cloud · Network     │
├───────────────────────────┴─────────────────────────────┤
│               Correlation Engine                         │
│    De-dup · Attack Chains · Risk Score                   │
├─────────────────────────────────────────────────────────┤
│               Reporting Engine                           │
│    HTML · JSON · Markdown · CSV                         │
├─────────────────────────────────────────────────────────┤
│          Logging  ·  Session Storage                     │
└─────────────────────────────────────────────────────────┘
```

## Scan Workflow

1. **Engine.scan()** — entry point for all scans
2. Config loaded, logging configured, session created
3. Targets parsed and validated via TargetManager
4. For each target:
   - All registered modules executed concurrently via Scheduler
   - All active plugins executed concurrently via Scheduler
   - Findings accumulated in session
5. All findings passed to CorrelationEngine
6. CorrelatedReport generated (de-duplicated, scored, chain-annotated)
7. ReportEngine writes all configured output formats
8. Session marked complete on disk

## Module Interface

Every module must implement:

```python
initialize()  → None        # one-time setup
validate(target) → bool     # can this module run against this target?
run(target, session) → ModuleResult
cleanup()    → None        # release resources
report(result) → dict      # optional custom report hook
```

The engine calls `execute()`, which wraps all lifecycle methods with:
- Timing (elapsed seconds in ModuleResult)
- Error isolation (exception → status="failed", never crashes engine)
- Session state persistence after each module

## Plugin Interface

Plugins are lighter-weight than modules (single protocol/check):

```python
initialize()    → None
can_run(target) → bool
run(target)     → PluginResult
cleanup()       → None
```

## Finding Structure

Every module and plugin returns findings as `Finding` objects:

```
module       – which module found this
title        – short, specific description
severity     – critical / high / medium / low / info
target       – affected host/URL
description  – full explanation
evidence     – list of proof strings
recommendation – remediation advice
references   – CVE links, OWASP, RFC, etc.
confidence   – 0.0–1.0
cve          – list of CVE IDs
cvss         – CVSS score if known
tags         – list of category labels
```

## Correlation Engine

After all modules and plugins complete:

1. **De-duplication** — exact (title + target) duplicate findings removed
2. **Sort by severity** — critical first
3. **Attack chain detection** — pattern-match across finding titles
4. **Risk score** — weighted sum + chain bonus → 0–100
5. **Severity distribution** — counts per level
6. **Statistics** — total findings, modules run, top tags
