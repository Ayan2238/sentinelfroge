#!/usr/bin/env python3
"""
SentinelForge local integration verification.

- Runs the existing local protocol and UDP/DNS test suites.
- Reports PASS / FAIL / SKIP per test file.
- Optionally probes explicitly configured database ports on 127.0.0.1.
- Never scans external hosts or sends database credentials, SQL, or writes.
"""

from __future__ import annotations

import glob
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass


ROOT = os.path.dirname(os.path.abspath(__file__))


@dataclass
class Check:
    name: str
    status: str
    detail: str


results: list[Check] = []


def record(name: str, status: str, detail: str) -> None:
    results.append(Check(name, status, detail))
    print(f"[{status:4}] {name}: {detail}", flush=True)


def run_test_file(path: str) -> None:
    name = os.path.relpath(path, ROOT)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", path],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        record(name, "FAIL", "Test process exceeded 180 seconds")
        return
    except Exception as exc:
        record(name, "FAIL", f"Could not run test: {type(exc).__name__}: {exc}")
        return

    output = (proc.stdout or "").strip().splitlines()
    summary = next(
        (
            line.strip()
            for line in reversed(output)
            if any(word in line for word in (
                " passed", " failed", " skipped", " error", " no tests ran"
            ))
        ),
        output[-1].strip() if output else "No output",
    )

    if proc.returncode == 0 and any(" passed" in line for line in output):
        record(name, "PASS", summary)
    elif proc.returncode == 0 and any(" skipped" in line for line in output):
        record(name, "SKIP", summary)
    elif "no tests ran" in " ".join(output).lower():
        record(name, "SKIP", "No pytest tests collected")
    else:
        record(name, "FAIL", summary)
        print("       Last test output:", flush=True)
        for line in output[-8:]:
            print("       " + line, flush=True)


def optional_local_database_checks() -> None:
    """Probe only ports explicitly configured by the user, on loopback."""
    services = (
        ("mysql", "SF_LIVE_MYSQL_PORT", 3306),
        ("mariadb", "SF_LIVE_MARIADB_PORT", None),
        ("postgresql", "SF_LIVE_POSTGRESQL_PORT", 5432),
        ("mssql", "SF_LIVE_MSSQL_PORT", 1433),
        ("mongodb", "SF_LIVE_MONGODB_PORT", 27017),
    )

    configured = [
        (service, env_name, os.environ.get(env_name), default)
        for service, env_name, default in services
        if os.environ.get(env_name)
    ]

    if not configured:
        for service, env_name, _, in services:
            record(
                f"real local {service} server",
                "SKIP",
                f"Not configured; set {env_name} to opt in",
            )
        return

    try:
        from sentinelforge.core.protocol_probe import ProtocolProbe
    except Exception as exc:
        for service, _, _, _ in configured:
            record(
                f"real local {service} server",
                "FAIL",
                f"ProtocolProbe import failed: {type(exc).__name__}: {exc}",
            )
        return

    probe = ProtocolProbe(timeout=3.0, max_body_bytes=8192)

    for service, env_name, raw_port, _ in configured:
        label = f"real local {service} server"
        try:
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")

            # Explicitly restrict the test to IPv4 loopback.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    record(label, "SKIP", f"Nothing listening on 127.0.0.1:{port}")
                    continue

            observation = probe.probe(
                target="127.0.0.1",
                address="127.0.0.1",
                address_family="ipv4",
                port=port,
                service=service,
                transport="tcp",
            )

            success = bool(getattr(observation, "success", False))
            protocol = getattr(observation, "protocol", "unknown")
            data = getattr(observation, "data", {}) or {}
            identity = (
                data.get("server_version")
                or data.get("server_name")
                or data.get("product")
                or data.get("server_response_type")
                or "handshake response received"
            )

            if success:
                record(
                    label,
                    "PASS",
                    f"ProtocolProbe recognized {protocol}; {identity}",
                )
            else:
                error = getattr(observation, "error", None) or "probe did not confirm protocol"
                record(label, "FAIL", str(error))

        except Exception as exc:
            record(label, "FAIL", f"{type(exc).__name__}: {exc}")


def main() -> int:
    print("SentinelForge Local Integration Verification")
    print("Target scope: 127.0.0.1 only; no external scanning")
    print("Protocol test fixtures are simulators, not genuine server compatibility proof.")
    print("-" * 68)

    patterns = (
        "test_protocol_probe_*.py",
        "test_dns_probe.py",
        "test_udp_discovery.py",
        "test_network_plugin_dns.py",
    )

    files: set[str] = set()
    for pattern in patterns:
        files.update(glob.glob(os.path.join(ROOT, pattern)))

    files = {
        path for path in files
        if os.path.isfile(path)
        and not os.path.basename(path).startswith("sentinelforge_live_test")
    }

    if not files:
        record(
            "existing protocol test suites",
            "FAIL",
            "No matching test files found; run this script from the project directory",
        )
    else:
        for path in sorted(files):
            run_test_file(path)

    optional_local_database_checks()

    print("\n" + "=" * 68)
    print("SUMMARY")
    for status in ("PASS", "FAIL", "SKIP"):
        print(f"{status}: {sum(item.status == status for item in results)}")

    failed = [item for item in results if item.status == "FAIL"]
    skipped = [item for item in results if item.status == "SKIP"]

    if skipped:
        print("\nSkipped checks are not counted as passes.")
    if failed:
        print("\nFailed checks:")
        for item in failed:
            print(f"- {item.name}: {item.detail}")

    print("\nNote: passing simulator tests proves the tested handshake path,")
    print("not compatibility with every genuine database-server version.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
