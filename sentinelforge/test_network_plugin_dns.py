"""NetworkPlugin DNS/UDP integration regression tests."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.target import Target, TargetType
from sentinelforge.plugins.network.plugin import NetworkPlugin
import sentinelforge.plugins.network.plugin as network_plugin_module


def _build_dns_response(request: bytes) -> bytes:
    transaction_id = request[:2]
    flags = b"\x81\x80"
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"

    # Copy only the DNS question section, excluding any EDNS additional record.
    offset = 12
    while True:
        if offset >= len(request):
            raise ValueError("Malformed DNS query name")
        label_length = request[offset]
        offset += 1
        if label_length == 0:
            break
        if label_length & 0xC0 or offset + label_length > len(request):
            raise ValueError("Malformed DNS query label")
        offset += label_length

    question_end = offset + 4  # QTYPE and QCLASS
    if question_end > len(request):
        raise ValueError("Incomplete DNS question")
    question = request[12:question_end]

    answer_name = b"\xc0\x0c"
    answer_type_class = b"\x00\x01\x00\x01"
    ttl = b"\x00\x00\x00\x3c"
    address = b"\x7f\x00\x00\x01"
    rdlength = b"\x00\x04"

    return (
        transaction_id
        + flags
        + counts
        + question
        + answer_name
        + answer_type_class
        + ttl
        + rdlength
        + address
    )


def _start_dns_server() -> tuple[socket.socket, threading.Thread, threading.Event, int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(0.2)

    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                request, address = server.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if request:
                try:
                    server.sendto(_build_dns_response(request), address)
                except OSError:
                    break

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    return server, thread, stop, port


def test_network_plugin_discovers_dns_udp(tmp_path: Path) -> None:
    server, thread, stop, dns_port = _start_dns_server()
    original_probe = network_plugin_module.DnsProbe.probe

    def probe_on_test_port(
        self, target, address, address_family, port=53, **kwargs
    ):
        return original_probe(
            self, target, address, address_family, dns_port, **kwargs
        )

    network_plugin_module.DnsProbe.probe = probe_on_test_port

    try:
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            f"""
scanning:
  ports:
    mode: explicit
    ports: [{dns_port}]
    ranges: []
    top: null
    max_workers: 4
    timeout: 1
"""
        )

        config = ConfigManager(config_path=config_path)

        target = Target(
            raw="127.0.0.1",
            kind=TargetType.IP,
            host="127.0.0.1",
            resolved_ips=["127.0.0.1"],
        )

        plugin = NetworkPlugin(config)
        result = plugin.execute(target)

        assert result.status == "success"
        assert result.error is None

        assert result.metadata["dns_udp_addresses_probed"] == 1
        assert result.metadata["dns_udp_responsive"] == 1

        dns_findings = [
            finding
            for finding in result.findings
            if "DNS Service Identified: UDP/53" in finding.title
        ]

        assert len(dns_findings) == 1

        finding = dns_findings[0]
        assert finding.severity.value == "info"
        assert "dns" in finding.tags
        assert "udp" in finding.tags
        assert finding.raw_data["protocol"] == "dns"
        assert finding.raw_data["transport"] == "udp"
        assert finding.raw_data["success"] is True
        assert finding.raw_data["response_code"] == 0
        assert finding.raw_data["query_type"] == "A"
        assert finding.raw_data["answers"]

    finally:
        network_plugin_module.DnsProbe.probe = original_probe
        stop.set()
        server.close()
        thread.join(timeout=1)
