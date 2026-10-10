import socket
import struct
import threading
import time

from sentinelforge.core.protocol_probe import ProtocolProbe


def _tds_packet(packet_type, payload, status=1):
    length = len(payload) + 8
    return struct.pack("!BBHHBB", packet_type, status, length, 0, 0, 0) + payload


def _prelogin_response():
    # TDS PRELOGIN response: VERSION, ENCRYPTION, terminator.
    version = b"\x00\x00\x00\x00\x00\x00"
    encryption = b"\x00"
    offset_version = 11
    offset_encryption = offset_version + len(version)
    table = (
        b"\x00" + struct.pack("!HH", offset_version, len(version))
        + b"\x01" + struct.pack("!HH", offset_encryption, len(encryption))
        + b"\xff"
    )
    return _tds_packet(0x04, table + version + encryption)


def _start_tds_server(response):
    ready = threading.Event()
    state = {}

    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            srv.settimeout(5)
            state["port"] = srv.getsockname()[1]
            ready.set()

            try:
                conn, _ = srv.accept()
                with conn:
                    conn.settimeout(3)
                    state["request"] = conn.recv(4096)
                    conn.sendall(response)
            except (OSError, socket.timeout) as exc:
                state["error"] = str(exc)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)
    return state["port"], state, thread


def test_mssql_prelogin_response_identifies_tds_without_authentication():
    port, state, thread = _start_tds_server(_prelogin_response())

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is True
    assert result.protocol == "mssql"
    assert result.data["prelogin_received"] is True
    assert state["request"]
    assert b"\x12" in state["request"]  # TDS PRELOGIN packet type


def test_mssql_rejects_unexpected_tds_packet_type():
    port, _, thread = _start_tds_server(_tds_packet(0x12, b"\xff"))
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)
    assert result.success is False


def test_mssql_reassembles_valid_multi_packet_prelogin_response():
    response = _prelogin_response()[8:]
    split_at = 5
    wire_response = (
        _tds_packet(0x04, response[:split_at], status=0)
        + _tds_packet(0x04, response[split_at:], status=1)
    )
    port, _, thread = _start_tds_server(wire_response)
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is True
    assert result.data["prelogin_received"] is True




def test_mssql_enforces_total_deadline_for_slow_continuation_packets():
    first_packet = _tds_packet(0x04, b"\x00", status=0)
    ready = threading.Event()
    state = {}

    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            srv.settimeout(5)
            state["port"] = srv.getsockname()[1]
            ready.set()

            try:
                conn, _ = srv.accept()
                with conn:
                    conn.settimeout(3)
                    state["request"] = conn.recv(4096)
                    conn.sendall(first_packet)
                    # Send the next header in pieces so individual reads
                    # arrive before the configured per-read timeout.
                    for byte in b"\x04\x01\x00\x09\x00\x00\x00\x00":
                        time.sleep(0.12)
                        conn.sendall(bytes([byte]))
            except (OSError, socket.timeout) as exc:
                state["error"] = str(exc)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)

    started = time.monotonic()
    result = ProtocolProbe(timeout=0.35).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", state["port"], "mssql"
    )
    elapsed = time.monotonic() - started
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "deadline exceeded" in result.error
    assert elapsed < 1.0


def test_mssql_accepts_eom_with_other_status_bits_set():
    response_payload = _prelogin_response()[8:]
    # EOM (0x01) plus another status bit must not be rejected blindly.
    response = _tds_packet(0x04, response_payload, status=0x03)
    port, _, thread = _start_tds_server(response)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is True
    assert result.data["prelogin_received"] is True

def test_mssql_rejects_truncated_continuation_header():
    first_packet = _tds_packet(0x04, b"\x00", status=0)
    # The next packet header is incomplete and the server closes the connection.
    port, _, thread = _start_tds_server(first_packet + b"\x04\x01")
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "Truncated TDS response header" in result.error


def test_mssql_rejects_truncated_continuation_payload():
    first_packet = _tds_packet(0x04, b"\x00", status=0)
    # Declare four payload bytes for packet two, but send only two.
    incomplete_header = struct.pack("!BBHHBB", 0x04, 1, 12, 0, 0, 0)
    port, _, thread = _start_tds_server(
        first_packet + incomplete_header + b"\x00\x00"
    )
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "Truncated TDS PRELOGIN response" in result.error


def test_mssql_rejects_tds_packet_length_smaller_than_header_plus_one_byte():
    invalid_header = struct.pack("!BBHHBB", 0x04, 1, 8, 0, 0, 0)
    port, _, thread = _start_tds_server(invalid_header)
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "Invalid TDS response length" in result.error

def test_mssql_rejects_response_exceeding_configured_body_limit():
    port, _, thread = _start_tds_server(_prelogin_response())
    result = ProtocolProbe(timeout=1.0, max_body_bytes=8).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "exceeds configured size limit" in result.error


def test_mssql_rejects_missing_prelogin_option_terminator():
    malformed = _tds_packet(0x04, b"\x00\x00\x0b\x00\x06" + b"\x00" * 6)
    port, _, thread = _start_tds_server(malformed)
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)
    assert result.success is False


def test_mssql_rejects_out_of_bounds_option_offset():
    payload = b"\x00\xff\xff\x00\x06\xff"
    port, _, thread = _start_tds_server(_tds_packet(0x04, payload))
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)
    assert result.success is False


def test_mssql_prelogin_request_is_well_formed_and_sends_no_login():
    port, state, thread = _start_tds_server(_prelogin_response())
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    request = state["request"]
    assert result.success is True
    assert request[0] == 0x12
    assert struct.unpack("!H", request[2:4])[0] == len(request)
    assert request[1] & 0x01
    # PRELOGIN only: no TDS LOGIN7 or SQL batch packet.
    assert request[0] not in {0x10, 0x01}


def test_mssql_rejects_invalid_encryption_option_value():
    version = b"\x00\x00\x00\x00\x00\x00"
    encryption = b"\x09"
    table_end = 10
    payload = (
        b"\x00" + struct.pack("!HH", table_end, len(version))
        + b"\x01" + struct.pack("!HH", table_end + len(version), 1)
        + b"\xff" + version + encryption
    )
    port, _, thread = _start_tds_server(_tds_packet(0x04, payload))
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)
    assert result.success is False


def test_mssql_rejects_malformed_version_option():
    version = b"\x01\x02"
    encryption = b"\x00"
    table_end = 10
    payload = (
        b"\x00" + struct.pack("!HH", table_end, len(version))
        + b"\x01" + struct.pack("!HH", table_end + len(version), 1)
        + b"\xff" + version + encryption
    )
    port, _, thread = _start_tds_server(_tds_packet(0x04, payload))
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)
    assert result.success is False


def test_mssql_rejects_overlapping_prelogin_option_ranges():
    version = b"\x00" * 6
    encryption = b"\x00"
    # Table ends at offset 11. VERSION [11, 17) and
    # ENCRYPTION [16, 17) overlap at byte 16.
    payload = (
        b"\x00" + struct.pack("!HH", 11, 6)
        + b"\x01" + struct.pack("!HH", 16, 1)
        + b"\xff" + version + encryption
    )
    port, _, thread = _start_tds_server(_tds_packet(0x04, payload))
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mssql"
    )
    thread.join(2)

    assert result.success is False
    assert result.error is not None
    assert "overlapping TDS PRELOGIN option ranges" in result.error