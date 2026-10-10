import socket
import struct
import threading

from sentinelforge.core.protocol_probe import ProtocolProbe


def _mysql_lenenc(value):
    if value < 251:
        return bytes([value])
    if value < 65536:
        return b"\xfc" + struct.pack("<H", value)
    if value < 16777216:
        return b"\xfd" + value.to_bytes(3, "little")
    return b"\xfe" + struct.pack("<Q", value)


def _mysql_greeting(
    server_version="8.0.36",
    capabilities=0x00088200 | 0x00080000 | 0x00000200,
    auth_plugin="caching_sha2_password",
):
    connection_id = 1234
    salt = b"12345678abcdefghijkl"
    lower_caps = capabilities & 0xFFFF
    upper_caps = (capabilities >> 16) & 0xFFFF

    payload = (
        b"\x0a"
        + server_version.encode("ascii")
        + b"\x00"
        + struct.pack("<I", connection_id)
        + salt[:8]
        + b"\x00"
        + struct.pack("<H", lower_caps)
        + b"\x21"
        + struct.pack("<H", 2)
        + struct.pack("<H", upper_caps)
        + bytes([len(salt) + 1])
        + b"\x00" * 10
        + salt[8:]
        + b"\x00"
        + (
            auth_plugin.encode("ascii") + b"\x00"
            if capabilities & 0x00080000
            else b""
        )
    )

    packet = (
        len(payload).to_bytes(3, "little")
        + b"\x00"
        + payload
    )
    return packet


def _start_mysql_server(packet):
    ready = threading.Event()
    state = {}

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5)
        state["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)
        try:
            conn.sendall(packet)
            try:
                state["client_data"] = conn.recv(1024)
            except (socket.timeout, ConnectionResetError):
                state["client_data"] = b""
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)
    return state["port"], state, thread


def test_mysql_handshake_identifies_server_without_authentication():
    packet = _mysql_greeting()
    port, state, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is True
    assert result.protocol == "mysql"
    assert result.identification_method == "mysql_initial_handshake"
    assert result.data["server_version"] == "8.0.36"
    assert result.data["protocol_version"] == 10
    assert result.data["connection_id"] == 1234
    assert result.data["authentication_plugin"] == "caching_sha2_password"
    assert result.data["capabilities"]
    assert result.data["fingerprint"]["protocol"] == "mysql"
    assert result.evidence
    assert not state.get("client_data")


def test_mysql_truncated_handshake_fails_safely():
    packet = b"\x05\x00\x00\x00\x0a\x38"
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0
    assert result.error is not None


def test_mysql_invalid_packet_length_fails_safely():
    packet = b"\xff\xff\xff\x00"
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.error is not None


def test_mysql_non_mysql_greeting_is_not_confirmed():
    packet = b"not a MySQL handshake"
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0


def test_mariadb_family_is_identified_separately():
    packet = _mysql_greeting(server_version="10.11.6-MariaDB")
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mariadb"
    )
    thread.join(2)

    assert result.success is True
    assert result.protocol == "mysql"
    assert result.data["server_family"] == "mariadb"
    assert result.data["server_version"] == "10.11.6-MariaDB"
    assert result.data["fingerprint"]["server_family"] == "mariadb"


def test_mysql_capability_names_match_protocol_bits():
    capabilities = (
        0x00088200  # protocol 4.1, secure connection, plugin auth
        | 0x002000  # transactions
        | 0x020000  # multi-results
        | 0x100000  # connection attributes
    )
    packet = _mysql_greeting(capabilities=capabilities)
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is True
    names = set(result.data["capabilities"])
    assert "protocol_41" in names
    assert "secure_connection" in names
    assert "plugin_auth" in names
    assert "transactions" in names
    assert "multi_results" in names
    assert "connect_attrs" in names
    assert "plugin_auth_lenenc_client_data" not in names


def test_mysql_nonprintable_server_version_is_rejected():
    packet = _mysql_greeting(server_version="8.0\x01")
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0
    assert result.error is not None


def _wrap_mysql_payload(payload, sequence_id=0):
    return (
        len(payload).to_bytes(3, "little")
        + bytes([sequence_id])
        + payload
    )


def test_mysql_unexpected_sequence_id_is_rejected():
    packet = _mysql_greeting()
    packet = packet[:3] + b"\x01" + packet[4:]
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0
    assert "sequence ID" in result.error


def test_mysql_invalid_greeting_filler_is_rejected():
    packet = _mysql_greeting()
    payload = bytearray(packet[4:])
    version_end = payload.index(0, 1)
    filler_offset = version_end + 1 + 4 + 8
    payload[filler_offset] = 1
    packet = _wrap_mysql_payload(bytes(payload))
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0
    assert "filler byte" in result.error


def test_mysql_truncated_authentication_metadata_is_rejected():
    packet = _mysql_greeting()
    payload = packet[4:]
    # Keep the protocol/version/connection ID/salt/filler/lower flags,
    # but truncate the extended handshake metadata.
    version_end = payload.index(0, 1)
    lower_caps_end = version_end + 1 + 4 + 8 + 1 + 2
    truncated_payload = payload[:lower_caps_end + 3]
    packet = _wrap_mysql_payload(truncated_payload)
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "mysql"
    assert result.confidence == 0.0
    assert result.error is not None


def test_mysql_unmarked_version_is_classified_as_compatible():
    packet = _mysql_greeting(server_version="8.0.36")
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is True
    assert result.data["server_family"] == "mysql_compatible"
    assert result.data["fingerprint"]["server_family"] == "mysql_compatible"
    assert "reserved" not in result.data["capabilities"]


def test_mysql_missing_authentication_plugin_terminator_is_rejected():
    packet = _mysql_greeting()
    payload = packet[4:]

    assert payload.endswith(b"\x00")
    malformed_payload = payload[:-1]
    port, _, thread = _start_mysql_server(
        _wrap_mysql_payload(malformed_payload)
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_mysql_inconsistent_authentication_length_is_rejected():
    packet = _mysql_greeting()
    payload = bytearray(packet[4:])

    version_end = payload.index(0, 1)
    lower_caps_end = version_end + 1 + 4 + 8 + 1 + 2
    auth_length_offset = lower_caps_end + 5
    payload[auth_length_offset] = 255

    port, _, thread = _start_mysql_server(
        _wrap_mysql_payload(bytes(payload))
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_mysql_non_ascii_server_version_is_rejected():
    packet = _mysql_greeting()
    payload = bytearray(packet[4:])
    version_end = payload.index(0, 1)
    payload[1:version_end] = b"\xff" + payload[2:version_end]
    packet = _wrap_mysql_payload(bytes(payload))

    port, _, thread = _start_mysql_server(packet)
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0
    assert result.error is not None


def test_mysql_secure_connection_rejects_missing_second_salt():
    packet = _mysql_greeting()
    payload = packet[4:]
    version_end = payload.index(0, 1)
    lower_caps_end = version_end + 1 + 4 + 8 + 1 + 2

    # Keep the mandatory extended fields and reserved bytes,
    # but remove the second authentication-salt segment and plugin name.
    truncated_payload = payload[:lower_caps_end + 1 + 2 + 2 + 1 + 10]
    port, _, thread = _start_mysql_server(
        _wrap_mysql_payload(truncated_payload)
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_mysql_secure_connection_without_plugin_auth_is_supported():
    capabilities = 0x00000200 | 0x00008000
    packet = _mysql_greeting(
        capabilities=capabilities,
        auth_plugin="",
    )
    port, _, thread = _start_mysql_server(packet)

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is True
    assert result.data["capability_flags"] == capabilities
    assert result.data["authentication_plugin"] is None


def test_mysql_nonzero_reserved_handshake_bytes_are_rejected():
    packet = _mysql_greeting()
    payload = bytearray(packet[4:])
    version_end = payload.index(0, 1)
    lower_caps_end = version_end + 1 + 4 + 8 + 1 + 2
    reserved_start = lower_caps_end + 1 + 2 + 2 + 1
    payload[reserved_start] = 1

    port, _, thread = _start_mysql_server(
        _wrap_mysql_payload(bytes(payload))
    )
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_mysql_rejects_unexpected_trailing_handshake_bytes():
    packet = _mysql_greeting()
    payload = packet[4:] + b"\x99"

    port, _, thread = _start_mysql_server(
        _wrap_mysql_payload(payload)
    )
    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "mysql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0
