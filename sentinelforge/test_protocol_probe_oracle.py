import socket
import struct
import threading
import time

import pytest

from sentinelforge.core.protocol_probe import ProtocolProbe


def _tns_packet(packet_type, payload=b""):
    length = 8 + len(payload)
    return struct.pack("!HHBBH", length, 0, packet_type, 0, 0) + payload


def _accept_response(
    version=0x0136, sdu=8192, tdu=32767, value_one=1,
    data_length=0, data_offset=0, extended=False,
    value_one_byteorder="big",
):
    payload = bytearray(37 if extended else 24)
    struct.pack_into("!HHHH", payload, 0, version, 0, sdu, tdu)
    payload[8:10] = value_one.to_bytes(2, byteorder=value_one_byteorder)
    struct.pack_into("!HH", payload, 10, data_length, data_offset)
    if extended:
        struct.pack_into("!II", payload, 24, 8192, 32767)
    return _tns_packet(2, bytes(payload))



def _refuse_response(reason=b"\x00\x00"):
    payload = b"\x00\x00" + struct.pack("!H", len(reason)) + reason
    return _tns_packet(4, payload)


def _redirect_response(data=b"(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))"):
    return _tns_packet(5, struct.pack("!H", len(data)) + data)


def _server(response=None, *, delay=0, fragments=False):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)

    port = listener.getsockname()[1]
    state = {}
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                header = bytearray()
                while len(header) < 8:
                    chunk = conn.recv(8 - len(header))
                    if not chunk:
                        raise AssertionError("Client closed before TNS header")
                    header.extend(chunk)

                packet_length = int.from_bytes(header[:2], "big")
                request = bytearray(header)
                while len(request) < packet_length:
                    chunk = conn.recv(packet_length - len(request))
                    if not chunk:
                        raise AssertionError("Client sent truncated TNS request")
                    request.extend(chunk)

                state["request"] = bytes(request)

                if delay:
                    time.sleep(delay)
                if response is not None:
                    if fragments:
                        for byte in response:
                            conn.sendall(bytes([byte]))
                            time.sleep(0.001)
                    else:
                        conn.sendall(response)
        except (OSError, TimeoutError, AssertionError) as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, state, thread, errors


def _join_server(thread, timeout=2):
    thread.join(timeout)
    assert not thread.is_alive(), "Local TNS mock server did not stop"


def _probe(port, *, timeout=1.0, max_body_bytes=8192, service="oracle"):
    return ProtocolProbe(
        timeout=timeout,
        max_body_bytes=max_body_bytes,
    ).probe(
        target="127.0.0.1",
        address="127.0.0.1",
        address_family="ipv4",
        port=port,
        service=service,
        transport="tcp",
    )


@pytest.mark.parametrize(
    ("response", "method", "kind"),
    [
        (_accept_response(), "oracle_tns_accept", "ACCEPT"),
        (_accept_response(value_one_byteorder="little"),
         "oracle_tns_accept", "ACCEPT"),
        (_accept_response(version=0x013B, extended=True), "oracle_tns_accept", "ACCEPT"),
        (
            _tns_packet(
                2,
                _accept_response(
                    version=0x013B, extended=True,
                    data_length=0, data_offset=41,
                )[8:41],
            ),
            "oracle_tns_accept",
            "ACCEPT",
        ),
        (_accept_response(version=0x013E, extended=True), "oracle_tns_accept", "ACCEPT"),
        (_refuse_response(), "oracle_tns_refuse", "REFUSE"),
        (_redirect_response(), "oracle_tns_redirect", "REDIRECT"),
    ],
)
def test_oracle_identifies_valid_tns_responses(response, method, kind):
    port, state, thread, errors = _server(response)

    result = _probe(port)
    _join_server(thread)

    assert not errors
    assert result.success is True
    assert result.protocol == "oracle"
    assert result.identification_method == method
    assert result.data["tns_packet_type_name"] == kind
    assert result.data["credentials_sent"] is False
    assert result.data["sql_executed"] is False

    request = state["request"]
    assert int.from_bytes(request[:2], "big") == len(request)
    assert request[4] == 1  # TNS CONNECT packet
    assert int.from_bytes(request[8:10], "big") == 0x013F  # TNS version 319
    assert int.from_bytes(request[12:14], "big") == 0x0C01  # TNS global options
    assert int.from_bytes(request[10:12], "big") == 0x012C  # Minimum version 300
    assert int.from_bytes(request[18:20], "big") == 0x7F08  # Protocol characteristics
    assert int.from_bytes(request[20:22], "big") == 0  # Line turnaround
    assert request[22:24] in (bytes((0, 1)), bytes((1, 0)))  # Native-order marker
    assert int.from_bytes(request[24:26], "big") > 0  # CONNECT data length
    assert int.from_bytes(request[26:28], "big") == 74  # CONNECT data offset
    assert int.from_bytes(request[28:32], "big") == 512  # 32-bit maximum CONNECT data
    assert request[32:34] == bytes(2)  # CONNECT flags
    assert int.from_bytes(request[50:52], "big") == 0  # Timeout
    assert int.from_bytes(request[54:56], "big") == 0  # Reconnect address length
    assert int.from_bytes(request[56:58], "big") == 0  # Reconnect address offset
    assert int.from_bytes(request[58:62], "big") == 8192  # Large SDU
    assert int.from_bytes(request[62:66], "big") == 32767  # Large TDU
    assert request[66:70] == bytes(4)  # Compression not requested
    assert request[70:74] == bytes(4)  # No optional CONNECT flags2
    descriptor = request[74:]
    declared_length = int.from_bytes(request[24:26], "big")

    assert len(request) == 74 + declared_length
    assert descriptor.startswith(b"(DESCRIPTION=")
    assert descriptor.endswith(b")))")
    assert b"(CONNECT_DATA=(SERVICE_NAME=ORCL))" in descriptor
    assert b"PASSWORD" not in descriptor.upper()
    assert b"(SERVICE_NAME=" in descriptor
    assert descriptor.count(b"(DESCRIPTION=") == 1


@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"\x00\x07\x00\x00\x02\x00\x00\x00",  # length smaller than header
        struct.pack("!HHBBH", 20, 0, 2, 0, 0) + b"\\x00" * 4,  # declares 20 bytes, sends 12
        _tns_packet(6, b"not an Oracle handshake response"),
        _tns_packet(2, b"\x00" * 8),  # truncated ACCEPT body
        _accept_response(version=0x012B),
        _accept_response(value_one=0),
        _accept_response(sdu=0),
        _accept_response(data_length=4, data_offset=31),
        _accept_response(version=0x013B),  # missing extended fields
        _tns_packet(
            2,
            _accept_response(
                version=0x013E, extended=True,
                data_length=0, data_offset=45,
            )[8:41],
        ),  # truncated before the version-318 flags field

        _tns_packet(4, b"\x00\x00\x00\x05x"),  # invalid REFUSE length
        _tns_packet(5),  # incomplete REDIRECT
        _tns_packet(5, b"\x00\x20short"),  # incorrect REDIRECT length
        _tns_packet(5, b"\x00\x04TEST"),  # no address descriptor
    ],
)
def test_oracle_rejects_malformed_or_unexpected_responses(response):
    port, _, thread, _ = _server(response)

    result = _probe(port)
    _join_server(thread)

    assert result.success is False
    assert result.protocol == "oracle"
    assert result.confidence == 0.0
    assert result.error is not None


def test_oracle_reads_fragmented_tns_response():
    port, _, thread, errors = _server(_accept_response(), fragments=True)

    result = _probe(port)
    _join_server(thread)

    assert not errors
    assert result.success is True
    assert result.identification_method == "oracle_tns_accept"


def test_oracle_enforces_response_size_limit():
    response = _tns_packet(5, b"x" * 80)
    port, _, thread, _ = _server(response)

    result = _probe(port, max_body_bytes=64)
    _join_server(thread)

    assert result.success is False
    assert result.error is not None
    assert "size limit" in result.error.lower()


def test_oracle_enforces_response_deadline():
    port, _, thread, _ = _server(_accept_response(), delay=0.2)

    result = _probe(port, timeout=0.05)
    _join_server(thread)

    assert result.success is False
    assert result.error is not None
    assert "deadline" in result.error.lower()


def test_oracle_dispatches_by_service_name():
    port, _, thread, _ = _server(_accept_response())

    result = _probe(port, service="tns")
    _join_server(thread)

    assert result.success is True
    assert result.protocol == "oracle"
    assert result.identification_method == "oracle_tns_accept"
