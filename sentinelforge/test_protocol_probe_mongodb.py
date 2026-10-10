import socket
import struct
import threading

import pytest

from sentinelforge.core.protocol_probe import ProtocolProbe


def _read_exact(sock, size):
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            raise ConnectionError("client closed")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def _crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def _doc(ok=1, **extra):
    from bson import BSON
    value = {"ok": ok, "isWritablePrimary": True, "maxWireVersion": 17}
    value.update(extra)
    return BSON.encode(value)


def _response(request_header, document, response_to=None, opcode=2013,
              flags=0, checksum=False):
    request_id = struct.unpack_from("<i", request_header, 4)[0]
    if response_to is None:
        response_to = request_id
    body = struct.pack("<I", flags | (1 if checksum else 0))
    body += b"\x00" + document
    length = 16 + len(body) + (4 if checksum else 0)
    header = struct.pack("<iiii", length, 54321, response_to, opcode)
    packet = header + body
    if checksum:
        packet += struct.pack("<I", _crc32c(packet))
    return packet


def _server(factory):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                header = _read_exact(conn, 16)
                length = struct.unpack_from("<i", header)[0]
                _read_exact(conn, length - 16)
                conn.sendall(factory(header))
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread, errors


def _probe(port):
    probe = ProtocolProbe(timeout=1.5, max_body_bytes=8192)
    return probe.probe(
        target="127.0.0.1",
        address=("127.0.0.1", port),
        address_family=socket.AF_INET,
        port=port,
        transport="tcp",
        service="mongodb",
    )


def test_mongodb_hello_identifies_local_server():
    port, thread, errors = _server(
        lambda h: _response(h, _doc(version="8.0.0"))
    )
    result = _probe(port)
    thread.join(timeout=2)
    assert not errors
    assert result.success is True
    assert result.protocol == "mongodb"
    assert result.identification_method == "mongodb_op_msg_hello"
    assert result.data["version"] == "8.0.0"


def test_mongodb_hello_valid_checksum():
    port, thread, errors = _server(
        lambda h: _response(h, _doc(), checksum=True)
    )
    result = _probe(port)
    thread.join(timeout=2)
    assert not errors
    assert result.success is True


@pytest.mark.parametrize("factory", [
    lambda h: _response(h, _doc(), response_to=999999),
    lambda h: _response(h, _doc(), opcode=2004),
    lambda h: _response(h, _doc(ok=0)),
    lambda h: _response(h, _doc(), flags=2),
])
def test_mongodb_rejects_invalid_response(factory):
    port, thread, _ = _server(factory)
    result = _probe(port)
    thread.join(timeout=2)
    assert result.success is False
    assert result.protocol == "mongodb"
    assert result.error


def test_mongodb_rejects_truncated_response():
    port, thread, _ = _server(
        lambda h: _response(h, _doc())[:-3]
    )
    result = _probe(port)
    thread.join(timeout=2)
    assert result.success is False
    assert result.protocol == "mongodb"


def test_mongodb_rejects_corrupt_checksum():
    def factory(header):
        packet = bytearray(_response(header, _doc(), checksum=True))
        packet[-1] ^= 0xff
        return bytes(packet)

    port, thread, _ = _server(factory)
    result = _probe(port)
    thread.join(timeout=2)
    assert result.success is False
    assert result.protocol == "mongodb"


def test_mongodb_rejects_oversized_frame():
    def factory(request_header):
        request_id = struct.unpack_from("<i", request_header, 4)[0]
        return struct.pack("<iiii", 8193, 54321, request_id, 2013)

    port, thread, _ = _server(factory)
    result = _probe(port)
    thread.join(timeout=2)

    assert result.success is False
    assert result.protocol == "mongodb"
    assert result.error


def test_mongodb_rejects_mismatched_bson_length():
    malformed = struct.pack("<i", 100) + b"\x00" * 5
    port, thread, _ = _server(
        lambda header: _response(header, malformed)
    )
    result = _probe(port)
    thread.join(timeout=2)

    assert result.success is False
    assert result.protocol == "mongodb"
    assert result.error


def test_mongodb_rejects_invalid_bson_document():
    malformed = struct.pack("<i", 5) + b"\x01"
    port, thread, _ = _server(
        lambda header: _response(header, malformed)
    )
    result = _probe(port)
    thread.join(timeout=2)

    assert result.success is False
    assert result.protocol == "mongodb"
    assert result.error


def test_mongodb_dispatches_by_port_without_service_hint():
    port, thread, errors = _server(
        lambda header: _response(header, _doc())
    )
    probe = ProtocolProbe(timeout=1.5, max_body_bytes=8192)

    result = probe.probe(
        target="127.0.0.1",
        address=("127.0.0.1", port),
        address_family=socket.AF_INET,
        port=27017,
        transport="tcp",
        service="unknown",
    )
    thread.join(timeout=2)

    assert not errors
    assert result.success is True
    assert result.protocol == "mongodb"


def test_mongodb_missing_optional_dependency_returns_observation(monkeypatch):
    import builtins

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "bson":
            raise ImportError("simulated missing BSON dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    result = ProtocolProbe(timeout=0.1).probe(
        target="127.0.0.1",
        address=("127.0.0.1", 27017),
        address_family=socket.AF_INET,
        port=27017,
        transport="tcp",
        service="mongodb",
    )

    assert result.success is False
    assert result.protocol == "mongodb"
    assert "mongodb_optional_dependency_missing" in result.error


def test_mongodb_timeout_returns_observation():
    import time

    port, thread, _ = _server(
        lambda header: (time.sleep(0.3) or _response(header, _doc()))
    )
    probe = ProtocolProbe(timeout=0.05, max_body_bytes=8192)

    result = probe.probe(
        target="127.0.0.1",
        address=("127.0.0.1", port),
        address_family=socket.AF_INET,
        port=port,
        transport="tcp",
        service="mongodb",
    )
    thread.join(timeout=2)

    assert result.success is False
    assert result.protocol == "mongodb"
    assert result.error
