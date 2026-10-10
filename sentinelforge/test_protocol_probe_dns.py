import socket
import struct
import threading

from sentinelforge.core.protocol_probe import ProtocolProbe


def _extract_dns_question(request):
    cursor = 12

    while True:
        if cursor >= len(request):
            raise ValueError("truncated DNS question")

        length = request[cursor]
        cursor += 1

        if length == 0:
            break

        if length & 0xC0:
            raise ValueError("unexpected compressed DNS question")

        cursor += length

    if cursor + 4 > len(request):
        raise ValueError("truncated DNS question type/class")

    return request[12:cursor + 4]


def _start_udp_dns_server():
    ready = threading.Event()
    state = {}

    def server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        state["port"] = sock.getsockname()[1]
        ready.set()

        try:
            request, address = sock.recvfrom(4096)
            transaction_id = request[:2]
            question = _extract_dns_question(request)

            response = (
                transaction_id
                + struct.pack("!H", 0x8180)
                + struct.pack("!HHHH", 1, 1, 0, 0)
                + question
                + b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 300, 4)
                + socket.inet_aton("127.0.0.1")
            )

            sock.sendto(response, address)
        finally:
            sock.close()

    threading.Thread(target=server, daemon=True).start()
    assert ready.wait(5)
    return state["port"]


def _start_tcp_dns_server():
    ready = threading.Event()
    state = {}

    def server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        sock.settimeout(5)
        state["port"] = sock.getsockname()[1]
        ready.set()

        conn, _ = sock.accept()
        conn.settimeout(5)

        try:
            length = struct.unpack("!H", conn.recv(2))[0]
            request = conn.recv(length)

            transaction_id = request[:2]
            question = _extract_dns_question(request)

            body = (
                transaction_id
                + struct.pack("!H", 0x8180)
                + struct.pack("!HHHH", 1, 1, 0, 0)
                + question
                + b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 300, 4)
                + socket.inet_aton("127.0.0.1")
            )

            conn.sendall(struct.pack("!H", len(body)) + body)
        finally:
            conn.close()
            sock.close()

    threading.Thread(target=server, daemon=True).start()
    assert ready.wait(5)
    return state["port"]


def _start_dns_truncation_server():
    ready = threading.Event()
    state = {}

    def udp_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        state["port"] = sock.getsockname()[1]
        ready.set()

        try:
            request, address = sock.recvfrom(4096)
            transaction_id = request[:2]
            question = _extract_dns_question(request)

            response = (
                transaction_id
                + struct.pack("!H", 0x8380)
                + struct.pack("!HHHH", 1, 0, 0, 0)
                + question
            )

            sock.sendto(response, address)
        finally:
            sock.close()

    def tcp_server():
        ready.wait(5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", state["port"]))
        sock.listen(1)
        sock.settimeout(5)

        try:
            conn, _ = sock.accept()
            conn.settimeout(5)

            try:
                length = struct.unpack("!H", conn.recv(2))[0]
                request = conn.recv(length)

                transaction_id = request[:2]
                question = _extract_dns_question(request)

                body = (
                    transaction_id
                    + struct.pack("!H", 0x8180)
                    + struct.pack("!HHHH", 1, 1, 0, 0)
                    + question
                    + b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 300, 4)
                    + socket.inet_aton("127.0.0.1")
                )

                conn.sendall(struct.pack("!H", len(body)) + body)
            finally:
                conn.close()
        finally:
            sock.close()

    threading.Thread(target=udp_server, daemon=True).start()
    assert ready.wait(5)

    threading.Thread(target=tcp_server, daemon=True).start()
    return state["port"]


def test_protocol_probe_dns_udp_dispatch():
    port = _start_udp_dns_server()

    result = ProtocolProbe(timeout=2).probe(
        "example.test",
        "127.0.0.1",
        "ipv4",
        port,
        "dns",
        "udp",
    )

    assert result.success is True
    assert result.protocol == "dns"
    assert result.transport == "udp"
    assert result.data["response_code_name"] == "NOERROR"
    assert result.data["answers"][0]["address"] == "127.0.0.1"


def test_protocol_probe_dns_tcp_dispatch():
    port = _start_tcp_dns_server()

    result = ProtocolProbe(timeout=2).probe(
        "example.test",
        "127.0.0.1",
        "ipv4",
        port,
        "dns",
        "tcp",
    )

    assert result.success is True
    assert result.protocol == "dns"
    assert result.transport == "tcp"
    assert result.data["answers"][0]["address"] == "127.0.0.1"


def test_protocol_probe_dns_preserves_structured_observation():
    port = _start_udp_dns_server()

    result = ProtocolProbe(timeout=2).probe(
        "example.test",
        "127.0.0.1",
        "ipv4",
        port,
        "dns",
        "udp",
    )

    assert result.data["target"] == "example.test"
    assert result.data["address"] == "127.0.0.1"
    assert result.data["query_type"] == "A"
    assert result.data["query_class"] == "IN"
    assert result.data["truncated"] is False
    assert result.data["tcp_fallback_attempted"] is False
    assert result.data["tcp_fallback_successful"] is False
    assert result.evidence


def test_protocol_probe_dns_udp_truncation_preserves_tcp_fallback():
    port = _start_dns_truncation_server()

    result = ProtocolProbe(timeout=2).probe(
        "example.test",
        "127.0.0.1",
        "ipv4",
        port,
        "dns",
        "udp",
    )

    assert result.success is True
    assert result.protocol == "dns"
    assert result.data["tcp_fallback_attempted"] is True
    assert result.data["tcp_fallback_successful"] is True
    assert result.data["answers"][0]["address"] == "127.0.0.1"
    assert any("TCP fallback" in item for item in result.evidence)
