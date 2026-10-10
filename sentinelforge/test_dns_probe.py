import socket
import struct
import threading

from sentinelforge.core.dns_probe import DnsProbe


def encode_name(name):
    return b"".join(
        bytes([len(part)]) + part.encode()
        for part in name.rstrip(".").split(".")
    ) + b"\x00"


def build_dns_response(query):
    txid = query[:2]

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton("127.0.0.1")
    )

    header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", txid)[0],
        0x8180,
        1,
        1,
        0,
        0,
    )

    return header + question + answer


def start_dns_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    ready = threading.Event()

    def worker():
        ready.set()
        try:
            data, address = server.recvfrom(4096)
            response = build_dns_response(data)
            server.sendto(response, address)
        finally:
            server.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    ready.wait()

    return server, thread, port


def test_dns_udp_a_record():
    server, thread, port = start_dns_server()

    observation = DnsProbe(timeout=2).probe(
        "example.test",
        "127.0.0.1",
        "ipv4",
        port,
        transport="udp",
        query_name="example.test",
        query_type="A",
    )

    thread.join(timeout=2)

    assert observation.success is True
    assert observation.transport == "udp"
    assert observation.response_code == 0
    assert observation.response_code_name == "NOERROR"
    assert observation.question_count == 1
    assert observation.answer_count == 1
    assert observation.answers[0]["type"] == "A"
    assert observation.answers[0]["address"] == "127.0.0.1"
    assert observation.answers[0]["ttl"] == 60
    assert observation.flags["qr"] is True
    assert observation.flags["ra"] is True
    assert observation.identification_method == "dns_protocol_response"
    assert observation.confidence == 1.0


def test_dns_udp_timeout_is_structured():
    observation = DnsProbe(timeout=0.1).probe(
        "example.test",
        "127.0.0.1",
        65534,
        transport="udp",
        query_name="example.test",
        query_type="A",
    )

    assert observation.success is False
    assert observation.transport == "udp"
    assert observation.error is not None
    assert observation.identification_method in {
        "timeout",
        "connection_refused",
        "probe_error",
    }


def test_dns_ipv4_query_builder():
    packet = DnsProbe._build_query(
        0x1234,
        "example.test",
        1,
        1,
    )

    txid, flags, qdcount = struct.unpack("!HHH", packet[:6])

    assert txid == 0x1234
    assert flags == 0x0100
    assert qdcount == 1


def test_dns_validation_rejects_invalid_inputs():
    probe = DnsProbe()

    invalid_cases = [
        ("not-an-ip", 53, "udp"),
        ("127.0.0.1", 0, "udp"),
        ("127.0.0.1", 53, "icmp"),
    ]

    for address, port, transport in invalid_cases:
        observation = probe.probe(
            "example.test",
            address,
            "ipv4",
            port,
            transport=transport,
            query_name="example.test",
            query_type="A",
        )

        assert observation.success is False
        assert observation.error is not None


def test_dns_name_compression_and_multiple_record_types():
    probe = DnsProbe()

    query = probe._build_query(
        0x4321,
        "example.test",
        15,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    cname_rdata = b"\x05alias\xc0\x0c"
    cname = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 5, 1, 300, len(cname_rdata))
        + cname_rdata
    )

    mx_rdata = struct.pack("!H", 10) + b"\x04mail\xc0\x0c"
    mx = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 15, 1, 300, len(mx_rdata))
        + mx_rdata
    )

    response = (
        struct.pack("!HHHHHH", 0x4321, 0x8180, 1, 2, 0, 0)
        + question
        + cname
        + mx
    )

    parsed = probe._parse_response(
        response,
        0x4321,
        "example.test",
        "MX",
        "IN",
    )

    assert parsed["answer_count"] == 2
    assert parsed["answers"][0]["type"] == "CNAME"
    assert parsed["answers"][0]["target"] == "alias.example.test"
    assert parsed["answers"][1]["type"] == "MX"
    assert parsed["answers"][1]["preference"] == 10
    assert parsed["answers"][1]["exchange"] == "mail.example.test"


def test_dns_aaaa_record_parser():
    probe = DnsProbe()

    query = probe._build_query(
        0x1111,
        "example.test",
        28,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    address = socket.inet_pton(
        socket.AF_INET6,
        "2001:db8::10",
    )

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 28, 1, 120, 16)
        + address
    )

    response = (
        struct.pack("!HHHHHH", 0x1111, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )

    parsed = probe._parse_response(
        response,
        0x1111,
        "example.test",
        "AAAA",
        "IN",
    )

    assert parsed["answers"][0]["type"] == "AAAA"
    assert parsed["answers"][0]["address"] == "2001:db8::10"
    assert parsed["answers"][0]["ttl"] == 120


def test_dns_txt_record_parser():
    probe = DnsProbe()

    query = probe._build_query(
        0x2222,
        "example.test",
        16,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    txt = b"\x0bhello=world"
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 16, 1, 60, len(txt))
        + txt
    )

    response = (
        struct.pack("!HHHHHH", 0x2222, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )

    parsed = probe._parse_response(
        response,
        0x2222,
        "example.test",
        "TXT",
        "IN",
    )

    assert parsed["answers"][0]["type"] == "TXT"
    assert parsed["answers"][0]["strings"] == ["hello=world"]
    assert parsed["answers"][0]["text"] == "hello=world"


def test_dns_response_codes():
    probe = DnsProbe()

    query = probe._build_query(
        0x3333,
        "missing.example.test",
        1,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    response = (
        struct.pack("!HHHHHH", 0x3333, 0x8183, 1, 0, 0, 0)
        + question
    )

    parsed = probe._parse_response(
        response,
        0x3333,
        "missing.example.test",
        "A",
        "IN",
    )

    assert parsed["response_code"] == 3
    assert parsed["response_code_name"] == "NXDOMAIN"
    assert parsed["authority_count"] == 0


def test_dns_malformed_response_is_rejected():
    probe = DnsProbe()

    malformed = b"\x00\x01\x81"

    try:
        probe._parse_response(
            malformed,
            1,
            "example.test",
            "A",
            "IN",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Malformed DNS response was accepted")


def test_dns_transaction_id_mismatch_is_rejected():
    probe = DnsProbe()

    packet = struct.pack(
        "!HHHHHH",
        0x9999,
        0x8180,
        0,
        0,
        0,
        0,
    )

    try:
        probe._parse_response(
            packet,
            0x1111,
            "example.test",
            "A",
            "IN",
        )
    except ValueError as exc:
        assert "transaction ID mismatch" in str(exc)
    else:
        raise AssertionError("Transaction ID mismatch was accepted")


def test_dns_soa_record_parser():
    probe = DnsProbe()

    query = probe._build_query(
        0x4444,
        "example.test",
        6,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    mname = encode_name("ns1.example.test")
    rname = encode_name("hostmaster.example.test")
    soa_values = struct.pack(
        "!IIIII",
        2026100701,
        3600,
        600,
        86400,
        300,
    )
    rdata = mname + rname + soa_values

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 6, 1, 300, len(rdata))
        + rdata
    )

    response = (
        struct.pack("!HHHHHH", 0x4444, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )

    parsed = probe._parse_response(
        response,
        0x4444,
        "example.test",
        "SOA",
        "IN",
    )

    record = parsed["answers"][0]

    assert record["type"] == "SOA"
    assert record["mname"] == "ns1.example.test"
    assert record["rname"] == "hostmaster.example.test"
    assert record["serial"] == 2026100701
    assert record["refresh"] == 3600
    assert record["retry"] == 600
    assert record["expire"] == 86400
    assert record["minimum"] == 300


def test_dns_srv_record_parser():
    probe = DnsProbe()

    query = probe._build_query(
        0x5555,
        "_service._tcp.example.test",
        33,
        1,
    )

    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5

    question = query[12:question_end]

    target = encode_name("server.example.test")
    rdata = struct.pack("!HHH", 10, 20, 443) + target

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 33, 1, 120, len(rdata))
        + rdata
    )

    response = (
        struct.pack("!HHHHHH", 0x5555, 0x8180, 1, 1, 0, 0)
        + question
        + answer
    )

    parsed = probe._parse_response(
        response,
        0x5555,
        "_service._tcp.example.test",
        "SRV",
        "IN",
    )

    record = parsed["answers"][0]

    assert record["type"] == "SRV"
    assert record["priority"] == 10
    assert record["weight"] == 20
    assert record["port"] == 443
    assert record["target"] == "server.example.test"


def test_dns_tcp_query_framing():
    probe = DnsProbe()

    captured = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, value):
            captured["timeout"] = value

        def connect(self, destination):
            captured["destination"] = destination

        def sendall(self, data):
            captured["sent"] = data

        def recv(self, size):
            if size == 2:
                return struct.pack("!H", 4)
            return b"\x12\x34\x56\x78"

    original_socket = socket.socket

    try:
        socket.socket = lambda *args, **kwargs: FakeSocket()

        response = probe._query_tcp(
            "127.0.0.1",
            53,
            "ipv4",
            b"test",
        )
    finally:
        socket.socket = original_socket

    assert response == b"\x12\x34\x56\x78"
    assert captured["destination"] == ("127.0.0.1", 53)
    assert captured["sent"] == struct.pack("!H", 4) + b"test"
    assert captured["timeout"] == 2.0


def test_dns_tcp_ipv6_destination():
    probe = DnsProbe()

    captured = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, value):
            pass

        def connect(self, destination):
            captured["destination"] = destination

        def sendall(self, data):
            pass

        def recv(self, size):
            if size == 2:
                return struct.pack("!H", 0)
            return b""

    original_socket = socket.socket

    try:
        socket.socket = lambda *args, **kwargs: FakeSocket()

        try:
            probe._query_tcp(
                "::1",
                53,
                "ipv6",
                b"test",
            )
        except ValueError:
            pass
    finally:
        socket.socket = original_socket

    assert captured["destination"] == ("::1", 53, 0, 0)


def test_dns_udp_truncation_triggers_tcp_fallback():
    import threading

    probe = DnsProbe(timeout=1.0)
    udp_ready = threading.Event()
    tcp_ready = threading.Event()

    class UDPHandler:
        pass

    def build_response(query, truncated):
        query_id = struct.unpack("!H", query[:2])[0]
        flags = 0x8200 if truncated else 0x8180
        return (
            struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
            + query[12:]
        )

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    port = udp_sock.getsockname()[1]

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("127.0.0.1", port))
    tcp_sock.listen(1)

    def udp_server():
        udp_ready.set()
        try:
            data, address = udp_sock.recvfrom(4096)
            udp_sock.sendto(build_response(data, True), address)
        finally:
            udp_sock.close()

    def tcp_server():
        tcp_ready.set()
        try:
            conn, _ = tcp_sock.accept()
            with conn:
                length = struct.unpack("!H", conn.recv(2))[0]
                data = b""
                while len(data) < length:
                    chunk = conn.recv(length - len(data))
                    if not chunk:
                        break
                    data += chunk

                response = build_response(data, False)
                conn.sendall(struct.pack("!H", len(response)) + response)
        finally:
            tcp_sock.close()

    udp_thread = threading.Thread(target=udp_server, daemon=True)
    tcp_thread = threading.Thread(target=tcp_server, daemon=True)

    udp_thread.start()
    tcp_thread.start()

    udp_ready.wait(1.0)
    tcp_ready.wait(1.0)

    observation = probe.probe(
        target="example.test",
        address="127.0.0.1",
        address_family="ipv4",
        port=port,
        transport="udp",
        query_name="example.test",
        query_type="A",
        query_class="IN",
    )

    udp_thread.join(1.0)
    tcp_thread.join(1.0)

    assert observation.success is True
    assert observation.truncated is False
    assert observation.tcp_fallback_attempted is True
    assert observation.tcp_fallback_successful is True
    assert any("TCP fallback completed successfully" in item
               for item in observation.evidence)
