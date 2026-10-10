import socket
import struct
import threading

from sentinelforge.core.dns_probe import DnsProbe


HOST = "127.0.0.1"


def question_section(packet):
    offset = 12

    while packet[offset] != 0:
        offset += packet[offset] + 1

    offset += 1
    return packet[12:offset + 4]


def build_answer(query, truncated=False, dnssec=False):
    txid = query[:2]
    question = question_section(query)

    flags = 0x8180

    if truncated:
        flags |= 0x0200

    answer = b""

    if not truncated:
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton("127.0.0.1")
        )

    opt_ttl = 0x00008000 if dnssec else 0

    opt = (
        b"\x00"
        + struct.pack("!HHIH", 41, 1232, opt_ttl, 0)
    )

    header = struct.pack(
        "!HHHHHH",
        struct.unpack("!H", txid)[0],
        flags,
        1,
        0 if truncated else 1,
        0,
        1,
    )

    return header + question + answer + opt


class DnsServer:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((HOST, 0))
        self.port = self.udp.getsockname()[1]

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((HOST, self.port))
        self.tcp.listen(5)

        self.stop_event = threading.Event()

        self.udp_thread = threading.Thread(
            target=self.udp_worker,
            daemon=True,
        )
        self.tcp_thread = threading.Thread(
            target=self.tcp_worker,
            daemon=True,
        )

    def start(self):
        self.udp_thread.start()
        self.tcp_thread.start()

    def udp_worker(self):
        while not self.stop_event.is_set():
            self.udp.settimeout(0.2)

            try:
                data, address = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            response = build_answer(
                data,
                truncated=True,
                dnssec=True,
            )

            try:
                self.udp.sendto(response, address)
            except OSError:
                break

    def tcp_worker(self):
        while not self.stop_event.is_set():
            self.tcp.settimeout(0.2)

            try:
                connection, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with connection:
                connection.settimeout(2)

                header = connection.recv(2)

                if len(header) != 2:
                    continue

                size = struct.unpack("!H", header)[0]
                query = b""

                while len(query) < size:
                    chunk = connection.recv(size - len(query))

                    if not chunk:
                        break

                    query += chunk

                if len(query) != size:
                    continue

                response = build_answer(
                    query,
                    truncated=False,
                    dnssec=True,
                )

                connection.sendall(
                    struct.pack("!H", len(response))
                    + response
                )

    def stop(self):
        self.stop_event.set()

        try:
            self.udp.close()
        except OSError:
            pass

        try:
            self.tcp.close()
        except OSError:
            pass

        self.udp_thread.join(timeout=2)
        self.tcp_thread.join(timeout=2)


def main():
    server = DnsServer()
    server.start()

    try:
        print("=== SentinelForge DNS Live Integration Test ===")
        print(f"Server: {HOST}:{server.port}")
        print()

        probe = DnsProbe(
            timeout=2,
            edns_enabled=True,
            edns_udp_payload_size=1232,
            dnssec_ok=True,
        )

        print("[1] UDP DNS probe")

        udp = probe.probe(
            "example.test",
            HOST,
            "ipv4",
            server.port,
            transport="udp",
            query_name="example.test",
            query_type="A",
        )

        print("success:", udp.success)
        print("response_code:", udp.response_code_name)
        print("answers:", udp.answer_count)
        print("truncated:", udp.truncated)
        print("tcp_fallback_attempted:", udp.tcp_fallback_attempted)
        print("tcp_fallback_successful:", udp.tcp_fallback_successful)
        print("EDNS:", udp.edns)
        print("DNSSEC:", udp.dnssec)
        print("evidence:", udp.evidence)
        print()

        assert udp.success
        assert udp.transport == "udp"
        assert udp.response_code == 0
        assert udp.truncated is False
        assert udp.tcp_fallback_attempted is True
        assert udp.tcp_fallback_successful is True
        assert udp.answer_count == 1
        assert udp.answers[0]["address"] == "127.0.0.1"
        assert udp.edns["present"] is True
        assert udp.edns["udp_payload_size"] == 1232
        assert udp.edns["dnssec_ok"] is True

        print("[2] Direct TCP DNS probe")

        tcp = probe.probe(
            "example.test",
            HOST,
            "ipv4",
            server.port,
            transport="tcp",
            query_name="example.test",
            query_type="A",
        )

        print("success:", tcp.success)
        print("response_code:", tcp.response_code_name)
        print("answers:", tcp.answer_count)
        print("EDNS:", tcp.edns)
        print("DNSSEC:", tcp.dnssec)
        print("evidence:", tcp.evidence)
        print()

        assert tcp.success
        assert tcp.transport == "tcp"
        assert tcp.response_code == 0
        assert tcp.answer_count == 1
        assert tcp.answers[0]["address"] == "127.0.0.1"
        assert tcp.edns["present"] is True
        assert tcp.edns["dnssec_ok"] is True

        print("[3] Structured DNSSEC state")
        assert udp.dnssec["present"] is False
        assert tcp.dnssec["present"] is False

        print("DNSSEC record analysis: PASS")
        print("EDNS(0) response parsing: PASS")
        print("DNSSEC OK signaling: PASS")
        print("UDP -> TCP fallback: PASS")
        print()
        print("=== DNS LIVE INTEGRATION TEST PASSED ===")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
