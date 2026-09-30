import socket
import threading

from sentinelforge.core.banner_grabber import BannerGrabber
from sentinelforge.core.service_identifier import ServiceObservation


def service(
    port: int,
    name: str,
    *,
    address: str = "127.0.0.1",
    family: str = "IPv4",
) -> ServiceObservation:
    return ServiceObservation(
        target="127.0.0.1",
        address=address,
        address_family=family,
        port=port,
        transport="tcp",
        service=name,
        protocol=name.lower(),
        identification_method="port_hint",
        confidence=0.5,
        evidence=("test",),
    )


def test_ssh_uses_passive_interaction():
    interaction, payload = BannerGrabber._initial_interaction(service(22, "SSH"))

    assert interaction == "passive"
    assert payload == b""


def test_http_uses_head_request():
    interaction, payload = BannerGrabber._initial_interaction(service(80, "HTTP"))

    assert interaction == "http_head"
    assert payload.startswith(b"HEAD / HTTP/1.0")
    assert b"Connection: close" in payload


def test_unknown_service_does_not_receive_speculative_payload():
    interaction, payload = BannerGrabber._initial_interaction(
        service(49152, "unknown")
    )

    assert interaction == "passive"
    assert payload == b""


def test_grabs_passive_tcp_banner():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 34601))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-TestSSH_1.0\r\n")
        conn.close()
        server.close()

    threading.Thread(target=serve, daemon=True).start()

    result = BannerGrabber(timeout=1).grab(
        [service(34601, "SSH")]
    )

    assert len(result) == 1
    banner = result[0]

    assert banner.error is None
    assert banner.interaction == "passive"
    assert banner.data == b"SSH-2.0-TestSSH_1.0\r\n"
    assert "SSH-2.0-TestSSH_1.0" in banner.text
    assert banner.truncated is False


def test_http_initial_interaction_preserves_response():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 34602))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        request = conn.recv(4096)
        assert request.startswith(b"HEAD / HTTP/1.0")
        conn.sendall(
            b"HTTP/1.0 200 OK\r\n"
            b"Server: TestHTTP/1.0\r\n"
            b"\r\n"
        )
        conn.close()
        server.close()

    threading.Thread(target=serve, daemon=True).start()

    result = BannerGrabber(timeout=1).grab(
        [service(34602, "HTTP")]
    )

    assert len(result) == 1
    banner = result[0]

    assert banner.error is None
    assert banner.interaction == "http_head"
    assert banner.data.startswith(b"HTTP/1.0 200 OK")
    assert "Server: TestHTTP/1.0" in banner.text


def test_connection_failure_is_structured():
    result = BannerGrabber(timeout=0.5).grab(
        [service(34603, "SSH")]
    )

    assert len(result) == 1
    banner = result[0]

    assert banner.data == b""
    assert banner.text == ""
    assert banner.error is not None


def test_ipv6_metadata_is_preserved():
    result = BannerGrabber(timeout=0.5).grab(
        [service(34604, "SSH", address="::1", family="IPv6")]
    )

    assert len(result) == 1
    assert result[0].address == "::1"
    assert result[0].address_family == "IPv6"
