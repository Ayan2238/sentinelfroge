import socket
import threading
import time

import pytest

from sentinelforge.core.protocol_probe import ProtocolProbe


PING_REQUEST = b"*1\r\n$4\r\nPING\r\n"


def _server(response=None, *, delay=0):
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
                request = bytearray()
                while len(request) < len(PING_REQUEST):
                    chunk = conn.recv(len(PING_REQUEST) - len(request))
                    if not chunk:
                        break
                    request.extend(chunk)
                state["request"] = bytes(request)

                if delay:
                    time.sleep(delay)
                if response is not None:
                    conn.sendall(response)
        except (OSError, TimeoutError) as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, state, thread, errors


def _probe(port, *, timeout=1.0, max_body_bytes=8192, service="redis"):
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


def test_redis_ping_identifies_server_without_authentication():
    port, state, thread, errors = _server(b"+PONG\r\n")

    result = _probe(port)
    thread.join(2)

    assert not errors
    assert result.success is True
    assert result.protocol == "redis"
    assert result.identification_method == "redis_resp_ping"
    assert result.confidence == 0.99
    assert result.data["command"] == "PING"
    assert result.data["response"] == "PONG"
    assert result.data["authentication_attempted"] is False
    assert state["request"] == PING_REQUEST
    assert result.evidence


def test_redis_recognized_noauth_reply_identifies_protected_service():
    port, _, thread, errors = _server(
        b"-NOAUTH Authentication required.\r\n"
    )

    result = _probe(port)
    thread.join(2)

    assert not errors
    assert result.success is True
    assert result.protocol == "redis"
    assert result.identification_method == "redis_resp_error_reply"
    assert result.data["server_error_code"] == "NOAUTH"


@pytest.mark.parametrize(
    "response",
    [
        b"-ERR unknown command\r\n",
        b"HTTP/1.1 200 OK\r\n",
        b"PONG\r\n",
        b":1\r\n",
        b"",
    ],
)
def test_redis_rejects_ambiguous_or_invalid_responses(response):
    port, _, thread, _ = _server(response)

    result = _probe(port)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None


def test_redis_rejects_truncated_resp_line():
    port, _, thread, _ = _server(b"+PON")

    result = _probe(port)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.error is not None


def test_redis_rejects_response_line_over_configured_limit():
    port, _, thread, _ = _server(b"+" + b"A" * 100 + b"\r\n")

    result = _probe(port, max_body_bytes=32)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert "size limit" in result.error


def test_redis_response_timeout_returns_failure_observation():
    port, _, thread, _ = _server(b"+PONG\r\n", delay=0.25)

    result = _probe(port, timeout=0.05)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None


def test_redis_service_alias_dispatches_probe():
    port, _, thread, errors = _server(b"+PONG\r\n")

    result = _probe(port, service="redis-server")
    thread.join(2)

    assert not errors
    assert result.success is True
    assert result.protocol == "redis"


def test_redis_connection_refusal_returns_failure_observation():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()

    result = _probe(port, timeout=0.5)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.identification_method == "redis_resp_invalid"
    assert result.error is not None


@pytest.mark.parametrize(
    ("response", "error_code"),
    [
        (b"-NOPERM this user has no permissions to run the command\r\n", "NOPERM"),
        (b"-DENIED Redis is running in protected mode\r\n", "DENIED"),
        (b"-LOADING Redis is loading the dataset in memory\r\n", "LOADING"),
        (b"-MASTERDOWN Link with MASTER is down\r\n", "MASTERDOWN"),
    ],
)
def test_redis_recognizes_additional_ping_error_replies(response, error_code):
    port, _, thread, errors = _server(response)

    result = _probe(port)
    thread.join(2)

    assert not errors
    assert result.success is True
    assert result.protocol == "redis"
    assert result.identification_method == "redis_resp_error_reply"
    assert result.data["server_error_code"] == error_code
    assert result.data["authentication_attempted"] is False


@pytest.mark.parametrize(
    "error_code",
    [
        "ERR", "READONLY", "MISCONF",
        "CLUSTERDOWN", "TRYAGAIN", "MOVED", "ASK", "CROSSSLOT",
    ],
)
def test_redis_rejects_unexpected_ping_error_codes(error_code):
    port, _, thread, _ = _server(
        f"-{error_code} unrelated error\r\n".encode()
    )

    result = _probe(port)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None


@pytest.mark.parametrize(
    "response",
    [
        b"+PO\nNG\r\n",
        b"+PO\rNG\r\n",
    ],
)
def test_redis_rejects_embedded_line_control_characters(response):
    port, _, thread, _ = _server(response)

    result = _probe(port)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None


def test_redis_accepts_resp_line_split_across_reads(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.chunks = [b"+PO", b"NG\r", b"\n"]
            self.sent = b""
            self.closed = False

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            self.sent = data

        def recv(self, size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr(
        "sentinelforge.core.protocol_probe.socket.create_connection",
        lambda *args, **kwargs: fake,
    )

    result = _probe(6379)

    assert fake.sent == PING_REQUEST
    assert fake.closed is True
    assert result.success is True
    assert result.protocol == "redis"
    assert result.identification_method == "redis_resp_ping"
    assert result.data["response"] == "PONG"

def test_redis_rejects_trailing_bytes_received_with_resp_line(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.chunks = [b"+PONG\r\nEXTRA"]
            self.sent = b""
            self.closed = False

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            self.sent = data

        def recv(self, size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr(
        "sentinelforge.core.protocol_probe.socket.create_connection",
        lambda *args, **kwargs: fake,
    )

    result = _probe(6379)

    assert fake.sent == b"*1\r\n$4\r\nPING\r\n"
    assert fake.closed is True
    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None



def test_redis_socket_close_error_does_not_override_result(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.chunks = [b"+PONG\r\n"]

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            pass

        def recv(self, size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            raise OSError("simulated close failure")

    fake = FakeSocket()
    monkeypatch.setattr(
        "sentinelforge.core.protocol_probe.socket.create_connection",
        lambda *args, **kwargs: fake,
    )

    result = _probe(6379)

    assert result.success is True
    assert result.protocol == "redis"
    assert result.data["response"] == "PONG"

def test_redis_does_not_wait_for_future_trailing_bytes(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.chunks = [b"+PONG\r\n", b"EXTRA"]
            self.sent = b""
            self.closed = False

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            self.sent = data

        def recv(self, size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr(
        "sentinelforge.core.protocol_probe.socket.create_connection",
        lambda *args, **kwargs: fake,
    )

    result = _probe(6379)

    assert result.success is True
    assert result.protocol == "redis"
    assert result.data["response"] == "PONG"
    assert fake.chunks == [b"EXTRA"]
    assert fake.closed is True

@pytest.mark.parametrize(
    "response",
    [
        b"+PONG\n",
        b"+PONG\rX",
        b"+PONG\r\r\n",
    ],
)
def test_redis_rejects_malformed_resp_terminators(response):
    port, _, thread, _ = _server(response)
    result = _probe(port)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert result.error is not None


def test_redis_accepts_pong_at_exact_response_size_limit():
    response = b"+PONG\r\n"
    port, _, thread, _ = _server(response)
    result = _probe(port, max_body_bytes=len(response))
    thread.join(2)

    assert result.success is True
    assert result.protocol == "redis"
    assert result.data["response"] == "PONG"


def test_redis_rejects_pong_when_response_limit_is_too_small():
    response = b"+PONG\r\n"
    port, _, thread, _ = _server(response)
    result = _probe(port, max_body_bytes=len(response) - 1)
    thread.join(2)

    assert result.success is False
    assert result.protocol == "redis"
    assert result.confidence == 0.0
    assert "size limit" in result.error.lower()

