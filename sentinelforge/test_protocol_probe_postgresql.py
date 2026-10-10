import pytest
import socket
import struct
import threading

from sentinelforge.core.protocol_probe import ProtocolProbe


SSL_REQUEST_CODE = 80877103


def _recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _start_postgres_server(ssl_response=b"N", startup_response=None):
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

        try:
            conn, _ = srv.accept()
            conn.settimeout(3)
            with conn:
                request = _recv_exact(conn, 8)
                state["ssl_request"] = request

                if request is None:
                    return

                conn.sendall(ssl_response)

                if ssl_response != b"N":
                    return

                header = _recv_exact(conn, 4)
                if header is None:
                    state["startup_packet"] = None
                    return

                length = struct.unpack("!I", header)[0]
                if length < 8 or length > 65536:
                    state["startup_packet"] = header
                    return

                body = _recv_exact(conn, length - 4)
                state["startup_packet"] = (
                    header + body if body is not None else None
                )

                if startup_response is not None:
                    conn.sendall(startup_response)
        except (OSError, socket.timeout) as exc:
            state["server_error"] = str(exc)
        finally:
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)
    return state["port"], state, thread


def _postgres_error_response(message="startup rejected"):
    fields = b"SERROR\x00C28000\x00M" + message.encode() + b"\x00\x00"
    return b"E" + struct.pack("!I", len(fields) + 4) + fields


def test_postgresql_ssl_refusal_is_followed_by_startup_probe():
    response = _postgres_error_response()
    port, state, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert state.get("ssl_request") == (
        struct.pack("!I", 8) + struct.pack("!I", SSL_REQUEST_CODE)
    )
    assert state.get("startup_packet") is not None
    assert result.protocol == "postgresql"
    assert result.success is True
    assert result.data["ssl_supported"] is False
    assert result.data["server_response_type"] == "error"
    assert result.data["startup_error"]["severity"] == "ERROR"
    assert result.data["startup_error"]["sqlstate"] == "28000"
    assert not result.data.get("credentials_sent", False)


def test_postgresql_invalid_ssl_response_is_rejected():
    port, _, thread = _start_postgres_server(ssl_response=b"X")

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "postgresql"
    assert result.confidence == 0.0


def test_postgresql_truncated_ssl_response_fails_safely():
    port, _, thread = _start_postgres_server(ssl_response=b"")

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.protocol == "postgresql"
    assert result.error is not None


def test_postgresql_ssl_acceptance_does_not_claim_identity_without_tls():
    port, _, thread = _start_postgres_server(ssl_response=b"S")

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_invalid_response_length():
    response = b"E" + struct.pack("!I", 3)
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_truncated_error_response():
    response = b"E" + struct.pack("!I", 20) + b"SERROR\x00"
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_unknown_response_type():
    response = b"X" + struct.pack("!I", 4)
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_identifies_authentication_method():
    # PostgreSQL AuthenticationSASL request (method code 10).
    payload = struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is True
    assert result.data["authentication_method"] == "SASL"
    assert result.data["credentials_sent"] is False


def test_postgresql_rejects_truncated_authentication_request():
    payload = b"\x00\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_authentication_ok_with_trailing_bytes():
    payload = struct.pack("!I", 0) + b"\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_md5_authentication_without_salt():
    # MD5 authentication requires a four-byte salt after the method code.
    payload = struct.pack("!I", 5)
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_unterminated_sasl_mechanism_list():
    payload = struct.pack("!I", 10) + b"SCRAM-SHA-256\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_empty_sasl_mechanism_list():
    payload = struct.pack("!I", 10) + b"\x00\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_malformed_parameter_status():
    # ParameterStatus requires two NUL-terminated strings: name and value.
    payload = b"server_version\x00"
    response = b"S" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_empty_ready_for_query_payload():
    # ReadyForQuery requires one transaction-status byte.
    payload = b""
    response = b"Z" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_malformed_backend_key_data():
    # BackendKeyData requires exactly two 32-bit integers.
    payload = struct.pack("!I", 12345)
    response = b"K" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_error_response_without_terminator():
    # ErrorResponse fields must end with a zero field-code terminator.
    payload = b"SERROR\x00C28000\x00Mstartup rejected\x00"
    response = b"E" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_notice_response_without_terminator():
    payload = b"SNOTICE\x00Mtest notice\x00"
    response = b"N" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.protocol == "postgresql"
    assert result.success is False
    assert result.confidence == 0.0


@pytest.mark.parametrize("auth_code", [11, 12])
def test_postgresql_rejects_empty_sasl_continuation_or_final(auth_code):
    payload = struct.pack("!I", auth_code)
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_non_ascii_sasl_mechanism():
    payload = struct.pack("!I", 10) + b"SCRAM-\xff\x00\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_duplicate_sasl_mechanisms():
    payload = struct.pack("!I", 10) + b"SCRAM-SHA-256\x00SCRAM-SHA-256\x00\x00"
    response = b"R" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_empty_parameter_status_name():
    payload = b"\x00value\x00"
    response = b"S" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_duplicate_parameter_status_names():
    payload = b"server_version\x0016.0\x00server_version\x0017.0\x00"
    response = b"S" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_non_ascii_parameter_status_name():
    payload = b"server_\xffversion\x0017.0\x00"
    response = b"S" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_duplicate_error_response_fields():
    payload = b"SERROR\x00Mfirst\x00Msecond\x00\x00"
    response = b"E" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_rejects_zero_backend_process_id():
    payload = struct.pack("!II", 0, 12345678)
    response = b"K" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is False
    assert result.confidence == 0.0


def test_postgresql_accepts_valid_parameter_status():
    payload = b"server_version\x0016.2\x00"
    response = b"S" + struct.pack("!I", len(payload) + 4) + payload
    port, _, thread = _start_postgres_server(
        ssl_response=b"N",
        startup_response=response,
    )

    result = ProtocolProbe(timeout=1.0).probe(
        "127.0.0.1", "127.0.0.1", "ipv4", port, "postgresql"
    )
    thread.join(2)

    assert result.success is True
    assert result.data["parameter_status"] == {
        "name": "server_version",
        "value": "16.2",
    }
