import socket
import struct
import threading

from sentinelforge.core.protocol_probe import ProtocolProbe


def _ssh_name_list(value):
    encoded = value.encode()
    return struct.pack("!I", len(encoded)) + encoded


def _build_kexinit():
    cookie = bytes(range(1, 17))

    fields = [
        "curve25519-sha256,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
        "ssh-ed25519,rsa-sha2-256",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ]

    payload = b"\x14" + cookie

    for field in fields:
        encoded = field.encode("ascii")
        payload += struct.pack("!I", len(encoded))
        payload += encoded

    payload += b"\x00"
    payload += struct.pack("!I", 0)

    for padding_length in range(4, 256):
        packet_length = 1 + len(payload) + padding_length
        if packet_length % 8 == 0:
            break
    else:
        raise AssertionError("Unable to construct aligned SSH packet")

    padding = b"\x00" * padding_length

    return (
        struct.pack("!I", packet_length)
        + bytes([padding_length])
        + payload
        + padding
    )


def _start_ssh_server():
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
            conn.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            state["client_data"] = conn.recv(1024)
            conn.sendall(_build_kexinit())
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    return state["port"], state


def test_ssh_banner_and_kexinit_baseline():
    port, state = _start_ssh_server()

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.identification_method == "ssh_banner_and_algorithm_negotiation"
    assert result.confidence == 0.99

    assert result.data["banner"] == "SSH-2.0-OpenSSH_9.6p1"
    assert result.data["protocol_version"] == "2.0"
    assert result.data["software"] == "OpenSSH_9.6p1"

    negotiation = result.data["algorithm_negotiation"]

    assert negotiation["message_type"] == 20
    assert negotiation["negotiation_complete"] is True
    assert negotiation["kex_algorithms"] == [
        "curve25519-sha256",
        "diffie-hellman-group14-sha256",
        "ext-info-s",
        "kex-strict-s-v00@openssh.com",
    ]

    capabilities = negotiation["capabilities"]
    assert capabilities["extensions"] == [
        "ext-info-s",
        "kex-strict-s-v00@openssh.com",
    ]
    assert capabilities["ext_info"] is True
    assert capabilities["strict_kex"] is True
    assert negotiation["server_host_key_algorithms"] == [
        "ssh-ed25519",
        "rsa-sha2-256",
    ]
    assert negotiation["encryption_algorithms_client_to_server"] == [
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
    ]
    assert negotiation["mac_algorithms_client_to_server"] == [
        "hmac-sha2-256",
    ]
    assert negotiation["compression_algorithms_client_to_server"] == [
        "none",
    ]

    assert state.get("client_data")

def _start_custom_ssh_server(packet):
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
            conn.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            state["client_data"] = conn.recv(1024)
            conn.sendall(packet)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    return state["port"], state


def test_ssh_truncated_kexinit_fails_safely():
    packet = struct.pack("!IB", 256, 4) + b"\x14"

    port, _ = _start_custom_ssh_server(packet)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["algorithm_negotiation"] is None

def test_ssh_invalid_padding_fails_safely():
    packet = struct.pack("!IB", 32, 32) + b"\x14" + b"\x00" * 31

    port, _ = _start_custom_ssh_server(packet)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["algorithm_negotiation"] is None

def test_ssh_unexpected_message_type_is_not_negotiation():
    packet = struct.pack("!IB", 16, 4) + b"\x15" + b"\x00" * 15

    port, _ = _start_custom_ssh_server(packet)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"

    negotiation = result.data["algorithm_negotiation"]
    assert negotiation is not None
    assert negotiation["message_type"] == 21
    assert negotiation["negotiation_complete"] is False

def test_ssh_oversized_kex_field_fails_safely():
    packet = (
        struct.pack("!IB", 24, 4)
        + b"\x14"
        + b"\x00" * 16
        + struct.pack("!I", 70000)
        + b"\x00" * 3
    )

    port, _ = _start_custom_ssh_server(packet)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["algorithm_negotiation"] is None

def test_ssh_preamble_before_identification_banner():
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
            conn.sendall(
                b"NOTICE: Authorized access only\r\n"
                b"SSH-2.0-OpenSSH_9.6p1\r\n"
            )
            state["client_data"] = conn.recv(1024)
            conn.sendall(_build_kexinit())
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        state["port"],
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["banner"] == "SSH-2.0-OpenSSH_9.6p1"
    assert result.data["protocol_version"] == "2.0"
    assert result.data["software"] == "OpenSSH_9.6p1"
    assert result.data["algorithm_negotiation"]["negotiation_complete"] is True

def test_ssh_missing_identification_banner_fails_cleanly():
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
            conn.sendall(b"NOTICE: Authorized access only\r\n")
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        state["port"],
        "ssh",
    )

    assert result.success is False
    assert result.protocol == "unknown"
    assert result.identification_method == "ssh_banner_missing"
    assert result.confidence == 0.0
    assert result.data == {}
    assert result.error == "Missing SSH identification string"

def test_ssh_unusual_protocol_version_is_preserved():
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
            conn.sendall(b"SSH-1.99-TestServer_1.0\r\n")
            state["client_data"] = conn.recv(1024)
            conn.sendall(_build_kexinit())
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        state["port"],
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["banner"] == "SSH-1.99-TestServer_1.0"
    assert result.data["protocol_version"] == "1.99"
    assert result.data["software"] == "TestServer_1.0"

def test_ssh_ipv6_banner_and_kexinit():
    ready = threading.Event()
    state = {}

    def server():
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("::1", 0))
        srv.listen(1)
        srv.settimeout(5)

        state["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)

        try:
            conn.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n")
            state["client_data"] = conn.recv(1024)
            conn.sendall(_build_kexinit())
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    probe = ProtocolProbe(timeout=1.0)
    result = probe.probe(
        "::1",
        "::1",
        "ipv6",
        state["port"],
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.address_family == "ipv6"
    assert result.data["banner"] == "SSH-2.0-OpenSSH_9.6p1"
    assert result.data["algorithm_negotiation"]["negotiation_complete"] is True

def test_ssh_algorithm_classification_detects_legacy_and_weak():
    negotiation = {
        "kex_algorithms": [
            "diffie-hellman-group14-sha1",
            "curve25519-sha256",
            "unknown-kex-example",
        ],
        "server_host_key_algorithms": [
            "ssh-dss",
            "ssh-rsa",
            "ssh-ed25519",
        ],
        "encryption_algorithms_client_to_server": [
            "3des-cbc",
            "aes128-ctr",
        ],
        "encryption_algorithms_server_to_client": [
            "arcfour256",
            "chacha20-poly1305@openssh.com",
        ],
        "mac_algorithms_client_to_server": [
            "hmac-sha1",
            "hmac-sha2-256",
        ],
        "mac_algorithms_server_to_client": [
            "hmac-md5",
            "hmac-sha2-256",
        ],
        "compression_algorithms_client_to_server": [
            "none",
        ],
        "compression_algorithms_server_to_client": [
            "none",
        ],
    }

    profile = ProtocolProbe._classify_ssh_algorithms(negotiation)

    assert {
        item["algorithm"]
        for item in profile["legacy_algorithms"]
    } >= {
        "diffie-hellman-group14-sha1",
        "ssh-rsa",
        "hmac-sha1",
        "hmac-md5",
    }

    assert {
        item["algorithm"]
        for item in profile["weak_algorithms"]
    } >= {
        "ssh-dss",
        "3des-cbc",
        "arcfour256",
    }

    assert {
        item["algorithm"]
        for item in profile["unknown_algorithms"]
    } == {
        "unknown-kex-example",
    }

def test_ssh_algorithm_classification_profiles():
    negotiation = {
        "kex_algorithms": [
            "diffie-hellman-group14-sha1",
            "curve25519-sha256",
            "unknown-kex-example",
        ],
        "server_host_key_algorithms": [
            "ssh-dss",
            "ssh-rsa",
            "ssh-ed25519",
        ],
        "encryption_algorithms_client_to_server": [
            "3des-cbc",
            "aes128-ctr",
        ],
        "encryption_algorithms_server_to_client": [
            "aes128-cbc",
            "aes256-gcm@openssh.com",
        ],
        "mac_algorithms_client_to_server": [
            "hmac-sha1",
            "hmac-sha2-256",
        ],
        "mac_algorithms_server_to_client": [
            "hmac-md5",
            "hmac-sha2-256",
        ],
        "compression_algorithms_client_to_server": [
            "none",
        ],
        "compression_algorithms_server_to_client": [
            "none",
        ],
        "first_kex_follows": False,
    }

    profile = ProtocolProbe._classify_ssh_algorithms(negotiation)

    assert {
        item["algorithm"]
        for item in profile["legacy_algorithms"]
    } >= {
        "diffie-hellman-group14-sha1",
        "ssh-rsa",
        "aes128-cbc",
        "hmac-sha1",
    }

    assert {
        item["algorithm"]
        for item in profile["weak_algorithms"]
    } >= {
        "ssh-dss",
        "3des-cbc",
    }

    assert {
        item["algorithm"]
        for item in profile["unknown_algorithms"]
    } == {
        "unknown-kex-example",
    }

    assert any(
        item["algorithm"] == "curve25519-sha256"
        and item["classification"] == "modern"
        for item in profile["kex"]
    )

    assert any(
        item["algorithm"] == "aes256-gcm@openssh.com"
        and item["classification"] == "modern"
        for item in profile["encryption"]
    )

def test_ssh_capabilities_and_fingerprint_integrity():
    negotiation = {
        "message_type": 20,
        "negotiation_complete": True,
        "kex_algorithms": [
            "curve25519-sha256",
            "ext-info-s",
            "kex-strict-s-v00@openssh.com",
        ],
        "server_host_key_algorithms": ["ssh-ed25519"],
        "encryption_algorithms_client_to_server": ["chacha20-poly1305@openssh.com"],
        "encryption_algorithms_server_to_client": ["chacha20-poly1305@openssh.com"],
        "mac_algorithms_client_to_server": ["hmac-sha2-256"],
        "mac_algorithms_server_to_client": ["hmac-sha2-256"],
        "compression_algorithms_client_to_server": ["none"],
        "compression_algorithms_server_to_client": ["none"],
        "languages_client_to_server": [],
        "languages_server_to_client": [],
        "first_kex_follows": False,
    }

    capabilities = ProtocolProbe._analyze_ssh_capabilities(negotiation)

    assert capabilities["extensions"] == [
        "ext-info-s",
        "kex-strict-s-v00@openssh.com",
    ]
    assert capabilities["ext_info"] is True
    assert capabilities["strict_kex"] is True
    assert capabilities["first_kex_follows"] is False

    negotiation["capabilities"] = capabilities

    fingerprint_one = ProtocolProbe._build_ssh_fingerprint(negotiation)
    fingerprint_two = ProtocolProbe._build_ssh_fingerprint(negotiation)

    assert fingerprint_one == fingerprint_two
    assert fingerprint_one["protocol"] == "ssh"
    assert fingerprint_one["message_type"] == 20
    assert fingerprint_one["negotiation_complete"] is True
    assert len(fingerprint_one["observation_sha256"]) == 64
    assert fingerprint_one["confidence"] == 0.95
    assert fingerprint_one["capabilities"] == capabilities
    assert fingerprint_one["evidence"]

def test_ssh_kex_field_length_exceeds_remaining_packet():
    port_holder = {}
    ready = threading.Event()

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5)
        port_holder["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)
        try:
            conn.sendall(b"SSH-2.0-TestServer_1.0\r\n")
            conn.recv(1024)

            payload = b"\x14" + bytes(range(1, 17))
            payload += struct.pack("!I", 100)
            payload += b"A"

            padding_length = 4
            packet_length = 1 + len(payload) + padding_length
            packet = (
                struct.pack("!I", packet_length)
                + bytes([padding_length])
                + payload
                + (b"\x00" * padding_length)
            )
            conn.sendall(packet)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port_holder["port"],
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["algorithm_negotiation"] is None

def test_ssh_banner_timeout_is_classified_cleanly():
    port_holder = {}
    ready = threading.Event()

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5)
        port_holder["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)
        try:
            threading.Event().wait(1)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)

    probe = ProtocolProbe(timeout=0.2)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port_holder["port"],
        "ssh",
    )

    assert result.success is False
    assert result.protocol == "ssh"
    assert result.identification_method == "connection_failed"
    assert result.confidence == 0.0
    assert result.error is not None

def test_ssh_banner_valid_but_kexinit_missing():
    port_holder = {}
    ready = threading.Event()

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5)
        port_holder["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)
        try:
            conn.sendall(b"SSH-2.0-TestServer_1.0\r\n")
            conn.recv(1024)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(5)

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port_holder["port"],
        "ssh",
    )

    assert result.success is True
    assert result.protocol == "ssh"
    assert result.data["banner"] == "SSH-2.0-TestServer_1.0"
    assert result.data["protocol_version"] == "2.0"
    assert result.data["software"] == "TestServer_1.0"
    assert result.data["algorithm_negotiation"] is None
    assert result.error is None
