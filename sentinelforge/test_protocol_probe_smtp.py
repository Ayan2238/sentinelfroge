import socket
import threading

from sentinelforge.core.protocol_probe import ProtocolProbe


def _start_smtp_server(responses):
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
            conn.sendall(responses["greeting"].encode())

            for expected, response in responses["commands"]:
                data = conn.recv(1024).decode(errors="replace")
                if expected not in data:
                    state["unexpected"] = data
                    break
                conn.sendall(response.encode())
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    return state["port"], state


def test_smtp_greeting_and_ehlo_capabilities():
    port, state = _start_smtp_server(
        {
            "greeting": "220-test.example ESMTP SentinelForge\r\n"
                        "220 Ready\r\n",
            "commands": [
                (
                    "EHLO SentinelForge",
                    "250-test.example\r\n"
                    "250-SIZE 52428800\r\n"
                    "250-8BITMIME\r\n"
                    "250-PIPELINING\r\n"
                    "250-STARTTLS\r\n"
                    "250-AUTH PLAIN LOGIN\r\n"
                    "250 SMTPUTF8\r\n",
                )
            ],
        }
    )

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "smtp",
    )

    assert result.success is True
    assert result.protocol == "smtp"
    assert result.data["greeting_code"] == 220
    assert result.data["greeting_identity"]["hostname"] == "test.example"
    assert result.data["greeting_identity"]["product_clues"] == []
    assert result.data["greeting_identity"]["multiline"] is True
    assert result.data["greeting_identity"]["semantic"] == "service_ready"
    assert result.data["greeting_identity"]["anomalies"] == []
    assert result.data["status_analysis"]["greeting"]["semantics"] == "accepted"

    identity = result.data["identity_consistency"]
    assert identity["dialect"] == "esmtp"
    assert identity["greeting_hostname"] == "test.example"
    assert identity["ehlo_hostname"] == "test.example"
    assert identity["helo_hostname"] is None
    assert identity["ehlo_accepted"] is True
    assert identity["hostname_identity_consistent"] is True
    assert identity["product_identity_consistent"] is None
    assert identity["anomalies"] == []

    fingerprint_identity = result.data["fingerprint"]["identity"]
    assert fingerprint_identity["consistency"]["dialect"] == "esmtp"
    assert fingerprint_identity["consistency"]["hostname_identity_consistent"] is True

    assert result.data["capabilities"] == [
        "TEST.EXAMPLE",
        "SIZE",
        "8BITMIME",
        "PIPELINING",
        "STARTTLS",
        "AUTH",
        "SMTPUTF8",
    ]
    assert result.data["capability_details"][1]["arguments"] == "52428800"
    assert result.data["capability_details"][5]["arguments"] == "PLAIN LOGIN"
    assert not state.get("unexpected")


def test_smtp_ehlo_fallback_to_helo():
    port, state = _start_smtp_server(
        {
            "greeting": "220 smtp.example ESMTP\r\n",
            "commands": [
                (
                    "EHLO SentinelForge",
                    "500 EHLO not supported\r\n",
                ),
                (
                    "HELO SentinelForge",
                    "250 smtp.example Hello\r\n",
                ),
            ],
        }
    )

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "smtp",
    )

    assert result.success is True
    assert result.data["ehlo"]["accepted"] is False
    assert result.data["helo"]["accepted"] is True
    assert result.data["commands"]["ehlo"]["status"] == "permanent_error"
    assert result.data["commands"]["helo"]["status"] == "success"
    assert not state.get("unexpected")


def test_smtp_multiline_response_handles_fragmented_data():
    ready = threading.Event()
    state = {}

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        state["port"] = srv.getsockname()[1]
        ready.set()

        conn, _ = srv.accept()
        conn.settimeout(5)

        try:
            for chunk in (
                b"220-fragment",
                b"ed.example\r\n220 Ready\r\n",
            ):
                conn.sendall(chunk)

            data = conn.recv(1024)
            assert b"EHLO SentinelForge" in data

            for chunk in (
                b"250-frag",
                b"mented.example\r\n250-SIZE 1000\r\n"
                b"250 SMTPUTF8\r\n",
            ):
                conn.sendall(chunk)
        finally:
            conn.close()
            srv.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(5)

    probe = ProtocolProbe(timeout=2.0)
    result = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        state["port"],
        "smtp",
    )

    assert result.success is True
    assert result.data["greeting_code"] == 220
    assert result.data["greeting_lines"][0] == "220-fragmented.example"
    assert "SIZE" in result.data["capabilities"]
    assert "SMTPUTF8" in result.data["capabilities"]


def test_smtp_response_classification():
    assert ProtocolProbe._classify_smtp_response(120) == "preliminary"
    assert ProtocolProbe._classify_smtp_response(250) == "success"
    assert ProtocolProbe._classify_smtp_response(354) == "continuation"
    assert ProtocolProbe._classify_smtp_response(421) == "transient_error"
    assert ProtocolProbe._classify_smtp_response(550) == "permanent_error"
    assert ProtocolProbe._classify_smtp_response(999) == "unknown"


def test_smtp_security_cleartext_auth_finding():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    port, state = _start_smtp_server(
        {
            "greeting": "220 smtp.example ESMTP\r\n",
            "commands": [
                (
                    "EHLO SentinelForge",
                    "250-smtp.example\r\n"
                    "250-AUTH PLAIN LOGIN\r\n"
                    "250 SMTPUTF8\r\n",
                )
            ],
        }
    )

    probe = ProtocolProbe(timeout=2.0)
    observation = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "smtp",
    )

    class DummyPlugin:
        def _finding(self, **kwargs):
            return kwargs

    class DummyTarget:
        pass

    findings = _smtp_security_findings(
        DummyPlugin(),
        DummyTarget(),
        observation,
    )

    titles = {finding["title"] for finding in findings}

    assert "SMTP Cleartext Authentication Advertised" in titles
    assert not state.get("unexpected")


def test_smtp_security_starttls_rejected_finding():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    class DummyPlugin:
        def _finding(self, **kwargs):
            return kwargs

    class DummyTarget:
        pass

    class Observation:
        protocol = "smtp"
        evidence = (
            "SMTP STARTTLS advertised.",
            "SMTP STARTTLS rejected with code 454.",
        )
        data = {
            "capabilities": ["STARTTLS", "AUTH"],
            "starttls": {
                "advertised": True,
                "accepted": False,
                "response_code": 454,
                "handshake": None,
            },
            "auth": {
                "mechanisms": ["PLAIN"],
                "mechanism_classes": {"PLAIN": "cleartext"},
            },
            "tls": {},
            "fingerprint": {},
        }

    findings = _smtp_security_findings(
        DummyPlugin(),
        DummyTarget(),
        Observation(),
    )

    titles = {finding["title"] for finding in findings}

    assert "SMTP STARTTLS Rejected" in titles



def test_smtp_security_legacy_auth_finding():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    port, state = _start_smtp_server(
        {
            "greeting": "220 smtp.example ESMTP\r\n",
            "commands": [
                (
                    "EHLO SentinelForge",
                    "250-smtp.example\r\n"
                    "250-AUTH NTLM XOAUTH2\r\n"
                    "250 SMTPUTF8\r\n",
                )
            ],
        }
    )

    probe = ProtocolProbe(timeout=2.0)
    observation = probe.probe(
        "127.0.0.1",
        "127.0.0.1",
        "ipv4",
        port,
        "smtp",
    )

    class DummyPlugin:
        def _finding(self, **kwargs):
            return kwargs

    class DummyTarget:
        pass

    findings = _smtp_security_findings(
        DummyPlugin(),
        DummyTarget(),
        observation,
    )

    titles = {finding["title"] for finding in findings}

    assert "SMTP Legacy Authentication Mechanism Advertised" in titles
    assert not state.get("unexpected")


def test_smtp_security_no_false_cleartext_auth_when_tls_active():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    class DummyPlugin:
        def _finding(self, **kwargs):
            return kwargs

    class DummyTarget:
        pass

    class Observation:
        protocol = "smtp"
        evidence = (
            "SMTP STARTTLS negotiation succeeded.",
            "TLS version: TLSv1.3.",
        )
        data = {
            "capabilities": ["STARTTLS", "AUTH"],
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "tls_version": "TLSv1.3",
            },
            "auth": {
                "mechanisms": ["PLAIN", "LOGIN"],
                "mechanism_classes": {
                    "PLAIN": "cleartext",
                    "LOGIN": "cleartext",
                },
            },
            "tls": {
                "handshake": True,
                "version": "TLSv1.3",
            },
            "fingerprint": {},
        }

    findings = _smtp_security_findings(
        DummyPlugin(),
        DummyTarget(),
        Observation(),
    )

    titles = {finding["title"] for finding in findings}

    assert "SMTP Cleartext Authentication Advertised" not in titles




def test_smtp_tls_capability_comparison_added_removed():
    data = {
        "capabilities": ["SIZE", "STARTTLS", "AUTH", "PIPELINING"],
        "auth": {"mechanisms": ["PLAIN", "LOGIN"]},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": [
                "SIZE",
                "AUTH",
                "PIPELINING",
                "SMTPUTF8",
            ],
            "post_tls_capability_details": [
                {"name": "SIZE", "arguments": "10485760"},
                {"name": "AUTH", "arguments": "PLAIN LOGIN"},
                {"name": "PIPELINING", "arguments": None},
                {"name": "SMTPUTF8", "arguments": None},
            ],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["capabilities_added_after_tls"] == ["SMTPUTF8"]
    assert result["capabilities_removed_after_tls"] == ["STARTTLS"]
    assert result["changed"] is True


def test_smtp_auth_becomes_available_after_tls():
    data = {
        "capabilities": ["SIZE", "STARTTLS"],
        "auth": {"mechanisms": []},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": ["SIZE", "AUTH"],
            "post_tls_capability_details": [
                {"name": "SIZE", "arguments": "10485760"},
                {"name": "AUTH", "arguments": "PLAIN LOGIN"},
            ],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["auth_added_after_tls"] == ["LOGIN", "PLAIN"]
    assert any(
        item["code"] == "auth_enabled_after_tls"
        for item in result["anomalies"]
    )


def test_smtp_auth_mechanisms_change_after_tls():
    data = {
        "capabilities": ["STARTTLS", "AUTH"],
        "auth": {"mechanisms": ["PLAIN", "LOGIN"]},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": ["AUTH"],
            "post_tls_capability_details": [
                {"name": "AUTH", "arguments": "PLAIN CRAM-MD5"},
            ],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["auth_added_after_tls"] == ["CRAM-MD5"]
    assert result["auth_removed_after_tls"] == ["LOGIN"]
    assert any(
        item["code"] == "auth_changed_after_tls"
        for item in result["anomalies"]
    )


def test_smtp_missing_post_tls_capabilities():
    data = {
        "capabilities": ["STARTTLS", "SIZE"],
        "auth": {"mechanisms": []},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": [],
            "post_tls_capability_details": [],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["changed"] is True
    assert any(
        item["code"] == "missing_post_tls_capabilities"
        for item in result["anomalies"]
    )


def test_smtp_tls_capability_comparison_unchanged():
    data = {
        "capabilities": ["SIZE", "AUTH", "PIPELINING"],
        "auth": {"mechanisms": ["PLAIN", "LOGIN"]},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": [
                "SIZE",
                "AUTH",
                "PIPELINING",
            ],
            "post_tls_capability_details": [
                {"name": "SIZE", "arguments": "10485760"},
                {"name": "AUTH", "arguments": "PLAIN LOGIN"},
                {"name": "PIPELINING", "arguments": None},
            ],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["capabilities_added_after_tls"] == []
    assert result["capabilities_removed_after_tls"] == []
    assert result["auth_added_after_tls"] == []
    assert result["auth_removed_after_tls"] == []
    assert result["changed"] is False
    assert result["anomalies"] == []


def test_smtp_post_tls_auth_without_arguments_is_not_invented():
    data = {
        "capabilities": ["STARTTLS", "AUTH"],
        "auth": {"mechanisms": ["PLAIN"]},
        "starttls": {
            "handshake": True,
            "post_tls_capabilities": ["AUTH"],
            "post_tls_capability_details": [
                {"name": "AUTH", "arguments": None},
            ],
        },
    }

    result = ProtocolProbe._compare_smtp_tls_capabilities(data)

    assert result["post_tls_auth_mechanisms"] == []
    assert result["auth_removed_after_tls"] == ["PLAIN"]


def test_smtp_certificate_analysis_self_signed_and_san():
    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "mail.example.com"),),),
        "serialNumber": "01",
        "notBefore": "Sep 01 00:00:00 2026 GMT",
        "notAfter": "Sep 01 00:00:00 2027 GMT",
        "subjectAltName": (
            ("DNS", "mail.example.com"),
            ("DNS", "smtp.example.com"),
            ("IP Address", "127.0.0.1"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["present"] is True
    assert result["self_signed"] is True
    assert result["subject"] == certificate["subject"]
    assert result["issuer"] == certificate["issuer"]
    assert result["serial_number"] == "01"
    assert result["san"] == [
        "mail.example.com",
        "smtp.example.com",
        "127.0.0.1",
    ]


def test_smtp_certificate_analysis_empty_certificate():
    result = ProtocolProbe._analyze_smtp_certificate({})

    assert result["present"] is False
    assert result["self_signed"] is False
    assert result["san"] == []


def test_smtp_certificate_analysis_validity_currently_valid():
    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "serialNumber": "02",
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2027 GMT",
        "subjectAltName": (("DNS", "mail.example.com"),),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["validity"]["state"] == "currently_valid"
    assert result["validity"]["not_before"] == "Jan 01 00:00:00 2026 GMT"
    assert result["validity"]["not_after"] == "Dec 31 23:59:59 2027 GMT"


def test_smtp_certificate_analysis_expired():
    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "serialNumber": "03",
        "notBefore": "Jan 01 2024 00:00:00 GMT",
        "notAfter": "Jan 01 2025 00:00:00 GMT",
        "subjectAltName": (("DNS", "mail.example.com"),),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["validity"]["state"] == "expired"


def test_smtp_certificate_analysis_not_yet_valid():
    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "serialNumber": "04",
        "notBefore": "Jan 01 2030 00:00:00 GMT",
        "notAfter": "Jan 01 2031 00:00:00 GMT",
        "subjectAltName": (("DNS", "mail.example.com"),),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["validity"]["state"] == "not_yet_valid"


def test_smtp_certificate_analysis_security_metadata():
    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "serialNumber": "05",
        "notBefore": "Jan 01 2026 00:00:00 GMT",
        "notAfter": "Jan 01 2027 00:00:00 GMT",
        "subjectAltName": (
            ("DNS", "mail.example.com"),
            ("DNS", "smtp.example.com"),
        ),
    }

    certificate["version"] = 3
    certificate["signatureAlgorithm"] = "sha256WithRSAEncryption"
    certificate["publicKeyAlgorithm"] = "RSA"
    certificate["publicKeyBits"] = 2048

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["security"]["version"] == 3
    assert result["security"]["signature_algorithm"] == "sha256WithRSAEncryption"
    assert result["security"]["public_key_algorithm"] == "RSA"
    assert result["security"]["public_key_bits"] == 2048


def test_smtp_certificate_analysis_from_der():
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com"),
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("mail.example.com"),
                x509.DNSName("smtp.example.com"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = ProtocolProbe._analyze_smtp_certificate(der)

    assert result["present"] is True
    assert result["san"] == [
        "mail.example.com",
        "smtp.example.com",
    ]
    assert result["self_signed"] is True
    assert result["validity"]["state"] == "currently_valid"
    assert result["security"]["version"] == 3
    assert result["security"]["public_key_algorithm"] == "RSA"
    assert result["security"]["public_key_bits"] == 2048
    assert result["security"]["signature_algorithm"] == "sha256"
    assert result["fingerprint_sha256"]


def test_smtp_tls_security_classification_modern_strong():
    result = ProtocolProbe._classify_smtp_tls_security(
        tls_version="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    )

    assert result["version"]["value"] == "TLSv1.3"
    assert result["version"]["classification"] == "modern"
    assert result["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
    assert result["cipher"]["bits"] == 256
    assert result["cipher"]["classification"] == "strong"
    assert result["classification"] == "strong"
    assert result["issues"] == []


def test_smtp_tls_security_classification_tls12_strong():
    result = ProtocolProbe._classify_smtp_tls_security(
        tls_version="TLSv1.2",
        cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
    )

    assert result["version"]["classification"] == "modern"
    assert result["cipher"]["classification"] == "strong"
    assert result["classification"] == "strong"
    assert result["issues"] == []


def test_smtp_tls_security_classification_legacy_tls():
    result = ProtocolProbe._classify_smtp_tls_security(
        tls_version="TLSv1.0",
        cipher=("AES128-SHA", "TLSv1.0", 128),
    )

    assert result["version"]["classification"] == "legacy"
    assert result["cipher"]["classification"] == "weak"
    assert result["classification"] == "weak"
    assert "legacy_tls_version" in result["issues"]
    assert "weak_cipher" in result["issues"]


def test_smtp_tls_security_classification_ssl():
    result = ProtocolProbe._classify_smtp_tls_security(
        tls_version="SSLv3",
        cipher=("AES128-SHA", "SSLv3", 128),
    )

    assert result["version"]["classification"] == "obsolete"
    assert result["cipher"]["classification"] == "weak"
    assert result["classification"] == "weak"
    assert "obsolete_tls_version" in result["issues"]


def test_smtp_tls_security_classification_missing_metadata():
    result = ProtocolProbe._classify_smtp_tls_security(
        tls_version=None,
        cipher=None,
    )

    assert result["version"]["classification"] == "unknown"
    assert result["cipher"]["classification"] == "unknown"
    assert result["classification"] == "unknown"
    assert "missing_tls_metadata" in result["issues"]


def test_smtp_tls_security_findings_legacy_tls():
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "tls_security": {
                    "version": {
                        "value": "TLSv1.0",
                        "classification": "legacy",
                    },
                    "cipher": {
                        "name": "AES128-SHA",
                        "bits": 128,
                        "classification": "weak",
                    },
                    "classification": "weak",
                    "issues": [
                        "legacy_tls_version",
                        "weak_cipher",
                    ],
                },
            }
        }
    })()

    plugin = NetworkPlugin({})
    plugin._findings = []

    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    findings = _smtp_security_findings(
        plugin,
        "test.example",
        observation,
    )

    titles = {finding.title for finding in findings}

    assert "SMTP Legacy TLS Version" in titles
    assert "SMTP Weak TLS Cipher" in titles


def test_smtp_tls_security_findings_obsolete_tls():
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "tls_security": {
                    "version": {
                        "value": "SSLv3",
                        "classification": "obsolete",
                    },
                    "cipher": {
                        "name": "AES128-SHA",
                        "bits": 128,
                        "classification": "weak",
                    },
                    "classification": "weak",
                    "issues": [
                        "obsolete_tls_version",
                        "weak_cipher",
                    ],
                },
            }
        }
    })()

    plugin = NetworkPlugin({})
    plugin._findings = []

    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    findings = _smtp_security_findings(
        plugin,
        "test.example",
        observation,
    )

    titles = {finding.title for finding in findings}

    assert "SMTP Obsolete TLS Version" in titles
    assert "SMTP Weak TLS Cipher" in titles


def test_smtp_tls_security_findings_strong_tls_has_no_weakness():
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "tls_security": {
                    "version": {
                        "value": "TLSv1.3",
                        "classification": "modern",
                    },
                    "cipher": {
                        "name": "TLS_AES_256_GCM_SHA384",
                        "bits": 256,
                        "classification": "strong",
                    },
                    "classification": "strong",
                    "issues": [],
                },
            }
        }
    })()

    plugin = NetworkPlugin({})
    plugin._findings = []

    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    findings = _smtp_security_findings(
        plugin,
        "test.example",
        observation,
    )

    titles = {finding.title for finding in findings}

    assert "SMTP Legacy TLS Version" not in titles
    assert "SMTP Obsolete TLS Version" not in titles
    assert "SMTP Weak TLS Cipher" not in titles


def test_smtp_certificate_security_findings_expired():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "evidence": ("SMTP TLS certificate observed.",),
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "certificate_analysis": {
                    "present": True,
                    "validity_state": "expired",
                    "self_signed": False,
                    "hostname_state": "verified",
                    "security": {
                        "version": 3,
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "public_key_algorithm": "RSA",
                        "public_key_bits": 2048,
                    },
                },
            }
        },
    })()

    plugin = NetworkPlugin(config={})
    findings = _smtp_security_findings(plugin, "mail.example", observation)
    titles = {finding.title for finding in findings}

    assert "SMTP TLS Certificate Expired" in titles


def test_smtp_certificate_security_findings_not_yet_valid():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "evidence": ("SMTP TLS certificate observed.",),
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "certificate_analysis": {
                    "present": True,
                    "validity_state": "not_yet_valid",
                    "self_signed": False,
                    "hostname_state": "verified",
                },
            }
        },
    })()

    plugin = NetworkPlugin(config={})
    findings = _smtp_security_findings(plugin, "mail.example", observation)
    titles = {finding.title for finding in findings}

    assert "SMTP TLS Certificate Not Yet Valid" in titles


def test_smtp_certificate_security_findings_self_signed():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "evidence": ("SMTP TLS certificate observed.",),
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "certificate_analysis": {
                    "present": True,
                    "validity_state": "currently_valid",
                    "self_signed": True,
                    "hostname_state": "verified",
                },
            }
        },
    })()

    plugin = NetworkPlugin(config={})
    findings = _smtp_security_findings(plugin, "mail.example", observation)
    titles = {finding.title for finding in findings}

    assert "SMTP TLS Certificate Self-Signed" in titles


def test_smtp_certificate_security_findings_hostname_mismatch():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "evidence": ("SMTP TLS certificate observed.",),
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "certificate_analysis": {
                    "present": True,
                    "validity_state": "currently_valid",
                    "self_signed": False,
                    "hostname_state": "mismatch",
                    "san": ["wrong.example"],
                },
            }
        },
    })()

    plugin = NetworkPlugin(config={})
    findings = _smtp_security_findings(plugin, "mail.example", observation)
    titles = {finding.title for finding in findings}

    assert "SMTP TLS Certificate Hostname Mismatch" in titles


def test_smtp_certificate_security_findings_weak_key_or_signature():
    from sentinelforge.plugins.network.plugin import _smtp_security_findings
    from sentinelforge.plugins.network.plugin import NetworkPlugin

    observation = type("Observation", (), {
        "protocol": "smtp",
        "evidence": ("SMTP TLS certificate observed.",),
        "data": {
            "starttls": {
                "advertised": True,
                "accepted": True,
                "handshake": True,
                "certificate_analysis": {
                    "present": True,
                    "validity_state": "currently_valid",
                    "self_signed": False,
                    "hostname_state": "verified",
                    "security": {
                        "version": 3,
                        "signature_algorithm": "sha1WithRSAEncryption",
                        "public_key_algorithm": "RSA",
                        "public_key_bits": 1024,
                    },
                },
            }
        },
    })()

    plugin = NetworkPlugin(config={})
    findings = _smtp_security_findings(plugin, "mail.example", observation)
    titles = {finding.title for finding in findings}

    assert "SMTP TLS Certificate Weak Key" in titles
    assert "SMTP TLS Certificate Weak Signature" in titles


def test_smtp_certificate_hostname_matches_dns_san():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "mail.example.com"),
            ("DNS", "smtp.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["san"] == ["mail.example.com", "smtp.example.com"]


def test_smtp_certificate_wildcard_dns_san_is_preserved():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "*.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "*.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert "*.example.com" in result["san"]


def test_smtp_certificate_ip_san_is_preserved():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("IP Address", "192.0.2.25"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert "192.0.2.25" in result["san"]


def test_smtp_certificate_missing_san_is_detected_as_incomplete():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["san"] == []


def test_smtp_certificate_empty_metadata_is_safe():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    result = ProtocolProbe._analyze_smtp_certificate({})

    assert result["present"] is False
    assert result["san"] == []


def test_smtp_certificate_der_hostname_metadata_is_preserved():
    from sentinelforge.core.protocol_probe import ProtocolProbe
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com"),
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=30)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("mail.example.com"),
                x509.DNSName("smtp.example.com"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = ProtocolProbe._analyze_smtp_certificate(der)

    assert result["san"] == ["mail.example.com", "smtp.example.com"]
    assert result["present"] is True


def test_smtp_dns_wildcard_matches_single_leftmost_label():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "mail.example.com",
        "*.example.com",
    ) is True


def test_smtp_dns_wildcard_does_not_match_bare_domain():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "example.com",
        "*.example.com",
    ) is False


def test_smtp_dns_wildcard_does_not_match_multiple_labels():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "mail.eu.example.com",
        "*.example.com",
    ) is False


def test_smtp_dns_wildcard_matches_case_insensitively():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "MAIL.Example.COM",
        "*.example.com",
    ) is True


def test_smtp_dns_exact_name_matches_case_insensitively():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "Mail.Example.COM",
        "mail.example.com",
    ) is True


def test_smtp_dns_wildcard_must_be_leftmost_entire_label():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "mail.example.com",
        "mail*.example.com",
    ) is False


def test_smtp_dns_wildcard_does_not_match_partial_label():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "mail.example.com",
        "*mail.example.com",
    ) is False


def test_smtp_dns_wildcard_requires_matching_suffix():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    assert ProtocolProbe._smtp_dns_name_matches(
        "mail.other.com",
        "*.example.com",
    ) is False


def test_smtp_certificate_hostname_state_exact_san():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "mail.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="mail.example.com",
    )

    assert result["hostname_state"] == "verified"


def test_smtp_certificate_hostname_state_wildcard_san():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "*.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "*.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="mail.example.com",
    )

    assert result["hostname_state"] == "verified"


def test_smtp_certificate_hostname_state_wildcard_multilevel_mismatch():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "*.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "*.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="mail.eu.example.com",
    )

    assert result["hostname_state"] == "mismatch"


def test_smtp_certificate_hostname_state_dns_mismatch():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "wrong.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "wrong.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="mail.example.com",
    )

    assert result["hostname_state"] == "mismatch"


def test_smtp_certificate_hostname_state_ip_san():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("IP Address", "192.0.2.25"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="192.0.2.25",
    )

    assert result["hostname_state"] == "verified"


def test_smtp_certificate_hostname_state_ip_mismatch():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("IP Address", "192.0.2.25"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="192.0.2.26",
    )

    assert result["hostname_state"] == "mismatch"


def test_smtp_certificate_hostname_state_missing_san_is_unknown():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (),
    }

    result = ProtocolProbe._analyze_smtp_certificate(
        certificate,
        target="mail.example.com",
    )

    assert result["hostname_state"] == "unknown"


def test_smtp_certificate_hostname_state_without_target_remains_unknown():
    from sentinelforge.core.protocol_probe import ProtocolProbe

    certificate = {
        "subject": ((("commonName", "mail.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (
            ("DNS", "mail.example.com"),
        ),
    }

    result = ProtocolProbe._analyze_smtp_certificate(certificate)

    assert result["hostname_state"] == "unknown"


def test_smtp_post_tls_identity_security_findings():
    from types import SimpleNamespace

    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    observation = SimpleNamespace(
        protocol="smtp",
        data={
            "starttls": {
                "post_tls_ehlo": {
                    "accepted": True,
                    "code": 250,
                    "lines": [
                        "250-secure.example.net",
                        "250-SIZE 52428800",
                    ],
                },
            },
            "tls": {},
            "auth": {},
            "fingerprint": {},
            "identity_consistency": {
                "ehlo_hostname": "mail.example.com",
                "helo_hostname": None,
            },
            "post_tls_identity_consistency": {
                "pre_tls_hostname": "mail.example.com",
                "post_tls_hostname": "secure.example.net",
                "post_tls_ehlo_accepted": True,
                "hostname_identity_consistent": False,
                "anomalies": [
                    {
                        "code": "smtp_post_tls_hostname_mismatch",
                        "severity": "low",
                        "confidence": 0.90,
                        "description": "Hostname changed after TLS.",
                        "evidence": [
                            "Pre-TLS hostname: mail.example.com",
                            "Post-TLS hostname: secure.example.net",
                        ],
                    }
                ],
                "anomaly_count": 1,
            },
        },
        evidence=(),
    )

    target = SimpleNamespace(host="mail.example.com")

    findings = _smtp_security_findings(
        SimpleNamespace(
            _finding=lambda **kwargs: kwargs
        ),
        target,
        observation,
    )

    assert any(
        finding["title"] == "SMTP Post-TLS Hostname Mismatch"
        for finding in findings
    )


def test_smtp_post_tls_ehlo_rejection_security_finding():
    from types import SimpleNamespace

    from sentinelforge.plugins.network.plugin import _smtp_security_findings

    observation = SimpleNamespace(
        protocol="smtp",
        data={
            "starttls": {
                "post_tls_ehlo": {
                    "accepted": False,
                    "code": 500,
                    "lines": ["500 EHLO rejected"],
                },
            },
            "tls": {},
            "auth": {},
            "fingerprint": {},
            "post_tls_identity_consistency": {
                "pre_tls_hostname": "mail.example.com",
                "post_tls_hostname": None,
                "post_tls_ehlo_accepted": False,
                "hostname_identity_consistent": None,
                "anomalies": [
                    {
                        "code": "smtp_post_tls_ehlo_rejected",
                        "severity": "low",
                        "confidence": 0.95,
                        "description": "EHLO rejected after TLS.",
                        "evidence": ["500 EHLO rejected"],
                    }
                ],
                "anomaly_count": 1,
            },
        },
        evidence=(),
    )

    target = SimpleNamespace(host="mail.example.com")

    findings = _smtp_security_findings(
        SimpleNamespace(
            _finding=lambda **kwargs: kwargs
        ),
        target,
        observation,
    )

    assert any(
        finding["title"] == "SMTP Post-TLS EHLO Rejected"
        for finding in findings
    )

def test_smtp_ipv6_localhost_integration():
    import socket
    import threading

    from sentinelforge.core.protocol_probe import ProtocolProbe

    def server(listener):
        conn, _ = listener.accept()
        try:
            conn.sendall(
                b"220-ipv6.example.test ESMTP SentinelForge\r\n"
                b"220 Ready\r\n"
            )

            buffer = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk

                while b"\r\n" in buffer:
                    raw, buffer = buffer.split(b"\r\n", 1)
                    command = raw.decode("ascii", "replace")

                    if command == "EHLO SentinelForge":
                        conn.sendall(
                            b"250-ipv6.example.test\r\n"
                            b"250-SIZE 52428800\r\n"
                            b"250-8BITMIME\r\n"
                            b"250-PIPELINING\r\n"
                            b"250 SMTPUTF8\r\n"
                        )
                    elif command.startswith("HELO "):
                        conn.sendall(b"250 ipv6.example.test\r\n")
                    elif command.startswith(("NOOP", "RSET")):
                        conn.sendall(b"250 OK\r\n")
                    elif command.startswith("HELP"):
                        conn.sendall(b"214 SMTP help\r\n")
                    elif command.startswith("QUIT"):
                        conn.sendall(b"221 Bye\r\n")
                        return
                    else:
                        conn.sendall(b"502 Command not implemented\r\n")
        finally:
            conn.close()
            listener.close()

    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(1)

    port = listener.getsockname()[1]
    thread = threading.Thread(
        target=server,
        args=(listener,),
        daemon=True,
    )
    thread.start()

    try:
        result = ProtocolProbe({}, timeout=2.0).probe(
            "ipv6.example.test",
            "::1",
            "ipv6",
            port,
            "smtp",
            "tcp",
        )

        assert result.success is True
        assert result.protocol == "smtp"
        assert result.address == "::1"
        assert result.address_family == "ipv6"
        assert result.data["greeting_code"] == 220
        assert result.data["ehlo"]["accepted"] is True
        assert result.data["capabilities"] == [
            "IPV6.EXAMPLE.TEST",
            "SIZE",
            "8BITMIME",
            "PIPELINING",
            "SMTPUTF8",
        ]
        assert result.data["fingerprint"]["protocol"] == "smtp"
        assert result.data["identity_consistency"][
            "hostname_identity_consistent"
        ] is True
    finally:
        thread.join(timeout=2)
