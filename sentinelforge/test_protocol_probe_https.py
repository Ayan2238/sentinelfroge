import http.server
import json
import os
import ssl
import subprocess
import tempfile
import threading

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.protocol_probe import ProtocolProbe


class TestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SentinelForgeTLS/1.0"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def log_message(self, *_):
        pass


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cert = os.path.join(tmp, "cert.pem")
        key = os.path.join(tmp, "key.pem")

        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key,
                "-out", cert,
                "-sha256",
                "-days", "1",
                "-nodes",
                "-subj", "/CN=127.0.0.1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        server = http.server.HTTPServer(("127.0.0.1", 0), TestHandler)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(
            server.socket,
            server_side=True,
        )

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
        )
        thread.start()

        try:
            config = ConfigManager()
            config.set("network.verify_ssl", False)

            probe = ProtocolProbe(
                config=config,
                timeout=3.0,
                max_body_bytes=8192,
            )

            result = probe.probe(
                target="127.0.0.1",
                address="127.0.0.1",
                address_family="ipv4",
                port=server.server_port,
                service="https",
            )

            print(json.dumps({
                "port": result.port,
                "protocol": result.protocol,
                "success": result.success,
                "method": result.identification_method,
                "confidence": result.confidence,
                "data": result.data,
                "evidence": list(result.evidence),
                "error": result.error,
            }, indent=2))

            assert result.success
            assert result.protocol == "https"
            assert result.data["status_code"] == 200

            tls = result.data["tls"]
            assert tls["version"]
            assert tls["cipher"]
            assert tls["certificate_subject"]
            assert tls["certificate_issuer"]
            assert tls["certificate_serial"]
            assert tls["certificate_not_before"]
            assert tls["certificate_not_after"]

            print("HTTPS/TLS protocol probe: PASS")

        finally:
            server.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
