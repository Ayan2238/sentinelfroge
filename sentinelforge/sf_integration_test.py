"""
SentinelForge Integration Test — Safe Environment
Spins up local services, scans them, verifies detection.
"""

import threading
import http.server
import socketserver
import socket
import time

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

def start_local_http(port=8000):
    handler = QuietHandler
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

def scan_ports(host, ports, max_workers=32):
    from concurrent.futures import ThreadPoolExecutor
    open_ports = []
    closed_ports = []

    def check(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return port, "open"
            except (ConnectionRefusedError, socket.timeout, OSError):
                return port, "closed"

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(check, ports))
    elapsed = time.perf_counter() - start

    for port, state in results:
        (open_ports if state == "open" else closed_ports).append(port)

    return {
        "ports_scanned": len(ports),
        "open_count": len(open_ports),
        "closed_count": len(closed_ports),
        "open_ports": open_ports,
        "scanner_elapsed": round(elapsed, 4),
        "max_workers": max_workers,
    }

def run_test():
    print("=" * 50)
    print("SentinelForge Integration Test — Safe Mode")
    print("=" * 50)

    servers = []
    for port in (8000, 8080):
        try:
            servers.append(start_local_http(port))
            print(f"[+] Local server started on 127.0.0.1:{port}")
        except OSError:
            print(f"[!] Port {port} already in use — skipping")

    time.sleep(0.5)
    ports = list(range(7990, 8101))
    print(f"\n[*] Scanning {len(ports)} ports on 127.0.0.1...")

    result = scan_ports("127.0.0.1", ports, max_workers=32)

    print("\n─── Scan Result ───")
    for k, v in result.items():
        print(f"  {k}: {v}")

    expected_open = {8000, 8080}
    found_open = set(result["open_ports"])

    print("\n─── Verification ───")
    if expected_open.issubset(found_open):
        print("  ✅ PASS — All expected ports detected")
    else:
        print(f"  ❌ FAIL — Missing: {expected_open - found_open}")

    print("  ✅ PASS — Speed acceptable" if result["scanner_elapsed"] < 5 else "  ⚠️ SLOW")

    for s in servers:
        s.shutdown()
        s.server_close()
    print("\n[+] Local servers shut down. Test complete.")

if __name__ == "__main__":
    run_test()
