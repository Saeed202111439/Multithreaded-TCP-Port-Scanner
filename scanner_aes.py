# scanner_aes.py - Phase 1 Port Scanner + AES Encrypted Communication Layer
# Course: 605346 - Information & Network Security Programming
# University of Petra

import socket
import threading
import os
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

log_lock = threading.Lock()

# ── AES helpers ───────────────────────────────────────────────────────────────

SHARED_KEY = b"ThisIs16ByteKey!"   # 16 bytes = AES-128
HMAC_KEY   = b"ThisIsHMACKey!32bytesLongForHMAC"

def encrypt(data: str) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data.encode(), AES.block_size))
    mac = HMAC.new(HMAC_KEY, iv + ct, SHA256).digest()
    return iv + ct + mac

def decrypt(raw: bytes) -> str:
    iv  = raw[:16]
    mac = raw[-32:]
    ct  = raw[16:-32]
    expected = HMAC.new(HMAC_KEY, iv + ct, SHA256).digest()
    if expected != mac:
        raise ValueError("Integrity check failed - message tampered!")
    cipher = AES.new(SHARED_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ── Encrypted server (receives scan results) ─────────────────────────────────

def run_server(host="127.0.0.1", port=9999):
    print(f"\n[SERVER] Listening on {host}:{port}")
    print("[SERVER] Waiting for encrypted scan results...\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)

    conn, addr = s.accept()
    print(f"[SERVER] Connection from {addr}")

    raw = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        raw += chunk

    try:
        message = decrypt(raw)
        print(f"[SERVER] Decrypted message:\n{message}")
    except ValueError as e:
        print(f"[SERVER] ERROR: {e}")

    conn.close()
    s.close()

# ── Encrypted client (sends scan results) ────────────────────────────────────

def run_client(message, host="127.0.0.1", port=9999):
    time.sleep(1)
    print(f"\n[CLIENT] Connecting to {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    encrypted = encrypt(message)
    s.sendall(encrypted)
    s.close()
    print(f"[CLIENT] Encrypted message sent ({len(encrypted)} bytes)")

# ── Port scanner (from Phase 1) ───────────────────────────────────────────────

def setup_log():
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"logs/scan_{ts}.log"
    with open(path, "w") as f:
        f.write(f"Scan Log - {datetime.now().isoformat()}\n{'='*50}\n\n")
    return path

def write_log(path, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name = threading.current_thread().name
    with log_lock:
        with open(path, "a") as f:
            f.write(f"[{ts}] [{name}] {msg}\n")

def scan_port(target, port, timeout, log_path):
    result = {"port": port, "status": "closed"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((target, port)) == 0:
            result["status"] = "open"
            write_log(log_path, f"Port {port}/TCP OPEN")
        s.close()
    except Exception as e:
        write_log(log_path, f"Port {port}/TCP ERROR: {e}")
        result["status"] = "error"
    return result

def parse_ports(arg):
    ports = []
    for part in arg.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def run_scan(target, ports, threads, timeout, log_path):
    results = []
    print(f"\n[SCANNER] Target  : {target}")
    print(f"[SCANNER] Ports   : {ports[0]}-{ports[-1]} ({len(ports)} ports)")
    print(f"[SCANNER] Threads : {threads}")
    print("-" * 50)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, target, p, timeout, log_path): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            results.append(r)
            if r["status"] == "open":
                print(f"  [OPEN] Port {r['port']}/TCP")
    return results

# ── Demo mode ─────────────────────────────────────────────────────────────────

def demo_aes():
    print("\n[*] AES Communication Demo")
    print("[*] Simulating encrypted scan result transmission\n")
    print("[*] Key      : SHARED_KEY (AES-128-CBC)")
    print("[*] Integrity: HMAC-SHA256")
    print("[*] Mode     : Localhost only (127.0.0.1:9999)\n")
    print("-" * 50)

    # Test message
    test_msg = "SCAN RESULT: scanme.nmap.org | Open ports: 22, 80 | Time: " + datetime.now().isoformat()

    print(f"[*] Original message:\n    {test_msg}")
    encrypted = encrypt(test_msg)
    print(f"\n[*] Encrypted ({len(encrypted)} bytes):")
    print(f"    {encrypted[:48].hex()}...")
    decrypted = decrypt(encrypted)
    print(f"\n[*] Decrypted:\n    {decrypted}")
    print("\n[+] Integrity check PASSED")

    # Tampering demo
    print("\n[*] Tampering demo: modifying one byte...")
    tampered = bytearray(encrypted)
    tampered[20] ^= 0xFF
    try:
        decrypt(bytes(tampered))
    except ValueError as e:
        print(f"[+] Tampered message detected: {e}")

def run_full_demo():
    print("\n[*] Full integrated demo: scan + encrypt + transmit")

    log_path = setup_log()
    target = "127.0.0.1"
    ports = parse_ports("20-25,80,443")

    start = time.time()
    results = run_scan(target, ports, threads=10, timeout=0.5, log_path=log_path)
    elapsed = round(time.time() - start, 2)

    open_ports = [r["port"] for r in results if r["status"] == "open"]
    summary = f"Target: {target} | Scanned: {len(results)} ports | Open: {open_ports} | Time: {elapsed}s"

    print(f"\n[SCANNER] Done in {elapsed}s")
    print(f"[SCANNER] Open ports: {open_ports}")
    print(f"\n[*] Encrypting and sending scan results...")

    server_thread = threading.Thread(target=run_server, args=("127.0.0.1", 9999))
    server_thread.daemon = True
    server_thread.start()

    run_client(summary, "127.0.0.1", 9999)
    server_thread.join(timeout=5)

# ── Entry point ───────────────────────────────────────────────────────────────

mode = sys.argv[1] if len(sys.argv) > 1 else "help"
print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if mode == "demo-aes":
    demo_aes()
elif mode == "demo-full":
    run_full_demo()
else:
    print("\nUsage:")
    print("  python scanner_aes.py demo-aes   # AES encrypt/decrypt + tamper demo")
    print("  python scanner_aes.py demo-full  # Full scan + encrypt + transmit demo")
    print("\nInstall: pip install pycryptodome")
