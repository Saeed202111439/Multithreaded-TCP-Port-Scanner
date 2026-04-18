"""
scanner.py - Multithreaded TCP Port Scanner
Course: 605346 - Information & Network Security Programming
University of Petra - Faculty of Information Technology
"""

import socket
import argparse
import os
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

log_lock = threading.Lock()


def setup_log_file(target):
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(logs_dir, f"scan_{timestamp}.log")
    with open(log_path, "w") as f:
        f.write(f"{'='*60}\n")
        f.write(f"  Port Scanner Log\n")
        f.write(f"  Target  : {target}\n")
        f.write(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*60}\n\n")
    return log_path


def write_log(log_path, message):
    thread_name = threading.current_thread().name
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        with open(log_path, "a") as f:
            f.write(f"[{timestamp}] [{thread_name}] {message}\n")


def scan_port(target, port, timeout, log_path):
    result = {"port": port, "status": "closed", "banner": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((target, port))
        if conn == 0:
            result["status"] = "open"
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                result["banner"] = banner[:80] if banner else ""
            except Exception:
                pass
            msg = f"Port {port}/TCP  OPEN"
            if result["banner"]:
                msg += f"  | Banner: {result['banner'][:60]}"
            write_log(log_path, msg)
        else:
            write_log(log_path, f"Port {port}/TCP  CLOSED")
    except socket.gaierror:
        write_log(log_path, f"Port {port}/TCP  ERROR - Could not resolve hostname")
        result["status"] = "error"
    except socket.error as e:
        write_log(log_path, f"Port {port}/TCP  ERROR - {e}")
        result["status"] = "error"
    finally:
        sock.close()
    return result


def parse_port_range(port_arg):
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def run_scan(target, ports, threads, timeout, log_path, silent=False):
    results = []
    if not silent:
        print(f"\n[*] Target   : {target}")
        print(f"[*] Ports    : {ports[0]}-{ports[-1]} ({len(ports)} ports)")
        print(f"[*] Threads  : {threads}")
        print(f"[*] Timeout  : {timeout}s")
        print(f"[*] Log      : {log_path}")
        print(f"[*] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)

    write_log(log_path, f"Target: {target} | Ports: {len(ports)} | Threads: {threads}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout, log_path): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result["status"] == "open" and not silent:
                print(f"  [OPEN]  Port {result['port']}/TCP")

    return results


def print_summary(results, log_path, elapsed):
    open_ports  = [r for r in results if r["status"] == "open"]
    closed_ports = [r for r in results if r["status"] == "closed"]
    error_ports  = [r for r in results if r["status"] == "error"]

    lines = [
        "", "=" * 50, "  SCAN SUMMARY", "=" * 50,
        f"  Total    : {len(results)}",
        f"  Open     : {len(open_ports)}",
        f"  Closed   : {len(closed_ports)}",
        f"  Errors   : {len(error_ports)}",
        f"  Time     : {elapsed:.2f}s", ""
    ]
    if open_ports:
        lines.append("  Open Ports:")
        for r in sorted(open_ports, key=lambda x: x["port"]):
            line = f"    - {r['port']}/TCP"
            if r["banner"]:
                line += f"  [{r['banner'][:50]}]"
            lines.append(line)
    lines.append("=" * 50)

    for line in lines:
        print(line)

    with log_lock:
        with open(log_path, "a") as f:
            f.write("\n" + "\n".join(lines) + "\n")
            f.write(f"\nScan ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def run_benchmark(target, ports, timeout, log_path):
    """Run scan with 4 different thread counts and print a results table."""
    thread_counts = [10, 50, 100, 200]
    print("\n" + "=" * 60)
    print("  BENCHMARK MODE")
    print(f"  Target : {target}")
    print(f"  Ports  : {ports[0]}-{ports[-1]} ({len(ports)} ports)")
    print(f"  Timeout: {timeout}s")
    print("=" * 60)

    rows = []
    for n in thread_counts:
        start = time.time()
        results = run_scan(target, ports, n, timeout, log_path, silent=True)
        elapsed = round(time.time() - start, 2)
        open_count = len([r for r in results if r["status"] == "open"])
        pps = round(len(ports) / elapsed, 1) if elapsed > 0 else 0
        rows.append((n, len(ports), elapsed, pps, open_count))
        print(f"  Threads={n:>3} | Time={elapsed:>6.2f}s | Ports/s={pps:>7} | Open={open_count}")

    print("\n  --- COPY THIS TABLE INTO YOUR REPORT ---")
    print(f"  {'Threads':<10} {'Ports':<8} {'Time(s)':<10} {'Ports/sec':<12} {'Open':<6}")
    print(f"  {'-'*48}")
    for row in rows:
        print(f"  {row[0]:<10} {row[1]:<8} {row[2]:<10} {row[3]:<12} {row[4]:<6}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner - 605346 Network Security"
    )
    parser.add_argument("-t", "--target", type=str, default="scanme.nmap.org",
                        help="Target IP or hostname (default: scanme.nmap.org)")
    parser.add_argument("-p", "--ports", type=str, default="1-1024",
                        help="Ports: 80 | 22,80,443 | 1-1024 (default: 1-1024)")
    parser.add_argument("-n", "--threads", type=int, default=100,
                        help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout per port in seconds (default: 1.0)")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run with thread counts 10/50/100/200 and print comparison table")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Resolved {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"[!] Could not resolve: {args.target}")
        return

    try:
        ports = parse_port_range(args.ports)
    except ValueError:
        print("[!] Invalid port format.")
        return

    log_path = setup_log_file(args.target)

    if args.benchmark:
        run_benchmark(target_ip, ports, args.timeout, log_path)
    else:
        start = time.time()
        results = run_scan(target_ip, ports, args.threads, args.timeout, log_path)
        elapsed = time.time() - start
        print(f"\n[*] Completed in {elapsed:.2f}s")
        print_summary(results, log_path, elapsed)
        print(f"\n[*] Log saved: {log_path}\n")


if __name__ == "__main__":
    main()
