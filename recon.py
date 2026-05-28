# ETHICAL USE: This tool is for authorized lab environments only.
# Do not run against any system you do not own or have permission to test.

import socket
import os
import json
import sys
from datetime import datetime

# checking for imports 
try:
    import dns.resolver
    DNS_OK = True
except:
    DNS_OK = False

try:
    import whois
    WHOIS_OK = True
except:
    WHOIS_OK = False

try:
    import requests
    REQ_OK = True
except:
    REQ_OK = False

TARGET = "scanme.nmap.org"
SUBDOMAINS = ["www", "mail", "ftp", "admin", "smtp", "ns1", "ns2", "vpn", "dev", "api", "test", "blog"]
PORTS = [21, 22, 25, 53, 80, 110, 443, 8080]


def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


def dns_enum(target, results):
    section("1. DNS Enumeration")
    data = {}
    if DNS_OK:
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=5)
                data[rtype] = [str(r) for r in answers]
                print(f"  [{rtype}] {data[rtype]}")
            except:
                print(f"  [{rtype}] No record")
    else:
        try:
            ip = socket.gethostbyname(target)
            data["A"] = [ip]
            print(f"  [A] {ip}")
        except Exception as e:
            print(f"  [!] Failed: {e}")
    results["dns"] = data


def whois_lookup(target, results):
    section("2. WHOIS Lookup")
    if not WHOIS_OK:
        print("  [!] python-whois not installed")
        results["whois"] = "not available"
        return
    try:
        w = whois.whois(target)
        info = {
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": str(w.name_servers)
        }
        for k, v in info.items():
            print(f"  {k:<20}: {v}")
        results["whois"] = info
    except Exception as e:
        print(f"  [!] WHOIS failed: {e}")
        results["whois"] = str(e)


def banner_grab(target, results):
    section("3. Banner Grabbing")
    banners = {}
    try:
        ip = socket.gethostbyname(target)
    except:
        print(f"  [!] Could not resolve {target}")
        results["banners"] = {}
        return

    for port in PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                try:
                    if port in [80, 8080]:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()[:100]
                    banners[port] = banner
                    print(f"  [Port {port}] OPEN | {banner[:70]}")
                except:
                    banners[port] = "open"
                    print(f"  [Port {port}] OPEN")
            s.close()
        except:
            pass

    results["banners"] = banners


def http_headers(target, results):
    section("4. HTTP Header Inspection")
    if not REQ_OK:
        print("  [!] requests not installed")
        results["http_headers"] = "not available"
        return
    for scheme in ["http", "https"]:
        try:
            r = requests.get(f"{scheme}://{target}", timeout=5)
            print(f"  URL: {scheme}://{target}  (Status: {r.status_code})")
            for k, v in r.headers.items():
                print(f"  {k:<30}: {v}")
            results["http_headers"] = {"status": r.status_code, "headers": dict(r.headers)}
            return
        except Exception as e:
            print(f"  [{scheme}] {e}")
    results["http_headers"] = "failed"


def subdomain_brute(target, results):
    section("5. Subdomain Brute-Force")
    parts = target.split(".")
    base = ".".join(parts[-2:])
    found = {}
    for sub in SUBDOMAINS:
        fqdn = f"{sub}.{base}"
        try:
            ip = socket.gethostbyname(fqdn)
            found[fqdn] = ip
            print(f"  [FOUND] {fqdn:<35} -> {ip}")
        except:
            print(f"  [    ] {fqdn}")
    results["subdomains"] = found
    print(f"\n  Found: {len(found)}")


def save_report(target, results):
    os.makedirs("recon_output", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"recon_output/recon_{ts}.json"
    with open(path, "w") as f:
        json.dump({"target": target, "timestamp": datetime.now().isoformat(), "results": results}, f, indent=2, default=str)
    print(f"\n[*] Report saved: {path}")


target = sys.argv[1] if len(sys.argv) > 1 else TARGET
print(f"\n[*] Target : {target}")
print(f"[*] Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("[!] ETHICAL USE: Authorized lab environments only.")

results = {}
dns_enum(target, results)
whois_lookup(target, results)
banner_grab(target, results)
http_headers(target, results)
subdomain_brute(target, results)
save_report(target, results)

print("\n[*] Done.\n")
