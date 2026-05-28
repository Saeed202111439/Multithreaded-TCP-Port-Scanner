# audit.py - Vulnerability Audit Script
# Runs Bandit on all phase scripts and saves the report
# Course: 605346 - University of Petra

import subprocess
import os
import sys
from datetime import datetime

files = ["scanner.py", "recon.py", "ftp_ssh.py", "payload.py"]
output_dir = "audit_output"
os.makedirs(output_dir, exist_ok=True)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_file = f"{output_dir}/bandit_report_{ts}.txt"

print("[*] Vulnerability Audit - Bandit Static Analysis")
print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"[*] Target files: {', '.join(files)}\n")

# Check bandit is installed
try:
    subprocess.run(["bandit", "--version"], capture_output=True, check=True)
except FileNotFoundError:
    print("[!] Bandit not found. Install it: pip install bandit")
    sys.exit(1)

with open(out_file, "w") as report:
    report.write(f"Bandit Vulnerability Audit Report\n")
    report.write(f"Generated: {datetime.now().isoformat()}\n")
    report.write(f"{'='*60}\n\n")

    for f in files:
        if not os.path.exists(f):
            print(f"  [!] {f} not found, skipping")
            continue

        print(f"  [*] Scanning {f}...")
        result = subprocess.run(
            ["bandit", "-r", f, "-ll"],
            capture_output=True, text=True
        )

        output = result.stdout + result.stderr
        print(output)

        report.write(f"FILE: {f}\n")
        report.write("-" * 50 + "\n")
        report.write(output)
        report.write("\n\n")

print(f"[*] Full report saved: {out_file}")
