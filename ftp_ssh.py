# ETHICAL USE: This tool is for authorized lab environments only.
# Do not run against any system you do not own or have permission to test.

import ftplib
import socket
import time
import os
import sys
from datetime import datetime

try:
    import paramiko
    SSH_OK = True
except:
    SSH_OK = False

# Rate limiting - max 5 attempts per 60 seconds per IP
attempt_log = {}
LIMIT = 5
WINDOW = 60


def is_blocked(ip):
    now = time.time()
    if ip not in attempt_log:
        attempt_log[ip] = []
    attempt_log[ip] = [t for t in attempt_log[ip] if now - t < WINDOW]
    if len(attempt_log[ip]) >= LIMIT:
        return True
    attempt_log[ip].append(now)
    return False


def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# FTP

def ftp_connect(host, port=21, user="anonymous", pwd="anon@lab.edu"):
    section("FTP Connection")
    if is_blocked(host):
        print(f"  [!] Rate limit exceeded for {host}. Blocked.")
        return None
    print(f"  [*] Connecting to {host}:{port} as {user}")
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=10)
        ftp.login(user, pwd)
        print(f"  [+] Login successful!")
        print(f"  [+] Banner: {ftp.getwelcome()}")
        return ftp
    except ftplib.error_perm as e:
        print(f"  [-] Login failed: {e}")
    except Exception as e:
        print(f"  [-] Error: {e}")
    return None


def ftp_list(ftp):
    print("\n  [*] Directory listing:")
    try:
        files = ftp.nlst()
        for f in files:
            print(f"      {f}")
        return files
    except Exception as e:
        print(f"  [!] {e}")
        return []


def ftp_download(ftp, filename):
    os.makedirs("ftp_output", exist_ok=True)
    local = f"ftp_output/{os.path.basename(filename)}"
    try:
        with open(local, "wb") as f:
            ftp.retrbinary(f"RETR {filename}", f.write)
        print(f"  [+] Downloaded: {filename} -> {local}")
    except Exception as e:
        print(f"  [!] Download failed: {e}")


# SSH

def ssh_password(host, port=22, user="user", pwd="password"):
    section("SSH - Password Auth")
    if not SSH_OK:
        print("  [!] paramiko not installed. Run: pip install paramiko")
        return None
    if is_blocked(host):
        print(f"  [!] Rate limit exceeded for {host}. Blocked.")
        return None
    print(f"  [*] Connecting to {host}:{port} as {user}")
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=port, username=user, password=pwd, timeout=10)
        print("  [+] Login successful!")
        return c
    except paramiko.AuthenticationException:
        print("  [-] Wrong credentials")
    except Exception as e:
        print(f"  [-] {e}")
    return None


def ssh_key(host, port=22, user="user", key="~/.ssh/id_rsa"):
    section("SSH - Key Auth")
    if not SSH_OK:
        print("  [!] paramiko not installed")
        return None
    if is_blocked(host):
        print(f"  [!] Rate limit exceeded for {host}. Blocked.")
        return None
    key = os.path.expanduser(key)
    print(f"  [*] Connecting to {host}:{port} as {user} using key: {key}")
    try:
        pk = paramiko.RSAKey.from_private_key_file(key)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=port, username=user, pkey=pk, timeout=10)
        print("  [+] Key auth successful!")
        return c
    except FileNotFoundError:
        print(f"  [-] Key file not found: {key}")
    except Exception as e:
        print(f"  [-] {e}")
    return None


def run_command(client, cmd):
    print(f"\n  [*] Command: {cmd}")
    try:
        _, out, err = client.exec_command(cmd)
        output = out.read().decode().strip()
        errors = err.read().decode().strip()
        if output:
            print(f"  {output}")
        if errors:
            print(f"  [err] {errors}")
        return output
    except Exception as e:
        print(f"  [!] {e}")
        return ""


def sftp_upload(client, local, remote="/tmp/upload.txt"):
    section("SFTP Upload")
    try:
        sftp = client.open_sftp()
        sftp.put(local, remote)
        sftp.close()
        print(f"  [+] Uploaded {local} -> {remote}")
    except Exception as e:
        print(f"  [!] {e}")


def sftp_download(client, remote, local_dir="sftp_output"):
    section("SFTP Download")
    os.makedirs(local_dir, exist_ok=True)
    local = f"{local_dir}/{os.path.basename(remote)}"
    try:
        sftp = client.open_sftp()
        sftp.get(remote, local)
        sftp.close()
        print(f"  [+] Downloaded {remote} -> {local}")
    except Exception as e:
        print(f"  [!] {e}")


# Main

print("\n[!] ETHICAL USE: Authorized lab environments only.")
print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

mode = sys.argv[1] if len(sys.argv) > 1 else "help"
host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

if mode == "ftp":
    ftp = ftp_connect(host)
    if ftp:
        files = ftp_list(ftp)
        if files:
            ftp_download(ftp, files[0])
        ftp.quit()

elif mode == "ssh-pass":
    user = sys.argv[3] if len(sys.argv) > 3 else "user"
    pwd  = sys.argv[4] if len(sys.argv) > 4 else "password"
    client = ssh_password(host, user=user, pwd=pwd)
    if client:
        section("Remote Commands")
        run_command(client, "whoami")
        run_command(client, "uname -a")
        with open("sftp_test.txt", "w") as f:
            f.write(f"test upload {datetime.now()}\n")
        sftp_upload(client, "sftp_test.txt", "/tmp/sftp_test.txt")
        sftp_download(client, "/tmp/sftp_test.txt")
        client.close()

elif mode == "ssh-key":
    user = sys.argv[3] if len(sys.argv) > 3 else "user"
    key  = sys.argv[4] if len(sys.argv) > 4 else "~/.ssh/id_rsa"
    client = ssh_key(host, user=user, key=key)
    if client:
        section("Remote Commands")
        run_command(client, "whoami")
        run_command(client, "uname -a")
        client.close()

elif mode == "rate-test":
    section("Rate Limiter Demo")
    print(f"  Sending 7 attempts to {host} (limit is {LIMIT} per {WINDOW}s):")
    for i in range(1, 8):
        status = "BLOCKED" if is_blocked(host) else "ALLOWED"
        print(f"  Attempt {i}: {status}")

else:
    print("\nUsage:")
    print("  python ftp_ssh.py ftp 127.0.0.1")
    print("  python ftp_ssh.py ssh-pass 127.0.0.1 user password")
    print("  python ftp_ssh.py ssh-key 127.0.0.1 user ~/.ssh/id_rsa")
    print("  python ftp_ssh.py rate-test 127.0.0.1")
