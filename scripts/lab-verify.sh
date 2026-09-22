#!/usr/bin/env bash
# Live checks for the lab VDS. Does not print sudo or first-login secrets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="${DEFENDRA_KEY:-$ROOT/id_ed25519}"
HOST="${DEFENDRA_HOST:-admin@195.58.153.30}"
export PATH="/opt/homebrew/bin:$PATH"

SUDO_PW=""
if [[ -f "$ROOT/LAB.local.md" ]]; then
  SUDO_PW="$(python3 - "$ROOT/LAB.local.md" <<'PY'
import sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
for i, line in enumerate(lines):
    if "sudo password" in line.lower():
        for nxt in lines[i + 1:]:
            s = nxt.strip()
            if s and not s.startswith("#") and not s.endswith(":"):
                print(s)
                raise SystemExit
raise SystemExit("sudo password not found in LAB.local.md")
PY
)"
fi
if [[ -z "$SUDO_PW" ]]; then
  echo "нет пароля sudo (LAB.local.md)" >&2
  exit 2
fi

SSH=(ssh -i "$KEY" -p 22 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

fail=0
pass() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

echo "=== public ==="
https_code="$(curl -skI --max-time 8 "https://195.58.153.30/" | tr -d '\r' | awk 'NR==1{print $2}')"
if [[ "$https_code" == "200" ]]; then pass "https 443 → $https_code"; else bad "https 443 → ${https_code:-empty}"; fi
shop_code="$(curl -sI --max-time 8 "http://195.58.153.30:8080/" | tr -d '\r' | awk 'NR==1{print $2}')"
if [[ "$shop_code" == "200" ]]; then pass "shop 8080 → $shop_code"; else bad "shop 8080 → ${shop_code:-empty}"; fi
http_code="$(curl -sI --max-time 8 "http://195.58.153.30/" | tr -d '\r' | awk 'NR==1{print $2}')"
if [[ "$http_code" =~ ^(200|301|302|404)$ ]]; then pass "http 80 reachable → $http_code"; else bad "http 80 → ${http_code:-empty}"; fi

python3 - <<'PY'
import socket, sys
fail = 0
for port, want_open, name in (
    (6380, False, "redis 6380"),
    (3000, False, "node 3000"),
    (4000, False, "node 4000"),
    (3306, False, "mysql 3306"),
    (5432, False, "postgres 5432"),
    (22, True, "ssh 22"),
):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect(("195.58.153.30", port))
        open_ = True
    except Exception:
        open_ = False
    finally:
        s.close()
    ok = open_ == want_open
    print(("PASS  " if ok else "FAIL  ") + f"{name} {'open' if open_ else 'closed'} (want {'open' if want_open else 'closed'})")
    if not ok:
        fail = 1
sys.exit(fail)
PY
port_ec=$?
if [[ "$port_ec" -ne 0 ]]; then fail=1; fi

echo "=== ssh non-sudo ==="
nonsudo="$("${SSH[@]}" "$HOST" 'set -e
echo "version=$(defendra version)"
echo "menu_exit=$(defendra >/tmp/df-menu.txt; echo $?)"
echo "help_exit=$(defendra help >/tmp/df-help.txt; echo $?)"
echo "how_exit=$(defendra how-to-login >/tmp/df-how.txt; echo $?)"
echo "unk_exit=$(defendra nope >/tmp/df-unk.txt; echo $?; true)"
echo "nosudo_protect=$(defendra protect --yes >/tmp/df-ns.txt 2>&1; echo $?)"
echo "---MENU---"
cat /tmp/df-menu.txt
echo "---HELP---"
head -5 /tmp/df-help.txt
echo "---HOW---"
head -8 /tmp/df-how.txt
echo "---NOSUDO---"
head -6 /tmp/df-ns.txt
')"
echo "$nonsudo"
echo "$nonsudo" | grep -q 'version=Defendra 0.1.14' && pass "version 0.1.14" || bad "version"
echo "$nonsudo" | grep -q 'menu_exit=0' && pass "menu exit 0" || bad "menu exit"
echo "$nonsudo" | grep -q 'сервер в порядке' && pass "menu green" || bad "menu green"
echo "$nonsudo" | grep -q 'how_exit=0' && pass "how-to-login exit 0" || bad "how-to-login"
echo "$nonsudo" | grep -q 'ssh admin@' && pass "how-to-login admin" || bad "how-to-login user"
if echo "$nonsudo" | grep -q 'ssh root@'; then bad "how-to-login promised root SSH"; fi
if echo "$nonsudo" | grep -q 'ssh admin@admin'; then bad "how-to-login doubled user"; fi
echo "$nonsudo" | grep -q 'unk_exit=2' && pass "unknown cmd 2" || bad "unknown cmd"
echo "$nonsudo" | grep -q 'nosudo_protect=2' && pass "protect without sudo → 2" || bad "protect without sudo"
if echo "$nonsudo" | grep -Eiq 'ufw|fail2ban|sshd|jail'; then
  # help/menu should not teach ufw disable; internal words in errors are still bad in UI
  if echo "$nonsudo" | grep -Eiq 'ufw disable|ufw reset|fail2ban|jail'; then
    bad "jargon in non-sudo UI"
  else
    pass "no dangerous jargon in non-sudo UI"
  fi
else
  pass "no jargon in non-sudo UI"
fi

echo "=== root ssh denied ==="
set +e
root_out="$(ssh -i "$KEY" -p 22 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 root@195.58.153.30 true 2>&1)"
root_ec=$?
set -e
if [[ "$root_ec" != 0 ]]; then pass "root SSH denied ($root_ec)"; else bad "root SSH accepted"; fi

echo "=== sudo suite ==="
remote() {
  {
    printf '%s\n' "$SUDO_PW"
    cat
  } | "${SSH[@]}" "$HOST" 'sudo -S -p "" bash -s'
}

sudo_out="$(remote <<'SCRIPT'
set +e
ok() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; }

echo "version=$(defendra version)"

defendra protect --yes >/tmp/df-prot.txt 2>/tmp/df-prot.err
echo "protect_yes=$?"
grep -q 'Проверил' /tmp/df-prot.txt && echo MARK_QUIET=1
echo "---PROTECT---"
cat /tmp/df-prot.txt /tmp/df-prot.err

defendra protect --dry-run >/tmp/df-dry.txt 2>/tmp/df-dry.err
echo "protect_dry=$?"
echo "---DRY---"
cat /tmp/df-dry.txt

defendra status >/tmp/df-st.txt
echo "status_ec=$?"
echo "---STATUS---"
cat /tmp/df-st.txt

defendra scan --format json >/tmp/df-scan.json
echo "scan_ec=$?"

defendra watch >/tmp/df-watch.txt
echo "watch_ec=$?"

defendra allow-site --dry-run >/tmp/df-as-dry.txt
echo "allow_dry=$?"
echo "---ALLOWDRY---"
cat /tmp/df-as-dry.txt

defendra allow-site --yes >/tmp/df-as.txt
echo "allow_yes=$?"
echo "---ALLOW---"
cat /tmp/df-as.txt

defendra undo --dry-run >/tmp/df-undo-dry.txt
echo "undo_dry=$?"
echo "---UNDODRY---"
cat /tmp/df-undo-dry.txt

defendra explain SSH-PASSWORD >/tmp/df-ex.txt
echo "explain_pw=$?"
echo "---EXPLAIN---"
cat /tmp/df-ex.txt

defendra explain NET-DB-EXPOSED >/tmp/df-ex2.txt
echo "explain_db=$?"

defendra explain FW-SSH-MISSING >/tmp/df-ex3.txt
echo "explain_fw=$?"

defendra explain NO-SUCH >/tmp/df-ex4.txt
echo "explain_miss=$?"

defendra motd >/tmp/df-motd.txt
echo "motd_ec=$?"
echo "---MOTD---"
cat /tmp/df-motd.txt

defendra password >/tmp/df-pw.txt
echo "password_ec=$?"
# do not print or keep the sudo password
rm -f /tmp/df-pw.txt

# no-tty confirm
defendra protect </dev/null >/tmp/df-notty.txt 2>&1
echo "protect_notty=$?"

echo "---SERVICES---"
echo "ssh=$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd)"
echo "f2b=$(systemctl is-active fail2ban)"
echo "timer=$(systemctl is-enabled defendra-watch.timer 2>/dev/null)"
echo "ufw=$(ufw status | head -1)"

echo "---SSHD-T---"
sshd -T 2>/dev/null | awk 'tolower($1) ~ /^(permitrootlogin|passwordauthentication|allowusers|pubkeyauthentication)$/'

echo "---PERMS---"
stat -c '%a %n' /var/lib/defendra/summary.json /var/lib/defendra/state.json /var/lib/defendra/first-login.txt /etc/ssh/sshd_config.d/00-defendra.conf /etc/fail2ban/jail.d/defendra.conf 2>/dev/null

echo "---USERS---"
awk -F: '$3>=1000 && $3<65534 {print $1,$3,$7}' /etc/passwd

echo "---DOCKER---"
docker ps --format '{{.Names}} {{.Status}} {{.Ports}}' 2>/dev/null

echo "---KEEP---"
python3 - <<'PY'
import json
st=json.load(open("/var/lib/defendra/state.json"))
print("level", st.get("level"))
print("user", st.get("user"))
print("ssh_locked", st.get("ssh_locked"))
print("keep", st.get("keep_ports"))
print("ssh_users", st.get("ssh_users"))
print("has_protect", st.get("has_protect"))
PY

echo "---SCAN-FAILS---"
python3 - <<'PY'
import json
doc=json.load(open("/tmp/df-scan.json"))
fails=[]
for f in doc.get("findings",[]):
    if f.get("status") in ("fail","warn"):
        fails.append(f"{f.get('id')} {f.get('status')}")
print("fail_count", len(fails))
for x in fails:
    print("FINDING", x)
print("schema", doc.get("schema_version"), "ver", doc.get("defendra_version"))
PY

echo "---BACKUP---"
test -f /var/lib/defendra/backups/last/MANIFEST && echo "manifest=yes" || echo "manifest=no"
# unexpected port while listening
python3 - <<'PY' &
import socket, time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 19999)); s.listen(); time.sleep(12); s.close()
PY
sleep 1
defendra status >/tmp/df-st2.txt
echo "status_unexpected=$?"
echo "---STATUS-UNEXP---"
cat /tmp/df-st2.txt
wait 2>/dev/null
sleep 1
defendra status >/tmp/df-st3.txt
echo "status_after=$?"

# local curls
echo "---LOCALCURL---"
curl -sI --max-time 5 -k https://127.0.0.1/ | tr -d '\r' | awk 'NR==1{print "local443",$2}'
curl -sI --max-time 5 http://127.0.0.1:8080/ | tr -d '\r' | awk 'NR==1{print "local8080",$2}'
rm -f /tmp/df-pw.txt /tmp/df-*.txt /tmp/df-*.err /tmp/df-*.json
SCRIPT
)"

echo "$sudo_out"

echo "$sudo_out" | grep -q 'protect_yes=0' && pass "protect --yes 0" || bad "protect --yes"
echo "$sudo_out" | grep -q 'MARK_QUIET=1' && pass "quiet protect text" || bad "quiet protect text"
echo "$sudo_out" | grep -q 'protect_dry=0' && pass "protect --dry-run 0" || bad "dry-run"
echo "$sudo_out" | grep -q 'status_ec=0' && pass "status 0" || bad "status"
echo "$sudo_out" | grep -q 'Defendra • порядок' && pass "status green" || bad "status green"
echo "$sudo_out" | grep -q 'scan_ec=0' && pass "scan json 0" || bad "scan"
echo "$sudo_out" | grep -q 'watch_ec=0' && pass "watch 0" || bad "watch"
echo "$sudo_out" | grep -q 'allow_yes=0' && pass "allow-site --yes 0" || bad "allow-site"
echo "$sudo_out" | grep -q 'undo_dry=0' && pass "undo --dry-run 0" || bad "undo dry-run"
echo "$sudo_out" | grep -q 'Ничего не меняю' && pass "undo dry-run text" || true
echo "$sudo_out" | grep -q 'explain_pw=0' && pass "explain SSH-PASSWORD" || bad "explain pw"
echo "$sudo_out" | grep -q 'explain_miss=1' && pass "explain unknown 1" || bad "explain unknown"
echo "$sudo_out" | grep -q 'protect_notty=2' && pass "protect no-tty → 2" || bad "protect no-tty"
echo "$sudo_out" | grep -q 'passwordauthentication no' && pass "sshd password no" || bad "sshd password"
echo "$sudo_out" | grep -q 'permitrootlogin no' && pass "sshd root no" || bad "sshd root"
echo "$sudo_out" | grep -q 'allowusers admin' && pass "sshd AllowUsers admin" || bad "sshd AllowUsers"
echo "$sudo_out" | grep -q '640 /var/lib/defendra/summary.json' && pass "summary 0640" || bad "summary perms"
echo "$sudo_out" | grep -q '600 /var/lib/defendra/first-login.txt' && pass "first-login 0600" || bad "first-login perms"
echo "$sudo_out" | grep -q '640 /etc/fail2ban/jail.d/defendra.conf' && pass "jail 0640" || bad "jail perms"
echo "$sudo_out" | grep -q 'f2b=active' && pass "fail2ban active" || bad "fail2ban"
echo "$sudo_out" | grep -q 'timer=enabled' && pass "watch timer enabled" || bad "watch timer"
echo "$sudo_out" | grep -qi 'status: active' && pass "ufw active" || bad "ufw"
echo "$sudo_out" | grep -q 'fail_count 0' && pass "scan no fail/warn" || bad "scan has findings"
echo "$sudo_out" | grep -q 'ver 0.1.14' && pass "scan version 0.1.14" || bad "scan version"
echo "$sudo_out" | grep -q 'user admin' && pass "state user admin" || bad "state user"
echo "$sudo_out" | grep -q 'ssh_locked True' && pass "state ssh locked" || bad "state ssh locked"
echo "$sudo_out" | grep -q '8080' && pass "keep/ufw has 8080" || bad "8080 keep"
echo "$sudo_out" | grep -q 'status_unexpected=1' && pass "unexpected 19999 → status 1" || bad "unexpected port not flagged"
echo "$sudo_out" | grep -q '19999' && pass "status mentions 19999" || bad "status text 19999"
echo "$sudo_out" | grep -q 'status_after=0' && pass "status green after 19999 gone" || bad "status after unexpected"
echo "$sudo_out" | grep -q 'local443 200' && pass "local 443" || bad "local 443"
echo "$sudo_out" | grep -q 'local8080 200' && pass "local 8080" || bad "local 8080"
echo "$sudo_out" | grep -q 'password_ec=0' && pass "password cmd 0" || bad "password cmd"
echo "$sudo_out" | grep -q 'motd_ec=0' && pass "motd 0" || bad "motd"

prot="$(echo "$sudo_out" | awk '/---PROTECT---/,/---DRY---/')"
if echo "$prot" | grep -Eiq 'fail2ban|\bsshd\b|jail|ufw disable'; then
  bad "jargon in user screens"
else
  pass "no jargon in user screens"
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "ALL CHECKS PASSED"
  exit 0
fi
echo "SOME CHECKS FAILED"
exit 1
