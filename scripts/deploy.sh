#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="${DEFENDRA_KEY:-$ROOT/id_ed25519}"
HOST="${DEFENDRA_HOST:-}"
export PATH="/opt/homebrew/bin:$PATH"
if [[ -z "$HOST" ]]; then
  echo "Задайте DEFENDRA_HOST, например admin@203.0.113.10" >&2
  exit 2
fi

cd "$ROOT"
VER="$(cat "$ROOT/VERSION")"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/johnkaine/defendra/internal/version.Version=$VER" -o bin/defendra-linux-amd64 ./cmd/defendra
scp -i "$KEY" -P 22 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new bin/defendra-linux-amd64 "$HOST:/tmp/defendra-upload"

REMOTE_USER="${HOST%%@*}"
if [[ "$REMOTE_USER" == "$HOST" ]]; then
  REMOTE_USER=root
fi

if [[ "$REMOTE_USER" == "root" ]]; then
  remote() {
    ssh -i "$KEY" -p 22 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$HOST" 'bash -s'
  }
else
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
  remote() {
    {
      printf '%s\n' "$SUDO_PW"
      cat
    } | ssh -i "$KEY" -p 22 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$HOST" 'sudo -S -p "" bash -s'
  }
fi

remote <<'SCRIPT'
set -euo pipefail
SRC=""
for p in /tmp/defendra-upload /root/defendra-upload; do
  if [[ -f "$p" ]]; then SRC="$p"; break; fi
done
if [[ -z "$SRC" ]]; then
  HOME_ADMIN="$(getent passwd admin | cut -d: -f6 || true)"
  if [[ -n "${HOME_ADMIN:-}" && -f "$HOME_ADMIN/defendra-upload" ]]; then
    SRC="$HOME_ADMIN/defendra-upload"
  fi
fi
if [[ -z "$SRC" || ! -f "$SRC" ]]; then
  echo "нет бинарника defendra-upload" >&2
  exit 2
fi
install -m 0755 "$SRC" /usr/bin/defendra
install -m 0755 "$SRC" /usr/local/bin/defendra
rm -f "$SRC" /tmp/defendra
chmod 0750 /var/lib/defendra 2>/dev/null || true
chgrp admin /var/lib/defendra 2>/dev/null || true
chmod 0640 /var/lib/defendra/summary.json 2>/dev/null || true
chmod 0644 /var/lib/defendra/motd.txt 2>/dev/null || true
defendra version
SCRIPT
