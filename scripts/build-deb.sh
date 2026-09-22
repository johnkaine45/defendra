#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/opt/homebrew/bin:$PATH"
VER="${1:-$(cat "$ROOT/VERSION")}"
ARCH="${2:-amd64}"
GOARCH="$ARCH"
if [[ "$ARCH" == "amd64" ]]; then
  GOARCH=amd64
elif [[ "$ARCH" == "arm64" ]]; then
  GOARCH=arm64
fi

cd "$ROOT"
mkdir -p bin dist
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/johnkaine/defendra/internal/version.Version=$VER" -o "bin/defendra-linux-$GOARCH" ./cmd/defendra

PKG="dist/defendra_${VER}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/doc/defendra"
install -m 0755 "bin/defendra-linux-$GOARCH" "$PKG/usr/bin/defendra"
cat > "$PKG/usr/share/doc/defendra/README" <<EOF
Defendra — защита Ubuntu VDS.

  sudo defendra protect
  defendra help
EOF
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -x /usr/bin/defendra ]; then
  rm -f /usr/local/bin/defendra
  ln -s /usr/bin/defendra /usr/local/bin/defendra
fi
echo "Defendra установлена. Дальше на сервере:"
echo "  sudo defendra protect"
echo "Справка: defendra help"
EOF
chmod 0755 "$PKG/DEBIAN/postinst"
cat > "$PKG/DEBIAN/control" <<EOF
Package: defendra
Version: $VER
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: Defendra <defendra@local>
Depends: adduser
Description: защита свежего Ubuntu VDS одной командой
 Утилита для человека без опыта администрирования.
 После установки: sudo defendra protect
EOF
python3 "$ROOT/scripts/pack-deb.py" "$PKG" "$ROOT/dist/defendra_${VER}_${ARCH}.deb"
cp "$ROOT/dist/defendra_${VER}_${ARCH}.deb" "$ROOT/dist/defendra_${ARCH}.deb"
( cd "$ROOT/dist" && shasum -a 256 "defendra_${VER}_${ARCH}.deb" > "defendra_${VER}_${ARCH}.deb.sha256" )
( cd "$ROOT/dist" && shasum -a 256 "defendra_${ARCH}.deb" > "defendra_${ARCH}.deb.sha256" )
echo "собрано dist/defendra_${VER}_${ARCH}.deb  (ещё dist/defendra_${ARCH}.deb для latest/download)"
ls -l "dist/defendra_${VER}_${ARCH}.deb" "dist/defendra_${ARCH}.deb"
cat "dist/defendra_${ARCH}.deb.sha256"
