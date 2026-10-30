#!/usr/bin/env bash
# language: bash, file: setup-termux-alpine.sh
# RUN THIS IN NATIVE TERMUX (not inside alpine).
# Installs proot-distro + alpine, exposes termux-api inside alpine, and creates the `atw` wrapper.
set -e

echo "[*] installing proot-distro..."
pkg install -y proot-distro

echo "[*] installing alpine..."
proot-distro install alpine 2>/dev/null || echo "[=] alpine already installed"

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

# wrapper: enter alpine with termux-api reachable via bind mounts, then run autowifi
cat > "$PREFIX/bin/atw" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
exec proot-distro login alpine \\
  --bind "$PREFIX/bin:/opt/tbin" \\
  --bind "$PREFIX/lib:/opt/tlib" \\
  -- /bin/sh -lc '
    export PATH="/opt/tbin:\$PATH"
    export LD_LIBRARY_PATH="/opt/tlib:\$LD_LIBRARY_PATH"
    cd /root/my-wificracker 2>/dev/null || cd /root
    exec python3 autowifi.py "\$@"
  ' -- "\$@"
EOF
chmod +x "$PREFIX/bin/atw"

cat <<'MSG'

[*] done. inside alpine, once:
      proot-distro login alpine
      apk add --no-cache python3 iw wireless-tools aircrack-ng
      apk add --no-cache git
      git clone https://github.com/SugarUnded/my-wificracker.git /root/my-wificracker

[*] after that, from native Termux, run with:
      atw                 # detect + recommend (uses the termux-api scan)
      atw --scan-json ~/scan.json   # saved scan from native Termux

[*] plan B (termux-api is flaky inside proot):
      termux-wifi-scaninfo > ~/scan.json     # in NATIVE TERMUX
      atw --scan-json ~/scan.json            # in ALPINE
MSG
