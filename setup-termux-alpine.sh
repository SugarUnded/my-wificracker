#!/usr/bin/env bash
# language: bash, file: setup-termux-alpine.sh
# RODAR NO TERMUX NATIVO (não dentro do alpine).
# Instala proot-distro + alpine, liga o termux-api no alpine e cria o wrapper `atw`.
set -e

echo "[*] instalando proot-distro..."
pkg install -y proot-distro

echo "[*] instalando alpine..."
proot-distro install alpine 2>/dev/null || echo "[=] alpine já instalado"

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

# wrapper: entra no alpine com termux-api acessível via bind, roda o autowifi
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

[*] pronto. dentro do alpine, uma vez:
      proot-distro login alpine
      apk add --no-cache python3 iw wireless-tools aircrack-ng
      apk add --no-cache git
      git clone https://github.com/SugarUnded/my-wificracker.git /root/my-wificracker

[*] depois, do Termux nativo, rode com:
      atw                 # detecta + recomenda (usa o scan do termux-api)
      atw --scan-json ~/scan.json   # scan salvo no Termux nativo

[*] plano B (termux-api chato dentro do proot):
      termux-wifi-scaninfo > ~/scan.json     # no TERMUX NATIVO
      atw --scan-json ~/scan.json            # no ALPINE
MSG
