#!/usr/bin/env bash
# language: bash, file: install.sh — instala deps no Termux (pkg) ou Alpine (apk)
set -e
if [ -f /etc/alpine-release ] || command -v apk >/dev/null; then
  echo "[*] Alpine detectado"
  apk add --no-cache python3 iw wireless-tools aircrack-ng
  apk add --no-cache hcxdumptool hcxtools hashcat reaver 2>/dev/null \
    || echo "[!] alguns pacotes de ataque não existem no repo Alpine — compile ou use o Termux nativo"
elif command -v pkg >/dev/null; then
  echo "[*] Termux detectado"
  pkg update -y
  pkg install -y python termux-api git
  pkg install -y aircrack-ng hashcat 2>/dev/null || true
  pkg install -y root-repo tsu 2>/dev/null || true
else
  echo "[!] SO não reconhecido — instale python3 na mão"; exit 1
fi
chmod +x autowifi.py wpa_crack.py 2>/dev/null || true
echo "[*] pronto. rode: python autowifi.py"
