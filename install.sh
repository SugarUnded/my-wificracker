#!/usr/bin/env bash
# language: bash, file: install.sh — install dependencies on Termux (pkg) or Alpine (apk)
set -e

if [ -f /etc/alpine-release ] || command -v apk >/dev/null; then
  echo "[*] Alpine detected"
  apk add --no-cache python3 iw wireless-tools aircrack-ng
  apk add --no-cache hcxdumptool hcxtools hashcat reaver 2>/dev/null \
    || echo "[!] some attack packages are not in the Alpine repo — build them or use native Termux"
elif command -v pkg >/dev/null; then
  echo "[*] Termux detected"
  pkg update -y
  pkg install -y python termux-api git
  pkg install -y aircrack-ng hashcat 2>/dev/null || true
  pkg install -y root-repo tsu 2>/dev/null || true
else
  echo "[!] Unrecognized OS — install python3 manually"; exit 1
fi

chmod +x autowifi.py wpa_crack.py 2>/dev/null || true
echo "[*] done. run: python autowifi.py"
