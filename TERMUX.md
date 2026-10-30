# Running autowifi on Termux (Android)

Install and usage guide for the phone. There are two layers:

- **Native Termux** — talks to the radio/scan (`termux-api`). This is where
  `termux-wifi-scaninfo` actually works.
- **Alpine (proot)** — runs the analysis, the cracking, and everything else.

The bridge between them is **`--scan-json`**: scan in Termux, analyse in Alpine.

---

## 1. Install the apps

1. **Termux** — get it from **F-Droid** or the GitHub releases. **Do NOT** use
   the Play Store build (outdated, broken).
   - https://f-droid.org/packages/com.termux/
2. **Termux:API** — same source, a version compatible with your Termux.
   - https://f-droid.org/packages/com.termux.api/

> F-Droid not opening? It is only a shortcut, not a requirement. Download the
> APKs straight from GitHub instead:
> `https://github.com/termux/termux-app/releases/latest` (pick `arm64-v8a`) and
> `https://github.com/termux/termux-api/releases/latest`. Install Termux first,
> then Termux:API. Do not mix the F-Droid and GitHub builds — the signatures
> differ and Android will refuse.

---

## 2. Base Termux

```bash
pkg update && pkg upgrade -y
pkg install -y python termux-api git
termux-setup-storage          # accept the file permission
```

Test the scan **before anything else**:

```bash
termux-wifi-scaninfo | head -c 300
```

- Returned JSON with networks → good, continue.
- Empty/error → the **location permission** is missing:
  Settings → Apps → Termux → Permissions → **Location: Allow**.
  Restart Termux and test again.

> The Wi-Fi scan API has been gated behind the location permission since
> Android 6. Without it, the scan returns empty.

---

## 3. Alpine (proot)

```bash
pkg install -y proot-distro
proot-distro install alpine
```

Enter Alpine with `termux-api` reachable over bind mounts:

```bash
proot-distro login alpine \
  --bind /data/data/com.termux/files/usr/bin:/opt/tbin \
  --bind /data/data/com.termux/files/usr/lib:/opt/tlib
```

Inside Alpine:

```bash
apk add --no-cache python3 iw wireless-tools aircrack-ng git
git clone https://github.com/SugarUnded/my-wificracker.git /root/my-wificracker
export PATH=/opt/tbin:$PATH
```

---

## 4. Run it

### Plan A — live scan (termux-api through the bind mounts)

Inside Alpine:

```bash
cd /root/my-wificracker
python3 autowifi.py            # detect + recommend (never touches the network)
python3 autowifi.py --run      # execute the best plan
```

### Plan B — the guaranteed one (scan in Termux, analyse in Alpine)

`termux-api` inside proot is flaky by nature. If plan A finds no networks, use
this:

```bash
# 1) in NATIVE TERMUX, save the scan:
termux-wifi-scaninfo > ~/scan.json

# 2) in ALPINE, analyse the saved scan (bind the Termux home):
proot-distro login alpine --bind "$HOME:/twhome"
python3 /root/my-wificracker/autowifi.py --scan-json /twhome/scan.json
```

---

## 5. The `atw` wrapper (optional)

Makes the command short. In **native Termux**:

```bash
curl -L -o setup-termux-alpine.sh https://raw.githubusercontent.com/SugarUnded/my-wificracker/main/setup-termux-alpine.sh
bash setup-termux-alpine.sh
```

Then, from anywhere in Termux:

```bash
atw                            # runs inside Alpine with the bind mounts ready
atw --scan-json ~/scan.json    # with a saved scan
```

---

## 6. Offline cracking inside Alpine

Capture the handshake/PMKID on another machine (a PC with a monitor-capable
adapter) and crack it on the phone:

```bash
python3 /root/my-wificracker/wpa_crack.py capture.cap -w rockyou.txt -t 4
# or export for hashcat (if installed / with a GPU):
python3 /root/my-wificracker/wpa_crack.py capture.cap --export-22000 out.22000
hashcat -m 22000 out.22000 rockyou.txt
```

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `termux-wifi-scaninfo: not found` | missing `pkg install termux-api` or the Termux:API app | install both the package **and** the app |
| scan returns `[]` | location disabled for Termux | Settings → Apps → Termux → Location: Allow |
| `apk add` fails / no network in Alpine | no DNS in proot | `echo 'nameserver 1.1.1.1' > /etc/resolv.conf` |
| `proot-distro install alpine` complains about architecture | 32-bit device (armv7) | use an aarch64 device/ROM, or build everything (painful) |
| `python3: not found` in Alpine | not installed inside Alpine (Termux's is separate) | `apk add python3` **inside** Alpine |
| `git clone` asks for username/password | wrong URL or nonexistent repo | use exactly `https://github.com/SugarUnded/my-wificracker.git` |

---

## 8. Limits (what the phone will NOT do)

- **The Android internal Wi-Fi chip cannot do monitor mode.** No command changes
  that — it is driver + kernel.
- **Live attacks** (reaver/PMKID/handshake) require a **monitor-capable USB
  adapter + root**: AR9271 / RTL8812AU / MT7612U over OTG, and `tsu` for root.
- **WPA3 / SAE** is not in this pipeline.
- **Scanning works without root** via termux-api; it is the attack that needs
  the hardware/root.

### Realistic path on the phone

`scan (Termux) → analyse (Alpine) → offline crack (Alpine)`. Live capture stays
on a PC with an adapter. This combo **never** drops your connection.
