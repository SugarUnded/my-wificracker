<p align="center">
  <img src="assets/logo.png" alt="autowifi" width="200">
</p>

<h1 align="center">autowifi</h1>

<p align="center">
  <b>Wi-Fi recon + automatic attack picker + from-scratch WPA/WPA2 cracker.</b><br>
  Runs on native Termux, inside Alpine (proot), or on any Linux box.
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="platform" src="https://img.shields.io/badge/platform-Termux%20%7C%20Alpine%20%7C%20Linux-informational">
  <img alt="cracker deps" src="https://img.shields.io/badge/cracker-stdlib--only-success">
  <img alt="status" src="https://img.shields.io/badge/tests-smoke%20suite-brightgreen">
</p>

---

`autowifi` scans the airwaves, fingerprints every access point, and picks the
fastest realistic path to its key — automatically. It ships with a
dependency-free WPA/WPA2-PSK cracker written from scratch, because doing the
crypto yourself is the only way to know exactly what you are running.

```console
$ python3 autowifi.py

[*] environment: alpine root=no ifaces=['wlan0'] monitor=NO

[*] 5 networks (scan via json). plan per target:

  SIG   CH  SEC   WPS TARGET                 METHOD
-----------------------------------------------------
  -40    1  wpa2  -   PlainWPA2              handshake + aircrack
  -45    6  wpa2  yes Home_2G                WPS pixie-dust (reaver)
  -80    1  wep   -   LegacyWEP              WEP arpreplay (aircrack)
  -60   11  open  -   CafeOpen               open network — connect directly
  -70   36  wpa3  -   Home_5G                WPA3/SAE — out of scope

[*] best option: Home_2G  →  WPS pixie-dust (reaver)
[*] (dry-run) run with --run to execute. --target <bssid> forces another target.
```

## Table of contents

- [What it does](#what-it-does)
- [How it decides](#how-it-decides)
- [Install](#install)
- [Usage](#usage)
- [Termux + Alpine](#termux--alpine)
- [Offline cracker](#offline-cracker)
- [Attack methods](#attack-methods)
- [Project layout](#project-layout)
- [Tests](#tests)
- [Hard limits](#hard-limits)

## What it does

| Stage | What happens |
|-------|--------------|
| **Detect** | Identifies the OS (Alpine / Termux / generic Linux), whether you are root, the wireless interfaces, and whether any of them supports monitor mode. |
| **Scan** | Tries every scanner it can find, in order: `termux-wifi-scaninfo`, `nmcli`, then `iw` (root). No single point of failure. |
| **Classify** | Reads each AP's capabilities string into a security class: `open`, `wep`, `wpa`, `wpa2`, `wpa3` — and detects WPS. |
| **Plan** | Maps each class to a concrete attack method, only using tools that are actually installed. |
| **Rank** | Sorts by (attack priority, signal strength). The easiest crackable target rises to the top. |
| **Execute** | `--run` drives the chosen toolchain: `reaver`, `hcxdumptool` + `hashcat`, or `airodump-ng` + `aireplay-ng` + `aircrack-ng`. |

Everything is stdlib Python — no pip, no build step. The only external programs
are the classic wireless tools, and each one is optional.

## How it decides

```
                 ┌──────────────┐
                 │  detect_env  │  OS · root · ifaces · monitor-capable
                 └──────┬───────┘
                        │
              ┌─────────▼─────────┐
              │       scan        │  termux-api → nmcli → iw   (first non-empty wins)
              └─────────┬─────────┘
                        │            or --scan-json FILE
              ┌─────────▼─────────┐
              │     classify      │  caps string → open | wep | wpa | wpa2 | wpa3 (+WPS)
              └─────────┬─────────┘
              ┌─────────▼─────────┐
              │     plan_for      │  class + installed tools → method + score
              └─────────┬─────────┘
              ┌─────────▼─────────┐
              │       rank        │  sort by (score, −signal)
              └─────────┬─────────┘
              ┌─────────▼─────────┐
              │     execute       │  --run drives the toolchain for the winner
              └───────────────────┘
```

Priority scores (lower runs first):

| Score | Method | Why this rank |
|------:|--------|---------------|
| 1 | WPS pixie-dust (`reaver`) | Usually seconds when the AP is vulnerable. |
| 2 | PMKID (`hcxdumptool` + `hashcat`) | No client needed; capture is quick. |
| 2 | Handshake + `aircrack-ng` | Needs a client to deauth; solid fallback. |
| 4 | WEP arpreplay | Trivial crypto, but slow traffic generation. |
| 5 | Open network | Nothing to crack — just connect. |
| 99 | WPA3 / SAE | Out of scope; not attempted. |

WPS and `hcxdumptool` are used only when those binaries are present, so the plan
degrades gracefully on a bare Alpine install.

## Install

```bash
git clone https://github.com/SugarUnded/my-wificracker.git
cd my-wificracker
bash install.sh
```

`install.sh` detects the environment and installs the right packages
(`apk` on Alpine, `pkg` on Termux). To let the script do it for you instead:

```bash
python3 autowifi.py --install
```

Minimal manual installs:

```bash
# Alpine
apk add --no-cache python3 iw wireless-tools aircrack-ng

# Termux
pkg install -y python termux-api
```

## Usage

```
python3 autowifi.py                     # detect + recommend (never touches the network)
python3 autowifi.py --run               # execute the best plan
python3 autowifi.py --target <bssid|ssid>
python3 autowifi.py --json              # machine-readable ranked result
python3 autowifi.py --scan-json FILE    # use a saved scan instead of scanning live
python3 autowifi.py --install           # install dependencies for the detected OS
python3 autowifi.py --version
```

`--json` is a superset of the Termux scan format, so its own output can be fed
back in through `--scan-json`. That is what makes the two-stage
scan-here / analyse-there workflow possible.

## Termux + Alpine

Two layers, one bridge:

- **Native Termux** talks to the radio (`termux-api`).
- **Alpine (proot)** does the analysis, the cracking, and everything else.
- The bridge is **`--scan-json`**: scan in Termux, analyse in Alpine.

```bash
# native Termux
bash setup-termux-alpine.sh      # creates the `atw` wrapper
atw                              # or: atw --scan-json ~/scan.json
```

Full step-by-step, including the guaranteed plan B and a troubleshooting
table, lives in **[TERMUX.md](TERMUX.md)**.

## Offline cracker

`wpa_crack.py` recovers WPA/WPA2-PSK from a 4-way handshake or a PMKID. No
aircrack, no hashcat, no dependencies — just `hashlib` and `hmac`.

```bash
python3 wpa_crack.py capture.cap -w rockyou.txt -t 8
python3 wpa_crack.py capture.cap -u MySSID -w words.txt      # filter by ESSID
python3 wpa_crack.py capture.cap --export-22000 out.22000    # for hashcat -m 22000
```

It parses `pcap` and `pcapng` (radiotap or bare 802.11), pulls EAPOL-Key
frames, and validates each candidate by recomputing the MIC with the derived
KCK — the exact math a real client would use:

```
passphrase ──PBKDF2-SHA1(ssid, 4096)──▶ PMK ──PRF-512──▶ PTK ──first 16B──▶ KCK ──HMAC──▶ MIC
```

## Attack methods

Short version below; the full reference — requirements, commands used, success
criteria — is in **[docs/METHODS.md](docs/METHODS.md)**.

| Method | Needs | Speed (vulnerable target) |
|--------|-------|---------------------------|
| WPS pixie-dust | monitor mode, `reaver` | seconds to minutes |
| PMKID | monitor mode, `hcxdumptool`, `hashcat` | capture in seconds, crack is wordlist-bound |
| Handshake + aircrack | monitor mode, a client to deauth | capture in minutes, crack is wordlist-bound |
| WEP arpreplay | monitor mode, traffic | 1–5 minutes |
| WPA3 / SAE | — | not supported |

## Project layout

```
autowifi.py            recon, classification, planning, ranking, execution
wpa_crack.py           offline WPA/WPA2-PSK cracker (stdlib only)
install.sh             dependency installer (Alpine / Termux)
setup-termux-alpine.sh proot-distro bootstrap + `atw` wrapper
TERMUX.md              Termux + Alpine walkthrough
docs/ARCHITECTURE.md   module map and data flow
docs/METHODS.md        attack-method reference
tests/smoke.py         dependency-free smoke suite (runs in CI)
tests/sample_scan.json fixture scan used by the tests
assets/logo.png        project art
```

## Tests

The suite is dependency-free and runs the real pipeline end to end — including
a synthetic 4-way handshake that the cracker has to actually recover:

```bash
python3 tests/smoke.py
```

It covers scan loading, classification for every security class, plan
selection with and without optional tools, ranking order, pcap parsing, the
PMK → PTK → MIC path, password recovery, and hc22000 export. CI runs it on
every push.

## Hard limits

- **The internal Wi-Fi chip in an Android/Termux device cannot do monitor
  mode.** No command changes that — it is a driver/kernel matter.
- **Live attacks need a monitor-capable USB adapter + root** (AR9271 /
  RTL8812AU / MT7612U over OTG, and `tsu` for root).
- **Scanning works without root** via `termux-api`, but it needs the location
  permission (Android blocks Wi-Fi scan results otherwise).
- **WPA3 / SAE is not in the pipeline.**
- With a **single** radio, going into monitor mode drops your own connection —
  `airmon-ng check kill` stops NetworkManager/`wpa_supplicant`. Restore with
  `sudo airmon-ng stop wlan0mon && sudo systemctl restart NetworkManager`.

The realistic mobile path is **scan (Termux) → analyse (Alpine) → offline crack
(Alpine)**. It never drops your connection. Live capture belongs on a PC with a
dedicated adapter.
