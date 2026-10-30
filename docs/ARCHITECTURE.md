# Architecture

How `autowifi` is put together, module by module. Two programs, one shared idea:
turn a messy radio environment into a ranked, actionable plan.

```
autowifi.py                         wpa_crack.py
────────────                        ─────────────
env  → scan → classify → plan       pcap → 802.11 → EAPOL → PMK/PTK/KCK → MIC
      → rank → execute                       ↑
                                     (runs offline, on a saved capture)
```

## `autowifi.py`

### 1. Environment detection

`detect_env()` builds a single dict that everything downstream reads:

| Key | Meaning |
|-----|---------|
| `is_root` | `os.geteuid() == 0` |
| `termux` | native Termux (`/data/data/com.termux` exists or `PREFIX` mentions `com.termux`) |
| `alpine` | `/etc/alpine-release` exists |
| `pkg` | `"apk"`, `"pkg"`, or `None` — which package manager to drive |
| `tools` | map of tool name → resolved path or `None` |
| `ifaces` | wireless interfaces discovered under `/sys/class/net` |
| `monitor_if` | first interface whose phy advertises monitor mode |
| `moncap` | per-interface monitor capability |

`find_termux_bin()` is the piece that makes the proot case work: it looks in
`$TERMUX_BIN`, then `/opt/tbin` (the bind mount created by
`setup-termux-alpine.sh`), then `PATH`, then the two hard-coded Termux
locations. Without it, an Alpine container could never reach the host's
`termux-wifi-scaninfo`.

`monitor_capable()` prefers the per-phy query (`iw phy <name> info`) and falls
back to the global `iw list`.

### 2. Scanning

`scan()` tries backends in order and returns the first non-empty result:

1. `scan_termux()` — `termux-wifi-scaninfo`, JSON out, no root needed.
2. `scan_nmcli()` — `nmcli -t -f … dev wifi`, with a custom splitter
   (`split_nmcli`) that respects backslash-escaped colons in SSIDs.
3. `scan_iw()` — `iw dev <iface> scan`, root required, parses the human-readable
   dump including RSN/WPA/WEP capability lines.

`load_scan_json()` is the offline path: it accepts either `termux-wifi-scaninfo`
output or `autowifi --json` output (it peels off the `aps` key), so a scan taken
on the phone can be analysed anywhere.

`freq_to_ch()` converts MHz to channel numbers for 2.4 / 5 / 6 GHz.

### 3. Classification

`classify(ap)` reduces a scan record to a single security class plus a WPS flag:

```
SAE | WPA3            → wpa3
WPA2 | RSN            → wpa2
WPA                   → wpa
WEP | PRIVACY         → wep
(none of the above)   → open
```

The check order matters: `SAE` must be tested before `WPA2`, and `WPA2` before
`WPA`, or the substring match would misclassify.

### 4. Planning

`plan_for(ap, env)` returns `{score, method, needs_monitor, mon}`. It only
proposes a method whose tools are installed, so a bare Alpine box silently
downgrades PMKID → handshake instead of failing at execution time.

| Condition | score | method |
|-----------|------:|--------|
| WPS **and** `reaver` present | 1 | `WPS pixie-dust (reaver)` |
| `wpa2`/`wpa` **and** `hcxdumptool` present | 2 | `PMKID + hashcat` |
| `wpa2`/`wpa` otherwise | 2 | `handshake + aircrack` |
| `wep` | 4 | `WEP arpreplay (aircrack)` |
| `open` | 5 | `open network — connect directly` |
| `wpa3` | 99 | `WPA3/SAE — out of scope` |

### 5. Ranking

```python
sorted(aps, key=lambda a: (a["plan"]["score"], -a["signal"]))
```

Attack priority dominates; stronger signal breaks ties. Open networks sort near
the bottom on purpose — there is nothing to recover from them.

### 6. Execution

`execute(ap, env)` dispatches on the method string:

- `enable_monitor()` puts the interface into monitor mode, preferring
  `airmon-ng` and falling back to the raw `ip` + `iw` sequence.
- **WPS** → `reaver … -K 1` (pixie-dust).
- **PMKID** → `hcxdumptool` capture → `hcxpcapngtool` conversion → `hashcat -m 22000`.
- **handshake** → `airodump-ng` capture while `aireplay-ng --deauth` forces a
  reconnect → `aircrack-ng -w`.
- **WEP** → `airodump-ng` + `aireplay-ng --arpreplay` → `aircrack-ng`.

If the plan needs monitor mode and none is available, execution stops with an
explicit explanation instead of silently doing nothing.

## `wpa_crack.py`

A deliberately dependency-free cracker. Every layer is small and testable.

| Layer | Function(s) | Responsibility |
|-------|-------------|----------------|
| Container | `parse_pcap`, `parse_pcapng` | read pcap (both endiannesses) and pcapng |
| Link | `get_80211` | strip radiotap (127) or pass bare 802.11 (105) |
| Frame | `parse_ssid` | pull `(bssid, ssid)` from beacons/probe responses |
| EAPOL | `extract_eapol`, `parse_eapol_key` | locate the EAPOL-Key frame, split nonce/MIC/key-data, read the key-info flags |
| PMKID | `parse_pmkid_kde` | walk the RSN KDE for the `00:0f:ac:04` PMKID |
| Crypto | `pmk`, `prf512`, `mic_ok`, `pmkid_ok` | PBKDF2 → PTK → KCK → MIC, and the PMKID check |
| Collect | `build_targets` | assemble per-BSSID handshake/PMKID sets |
| Crack | `crack`, `_try` | multiprocessing pool streaming the wordlist, early exit on a hit |
| Export | `export_22000` | write hashcat's hc22000 format |

The MIC check is the heart of it: for each candidate passphrase, derive the PMK,
derive the PTK, take the KCK, zero the MIC field, recompute the HMAC, and compare
in constant time (`hmac.compare_digest`).

## Two-stage workflow (phone)

```
NATIVE TERMUX                     ALPINE (proot)
─────────────                     ──────────────
termux-wifi-scaninfo  ──scan.json──▶  autowifi --scan-json scan.json
   (radio access)                       (classify, plan, rank)
                                        wpa_crack.py  (offline cracking)
```

The radio work stays where the radio actually is; everything else runs in a
normal Linux userland.

## Testing

`tests/smoke.py` exercises the real code paths with zero third-party deps:

- loads the fixture scan and asserts classification + ranking order;
- asserts plan selection with and without optional tools;
- builds a synthetic pcap containing a beacon and a valid 4-way handshake,
  then asserts the cracker recovers the password and the hc22000 export is
  non-empty.

It runs in CI on every push.
