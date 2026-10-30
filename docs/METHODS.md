# Attack methods reference

What each method in the picker actually does, what it needs, and how you know it
worked. Priority (the score in the picker) is about *speed on a vulnerable
target*, not about reliability — every one of these assumes the target is
cooperative.

---

## 1. WPS pixie-dust — `reaver` (score 1)

**Idea.** WPS enabled the easy setup flow most people never turn off. The
pixie-dust flaw lives in weak nonce generation during the WPS handshake: instead
of brute-forcing the 8-digit PIN (which is rate-limited), it recovers the PIN
from a single failed exchange by recovering the AP's keys.

**Needs.** Monitor mode, `reaver`, WPS enabled on the AP.

**Command run.**

```bash
reaver -i <mon> -b <bssid> -c <channel> -K 1 -vv
```

`-K 1` selects the pixie-dust attack.

**Speed.** Seconds to a couple of minutes on a vulnerable AP.

**How you know it worked.** `reaver` prints the WPA PSK. If it reports
`WPS PIN not found` or loops through PINs, the AP is patched — fall back to
handshake/PMKID.

**Notes.** WPS lockout can trigger after a handful of failed attempts. Some
vendors only rate-limit the *PIN* attack, not pixie-dust. WPS being advertised
in the beacon is a hint, not a guarantee.

---

## 2. PMKID — `hcxdumptool` + `hashcat` (score 2)

**Idea.** The first EAPOL message of the 4-way handshake can carry a PMKID
computed from `PMK + "PMK Name" + AP-MAC + STA-MAC`. If an AP hands one out
without a client being present, you can capture it and crack it offline without
ever touching a real client.

**Needs.** Monitor mode, `hcxdumptool`, `hcxpcapngtool`, `hashcat` (or any
hc22000-capable tool).

**Commands run.**

```bash
hcxdumptool -i <mon> -o out.pcapng --enable_status=1 --filterlist_ap=<bssid>
hcxpcapngtool -o out.hc22000 out.pcapng
hashcat -m 22000 out.hc22000 <wordlist>
```

**Speed.** Capture in seconds; the crack is bound by your wordlist and hardware.

**How you know it worked.** `hcxpcapngtool` reports at least one PMKID line, and
`hashcat` proves a candidate as recovered.

**Notes.** Not every AP emits a PMKID where you can see it. Roaming-capable and
PMF-enabled APs are the friendlier ones. If the capture stays empty, switch to
the handshake method.

---

## 3. Handshake capture + `aircrack-ng` (score 2)

**Idea.** Capture the 4-way handshake in the air (a client must connect while
you watch) and crack the MIC offline. A `--deauth` burst forces a client to
reconnect, which produces the handshake on demand.

**Needs.** Monitor mode, `airodump-ng`, `aireplay-ng`, `aircrack-ng`, and a
client in range to deauthenticate.

**Commands run.**

```bash
airodump-ng -c <channel> --bssid <bssid> -w ~/cap <mon>      # capture
aireplay-ng --deauth 5 -a <bssid> <mon>                      # force a reconnect
aircrack-ng -w <wordlist> -b <bssid> ~/cap-01.cap            # crack
```

**Speed.** Capture in minutes; crack is wordlist-bound.

**How you know it worked.** `airodump-ng` shows `WPA handshake: <bssid>`, and
`aircrack-ng` prints `KEY FOUND! [ … ]`.

**Notes.** Deauth is loud — if the target is a busy network, the burst is
usually enough. If you cannot capture in the field, this is the case where you
capture on a PC and crack on the phone with `wpa_crack.py`.

---

## 4. WEP arpreplay — `aircrack-ng` (score 4)

**Idea.** WEP's IV space is small and RC4 is broken. Generate traffic to
accelerate IV collection, then recover the key statistically.

**Needs.** Monitor mode, `airodump-ng`, `aireplay-ng`, `aircrack-ng`, and a
client (or ARP traffic) on the network.

**Commands run.**

```bash
airodump-ng -c <channel> --bssid <bssid> -w ~/wep <mon>       # capture
aireplay-ng --arpreplay -b <bssid> <mon>                      # inject ARP
aircrack-ng ~/wep-01.cap                                      # crack
```

**Speed.** 1–5 minutes once ARP replay takes off.

**How you know it worked.** `aircrack-ng` reports `KEY FOUND!` with a high
number of IVs.

**Notes.** WEP is effectively extinct, but it still shows up on old gear — fast
and cheap when it does. ARP replay needs at least one client exchanging traffic.

---

## 5. Open network — nothing to crack (score 5)

No key derivation exists. `plan_for` returns this class so it is never confused
with a crackable target, and `execute()` just says "connect directly" and stops.
Ranking it near the bottom keeps it out of the way of real work.

---

## 6. WPA3 / SAE — out of scope (score 99)

Simultaneous Authentication of Equals replaces the PSK handshake with a
Dragonfly exchange that is resistant to offline dictionary attacks, and PMF is
mandatory. Nothing in this pipeline attempts it. It is detected and reported so
you know why an AP was skipped.

---

## Choosing by hand

When the automatic picker is not what you want, drive the tools directly. The
order to try, given a monitor-capable adapter:

1. WPS advertised? → pixie-dust.
2. Otherwise, try to see a PMKID → capture.
3. Otherwise → handshake, with a deauth to encourage a reconnect.
4. WEP? → arpreplay.
5. WPA3? → nothing here for you.

For anything beyond a single radio, capture on a machine with a dedicated
adapter and do the cracking wherever the CPU is — `wpa_crack.py` will run
anywhere Python runs.
