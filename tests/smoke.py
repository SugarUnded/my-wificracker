#!/usr/bin/env python3
# language: Python 3.8+, file: tests/smoke.py
# Dependency-free smoke test for autowifi + wpa_crack. Run from the repo root:
#   python3 tests/smoke.py
# Exits non-zero on the first failed assertion.

import hashlib
import hmac
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import autowifi            # noqa: E402
import wpa_crack           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        raise SystemExit(1)


# ---------------------------------------------------------------- env helpers

def fake_env(reaver=True, hcxdumptool=True):
    tools = {t: None for t in autowifi.TOOLS}
    if reaver:
        tools["reaver"] = "/usr/bin/reaver"
        tools["wash"] = "/usr/bin/wash"
    if hcxdumptool:
        tools["hcxdumptool"] = "/usr/bin/hcxdumptool"
    return {"tools": tools, "monitor_if": "wlan0mon", "ifaces": ["wlan0"], "is_root": True}


# ---------------------------------------------------------------- scan / plan

def test_scan_pipeline():
    print("[scan + classify + plan]")
    aps = autowifi.load_scan_json(os.path.join(HERE, "sample_scan.json"))
    check("load_scan_json reads 5 APs", len(aps) == 5)

    ranked = autowifi.rank(aps, fake_env())
    order = [a["ssid"] for a in ranked]
    check("WPS/WPA2 target ranked first", order[0] == "Home_2G")
    check("open network ranked after crackable ones", order.index("CafeOpen") > order.index("Home_2G"))
    check("WPA3 ranked last (out of scope)", order[-1] == "Home_5G")

    secs = {a["ssid"]: a["sec"] for a in ranked}
    check("WPA2 classified", secs["Home_2G"] == "wpa2" and secs["PlainWPA2"] == "wpa2")
    check("WPA3 classified", secs["Home_5G"] == "wpa3")
    check("WEP classified", secs["LegacyWEP"] == "wep")
    check("open classified", secs["CafeOpen"] == "open")
    check("WPS flag detected", ranked[0]["wps"] is True)

    wpa2 = next(a for a in ranked if a["ssid"] == "PlainWPA2")
    check("PMKID chosen when hcxdumptool present", wpa2["plan"]["method"].startswith("PMKID"))

    bare = autowifi.rank(autowifi.load_scan_json(os.path.join(HERE, "sample_scan.json")),
                         fake_env(reaver=False, hcxdumptool=False))
    wpa2b = next(a for a in bare if a["ssid"] == "PlainWPA2")
    check("falls back to handshake+aircrack without hcxdumptool",
          wpa2b["plan"]["method"] == "handshake + aircrack")


# ---------------------------------------------------------------- pcap building

def _beacon(ap, ssid):
    f = bytearray()
    f += struct.pack("<H", 0x0080)          # fc: mgmt, subtype 8 (beacon)
    f += b"\x00\x00"                        # duration
    f += b"\xff" * 6                        # addr1 broadcast
    f += ap                                 # addr2
    f += ap                                 # addr3 (bssid)
    f += b"\x00\x00"                        # seq
    f += b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0431)  # fixed params
    f += bytes([0, len(ssid)]) + ssid       # SSID tag
    return bytes(f)


def _data(src, dst, bssid, eapol):
    f = bytearray()
    f += struct.pack("<H", 0x0008)          # fc: data, subtype 0
    f += b"\x00\x00"                        # duration
    f += dst                                # addr1
    f += src                                # addr2
    f += bssid                              # addr3
    f += b"\x00\x00"                        # seq
    f += b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    f += eapol
    return bytes(f)


def _eapol(ki, nonce, kd=b"", mic=b"\x00" * 16):
    e = bytearray(99 + len(kd))
    e[0] = 2                                # EAPOL version
    e[1] = 3                                # EAPOL-Key
    e[4] = 2                                # RSN descriptor
    e[5:7] = struct.pack(">H", ki)
    e[17:49] = nonce
    e[81:97] = mic
    e[97:99] = struct.pack(">H", len(kd))
    e[99:99 + len(kd)] = kd
    return e


def _write_pcap(path, frames):
    out = bytearray()
    out += b"\xd4\xc3\xb2\xa1"              # pcap magic (LE)
    out += struct.pack("<HH", 2, 4)         # version 2.4
    out += struct.pack("<i", 0)             # thiszone
    out += struct.pack("<I", 0)             # sigfigs
    out += struct.pack("<I", 65535)         # snaplen
    out += struct.pack("<I", 105)           # linktype: bare 802.11
    for fr in frames:
        out += struct.pack("<IIII", 0, 0, len(fr), len(fr))
        out += fr
    with open(path, "wb") as fh:
        fh.write(out)


def test_crack_end_to_end():
    print("[wpa_crack: synthetic handshake -> recovery]")
    ssid = b"TestNet"
    password = "hunter2"
    ap = bytes.fromhex("aabbcc112233")
    sta = bytes.fromhex("112233445566")
    anonce = b"\x01" * 32
    snonce = b"\x02" * 32

    # Build a handshake with a password the cracker does not know, using the
    # public 802.11 crypto. (Self-consistency test: same primitives, not an
    # independent test vector.)
    k = wpa_crack.pmk(password, ssid)
    kck = wpa_crack.prf512(k, ap, sta, anonce, snonce)[:16]

    eapol2 = _eapol(ki=0x0102, nonce=snonce)          # msg2: MIC set, ver 2
    mic = hmac.new(kck, bytes(eapol2), hashlib.sha1).digest()[:16]
    eapol2[81:97] = mic

    eapol1 = _eapol(ki=0x0082, nonce=anonce)          # msg1: ACK set

    cap = os.path.join("/tmp", "aw_smoke.cap")
    _write_pcap(cap, [_beacon(ap, ssid),
                      _data(ap, sta, ap, bytes(eapol1)),   # msg1: AP -> STA
                      _data(sta, ap, ap, bytes(eapol2))])  # msg2: STA -> AP

    targets = wpa_crack.build_targets(cap, None)
    check("one target recovered from capture", len(targets) == 1)
    check("handshake parsed", len(targets[0]["handshakes"]) == 1)

    wrong = wpa_crack.mic_ok(wpa_crack.pmk("nope", ssid), ap, sta, anonce, snonce,
                             bytes(eapol2), mic, 2)
    check("wrong password rejected", wrong is False)
    right = wpa_crack.mic_ok(k, ap, sta, anonce, snonce, bytes(eapol2), mic, 2)
    check("correct password accepted", right is True)

    wl = os.path.join("/tmp", "aw_smoke.wl")
    with open(wl, "w") as fh:
        fh.write("letmein\npassword\nhunter2\n")
    res = wpa_crack.crack(targets, wl, 2)
    check("cracker recovers the password", res is not None and res[0] == password)

    hc = os.path.join("/tmp", "aw_smoke.22000")
    wpa_crack.export_22000(targets, hc)
    check("hc22000 export written", os.path.getsize(hc) > 0)


if __name__ == "__main__":
    test_scan_pipeline()
    test_crack_end_to_end()
    print("\nall smoke tests passed")
