# Changelog

## 0.3.0

- Full English rewrite of code, comments, and printed output.
- Added `--version`.
- Added `tests/smoke.py`: a dependency-free suite that runs the real pipeline,
  including recovering a synthetic 4-way handshake, plus a fixture scan.
- Added `docs/ARCHITECTURE.md` and `docs/METHODS.md`.
- Added CI (byte-compile, smoke suite, CLI sanity, shell syntax).
- Added the project logo.

## 0.2.0

- Added `--scan-json` to bridge native Termux scanning and Alpine analysis.
- `find_termux_bin` now resolves Termux:API binaries across proot bind mounts
  (`$TERMUX_BIN`, `/opt/tbin`).
- Added `setup-termux-alpine.sh` (proot bootstrap + `atw` wrapper).
- Ranking fix: open networks no longer outrank crackable targets.
- Added `TERMUX.md`.

## 0.1.0

- Initial release: environment detection, scanning (`termux-api` / `nmcli` /
  `iw`), AP classification, attack planning, ranking, and live execution.
- `wpa_crack.py`: stdlib-only offline WPA/WPA2-PSK cracker
  (pcap/pcapng, handshake + PMKID, hc22000 export).
- `install.sh`.
