# autowifi

Recon de wifi + seletor automático de ataque. Alpine (proot/Termux) e Linux.

Detecta o ambiente, escaneia, classifica cada AP (open/wep/wpa/wpa2/wpa3 + WPS)
e escolhe o caminho de ataque mais rápido por alvo. Inclui um cracker offline
WPA/WPA2-PSK from-scratch (só stdlib) para handshake e PMKID.

## Instalar
    git clone https://github.com/SugarUnded/my-wificracker.git
    cd autowifi && bash install.sh

## Usar
    python autowifi.py            # detecta + recomenda (não toca em rede)
    python autowifi.py --run      # executa o melhor plano
    python autowifi.py --target <bssid|ssid>
    python autowifi.py --json
    python autowifi.py --scan-json scan.json   # usa um scan salvo (Termux/Alpine)

## Termux + Alpine (proot)
**Guia completo passo a passo: [TERMUX.md](TERMUX.md)**

    # no Termux nativo:
    bash setup-termux-alpine.sh
    # depois: atw   (ou atw --scan-json ~/scan.json)
    #
    # plano B se o termux-api não responder dentro do proot:
    termux-wifi-scaninfo > ~/scan.json      # Termux nativo
    atw --scan-json ~/scan.json             # Alpine

## Crack offline
    python wpa_crack.py captura.cap -w rockyou.txt -t 8
    python wpa_crack.py captura.cap --export-22000 out.22000   # hashcat -m 22000

## Limites
- Chip wifi interno do Android/Termux não faz monitor mode.
- Ataque ao vivo precisa de adaptador USB monitor-capable + root.
- Escaneia sem root via termux-api (requer permissão de localização).
- WPA3/SAE não cai neste pipeline.

Uso em rede própria / ambiente autorizado.
