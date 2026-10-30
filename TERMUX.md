# Rodar o autowifi no Termux (Android)

Guia de instalação e uso do autowifi no celular. Duas camadas:

- **Termux nativo** — fala com o rádio/scan (`termux-api`). É onde o `termux-wifi-scaninfo` funciona.
- **Alpine (proot)** — roda a análise, o crack e o resto.

O elo entre as duas é o **`--scan-json`**: escaneia no Termux, analisa no Alpine.

---

## 1. Instalar os apps

1. **Termux** — baixe do **F-Droid** ou dos releases do GitHub. **NÃO** use o da Play Store (desatualizado, quebra).
   - https://f-droid.org/packages/com.termux/
2. **Termux:API** — mesma fonte, versão compatível com o Termux.
   - https://f-droid.org/packages/com.termux.api/

---

## 2. Termux base

```bash
pkg update && pkg upgrade -y
pkg install -y python termux-api git
termux-setup-storage          # aceite a permissão de arquivos
```

Teste o scan **antes de qualquer coisa**:

```bash
termux-wifi-scaninfo | head -c 300
```

- Voltou JSON com redes → ok, siga.
- Vazio/erro → falta **permissão de localização**:
  Ajustes → Apps → Termux → Permissões → **Localização: Permitir**.
  Reinicie o Termux e teste de novo.

> A API de scan de wifi é bloqueada por permissão de localização desde o Android 6. Sem ela, o scan volta vazio.

---

## 3. Alpine (proot)

```bash
pkg install -y proot-distro
proot-distro install alpine
```

Entre no Alpine com o `termux-api` acessível via bind:

```bash
proot-distro login alpine \
  --bind /data/data/com.termux/files/usr/bin:/opt/tbin \
  --bind /data/data/com.termux/files/usr/lib:/opt/tlib
```

Já dentro do Alpine:

```bash
apk add --no-cache python3 iw wireless-tools aircrack-ng git
git clone https://github.com/SugarUnded/my-wificracker.git /root/my-wificracker
export PATH=/opt/tbin:$PATH
```

---

## 4. Rodar

### Plano A — scan ao vivo (termux-api pelo bind)

Dentro do Alpine:

```bash
cd /root/my-wificracker
python3 autowifi.py            # detecta + recomenda (não toca em rede)
python3 autowifi.py --run      # executa o melhor plano
```

### Plano B — o garantido (scan no Termux, análise no Alpine)

O `termux-api` dentro do proot é instável por natureza. Se o plano A não achar as redes, use este:

```bash
# 1) no TERMUX NATIVO, salva o scan:
termux-wifi-scaninfo > ~/scan.json

# 2) no ALPINE, analisa o scan salvo (binde o home do Termux):
proot-distro login alpine --bind "$HOME:/twhome"
python3 /root/my-wificracker/autowifi.py --scan-json /twhome/scan.json
```

---

## 5. Wrapper `atw` (opcional)

Deixa o comando curto. No **Termux nativo**:

```bash
curl -L -o setup-termux-alpine.sh https://raw.githubusercontent.com/SugarUnded/my-wificracker/main/setup-termux-alpine.sh
bash setup-termux-alpine.sh
```

Depois:

```bash
atw                            # roda no Alpine com os binds prontos
atw --scan-json ~/scan.json    # com scan salvo
```

---

## 6. Crack offline no Alpine

Captura o handshake/PMKID em outro máquina (PC com adaptador monitor-capable) e quebra no celular:

```bash
python3 /root/my-wificracker/wpa_crack.py captura.cap -w rockyou.txt -t 4
# ou exporta pro hashcat (se tiver GPU/instalado):
python3 /root/my-wificracker/wpa_crack.py captura.cap --export-22000 out.22000
hashcat -m 22000 out.22000 rockyou.txt
```

---

## 7. Troubleshooting

| Sintoma | Causa | Fix |
|---|---|---|
| `termux-wifi-scaninfo: not found` | faltou `pkg install termux-api` ou o app Termux:API | instale o pacote **e** o app |
| scan volta `[]` | localização desligada pro Termux | Ajustes → Apps → Termux → Localização: Permitir |
| `apk add` falha / sem rede no Alpine | DNS ausente no proot | `echo 'nameserver 1.1.1.1' > /etc/resolv.conf` |
| `proot-distro install alpine` reclama de arquitetura | device 32-bit (armv7) | use um device/ROM aarch64, ou compile tudo (chato) |
| `python3: not found` no Alpine | faltou instalar no Alpine (não é o do Termux) | `apk add python3` **dentro** do Alpine |
| `git clone` pede usuário/senha | URL errada ou repo inexistente | use exatamente `https://github.com/SugarUnded/my-wificracker.git` |

---

## 8. Limites (o que o celular NÃO faz)

- **Chip wifi interno do Android não faz monitor mode.** Nenhum comando muda isso — é driver + kernel.
- **Ataque ao vivo** (reaver/PMKID/handshake) exige **adaptador USB monitor-capable + root**:
  AR9271 / RTL8812AU / MT7612U via OTG, e `tsu` pra root.
- **WPA3/SAE** não cai neste pipeline.
- **Escaneia sem root** via termux-api; o ataque é que precisa do hardware/root.

### Caminho realista no celular
`scan (Termux) → análise (Alpine) → crack offline (Alpine)`. Captura ao vivo fica no PC com adaptador. Esse combo **nunca** derruba tua conexão.

---

