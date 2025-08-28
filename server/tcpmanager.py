import socket
import threading
import time
import queue
import json
import os

CLIENTS = {}         # id: client sock
DATAS   = {}         # id: meta/status
MSGQ    = queue.Queue()

SERVER_IP = "0.0.0.0"
SERVER_PORT = 5555

class ClientHandler(threading.Thread):
    def __init__(self, client_id, sock, addr):
        threading.Thread.__init__(self,daemon=True)
        self.client_id = client_id
        self.sock = sock
        self.addr = addr
        self.active = True
        self.last_beat = time.time()
        DATAS[self.client_id] = {"ip":self.addr[0],"status":"ONLINE","last":"--","log":[], "queue":queue.Queue()}
        CLIENTS[self.client_id] = self.sock
    def run(self):
        try:
            while self.active:
                data = self.recv_chunk()
                if not data:
                    self.disconnect("Connection lost")
                    break
                DATAS[self.client_id]["last"] = time.strftime("%d/%m %H:%M")
                MSGQ.put({"id":self.client_id,"type":"img","data":data})
        except Exception as e:
            self.disconnect(f"Exception: {e}")
    def recv_chunk(self):
        img_bytes = b""
        while True:
            try:
                chunk = self.sock.recv(49152)
            except:
                self.active = False
                break
            if not chunk: self.active = False; break
            img_bytes += chunk
            if b"ENDIMG" in chunk: break
        return img_bytes.split(b"ENDIMG")[0] if img_bytes else None
    def send_data(self,data):
        try:
            self.sock.sendall(data)
        except: self.disconnect("Send error")
    def disconnect(self,reason=""):
        self.active = False
        try:
            self.sock.close()
        except: pass
        DATAS[self.client_id]["status"] = "OFFLINE"
        DATAS[self.client_id]["log"].append(f"DISCONNECT: {reason}")

def server_loop():
    servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    servsock.bind((SERVER_IP, SERVER_PORT)); servsock.listen(50)
    print(f"[TCPMGR] Listening {SERVER_IP}:{SERVER_PORT}")
    cid = 0
    while True:
        sock, addr = servsock.accept()
        print(f"[TCPMGR] Client {cid} connected: {addr}")
        handler = ClientHandler(cid,sock,addr)
        handler.start()
        cid+=1

def broadcast(data):
    # Envia comando para todos conectados
    for cid,client in CLIENTS.items():
        try: client.sendall(data)
        except: pass

def send_to(cid,data):
    # Envia comando para cliente específico
    if cid in CLIENTS:
        try: CLIENTS[cid].sendall(data)
        except: pass

def shutdown():
    # Fecha todos clientes
    for cid,client in CLIENTS.items():
        try: client.close()
        except: pass
    CLIENTS.clear(); DATAS.clear(); print("[TCPMGR] All connections closed.")

def get_log(cid):
    return DATAS.get(cid,{}).get("log",[])

def poll_img():
    while True:
        if not MSGQ.empty():
            msg = MSGQ.get()
            process_img(msg)
        time.sleep(0.1)

def process_img(msg):
    # Exemplo de como processar o IMG stream. Integre com painel.
    cid = msg["id"]; img_data = msg["data"]
    # Salvar img_data para cid, atualizar painel, etc.

if __name__ == "__main__":
    threading.Thread(target=server_loop,daemon=True).start()
    threading.Thread(target=poll_img,daemon=True).start()
    while True:
        try: time.sleep(2)
        except KeyboardInterrupt: shutdown(); os._exit(0)