import socket
import threading
import datetime

SERVER_IP = "0.0.0.0"
SERVER_PORT = 5555

clients = []
addresses = []
info = {}

def log(msg):
    now = datetime.datetime.now().strftime("[%H:%M:%S]")
    print(f"{now} {msg}")

def handle_client(sock, idx):
    """Manipula cliente conectado"""
    ip = addresses[idx]
    log(f"Iniciando handler para cliente {ip} (idx: {idx})")
    
    try:
        # Recebe token de sessão primeiro
        token_data = sock.recv(1024)
        if token_data:
            token = token_data.decode('utf-8', errors='ignore').strip()
            log(f"Token recebido de {ip}: {token}")
        
        # Loop principal de recepção
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                    
                log(f"Dados recebidos de {ip}: {len(data)} bytes")
                
            except socket.timeout:
                continue
            except Exception as e:
                log(f"Erro na comunicação com {ip}: {e}")
                break
                
    except Exception as e:
        log(f"Erro no handler do cliente {ip}: {e}")
    finally:
        log(f"Cliente {ip} desconectado")
        sock.close()

def accept_clients():
    """Aceita conexões de clientes"""
    servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servsock.bind((SERVER_IP, SERVER_PORT))
    servsock.listen(25)
    
    log(f"SERVIDOR TESTE INICIADO: Escutando em {SERVER_IP}:{SERVER_PORT}")
    log(f"Aguardando conexões de clientes...")
    
    while True:
        try:
            log(f"Aguardando nova conexão...")
            sock, addr = servsock.accept()
            log(f"NOVA CONEXÃO RECEBIDA de {addr[0]}:{addr[1]}")
            
            sock.settimeout(5.0)
            clients.append(sock)
            addresses.append(addr[0])
            idx = len(clients) - 1
            info[idx] = {"status": "ONLINE", "last": datetime.datetime.now().strftime("%d/%m %H:%M")}
            
            log(f"Cliente {addr[0]} conectado com índice {idx}")
            threading.Thread(target=handle_client, args=(sock, idx), daemon=True).start()
            
        except Exception as e:
            log(f"ERRO ao aceitar conexão: {e}")

if __name__ == "__main__":
    try:
        accept_clients()
    except KeyboardInterrupt:
        log("Servidor interrompido pelo usuário")
    except Exception as e:
        log(f"Erro crítico no servidor: {e}")