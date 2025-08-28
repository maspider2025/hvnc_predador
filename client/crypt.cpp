#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

std::string GenRandomKey(int bytes) {
    std::string key; key.resize(bytes);
    HCRYPTPROV prov; CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(prov, bytes, (BYTE*)key.data());
    CryptReleaseContext(prov, 0);
    return key;
}
std::string Base64Encode(const BYTE* buf, size_t size) {
    DWORD outLen = 0;
    CryptBinaryToStringA(buf, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outLen);
    std::string base64; base64.resize(outLen);
    CryptBinaryToStringA(buf, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64[0], &outLen);
    return base64;
}
std::vector<BYTE> Base64Decode(const std::string& s) {
    DWORD outLen = 0;
    CryptStringToBinaryA(s.c_str(), s.length(), CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL);
    std::vector<BYTE> out(outLen);
    CryptStringToBinaryA(s.c_str(), s.length(), CRYPT_STRING_BASE64, out.data(), &outLen, NULL, NULL);
    return out;
}

// AES256 CBC com polimorfismo saltado + fallback DPAPI
std::vector<BYTE> EncryptAES(const BYTE* data, size_t sz) {
    std::vector<BYTE> out;
    // OpenSSL AES-256 CBC
    const int KEYLEN = 32, IVLEN = 16;
    std::string key = GenRandomKey(KEYLEN);
    std::string iv = GenRandomKey(IVLEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    out.resize(sz + AES_BLOCK_SIZE);

    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), (unsigned char*)iv.data());
    EVP_EncryptUpdate(ctx, out.data(), &outl, data, sz);
    int totlen = outl;
    EVP_EncryptFinal_ex(ctx, out.data() + outl, &outl);
    totlen += outl;
    out.resize(totlen);

    // Sobrescreve: polimorfismo, buffer salt shuffle
    std::mt19937 rng(GetTickCount());
    for (size_t i = 0; i < out.size(); ++i) out[i] ^= (BYTE)key[i % KEYLEN] ^ iv[i % IVLEN] ^ rng();
    EVP_CIPHER_CTX_free(ctx);

    // Header key/iv
    std::string bkey = Base64Encode((BYTE*)key.data(), key.size());
    std::string biv = Base64Encode((BYTE*)iv.data(), iv.size());
    DWORD blen = (DWORD)out.size();
    std::vector<BYTE> final(bkey.length()+biv.length()+sizeof(blen)+out.size()+8);
    memcpy(final.data(), bkey.c_str(), bkey.length());
    memcpy(final.data() + bkey.length(), biv.c_str(), biv.length());
    memcpy(final.data() + bkey.length() + biv.length(), &blen, sizeof(blen));
    memcpy(final.data() + bkey.length() + biv.length() + sizeof(blen), out.data(), out.size());
    // Termina
    return final;
}
std::vector<BYTE> DecryptAES(const BYTE* buf, size_t sz) {
    // Extrai key/iv
    // Aqui depende do header (lengths do base64 etc), ajuste conforme builder
    // Simplificado para builder default
    std::string key = "UseMesmaGeracaoDoBuilderAqui123456789012345"; // 32 bytes key fix ex.
    std::string iv  = "FixedIVStringXYZ"; // 16 bytes fixed, match stub/builder logic
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<BYTE> out(sz + AES_BLOCK_SIZE);
    int outl = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), (unsigned char*)iv.data());
    EVP_DecryptUpdate(ctx, out.data(), &outl, buf, sz);
    int totlen = outl;
    EVP_DecryptFinal_ex(ctx, out.data() + outl, &outl);
    totlen += outl;
    out.resize(totlen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// Fallback para DPAPI quando disco é cifrado ou crypto não tá jogando
std::vector<BYTE> DpapiProtect(const std::vector<BYTE>& buf) {
    DATA_BLOB DataIn, DataOut;
    DataIn.pbData = (BYTE*)buf.data(); DataIn.cbData = buf.size();
    std::vector<BYTE> out;
    if (CryptProtectData(&DataIn, L"DPAPI", NULL, NULL, NULL, 0, &DataOut)) {
        out.resize(DataOut.cbData);
        memcpy(out.data(), DataOut.pbData, DataOut.cbData);
        LocalFree(DataOut.pbData);
    }
    return out;
}
std::vector<BYTE> DpapiUnprotect(const std::vector<BYTE>& buf) {
    DATA_BLOB DataIn, DataOut;
    DataIn.pbData = (BYTE*)buf.data(); DataIn.cbData = buf.size();
    std::vector<BYTE> out;
    if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
        out.resize(DataOut.cbData);
        memcpy(out.data(), DataOut.pbData, DataOut.cbData);
        LocalFree(DataOut.pbData);
    }
    return out;
}