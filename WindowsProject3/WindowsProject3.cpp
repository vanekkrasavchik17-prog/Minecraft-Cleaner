#include <windows.h>
#include <winternl.h>
#include <wrl.h>
#include <wil/com.h>
#include <WebView2.h>
#include <sstream>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <cwctype>
#include <ctime>
#include <shlobj.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>
#include <intrin.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <shellapi.h>
#include <shlobj_core.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#include <thread>
#include <functional>
#include <chrono>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <comdef.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include "resource.h"

typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
    PVOID ProcessHeap;
} MY_PEB, *PMY_PEB;

namespace ObfStr {
    constexpr unsigned char KEY1 = 0x5A;
    constexpr unsigned char KEY2 = 0x3F;
    constexpr unsigned char KEY3 = 0x7C;

    template<size_t N>
    struct Encrypted {
        char data[N];

        constexpr Encrypted(const char(&str)[N]) : data{} {
            for (size_t i = 0; i < N; ++i) {
                char c = str[i];
                c ^= KEY1;
                c ^= (KEY2 + (i % 13));
                c ^= (KEY3 ^ ((i * 7) % 256));
                data[i] = c;
            }
        }
    };

    template<size_t N>
    std::wstring Decrypt(const char(&enc)[N]) {
        std::string result;
        result.reserve(N);
        for (size_t i = 0; i < N - 1; ++i) {
            char c = enc[i];
            c ^= (KEY3 ^ ((i * 7) % 256));
            c ^= (KEY2 + (i % 13));
            c ^= KEY1;
            result += c;
        }
        return std::wstring(result.begin(), result.end());
    }
}

#define OBFSTR(s) ([]() -> std::wstring { \
    constexpr auto enc = ObfStr::Encrypted(s); \
    return ObfStr::Decrypt(enc.data); \
}())

namespace AntiDebug {
    __forceinline bool IsDebuggerPresentPEB() {
        PMY_PEB peb = (PMY_PEB)__readgsqword(0x60);
        if (peb->BeingDebugged) return true;
        ULONG ntg = *(ULONG*)((BYTE*)peb + 0x68);
        if ((ntg & 0x70) != 0) return true;
        return false;
    }

    __forceinline bool CheckRemoteDebugger() {
        BOOL present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present))
            return present != FALSE;
        return false;
    }

    __forceinline bool CheckDebuggerTools() {
        const wchar_t* tools[] = {
            L"windbg.exe", L"cdb.exe", L"x64dbg.exe", L"x32dbg.exe",
            L"ollydbg.exe", L"ida.exe", L"ida64.exe", L"procmon.exe",
            L"procmon64.exe", L"processhacker.exe", L"procexp.exe", L"gdb.exe"
        };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        bool found = false;
        if (Process32FirstW(snapshot, &pe)) {
            do {
                std::wstring pname = pe.szExeFile;
                for (auto& c : pname) c = towlower(c);
                for (auto* tool : tools) {
                    if (pname == tool) { found = true; break; }
                }
            } while (!found && Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
        return found;
    }

    __forceinline bool CheckDebuggerWindow() {
        const wchar_t* classes[] = {
            L"WinDbgFrameClass", L"OLLYDBG", L"OLLYDDG", L"SWCLIENT",
            L"OllyDbg", L"IDAMain", L"Ida", L"TIDWindow", L"Qt5QWindowIcon"
        };
        for (auto* cls : classes) {
            if (FindWindowW(cls, nullptr)) return true;
        }
        return false;
    }

    __forceinline bool CheckHardwareBreakpoints() {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &context)) return false;
        return context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3;
    }

    __forceinline bool CheckProcessDebugPort() {
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (!NtQIP) return false;
        DWORD debugPort = 0;
        if (NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr) >= 0)
            return debugPort != 0;
        return false;
    }

    __forceinline bool CheckDebugObject() {
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (!NtQIP) return false;
        PVOID debugObject = nullptr;
        if (NtQIP(GetCurrentProcess(), 0x1E, &debugObject, sizeof(debugObject), nullptr) >= 0)
            return debugObject != nullptr;
        return false;
    }

    __forceinline bool CheckLoadedModules() {
        const wchar_t* names[] = {
            L"inject", L"hook", L"ollydbg", L"x64dbg", L"x32dbg", L"phook.dll"
        };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W me = { sizeof(MODULEENTRY32W) };
        bool found = false;
        if (Module32FirstW(snapshot, &me)) {
            do {
                std::wstring mname = me.szModule;
                for (auto& c : mname) c = towlower(c);
                for (auto* name : names) {
                    if (mname == name) { found = true; break; }
                }
            } while (!found && Module32NextW(snapshot, &me));
        }
        CloseHandle(snapshot);
        return found;
    }

    __forceinline bool CheckCloseHandle() {
        SetLastError(ERROR_SUCCESS);
        CloseHandle((HANDLE)0x1234);
        return GetLastError() != ERROR_INVALID_HANDLE;
    }

    __forceinline bool CheckNtClose() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        BYTE* NtCloseFn = (BYTE*)GetProcAddress(ntdll, "NtClose");
        if (!NtCloseFn) return false;
        return (NtCloseFn[0] == 0xE9 || NtCloseFn[0] == 0xEB);
    }

    __forceinline bool CheckSandbox() {
        wchar_t userName[MAX_PATH];
        DWORD size = MAX_PATH;
        if (GetUserNameW(userName, &size)) {
            std::wstring u = userName;
            for (auto& c : u) c = towlower(c);
            const wchar_t* names[] = { L"sandbox", L"virus", L"malware", L"sample", L"test" };
            for (auto* name : names) {
                if (u.find(name) != std::wstring::npos) return true;
            }
        }
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &key) == ERROR_SUCCESS) {
            wchar_t manufacturer[256] = {};
            DWORD mSize = sizeof(manufacturer);
            if (RegQueryValueExW(key, L"SystemManufacturer", nullptr, nullptr, (LPBYTE)manufacturer, &mSize) == ERROR_SUCCESS) {
                std::wstring m = manufacturer;
                for (auto& c : m) c = towlower(c);
                if (m.find(L"vmware") != std::wstring::npos ||
                    m.find(L"virtualbox") != std::wstring::npos ||
                    m.find(L"qemu") != std::wstring::npos ||
                    m.find(L"innotek") != std::wstring::npos) {
                    RegCloseKey(key);
                    return true;
                }
            }
            RegCloseKey(key);
        }
        return false;
    }

    __forceinline bool CheckSuspiciousFiles() {
        const wchar_t* paths[] = {
            L"C:\\Windows\\System32\\sbiedll.dll",
            L"C:\\Windows\\System32\\snxhk.dll",
            L"C:\\Program Files\\Sandboxie",
            L"C:\\Program Files (x86)\\Sandboxie",
            L"C:\\sandbox",
            L"C:\\Windows\\System32\\drivers\\sandboxd.sys"
        };
        for (auto* p : paths) {
            if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) return true;
        }
        return false;
    }

    __forceinline bool CheckRegistryKeys() {
        const wchar_t* keys[] = {
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\windbg.exe",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x64dbg.exe",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ollydbg.exe"
        };
        for (auto* k : keys) {
            HKEY key;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &key) == ERROR_SUCCESS) {
                RegCloseKey(key);
                return true;
            }
        }
        return false;
    }
    
    __forceinline bool CheckWriteWatch() {
        PVOID mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
        if (!mem) return false;
        *(BYTE*)mem = 0;
        PVOID pages[1];
        ULONG_PTR count = 1;
        DWORD granularity;
        GetWriteWatch(0, mem, 0x1000, pages, &count, &granularity);
        VirtualFree(mem, 0, MEM_RELEASE);
        return count == 0;
    }
    
    __forceinline bool CheckPageGuard() {
        PVOID mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) return false;
        DWORD oldProtect;
        VirtualProtect(mem, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
        __try {
            *(BYTE*)mem = 0;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            VirtualFree(mem, 0, MEM_RELEASE);
            return false;
        }
        VirtualFree(mem, 0, MEM_RELEASE);
        return true;
    }
    
    __forceinline bool CheckDebugString() {
        wchar_t buf[MAX_PATH];
        if (GetEnvironmentVariableW(L"_NO_DEBUG_HEAP", buf, MAX_PATH) > 0) return true;
        if (GetEnvironmentVariableW(L"COMPLUS_ENABLE_64BIT", buf, MAX_PATH) > 0) return true;
        return false;
    }
    
    __forceinline bool CheckSEH() {
        return false;
    }
    
    __forceinline bool CheckVEH() {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!kernel32) return false;
        FARPROC AddVEH = GetProcAddress(kernel32, "AddVectoredExceptionHandler");
        if (!AddVEH) return false;
        BYTE* funcBytes = (BYTE*)AddVEH;
        return (funcBytes[0] == 0xE9 || funcBytes[0] == 0xEB);
    }
    
    __forceinline bool CheckThreadStartAddress() {
        typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        pNtQueryInformationThread NtQIT = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
        if (!NtQIT) return false;
        PVOID startAddr = nullptr;
        if (NtQIT(GetCurrentThread(), 9, &startAddr, sizeof(startAddr), nullptr) >= 0) {
            HMODULE hMod;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)startAddr, &hMod)) {
                wchar_t modPath[MAX_PATH];
                GetModuleFileNameW(hMod, modPath, MAX_PATH);
                std::wstring path = modPath;
                for (auto& c : path) c = towlower(c);
                if (path.find(L"ntdll") != std::wstring::npos) return true;
            }
        }
        return false;
    }
    
    __forceinline bool CheckMemoryBreakpoints() {
        BYTE testBuf[4] = {0xCC, 0xCC, 0xCC, 0xCC};
        DWORD oldProtect;
        VirtualProtect(testBuf, sizeof(testBuf), PAGE_EXECUTE_READWRITE, &oldProtect);
        bool found = false;
        for (int i = 0; i < 4; i++) {
            if (testBuf[i] == 0xCC) found = true;
        }
        VirtualProtect(testBuf, sizeof(testBuf), oldProtect, &oldProtect);
        return false;
    }
    
    __forceinline bool CheckCRC() {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sec[i].Name, ".text") == 0) {
                BYTE* start = (BYTE*)hMod + sec[i].VirtualAddress;
                for (DWORD j = 0; j < sec[i].Misc.VirtualSize; j++) {
                    if (start[j] == 0xCC) return true;
                }
                break;
            }
        }
        return false;
    }
    
    __forceinline void HideThread() {
        typedef NTSTATUS(WINAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            pNtSetInformationThread NtSIT = (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
            if (NtSIT) NtSIT(GetCurrentThread(), 0x11, nullptr, 0);
        }
    }
    
    __forceinline void ErasePEHeader() {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
        DWORD oldProtect;
        DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
        VirtualProtect(hMod, headerSize, PAGE_READWRITE, &oldProtect);
        SecureZeroMemory(hMod, headerSize);
        VirtualProtect(hMod, headerSize, oldProtect, &oldProtect);
    }
    
    __forceinline void Check() {
        HideThread();
        if (IsDebuggerPresentPEB() || CheckRemoteDebugger() || 
            CheckDebuggerTools() || CheckDebuggerWindow() ||
            CheckHardwareBreakpoints() || CheckProcessDebugPort() ||
            CheckDebugObject() || CheckLoadedModules() ||
            CheckCloseHandle() || CheckNtClose()) {
            ExitProcess(0);
        }
    }
    
    __forceinline void SoftCheck() {
    }
    
    __forceinline void Init() {
        HideThread();
    }
}

using namespace Microsoft::WRL;
using namespace Gdiplus;

wil::com_ptr<ICoreWebView2Controller> g_controller;
wil::com_ptr<ICoreWebView2> g_webView;
HWND g_hWnd;
ULONG_PTR gdiplusToken;
POINT g_dragOffset = { 0, 0 };
bool g_isDragging = false;

std::wstring g_clientFolder = L"C:\\yougamecorm";
std::wstring g_downloadUrl = L"https://yougamecorm.ru/launcher/client.zip";
std::wstring g_zipPath = L"C:\\yougamecorm\\client.zip";
std::wstring g_token = L"";
std::map<std::wstring, std::wstring> g_userData;
bool g_isUpdating = false;

DWORD GetFileSize(const std::wstring& filePath);
bool CheckFilesExtracted();
bool ExtractArchive();
std::wstring ClientInfo(const std::string& key);
std::wstring user(const std::wstring& key);
std::wstring GetHWID();
bool CheckToken();
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateWebView(HWND);
void ResizeWebView();
std::wstring HttpPost(const std::wstring& url, const std::wstring& data, bool includeAdminKey = true, bool includeAuth = true);
void SaveToken(const std::wstring& token);
std::wstring LoadToken();
void ClearToken();
void SaveCredentials(const std::wstring& login, const std::wstring& password);
std::pair<std::wstring, std::wstring> LoadCredentials();
void SendToWebView(const std::wstring& message);
std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim);
bool BindHWID(const std::wstring& currentHWID, const std::wstring& userId);
void LaunchGameAndClose();
bool LaunchGame();

std::wstring ExecuteWMICommand(const std::wstring& command) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hStdoutRd, hStdoutWr;
    CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0);

    SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi;
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWr;
    si.hStdError = hStdoutWr;

    std::wstring fullCommand = L"cmd.exe /c " + command;
    wchar_t* cmd = _wcsdup(fullCommand.c_str());

    std::wstring result;
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hStdoutWr);

        DWORD dwRead;
        CHAR buffer[4096];
        std::string output;

        while (ReadFile(hStdoutRd, buffer, sizeof(buffer) - 1, &dwRead, nullptr) && dwRead) {
            buffer[dwRead] = '\0';
            output += buffer;
        }

        int wlen = MultiByteToWideChar(CP_ACP, 0, output.c_str(), -1, nullptr, 0);
        if (wlen > 0) {
            std::vector<wchar_t> woutput(wlen);
            MultiByteToWideChar(CP_ACP, 0, output.c_str(), -1, woutput.data(), wlen);
            result = woutput.data();
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    free(cmd);
    CloseHandle(hStdoutRd);
    return result;
}

std::wstring GetCPUInfoWMI() {
    std::wstring output = ExecuteWMICommand(L"wmic cpu get ProcessorId,Name");
    std::wstringstream cleaned;
    std::wstringstream ss(output);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (!line.empty() &&
            line.find(L"ProcessorId") == std::wstring::npos &&
            line.find(L"Name") == std::wstring::npos) {
            size_t start = line.find_first_not_of(L" \t\r\n");
            size_t end = line.find_last_not_of(L" \t\r\n");
            if (start != std::wstring::npos && end != std::wstring::npos) {
                cleaned << line.substr(start, end - start + 1);
            }
        }
    }
    return cleaned.str();
}

std::wstring GetRAMInfoWMI() {
    std::wstring output = ExecuteWMICommand(L"wmic memorychip get Capacity,SerialNumber");
    std::wstringstream cleaned;
    std::wstringstream ss(output);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (!line.empty() &&
            line.find(L"Capacity") == std::wstring::npos &&
            line.find(L"SerialNumber") == std::wstring::npos) {
            size_t start = line.find_first_not_of(L" \t\r\n");
            size_t end = line.find_last_not_of(L" \t\r\n");
            if (start != std::wstring::npos && end != std::wstring::npos) {
                cleaned << line.substr(start, end - start + 1);
            }
        }
    }
    return cleaned.str();
}

std::wstring GetGPUInfoWMI() {
    std::wstring output = ExecuteWMICommand(L"wmic path win32_videocontroller get Name,PNPDeviceID");
    std::wstringstream cleaned;
    std::wstringstream ss(output);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (!line.empty() &&
            line.find(L"Name") == std::wstring::npos &&
            line.find(L"PNPDeviceID") == std::wstring::npos) {
            size_t start = line.find_first_not_of(L" \t\r\n");
            size_t end = line.find_last_not_of(L" \t\r\n");
            if (start != std::wstring::npos && end != std::wstring::npos) {
                cleaned << line.substr(start, end - start + 1);
            }
        }
    }
    return cleaned.str();
}

std::wstring GetSystemUUIDWMI() {
    std::wstring output = ExecuteWMICommand(L"wmic csproduct get UUID");
    std::wstringstream cleaned;
    std::wstringstream ss(output);
    std::wstring line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.find(L"UUID") == std::wstring::npos) {
            size_t start = line.find_first_not_of(L" \t\r\n");
            size_t end = line.find_last_not_of(L" \t\r\n");
            if (start != std::wstring::npos && end != std::wstring::npos) {
                cleaned << line.substr(start, end - start + 1);
            }
        }
    }
    return cleaned.str();
}

std::wstring GetHWID() {
    std::wstring hwidData = L"";

    std::wstring cpu = GetCPUInfoWMI();
    if (!cpu.empty()) hwidData += cpu;

    std::wstring ram = GetRAMInfoWMI();
    if (!ram.empty()) hwidData += ram;

    std::wstring gpu = GetGPUInfoWMI();
    if (!gpu.empty()) hwidData += gpu;

    std::wstring uuid = GetSystemUUIDWMI();
    if (!uuid.empty()) hwidData += uuid;

    if (hwidData.empty()) {
        GUID guid;
        if (CoCreateGuid(&guid) == S_OK) {
            wchar_t guidStr[39];
            swprintf_s(guidStr, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
            return guidStr;
        }
        return L"UNKNOWN_HWID";
    }

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, hwidData.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> utf8Data(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, hwidData.c_str(), -1, utf8Data.data(), utf8Size, nullptr, nullptr);

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE hash[32];
    DWORD hashLen = 32;

    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash) &&
        CryptHashData(hHash, reinterpret_cast<const BYTE*>(utf8Data.data()), utf8Size - 1, 0) &&
        CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {

        std::wstringstream hexStream;
        hexStream << std::hex << std::setfill(L'0');
        for (DWORD i = 0; i < hashLen; i++) {
            hexStream << std::setw(2) << static_cast<int>(hash[i]);
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hexStream.str();
    }

    return L"ERROR_HWID";
}

std::wstring HttpPost(const std::wstring& url, const std::wstring& data, bool includeAdminKey, bool includeAuth) {
    HINTERNET hSession = WinHttpOpen(L"GuardLauncher/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return L"";

    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    urlComp.dwSchemeLength = -1;
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    urlComp.dwExtraInfoLength = -1;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return L"";
    }

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.lpszExtraInfo && urlComp.dwExtraInfoLength > 0) {
        path += std::wstring(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return L"";
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return L"";
    }

    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

    DWORD timeout = 30000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (includeAdminKey) {
        std::wstring key = ClientInfo("admin_key");
        headers += L"X-Admin-Key: " + key + L"\r\n";
    }
    if (includeAuth && !g_token.empty()) {
        headers += L"Authorization: Bearer " + g_token + L"\r\n";
    }

    int utf8_size = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> utf8_data(utf8_size);
    WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, utf8_data.data(), utf8_size, nullptr, nullptr);

    BOOL sent = WinHttpSendRequest(hRequest,
        headers.c_str(), headers.length(),
        utf8_data.data(), utf8_size - 1,
        utf8_size - 1, 0);

    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return L"";
    }

    std::wstring result;
    if (WinHttpReceiveResponse(hRequest, NULL)) {
        std::string response_utf8;
        DWORD dwSize = 0;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            std::vector<char> buffer(dwSize + 1);
            DWORD dwDownloaded = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response_utf8.append(buffer.data(), dwDownloaded);
            }
            else break;
        } while (dwSize > 0);

        if (!response_utf8.empty()) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, response_utf8.c_str(), -1, nullptr, 0);
            if (wlen > 0) {
                result.resize(wlen - 1);
                MultiByteToWideChar(CP_UTF8, 0, response_utf8.c_str(), -1, result.data(), wlen);
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

bool CheckAndCreateFolder() {
    DWORD attrib = GetFileAttributesW(g_clientFolder.c_str());
    if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY)) return true;
    return CreateDirectoryW(g_clientFolder.c_str(), NULL);
}

class DownloadCallback : public IBindStatusCallback {
private:
    ULONG m_totalSize = 0;
    ULONG m_downloaded = 0;
    bool m_sizeSet = false;
    
public:
    STDMETHOD(OnStartBinding)(DWORD dwReserved, IBinding __RPC_FAR* pib) { return S_OK; }
    STDMETHOD(GetPriority)(LONG __RPC_FAR* pnPriority) { return S_OK; }
    STDMETHOD(OnLowResource)(DWORD reserved) { return S_OK; }
    STDMETHOD(OnStopBinding)(HRESULT hresult, LPCWSTR szError) { return S_OK; }
    STDMETHOD(GetBindInfo)(DWORD __RPC_FAR* grfBINDF, BINDINFO __RPC_FAR* pbindinfo) { return S_OK; }
    STDMETHOD(OnDataAvailable)(DWORD grfBSCF, DWORD dwSize, FORMATETC __RPC_FAR* pformatetc, STGMEDIUM __RPC_FAR* pstgmed) { return S_OK; }
    STDMETHOD(OnObjectAvailable)(REFIID riid, IUnknown __RPC_FAR* punk) { return S_OK; }

    STDMETHOD(OnProgress)(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText) {
        if (ulProgressMax > 0 && !m_sizeSet) {
            m_totalSize = ulProgressMax;
            m_sizeSet = true;
        }
        
        if (ulProgress > 0) {
            m_downloaded = ulProgress;
        }
        
        if (m_totalSize > 0 && m_downloaded > 0) {
            int percent = (int)((double)m_downloaded / (double)m_totalSize * 100.0);
            if (percent > 100) percent = 100;
            
            std::wstring statusText = g_isUpdating ? L"Скачивание обновления: " : L"Скачивание: ";
            std::wstring script = L"updateDownloadStatus('" + statusText + std::to_wstring(percent) + L"% (" +
                std::to_wstring(m_downloaded / 1024 / 1024) + L" / " +
                std::to_wstring(m_totalSize / 1024 / 1024) + L" МБ)');";
            SendToWebView(script);
        }
        return S_OK;
    }

    STDMETHOD_(ULONG, AddRef)() { return 1; }
    STDMETHOD_(ULONG, Release)() { return 1; }
    STDMETHOD(QueryInterface)(REFIID riid, void** ppvObject) {
        if (riid == IID_IUnknown || riid == IID_IBindStatusCallback) {
            *ppvObject = this;
            return S_OK;
        }
        return E_NOINTERFACE;
    }
};

bool DownloadArchive() {
    DownloadCallback callback;
    HRESULT result = URLDownloadToFileW(NULL, g_downloadUrl.c_str(), g_zipPath.c_str(), 0, &callback);
    return result == S_OK;
}

std::wstring FindWinRAR() {
    const wchar_t* possiblePaths[] = {
        L"C:\\Program Files\\WinRAR\\WinRAR.exe",
        L"C:\\Program Files (x86)\\WinRAR\\WinRAR.exe",
        L"WinRAR.exe"
    };

    for (const wchar_t* path : possiblePaths) {
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return path;
    }
    return L"";
}

std::wstring Find7Zip() {
    const wchar_t* possiblePaths[] = {
        L"C:\\Program Files\\7-Zip\\7z.exe",
        L"C:\\Program Files (x86)\\7-Zip\\7z.exe",
        L"7z.exe"
    };

    for (const wchar_t* path : possiblePaths) {
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return path;
    }
    return L"";
}

bool ExtractWithWinRAR() {
    std::wstring winrarPath = FindWinRAR();
    if (winrarPath.empty()) return false;

    std::wstring command = L"\"" + winrarPath + L"\" x -y -ibck \"" + g_zipPath + L"\" \"" + g_clientFolder + L"\\\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t* cmd = _wcsdup(command.c_str());
    BOOL success = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);

    if (success) {
        WaitForSingleObject(pi.hProcess, 60000);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

bool ExtractWith7Zip() {
    std::wstring sevenZipPath = Find7Zip();
    if (sevenZipPath.empty()) return false;

    std::wstring command = L"\"" + sevenZipPath + L"\" x \"" + g_zipPath + L"\" -o\"" + g_clientFolder + L"\" -y";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t* cmd = _wcsdup(command.c_str());
    BOOL success = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);

    if (success) {
        WaitForSingleObject(pi.hProcess, 60000);
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }
    return false;
}

bool ExtractWithWindowsShell() {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) return false;

    IShellDispatch* pShellApp = NULL;
    hr = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void**)&pShellApp);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    VARIANT vZipFile;
    VariantInit(&vZipFile);
    vZipFile.vt = VT_BSTR;
    vZipFile.bstrVal = SysAllocString(g_zipPath.c_str());

    Folder* pZipFolder = NULL;
    hr = pShellApp->NameSpace(vZipFile, &pZipFolder);
    if (FAILED(hr) || !pZipFolder) {
        VariantClear(&vZipFile);
        pShellApp->Release();
        CoUninitialize();
        return false;
    }

    VARIANT vDestFolder;
    VariantInit(&vDestFolder);
    vDestFolder.vt = VT_BSTR;
    vDestFolder.bstrVal = SysAllocString(g_clientFolder.c_str());

    Folder* pDestFolder = NULL;
    hr = pShellApp->NameSpace(vDestFolder, &pDestFolder);
    if (FAILED(hr) || !pDestFolder) {
        VariantClear(&vZipFile);
        VariantClear(&vDestFolder);
        pZipFolder->Release();
        pShellApp->Release();
        CoUninitialize();
        return false;
    }

    FolderItems* pZipItems = NULL;
    hr = pZipFolder->Items(&pZipItems);
    if (FAILED(hr) || !pZipItems) {
        VariantClear(&vZipFile);
        VariantClear(&vDestFolder);
        pDestFolder->Release();
        pZipFolder->Release();
        pShellApp->Release();
        CoUninitialize();
        return false;
    }

    VARIANT vItems;
    VariantInit(&vItems);
    vItems.vt = VT_DISPATCH;
    vItems.pdispVal = pZipItems;

    VARIANT vOptions;
    VariantInit(&vOptions);
    vOptions.vt = VT_I4;
    vOptions.lVal = 0x14;

    hr = pDestFolder->CopyHere(vItems, vOptions);

    VariantClear(&vZipFile);
    VariantClear(&vDestFolder);
    VariantClear(&vItems);
    VariantClear(&vOptions);
    pZipItems->Release();
    pDestFolder->Release();
    pZipFolder->Release();
    pShellApp->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}

bool ExtractArchive() {
    CreateDirectoryW(g_clientFolder.c_str(), NULL);
    if (ExtractWithWinRAR()) return true;
    if (ExtractWith7Zip()) return true;
    if (ExtractWithWindowsShell()) return true;
    return false;
}

DWORD GetFileSize(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    return size;
}

bool CheckFilesExtracted() {
    std::vector<std::wstring> requiredFolders = {
        g_clientFolder + L"\\jar",
        g_clientFolder + L"\\java",
        g_clientFolder + L"\\game"
    };

    for (const auto& folder : requiredFolders) {
        DWORD attrib = GetFileAttributesW(folder.c_str());
        if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return false;
    }

    std::wstring jvmPath = g_clientFolder + L"\\java\\bin\\java.exe";
    DWORD jvmAttrib = GetFileAttributesW(jvmPath.c_str());
    if (jvmAttrib == INVALID_FILE_ATTRIBUTES) return false;

    std::wstring clientJar = g_clientFolder + L"\\jar\\client.jar";
    DWORD clientAttrib = GetFileAttributesW(clientJar.c_str());
    
    return (clientAttrib != INVALID_FILE_ATTRIBUTES);
}

void CleanupArchive() {
    DeleteFileW(g_zipPath.c_str());
}

bool IsClientInstalled() {
    std::vector<std::wstring> requiredFolders = {
        g_clientFolder + L"\\jar",
        g_clientFolder + L"\\java",
        g_clientFolder + L"\\game"
    };

    for (const auto& folder : requiredFolders) {
        DWORD attrib = GetFileAttributesW(folder.c_str());
        if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return false;
    }

    std::wstring jvmPath = g_clientFolder + L"\\java\\bin\\java.exe";
    DWORD jvmAttrib = GetFileAttributesW(jvmPath.c_str());
    if (jvmAttrib == INVALID_FILE_ATTRIBUTES) return false;

    std::wstring clientJar = g_clientFolder + L"\\jar\\client.jar";
    DWORD clientAttrib = GetFileAttributesW(clientJar.c_str());
    
    return (clientAttrib != INVALID_FILE_ATTRIBUTES);
}

bool VerifyInstallation() {
    SendToWebView(L"updateDownloadStatus('Проверка файлов...');");
    
    std::wstring jvmPath = g_clientFolder + L"\\java\\bin\\java.exe";
    DWORD jvmAttrib = GetFileAttributesW(jvmPath.c_str());
    if (jvmAttrib == INVALID_FILE_ATTRIBUTES) return false;

    std::vector<std::wstring> requiredFolders = {
        g_clientFolder + L"\\jar",
        g_clientFolder + L"\\java",
        g_clientFolder + L"\\game"
    };

    for (const auto& folder : requiredFolders) {
        DWORD attrib = GetFileAttributesW(folder.c_str());
        if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return false;
    }

    std::wstring clientJar = g_clientFolder + L"\\jar\\client.jar";
    DWORD clientAttrib = GetFileAttributesW(clientJar.c_str());
    
    return (clientAttrib != INVALID_FILE_ATTRIBUTES);
}

void DeleteClientFolder() {
    std::wstring command = L"cmd.exe /c rmdir /s /q \"" + g_clientFolder + L"\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t* cmd = _wcsdup(command.c_str());
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    free(cmd);
}

// Получить версию с сервера
std::wstring GetServerVersion() {
    std::wstring host = ClientInfo("host");
    std::wstring path = ClientInfo("version-path");
    
    HINTERNET hSession = WinHttpOpen(L"yougamecorm/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return L"";
    
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return L"";
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return L"";
    }
    
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
    
    std::wstring result;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL)) {
        std::string response;
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            std::vector<char> buffer(dwSize + 1);
            DWORD dwDownloaded = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                response.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);
        
        // Trim whitespace
        while (!response.empty() && (response.back() == '\n' || response.back() == '\r' || response.back() == ' ')) {
            response.pop_back();
        }
        
        int wlen = MultiByteToWideChar(CP_UTF8, 0, response.c_str(), -1, nullptr, 0);
        if (wlen > 0) {
            result.resize(wlen - 1);
            MultiByteToWideChar(CP_UTF8, 0, response.c_str(), -1, result.data(), wlen);
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// Получить путь к скрытому файлу версии в AppData
std::wstring GetVersionFilePath() {
    wchar_t path[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path);
    std::wstring dir = std::wstring(path) + L"\\yougamecorm";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\.version";
}

// Получить локальную версию
std::wstring GetLocalVersion() {
    std::wstring versionFile = GetVersionFilePath();
    std::wifstream f(versionFile);
    if (!f.is_open()) return L"";
    std::wstring version;
    std::getline(f, version);
    while (!version.empty() && (version.back() == L'\n' || version.back() == L'\r' || version.back() == L' ')) {
        version.pop_back();
    }
    return version;
}

// Сохранить локальную версию
void SaveLocalVersion(const std::wstring& version) {
    std::wstring versionFile = GetVersionFilePath();
    
    // Убираем атрибут hidden перед записью (если файл существует)
    SetFileAttributesW(versionFile.c_str(), FILE_ATTRIBUTE_NORMAL);
    
    std::wofstream f(versionFile, std::ios::out | std::ios::trunc);
    if (f.is_open()) {
        f << version;
        f.close();
        SetFileAttributesW(versionFile.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }
}

// Проверить нужно ли обновление
bool NeedsUpdate() {
    std::wstring serverVersion = GetServerVersion();
    if (serverVersion.empty()) return false;
    
    std::wstring localVersion = GetLocalVersion();
    if (localVersion.empty()) return false;
    
    return serverVersion != localVersion;
}

// Обновить клиент
void UpdateClient() {
    g_isUpdating = true;
    
    SendToWebView(L"updateDownloadStatus('Проверка обновлений...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    std::wstring serverVersion = GetServerVersion();
    if (serverVersion.empty()) {
        SendToWebView(L"showMessage('Не удалось проверить обновления', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        SendToWebView(L"hideDownloadOverlay();");
        g_isUpdating = false;
        return;
    }
    
    SendToWebView(L"updateDownloadStatus('Удаление старой версии...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    DeleteClientFolder();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    if (!CheckAndCreateFolder()) {
        SendToWebView(L"showMessage('Ошибка создания папки', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        SendToWebView(L"hideDownloadOverlay();");
        g_isUpdating = false;
        return;
    }
    
    SendToWebView(L"updateDownloadStatus('Скачивание обновления...');");
    if (!DownloadArchive()) {
        SendToWebView(L"showMessage('Ошибка скачивания обновления', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        g_isUpdating = false;
        return;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    SendToWebView(L"updateDownloadStatus('Распаковка обновления...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    
    if (!ExtractArchive()) {
        SendToWebView(L"showMessage('Ошибка распаковки', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        DeleteFileW(g_zipPath.c_str());
        g_isUpdating = false;
        return;
    }
    
    CleanupArchive();
    
    // Сохраняем новую версию
    SaveLocalVersion(serverVersion);
    
    SendToWebView(L"updateDownloadStatus('Проверка файлов...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    if (!VerifyInstallation()) {
        SendToWebView(L"showMessage('Ошибка проверки файлов', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        DeleteClientFolder();
        g_isUpdating = false;
        return;
    }
    
    SendToWebView(L"showMessage('Обновление установлено! Версия: " + serverVersion + L"', 'success');");
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    SendToWebView(L"hideDownloadOverlay();");
    g_isUpdating = false;
}

// Проверить и обновить при необходимости
void CheckAndUpdate() {
    if (!IsClientInstalled()) return;
    
    std::wstring serverVersion = GetServerVersion();
    if (serverVersion.empty()) return;
    
    std::wstring localVersion = GetLocalVersion();
    
    if (localVersion.empty() || serverVersion != localVersion) {
        std::thread updateThread(UpdateClient);
        updateThread.detach();
    }
}

void InstallClient() {
    g_isUpdating = false;
    if (!CheckAndCreateFolder()) {
        SendToWebView(L"showMessage('Ошибка создания папки', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        SendToWebView(L"hideDownloadOverlay();");
        return;
    }

    SendToWebView(L"updateDownloadStatus('Подключение к серверу...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    SendToWebView(L"updateDownloadStatus('Скачивание клиента...');");
    if (!DownloadArchive()) {
        SendToWebView(L"showMessage('Ошибка скачивания. Проверьте интернет.', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        return;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    SendToWebView(L"updateDownloadStatus('Распаковка архива...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    if (!ExtractArchive()) {
        SendToWebView(L"showMessage('Ошибка распаковки. Установите WinRAR или 7-Zip.', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        DeleteFileW(g_zipPath.c_str());
        return;
    }

    CleanupArchive();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    SendToWebView(L"updateDownloadStatus('Проверка файлов...');");
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    if (!VerifyInstallation()) {
        SendToWebView(L"showMessage('Ошибка проверки файлов. Архив поврежден.', 'error');");
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        SendToWebView(L"hideDownloadOverlay();");
        DeleteClientFolder();
        return;
    }

    // Сохраняем версию при первой установке
    std::wstring serverVersion = GetServerVersion();
    if (!serverVersion.empty()) {
        SaveLocalVersion(serverVersion);
    }

    SendToWebView(L"showInstallSuccess();");
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    SendToWebView(L"hideDownloadOverlay();");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    SendToWebView(L"showMessage('Клиент установлен! Нажмите Запустить игру.', 'success');");
}

bool BindHWID(const std::wstring& currentHWID, const std::wstring& userId) {
    std::wstring bindJson = L"{\"hwid\":\"" + currentHWID + L"\",\"userId\":" + userId + L"}";
    std::wstring bindResponse = HttpPost(L"https://yougamecorm.ru/api/admin/bind_hwid.php", bindJson, true, false);

    if (bindResponse.empty()) return false;

    if (bindResponse.find(L"\"success\":true") != std::wstring::npos) return true;
    else if (bindResponse.find(L"\"success\": false") != std::wstring::npos) return false;

    if (bindResponse.find(L"HWID успешно привязан") != std::wstring::npos) return true;
    else if (bindResponse.find(L"HWID уже привязан к этому устройству") != std::wstring::npos) return true;
    else if (bindResponse.find(L"HWID уже привязан") != std::wstring::npos) return false;
    else if (bindResponse.find(L"Пользователь не найден") != std::wstring::npos) return false;
    else if (bindResponse.find(L"Доступ запрещён") != std::wstring::npos) return false;
    else return false;
}

std::wstring user(const std::wstring& key) {
    if (key == L"login") return g_userData[L"login"];
    if (key == L"role")  return g_userData[L"role"];
    if (key == L"uid")   return g_userData[L"id"];
    return L"—";
}

bool CheckToken() {
    return !g_token.empty();
}

// Генерация токена для защиты от запуска без лоадера
std::wstring GenerateHydraToken() {
    // Получаем текущее время в миллисекундах
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    
    // Секретный ключ (должен совпадать с Java LoaderGuard)
    const long long VALIDATION_KEY = 0x48594452414C4F41LL; // "HYDRALOA"
    
    // Генерация хеша
    long long hash = timestamp ^ VALIDATION_KEY;
    hash = (hash * 31) + (timestamp % 1000);
    
    // Форматирование токена
    std::wstringstream ss;
    ss << L"HYDRA_" << timestamp << L"_" << std::uppercase << std::hex << hash;
    return ss.str();
}

bool LaunchGame() {
    std::wstring jvmPath = g_clientFolder + L"\\java\\bin\\java.exe";
    std::wstring clientJar = g_clientFolder + L"\\jar\\client.jar";
    
    if (GetFileAttributesW(jvmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        SendToWebView(L"showMessage('Java не найден', 'error');");
        return false;
    }
    
    if (GetFileAttributesW(clientJar.c_str()) == INVALID_FILE_ATTRIBUTES) {
        SendToWebView(L"showMessage('client.jar не найден', 'error');");
        return false;
    }
    
    // Генерируем токен для защиты
    std::wstring token = GenerateHydraToken();
    
    // Получаем данные пользователя
    std::wstring userName = g_userData[L"login"];
    std::wstring userHwid = GetHWID();
    std::wstring userId = g_userData[L"id"];
    std::wstring userRole = g_userData[L"role"];
    std::wstring userSub = g_userData[L"subscription"];
    
    // Формируем команду с параметрами JVM
    std::wstring command = L"\"" + jvmPath + L"\"";
    // Память: 4GB максимум, 2GB минимум
    command += L" -Xmx4G -Xms2G";
    command += L" -Dhydra.token=" + token;
    command += L" -Dhydra.user=" + userName;
    command += L" -Dhydra.hwid=" + userHwid;
    command += L" -Dhydra.uid=" + userId;
    command += L" -Dhydra.role=" + userRole;
    command += L" -Dhydra.sub=" + userSub;
    command += L" -jar \"" + clientJar + L"\"";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t* cmd = _wcsdup(command.c_str());
    BOOL success = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, g_clientFolder.c_str(), &si, &pi);
    free(cmd);

    if (success) {
        WaitForSingleObject(pi.hProcess, 1500);
        
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            SendToWebView(L"showMessage('Ошибка запуска игры', 'error');");
            return false;
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    
    SendToWebView(L"showMessage('Ошибка запуска', 'error');");
    return false;
}

void LaunchGameAndClose() {
    LaunchGame();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    GdiplusStartupInput gdiplusStartupInput{};
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    const wchar_t CLASS_NAME[] = L"WebViewApp";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON8));
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClass(&wc);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowWidth = 1250;
    int windowHeight = 650;
    int x = (screenWidth - windowWidth) / 2;
    int y = (screenHeight - windowHeight) / 2;

    g_hWnd = CreateWindowEx(
        WS_EX_LAYERED | WS_EX_NOREDIRECTIONBITMAP,
        CLASS_NAME,
        ClientInfo("name").c_str(),
        WS_POPUP,
        x, y, windowWidth, windowHeight,
        nullptr, nullptr, hInstance, nullptr
    );

    SetLayeredWindowAttributes(g_hWnd, 0, 255, LWA_ALPHA);
    HICON hBig = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON8));
    HICON hSmall = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON2));
    SendMessageW(g_hWnd, WM_SETICON, ICON_BIG, (LPARAM)hBig);
    SendMessageW(g_hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hSmall);
    ShowWindow(g_hWnd, nCmdShow);
    CreateWebView(g_hWnd);

    std::thread([]() {
        AntiDebug::Init();
        AntiDebug::Check();
        AntiDebug::SoftCheck();
        while (true) {
            Sleep(3000);
            AntiDebug::Check();
        }
    }).detach();
    
    std::thread([]() {
        while (true) {
            Sleep(15000);
            AntiDebug::SoftCheck();
        }
    }).detach();

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    GdiplusShutdown(gdiplusToken);
    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_USER + 1: {
        std::wstring* jsPtr = reinterpret_cast<std::wstring*>(lParam);
        if (jsPtr && g_webView) {
            g_webView->ExecuteScript(jsPtr->c_str(), nullptr);
            delete jsPtr;
        }
        return 0;
    }
    case WM_KEYDOWN:
        if (wParam == VK_F5) return 0;
        break;
    case WM_LBUTTONDOWN: {
        ReleaseCapture();
        SendMessage(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, lParam);
        return 0;
    }

    case WM_SIZE:
        if (wParam == SIZE_RESTORED) {
            SendToWebView(L"playOpenAnimation();");
        }
        ResizeWebView();
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
    return out;
}

void RunTraceCleaner() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring bat = std::wstring(tmp) + L"CachedPrograms.bat";

    const wchar_t* script = LR"TAG(@ECHO OFF
chcp 65001 >nul
COLOR 3
CLS

FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Отказано) GOTO errNoAdmin
IF (%adminTest%)==(Access) GOTO errNoAdmin

ECHO Desire.pro (FUCK#9803)
ECHO.
ECHO  -Очистка журнала шалуна
ECHO  -Полная очистка запущена...

FOR /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")

REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"

REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\UsbEStub" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\USBSTOR" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications"

FOR /F "tokens=2" %%i IN ('whoami /user /fo table /nh') DO set usersid=%%i

REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps" /f
REG ADD "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\%usersid%" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\UserSettings\%usersid%" /va /f
REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /va /f
REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /va /f

REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f
REG ADD "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

DEL /f /q %APPDATA%\Microsoft\Windows\Recent\*.*
DEL /f /q %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*
DEL /f /q %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
DEL /f /q %systemroot%\Panther\*.*
DEL /f /q %systemroot%\appcompat\Programs\*.txt
DEL /f /q %systemroot%\appcompat\Programs\*.xml
DEL /f /q %systemroot%\appcompat\Programs\Install\*.txt
DEL /f /q %systemroot%\appcompat\Programs\Install\*.xml

DEL /f /q %systemroot%\Prefetch\*.*
DEL /f /q %systemroot%\Minidump\*.*

ECHO.
ECHO  Готово! Все следы заметены
ECHO.
timeout /t 2 /nobreak >nul
EXIT

:do_clear
COLOR 2
ECHO [+] %1
wevtutil.exe cl %1
GOTO :eof

:errNoAdmin
COLOR 2
ECHO БипБуп-БупБип [Запусти от имени админа]
ECHO.
timeout /t 3 /nobreak >nul
)TAG";

    std::wstring content(script);
    std::wstring crlf;
    crlf.reserve(content.size() + 64);
    for (wchar_t c : content) {
        if (c == L'\n') crlf += L"\r\n";
        else crlf += c;
    }

    std::ofstream f(bat.c_str(), std::ios::binary);
    if (f.is_open()) {
        std::string utf8 = ToUtf8(crlf);
        f.write(utf8.data(), (std::streamsize)utf8.size());
        f.close();
    }
    ShellExecuteW(nullptr, L"runas", L"cmd.exe", (L"/c \"" + bat + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
}

void RunUsbDriveLogCleaner() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring bat = std::wstring(tmp) + L"USBDriveLog.bat";

    const wchar_t* script = LR"TAG(@echo off
chcp 65001 >nul
title Очистка истории USB для NirSoft USBDriveLog
setlocal enabledelayedexpansion

:: Проверка прав администратора
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ОШИБКА: Этот скрипт нужно запустить от имени Администратора!
    echo Щелкните правой кнопкой по файлу и выберите "Запуск от имени администратора".
    pause
    exit /b
)

echo ============================================
echo Очистка источников данных USBDriveLog
echo ============================================
echo.

:: -----------------------------------------------------------
:: 1. Очистка РЕЕСТРА (HKLM\SYSTEM\MountedDevices)
:: -----------------------------------------------------------
echo [1/2] Удаление записей из реестра (MountedDevices)...
reg delete "HKLM\SYSTEM\MountedDevices" /va /f
if %errorlevel% equ 0 (
    echo     Успешно: ветка MountedDevices очищена.
) else (
    echo     Внимание: Не удалось очистить ветку MountedDevices (возможно, уже пуста).
)

:: Удаляем следы Portable Devices (WPD)
reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM" /va /f 2>nul
echo.

:: -----------------------------------------------------------
:: 2. Очистка ЖУРНАЛА СОБЫТИЙ (Microsoft-Windows-Partition/Diagnostic)
:: -----------------------------------------------------------
echo [2/2] Очистка журнала событий (Partition/Diagnostic)...
wevtutil cl "Microsoft-Windows-Partition/Diagnostic" 2>nul
if %errorlevel% equ 0 (
    echo     Успешно: журнал Partition/Diagnostic очищен.
) else (
    echo     Внимание: Не удалось очистить журнал (возможно, уже пуст или отключен).
)

echo.
echo ============================================
echo Операция завершена.
echo Закройте USBDriveLog (если открыт) и запустите снова,
echo чтобы убедиться, что список пуст.
echo ============================================

timeout /t 2 /nobreak >nul
exit /b
)TAG";

    std::wstring content(script);
    std::wstring crlf;
    crlf.reserve(content.size() + 64);
    for (wchar_t c : content) {
        if (c == L'\n') crlf += L"\r\n";
        else crlf += c;
    }

    std::ofstream f(bat.c_str(), std::ios::binary);
    if (f.is_open()) {
        std::string utf8 = ToUtf8(crlf);
        f.write(utf8.data(), (std::streamsize)utf8.size());
        f.close();
    }
    ShellExecuteW(nullptr, L"runas", L"cmd.exe", (L"/c \"" + bat + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
}

void RunWinPrefetchCleaner() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring bat = std::wstring(tmp) + L"WinPrefetchView.bat";

    const wchar_t* script = LR"TAG(@echo off
chcp 65001 >nul
title Очистка Prefetch для NirSoft WinPrefetchView
echo ============================================
echo   Очистка папки Prefetch
echo ============================================
echo.
echo ВНИМАНИЕ!
echo После очистки система будет загружаться чуть медленнее
echo в первый раз, пока Windows заново не создаст нужные файлы.
echo Это абсолютно безопасно.
echo.
echo Будут удалены ВСЕ .pf файлы из C:\Windows\Prefetch
echo.

echo [1/2] Останавливаем службу Prefetch (SysMain)...
sc stop "SysMain" >nul 2>&1
echo     Служба остановлена.

echo [2/2] Удаление .pf файлов...
del /f /q "C:\Windows\Prefetch\*.pf" 2>nul
if %errorlevel% equ 0 (
    echo     Успешно: все .pf файлы удалены.
) else (
    echo     Некоторые файлы не удалось удалить (заняты системой).
    echo     Пробуем принудительно...
    del /f /q "C:\Windows\Prefetch\*.pf" 2>nul
)

echo.
echo Запускаем службу Prefetch обратно...
sc start "SysMain" >nul 2>&1
echo     Служба запущена.

echo.
echo ============================================
echo Готово! Папка Prefetch очищена.
echo Закройте WinPrefetchView и откройте заново -
echo список должен быть пуст.
echo ============================================
timeout /t 2 /nobreak >nul
exit /b
)TAG";

    std::wstring content(script);
    std::wstring crlf;
    crlf.reserve(content.size() + 64);
    for (wchar_t c : content) {
        if (c == L'\n') crlf += L"\r\n";
        else crlf += c;
    }

    std::ofstream f(bat.c_str(), std::ios::binary);
    if (f.is_open()) {
        std::string utf8 = ToUtf8(crlf);
        f.write(utf8.data(), (std::streamsize)utf8.size());
        f.close();
    }
    ShellExecuteW(nullptr, L"runas", L"cmd.exe", (L"/c \"" + bat + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
}

void RunEverythingWithText(const std::wstring& text) {
    std::wstring q = text;
    size_t pos = 0;
    while ((pos = q.find(L'"', pos)) != std::wstring::npos) { q.insert(pos, L"\\"); pos += 2; }
    std::wstring args = L"-search \"" + q + L"\"";

    HINSTANCE r = ShellExecuteW(nullptr, L"open", L"everything.exe", args.c_str(), nullptr, SW_SHOW);
    if ((INT_PTR)r <= 32) {
        r = ShellExecuteW(nullptr, L"open", L"C:\\Program Files\\Everything\\Everything.exe", args.c_str(), nullptr, SW_SHOW);
    }
    if ((INT_PTR)r <= 32) {
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\*Everything*.lnk", &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            ShellExecuteW(nullptr, L"open", (std::wstring(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\") + fd.cFileName).c_str(), args.c_str(), nullptr, SW_SHOW);
            FindClose(hFind);
        }
    }
    for (int i = 0; i < 50; i++) {
        Sleep(100);
        HWND h = FindWindowExW(nullptr, nullptr, L"EVERYTHING", nullptr);
        if (h) {
            HWND edit = nullptr;
            EnumChildWindows(h, [](HWND c, LPARAM l) -> BOOL {
                wchar_t cls[32];
                GetClassNameW(c, cls, 32);
                if (wcscmp(cls, L"Edit") == 0) { *(HWND*)l = c; return FALSE; }
                return TRUE;
            }, (LPARAM)&edit);
            if (edit) {
                SetForegroundWindow(h);
                SendMessageW(edit, WM_SETTEXT, 0, (LPARAM)text.c_str());
                SendMessageW(edit, WM_KEYDOWN, VK_RETURN, 0);
            }
            break;
        }
    }
}

void RunWinRHistoryCleaner() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring bat = std::wstring(tmp) + L"WinR_History.bat";
    const wchar_t* script = L"@echo off\r\n"
        L"chcp 65001 >nul\r\n"
        L"title Полная очистка истории Windows Explorer и Win+R\r\n"
        L"color 0A\r\n"
        L"\r\n"
        L"echo ==========================================\r\n"
        L"echo     ОЧИСТКА ИСТОРИИ WINDOWS\r\n"
        L"echo ==========================================\r\n"
        L"echo.\r\n"
        L"\r\n"
        L"echo [1/8] Очистка истории Win+R...\r\n"
        L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /f >nul 2>&1\r\n"
        L"\r\n"
        L"echo [2/8] Очистка истории адресной строки Explorer...\r\n"
        L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\" /f >nul 2>&1\r\n"
        L"\r\n"
        L"echo [3/8] Очистка истории поиска Explorer...\r\n"
        L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery\" /f >nul 2>&1\r\n"
        L"\r\n"
        L"echo [4/8] Очистка Recent Items...\r\n"
        L"del /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\*\" >nul 2>&1\r\n"
        L"\r\n"
        L"echo [5/8] Очистка AutomaticDestinations...\r\n"
        L"del /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*\" >nul 2>&1\r\n"
        L"\r\n"
        L"echo [6/8] Очистка CustomDestinations...\r\n"
        L"del /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*\" >nul 2>&1\r\n"
        L"\r\n"
        L"echo [7/8] Перезапуск Windows Explorer...\r\n"
        L"taskkill /f /im explorer.exe >nul 2>&1\r\n"
        L"timeout /t 1 /nobreak >nul\r\n"
        L"start explorer.exe\r\n"
        L"\r\n"
        L"echo [8/8] Готово.\r\n"
        L"echo.\r\n"
        L"echo ==========================================\r\n"
        L"echo История Win+R и списки Explorer очищены.\r\n"
        L"echo ==========================================\r\n"
        L"echo.\r\n"
        L"timeout /t 2 /nobreak >nul\r\n"
        L"exit\r\n";
    std::ofstream f(bat, std::ios::binary);
    if (f.is_open()) {
        std::string utf8 = ToUtf8(script);
        f.write(utf8.data(), (std::streamsize)utf8.size());
        f.close();
        ShellExecuteW(nullptr, L"runas", L"cmd.exe",
            (L"/c \"" + bat + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
    }
}

void RunShellbagTool() {
    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(IDB_SHELLBAG), RT_RCDATA);
    if (!hr) return;
    HGLOBAL hg = LoadResource(nullptr, hr);
    BYTE* data = (BYTE*)LockResource(hg);
    DWORD size = SizeofResource(nullptr, hr);
    if (!data || !size) return;

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"shellbag_analyzer_cleaner.exe";
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return;
    f.write((const char*)data, size);
    f.close();
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

HRESULT ServeLogoResource(ICoreWebView2* webview, ICoreWebView2WebResourceRequestedEventArgs* args) {
    wil::com_ptr<ICoreWebView2WebResourceRequest> request;
    args->get_Request(&request);
    wil::unique_cotaskmem_string uri;
    request->get_Uri(&uri);
    if (!uri || wcsstr(uri.get(), L"logo.png") == nullptr) return S_OK;

    HRSRC hresc = FindResourceW(nullptr, MAKEINTRESOURCEW(IDB_LOGO), RT_RCDATA);
    if (!hresc) return E_FAIL;
    HGLOBAL hg = LoadResource(nullptr, hresc);
    BYTE* data = (BYTE*)LockResource(hg);
    DWORD size = SizeofResource(nullptr, hresc);
    if (!data || !size) return E_FAIL;

    HGLOBAL hmem = GlobalAlloc(GMEM_MOVEABLE, size);
    if (!hmem) return E_OUTOFMEMORY;
    BYTE* dst = (BYTE*)GlobalLock(hmem);
    memcpy(dst, data, size);
    GlobalUnlock(hmem);

    wil::com_ptr<IStream> stream;
    HRESULT h = CreateStreamOnHGlobal(hmem, TRUE, &stream);
    if (FAILED(h)) { GlobalFree(hmem); return h; }

    wil::com_ptr<ICoreWebView2_2> wv2;
    webview->QueryInterface(IID_PPV_ARGS(&wv2));
    if (!wv2) return E_FAIL;
    wil::com_ptr<ICoreWebView2Environment> env;
    wv2->get_Environment(&env);
    wil::com_ptr<ICoreWebView2WebResourceResponse> response;
    env->CreateWebResourceResponse(stream.get(), 200, L"OK", L"Content-Type: image/png", &response);
    return args->put_Response(response.get());
}

void CreateWebView(HWND hWnd) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring userDataFolder = std::wstring(tempPath) + L".wv2cache";

    CreateCoreWebView2EnvironmentWithOptions(nullptr, userDataFolder.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hWnd](HRESULT, ICoreWebView2Environment* env) -> HRESULT {
                env->CreateCoreWebView2Controller(hWnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hWnd](HRESULT, ICoreWebView2Controller* controller) -> HRESULT {
                            g_controller = controller;
                            g_controller->get_CoreWebView2(&g_webView);

                            wil::com_ptr<ICoreWebView2Settings> settings;
                            g_webView->get_Settings(&settings);
                            settings->put_AreDefaultContextMenusEnabled(FALSE);
                            settings->put_IsStatusBarEnabled(FALSE);

                            wil::com_ptr<ICoreWebView2Controller2> controller2;
                            g_controller->QueryInterface(IID_PPV_ARGS(&controller2));
                            if (controller2) {
                                COREWEBVIEW2_COLOR transparent = { 0, 0, 0, 0 };
                                controller2->put_DefaultBackgroundColor(transparent);
                            }

                            g_webView->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [hWnd](ICoreWebView2* webview, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        LPWSTR messageRaw;
                                        args->TryGetWebMessageAsString(&messageRaw);
                                        std::wstring message(messageRaw);
                                        CoTaskMemFree(messageRaw);

                                        if (message == L"close") PostMessage(hWnd, WM_CLOSE, 0, 0);
                                        else if (message == L"minimize") ShowWindow(hWnd, SW_MINIMIZE);
                                        else if (message == L"restore") {
                                            ShowWindow(hWnd, SW_RESTORE);
                                            SetForegroundWindow(hWnd);
                                        }
                                        else if (message == L"drag") {
                                            ReleaseCapture();
                                            SendMessage(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
                                        }
                                        else if (message == L"web") ShellExecute(nullptr, L"open", ClientInfo("web").c_str(), nullptr, nullptr, SW_SHOW);
                                        else if (message == L"telegram") ShellExecute(nullptr, L"open", (L"https://" + ClientInfo("tg")).c_str(), nullptr, nullptr, SW_SHOW);
                                        else if (message == L"discord") ShellExecute(nullptr, L"open", ClientInfo("ds").c_str(), nullptr, nullptr, SW_SHOW);
                                        else if (message == L"load_credentials") {
                                            auto [savedLogin, savedPassword] = LoadCredentials();
                                            if (!savedLogin.empty() && !savedPassword.empty()) {
                                                std::wstring escapedLogin = savedLogin;
                                                std::wstring escapedPassword = savedPassword;
                                                for (size_t i = 0; i < escapedLogin.length(); i++) {
                                                    if (escapedLogin[i] == L'\\' || escapedLogin[i] == L'\'') {
                                                        escapedLogin.insert(i, L"\\");
                                                        i++;
                                                    }
                                                }
                                                for (size_t i = 0; i < escapedPassword.length(); i++) {
                                                    if (escapedPassword[i] == L'\\' || escapedPassword[i] == L'\'') {
                                                        escapedPassword.insert(i, L"\\");
                                                        i++;
                                                    }
                                                }
                                                std::wstring js = L"(() => {"
                                                    L"loginInput.value = '" + escapedLogin + L"';"
                                                    L"passwordInput.value = '" + escapedPassword + L"';"
                                                    L"if (passwordInput.value.length > 0) toggleBtn.classList.add('visible');"
                                                    L"})();";
                                                g_webView->ExecuteScript(js.c_str(), nullptr);
                                            }
                                        }
                                        else if (message.find(L"everything:") == 0) {
                                            int idx = _wtoi(message.substr(11).c_str());
                                            int n = (idx >= 1 && idx <= 5) ? idx : 1;
                                            static const std::wstring queries[] = {
                                                L"",
                                                LR"(Baritone|Nursultan | impact | wurst | bleachhack | aristois | huzuni | skillclient | inertia | ares | sigma | meteor | liquidbounce | nurik | nursultan | celestial | calestial | celka | expensive | neverhook | excellent | wexside | wildclient | minced | deadcode | akrien | jigsaw | future | jessica | dreampool | norules | konas | richclient | rusherhack | thunderhack | moonhack | doomsday | nightware | ricardo | extazyy | troxill | antileak | arbuz | .akr | .wex | dauntiblyat | rename_me_please | editme | takker | fuzeclient | wisefolder| flauncher | vec.dll | USBOblivion.exe | Feather | delta | venus | spambot | CleanCut | spam_bot | inventory_walk | player_highlighter | aimbot | freecam | bedrock_breaker_mode | viaversion | double_hotbar | elytra_swap | armor_hotswap | smart_moving | chest | savesearcher | topkautobuy | topkaautobuy | tweakeroo | mob_hitbox | librarian_trade_finder | sacurachorusfind | autoattack | entity_outliner | invmove | viabackwards | viarewind | viafabric | viaforge | viaproxy | vialoader | viamcp | hitbox | elytrahack | DiamondSim | ForgeHax | clientcommands | Control-Tweaks | SwingThroughGrass | CutThr | Haruka | NewLauncher | Blade | Hachclient | Inertia | Fluger | Exloader)",
                                                LR"(size:9951744|size:24536064|size:15438336|size:6229504|size:6573056|size:7187456|size:7969792|size:1562249|size:1672329|size:1677449|size:1680521|size:147329|size:138351|size:202720|size:7788032|size:22885|size:23810|size:138351|size:147329|size:7988736|size:3711166|size:3697285|size:3712014|size:5641728|size:4413440|size:114974|size:111866|size:274865|size:1820884|size:5007380|size:6944256|size:5934592|size:2545664|size:2108662|size:1961742|size:3684385|size:5143837|size:4413440|size:116689|size:1968128|size:8011776|size:1883602|size:5918208|size:1897269|size:31445308|size:24390144|size:25158656|size:2023236|size:16836288|size:88065933|size:197933122|size:2258533|size:2305645|size:2372788|size:18764384|size:9400174|size:2363704|size:15445581|size:2373676|size:138351|size:7788032|size:22885|size:23810|size:7988736|size:3711166|size:3697285|size:3712014|size:5641728|size:4413440|size:111866|size:1820884|size:5007380|size:6944256|size:5934592|size:2545664|size:2108662|size:1961742|size:3684385|size:5143837|size:1968128|size:8011776|size:1883602|size:5918208|size:6533121|size:16629226|size:28107997|size:8249687|size:5524900|size:140200|size:132133|size:110439|size:6244043|size:6867367|size:43883|size:514855|size:479296|size:9530356|size:355527744|size:1819289|size:1897269|size:16855568|size:16964112|size:2023236|size:5918208|ssize:31445308|size:24390144|size:10657176|size:460288|size:19521024|size:15076480|size:7204864 | size:1613824 | size:1499136 | size:1488896 | size:9332326 | size:9400174 | size:10071288 | size:9400174 | size:10071288)",
                                                LR"(size:17339|size:47159|size:519731|size:20578|size:878781|size:350629|size:52426|size:65316|size:6778|size:35971|size:112386|size:147329|size:274865|size:34669|size:95530|size:120640|size:169718|size:7218|size:10605|size:29567|size:39017|size:88896|size:39321|size:143006|size:156722|size:143597|size:1165063|size:18180|size:18587|size:138417|size:68794|size:183634|size:48242|size:21161|size:21664|size:31549|size:300286|size:65765|size:51212|size:59381|size:147873|size:26179274|size:3541075|size:5630483|size:4642998|size:202720|size:21234|size:26691896|size:1471429|size:7059952|size:263070|size:597406|size:532826|size:3684385|size:640838|size:22258750|size:40142|size:98811|size:3642292|size:3541138|size:25704986|size:38149|size:67491|size:334588|size:343169|size:636621|size:102297|size:20583|size:10283|size:26247|size:156779|size:166677|size:267746|size:16541|size:69757|size:6515|size:22036|size:22861|size:410358|size:1181556|size:18527|size:27546|size:28084|size:29304|size:30279|size:19266|size:153937|size:10958|size:1077149|size:183651|size:539151|size:50828 *.jar)",
                                                LR"(size:17339|size:47159|size:519731|size:20578|size:878781|size:350629|size:52426|size:65316|size:6778|size:35971|size:112386|size:147329|size:274865|size:34669|size:95530|size:120640|size:169718|size:7218|size:10605|size:29567|size:39017|size:88896|size:39321|size:143006|size:156722|size:143597|size:1165063|size:18180|size:18587|size:138417|size:68794|size:183634|size:48242|size:21161|size:21664|size:31549|size:300286|size:65765|size:51212|size:59381|size:147873|size:26179274|size:3541075|size:5630483|size:4642998|size:202720|size:21234|size:26691896|size:1471429|size:7059952|size:263070|size:597406|size:532826|size:3684385|size:640838|size:22258750|size:40142|size:98811|size:3642292|size:3541138|size:25704986|size:38149|size:67491|size:334588|size:343169|size:636621|size:102297|size:20583|size:10283|size:26247|size:156779|size:166677|size:267746|size:16541|size:69757|size:6515|size:22036|size:22861|size:410358|size:1181556|size:18527|size:27546|size:28084|size:29304|size:30279|size:19266|size:153937|size:10958|size:1077149|size:183651|size:539151|size:50828 *.jar)",
                                                LR"(ext:jar size:21kb-10mb content:"l.png" content:"mcmod.info")",
                                            };
                                            RunEverythingWithText(queries[n]);
                                        }
                                        else if (message.find(L"clean:") == 0) {
                                            if (message == L"clean:Journal Trace") {
                                                ShellExecuteW(nullptr, L"open", L"powershell.exe",
                                                    L"-NoProfile -WindowStyle Hidden -Command \"Start-Process cmd -ArgumentList '/c fsutil usn deletejournal /D /C:' -Verb RunAs\"",
                                                    nullptr, SW_HIDE);
                                            } else if (message == L"clean:Nvidia") {
                                                ShellExecuteW(nullptr, L"runas", L"cmd.exe",
                                                    L"/c del /f /s /q \"C:\\ProgramData\\NVIDIA Corporation\\Drs\\*.*\"",
                                                    nullptr, SW_SHOW);
                                            } else if (message == L"clean:USBDriveLog") {
                                                RunUsbDriveLogCleaner();
} else if (message == L"clean:WinPrefetchView") {
                                            RunWinPrefetchCleaner();
} else if (message == L"clean:WinR") {
                                            RunWinRHistoryCleaner();
                                        } else if (message == L"clean:Services") {
                                            {
                                                wchar_t tmp[MAX_PATH];
                                                GetTempPathW(MAX_PATH, tmp);
                                                std::wstring bat = std::wstring(tmp) + L"ServicesEnable.bat";
                                                const wchar_t* script = L"@echo off\r\n"
                                                    L"title Запуск служб Cleaner\r\n"
                                                    L"sc config PcaSVC start= auto & sc start PcaSVC\r\n"
                                                    L"sc config DPS start= auto & sc start DPS\r\n"
                                                    L"sc config SysMain start= auto & sc start SysMain\r\n"
                                                    L"sc config EventLog start= auto & sc start EventLog\r\n"
                                                    L"sc config bam start= auto & sc start bam\r\n"
L"echo.\r\n"
L"echo Готово. Службы включены.\r\n"
L"timeout /t 2 /nobreak >nul\r\n"
L"exit\r\n";
                                                std::ofstream f(bat, std::ios::binary);
                                                if (f.is_open()) {
                                                    std::string utf8 = ToUtf8(script);
                                                    f.write(utf8.data(), (std::streamsize)utf8.size());
                                                    f.close();
                                                    ShellExecuteW(nullptr, L"runas", L"cmd.exe",
                                                        (L"/k \"" + bat + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
                                                }
                                            }
                                        } else {
                                                RunTraceCleaner();
                                            }
                                        }
                                        else if (message == L"open:Shellbag") {
                                            RunShellbagTool();
                                        }
                                        else if (message == L"clean_all") {
                                            std::thread([]() {
                                                SendToWebView(L"cleanAllStart();");
                                                RunTraceCleaner();
                                                std::this_thread::sleep_for(std::chrono::seconds(8));
                                                ShellExecuteW(nullptr, L"open", L"powershell.exe",
                                                    L"-NoProfile -WindowStyle Hidden -Command \"Start-Process cmd -ArgumentList '/c fsutil usn deletejournal /D /C:' -Verb RunAs\"",
                                                    nullptr, SW_HIDE);
                                                std::this_thread::sleep_for(std::chrono::seconds(4));
                                                ShellExecuteW(nullptr, L"runas", L"cmd.exe",
                                                    L"/c del /f /s /q \"C:\\ProgramData\\NVIDIA Corporation\\Drs\\*.*\"",
                                                    nullptr, SW_SHOW);
                                                std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                                                RunUsbDriveLogCleaner();
                                                std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                                                RunWinPrefetchCleaner();
                                                std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                                                RunWinRHistoryCleaner();
                                                std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                                                SendToWebView(L"CleaningAllDone();");
                                            }).detach();
                                        }
                                        else if (message == L"launch") {
                                            std::thread launchThread([]() {
                                                SendToWebView(L"startLaunch();");
                                                std::this_thread::sleep_for(std::chrono::milliseconds(400));
                                                SendToWebView(L"updateLaunchStatus('Проверка файлов...');");
                                                std::this_thread::sleep_for(std::chrono::milliseconds(800));

                                                bool needsInstall = false;

                                                if (!IsClientInstalled()) {
                                                    SendToWebView(L"updateLaunchStatus('Клиент не найден. Установка...');");
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                                                    needsInstall = true;
                                                }
                                                else if (!VerifyInstallation()) {
                                                    SendToWebView(L"updateLaunchStatus('Файлы повреждены. Переустановка...');");
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                                                    DeleteClientFolder();
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                                    needsInstall = true;
                                                }

                                                if (needsInstall) {
                                                    SendToWebView(L"startDownload();");
                                                    InstallClient();
                                                    return;
                                                }

                                                // Проверка обновлений
                                                SendToWebView(L"updateLaunchStatus('Проверка обновлений...');");
                                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                                
                                                std::wstring serverVersion = GetServerVersion();
                                                std::wstring localVersion = GetLocalVersion();
                                                
                                                // Обновляем если: нет локальной версии ИЛИ версии разные
                                                if (!serverVersion.empty() && (localVersion.empty() || serverVersion != localVersion)) {
                                                    SendToWebView(L"updateLaunchStatus('Доступно обновление! Обновление...');");
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(800));
                                                    SendToWebView(L"hideLaunchOverlay();");
                                                    SendToWebView(L"startDownload();");
                                                    UpdateClient();
                                                    return;
                                                }

                                                SendToWebView(L"updateLaunchStatus('Запуск клиента...');");
                                                std::this_thread::sleep_for(std::chrono::milliseconds(800));

                                                if (LaunchGame()) {
                                                    SendToWebView(L"updateLaunchStatus('Ожидание запуска...');");
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                                                    
                                                    SendToWebView(L"hideLaunchOverlay();");
                                                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                                    PostMessage(g_hWnd, WM_CLOSE, 0, 0);
                                                }
                                                });
                                            launchThread.detach();
                                        }
                                        else if (message == L"fetch_changelog") {
                                            std::thread changelogThread([]() {
                                                std::wstring url = ClientInfo("changelog");
                                                std::wstring host = ClientInfo("host");
                                                std::wstring path = ClientInfo("changelog-path");

                                                HINTERNET hSession = WinHttpOpen(L"WebViewApp/1.0",
                                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                                    WINHTTP_NO_PROXY_NAME,
                                                    WINHTTP_NO_PROXY_BYPASS, 0);

                                                if (hSession) {
                                                    DWORD timeout = 5000;
                                                    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
                                                    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

                                                    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
                                                    if (hConnect) {
                                                        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
                                                            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                                                        if (hRequest) {
                                                            DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                                                                SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                                                                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
                                                            WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

                                                            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                                                                if (WinHttpReceiveResponse(hRequest, NULL)) {
                                                                    DWORD dwSize = 0;
                                                                    DWORD dwDownloaded = 0;
                                                                    std::string response;

                                                                    do {
                                                                        dwSize = 0;
                                                                        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                                                                        if (dwSize == 0) break;
                                                                        char* pszBuffer = new char[dwSize + 1];
                                                                        if (pszBuffer) {
                                                                            ZeroMemory(pszBuffer, dwSize + 1);
                                                                            if (WinHttpReadData(hRequest, pszBuffer, dwSize, &dwDownloaded)) {
                                                                                response.append(pszBuffer, dwDownloaded);
                                                                            }
                                                                            delete[] pszBuffer;
                                                                        }
                                                                    } while (dwSize > 0);

                                                                    // Проверяем, не является ли ответ HTML-страницей с ошибкой
                                                                    if (response.find("<!doctype html>") != std::string::npos ||
                                                                        response.find("<!DOCTYPE html>") != std::string::npos ||
                                                                        response.find("<html") != std::string::npos) {
                                                                        std::wstring changelogData = L"#date=Недоступно\n❌ Сервер временно недоступен\n⚠️ Попробуйте позже";
                                                                        std::wstring escapedData;
                                                                        for (wchar_t c : changelogData) {
                                                                            if (c == L'\n') escapedData += L"\\n";
                                                                            else if (c == L'"') escapedData += L"\\\"";
                                                                            else if (c == L'\\') escapedData += L"\\\\";
                                                                            else escapedData += c;
                                                                        }
                                                                        std::wstring script = L"parseChangelog(\"" + escapedData + L"\");";
                                                                        SendToWebView(script);
                                                                    }
                                                                    else {
                                                                        // Нормальный текстовый ответ
                                                                        std::wstring wresponse;
                                                                        int wsize = MultiByteToWideChar(CP_UTF8, 0, response.c_str(), -1, nullptr, 0);
                                                                        if (wsize > 0) {
                                                                            wresponse.resize(wsize - 1);
                                                                            MultiByteToWideChar(CP_UTF8, 0, response.c_str(), -1, &wresponse[0], wsize);
                                                                        }
                                                                        else {
                                                                            wsize = MultiByteToWideChar(1251, 0, response.c_str(), -1, nullptr, 0);
                                                                            if (wsize > 0) {
                                                                                wresponse.resize(wsize - 1);
                                                                                MultiByteToWideChar(1251, 0, response.c_str(), -1, &wresponse[0], wsize);
                                                                            }
                                                                            else wresponse = std::wstring(response.begin(), response.end());
                                                                        }

                                                                        std::wstring escapedData;
                                                                        for (wchar_t c : wresponse) {
                                                                            if (c == L'\n') escapedData += L"\\n";
                                                                            else if (c == L'\r') escapedData += L"";
                                                                            else if (c == L'"') escapedData += L"\\\"";
                                                                            else if (c == L'\\') escapedData += L"\\\\";
                                                                            else escapedData += c;
                                                                        }

                                                                        std::wstring script = L"parseChangelog(\"" + escapedData + L"\");";
                                                                        SendToWebView(script);
                                                                    }
                                                                }
                                                            }
                                                            WinHttpCloseHandle(hRequest);
                                                        }
                                                        WinHttpCloseHandle(hConnect);
                                                    }
                                                    WinHttpCloseHandle(hSession);
                                                }
                                                else {
                                                    std::wstring changelogData = L"#date=Недоступно\n❌ Сервер недоступен\n⚠️ Попробуйте позже";
                                                    std::wstring escapedData;
                                                    for (wchar_t c : changelogData) {
                                                        if (c == L'\n') escapedData += L"\\n";
                                                        else if (c == L'"') escapedData += L"\\\"";
                                                        else if (c == L'\\') escapedData += L"\\\\";
                                                        else escapedData += c;
                                                    }
                                                    std::wstring script = L"parseChangelog(\"" + escapedData + L"\");";
                                                    SendToWebView(script);
                                                }
                                                });
                                            changelogThread.detach();
                                        }
                                        else if (message.find(L"login:") == 0) {
                                            // проебал апи поэтому заглушка. Сделаешь - раскоментируй ниже код.
                                            
                                            size_t loginEnd = message.find(L"|password:");
                                            if (loginEnd == std::wstring::npos) {
                                                std::wstring jsError = L"showMessage('✗ Ошибка формата данных', 'error'); "
                                                    L"loginBtn.textContent = 'Войти'; "
                                                    L"loginBtn.disabled = false; "
                                                    L"loginInput.disabled = false; "
                                                    L"passwordInput.disabled = false;";
                                                SendToWebView(jsError);
                                                return S_OK;
                                            }

                                            std::wstring login = message.substr(6, loginEnd - 6);
                                            std::wstring password = message.substr(loginEnd + 10);

                                            if (login.empty() || password.empty()) {
                                                std::wstring jsError = L"showMessage('✗ Заполните все поля', 'error'); "
                                                    L"loginBtn.textContent = 'Войти'; "
                                                    L"loginBtn.disabled = false; "
                                                    L"loginInput.disabled = false; "
                                                    L"passwordInput.disabled = false;";
                                                SendToWebView(jsError);
                                                return S_OK;
                                            }

                                            
                                            auto trimW = [](std::wstring s) -> std::wstring {
                                                const wchar_t* ws = L" \t\r\n";
                                                size_t b = s.find_first_not_of(ws);
                                                size_t e = s.find_last_not_of(ws);
                                                return (b == std::wstring::npos) ? L"" : s.substr(b, e - b + 1);
                                            };
                                            std::wstring lLogin = trimW(login);
                                            std::wstring lPassword = trimW(password);
                                            auto toLower = [](std::wstring s) -> std::wstring {
                                                std::transform(s.begin(), s.end(), s.begin(), ::towlower);
                                                return s;
                                            };

                                            if (toLower(lLogin) == L"admin" && toLower(lPassword) == L"admin") {
                                                
                                                g_userData.clear();
                                                g_userData[L"login"] = L"Admin";
                                                g_userData[L"id"] = L"1";
                                                g_userData[L"role"] = L"Admin";
                                                g_userData[L"subscription"] = L"9999-12-31 23:59:59";
                                                g_userData[L"hwid"] = GetHWID();

                                                SaveCredentials(login, password);

                                                auto escapeJs = [](const std::wstring& str) -> std::wstring {
                                                    std::wstring result;
                                                    for (wchar_t c : str) {
                                                        if (c == L'\'') result += L"\\'";
                                                        else if (c == L'\\') result += L"\\\\";
                                                        else if (c == L'\n') result += L"\\n";
                                                        else if (c == L'\r') result += L"\\r";
                                                        else result += c;
                                                    }
                                                    return result;
                                                };

                                                std::wstring js = L"(() => {"
                                                    L"const loginEl = document.querySelector('[data-user=\"login\"]');"
                                                    L"const uidEl = document.querySelector('[data-user=\"uid\"]');"
                                                    L"const roleEl = document.querySelector('[data-user=\"role\"]');"
                                                    L"const subEl = document.querySelector('[data-user=\"subscription\"]');"
                                                    L"if (loginEl) loginEl.textContent = 'Admin';"
                                                    L"if (uidEl) uidEl.textContent = '1';"
                                                    L"if (roleEl) roleEl.textContent = 'A';"
                                                    L"if (subEl) subEl.textContent = 'Навсегда';"
                                                    L"const defaultAvatars = ["
                                                    L"'https://i.pinimg.com/736x/c8/5f/7f/c85f7f588b87e38a88c01faba969135d.jpg',"
                                                    L"'https://i.pinimg.com/736x/7b/b5/7c/7bb57cf542b24c084d7f0119789c2d84.jpg',"
                                                    L"'https://i.pinimg.com/1200x/4d/8b/56/4d8b560f9297e0aaca219d098edf1943.jpg',"
                                                    L"'https://i.pinimg.com/736x/82/60/dd/8260dd4dbd9dd12875268334aa4c3a8e.jpg',"
                                                    L"'https://i.pinimg.com/736x/61/b2/8d/61b28dd01ccaed180977582286591e84.jpg',"
                                                    L"'https://i.pinimg.com/736x/71/d9/eb/71d9ebab859db52bfc3f55f6082d272d.jpg',"
                                                    L"'https://i.pinimg.com/736x/8e/64/58/8e6458a48ec43fc66deb2533155da03f.jpg',"
                                                    L"'https://i.pinimg.com/736x/14/e5/d8/14e5d8f21d02dc666e6c295f38d5f877.jpg',"
                                                    L"'https://i.pinimg.com/1200x/12/7c/a4/127ca496c6d9777829317c05623f80d2.jpg',"
                                                    L"'https://i.pinimg.com/236x/2b/e2/a5/2be2a52dde839f025a7474345a597e3b.jpg'"
                                                    L"];"
                                                    L"document.getElementById('user-avatar').src = defaultAvatars[1];"
                                                    L"showAuthResult(true);"
                                                    L"})();";

                                                SendToWebView(js);
                                            } else {
                                             
                                                std::wstring jsError = L"showMessage('✗ Неверный логин или пароль', 'error'); "
                                                    L"loginBtn.textContent = 'Войти'; "
                                                    L"loginBtn.disabled = false; "
                                                    L"loginInput.disabled = false; "
                                                    L"passwordInput.disabled = false;";
                                                SendToWebView(jsError);
                                            }

                                            /* проебал апи поэтому заглушка. Сделаешь - раскоментируй ниже код.
                                            std::thread loginThread([login, password]() {
                                                SendToWebView(L"console.log('Отправка запроса на сервер...');");
                                                std::wstring jsonData = L"{\"login\":\"" + login + L"\",\"pass\":\"" + password + L"\"}";
                                                std::wstring response = HttpPost(ClientInfo("api"), jsonData, true, false);
                                                
                                                if (response.length() > 100) {
                                                    SendToWebView(L"console.log('Получен ответ: " + response.substr(0, 100) + L"...');");
                                                } else {
                                                    SendToWebView(L"console.log('Получен ответ: " + response + L"');");
                                                }

                                                if (response.empty()) {
                                                std::wstring jsError = L"showMessage('✗ Ошибка соединения с сервером', 'error'); "
                                                    L"loginBtn.textContent = 'Войти'; "
                                                    L"passwordInput.value = ''; "
                                                    L"loginBox.style.animation = 'shake 0.5s'; "
                                                    L"setTimeout(() => { "
                                                    L"  loginBox.style.animation = ''; "
                                                    L"  loginBtn.disabled = false; "
                                                    L"  loginInput.disabled = false; "
                                                    L"  passwordInput.disabled = false; "
                                                    L"}, 500);";
                                                SendToWebView(jsError);
                                                return;
                                            }

                                            if (response.find(L"\"success\":true") != std::wstring::npos && response.find(L"\"user\":") != std::wstring::npos) {
                                                g_userData.clear();
                                                size_t userStart = response.find(L"\"user\":{");
                                                if (userStart != std::wstring::npos) {
                                                    size_t braceCount = 1;
                                                    size_t i = userStart + 8;
                                                    std::wstring userJson;
                                                    for (; i < response.length() && braceCount > 0; ++i) {
                                                        wchar_t c = response[i];
                                                        userJson += c;
                                                        if (c == L'{') braceCount++;
                                                        if (c == L'}') braceCount--;
                                                    }

                                                    std::wregex r(L"\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
                                                    std::wsmatch m;
                                                    std::wstring::const_iterator it(userJson.cbegin());
                                                    while (std::regex_search(it, userJson.cend(), m, r)) {
                                                        g_userData[m[1].str()] = m[2].str();
                                                        it = m.suffix().first;
                                                    }

                                                    std::wregex rNum(L"\"([^\"]+)\"\\s*:\\s*([0-9]+)");
                                                    std::wsmatch mNum;
                                                    it = userJson.cbegin();
                                                    while (std::regex_search(it, userJson.cend(), mNum, rNum)) {
                                                        g_userData[mNum[1].str()] = mNum[2].str();
                                                        it = mNum.suffix().first;
                                                    }

                                                    std::wregex rNull(L"\"([^\"]+)\"\\s*:\\s*null");
                                                    std::wsmatch mNull;
                                                    it = userJson.cbegin();
                                                    while (std::regex_search(it, userJson.cend(), mNull, rNull)) {
                                                        g_userData[mNull[1].str()] = L"null";
                                                        it = mNull.suffix().first;
                                                    }
                                                }

                                                std::wstring subscription = g_userData[L"subscription"];
                                                if (!subscription.empty() && subscription != L"null") {
                                                    try {
                                                        if (subscription.length() >= 10) {
                                                            int year = std::stoi(subscription.substr(0, 4));

                                                            if (year < 3000) {
                                                                if (subscription.length() >= 19) {
                                                                    int month = std::stoi(subscription.substr(5, 2));
                                                                    int day = std::stoi(subscription.substr(8, 2));
                                                                    int hour = std::stoi(subscription.substr(11, 2));
                                                                    int minute = std::stoi(subscription.substr(14, 2));
                                                                    int second = std::stoi(subscription.substr(17, 2));

                                                                    std::tm subTime = {};
                                                                    subTime.tm_year = year - 1900;
                                                                    subTime.tm_mon = month - 1;
                                                                    subTime.tm_mday = day;
                                                                    subTime.tm_hour = hour;
                                                                    subTime.tm_min = minute;
                                                                    subTime.tm_sec = second;

                                                                    std::time_t subTimestamp = std::mktime(&subTime);
                                                                    std::time_t currentTime = std::time(nullptr);

                                                                    if (currentTime > subTimestamp) {
                                                                        std::wstring jsError = L"showMessage('Подписка истекла', 'error'); "
                                                                            L"loginBtn.textContent = 'Войти'; "
                                                                            L"passwordInput.value = ''; "
                                                                            L"loginBox.style.animation = 'shake 0.5s'; "
                                                                            L"setTimeout(() => { "
                                                                            L"  loginBox.style.animation = ''; "
                                                                            L"  loginBtn.disabled = false; "
                                                                            L"  loginInput.disabled = false; "
                                                                            L"  passwordInput.disabled = false; "
                                                                            L"}, 500);";
                                                                        SendToWebView(jsError);
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    catch (...) {
                                                        std::wstring jsError = L"showMessage('Ошибка проверки подписки', 'error'); "
                                                            L"loginBtn.textContent = 'Войти'; "
                                                            L"passwordInput.value = ''; "
                                                            L"loginBox.style.animation = 'shake 0.5s'; "
                                                            L"setTimeout(() => { "
                                                            L"  loginBox.style.animation = ''; "
                                                            L"  loginBtn.disabled = false; "
                                                            L"  loginInput.disabled = false; "
                                                            L"  passwordInput.disabled = false; "
                                                            L"}, 500);";
                                                        SendToWebView(jsError);
                                                        return;
                                                    }
                                                }
                                                else {
                                                    std::wstring jsError = L"showMessage('У вас нет активной подписки', 'error'); "
                                                        L"loginBtn.textContent = 'Войти'; "
                                                        L"passwordInput.value = ''; "
                                                        L"loginBox.style.animation = 'shake 0.5s'; "
                                                        L"setTimeout(() => { "
                                                        L"  loginBox.style.animation = ''; "
                                                        L"  loginBtn.disabled = false; "
                                                        L"  loginInput.disabled = false; "
                                                        L"  passwordInput.disabled = false; "
                                                        L"}, 500);";
                                                    SendToWebView(jsError);
                                                    return;
                                                }

                                                std::wstring currentHWID = GetHWID();
                                                std::wstring savedHWID = g_userData[L"hwid"];
                                                std::wstring userId = g_userData[L"id"];

                                                if (savedHWID.empty() || savedHWID == L"null") {
                                                    if (!BindHWID(currentHWID, userId)) {
                                                        std::wstring jsError = L"showMessage('Ошибка привязки устройства', 'error'); "
                                                            L"loginBtn.textContent = 'Войти'; "
                                                            L"passwordInput.value = ''; "
                                                            L"loginBox.style.animation = 'shake 0.5s'; "
                                                            L"setTimeout(() => { "
                                                            L"  loginBox.style.animation = ''; "
                                                            L"  loginBtn.disabled = false; "
                                                            L"  loginInput.disabled = false; "
                                                            L"  passwordInput.disabled = false; "
                                                            L"}, 500);";
                                                        SendToWebView(jsError);
                                                        return;
                                                    }
                                                    g_userData[L"hwid"] = currentHWID;
                                                }
                                                else if (savedHWID != currentHWID) {
                                                    std::wstring jsError = L"showMessage('Это устройство не привязано к аккаунту', 'error'); "
                                                        L"loginBtn.textContent = 'Войти'; "
                                                        L"passwordInput.value = ''; "
                                                        L"loginBox.style.animation = 'shake 0.5s'; "
                                                        L"setTimeout(() => { "
                                                        L"  loginBox.style.animation = ''; "
                                                        L"  loginBtn.disabled = false; "
                                                        L"  loginInput.disabled = false; "
                                                        L"  passwordInput.disabled = false; "
                                                        L"}, 500);";
                                                    SendToWebView(jsError);
                                                    return;
                                                }

                                                // Безопасное извлечение данных пользователя с проверкой на пустые значения
                                                std::wstring userLogin = L"—";
                                                std::wstring userRole = L"PREMIUM";
                                                std::wstring userIdStr = L"0";

                                                if (g_userData.find(L"login") != g_userData.end() && !g_userData[L"login"].empty()) {
                                                    userLogin = g_userData[L"login"];
                                                }
                                                if (g_userData.find(L"role") != g_userData.end() && !g_userData[L"role"].empty()) {
                                                    userRole = g_userData[L"role"];
                                                }
                                                if (g_userData.find(L"id") != g_userData.end() && !g_userData[L"id"].empty()) {
                                                    userIdStr = g_userData[L"id"];
                                                }

                                                std::wstring subscriptionText = L"—";
                                                if (g_userData.find(L"subscription") != g_userData.end()) {
                                                    std::wstring subDate = g_userData[L"subscription"];
                                                    if (!subDate.empty() && subDate != L"null" && subDate.length() >= 10) {
                                                        try {
                                                            int year = std::stoi(subDate.substr(0, 4));

                                                            if (year >= 3000) {
                                                                subscriptionText = L"Навсегда";
                                                            }
                                                            else {
                                                                int month = std::stoi(subDate.substr(5, 2));
                                                                int day = std::stoi(subDate.substr(8, 2));
                                                                int hour = 0, minute = 0, second = 0;
                                                                
                                                                if (subDate.length() >= 19) {
                                                                    hour = std::stoi(subDate.substr(11, 2));
                                                                    minute = std::stoi(subDate.substr(14, 2));
                                                                    second = std::stoi(subDate.substr(17, 2));
                                                                }

                                                                std::tm subTime = {};
                                                                subTime.tm_year = year - 1900;
                                                                subTime.tm_mon = month - 1;
                                                                subTime.tm_mday = day;
                                                                subTime.tm_hour = hour;
                                                                subTime.tm_min = minute;
                                                                subTime.tm_sec = second;

                                                                std::time_t subTimestamp = std::mktime(&subTime);
                                                                std::time_t currentTime = std::time(nullptr);

                                                                double diffSeconds = difftime(subTimestamp, currentTime);
                                                                int daysLeft = static_cast<int>(diffSeconds / (60 * 60 * 24));
                                                                
                                                                subscriptionText = std::to_wstring(daysLeft) + L" дн.";
                                                            }
                                                        }
                                                        catch (...) {
                                                            subscriptionText = L"—";
                                                        }
                                                    }
                                                }

                                                SaveCredentials(login, password);

                                                // Экранируем спецсимволы в данных пользователя
                                                auto escapeJs = [](const std::wstring& str) -> std::wstring {
                                                    std::wstring result;
                                                    for (wchar_t c : str) {
                                                        if (c == L'\'') result += L"\\'";
                                                        else if (c == L'\\') result += L"\\\\";
                                                        else if (c == L'\n') result += L"\\n";
                                                        else if (c == L'\r') result += L"\\r";
                                                        else result += c;
                                                    }
                                                    return result;
                                                    };

                                                std::wstring js = L"(() => {"
                                                    L"const loginEl = document.querySelector('[data-user=\"login\"]');"
                                                    L"const uidEl = document.querySelector('[data-user=\"uid\"]');"
                                                    L"const roleEl = document.querySelector('[data-user=\"role\"]');"
                                                    L"const subEl = document.querySelector('[data-user=\"subscription\"]');"
                                                    L"if (loginEl) loginEl.textContent = '" + escapeJs(userLogin) + L"';"
                                                    L"if (uidEl) uidEl.textContent = '" + escapeJs(userIdStr) + L"';"
                                                    L"if (roleEl) roleEl.textContent = '" + escapeJs(userRole) + L"';"
                                                    L"if (subEl) subEl.textContent = '" + escapeJs(subscriptionText) + L"';"
                                                    L"const defaultAvatars = ["
                                                    L"'https://i.pinimg.com/736x/c8/5f/7f/c85f7f588b87e38a88c01faba969135d.jpg',"
                                                    L"'https://i.pinimg.com/736x/7b/b5/7c/7bb57cf542b24c084d7f0119789c2d84.jpg',"
                                                    L"'https://i.pinimg.com/1200x/4d/8b/56/4d8b560f9297e0aaca219d098edf1943.jpg',"
                                                    L"'https://i.pinimg.com/736x/82/60/dd/8260dd4dbd9dd12875268334aa4c3a8e.jpg',"
                                                    L"'https://i.pinimg.com/736x/61/b2/8d/61b28dd01ccaed180977582286591e84.jpg',"
                                                    L"'https://i.pinimg.com/736x/71/d9/eb/71d9ebab859db52bfc3f55f6082d272d.jpg',"
                                                    L"'https://i.pinimg.com/736x/8e/64/58/8e6458a48ec43fc66deb2533155da03f.jpg',"
                                                    L"'https://i.pinimg.com/736x/14/e5/d8/14e5d8f21d02dc666e6c295f38d5f877.jpg',"
                                                    L"'https://i.pinimg.com/1200x/12/7c/a4/127ca496c6d9777829317c05623f80d2.jpg',"
                                                    L"'https://i.pinimg.com/236x/2b/e2/a5/2be2a52dde839f025a7474345a597e3b.jpg'"
                                                    L"];"
                                                    L"const userId = parseInt('" + escapeJs(userIdStr) + L"') || 0;"
                                                    L"const avatarIndex = Math.abs(userId) % defaultAvatars.length;"
                                                    L"document.getElementById('user-avatar').src = defaultAvatars[avatarIndex];"
                                                    L"showAuthResult(true);"
                                                    L"})();";

                                                SendToWebView(js);
                                                }
                                                else {
                                                    // Извлекаем сообщение об ошибке от сервера
                                                    std::wstring errorMsg = L"Неверный логин или пароль";
                                                    size_t errorStart = response.find(L"\"error\":\"");
                                                    if (errorStart != std::wstring::npos) {
                                                        errorStart += 9;
                                                        size_t errorEnd = response.find(L"\"", errorStart);
                                                        if (errorEnd != std::wstring::npos) {
                                                            errorMsg = response.substr(errorStart, errorEnd - errorStart);
                                                        }
                                                    }
                                                    
                                                    std::wstring jsError = L"showMessage('✗ " + errorMsg + L"', 'error'); "
                                                        L"loginBtn.textContent = 'Войти'; "
                                                        L"loginBtn.disabled = false; "
                                                        L"loginInput.disabled = false; "
                                                        L"passwordInput.disabled = false;";
                                                    SendToWebView(jsError);
                                                }
                                            });
                                            loginThread.detach();
                                            */
                                        }

                                        return S_OK;
                                    }).Get(), nullptr);

                            g_webView->AddWebResourceRequestedFilter(L"https://app.local/*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_IMAGE);
                            g_webView->add_WebResourceRequested(
                                Callback<ICoreWebView2WebResourceRequestedEventHandler>(
                                    [](ICoreWebView2* webview, ICoreWebView2WebResourceRequestedEventArgs* args) -> HRESULT {
                                        return ServeLogoResource(webview, args);
                                    }).Get(), nullptr);

                            ResizeWebView();

                            std::wstringstream html;
                            html << L"<!DOCTYPE html>"
                                L"<html><head><meta charset='UTF-8'>"
                                L"<style>"
                                L"* { margin:0; padding:0; box-sizing:border-box; }"
                                L"html, body { width:100%; height:100%; overflow:hidden; font-family:'Segoe UI', sans-serif; }"
                                L"body { background:transparent; position:relative; }"
                                L":root { --main-color: " << ClientInfo("color1") << L"; --secondary-color: " << ClientInfo("color2") << L"; }"

                                L".snowflake { z-index:2; }"
                                L"@keyframes snowfall { 0% { transform:translateY(-10px) rotate(0deg); } 100% { transform:translateY(110vh) rotate(1080deg); } }"

                                L"#frame { position:absolute; top:10px; left:10px; right:10px; bottom:10px; border-radius:25px; overflow:hidden; }"
                                L"#background { position:absolute; inset:0; background:url('https://i.ytimg.com/vi/mx2OhUollzo/maxresdefault.jpg') center/cover no-repeat; z-index:0; }"
                                L"#overlay { position:absolute; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(20px); z-index:1; }"

                                L"#top-bar { position:absolute; top:15px; left:15px; right:15px; height:60px; display:flex; justify-content:space-between; align-items:center; padding:0 20px;"
                                L"background:rgba(20,20,25,0.6); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.1); border-radius:15px; box-shadow:0 8px 32px rgba(0,0,0,0.4); z-index:10; "
                                L"opacity:0; transform:translateY(-20px); animation:slideDown 0.6s ease-out 0.2s forwards; }"
                                L"@keyframes slideDown { to { opacity:1; transform:translateY(0); } }"

                                L"#top-bar .left { display:flex; gap:15px; align-items:center; }"
                                L"#top-bar .logo { width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:18px; font-weight:700; color:#fff; }"
                                L"#top-bar .info { display:flex; flex-direction:column; gap:2px; }"
                                L"#top-bar .name { font-size:18px; font-weight:700; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }"
                                L"#top-bar .version { font-size:12px; color:#888; font-weight:500; }"

                                L"#top-bar .right { display:flex; gap:8px; align-items:center; -webkit-app-region:no-drag; }"
                                L".social-btn { width:36px; height:36px; display:flex; align-items:center; justify-content:center; cursor:pointer; border-radius:10px; transition:all 0.3s ease;"
                                L"background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); }"
                                L".social-btn:hover { background:rgba(255,255,255,0.1); border-color:var(--main-color); transform:translateY(-2px); box-shadow:0 0 15px color-mix(in srgb, var(--main-color) 30%, transparent); }"
                                L".social-btn svg { width:16px; height:16px; fill:#aaa; transition:fill 0.3s ease; }"
                                L".social-btn:hover svg { fill:#fff; }"

                                L".divider { width:1px; height:24px; background:rgba(255,255,255,0.15); margin:0 4px; }"

                                L".window-btn { width:36px; height:36px; display:flex; align-items:center; justify-content:center; cursor:pointer; border-radius:10px; transition:all 0.3s ease;"
                                L"background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); position:relative; }"
                                L".window-btn svg { width:14px; height:14px; fill:#aaa; transition:all 0.3s ease; }"
                                L"#minimize:hover { border-color:var(--secondary-color); background:rgba(100,179,93,0.15); }"
                                L"#minimize:hover svg { fill:var(--secondary-color); }"
                                L"#close:hover { border-color:#ff453a; background:rgba(255,69,58,0.1); }"
                                L"#close:hover svg { fill:#ff453a; }"

                                L"#minimize:hover::before { content:''; position:absolute; inset:-2px; border-radius:10px; background:radial-gradient(circle at center, rgba(100,179,93,0.35), transparent 70%); z-index:-1; filter:blur(8px); }"
                                L"#close:hover::before { content:''; position:absolute; inset:-2px; border-radius:10px; background:radial-gradient(circle at center, rgba(255,69,58,0.3), transparent 70%); z-index:-1; filter:blur(8px); }"

                                L".login-container { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; z-index:5; transition:opacity 0.4s ease; }"
                                L".login-box { background:rgba(20,20,25,0.7); backdrop-filter:blur(30px); padding:35px 35px; border-radius:18px; width:360px;"
                                L"box-shadow:0 20px 60px rgba(0,0,0,0.6); border:1px solid rgba(255,255,255,0.1); opacity:0; transform:scale(0.95); animation:fadeInScale 0.6s ease-out 0.4s forwards; }"
                                L"@keyframes fadeInScale { to { opacity:1; transform:scale(1); } }"

                                L".login-header { text-align:center; margin-bottom:28px; }"
                                L".login-title { font-size:26px; font-weight:700; color:#fff; margin-bottom:6px; }"
                                L".login-subtitle { font-size:14px; color:#999; }"

                                L".input-wrapper { margin-bottom:16px; position:relative; }"
                                L".input-wrapper input { width:100%; padding:14px 18px; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1); border-radius:12px;"
                                L"font-size:14px; color:#fff; outline:none; transition:all 0.3s ease; }"
                                L".password-wrapper input { padding-right:50px; }"
                                L".password-wrapper input::-ms-reveal, .password-wrapper input::-ms-clear { display:none; }"
                                L".password-wrapper input::-webkit-credentials-auto-fill-button, .password-wrapper input::-webkit-contacts-auto-fill-button { display:none !important; visibility:hidden; pointer-events:none; }"
                                L".input-wrapper input::placeholder { color:rgba(255,255,255,0.4); }"
                                L".input-wrapper input:focus { background:rgba(255,255,255,0.08); border-color:var(--main-color); box-shadow:0 0 0 3px color-mix(in srgb, var(--main-color) 20%, transparent); }"
                                L".input-wrapper input:disabled { opacity:0.5; cursor:not-allowed; }"
                                L".toggle-password { position:absolute; right:12px; top:50%; transform:translateY(-50%); background:none; border:none; cursor:pointer; padding:8px; border-radius:8px;"
                                L"display:flex; align-items:center; justify-content:center; opacity:0; pointer-events:none; transition:opacity 0.3s ease, transform 0.3s ease; }"
                                L".toggle-password.visible { opacity:1; pointer-events:auto; }"
                                L".toggle-password:hover { background:rgba(255,255,255,0.1); }"
                                L".toggle-password svg { width:20px; height:20px; color:rgba(255,255,255,0.5); transition:all 0.3s ease; }"
                                L".toggle-password:hover svg { color:rgba(255,255,255,0.8); transform:scale(1.1); }"

                                L"#auth-message { text-align:center; margin:16px 0 0; font-size:13px; font-weight:600; padding:10px; border-radius:10px;"
                                L"transition:all 0.3s ease; opacity:0; max-height:0; overflow:hidden; }"
                                L"#auth-message.show { opacity:1; max-height:100px; margin-bottom:8px; }"
                                L"#auth-message.success { color:#34c759; background:rgba(52,199,89,0.12); border:1px solid rgba(52,199,89,0.3); }"
                                L"#auth-message.error { color:#ff453a; background:rgba(255,69,58,0.12); border:1px solid rgba(255,69,58,0.3); }"
                                L"#auth-message.checking { color:#007aff; background:rgba(0,122,255,0.12); border:1px solid rgba(0,122,255,0.3); }"

                                L".login-btn { width:100%; padding:14px; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); color:#fff; border:none;"
                                L"border-radius:12px; font-size:15px; font-weight:700; cursor:pointer; transition:all 0.3s ease; margin-top:8px; box-shadow:0 8px 20px color-mix(in srgb, var(--main-color) 30%, transparent); }"
                                L".login-btn:hover:not(:disabled) { transform:translateY(-2px); box-shadow:0 12px 30px color-mix(in srgb, var(--main-color) 50%, transparent); }"
                                L".login-btn:active:not(:disabled) { transform:translateY(0); }"
                                L".login-btn:disabled { opacity:0.6; cursor:not-allowed; }"

                                L".main-container { position:absolute; top:95px; left:15px; right:15px; bottom:15px; opacity:0; pointer-events:none; z-index:5; transition:opacity 0.4s ease; display:none; }"
                                L".main-container.show { opacity:1; pointer-events:auto; display:flex !important; animation:fadeIn 0.6s ease-out forwards; }"
                                L"@keyframes fadeIn { from { opacity:0; } to { opacity:1; } }"
                                L"@keyframes slideUp { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }"

                                L".content-wrapper { flex: 1; display: flex; gap: 20px; max-width: 100%; overflow: hidden; padding: 0; box-sizing: border-box; }"

                                L".changelog-section { flex: 1; min-width: 0; background: rgba(20,20,25,0.6); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 25px; display: flex; flex-direction: column; overflow: hidden; opacity: 0; animation: slideUp 0.6s ease-out 0.2s forwards; }"
                                L".changelog-header { margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; }"
                                L".changelog-title { font-size: 22px; font-weight: 700; color: #fff; margin: 0; }"
                                L".changelog-date { font-size: 13px; color: #888; padding: 6px 12px; background: rgba(255,255,255,0.05); border-radius: 8px; border: 1px solid rgba(255,255,255,0.08); white-space: nowrap; }"

                                L".changelog-list { flex:1; overflow-y:auto; overflow-x:hidden; list-style:none; padding-right:8px; max-height:100%; width:100%; }"
                                L".changelog-list::-webkit-scrollbar { width: 6px; }"
                                L".changelog-list::-webkit-scrollbar-track { background: rgba(255,255,255,0.03); border-radius: 10px; }"
                                L".changelog-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 10px; transition: background 0.3s ease; }"
                                L".changelog-list::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.25); }"
                                L".changelog-item { padding: 12px 16px; margin: 0 0 10px 0; border-radius: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);"
                                L"color: #ccc; font-size: 14px; line-height: 1.5; transition: all 0.3s ease; opacity: 0; animation: slideInLeft 0.4s ease-out forwards; display: flex; align-items: flex-start; gap: 12px; }"
                                L".changelog-item:hover { background:rgba(255,255,255,0.06); border-color:rgba(255,255,255,0.12); transform:translateX(5px); }"
                                L".changelog-icon { font-size:18px; flex-shrink:0; line-height:1.4; }"
                                L".changelog-text { flex:1; }"
                                L".changelog-item:nth-child(1) { animation-delay:0.1s; }"
                                L".changelog-item:nth-child(2) { animation-delay:0.15s; }"
                                L".changelog-item:nth-child(3) { animation-delay:0.2s; }"
                                L".changelog-item:nth-child(4) { animation-delay:0.25s; }"
                                L".changelog-item:nth-child(5) { animation-delay:0.3s; }"
                                L".changelog-item:nth-child(6) { animation-delay:0.35s; }"
                                L".changelog-item:nth-child(7) { animation-delay:0.4s; }"
                                L".changelog-item:nth-child(8) { animation-delay:0.45s; }"
                                L".changelog-item:nth-child(9) { animation-delay:0.5s; }"
                                L".changelog-item:nth-child(10) { animation-delay:0.55s; }"
                                L"@keyframes slideInLeft { from { opacity:0; transform:translateX(-15px); } to { opacity:1; transform:translateX(0); } }"

                                L".launch-section { width: 340px; min-width: 340px; opacity: 0; transform: translateY(20px); animation: slideUp 0.6s ease-out 0.3s forwards; flex-shrink: 0; }"
                                L".launch-card { background: rgba(20,20,25,0.6); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 30px; display: flex; flex-direction: column; height: 100%; position: relative; overflow: hidden; min-height: 400px; }"

                                L".launch-card::before { content:''; position:absolute; top:-50%; right:-50%; width:200%; height:200%; background:radial-gradient(circle at center, rgba(102,126,234,0.08) 0%, transparent 50%); pointer-events:none; }"

                                L".user-avatar-container { display:flex; justify-content:center; margin-bottom:20px; position:relative; z-index:1; opacity:0; animation:fadeInScale 0.5s ease-out 0.3s forwards; }"
                                L".user-avatar { width:80px; height:80px; border-radius:50%; border:3px solid rgba(255,255,255,0.15); box-shadow:0 8px 25px rgba(0,0,0,0.3); object-fit:cover; transition:all 0.3s ease; }"
                                L".user-avatar:hover { transform:scale(1.05); border-color:var(--main-color); box-shadow:0 12px 35px color-mix(in srgb, var(--main-color) 40%, transparent); }"

                                L".info-grid { display:flex; flex-direction:column; gap:12px; margin-bottom:25px; margin-top:25px; flex:1; position:relative; z-index:1; }"
                                L".info-item { display:flex; justify-content:space-between; align-items:center; padding:16px 18px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); border-radius:12px; transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position:relative; overflow:hidden; opacity:0; animation:slideInRight 0.5s ease-out forwards; }"
                                L".info-item:nth-child(1) { animation-delay:0.4s; }"
                                L".info-item:nth-child(2) { animation-delay:0.5s; }"
                                L".info-item:nth-child(3) { animation-delay:0.6s; }"
                                L".info-item:nth-child(4) { animation-delay:0.7s; }"
                                L".info-item::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); opacity:0; transition:opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1); }"
                                L".info-item:hover { background:rgba(255,255,255,0.06); border-color:rgba(255,255,255,0.12); transform:translateX(-3px); }"
                                L".info-item:hover::before { opacity:1; }"
                                L".info-label { color:#999; font-size:13px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; transition:color 0.3s ease; }"
                                L".info-value { color:#fff; font-size:15px; font-weight:700; text-align:right; transition:all 0.3s ease; }"
                                L".info-item:hover .info-label { color:#bbb; }"
                                L".info-item:hover .info-value { transform:translateX(-2px); }"
                                L"@keyframes slideInRight { from { opacity:0; transform:translateX(20px); } to { opacity:1; transform:translateX(0); } }"

                                L".launch-btn { width:100%; padding:18px; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); color:#fff; border:none; border-radius:14px;"
                                L"font-size:16px; font-weight:700; cursor:pointer; transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow:0 8px 25px color-mix(in srgb, var(--main-color) 35%, transparent); margin-top:auto; position:relative; overflow:hidden; z-index:1; opacity:0; animation:fadeInScale 0.6s ease-out 0.8s forwards; }"
                                L".launch-btn::before { content:''; position:absolute; inset:0; background:linear-gradient(135deg, transparent, rgba(255,255,255,0.2)); opacity:0; transition:opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index:-1; }"
                                L".launch-btn::after { content:''; position:absolute; inset:-2px; border-radius:14px; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); opacity:0; filter:blur(15px); transition:opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index:-2; }"
                                L".launch-btn:hover::before { opacity:1; }"
                                L".launch-btn:hover::after { opacity:0.6; }"
                                L".launch-btn:hover { transform:translateY(-3px) scale(1.02); box-shadow:0 12px 35px color-mix(in srgb, var(--main-color) 50%, transparent); }"
                                L".launch-btn:active { transform:translateY(-1px) scale(0.98); transition:all 0.1s cubic-bezier(0.4, 0, 0.2, 1); }"
                                L".launch-btn:disabled { opacity:0.6; cursor:not-allowed; transform:none !important; }"
L".program-item { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 16px; background:transparent; border:1px solid rgba(255,255,255,0.15); border-radius:12px; }"
L".program-item:hover { border-color:color-mix(in srgb, var(--main-color) 45%, rgba(255,255,255,0.15)); }"
L".program-name { font-size:16px; font-weight:600; color:#fff; }"
L".everything-wrap { position:relative; }"
L".everything-menu { position:absolute; right:0; bottom:calc(100% + 8px); display:none; flex-direction:column; gap:6px; background:rgba(20,20,25,0.95); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.15); border-radius:12px; padding:8px; z-index:50; min-width:140px; }"
L".everything-menu.visible { display:flex; animation:fadeInScale 0.2s ease-out; }"
L".everything-menu button { padding:8px 14px; text-align:left; background:rgba(255,255,255,0.05); color:#fff; border:1px solid rgba(255,255,255,0.1); border-radius:8px; font-size:12px; cursor:pointer; transition:all 0.2s; white-space:nowrap; }"
L".everything-menu button:hover { background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); border-color:transparent; transform:translateX(2px); }"
L".clean-btn { padding:9px 20px; background:linear-gradient(135deg, var(--main-color), var(--secondary-color)); color:#fff; border:1px solid rgba(255,255,255,0.25); border-radius:10px;"
L"font-size:13px; font-weight:700; cursor:pointer; transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position:relative; overflow:hidden; box-shadow:0 6px 18px color-mix(in srgb, var(--main-color) 40%, transparent);"
L"min-width:120px; height:42px; display:inline-flex; align-items:center; justify-content:center; white-space:nowrap; box-sizing:border-box; }"
L".clean-btn::before { content:''; position:absolute; inset:0; background:linear-gradient(135deg, transparent, rgba(255,255,255,0.25)); opacity:0; transition:opacity 0.3s; }"
L".clean-btn:hover::before { opacity:1; }"
L".clean-btn:hover { transform:translateY(-2px); box-shadow:0 10px 25px color-mix(in srgb, var(--main-color) 55%, transparent); }"
L".clean-btn:active { transform:translateY(0) scale(0.95); }"
                                L"@keyframes fadeInScale { from { opacity:0; transform:scale(0.95); } to { opacity:1; transform:scale(1); } }"

                                L".download-overlay { position:absolute; inset:0; background:rgba(0,0,0,0); backdrop-filter:blur(0px); z-index:100; display:none; align-items:center; justify-content:center; opacity:0; transition:opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1), background 0.7s cubic-bezier(0.4, 0, 0.2, 1), backdrop-filter 0.8s cubic-bezier(0.4, 0, 0.2, 1); overflow:hidden; }"
                                L".download-overlay.show { display:flex; opacity:1; background:rgba(0,0,0,0.55); backdrop-filter:blur(20px); }"
                                L".download-overlay.success { background:rgba(34,139,34,0.25) !important; transition:background 0.5s cubic-bezier(0.4, 0, 0.2, 1); }"
                                L".overlay-snowflake { z-index:101; }"

                                L".download-content { text-align:center; width:500px; opacity:0; transform:scale(0.95) translateY(20px); transition:opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1), transform 0.6s cubic-bezier(0.4, 0, 0.2, 1); }"
                                L".download-overlay.show .download-content { opacity:1; transform:scale(1) translateY(0); transition-delay:0.2s; }"

                                L".loading-spinner { position:relative; width:80px; height:80px; margin:0 auto 30px; opacity:0; transform:scale(0.8); transition:opacity 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.3s, transform 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.3s; }"
                                L".download-overlay.show .loading-spinner { opacity:1; transform:scale(1); }"

                                L".spinner-ring { position:absolute; width:100%; height:100%; border-radius:50%; }"
                                L".spinner-ring:nth-child(1) { border:3px solid rgba(74,144,226,0.12); border-top-color:var(--main-color); animation:spin 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }"
                                L".spinner-ring:nth-child(2) { border:3px solid rgba(107,168,232,0.12); border-bottom-color:var(--secondary-color); animation:spinReverse 1.6s cubic-bezier(0.4, 0, 0.6, 1) infinite; width:70%; height:70%; top:15%; left:15%; }"
                                L".spinner-ring:nth-child(3) { width:40%; height:40%; top:30%; left:30%; background:radial-gradient(circle, var(--main-color) 0%, var(--secondary-color) 60%, transparent 80%); animation:pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; filter:blur(6px); opacity:0.4; }"

                                L"@keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }"
                                L"@keyframes spinReverse { 0% { transform:rotate(360deg); } 100% { transform:rotate(0deg); } }"
                                L"@keyframes pulse { 0%, 100% { opacity:0.4; transform:scale(1); } 50% { opacity:0.6; transform:scale(1.08); } }"

                                L".download-overlay.success .loading-spinner { animation:successScale 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) forwards; }"
                                L".download-overlay.success .spinner-ring:nth-child(1), .download-overlay.success .spinner-ring:nth-child(2) { border-color:rgba(52,199,89,0.15); border-top-color:#34c759; border-bottom-color:#34c759; animation:successSpin 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }"
                                L".download-overlay.success .spinner-ring:nth-child(3) { background:radial-gradient(circle, #34c759 0%, #5dd87f 60%, transparent 80%); animation:successPulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite; opacity:0.5; }"
                                L"@keyframes successScale { 0% { transform:scale(1); } 50% { transform:scale(1.12); } 100% { transform:scale(1); } }"
                                L"@keyframes successSpin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }"
                                L"@keyframes successPulse { 0%, 100% { opacity:0.5; transform:scale(1); } 50% { opacity:0.7; transform:scale(1.1); } }"

                                L".download-title { font-size:32px; font-weight:600; color:#fff; margin-bottom:16px; position:relative; display:inline-block; opacity:0; transform:translateY(15px); transition:opacity 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.4s, transform 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.4s, color 0.4s cubic-bezier(0.4, 0, 0.2, 1); letter-spacing:-0.02em; }"
                                L".download-overlay.show .download-title { opacity:1; transform:translateY(0); }"
                                L".download-title::after { content:''; position:absolute; bottom:-8px; left:50%; transform:translateX(-50%); width:0; height:3px; background:linear-gradient(90deg, var(--main-color), var(--secondary-color)); border-radius:2px; transition:width 0.6s cubic-bezier(0.4, 0, 0.2, 1) 0.6s, background 0.4s cubic-bezier(0.4, 0, 0.2, 1); }"
                                L".download-overlay.show .download-title::after { width:55%; }"

                                L".download-subtitle { font-size:17px; color:#bbb; margin-bottom:0; opacity:0; transform:translateY(15px); transition:opacity 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.5s, transform 0.5s cubic-bezier(0.4, 0, 0.2, 1) 0.5s, color 0.4s cubic-bezier(0.4, 0, 0.2, 1); font-weight:400; letter-spacing:0.02em; }"
                                L".download-overlay.show .download-subtitle { opacity:1; transform:translateY(0); }"

                                L".download-overlay.success .download-title { color:#34c759; }"
                                L".download-overlay.success .download-title::after { background:linear-gradient(90deg, #34c759, #5dd87f); }"
                                L".download-overlay.success .download-subtitle { color:#7ed89f; }"

                                L"@keyframes shake { 0%, 100% { transform:translateX(0); } 10%, 30%, 50%, 70%, 90% { transform:translateX(-6px); } 20%, 40%, 60%, 80% { transform:translateX(6px); } }"
                                L"@keyframes closeAnim { to { opacity:0; transform:scale(0.8) rotate(10deg); } }"
                                L"@keyframes minimizeAnim { to { opacity:0; transform:scale(0.9) translateY(20px); } }"
                                L".closing #frame { animation:closeAnim 0.3s ease-out forwards; }"
                                L".minimizing #frame { animation:minimizeAnim 0.25s ease-out forwards; }"

                                L"</style></head><body>"
                                L"<div id='frame'>"
                                L" <div id='background'></div>"
                                L" <div id='overlay'></div>"

                                L" <div id='top-bar'>"
                                L"  <div class='left' style='display:flex; align-items:center; gap:15px;'>"
                                L"   <div class='logo' style='width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center; overflow:hidden;'>"
                                L"     <span style='display:block; width:100%; height:100%; text-align:center; line-height:40px; font-size:18px; font-weight:700; color:#fff;'>P</span>"
                                L"     <img src='https://app.local/logo.png' style='width:100%; height:100%; object-fit:contain; display:none;'"
                                L"          onerror=\"this.style.display='none'; this.previousElementSibling.style.display='block'\""
                                L"          onload=\"this.style.display='block'; this.previousElementSibling.style.display='none'\">"
                                L"   </div>"
                                L"   <div class='info'>"
                                L"    <div class='name'>" << ClientInfo("name") << L"</div>"
                                L"    <div class='version'>" << ClientInfo("version") << L"</div>"
                                L"   </div>"
                                L"  </div>"
L"  <div class='right'>"
                                 L"   <div class='social-btn' id='ds-btn' title='Discord'>"
                                L"    <svg viewBox='0 0 24 24'><path d='M20.317 4.37a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.72 19.72 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.056 20.14 20.14 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.1 14.1 0 0 0 1.226-2.004.075.075 0 0 0-.041-.105 13.17 13.17 0 0 1-1.872-.877.076.076 0 0 1-.008-.125c.126-.094.253-.188.372-.286a.076.076 0 0 1 .077-.01 13.3 13.3 0 0 0 3.928 1.2 12.87 12.87 0 0 0 4.1-.001 13.3 13.3 0 0 0 3.927-1.2.076.076 0 0 1 .078.01c.12.098.245.192.372.286a.076.076 0 0 1-.007.125 13.07 13.07 0 0 1-1.873.877.076.076 0 0 0-.041.105c.36.698.774 1.354 1.226 2.004a.076.076 0 0 0 .084.028 20.14 20.14 0 0 0 6.002-3.03.077.077 0 0 0 .032-.056c.5-4.477-.838-8.01-3.548-12.66a.066.066 0 0 0-.031-.026zM8.02 15.331c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.097 2.157 2.419 0 1.334-.956 2.419-2.157 2.419zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.097 2.157 2.419 0 1.334-.946 2.419-2.157 2.419z'/></svg>"
                                L"   </div>"
                                L"   <div class='social-btn' id='tg-btn' title='Telegram'>"
                                L"    <svg viewBox='0 0 24 24'><path d='M9.78 18.65l.28-4.23 7.68-6.92c.34-.31-.07-.46-.52-.19L7.74 13.3 3.64 12c-.88-.25-.89-.86.2-1.3l15.97-6.16c.73-.33 1.43.18 1.15 1.3l-2.72 12.81c-.19.91-.74 1.13-1.5.71L12.6 16.3l-1.99 1.93c-.23.23-.42.42-.83.42z'/></svg>"
                                L"   </div>"
                                L"   <div class='social-btn' id='web-btn' title='Website'>"
                                L"    <svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'/></svg>"
                                L"   </div>"
                                L"   <div class='divider'></div>"
                                L"   <div class='window-btn' id='minimize'>"
                                L"    <svg viewBox='0 0 24 24'><path d='M19 13H5v-2h14v2z'/></svg>"
                                L"   </div>"
                                L"   <div class='window-btn' id='close'>"
                                L"    <svg viewBox='0 0 24 24'><path d='M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z'/></svg>"
                                L"   </div>"
                                L"  </div>"
L" </div>"
L""
L" <div class='main-container' id='main-container'>"
                                L"  <div class='content-wrapper'>"
                                L"   <div class='changelog-section'>"
                                L"    <div class='changelog-header'>"
L"     <div class='changelog-title'>Какие программы чистить ?</div>"
L"    </div>"
L"    <ul class='changelog-list' id='program-list'>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>CachedProgramsList &amp; LastActivityView &amp; Executed Programslist</span>"
L"       <button class='clean-btn' onclick='runProgram(\"CachedProgramsList\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>Journal Trace</span>"
L"       <button class='clean-btn' onclick='runProgram(\"Journal Trace\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>NvidiaPanel</span>"
L"       <button class='clean-btn' onclick='runProgram(\"Nvidia\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>USBDriveLog</span>"
L"       <button class='clean-btn' onclick='runProgram(\"USBDriveLog\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>WinPrefetchView</span>"
L"       <button class='clean-btn' onclick='runProgram(\"WinPrefetchView\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>Shellbag</span>"
L"       <button class='clean-btn' onclick='runOpen(\"Shellbag\")'>Открыть</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>Службы</span>"
L"       <button class='clean-btn' onclick='runProgram(\"Services\")'>Включить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>Чистка Win + R</span>"
L"       <button class='clean-btn' onclick='runProgram(\"WinR\")'>Очистить</button>"
L"      </div>"
L"     </li>"
L"     <li style='list-style:none; padding:0;'>"
L"      <div class='program-item'>"
L"       <span class='program-name'>Everything</span>"
L"       <div class='everything-wrap'>"
L"        <button class='clean-btn' onclick='toggleEverythingMenu(event)'>Искать</button>"
L"        <div class='everything-menu' id='everything-menu'>"
L"         <button onclick='runEverything(1)'>Текст 1</button>"
L"         <button onclick='runEverything(2)'>Текст 2</button>"
L"         <button onclick='runEverything(3)'>Текст 3</button>"
L"         <button onclick='runEverything(4)'>Текст 4</button>"
L"         <button onclick='runEverything(5)'>Текст 5</button>"
L"        </div>"
L"       </div>"
L"      </div>"
L"     </li>"
L"    </ul>"
                                L"   </div>"
                                L"   <div class='launch-section'>"
                                L"    <div class='launch-card'>"
                                L"     <div class='user-avatar-container'>"
                                L"      <img class='user-avatar' id='user-avatar' src='https://i.pinimg.com/736x/c8/5f/7f/c85f7f588b87e38a88c01faba969135d.jpg' alt='Avatar'>"
                                L"     </div>"
                                L"     <div class='info-grid'>"
                                L"      <div class='info-item'>"
                                L"       <span class='info-label'>Логин</span>"
                                L"       <span class='info-value' data-user='login'>—</span>"
                                L"      </div>"
                                L"      <div class='info-item'>"
                                L"       <span class='info-label'>UID</span>"
                                L"       <span class='info-value' data-user='uid'>—</span>"
                                L"      </div>"
                                L"      <div class='info-item'>"
                                L"       <span class='info-label'>Роль</span>"
                                L"       <span class='info-value' data-user='role'>—</span>"
                                L"      </div>"
                                L"      <div class='info-item'>"
                                L"       <span class='info-label'>Подписка</span>"
                                L"       <span class='info-value' data-user='subscription'>—</span>"
                                L"      </div>"
                                L"     </div>"
                                L"     <button class='launch-btn' onclick='launchClient()'>✨ Очистить все</button>"
                                L"    </div>"
                                L"   </div>"
                                L"  </div>"
                                L" </div>"

                                L" <div class='download-overlay' id='download-overlay' onmousedown='handleOverlayDrag(event)'>"
                                L"  <div class='download-content'>"
                                L"   <div class='loading-spinner'>"
                                L"    <div class='spinner-ring'></div>"
                                L"    <div class='spinner-ring'></div>"
                                L"    <div class='spinner-ring'></div>"
                                L"   </div>"
                                L"   <div class='download-title'>Установка клиента</div>"
                                L"   <div class='download-subtitle' id='download-status'>Пожалуйста, подождите...</div>"
                                L"  </div>"
                                L" </div>"

                                L"</div>"

                                L"<script>"
L"const mainContainer = document.getElementById('main-container');"
L"const downloadOverlay = document.getElementById('download-overlay');"
L"const downloadStatus = document.getElementById('download-status');"
L""
L"mainContainer.classList.add('show');"
L"document.querySelector('[data-user=\"login\"]').textContent = 'Гость';"
L"document.querySelector('[data-user=\"uid\"]').textContent = '1';"
L"document.querySelector('[data-user=\"role\"]').textContent = 'Пользователь';"
L"document.querySelector('[data-user=\"subscription\"]').textContent = 'Бессрочно';"
                                L""
                                L"document.getElementById('close').addEventListener('click', () => {"
                                L"  document.body.classList.add('closing');"
                                L"  setTimeout(() => window.chrome.webview.postMessage('close'), 300);"
                                L"});"
                                L"document.getElementById('minimize').addEventListener('click', () => {"
                                L"  document.body.classList.add('minimizing');"
                                L"  setTimeout(() => {"
                                L"    window.chrome.webview.postMessage('minimize');"
                                L"    document.body.classList.remove('minimizing');"
                                L"  }, 250);"
                                L"});"
                                L"document.getElementById('top-bar').addEventListener('mousedown', (e) => {"
                                L"  const isLeft = e.button === 0;"
                                L"  const inRight = e.target.closest('.right');"
                                L"  if (isLeft && !inRight) { window.chrome.webview.postMessage('drag'); }"
                                L"});"

L"document.getElementById('web-btn').addEventListener('click', () => window.chrome.webview.postMessage('web'));"
L"document.getElementById('tg-btn').addEventListener('click', () => window.chrome.webview.postMessage('telegram'));"
L"document.getElementById('ds-btn').addEventListener('click', () => window.chrome.webview.postMessage('discord'));"

L"function updateDownloadStatus(text) {"
                                L"  downloadStatus.textContent = text;"
                                L"}"

                                L"function hideDownloadOverlay() {"
                                L"  downloadOverlay.classList.remove('show', 'success');"
                                L"  setTimeout(() => {"
L"    document.querySelector('.download-title').textContent = 'Установка клиента';"
                                 L"    downloadStatus.textContent = 'Пожалуйста, подождите...';"
                                L"  }, 400);"
                                L"}"

                                L"function hideLaunchOverlay() {"
                                L"  downloadOverlay.classList.remove('show');"
                                L"}"

                                L"function startDownload() {"
                                L"  downloadOverlay.classList.remove('success');"
                                L"  downloadOverlay.classList.add('show');"
L"  document.querySelector('.download-title').textContent = 'Установка клиента';"
                                 L"  updateDownloadStatus('Начинаем установку...');"
                                L"  window.chrome.webview.postMessage('install');"
                                L"}"

                                L"function startLaunch() {"
                                L"  if (!downloadOverlay) return;"
                                L"  downloadOverlay.classList.remove('success');"
                                L"  downloadOverlay.classList.add('show');"
                                L"  const titleEl = document.querySelector('.download-title');"
L"  if (titleEl) titleEl.textContent = 'Запуск';"
                                 L"  updateDownloadStatus('Подготовка...');"
                                L"}"

                                L"function showInstallSuccess() {"
                                L"  downloadOverlay.classList.add('success');"
L"  document.querySelector('.download-title').textContent = '✓ Успешная установка!';"
                                 L"  downloadStatus.textContent = 'Автоматический запуск...';"
                                L"}"

                                L"function updateLaunchStatus(text) {"
                                L"  downloadStatus.textContent = text;"
                                L"}"

                                L"function fetchChangelog() {"
                                L"  window.chrome.webview.postMessage('fetch_changelog');"
                                L"}"

                                L"function parseChangelog(text) {"
                                L"  const lines = text.split('\\n').filter(line => line.trim());"
                                L"  let date = 'Неизвестно';"
                                L"  const changes = [];"
                                L"  "
                                L"  lines.forEach(line => {"
                                L"    if (line.startsWith('#date=')) {"
                                L"      date = line.replace('#date=', '').trim();"
                                L"    } else if (line.trim().length > 0 && !line.startsWith('#')) {"
                                L"      changes.push(line.trim());"
                                L"    }"
                                L"  });"
                                L"  "
                                L"  document.getElementById('changelog-date').textContent = date;"
                                L"  "
                                L"  const list = document.getElementById('changelog-list');"
                                L"  list.innerHTML = '';"
                                L"  "
                                L"  if (changes.length === 0) {"
                                L"    list.innerHTML = '<li class=\"changelog-item\"><span class=\"changelog-icon\">❌</span><span class=\"changelog-text\">Не удалось получить последнее обновление</span></li>';"
                                L"    return;"
                                L"  }"
                                L"  "
                                L"  changes.forEach((change, i) => {"
                                L"    const li = document.createElement('li');"
                                L"    li.className = 'changelog-item';"
                                L"    li.style.animationDelay = (i * 0.05) + 's';"
                                L"    const icon = document.createElement('span');"
                                L"    icon.className = 'changelog-icon';"
                                L"    icon.textContent = getIcon(i);"
                                L"    const text = document.createElement('span');"
                                L"    text.className = 'changelog-text';"
                                L"    text.textContent = change;"
                                L"    li.appendChild(icon);"
                                L"    li.appendChild(text);"
                                L"    list.appendChild(li);"
                                L"  });"
                                L"}"

                                L"function getIcon(index) {"
                                L"  const icons = ['✨', '🚀', '🎨', '🔐', '⚡', '🐛', '🎮', '📊', '🔧', '💾', '🌟', '💡', '🔥', '📱', '🎯'];"
                                L"  return icons[index % icons.length];"
                                L"}"

L"function launchClient() {"
L"  window.chrome.webview.postMessage('clean_all');"
L"}"
L""
L"let cleanAllToastReady = false;"
L"function makeAllCleanToast() {"
L"  if (cleanAllToastReady) return document.getElementById('clean-all-toast');"
L"  const toast = document.createElement('div');"
L"  toast.id = 'clean-all-toast';"
L"  toast.style.cssText = 'position:fixed; top:20px; left:20px; z-index:9999; display:flex; align-items:center; gap:10px; background:rgba(20,30,20,0.95); border:1px solid rgba(52,199,89,0.6); border-radius:14px; padding:14px 20px; color:#fff; font-size:15px; font-weight:700; box-shadow:0 10px 30px rgba(0,0,0,0.5); opacity:0; transform:translateY(-15px); transition:all 0.4s ease; pointer-events:none;';"
L"  const check = document.createElement('span');"
L"  check.style.cssText = 'width:26px; height:26px; border-radius:50%; background:linear-gradient(135deg,#34c759,#28a745); display:flex; align-items:center; justify-content:center; font-size:15px; color:#fff; box-shadow:0 0 15px rgba(52,199,89,0.6);';"
L"  check.textContent = '✓';"
L"  const text = document.createElement('span');"
L"  text.id = 'clean-all-toast-text';"
                                 L"  text.textContent = 'Готово';"
L"  toast.appendChild(check);"
L"  toast.appendChild(text);"
L"  document.body.appendChild(toast);"
L"  cleanAllToastReady = true;"
L"  return toast;"
L"}"
L""
L"function cleanAllStart() {}"
L""
L"function CleaningAllDone() {"
L"  const toast = makeAllCleanToast();"
L"  toast.style.opacity = '1';"
L"  toast.style.transform = 'translateY(0)';"
L"  toast.querySelector('#clean-all-toast-text').textContent = 'Готово';"
L"  clearTimeout(CleaningAllDone._t);"
L"  CleaningAllDone._t = setTimeout(() => {"
L"    toast.style.opacity = '0';"
L"    toast.style.transform = 'translateY(-15px)';"
L"  }, 5000);"
L"}"
L""
L"function runProgram(name) {"
L"  window.chrome.webview.postMessage('clean:' + name);"
L"}"
L""
L"function runOpen(name) {"
L"  window.chrome.webview.postMessage('open:' + name);"
L"}"
L""
L"function runEverything(n) {"
L"  document.getElementById('everything-menu').classList.remove('visible');"
L"  window.chrome.webview.postMessage('everything:' + n);"
L"}"
L""
L"function toggleEverythingMenu(e) {"
L"  e.stopPropagation();"
L"  document.getElementById('everything-menu').classList.toggle('visible');"
L"}"
L""
L"document.addEventListener('click', (e) => {"
L"  const menu = document.getElementById('everything-menu');"
L"  if (menu && !e.target.closest('.everything-wrap')) menu.classList.remove('visible');"
L"});"

                                L"function handleOverlayDrag(e) {"
L"  if (e.button === 0 && !e.target.closest('.download-content')) {"
L"    window.chrome.webview.postMessage('drag');"
L"  }"
L"}"

                                L"if ('" << ClientInfo("snow") << L"' === 'true') {"
                                L"  const frame = document.getElementById('frame');"
                                L"  const flakes = ['❄','❅','❆','❉','❋','✻','✽','❊','❋','❅'];"
                                L"  let snowCreated = false;"
                                L"  "
                                L"  function createSnow(container, count, className = 'snowflake') {"
                                L"    for (let i = 0; i < count; i++) {"
                                L"      const f = document.createElement('div');"
                                L"      f.className = className;"
                                L"      f.textContent = flakes[Math.floor(Math.random() * flakes.length)];"
                                L"      const size = Math.random() * 16 + 10 + 'px';"
                                L"      const duration = Math.random() * 15 + 10 + 's';"
                                L"      const delay = Math.random() * 10 + 's';"
                                L"      const left = Math.random() * 100 + 'vw';"
                                L"      const opacity = Math.random() * 0.6 + 0.4;"
                                L"      f.style.cssText = `position:absolute;color:#fff;font-size:${size};opacity:${opacity};left:${left};top:-30px;pointer-events:none;animation:snowfall ${duration} linear infinite ${delay};filter:drop-shadow(0 0 10px rgba(255,255,255,0.7));user-select:none;z-index:1000;`;"
                                L"      container.appendChild(f);"
                                L"    }"
                                L"  }"
                                L"  "
                                L"  if (!snowCreated) {"
                                L"    createSnow(frame, 50);"
                                L"    snowCreated = true;"
                                L"  }"
L"}"
                                
                                L""
                                L"</script></body></html>";

                            g_webView->NavigateToString(html.str().c_str());
                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());
}

void ResizeWebView() {
    if (g_controller) {
        RECT r;
        GetClientRect(g_hWnd, &r);
        g_controller->put_Bounds(r);
    }
}

std::wstring ClientInfo(const std::string& key) {
    if (key == "name") return L"Cleaner";
    if (key == "version") return L"Beta 0.0.1";
    if (key == "web") return L"https://t.me/xatavanekfame";
    if (key == "tg") return L"telegram.me/bestclleaner";
    if (key == "ds") return L"https://discord.gg/HjEzTF9tB";
    if (key == "color1") return L"rgb(66, 103, 178)"; // хуйня 1
    if (key == "color2") return L"rgb(38, 66, 148)"; // хуйня 2
    if (key == "changelog") return L"https://yougamecorm.ru/launcher/changelog.txt";
    if (key == "changelog-path") return L"/launcher/changelog.txt";
    if (key == "version-url") return L"https://yougamecorm.ru/launcher/version.txt"; // хз работает ли
    if (key == "version-path") return L"/launcher/version.txt";
    if (key == "api") return OBFSTR("https://yougamecorm.ru/api/loader.php");
    if (key == "host") return OBFSTR("yougamecorm.ru");
    if (key == "admin_key") return OBFSTR("lalala");
    if (key == "api-bind-hwid") return OBFSTR("https://yougamecorm.ru/api/bind_hwid.php");
    if (key == "snow") return L"true"; /// Залупа кстати ебаная отключайте..
    return L"Unknown";
}

void SaveToken(const std::wstring& token) {
}

std::wstring LoadToken() {
    return L"";
}

void ClearToken() {
}

void SaveCredentials(const std::wstring& login, const std::wstring& password) {
}

std::pair<std::wstring, std::wstring> LoadCredentials() {
    return { L"", L"" };
}



void SendToWebView(const std::wstring& js) {
    if (g_webView) {
        std::wstring* jsPtr = new std::wstring(js);
        PostMessage(g_hWnd, WM_USER + 1, 0, reinterpret_cast<LPARAM>(jsPtr));
    }
}

std::vector<std::wstring> Split(const std::wstring& s, wchar_t delim) {
    std::vector<std::wstring> result;
    std::wstringstream ss(s);
    std::wstring item;
    while (std::getline(ss, item, delim)) result.push_back(item);
    return result;
}
