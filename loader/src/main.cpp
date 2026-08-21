#define WIN32_LEAN_AND_MEAN
#define WM_APP_REFRESH (WM_APP + 1)
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objidl.h>
#pragma comment(lib, "ole32.lib")
#include <string>
#include <thread>
#include <vector>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <psapi.h>
#include <gdiplus.h>
#include "cs2_embed.hpp"
#include "logo_embed.hpp"
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;
#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "msimg32.lib")

// ===== configure for your VPS / domain =====
static const wchar_t* k_api_host = L"phantomauth-khc4.onrender.com";
static const INTERNET_PORT k_api_port = 443;
static const bool k_api_https = true;
// ===========================================

static constexpr int k_wait_seconds = 45;
static constexpr int k_win_w = 440;
static constexpr int k_win_h = 460;

enum class Page { Login, Verify, Main };

struct App {
    HWND hwnd{};
    Page page{ Page::Login };
    std::wstring email, password, license;
    bool remember{ true };
    bool busy{ false };
    int focus{ 1 }; // 1 email, 2 password, 3 license
    std::wstring status{ L"Sign in to continue" };
    std::wstring token;
    std::wstring userName, role, expires;
    float progress{ 0.f };
    Image* logo{};
    Image* cs2{};
    ULONG_PTR gdiplusToken{};
    HICON hIcon{};
    HICON hIconSm{};
    HFONT fontTitle{}, fontBody{}, fontSmall{}, fontBtn{}, fontLabel{};
};

static App g{};

static std::wstring exe_dir() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf);
    auto pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : p.substr(0, pos);
}

// writable for every Windows user (Downloads folder is fine; Program Files is not)
static std::wstring data_dir() {
    wchar_t* appdata = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &appdata)) && appdata) {
        dir = std::wstring(appdata) + L"\\Phantom";
        CoTaskMemFree(appdata);
    } else {
        dir = exe_dir();
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}
static std::wstring cred_path() { return data_dir() + L"\\phantom.session"; }



static void save_session() {
    if (!g.remember) {
        DeleteFileW(cred_path().c_str());
        DeleteFileW((exe_dir() + L"\\phantom.session").c_str());
        return;
    }
    // plain UTF-8 lines: email / password / token / user / role / expires
    auto to_utf8 = [](const std::wstring& w) -> std::string {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (n <= 1) return {};
        std::string s((size_t)n - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
        return s;
    };
    std::string body;
    body += to_utf8(g.email); body.push_back('\n');
    body += to_utf8(g.password); body.push_back('\n');
    body += to_utf8(g.token); body.push_back('\n');
    body += to_utf8(g.userName); body.push_back('\n');
    body += to_utf8(g.role); body.push_back('\n');
    body += to_utf8(g.expires); body.push_back('\n');
    // light obfuscation
    for (auto& c : body) c = (char)((unsigned char)c ^ 0x5A);

    std::wstring wpath = cred_path();
    FILE* fp = nullptr;
    _wfopen_s(&fp, wpath.c_str(), L"wb");
    if (!fp) return;
    const char magic[] = "PHM2";
    fwrite(magic, 1, 4, fp);
    fwrite(body.data(), 1, body.size(), fp);
    fclose(fp);
}

static bool load_session() {
    g.email.clear();
    g.password.clear();
    g.token.clear();
    g.userName.clear();
    g.role.clear();
    g.expires.clear();

    std::wstring paths[2] = { cred_path(), exe_dir() + L"\\phantom.session" };
    std::string raw;
    for (auto& wpath : paths) {
        FILE* fp = nullptr;
        _wfopen_s(&fp, wpath.c_str(), L"rb");
        if (!fp) continue;
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (sz <= 0 || sz > 64 * 1024) { fclose(fp); continue; }
        raw.assign((size_t)sz, '\0');
        fread(raw.data(), 1, (size_t)sz, fp);
        fclose(fp);
        break;
    }
    if (raw.empty()) return false;

    auto from_utf8 = [](const std::string& s) -> std::wstring {
        if (s.empty()) return {};
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (n <= 0) return {};
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
        return w;
    };

    // new format PHM2
    if (raw.size() >= 4 && raw[0] == 'P' && raw[1] == 'H' && raw[2] == 'M' && raw[3] == '2') {
        std::string body = raw.substr(4);
        for (auto& c : body) c = (char)((unsigned char)c ^ 0x5A);
        std::string fields[6];
        size_t start = 0, fi = 0;
        for (size_t i = 0; i < body.size() && fi < 6; ++i) {
            if (body[i] == '\n') {
                fields[fi++] = body.substr(start, i - start);
                start = i + 1;
            }
        }
        if (fi < 6 && start < body.size()) fields[fi++] = body.substr(start);
        g.email = from_utf8(fields[0]);
        g.password = from_utf8(fields[1]);
        g.token = from_utf8(fields[2]);
        g.userName = from_utf8(fields[3]);
        g.role = from_utf8(fields[4]);
        g.expires = from_utf8(fields[5]);
        g.remember = true;
        return !g.email.empty() || !g.password.empty();
    }

    // corrupt/legacy — ignore so fields stay clean
    DeleteFileW(cred_path().c_str());
    DeleteFileW((exe_dir() + L"\\phantom.session").c_str());
    return false;
}

static std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}
static std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

struct HttpResult { int status{ 0 }; std::string body; std::vector<uint8_t> bin; };

static HttpResult http_request(const wchar_t* method, const wchar_t* path, const std::string& body, const std::wstring& bearer, bool binary) {
    HttpResult r;
    HINTERNET ses = WinHttpOpen(L"PhantomLoader/1.2", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return r;
    DWORD t_resolve = 60000, t_connect = 60000, t_send = 120000, t_recv = 180000;
    WinHttpSetTimeouts(ses, t_resolve, t_connect, t_send, t_recv);
    HINTERNET con = WinHttpConnect(ses, k_api_host, k_api_port, 0);
    if (!con) { WinHttpCloseHandle(ses); return r; }
    DWORD flags = k_api_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(con, method, path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return r; }
    if (k_api_https) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }
    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearer.empty()) headers += L"Authorization: Bearer " + bearer + L"\r\n";
    BOOL ok = WinHttpSendRequest(req, headers.c_str(), (DWORD)-1,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(req, nullptr);
    if (!ok) {
        r.status = -(int)GetLastError();
        WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
        return r;
    }
    DWORD code = 0, codeSize = sizeof(code);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeSize, WINHTTP_NO_HEADER_INDEX);
    r.status = (int)code;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail) || !avail) break;
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, buf.data(), avail, &read) || !read) break;
        if (binary) r.bin.insert(r.bin.end(), buf.begin(), buf.begin() + read);
        else r.body.append(buf.data(), read);
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return r;
}

static std::string json_get_string(const std::string& j, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    auto p = j.find(pat);
    if (p == std::string::npos) return {};
    p = j.find(':', p); if (p == std::string::npos) return {};
    p = j.find('"', p); if (p == std::string::npos) return {};
    auto e = j.find('"', p + 1); if (e == std::string::npos) return {};
    return j.substr(p + 1, e - p - 1);
}

static void set_status(const std::wstring& s) {
    g.status = s;
    if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
}

static DWORD find_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void enable_debug_privilege() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    TOKEN_PRIVILEGES tp{};
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(token);
}



static bool read_file_bytes(const std::wstring& path, std::vector<uint8_t>& out) {
    FILE* fp = nullptr;
    _wfopen_s(&fp, path.c_str(), L"rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return false; }
    out.resize((size_t)sz);
    fread(out.data(), 1, out.size(), fp);
    fclose(fp);
    return true;
}

static HMODULE remote_get_module(HANDLE hProc, const char* name) {
    HMODULE mods[1024]{};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_64BIT))
        return nullptr;
    char baseName[MAX_PATH]{};
    const size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        if (!GetModuleBaseNameA(hProc, mods[i], baseName, MAX_PATH)) continue;
        if (_stricmp(baseName, name) == 0) return mods[i];
    }
    return nullptr;
}


static HMODULE remote_load_library(HANDLE hProc, const char* name) {
    HMODULE existing = remote_get_module(hProc, name);
    if (existing) return existing;
    // allocate name in remote and LoadLibraryA
    size_t len = strlen(name) + 1;
    void* remoteName = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteName) return nullptr;
    WriteProcessMemory(hProc, remoteName, name, len, nullptr);
    auto load = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, load, remoteName, 0, nullptr);
    if (!th) { VirtualFreeEx(hProc, remoteName, 0, MEM_RELEASE); return nullptr; }
    WaitForSingleObject(th, 15000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    VirtualFreeEx(hProc, remoteName, 0, MEM_RELEASE);
    return remote_get_module(hProc, name);
}

static FARPROC remote_get_proc(HANDLE hProc, HMODULE remoteMod, const char* exportName) {
    BYTE headers[0x1000]{};
    SIZE_T readn = 0;
    if (!ReadProcessMemory(hProc, remoteMod, headers, sizeof(headers), &readn)) return nullptr;
    auto* dos = (IMAGE_DOS_HEADER*)headers;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (IMAGE_NT_HEADERS64*)(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) return nullptr;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadProcessMemory(hProc, (BYTE*)remoteMod + expDir.VirtualAddress, &exp, sizeof(exp), &readn))
        return nullptr;

    std::vector<DWORD> names(exp.NumberOfNames);
    std::vector<DWORD> funcs(exp.NumberOfFunctions);
    std::vector<WORD> ords(exp.NumberOfNames);
    if (exp.NumberOfNames)
        ReadProcessMemory(hProc, (BYTE*)remoteMod + exp.AddressOfNames, names.data(), names.size() * 4, &readn);
    if (exp.NumberOfFunctions)
        ReadProcessMemory(hProc, (BYTE*)remoteMod + exp.AddressOfFunctions, funcs.data(), funcs.size() * 4, &readn);
    if (exp.NumberOfNames)
        ReadProcessMemory(hProc, (BYTE*)remoteMod + exp.AddressOfNameOrdinals, ords.data(), ords.size() * 2, &readn);

    DWORD funcRva = 0;
    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char nameBuf[256]{};
        ReadProcessMemory(hProc, (BYTE*)remoteMod + names[i], nameBuf, sizeof(nameBuf) - 1, &readn);
        if (strcmp(nameBuf, exportName) == 0) {
            WORD ord = ords[i];
            if (ord < exp.NumberOfFunctions) funcRva = funcs[ord];
            break;
        }
    }
    if (!funcRva) return nullptr;

    // Forwarded export if RVA falls inside export directory
    if (funcRva >= expDir.VirtualAddress && funcRva < expDir.VirtualAddress + expDir.Size) {
        char forward[256]{};
        ReadProcessMemory(hProc, (BYTE*)remoteMod + funcRva, forward, sizeof(forward) - 1, &readn);
        // format: MODULE.Function or MODULE.#ordinal
        char* dot = strchr(forward, '.');
        if (!dot) return nullptr;
        *dot = 0;
        char modFile[260]{};
        snprintf(modFile, sizeof(modFile), "%s.dll", forward);
        HMODULE fwd = remote_load_library(hProc, modFile);
        if (!fwd) return nullptr;
        if (dot[1] == '#')
            return nullptr; // ordinal forward rare
        return remote_get_proc(hProc, fwd, dot + 1);
    }
    return (FARPROC)((BYTE*)remoteMod + funcRva);
}


static void apply_relocations(BYTE* image, ULONG_PTR remoteBase, IMAGE_NT_HEADERS64* nt) {
    ULONG_PTR delta = remoteBase - nt->OptionalHeader.ImageBase;
    if (!delta) return;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.Size) return;
    auto* reloc = (IMAGE_BASE_RELOCATION*)(image + dir.VirtualAddress);
    while (reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)(reloc + 1);
        for (DWORD i = 0; i < count; ++i) {
            int type = list[i] >> 12;
            int off = list[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                auto* p = (ULONG_PTR*)(image + reloc->VirtualAddress + off);
                *p += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                auto* p = (DWORD*)(image + reloc->VirtualAddress + off);
                *p += (DWORD)delta;
            }
        }
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}





static std::wstring g_import_fail;

static bool resolve_imports_remote(HANDLE hProc, ULONG_PTR remoteBase, BYTE* localImage, IMAGE_NT_HEADERS64* nt) {
    g_import_fail.clear();
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.Size) return true;

    auto basename = [](const char* p) -> std::string {
        const char* b = p;
        for (const char* q = p; *q; ++q)
            if (*q == '/' || *q == '\\\\') b = q + 1;
        return std::string(b);
    };

    auto try_remote_mod = [&](const std::string& name) -> HMODULE {
        if (name.empty()) return nullptr;
        HMODULE m = remote_load_library(hProc, name.c_str());
        if (m) return m;
        // without .dll
        if (name.size() > 4 && _stricmp(name.c_str() + name.size() - 4, ".dll") == 0) {
            std::string n2 = name.substr(0, name.size() - 4);
            m = remote_load_library(hProc, n2.c_str());
        }
        return m;
    };

    auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + dir.VirtualAddress);
    while (imp->Name) {
        std::string modName = basename((char*)(localImage + imp->Name));
        HMODULE remoteMod = try_remote_mod(modName);

        if (!remoteMod) {
            HMODULE loc = LoadLibraryExA(modName.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
            if (!loc) loc = LoadLibraryExA(modName.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!loc) loc = LoadLibraryA(modName.c_str());
            if (loc) {
                char path[MAX_PATH]{};
                GetModuleFileNameA(loc, path, MAX_PATH);
                remoteMod = try_remote_mod(basename(path));
            }
        }
        if (!remoteMod) {
            // common api-set redirects
            const char* alias = nullptr;
            if (modName.rfind("api-ms-win-crt", 0) == 0) alias = "ucrtbase.dll";
            else if (modName.rfind("api-ms-win-core-file", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-synch", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-memory", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-libraryloader", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-processthreads", 0) == 0) alias = "kernel32.dll";
            else if (modName.rfind("api-ms-win-core-handle", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-errorhandling", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-string", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-sysinfo", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-debug", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-profile", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-localization", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-core-registry", 0) == 0) alias = "advapi32.dll";
            else if (modName.rfind("api-ms-win-core-processthreads", 0) == 0) alias = "kernel32.dll";
            else if (modName.rfind("api-ms-win-core-", 0) == 0) alias = "kernelbase.dll";
            else if (modName.rfind("api-ms-win-", 0) == 0) alias = "kernel32.dll";
            else if (modName.rfind("VCRUNTIME", 0) == 0 || modName.rfind("vcruntime", 0) == 0) alias = "vcruntime140.dll";
            else if (modName.rfind("MSVCP", 0) == 0 || modName.rfind("msvcp", 0) == 0) alias = "msvcp140.dll";
            if (alias) remoteMod = try_remote_mod(alias);
        }
        if (!remoteMod) {
            g_import_fail = L"module " + std::wstring(modName.begin(), modName.end());
            return false;
        }

        DWORD oft = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        DWORD ft = imp->FirstThunk;
        for (DWORD i = 0; ; ++i) {
            auto* localThunk = (IMAGE_THUNK_DATA64*)(localImage + oft + i * sizeof(IMAGE_THUNK_DATA64));
            if (!localThunk->u1.AddressOfData) break;
            ULONG_PTR funcAddr = remoteBase + ft + i * sizeof(IMAGE_THUNK_DATA64);

            FARPROC addr = nullptr;
            std::string expDbg;
            if (IMAGE_SNAP_BY_ORDINAL64(localThunk->u1.Ordinal)) {
                HMODULE loc = LoadLibraryA(modName.c_str());
                if (loc) {
                    FARPROC lf = GetProcAddress(loc, (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL64(localThunk->u1.Ordinal));
                    if (lf) {
                        MODULEINFO mi{};
                        if (GetModuleInformation(GetCurrentProcess(), loc, &mi, sizeof(mi))) {
                            HMODULE owner = loc;
                            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)lf, &owner);
                            char op[MAX_PATH]{}; GetModuleFileNameA(owner, op, MAX_PATH);
                            HMODULE ro = try_remote_mod(basename(op));
                            if (!ro) ro = remoteMod;
                            MODULEINFO omi{};
                            if (GetModuleInformation(GetCurrentProcess(), owner, &omi, sizeof(omi)))
                                addr = (FARPROC)((BYTE*)ro + ((BYTE*)lf - (BYTE*)omi.lpBaseOfDll));
                        }
                    }
                }
                expDbg = "#" + std::to_string((int)IMAGE_ORDINAL64(localThunk->u1.Ordinal));
            } else {
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)(localImage + localThunk->u1.AddressOfData);
                const char* expName = (const char*)ibn->Name;
                expDbg = expName;
                addr = remote_get_proc(hProc, remoteMod, expName);
                if (!addr) {
                    HMODULE loc = LoadLibraryExA(modName.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                    if (!loc) loc = LoadLibraryA(modName.c_str());
                    if (loc) {
                        FARPROC lf = GetProcAddress(loc, expName);
                        if (lf) {
                            HMODULE owner = nullptr;
                            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)lf, &owner);
                            if (!owner) owner = loc;
                            char op[MAX_PATH]{}; GetModuleFileNameA(owner, op, MAX_PATH);
                            HMODULE ro = try_remote_mod(basename(op));
                            if (!ro) ro = remoteMod;
                            MODULEINFO mi{};
                            if (GetModuleInformation(GetCurrentProcess(), owner, &mi, sizeof(mi)))
                                addr = (FARPROC)((BYTE*)ro + ((BYTE*)lf - (BYTE*)mi.lpBaseOfDll));
                        }
                    }
                }
            }
            if (!addr) {
                std::wstring wmod(modName.begin(), modName.end());
                std::wstring wexp(expDbg.begin(), expDbg.end());
                g_import_fail = wmod + L"!" + wexp;
                return false;
            }
            ULONGLONG val = (ULONGLONG)addr;
            if (!WriteProcessMemory(hProc, (void*)funcAddr, &val, sizeof(val), nullptr)) {
                g_import_fail = L"WPM IAT";
                return false;
            }
        }
        ++imp;
    }
    return true;
}

static std::wstring inject_dll_manual(DWORD pid, const std::wstring& dllPath) {
    std::vector<uint8_t> file;
    if (!read_file_bytes(dllPath, file) || file.size() < sizeof(IMAGE_DOS_HEADER))
        return L"Cannot read module file";

    auto* dos = (IMAGE_DOS_HEADER*)file.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return L"Invalid DOS signature";
    auto* ntFile = (IMAGE_NT_HEADERS64*)(file.data() + dos->e_lfanew);
    if (ntFile->Signature != IMAGE_NT_SIGNATURE) return L"Invalid NT signature";
    if (ntFile->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return L"DLL must be x64";

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"OpenProcess failed — run as Admin";

    SIZE_T imageSize = ntFile->OptionalHeader.SizeOfImage;
    void* remoteBase = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) { CloseHandle(hProc); return L"VirtualAllocEx failed"; }

    std::vector<uint8_t> image(imageSize, 0);
    memcpy(image.data(), file.data(), ((size_t)ntFile->OptionalHeader.SizeOfHeaders < imageSize) ? (size_t)ntFile->OptionalHeader.SizeOfHeaders : imageSize);
    auto* sec = IMAGE_FIRST_SECTION(ntFile);
    for (WORD i = 0; i < ntFile->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        if ((size_t)sec->VirtualAddress + sec->SizeOfRawData > imageSize) continue;
        memcpy(image.data() + sec->VirtualAddress, file.data() + sec->PointerToRawData, sec->SizeOfRawData);
    }

    auto* nt = (IMAGE_NT_HEADERS64*)(image.data() + ((IMAGE_DOS_HEADER*)image.data())->e_lfanew);
    apply_relocations(image.data(), (ULONG_PTR)remoteBase, nt);

    // Write image first (IAT zeros), then patch IAT in remote
    if (!WriteProcessMemory(hProc, remoteBase, image.data(), imageSize, nullptr)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"Write image failed";
    }
    FlushInstructionCache(hProc, remoteBase, imageSize);

    if (!resolve_imports_remote(hProc, (ULONG_PTR)remoteBase, image.data(), nt)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"Import: " + (g_import_fail.empty() ? L"unknown" : g_import_fail);
    }

    ULONG_PTR entry = (ULONG_PTR)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;
    BYTE sc[64];
    size_t n = 0;
    auto emit = [&](std::initializer_list<BYTE> b) { for (BYTE x : b) sc[n++] = x; };
    emit({ 0x48, 0x83, 0xEC, 0x28 });
    emit({ 0x48, 0xB9 });
    ULONG_PTR base = (ULONG_PTR)remoteBase;
    memcpy(sc + n, &base, 8); n += 8;
    emit({ 0xBA, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x45, 0x31, 0xC0 });
    emit({ 0x48, 0xB8 });
    memcpy(sc + n, &entry, 8); n += 8;
    emit({ 0xFF, 0xD0 });
    emit({ 0x48, 0x83, 0xC4, 0x28 });
    emit({ 0xC3 });

    void* remoteSc = VirtualAllocEx(hProc, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteSc) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"Stub alloc failed";
    }
    WriteProcessMemory(hProc, remoteSc, sc, n, nullptr);

    HANDLE th = nullptr;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    using NtCTE_t = LONG (NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    auto NtCTE = ntdll ? (NtCTE_t)GetProcAddress(ntdll, "NtCreateThreadEx") : nullptr;
    if (NtCTE) {
        if (NtCTE(&th, 0x1FFFFF, nullptr, hProc, remoteSc, nullptr, 0, 0, 0, 0, nullptr) < 0)
            th = nullptr;
    }
    if (!th) th = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteSc, nullptr, 0, nullptr);
    if (!th) {
        VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"Thread create failed";
    }
    WaitForSingleObject(th, 120000);
    CloseHandle(th);
    VirtualFreeEx(hProc, remoteSc, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return L"";
}

static std::wstring inject_dll_loadlibrary(DWORD pid, const std::wstring& dllPath) {
    wchar_t full[MAX_PATH]{};
    if (!GetFullPathNameW(dllPath.c_str(), MAX_PATH, full, nullptr)) return L"Bad path";
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) return L"module.bin missing";

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return L"OpenProcess failed";

    size_t bytes = (wcslen(full) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hProc); return L"VirtualAllocEx failed"; }
    WriteProcessMemory(hProc, remote, full, bytes, nullptr);
    auto pLoad = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, pLoad, remote, 0, nullptr);
    if (!th) { VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); CloseHandle(hProc); return L"CRT failed"; }
    WaitForSingleObject(th, 30000);
    DWORD code = 0; GetExitCodeThread(th, &code);
    CloseHandle(th); VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); CloseHandle(hProc);
    if (!code) return L"LoadLibrary NULL (need -allow_third_party_software)";
    return L"";
}


// Unlink module from PEB lists (InLoadOrder, InMemoryOrder, InInitializationOrder)
// Runs in remote process after LoadLibraryW
#pragma pack(push, 8)
struct UNLINK_DATA {
    ULONG_PTR ModuleBase; // HMODULE returned by LoadLibraryW
};
#pragma pack(pop)



static bool opts_has_allow(const std::wstring& s) {
    return s.find(L"-allow_third_party_software") != std::wstring::npos;
}
static bool opts_has_allow_a(const std::string& s) {
    return s.find("-allow_third_party_software") != std::string::npos;
}

static std::wstring merge_allow(std::wstring opts) {
    if (opts_has_allow(opts)) return opts;
    while (!opts.empty() && (opts.back() == L' ' || opts.back() == L'\t')) opts.pop_back();
    if (!opts.empty()) opts.push_back(L' ');
    opts += L"-allow_third_party_software";
    return opts;
}

static bool steam_has_allow_flag() {
    // registry
    HKEY key{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\Apps\\730", 0, KEY_READ, &key) == ERROR_SUCCESS) {
        wchar_t buf[1024]{};
        DWORD typ = 0, cb = sizeof(buf);
        if (RegQueryValueExW(key, L"LaunchOptions", nullptr, &typ, (LPBYTE)buf, &cb) == ERROR_SUCCESS && typ == REG_SZ) {
            RegCloseKey(key);
            if (opts_has_allow(buf)) return true;
        } else RegCloseKey(key);
    }
    // localconfig.vdf
    HKEY sk{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &sk) != ERROR_SUCCESS)
        return false;
    wchar_t steamPath[MAX_PATH]{};
    DWORD cb = sizeof(steamPath), typ = 0;
    if (RegQueryValueExW(sk, L"SteamPath", nullptr, &typ, (LPBYTE)steamPath, &cb) != ERROR_SUCCESS) {
        RegCloseKey(sk);
        return false;
    }
    RegCloseKey(sk);
    for (auto& c : steamPath) if (c == L'/') c = L'\\';
    std::wstring userData = std::wstring(steamPath) + L"\\userdata";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((userData + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;
        bool digits = true;
        for (wchar_t* p = fd.cFileName; *p; ++p) if (*p < L'0' || *p > L'9') { digits = false; break; }
        if (!digits) continue;
        std::wstring vdf = userData + L"\\" + fd.cFileName + L"\\config\\localconfig.vdf";
        FILE* fp = nullptr;
        _wfopen_s(&fp, vdf.c_str(), L"rb");
        if (!fp) continue;
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (sz <= 0 || sz > 12 * 1024 * 1024) { fclose(fp); continue; }
        std::string data(sz, '\0');
        fread(data.data(), 1, (size_t)sz, fp);
        fclose(fp);
        if (opts_has_allow_a(data)) { found = true; break; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

static bool steam_set_allow_flag() {
    bool ok = false;
    HKEY key{};
    DWORD disp = 0;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam\\Apps\\730", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disp) == ERROR_SUCCESS) {
        wchar_t buf[1024]{};
        DWORD typ = 0, cb = sizeof(buf);
        std::wstring opts;
        if (RegQueryValueExW(key, L"LaunchOptions", nullptr, &typ, (LPBYTE)buf, &cb) == ERROR_SUCCESS && typ == REG_SZ)
            opts = buf;
        opts = merge_allow(opts);
        if (RegSetValueExW(key, L"LaunchOptions", 0, REG_SZ,
            (const BYTE*)opts.c_str(), (DWORD)((opts.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS)
            ok = true;
        RegCloseKey(key);
    }
    return ok;
}


static bool write_text_file_utf8(const std::wstring& path, const std::string& data) {
    FILE* fp = nullptr;
    _wfopen_s(&fp, path.c_str(), L"wb");
    if (!fp) return false;
    fwrite(data.data(), 1, data.size(), fp);
    fclose(fp);
    return true;
}

static bool read_text_file_utf8(const std::wstring& path, std::string& data) {
    FILE* fp = nullptr;
    _wfopen_s(&fp, path.c_str(), L"rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > 16 * 1024 * 1024) { fclose(fp); return false; }
    data.assign((size_t)sz, '\0');
    fread(data.data(), 1, (size_t)sz, fp);
    fclose(fp);
    return true;
}

// Patch LaunchOptions for app 730 inside a VDF blob
static bool vdf_set_730_launch_options(std::string& data) {
    const char flag[] = "-allow_third_party_software";
    if (data.find(flag) != std::string::npos) return true;

    // find "730" key
    size_t appPos = data.find("\"730\"");
    if (appPos == std::string::npos)
        appPos = data.find("\"730\""); // keep
    if (appPos == std::string::npos) return false;

    size_t regionEnd = data.size();
    // crude: limit to next sibling app id or 4k
    if (appPos + 4000 < data.size()) regionEnd = appPos + 4000;

    size_t lo = data.find("\"LaunchOptions\"", appPos);
    if (lo != std::string::npos && lo < regionEnd) {
        // find value quotes after LaunchOptions
        size_t q1 = data.find('"', lo + 15);
        if (q1 == std::string::npos) return false;
        size_t q2 = data.find('"', q1 + 1);
        if (q2 == std::string::npos || q2 <= q1) return false;
        std::string cur = data.substr(q1 + 1, q2 - q1 - 1);
        if (cur.find(flag) == std::string::npos) {
            if (!cur.empty() && cur.back() != ' ') cur.push_back(' ');
            cur += flag;
            data.replace(q1 + 1, q2 - q1 - 1, cur);
        }
        return true;
    }

    // no LaunchOptions — insert after opening brace of 730
    size_t brace = data.find('{', appPos);
    if (brace == std::string::npos || brace > appPos + 64) return false;
    std::string ins = "\n\t\t\t\t\"LaunchOptions\"\t\t\"";
    ins += flag;
    ins += "\"\n";
    data.insert(brace + 1, ins);
    return true;
}

static std::wstring steam_install_path() {
    HKEY sk{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &sk) != ERROR_SUCCESS)
        return L"";
    wchar_t steamPath[MAX_PATH]{};
    DWORD cb = sizeof(steamPath), typ = 0;
    LONG st = RegQueryValueExW(sk, L"SteamPath", nullptr, &typ, (LPBYTE)steamPath, &cb);
    RegCloseKey(sk);
    if (st != ERROR_SUCCESS) return L"";
    for (auto& c : steamPath) if (c == L'/') c = L'\\';
    return steamPath;
}

static void steam_patch_localconfig_vdf() {
    std::wstring steamPath = steam_install_path();
    if (steamPath.empty()) return;

    std::wstring userData = steamPath + L"\\userdata";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((userData + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;
        bool digits = true;
        for (wchar_t* p = fd.cFileName; *p; ++p) if (*p < L'0' || *p > L'9') { digits = false; break; }
        if (!digits) continue;

        const wchar_t* names[] = { L"\\config\\localconfig.vdf", L"\\config\\sharedconfig.vdf" };
        for (auto rel : names) {
            std::wstring path = userData + L"\\" + fd.cFileName + rel;
            std::string data;
            if (!read_text_file_utf8(path, data)) continue;
            std::string before = data;
            if (!vdf_set_730_launch_options(data)) continue;
            if (data == before) continue;
            std::wstring bak = path + L".phantom.bak";
            CopyFileW(path.c_str(), bak.c_str(), FALSE);
            write_text_file_utf8(path, data);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void ensure_cs2_requirements() {
    set_status(L"Installing Requirements...");
    if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
    Sleep(800);
    // always force registry write
    steam_set_allow_flag();
    // force VDF write (Steam UI source of truth)
    steam_patch_localconfig_vdf();
    // second pass registry in case VDF was locked
    steam_set_allow_flag();
    set_status(L"Requirements ready");
    if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
    Sleep(200);
}

static std::wstring inject_dll(DWORD pid, const std::wstring& dllPath) {
    wchar_t fullW[MAX_PATH]{};
    if (!GetFullPathNameW(dllPath.c_str(), MAX_PATH, fullW, nullptr))
        return L"Bad module path";
    if (GetFileAttributesW(fullW) == INVALID_FILE_ATTRIBUTES)
        return L"module.bin missing";

    // LoadLibraryA path (ANSI)
    char fullA[MAX_PATH * 2]{};
    WideCharToMultiByte(CP_ACP, 0, fullW, -1, fullA, sizeof(fullA), nullptr, nullptr);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return L"OpenProcess failed — run as Admin";

    size_t len = strlen(fullA) + 1;
    void* remotePath = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) { CloseHandle(hProc); return L"VirtualAllocEx failed"; }
    if (!WriteProcessMemory(hProc, remotePath, fullA, len, nullptr)) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"WPM path failed";
    }

    auto pLoad = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, pLoad, remotePath, 0, nullptr);
    if (!th) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return L"CreateRemoteThread failed";
    }
    WaitForSingleObject(th, 60000);
    DWORD modBase = 0;
    GetExitCodeThread(th, &modBase);
    CloseHandle(th);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);
    if (!modBase)
        return L"LoadLibraryA returned NULL";
    return L"";
}


static std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\\' || c == '"') { o.push_back('\\'); o.push_back((char)c); }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else o.push_back((char)c);
    }
    return o;
}

static bool do_login() {
    set_status(L"Authenticating...");
    if (g.email.empty() || g.password.empty()) {
        set_status(L"Enter email and password");
        return false;
    }
    while (!g.email.empty() && (g.email.back() == L' ' || g.email.back() == L'\t')) g.email.pop_back();
    while (!g.email.empty() && (g.email.front() == L' ' || g.email.front() == L'\t')) g.email.erase(g.email.begin());

    std::string email_a = narrow(g.email);
    for (auto& c : email_a) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    std::string body = std::string("{\"email\":\"") + json_escape(email_a) +
        "\",\"password\":\"" + json_escape(narrow(g.password)) + "\"}";

    HttpResult r{};
    try {
        r = http_request(L"POST", L"/api/login", body, L"", false);
    } catch (...) {
        set_status(L"Network exception");
        return false;
    }

    if (r.status == 0) { set_status(L"No response — server waking, wait 30s and retry"); return false; }
    if (r.status < 0) { set_status(L"Network error — allow loader through firewall"); return false; }
    if (r.status == 401) { set_status(L"Wrong email or password"); return false; }
    if (r.status != 200) {
        set_status(L"Login failed (" + std::to_wstring(r.status) + L")");
        return false;
    }

    g.token = wide(json_get_string(r.body, "token"));
    if (g.token.empty()) { set_status(L"Bad server response"); return false; }

    g.userName = wide(json_get_string(r.body, "username"));
    g.role = wide(json_get_string(r.body, "role"));
    auto exp0 = json_get_string(r.body, "expires_label");
    if (exp0.empty()) exp0 = json_get_string(r.body, "expires");
    g.expires = wide(exp0);

    // session is optional enrich — never crash login if it fails
    try {
        auto s = http_request(L"POST", L"/api/loader/session", "{}", g.token, false);
        if (s.status == 403) {
            set_status(L"Subscription expired — redeem a key on the site");
            g.token.clear();
            return false;
        }
        if (s.status == 200) {
            auto u = json_get_string(s.body, "user"); if (!u.empty()) g.userName = wide(u);
            auto role = json_get_string(s.body, "role"); if (!role.empty()) g.role = wide(role);
            auto exp = json_get_string(s.body, "expires"); if (!exp.empty()) g.expires = wide(exp);
        }
    } catch (...) {}

    if (g.userName.empty()) g.userName = L"User";
    if (g.role.empty()) g.role = L"member";
    if (g.role == L"owner" || g.role == L"admin") g.expires = L"Never";
    else if (g.expires.empty() || g.expires.find(L"1970") != std::wstring::npos) g.expires = L"—";

    try { save_session(); } catch (...) {}

    bool needs = true;
    try {
        auto sa = json_get_string(r.body, "sub_active");
        if (sa == "true") needs = false;
    } catch (...) {}
    if (g.role == L"owner" || g.role == L"admin") needs = false;

    if (needs) {
        g.page = Page::Verify;
        g.focus = 3;
        g.license.clear();
        set_status(L"Enter your license key to verify");
    } else {
        g.page = Page::Main;
        std::thread([] { try { ensure_cs2_requirements(); } catch (...) {} }).detach();
        set_status(L"Ready");
    }
    return true;
}

static bool do_verify() {
    if (g.token.empty()) {
        set_status(L"Login first");
        g.page = Page::Login;
        return false;
    }
    std::wstring key = g.license;
    while (!key.empty() && (key.back() == L' ' || key.back() == L'\t')) key.pop_back();
    while (!key.empty() && (key.front() == L' ' || key.front() == L'\t')) key.erase(key.begin());
    if (key.empty()) { set_status(L"Paste your license key"); return false; }

    std::string body = std::string("{\"key\":\"") + json_escape(narrow(key)) + "\"}";
    HttpResult r{};
    try {
        r = http_request(L"POST", L"/api/verify-license", body, g.token, false);
    } catch (...) {
        set_status(L"Network error");
        return false;
    }
    if (r.status == 0) { set_status(L"No response — wait 30s and retry"); return false; }
    if (r.status == 401) { set_status(L"Session expired — login again"); g.page = Page::Login; return false; }
    if (r.status != 200) {
        auto err = json_get_string(r.body, "error");
        set_status(err.empty() ? (L"Verify failed (" + std::to_wstring(r.status) + L")") : wide(err));
        return false;
    }
    try {
        auto s = http_request(L"POST", L"/api/loader/session", "{}", g.token, false);
        if (s.status == 200) {
            auto exp = json_get_string(s.body, "expires"); if (!exp.empty()) g.expires = wide(exp);
            auto user = json_get_string(s.body, "user"); if (!user.empty()) g.userName = wide(user);
        }
    } catch (...) {}
    try { save_session(); } catch (...) {}
    g.page = Page::Main;
    std::thread([] { try { ensure_cs2_requirements(); } catch (...) {} }).detach();
    set_status(L"Verified — Ready");
    return true;
}

static void launch_flow() {
    if (g.busy) return;
    g.busy = true;
    std::thread([] {
        set_status(L"Validating session...");
        auto s = http_request(L"POST", L"/api/loader/session", "{}", g.token, false);
        if (s.status != 200) {
            set_status(s.status == 403 ? L"Subscription expired" : L"Session invalid — login again");
            g.page = Page::Login; g.busy = false;
            if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
            return;
        }
        auto exp = json_get_string(s.body, "expires"); if (!exp.empty()) g.expires = wide(exp);
        auto role = json_get_string(s.body, "role"); if (!role.empty()) g.role = wide(role);
        auto user = json_get_string(s.body, "user"); if (!user.empty()) g.userName = wide(user);

        set_status(L"Fetching module...");
        auto payload = http_request(L"GET", L"/api/loader/payload", "", g.token, true);
        if (payload.status != 200 || payload.bin.size() < 64) {
            set_status(L"Payload denied / missing on server");
            g.busy = false; if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0); return;
        }
        std::wstring mod = data_dir() + L"\\module.bin";
        FILE* fp = nullptr; _wfopen_s(&fp, mod.c_str(), L"wb");
        if (!fp) { set_status(L"Cannot write module"); g.busy = false; return; }
        fwrite(payload.bin.data(), 1, payload.bin.size(), fp); fclose(fp);

        // ALWAYS write launch option before starting CS2
        ensure_cs2_requirements();

        set_status(L"Starting CS2...");
        if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
        // pass flag on the steam protocol too (works even if VDF lag)
        ShellExecuteW(nullptr, L"open",
            L"steam://rungameid/730//-allow_third_party_software",
            nullptr, nullptr, SW_SHOWNORMAL);
        Sleep(1500);
        // fallback classic run
        ShellExecuteW(nullptr, L"open", L"steam://run/730", nullptr, nullptr, SW_SHOWNORMAL);

        set_status(L"Waiting for cs2.exe...");
        DWORD pid = 0;
        for (int i = 0; i < 120 && !pid; ++i) { pid = find_pid(L"cs2.exe"); Sleep(500); }
        if (!pid) { set_status(L"cs2.exe not found"); g.busy = false; return; }

        set_status(L"Stabilizing...");
        for (int i = 0; i <= k_wait_seconds; ++i) {
            g.progress = (float)i / (float)k_wait_seconds;
            if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
            Sleep(1000);
        }
        ensure_cs2_requirements();

        enable_debug_privilege();
        set_status(L"Injecting...");
        if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
        auto err = inject_dll(pid, mod);
        DeleteFileW(mod.c_str());
        if (!err.empty()) { set_status(err); g.busy = false; if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0); return; }
        set_status(L"Injected Successfully — wait");
        if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
        Sleep(4000); // let DllMain / hooks settle before closing loader
        set_status(L"Injected Successfully");
        if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
        Sleep(800);
        PostMessageW(g.hwnd, WM_CLOSE, 0, 0);
        g.busy = false;
    }).detach();
}

static void fill_round(HDC hdc, RECT rc, COLORREF c, int rad) {
    HBRUSH br = CreateSolidBrush(c);
    HPEN pen = CreatePen(PS_SOLID, 1, c);
    auto oldB = SelectObject(hdc, br);
    auto oldP = SelectObject(hdc, pen);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
    SelectObject(hdc, oldB); SelectObject(hdc, oldP);
    DeleteObject(br); DeleteObject(pen);
}

static void frame_round(HDC hdc, RECT rc, COLORREF c, int rad, int thickness) {
    for (int i = 0; i < thickness; ++i) {
        RECT r = { rc.left + i, rc.top + i, rc.right - i, rc.bottom - i };
        HPEN pen = CreatePen(PS_SOLID, 1, c);
        auto oldP = SelectObject(hdc, pen);
        auto oldB = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, r.left, r.top, r.right, r.bottom, rad, rad);
        SelectObject(hdc, oldB); SelectObject(hdc, oldP);
        DeleteObject(pen);
    }
}

static void text_out(HDC hdc, HFONT f, RECT rc, const wchar_t* s, COLORREF c, UINT fmt) {
    auto old = SelectObject(hdc, f);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, c);
    DrawTextW(hdc, s, -1, &rc, fmt);
    SelectObject(hdc, old);
}

static void draw_circle(HDC hdc, int cx, int cy, int r, COLORREF c) {
    HBRUSH br = CreateSolidBrush(c);
    HPEN pen = CreatePen(PS_SOLID, 1, c);
    auto oldB = SelectObject(hdc, br);
    auto oldP = SelectObject(hdc, pen);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, oldB); SelectObject(hdc, oldP);
    DeleteObject(br); DeleteObject(pen);
}

static void load_logo_image() {
    if (g.logo) return;
    std::wstring path = exe_dir() + L"\\logo.png";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        path = data_dir() + L"\\logo.png";
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        g.logo = new Image(path.c_str());
        if (g.logo && g.logo->GetLastStatus() != Ok) { delete g.logo; g.logo = nullptr; }
    }
    if (!g.logo) {
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, k_logo_png_size);
        if (hMem) {
            void* pMem = GlobalLock(hMem);
            if (pMem) {
                memcpy(pMem, k_logo_png, k_logo_png_size);
                GlobalUnlock(hMem);
                IStream* stream = nullptr;
                if (CreateStreamOnHGlobal(hMem, TRUE, &stream) == S_OK && stream) {
                    g.logo = new Image(stream);
                    stream->Release();
                    if (g.logo && g.logo->GetLastStatus() != Ok) { delete g.logo; g.logo = nullptr; }
                } else GlobalFree(hMem);
            } else GlobalFree(hMem);
        }
    }
    if (!g.logo) return;
    // taskbar / alt-tab icons
    Gdiplus::Bitmap* iconBmp = nullptr;
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        iconBmp = new Gdiplus::Bitmap(path.c_str());
    } else {
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, k_logo_png_size);
        if (hMem) {
            void* pMem = GlobalLock(hMem);
            if (pMem) {
                memcpy(pMem, k_logo_png, k_logo_png_size);
                GlobalUnlock(hMem);
                IStream* stream = nullptr;
                if (CreateStreamOnHGlobal(hMem, TRUE, &stream) == S_OK && stream) {
                    iconBmp = new Gdiplus::Bitmap(stream);
                    stream->Release();
                } else GlobalFree(hMem);
            } else GlobalFree(hMem);
        }
    }
    if (iconBmp && iconBmp->GetLastStatus() == Ok) {
        iconBmp->GetHICON(&g.hIcon);
        Gdiplus::Bitmap* smallBmp = new Gdiplus::Bitmap(16, 16, PixelFormat32bppARGB);
        if (smallBmp && smallBmp->GetLastStatus() == Ok) {
            Gdiplus::Graphics gs(smallBmp);
            gs.SetInterpolationMode(InterpolationModeHighQualityBicubic);
            gs.Clear(Color(0, 0, 0, 0));
            gs.DrawImage(iconBmp, 0, 0, 16, 16);
            smallBmp->GetHICON(&g.hIconSm);
        }
        if (smallBmp) delete smallBmp;
    }
    if (iconBmp) delete iconBmp;

    // CS2 product icon — file first, then embedded PNG
    if (!g.cs2) {
        const wchar_t* tries[] = {
            L"\\cs2.png",
            L"\\assets\\cs2.png",
            L"\\cs2 logo.png",
        };
        std::wstring base = exe_dir();
        std::wstring ddir = data_dir();
        for (auto rel : tries) {
            std::wstring cpath = base + rel;
            if (GetFileAttributesW(cpath.c_str()) == INVALID_FILE_ATTRIBUTES)
                cpath = ddir + rel;
            if (GetFileAttributesW(cpath.c_str()) == INVALID_FILE_ATTRIBUTES)
                continue;
            g.cs2 = new Image(cpath.c_str());
            if (g.cs2 && g.cs2->GetLastStatus() == Ok) break;
            if (g.cs2) { delete g.cs2; g.cs2 = nullptr; }
        }
    }
    if (!g.cs2) {
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, k_cs2_png_size);
        if (hMem) {
            void* pMem = GlobalLock(hMem);
            if (pMem) {
                memcpy(pMem, k_cs2_png, k_cs2_png_size);
                GlobalUnlock(hMem);
                IStream* stream = nullptr;
                if (CreateStreamOnHGlobal(hMem, TRUE, &stream) == S_OK && stream) {
                    g.cs2 = new Image(stream);
                    stream->Release();
                    if (g.cs2 && g.cs2->GetLastStatus() != Ok) {
                        delete g.cs2;
                        g.cs2 = nullptr;
                    }
                } else {
                    GlobalFree(hMem);
                }
            } else {
                GlobalFree(hMem);
            }
        }
    }
}


static void paint(HWND hwnd) {

    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT cr; GetClientRect(hwnd, &cr);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, cr.right, cr.bottom);
    auto oldBmp = SelectObject(mem, bmp);

    // background
    fill_round(mem, cr, RGB(10, 10, 14), 0);

    // title bar dots: grey minimize, white close
    draw_circle(mem, cr.right - 28, 22, 7, RGB(245, 245, 248)); // close
    draw_circle(mem, cr.right - 52, 22, 7, RGB(90, 90, 98));    // minimize

    if (g.page == Page::Login) {
        // logo + title
        {
            int lx = 36, ly = 36, ls = 40;
            if (g.logo) {
                Graphics gfx(mem);
                gfx.SetInterpolationMode(InterpolationModeHighQualityBicubic);
                gfx.DrawImage(g.logo, lx, ly, ls, ls);
                text_out(mem, g.fontTitle, { lx + ls + 12, 40, cr.right - 80, 78 }, L"Phantom", RGB(250, 250, 252), DT_LEFT);
            } else {
                text_out(mem, g.fontTitle, { 36, 40, cr.right - 36, 78 }, L"Phantom", RGB(250, 250, 252), DT_LEFT);
            }
        }
        text_out(mem, g.fontSmall, { 36, 82, cr.right - 36, 104 }, L"Secure access", RGB(140, 140, 150), DT_LEFT);

        // EMAIL (top)
        text_out(mem, g.fontLabel, { 40, 118, 200, 136 }, L"EMAIL", RGB(160, 160, 170), DT_LEFT);
        RECT e = { 36, 140, cr.right - 36, 182 };
        fill_round(mem, e, RGB(22, 22, 28), 14);
        if (g.focus == 1) frame_round(mem, e, RGB(255, 255, 255), 14, 3);
        else frame_round(mem, e, RGB(48, 48, 56), 14, 1);
        text_out(mem, g.fontBody, { e.left + 16, e.top, e.right - 16, e.bottom },
            g.email.empty() ? L"you@mail.com" : g.email.c_str(),
            g.email.empty() ? RGB(100, 100, 110) : RGB(240, 240, 245),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // PASSWORD (below email)
        text_out(mem, g.fontLabel, { 40, 198, 200, 216 }, L"PASSWORD", RGB(160, 160, 170), DT_LEFT);
        RECT p = { 36, 220, cr.right - 36, 262 };
        fill_round(mem, p, RGB(22, 22, 28), 14);
        if (g.focus == 2) frame_round(mem, p, RGB(255, 255, 255), 14, 3);
        else frame_round(mem, p, RGB(48, 48, 56), 14, 1);
        std::wstring dots(g.password.size(), L'*');
        text_out(mem, g.fontBody, { p.left + 16, p.top, p.right - 16, p.bottom },
            g.password.empty() ? L"Enter your password here" : dots.c_str(),
            g.password.empty() ? RGB(100, 100, 110) : RGB(240, 240, 245),
            DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // REMEMBER ME (below password, own row)
        RECT cb = { 40, 280, 58, 298 };
        if (g.remember) {
            fill_round(mem, cb, RGB(255, 255, 255), 5);
            // draw check mark with lines (no letter overlapping fields)
            HPEN pen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
            auto oldP = SelectObject(mem, pen);
            MoveToEx(mem, 44, 289, nullptr);
            LineTo(mem, 49, 294);
            LineTo(mem, 54, 284);
            SelectObject(mem, oldP);
            DeleteObject(pen);
        } else {
            fill_round(mem, cb, RGB(18, 18, 22), 5);
            frame_round(mem, cb, RGB(255, 255, 255), 5, 1);
        }
        text_out(mem, g.fontSmall, { 68, 278, 260, 300 }, L"Remember me", RGB(175, 175, 185), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT btn = { 36, 318, cr.right - 36, 362 };
        fill_round(mem, btn, RGB(245, 245, 248), 16);
        text_out(mem, g.fontBtn, btn, g.busy ? L"PLEASE WAIT..." : L"LOGIN", RGB(12, 12, 16), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        text_out(mem, g.fontSmall, { 36, 378, cr.right - 36, 430 }, g.status.c_str(), RGB(150, 150, 160), DT_LEFT | DT_WORDBREAK);
    } else {
    if (g.page == Page::Verify) {
        // Verification page
        int top = 40;
        if (g.logo) {
            const int ls = 64;
            int lx = (k_win_w - ls) / 2;
            gfx.DrawImage(g.logo, lx, top, ls, ls);
            top += ls + 16;
        }
        text_out(mem, g.fontTitle, RECT{ 0, top, k_win_w, top + 28 }, L"Verification", RGB(255,255,255), DT_CENTER | DT_SINGLELINE);
        top += 36;
        text_out(mem, g.fontSmall, RECT{ 40, top, k_win_w - 40, top + 40 }, L"Paste the license key from sell.app / Discord", RGB(160,160,165), DT_CENTER | DT_WORDBREAK);
        top += 48;
        RECT lab{ 48, top, k_win_w - 48, top + 18 };
        text_out(mem, g.fontLabel, lab, L"LICENSE KEY", RGB(140,140,145), DT_LEFT | DT_SINGLELINE);
        top += 22;
        RECT box{ 48, top, k_win_w - 48, top + 36 };
        HBRUSH br = CreateSolidBrush(RGB(22, 22, 26));
        FillRect(mem, &box, br); DeleteObject(br);
        FrameRect(mem, &box, (HBRUSH)GetStockObject(GRAY_BRUSH));
        std::wstring show = g.license.empty() ? L"" : g.license;
        text_out(mem, g.fontBody, RECT{ box.left + 10, box.top, box.right - 10, box.bottom }, show.c_str(), RGB(230,230,235), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        top += 52;
        RECT vbtn{ 48, top, k_win_w - 48, top + 40 };
        HBRUSH bb = CreateSolidBrush(g.busy ? RGB(80,80,90) : RGB(235, 235, 240));
        FillRect(mem, &vbtn, bb); DeleteObject(bb);
        text_out(mem, g.fontBtn, vbtn, g.busy ? L"CHECKING..." : L"VERIFY", RGB(12,12,16), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT st{ 40, k_win_h - 70, k_win_w - 40, k_win_h - 40 };
        text_out(mem, g.fontSmall, st, g.status.c_str(), RGB(180,180,185), DT_CENTER | DT_WORDBREAK);
        return;
    }

    // post-login page — mockup layout
        {
            int lx = 28, ly = 28, ls = 44;
            // logo tile
            RECT logoTile = { lx, ly, lx + ls, ly + ls };
            fill_round(mem, logoTile, RGB(28, 28, 34), 12);
            if (g.logo) {
                Graphics gfx(mem);
                gfx.SetInterpolationMode(InterpolationModeHighQualityBicubic);
                gfx.DrawImage(g.logo, lx + 4, ly + 4, ls - 8, ls - 8);
            }
            text_out(mem, g.fontTitle, { lx + ls + 14, 34, cr.right - 80, 72 }, L"Phantom", RGB(250, 250, 252), DT_LEFT);
        }

        // Current Products (left)
        RECT prod = { 24, 88, 255, 185 };
        fill_round(mem, prod, RGB(26, 26, 32), 16);
        text_out(mem, g.fontSmall, { prod.left + 16, prod.top + 12, prod.right - 12, prod.top + 30 },
            L"Current Products:", RGB(200, 200, 208), DT_LEFT);
        int ix = prod.left + 16, iy = prod.top + 44, isz = 40;
        if (g.cs2) {
            Graphics gfx(mem);
            gfx.SetInterpolationMode(InterpolationModeHighQualityBicubic);
            gfx.DrawImage(g.cs2, ix, iy, isz, isz);
        }
        text_out(mem, g.fontBody, { ix + isz + 12, iy, prod.right - 14, iy + isz },
            L"counter-strike 2", RGB(235, 235, 240), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Status (right) — wider
        RECT st = { 268, 88, cr.right - 24, 185 };
        fill_round(mem, st, RGB(26, 26, 32), 16);
        text_out(mem, g.fontSmall, { st.left + 16, st.top + 12, st.right - 12, st.top + 30 },
            L"Status:", RGB(200, 200, 208), DT_LEFT);
        text_out(mem, g.fontBody, { st.left + 16, st.top + 44, st.right - 16, st.bottom - 14 },
            g.status.c_str(), RGB(235, 235, 240), DT_LEFT | DT_WORDBREAK);

        // User card
        RECT info = { 24, 200, 255, 325 };
        fill_round(mem, info, RGB(26, 26, 32), 16);
        auto info_row = [&](int y, const wchar_t* label, const std::wstring& val) {
            std::wstring line = std::wstring(label) + L" " + (val.empty() ? L"—" : val);
            text_out(mem, g.fontBody, { info.left + 14, y, info.right - 12, y + 22 },
                line.c_str(), RGB(225, 225, 230), DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        };
        info_row(info.top + 18, L"User:", g.userName);
        info_row(info.top + 48, L"Role:", g.role.empty() ? L"member" : g.role);
        info_row(info.top + 78, L"Expire date:", g.expires.empty() ? L"—" : g.expires);

        // progress thin line under status when busy
        if (g.busy && g.progress > 0.f) {
            RECT track = { 246, 182, cr.right - 28, 186 };
            fill_round(mem, track, RGB(40, 40, 48), 2);
            int fillW = (int)((track.right - track.left) * g.progress);
            if (fillW > 0) {
                RECT fill = { track.left, track.top, track.left + fillW, track.bottom };
                fill_round(mem, fill, RGB(245, 245, 248), 2);
            }
        }

        // LAUNCH button bottom right
        RECT btn = { cr.right - 200, 340, cr.right - 28, 390 };
        fill_round(mem, btn, RGB(245, 245, 248), 14);
        text_out(mem, g.fontBtn, btn, g.busy ? L"WORKING..." : L"LAUNCH", RGB(12, 12, 16), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        // logout text bottom left
        text_out(mem, g.fontSmall, { 28, 410, 140, 440 }, L"Logout", RGB(140, 140, 150), DT_LEFT);
    }

    // window outline white
    frame_round(mem, RECT{ 1, 1, cr.right - 1, cr.bottom - 1 }, RGB(255, 255, 255), 12, 2);

    BitBlt(hdc, 0, 0, cr.right, cr.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

static bool hit_close(int x, int y, int w) {
    int cx = w - 28, cy = 22;
    int dx = x - cx, dy = y - cy;
    return dx * dx + dy * dy <= 10 * 10;
}
static bool hit_min(int x, int y, int w) {
    int cx = w - 52, cy = 22;
    int dx = x - cx, dy = y - cy;
    return dx * dx + dy * dy <= 10 * 10;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g.hwnd = hwnd;
        g.fontTitle = CreateFontW(28, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g.fontBody = CreateFontW(15, 0, 0, 0, FW_MEDIUM, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g.fontSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g.fontBtn = CreateFontW(15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g.fontLabel = CreateFontW(11, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        if (load_session() && !g.token.empty()) {
            std::thread([] {
                auto s = http_request(L"POST", L"/api/loader/session", "{}", g.token, false);
                if (s.status == 200) {
                    g.page = Page::Main;
                    auto u = json_get_string(s.body, "user"); if (!u.empty()) g.userName = wide(u);
                    auto role = json_get_string(s.body, "role"); if (!role.empty()) g.role = wide(role);
                    auto exp = json_get_string(s.body, "expires"); if (!exp.empty()) g.expires = wide(exp);
                    set_status(L"Ready");
                } else {
                    g.token.clear();
                    set_status(L"Session expired — sign in");
                }
                if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
            }).detach();
        }
        return 0;
    case WM_APP_REFRESH:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_PAINT:
        paint(hwnd);
        return 0;
    case WM_LBUTTONDOWN: {
        int x = LOWORD(lParam), y = HIWORD(lParam);
        RECT cr; GetClientRect(hwnd, &cr);
        if (hit_close(x, y, cr.right)) { PostMessageW(hwnd, WM_CLOSE, 0, 0); return 0; }
        if (hit_min(x, y, cr.right)) { ShowWindow(hwnd, SW_MINIMIZE); return 0; }

        if (g.page == Page::Login) {
            if (y >= 140 && y <= 182) { g.focus = 1; InvalidateRect(hwnd, nullptr, FALSE); }
            else if (y >= 220 && y <= 262) { g.focus = 2; InvalidateRect(hwnd, nullptr, FALSE); }
            else if (y >= 278 && y <= 300 && x >= 36 && x <= 260) {
                g.remember = !g.remember;
                if (g.remember) { try { save_session(); } catch (...) {} }
                else { DeleteFileW(cred_path().c_str()); }
                InvalidateRect(hwnd, nullptr, FALSE);
            } else if (y >= 318 && y <= 362) {
                if (!g.busy) {
                    g.busy = true;
                    std::thread([] {
                        try { do_login(); } catch (...) { set_status(L"Login crashed"); }
                        g.busy = false;
                        if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0);
                    }).detach();
                }
            }
        } else {
            // VERIFY button
            if (g.page == Page::Verify) {
                RECT vbtn{ 48, 250, k_win_w - 48, 290 };
                // approximate — also check lower area
                RECT vbtn2{ 48, 200, k_win_w - 48, 320 };
                POINT pt{ LOWORD(lParam), HIWORD(lParam) };
                if (PtInRect(&vbtn2, pt) && !g.busy) {
                    g.busy = true;
                    std::thread([] { try { do_verify(); } catch (...) { set_status(L"Verify crashed"); } g.busy = false; if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0); }).detach();
                    return 0;
                }
            }
            // LAUNCH button
            if (y >= 340 && y <= 390 && x >= (440 - 200) && x <= (440 - 28)) launch_flow();
            else if (y >= 410 && y <= 440 && x < 140) {
                g.token.clear(); g.page = Page::Login; DeleteFileW(cred_path().c_str());
                set_status(L"Signed out");
            }
        }
        return 0;
    }
    case WM_KEYDOWN: {
        if ((g.page != Page::Login && g.page != Page::Verify) || g.busy) break;
        if ((GetKeyState(VK_CONTROL) & 0x8000) && wParam == 'V') {
            if (OpenClipboard(hwnd)) {
                HANDLE h = GetClipboardData(CF_UNICODETEXT);
                if (h) {
                    wchar_t* clip = (wchar_t*)GlobalLock(h);
                    if (clip) {
                        auto& s = g.focus == 1 ? g.email : g.password;
                        for (wchar_t* q = clip; *q && s.size() < 128; ++q) {
                            if (*q >= 32 && *q != 127) s.push_back(*q);
                        }
                        GlobalUnlock(h);
                    }
                }
                CloseClipboard();
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        break;
    }
    case WM_CHAR: {
        if ((g.page != Page::Login && g.page != Page::Verify) || g.busy) return 0;
        wchar_t ch = (wchar_t)wParam;
        if (ch == 22) { // Ctrl+V paste
            if (OpenClipboard(hwnd)) {
                HANDLE h = GetClipboardData(CF_UNICODETEXT);
                if (h) {
                    wchar_t* clip = (wchar_t*)GlobalLock(h);
                    if (clip) {
                        auto& s = g.focus == 1 ? g.email : g.password;
                        for (wchar_t* p = clip; *p && s.size() < 128; ++p) {
                            if (*p >= 32 && *p != 127) s.push_back(*p);
                        }
                        GlobalUnlock(h);
                    }
                }
                CloseClipboard();
            }
        } else if (ch == 8) {
            if (g.page == Page::Verify) {
                if (!g.license.empty()) g.license.pop_back();
            } else {
                auto& s = g.focus == 1 ? g.email : g.password;
                if (!s.empty()) s.pop_back();
            }
        } else if (ch == 9) {
            if (g.page == Page::Login) g.focus = g.focus == 1 ? 2 : 1;
        } else if (ch == 13) {
            if (!g.busy) {
                g.busy = true;
                if (g.page == Page::Verify) {
                    std::thread([] { try { do_verify(); } catch (...) { set_status(L"Verify crashed"); } g.busy = false; if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0); }).detach();
                } else {
                    std::thread([] { try { do_login(); } catch (...) { set_status(L"Login crashed"); } g.busy = false; if (g.hwnd) PostMessageW(g.hwnd, WM_APP_REFRESH, 0, 0); }).detach();
                }
            }
        } else if (ch >= 32) {
            if (g.page == Page::Verify) {
                if (g.license.size() < 64) g.license.push_back(ch);
            } else {
                auto& s = g.focus == 1 ? g.email : g.password;
                if (s.size() < 128) s.push_back(ch);
            }
        }
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_NCHITTEST: {
        // drag window from empty title area
        LRESULT hit = DefWindowProcW(hwnd, msg, wParam, lParam);
        if (hit == HTCLIENT) {
            POINT pt{ LOWORD(lParam), HIWORD(lParam) };
            ScreenToClient(hwnd, &pt);
            if (pt.y < 36 && pt.x < k_win_w - 70) return HTCAPTION;
        }
        return hit;
    }
    case WM_DESTROY:
        if (g.logo) { delete g.logo; g.logo = nullptr; }
        if (g.cs2) { delete g.cs2; g.cs2 = nullptr; }
        if (g.hIcon) { DestroyIcon(g.hIcon); g.hIcon = nullptr; }
        if (g.hIconSm) { DestroyIcon(g.hIconSm); g.hIconSm = nullptr; }
        if (g.gdiplusToken) { GdiplusShutdown(g.gdiplusToken); g.gdiplusToken = 0; }
        if (g.fontTitle) DeleteObject(g.fontTitle);
        if (g.fontBody) DeleteObject(g.fontBody);
        if (g.fontSmall) DeleteObject(g.fontSmall);
        if (g.fontBtn) DeleteObject(g.fontBtn);
        if (g.fontLabel) DeleteObject(g.fontLabel);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int) {
    HANDLE mtx = CreateMutexW(nullptr, TRUE, L"Local\\PhantomLoaderAuthSingleton");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND existing = FindWindowW(L"PhantomAuthLoader", nullptr);
        if (existing) {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return 0;
        }
        // stale mutex — continue opening
    }

    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&g.gdiplusToken, &gdiplusStartupInput, nullptr);
    load_logo_image();

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"PhantomAuthLoader";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    if (g.hIcon) wc.hIcon = g.hIcon;
    if (g.hIconSm) wc.hIconSm = g.hIconSm;
    else if (g.hIcon) wc.hIconSm = g.hIcon;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"Phantom",
        WS_POPUP | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, k_win_w, k_win_h, nullptr, nullptr, hi, nullptr);

    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwnd, nullptr, (sx - k_win_w) / 2, (sy - k_win_h) / 2, k_win_w, k_win_h, SWP_NOZORDER);
    if (g.hIcon) SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)g.hIcon);
    if (g.hIconSm) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g.hIconSm);
    else if (g.hIcon) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g.hIcon);
    HRGN rgn = CreateRoundRectRgn(0, 0, k_win_w + 1, k_win_h + 1, 18, 18);
    SetWindowRgn(hwnd, rgn, TRUE);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
