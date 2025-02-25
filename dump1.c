// File: extended_hooks.c

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <combaseapi.h>
#include "hook.c"  // Assumes MinHook API is available

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ole32.lib")

// Global log file pointer
static FILE *g_logFile = NULL;
// Thread-local flag to prevent recursive hook calls
static __declspec(thread) int g_disableHook = 0;

//---------------------------------------------------------------------
// Logging and helper functions
//---------------------------------------------------------------------
static void log_printf(const char *fmt, ...) {
    if (g_logFile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fflush(g_logFile);
    }
}

void hexdump(const void *data, size_t size) {
    const unsigned char *p = (const unsigned char*)data;
    char line[100], ascii[17];
    ascii[16] = '\0';
    for (size_t i = 0; i < size; i += 16) {
        int pos = sprintf(line, "%08zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                pos += sprintf(line + pos, "%02x ", p[i + j]);
                ascii[j] = (p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.';
            } else {
                pos += sprintf(line + pos, "   ");
                ascii[j] = ' ';
            }
        }
        sprintf(line + pos, " %s\n", ascii);
        log_printf("%s", line);
    }
}

void print_backtrace(void) {
    void* stack[62];
    USHORT frames = CaptureStackBackTrace(0, 62, stack, NULL);
    char buffer[1024];
    for (USHORT i = 0; i < frames; i++) {
        SYMBOL_INFO *symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char));
        if (!symbol) continue;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;
        DWORD64 disp = 0;
        if (SymFromAddr(GetCurrentProcess(), (DWORD64)stack[i], &disp, symbol))
            sprintf(buffer, "%s - 0x%llx\n", symbol->Name, (unsigned long long)stack[i]);
        else
            sprintf(buffer, "0x%llx (no symbol)\n", (unsigned long long)stack[i]);
        log_printf("%s", buffer);
        free(symbol);
    }
}

// Protobuf varint parsing helpers
bool read_varint(const char** p, const char* end, uint64_t* value) {
    *value = 0;
    int shift = 0;
    while (*p < end) {
        uint8_t byte = (uint8_t)**p;
        (*p)++;
        *value |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80))
            return true;
        shift += 7;
        if (shift >= 64) return false;
    }
    return false;
}

bool is_likely_protobuf(const char* buf, size_t len) {
    const char* p = buf;
    const char* end = buf + len;
    while (p < end) {
        uint64_t key;
        if (!read_varint(&p, end, &key)) return false;
        uint32_t wire_type = key & 7;
        uint32_t field_number = key >> 3;
        if (field_number == 0) return false;
        switch (wire_type) {
            case 0: {
                uint64_t dummy;
                if (!read_varint(&p, end, &dummy)) return false;
                break;
            }
            case 1:
                if (p + 8 > end) return false;
                p += 8;
                break;
            case 2: {
                uint64_t length;
                if (!read_varint(&p, end, &length)) return false;
                if (p + length > end) return false;
                p += length;
                break;
            }
            case 5:
                if (p + 4 > end) return false;
                p += 4;
                break;
            default:
                return false;
        }
    }
    return (p == end);
}

//---------------------------------------------------------------------
// Hook Function Pointer Typedefs & Globals
//---------------------------------------------------------------------

// recv, recvfrom, SendMessageW (existing hooks)
typedef int (WINAPI *recv_t)(SOCKET s, char* buf, int len, int flags);
static recv_t orig_recv = NULL;

typedef int (WINAPI *recvfrom_t)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
static recvfrom_t orig_recvfrom = NULL;

typedef LRESULT (WINAPI *SendMessage_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
static SendMessage_t orig_SendMessage = NULL;

// Asynchronous network functions
typedef int (WINAPI *WSARecv_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static WSARecv_t orig_WSARecv = NULL;

typedef int (WINAPI *WSARecvFrom_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static WSARecvFrom_t orig_WSARecvFrom = NULL;

typedef int (WINAPI *WSASend_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static WSASend_t orig_WSASend = NULL;

typedef int (WINAPI *WSASendTo_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static WSASendTo_t orig_WSASendTo = NULL;

// Crypto API functions
typedef BOOL (WINAPI *CryptDecrypt_t)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen);
static CryptDecrypt_t orig_CryptDecrypt = NULL;

typedef BOOL (WINAPI *CryptEncrypt_t)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
static CryptEncrypt_t orig_CryptEncrypt = NULL;

// OpenSSL encryption/decryption functions
typedef int (*EVP_DecryptUpdate_t)(void* ctx, unsigned char* out, int* outl,
    const unsigned char* in, int inl);
static EVP_DecryptUpdate_t orig_EVP_DecryptUpdate = NULL;

typedef int (*EVP_DecryptFinal_ex_t)(void* ctx, unsigned char* outm, int* outl);
static EVP_DecryptFinal_ex_t orig_EVP_DecryptFinal_ex = NULL;

typedef int (*EVP_EncryptUpdate_t)(void* ctx, unsigned char* out, int* outl,
    const unsigned char* in, int inl);
static EVP_EncryptUpdate_t orig_EVP_EncryptUpdate = NULL;

typedef int (*EVP_EncryptFinal_ex_t)(void* ctx, unsigned char* outm, int* outl);
static EVP_EncryptFinal_ex_t orig_EVP_EncryptFinal_ex = NULL;

// Standard library memory copy
typedef void* (*memcpy_t)(void* dest, const void* src, size_t n);
static memcpy_t orig_memcpy = NULL;

// File I/O functions
typedef BOOL (WINAPI *ReadFile_t)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
static ReadFile_t orig_ReadFile = NULL;

typedef BOOL (WINAPI *WriteFile_t)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
static WriteFile_t orig_WriteFile = NULL;

// Memory-mapped file functions
typedef LPVOID (WINAPI *MapViewOfFile_t)(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
static MapViewOfFile_t orig_MapViewOfFile = NULL;

typedef BOOL (WINAPI *UnmapViewOfFile_t)(LPCVOID lpBaseAddress);
static UnmapViewOfFile_t orig_UnmapViewOfFile = NULL;

// COM memory allocation functions
typedef LPVOID (WINAPI *CoTaskMemAlloc_t)(SIZE_T cb);
static CoTaskMemAlloc_t orig_CoTaskMemAlloc = NULL;

typedef void (WINAPI *CoTaskMemFree_t)(LPVOID pv);
static CoTaskMemFree_t orig_CoTaskMemFree = NULL;

//---------------------------------------------------------------------
// Hook Implementations
//---------------------------------------------------------------------

// recv hook
int WINAPI my_recv(SOCKET s, char* buf, int len, int flags) {
    if (g_disableHook) return orig_recv(s, buf, len, flags);
    g_disableHook++;
    int ret = orig_recv(s, buf, len, flags);
    if (ret >= 32 && is_likely_protobuf(buf, (size_t)ret)) {
        log_printf("\n[+] recv: %d bytes received on socket %d\n", ret, (int)s);
        print_backtrace();
        hexdump(buf, ret);
    }
    g_disableHook--;
    return ret;
}

// recvfrom hook
int WINAPI my_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    if (g_disableHook) return orig_recvfrom(s, buf, len, flags, from, fromlen);
    g_disableHook++;
    int ret = orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (ret >= 32 && is_likely_protobuf(buf, (size_t)ret)) {
        log_printf("\n[+] recvfrom: %d bytes received on socket %d\n", ret, (int)s);
        print_backtrace();
        hexdump(buf, ret);
    }
    g_disableHook--;
    return ret;
}

// SendMessageW hook for WM_COPYDATA
LRESULT WINAPI my_SendMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (g_disableHook) return orig_SendMessage(hWnd, Msg, wParam, lParam);
    g_disableHook++;
    LRESULT ret = orig_SendMessage(hWnd, Msg, wParam, lParam);
    if (Msg == WM_COPYDATA) {
        COPYDATASTRUCT* cds = (COPYDATASTRUCT*)lParam;
        if (cds && cds->lpData && cds->cbData >= 32 &&
            is_likely_protobuf((const char*)cds->lpData, cds->cbData)) {
            log_printf("\n[+] SendMessage (WM_COPYDATA): %d bytes transferred\n", cds->cbData);
            print_backtrace();
            hexdump(cds->lpData, cds->cbData);
        }
    }
    g_disableHook--;
    return ret;
}

// WSARecv hook
int WINAPI my_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (g_disableHook) return orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                                             lpFlags, lpOverlapped, lpCompletionRoutine);
    g_disableHook++;
    int ret = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                           lpFlags, lpOverlapped, lpCompletionRoutine);
    if (!lpOverlapped && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd >= 32) {
        for (DWORD i = 0; i < dwBufferCount; i++) {
            WSABUF buf = lpBuffers[i];
            if (buf.len >= 32 && is_likely_protobuf(buf.buf, buf.len)) {
                log_printf("\n[+] WSARecv: Buffer %u, %d bytes on socket %d\n", i, buf.len, (int)s);
                print_backtrace();
                hexdump(buf.buf, buf.len);
            }
        }
    }
    g_disableHook--;
    return ret;
}

// WSARecvFrom hook
int WINAPI my_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (g_disableHook) return orig_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                                                 lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    g_disableHook++;
    int ret = orig_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                               lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    if (!lpOverlapped && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd >= 32) {
        for (DWORD i = 0; i < dwBufferCount; i++) {
            WSABUF buf = lpBuffers[i];
            if (buf.len >= 32 && is_likely_protobuf(buf.buf, buf.len)) {
                log_printf("\n[+] WSARecvFrom: Buffer %u, %d bytes on socket %d\n", i, buf.len, (int)s);
                print_backtrace();
                hexdump(buf.buf, buf.len);
            }
        }
    }
    g_disableHook--;
    return ret;
}

// WSASend hook
int WINAPI my_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (g_disableHook) return orig_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                             dwFlags, lpOverlapped, lpCompletionRoutine);
    g_disableHook++;
    int ret = orig_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                           dwFlags, lpOverlapped, lpCompletionRoutine);
    if (!lpOverlapped && lpNumberOfBytesSent && *lpNumberOfBytesSent >= 32) {
        for (DWORD i = 0; i < dwBufferCount; i++) {
            WSABUF buf = lpBuffers[i];
            if (buf.len >= 32 && is_likely_protobuf(buf.buf, buf.len)) {
                log_printf("\n[+] WSASend: Buffer %u, %d bytes sent on socket %d\n", i, buf.len, (int)s);
                print_backtrace();
                hexdump(buf.buf, buf.len);
            }
        }
    }
    g_disableHook--;
    return ret;
}

// WSASendTo hook
int WINAPI my_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr *lpTo, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (g_disableHook) return orig_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                               dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
    g_disableHook++;
    int ret = orig_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                             dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
    if (!lpOverlapped && lpNumberOfBytesSent && *lpNumberOfBytesSent >= 32) {
        for (DWORD i = 0; i < dwBufferCount; i++) {
            WSABUF buf = lpBuffers[i];
            if (buf.len >= 32 && is_likely_protobuf(buf.buf, buf.len)) {
                log_printf("\n[+] WSASendTo: Buffer %u, %d bytes sent on socket %d\n", i, buf.len, (int)s);
                print_backtrace();
                hexdump(buf.buf, buf.len);
            }
        }
    }
    g_disableHook--;
    return ret;
}

// CryptDecrypt hook (existing)
BOOL WINAPI my_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen) {
    if (g_disableHook) return orig_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    g_disableHook++;
    BOOL ret = orig_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    if (ret && pdwDataLen && *pdwDataLen >= 32 &&
        is_likely_protobuf((const char*)pbData, *pdwDataLen)) {
        log_printf("\n[+] CryptDecrypt: produced %lu bytes\n", *pdwDataLen);
        print_backtrace();
        hexdump(pbData, *pdwDataLen);
    }
    g_disableHook--;
    return ret;
}

// CryptEncrypt hook
BOOL WINAPI my_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    if (g_disableHook) return orig_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    g_disableHook++;
    BOOL ret = orig_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    if (ret && pdwDataLen && *pdwDataLen >= 32 &&
        is_likely_protobuf((const char*)pbData, *pdwDataLen)) {
        log_printf("\n[+] CryptEncrypt: processed %lu bytes\n", *pdwDataLen);
        print_backtrace();
        hexdump(pbData, *pdwDataLen);
    }
    g_disableHook--;
    return ret;
}

// EVP_DecryptUpdate hook (existing)
int my_EVP_DecryptUpdate(void* ctx, unsigned char* out, int* outl,
    const unsigned char* in, int inl) {
    if (g_disableHook) return orig_EVP_DecryptUpdate(ctx, out, outl, in, inl);
    g_disableHook++;
    int ret = orig_EVP_DecryptUpdate(ctx, out, outl, in, inl);
    if (ret && outl && *outl >= 32 &&
        is_likely_protobuf((const char*)out, *outl)) {
        log_printf("\n[+] EVP_DecryptUpdate: produced %d bytes\n", *outl);
        print_backtrace();
        hexdump(out, *outl);
    }
    g_disableHook--;
    return ret;
}

// EVP_DecryptFinal_ex hook (existing)
int my_EVP_DecryptFinal_ex(void* ctx, unsigned char* outm, int* outl) {
    if (g_disableHook) return orig_EVP_DecryptFinal_ex(ctx, outm, outl);
    g_disableHook++;
    int ret = orig_EVP_DecryptFinal_ex(ctx, outm, outl);
    if (ret && outl && *outl >= 32 &&
        is_likely_protobuf((const char*)outm, *outl)) {
        log_printf("\n[+] EVP_DecryptFinal_ex: produced %d bytes\n", *outl);
        print_backtrace();
        hexdump(outm, *outl);
    }
    g_disableHook--;
    return ret;
}

// EVP_EncryptUpdate hook
int my_EVP_EncryptUpdate(void* ctx, unsigned char* out, int* outl,
    const unsigned char* in, int inl) {
    if (g_disableHook) return orig_EVP_EncryptUpdate(ctx, out, outl, in, inl);
    g_disableHook++;
    int ret = orig_EVP_EncryptUpdate(ctx, out, outl, in, inl);
    if (ret && outl && *outl >= 32 &&
        is_likely_protobuf((const char*)out, *outl)) {
        log_printf("\n[+] EVP_EncryptUpdate: produced %d bytes\n", *outl);
        print_backtrace();
        hexdump(out, *outl);
    }
    g_disableHook--;
    return ret;
}

// EVP_EncryptFinal_ex hook
int my_EVP_EncryptFinal_ex(void* ctx, unsigned char* outm, int* outl) {
    if (g_disableHook) return orig_EVP_EncryptFinal_ex(ctx, outm, outl);
    g_disableHook++;
    int ret = orig_EVP_EncryptFinal_ex(ctx, outm, outl);
    if (ret && outl && *outl >= 32 &&
        is_likely_protobuf((const char*)outm, *outl)) {
        log_printf("\n[+] EVP_EncryptFinal_ex: produced %d bytes\n", *outl);
        print_backtrace();
        hexdump(outm, *outl);
    }
    g_disableHook--;
    return ret;
}

// memcpy hook (existing)
void* my_memcpy(void* dest, const void* src, size_t n) {
    if (g_disableHook) return orig_memcpy(dest, src, n);
    g_disableHook++;
    void* ret = orig_memcpy(dest, src, n);
    if (n >= 32 && is_likely_protobuf((const char*)src, n)) {
        log_printf("\n[+] memcpy: copied %zu bytes\n", n);
        print_backtrace();
        hexdump(src, n);
    }
    g_disableHook--;
    return ret;
}

// ReadFile hook
BOOL WINAPI my_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    if (g_disableHook) return orig_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    g_disableHook++;
    BOOL ret = orig_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (ret && lpNumberOfBytesRead && *lpNumberOfBytesRead >= 32 &&
        is_likely_protobuf((const char*)lpBuffer, *lpNumberOfBytesRead)) {
        log_printf("\n[+] ReadFile: read %lu bytes\n", *lpNumberOfBytesRead);
        print_backtrace();
        hexdump(lpBuffer, *lpNumberOfBytesRead);
    }
    g_disableHook--;
    return ret;
}

// WriteFile hook
BOOL WINAPI my_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    if (g_disableHook) return orig_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    g_disableHook++;
    BOOL ret = orig_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    if (ret && lpNumberOfBytesWritten && *lpNumberOfBytesWritten >= 32 &&
        is_likely_protobuf((const char*)lpBuffer, *lpNumberOfBytesWritten)) {
        log_printf("\n[+] WriteFile: wrote %lu bytes\n", *lpNumberOfBytesWritten);
        print_backtrace();
        hexdump(lpBuffer, *lpNumberOfBytesWritten);
    }
    g_disableHook--;
    return ret;
}

// MapViewOfFile hook
LPVOID WINAPI my_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    if (g_disableHook) return orig_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    g_disableHook++;
    LPVOID ret = orig_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    if (ret && dwNumberOfBytesToMap >= 32 && is_likely_protobuf((const char*)ret, dwNumberOfBytesToMap)) {
        log_printf("\n[+] MapViewOfFile: mapped %zu bytes at %p\n", dwNumberOfBytesToMap, ret);
        print_backtrace();
        hexdump(ret, dwNumberOfBytesToMap < 64 ? dwNumberOfBytesToMap : 64);
    }
    g_disableHook--;
    return ret;
}

// UnmapViewOfFile hook
BOOL WINAPI my_UnmapViewOfFile(LPCVOID lpBaseAddress) {
    if (g_disableHook) return orig_UnmapViewOfFile(lpBaseAddress);
    g_disableHook++;
    log_printf("\n[+] UnmapViewOfFile: unmapping memory at %p\n", lpBaseAddress);
    print_backtrace();
    BOOL ret = orig_UnmapViewOfFile(lpBaseAddress);
    g_disableHook--;
    return ret;
}

// CoTaskMemAlloc hook
LPVOID WINAPI my_CoTaskMemAlloc(SIZE_T cb) {
    if (g_disableHook) return orig_CoTaskMemAlloc(cb);
    g_disableHook++;
    LPVOID ret = orig_CoTaskMemAlloc(cb);
    if (cb >= 32) {
        log_printf("\n[+] CoTaskMemAlloc: allocated %zu bytes at %p\n", cb, ret);
        print_backtrace();
    }
    g_disableHook--;
    return ret;
}

// CoTaskMemFree hook
void WINAPI my_CoTaskMemFree(LPVOID pv) {
    if (g_disableHook) { orig_CoTaskMemFree(pv); return; }
    g_disableHook++;
    log_printf("\n[+] CoTaskMemFree: freeing memory at %p\n", pv);
    print_backtrace();
    orig_CoTaskMemFree(pv);
    g_disableHook--;
}

//---------------------------------------------------------------------
// DLL Main: Hook Installation & Cleanup
//---------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Open log file in user's home directory (or fallback)
        char *home = getenv("USERPROFILE");
        if (!home) home = "C:\\";
        char logPath[512];
        sprintf(logPath, "%s\\stardump_extended.log", home);
        g_logFile = fopen(logPath, "a+");
        if (!g_logFile) g_logFile = fopen("stardump_extended.log", "a+");

        // Initialize DbgHelp
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
            log_printf("Failed to initialize DbgHelp.\n");

        // Initialize MinHook
        if (MH_Initialize() != MH_OK) {
            log_printf("Failed to initialize MinHook.\n");
            return FALSE;
        }

        // Install hooks
        MH_CreateHookApi(L"ws2_32.dll", "recv", &my_recv, (LPVOID*)&orig_recv);
        MH_CreateHookApi(L"ws2_32.dll", "recvfrom", &my_recvfrom, (LPVOID*)&orig_recvfrom);
        MH_CreateHookApi(L"user32.dll", "SendMessageW", &my_SendMessage, (LPVOID*)&orig_SendMessage);
        MH_CreateHookApi(L"ws2_32.dll", "WSARecv", &my_WSARecv, (LPVOID*)&orig_WSARecv);
        MH_CreateHookApi(L"ws2_32.dll", "WSARecvFrom", &my_WSARecvFrom, (LPVOID*)&orig_WSARecvFrom);
        MH_CreateHookApi(L"ws2_32.dll", "WSASend", &my_WSASend, (LPVOID*)&orig_WSASend);
        MH_CreateHookApi(L"ws2_32.dll", "WSASendTo", &my_WSASendTo, (LPVOID*)&orig_WSASendTo);
        MH_CreateHookApi(L"advapi32.dll", "CryptDecrypt", &my_CryptDecrypt, (LPVOID*)&orig_CryptDecrypt);
        MH_CreateHookApi(L"advapi32.dll", "CryptEncrypt", &my_CryptEncrypt, (LPVOID*)&orig_CryptEncrypt);
        MH_CreateHookApi(L"libcrypto.dll", "EVP_DecryptUpdate", &my_EVP_DecryptUpdate, (LPVOID*)&orig_EVP_DecryptUpdate);
        MH_CreateHookApi(L"libcrypto.dll", "EVP_DecryptFinal_ex", &my_EVP_DecryptFinal_ex, (LPVOID*)&orig_EVP_DecryptFinal_ex);
        MH_CreateHookApi(L"libcrypto.dll", "EVP_EncryptUpdate", &my_EVP_EncryptUpdate, (LPVOID*)&orig_EVP_EncryptUpdate);
        MH_CreateHookApi(L"libcrypto.dll", "EVP_EncryptFinal_ex", &my_EVP_EncryptFinal_ex, (LPVOID*)&orig_EVP_EncryptFinal_ex);
        MH_CreateHookApi(L"msvcrt.dll", "memcpy", &my_memcpy, (LPVOID*)&orig_memcpy);
        MH_CreateHookApi(L"KERNEL32.dll", "ReadFile", &my_ReadFile, (LPVOID*)&orig_ReadFile);
        MH_CreateHookApi(L"KERNEL32.dll", "WriteFile", &my_WriteFile, (LPVOID*)&orig_WriteFile);
        MH_CreateHookApi(L"KERNEL32.dll", "MapViewOfFile", &my_MapViewOfFile, (LPVOID*)&orig_MapViewOfFile);
        MH_CreateHookApi(L"KERNEL32.dll", "UnmapViewOfFile", &my_UnmapViewOfFile, (LPVOID*)&orig_UnmapViewOfFile);
        MH_CreateHookApi(L"ole32.dll", "CoTaskMemAlloc", &my_CoTaskMemAlloc, (LPVOID*)&orig_CoTaskMemAlloc);
        MH_CreateHookApi(L"ole32.dll", "CoTaskMemFree", &my_CoTaskMemFree, (LPVOID*)&orig_CoTaskMemFree);

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
            log_printf("Failed to enable hooks.\n");
        else
            log_printf("[+] All hooks installed successfully.\n");

        char symPath[MAX_PATH * 2];
        if (GetEnvironmentVariable("_NT_SYMBOL_PATH", symPath, MAX_PATH * 2) == 0) {
            strcpy(symPath, "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
            SetEnvironmentVariable("_NT_SYMBOL_PATH", symPath);
        }
        SymSetSearchPath(GetCurrentProcess(), symPath);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        MH_Uninitialize();
        SymCleanup(GetCurrentProcess());
        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = NULL;
        }
    }
    return TRUE;
}
