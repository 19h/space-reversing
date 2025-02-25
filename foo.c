// File: decrypt_hook.c

#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dbghelp.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include "hook.c"  // MinHook header
#include <direct.h>

#pragma comment(lib, "MinHook.lib")

// Dump decrypted data to a file named with the current microtimestamp in "$HOME/sc_dumps".
void dump_message(const char *buf, int len)
{
    const char *home = getenv("HOME");
    if (!home)
        home = getenv("USERPROFILE");
    if (!home)
        home = ".";
    char dumpDir[512];
    sprintf(dumpDir, "%s\\sc_dumps", home);
    _mkdir(dumpDir);
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    const unsigned long long EPOCH_DIFF = 116444736000000000ULL;
    unsigned long long microtimestamp = (uli.QuadPart - EPOCH_DIFF) / 10;
    char filePath[1024];
    sprintf(filePath, "%s\\%llu.bin", dumpDir, microtimestamp);
    FILE *f = fopen(filePath, "wb");
    if (f)
    {
        fwrite(buf, 1, len, f);
        fclose(f);
    }
}

/*
   Decryption function signature (decompiled):
     void UndefinedFunction_147b20fa0(undefined8 *p1, int p2,
                                       void *buf, ulonglong len,
                                       int *err);
   For our hook, we define:
     p1: internal context pointer
     p2: connection index
     buf: caller's plaintext output buffer
     len: maximum requested output length
     err: pointer to error code
*/
typedef void (*decrypt_func_t)(void *p1, int p2, void *buf, unsigned long long len, int *err);
static decrypt_func_t orig_decrypt = NULL;

// Our hook logs all incoming arguments, calls the original function into a temporary buffer,
// dumps the decrypted plaintext if decryption succeeded, then copies the data into the caller's buffer.
void my_decrypt(void *p1, int p2, void *buf, unsigned long long len, int *err)
{
    // --- Decorated logging of input arguments ---
    printf("============================================\n");
    printf("[my_decrypt] Hook invoked.\n");
    printf("  p1   (context pointer): %p\n", p1);
    printf("  p2   (connection index): %d\n", p2);
    printf("  buf  (output buffer ptr): %p\n", buf);
    printf("  len  (requested length) : %llu\n", len);
    if (err)
        printf("  err  (error pointer)    : %p, *err = %d\n", err, *err);
    else
        printf("  err  (error pointer)    : NULL\n");
    printf("============================================\n");

    void *tempBuffer = malloc(len);
    if (!tempBuffer)
    {
        printf("[my_decrypt] Memory allocation failed; calling original decrypt.\n");
        orig_decrypt(p1, p2, buf, len, err);
        return;
    }

    // Call original decryption into temporary buffer.
    orig_decrypt(p1, p2, tempBuffer, len, err);

    // On successful decryption (*err == 0), assume decrypted length equals len.
    int decryptedLen = (err && *err == 0) ? (int)len : 0;
    if (decryptedLen > 0)
    {
        printf("[my_decrypt] Decryption succeeded. Dumping %d bytes of data.\n", decryptedLen);
        dump_message((const char *)tempBuffer, decryptedLen);
    }
    else
    {
        printf("[my_decrypt] Decryption failed or produced zero-length output.\n");
    }

    memcpy(buf, tempBuffer, decryptedLen);
    free(tempBuffer);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() != MH_OK)
            return FALSE;
        if (MH_CreateHook((LPVOID)0x147b20fa0, &my_decrypt, (LPVOID *)&orig_decrypt) != MH_OK)
        {
            // Optional: error handling.
        }
        if (MH_EnableHook((LPVOID)0x147b20fa0) != MH_OK)
        {
            // Optional: error handling.
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
    }
    return TRUE;
}
