// File: parsing_hook.c
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

// -----------------------------------------------------------------------------
// Helper: Check if a memory region [addr, addr+size) is accessible (committed
// and readable) using VirtualQuery.
// Returns nonzero if accessible.
int is_memory_readable(const void *addr, size_t size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return 0;
    // Check that the region is committed and that the protection allows read.
    if (mbi.State != MEM_COMMIT)
        return 0;
    // PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
    if ((mbi.Protect & PAGE_READONLY)  ||
        (mbi.Protect & PAGE_READWRITE) ||
        (mbi.Protect & PAGE_EXECUTE_READ) ||
        (mbi.Protect & PAGE_EXECUTE_READWRITE))
    {
        // Also, check that the region covers the entire requested size.
        SIZE_T regionSize = (char *)mbi.BaseAddress + mbi.RegionSize - (char *)addr;
        return regionSize >= size;
    }
    return 0;
}

// -----------------------------------------------------------------------------
// Dump function: Dump raw data to a file whose name is based on the current
// microtimestamp.
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
        printf("[parsing_hook] Dumped %d bytes to %s\n", len, filePath);
    }
    else
    {
        printf("[parsing_hook] Failed to open dump file: %s\n", filePath);
    }
}

// -----------------------------------------------------------------------------
// Original parsing function signature (as deduced from decompilation):
//   void FUN_1476cdfa0(undefined8 *out_frame, long long transportState);
// We assume that the first parameter is a pointer to a 64-bit value (frame pointer).
typedef void (*parsing_func_t)(unsigned __int64 *out_frame, long long transportState);
static parsing_func_t orig_parsing = NULL;

// -----------------------------------------------------------------------------
// Our hook for the parsing function.
// It logs input parameters, calls the original function, and if a frame pointer
// is returned, it checks if the memory is readable before dumping a small portion
// of the frame data.
// -----------------------------------------------------------------------------
void my_parsing(unsigned __int64 *out_frame, long long transportState)
{
    printf("============================================\n");
    printf("[my_parsing] Hook invoked.\n");
    printf("  out_frame pointer address: %p\n", out_frame);
    printf("  transportState pointer   : %p\n", (void*)transportState);
    printf("============================================\n");

    // Call the original parsing function.
    orig_parsing(out_frame, transportState);

    // Check if a frame was produced.
    if (out_frame && *out_frame != 0)
    {
        // For safety, choose a conservative dump size.
        const int dumpSize = 64;
        printf("[my_parsing] Parsed frame produced at 0x%llx. Attempting to dump first %d bytes...\n",
               *out_frame, dumpSize);

        // Check that the memory is readable.
        if (is_memory_readable((const void *)*out_frame, dumpSize))
        {
#ifdef _MSC_VER
            __try {
                dump_message((const char *)*out_frame, dumpSize);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                printf("[my_parsing] Exception occurred while dumping frame memory.\n");
            }
#else
            dump_message((const char *)*out_frame, dumpSize);
#endif
        }
        else
        {
            printf("[my_parsing] Memory at 0x%llx is not readable for %d bytes; dump skipped.\n", *out_frame, dumpSize);
        }
    }
    else
    {
        printf("[my_parsing] No frame produced by parsing function.\n");
    }
    printf("============================================\n");
}

// -----------------------------------------------------------------------------
// DLL Main: Initialize MinHook and create the hook for the parsing function.
// -----------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() != MH_OK)
        {
            printf("[parsing_hook] MH_Initialize failed.\n");
            return FALSE;
        }
        
        // IMPORTANT: Verify that the address below is the correct target.
        // The hardcoded address (0x1476cdfa0) must be valid in the target process.
        if (MH_CreateHook((LPVOID)0x1476cdfa0, &my_parsing, (LPVOID *)&orig_parsing) != MH_OK)
        {
            printf("[parsing_hook] MH_CreateHook failed.\n");
            MH_Uninitialize();
            return FALSE;
        }
        
        if (MH_EnableHook((LPVOID)0x1476cdfa0) != MH_OK)
        {
            printf("[parsing_hook] MH_EnableHook failed.\n");
            MH_Uninitialize();
            return FALSE;
        }
        printf("[parsing_hook] Hook on parsing function installed successfully.\n");
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
    }
    return TRUE;
}