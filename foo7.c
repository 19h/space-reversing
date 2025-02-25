// File: celestial_hook.c

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

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// --------------------------------------------------------------------------
// Helper functions (backtrace, hexdump, logging, etc.) – similar to socket_hook.c
// --------------------------------------------------------------------------

static FILE *g_logFile = NULL;

static void log_printf(const char *fmt, ...)
{
    if (g_logFile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fflush(g_logFile);
    }
}

void hexdump(const void *data, size_t size)
{
    const unsigned char *p = (const unsigned char*)data;
    char line[100];
    char ascii[17];
    ascii[16] = '\0';

    for (size_t i = 0; i < size; i += 16) {
        int linePos = sprintf(line, "%08zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                linePos += sprintf(line + linePos, "%02x ", p[i + j]);
                ascii[j] = (p[i + j] >= 32 && p[i + j] < 127) ? p[i + j] : '.';
            } else {
                linePos += sprintf(line + linePos, "   ");
                ascii[j] = ' ';
            }
        }
        sprintf(line + linePos, " %s\n", ascii);
        log_printf("%s", line);
    }
}

void print_backtrace(void)
{
    void* stack[62];
    USHORT frames = CaptureStackBackTrace(0, 62, stack, NULL);
    HMODULE hMain = GetModuleHandle(NULL);
    MODULEINFO modInfo = {0};
    if (!GetModuleInformation(GetCurrentProcess(), hMain, &modInfo, sizeof(modInfo))) {
        log_printf("Failed to get module information.\n");
        return;
    }
    DWORD64 base = (DWORD64)hMain;
    DWORD64 modSize = modInfo.SizeOfImage;
    char buffer[1024];

    for (USHORT i = 0; i < frames; i++) {
        DWORD64 addr = (DWORD64)stack[i];
        SYMBOL_INFO *symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char));
        if (!symbol)
            continue;
        memset(symbol, 0, sizeof(SYMBOL_INFO) + 256 * sizeof(char));
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 255;
        DWORD64 displacement = 0;
        if (SymFromAddr(GetCurrentProcess(), addr, &displacement, symbol)) {
            if (addr >= base && addr < base + modSize) {
                DWORD64 offset = addr - base;
                sprintf(buffer, "ModuleBase+0x%llx %s", offset, symbol->Name);
            } else {
                sprintf(buffer, "%s+0x%llx", symbol->Name, displacement);
            }
        } else {
            sprintf(buffer, "0x%llx", addr);
        }
        log_printf("%s\n", buffer);
        free(symbol);
    }
}

// --------------------------------------------------------------------------
// Definitions of “absolute” addresses for the target functions.
// In a real scenario these addresses must be determined and adjusted as needed.
// --------------------------------------------------------------------------
#define CELESTIAL_TRANSFORM_ADDR    ((LPVOID)0x146f4e0f0)
#define QUATERNION_TRANSFORM_ADDR   ((LPVOID)0x14666bb10)
#define GLOBAL_TRANSFORM_ADDR       ((LPVOID)0x14702e5c0)

// --------------------------------------------------------------------------
// Typedefs for the functions we wish to hook.
// (These prototypes are best–guess based on our analysis.)
// --------------------------------------------------------------------------

// Example: A function that applies a rotation/transform to an entity.
// Prototype: void FUN_146f4e0f0(long long param1, float* matrix, unsigned long long param3, unsigned long long param4)
typedef void (*celestial_transform_t)(long long, float*, unsigned long long, unsigned long long);

// Example: A function that uses vectorized operations to compute a quaternion transform.
// Prototype: unsigned long long* FUN_14666bb10(double* param1, u_int* param2, u_int param3)
typedef unsigned long long* (*quaternion_transform_t)(double*, u_int*, u_int);

// Example: A function that computes a “global” transform matrix.
// Prototype: float* FUN_14702e5c0(long long param1, float* matrix, unsigned long long param3, unsigned long long param4)
typedef float* (*global_transform_t)(long long, float*, unsigned long long, unsigned long long);

// --------------------------------------------------------------------------
// Global variables to store original function pointers.
static celestial_transform_t orig_celestial_transform = NULL;
static quaternion_transform_t orig_quaternion_transform = NULL;
static global_transform_t     orig_global_transform = NULL;

// --------------------------------------------------------------------------
// Hook implementations
// --------------------------------------------------------------------------

// Hook for celestial_transform (FUN_146f4e0f0)
void my_celestial_transform(long long param1, float *matrix, unsigned long long param3, unsigned long long param4)
{
    log_printf("\n[+] Hooked celestial_transform (FUN_146f4e0f0) called:\n");
    log_printf("    param1 = 0x%llx, matrix = %p, param3 = 0x%llx, param4 = 0x%llx\n",
               param1, matrix, param3, param4);
    print_backtrace();

    if (matrix) {
        log_printf("    [Before] Matrix contents:\n");
        hexdump(matrix, 64); // assuming a 4x4 float matrix (16 floats = 64 bytes)
    }

    // Call the original function.
    orig_celestial_transform(param1, matrix, param3, param4);

    if (matrix) {
        log_printf("    [After] Matrix contents:\n");
        hexdump(matrix, 64);
    }
    log_printf("    [celestial_transform] completed.\n");
}

// Hook for quaternion_transform (FUN_14666bb10)
unsigned long long* my_quaternion_transform(double *param1, u_int *param2, u_int param3)
{
    log_printf("\n[+] Hooked quaternion_transform (FUN_14666bb10) called:\n");
    log_printf("    param1 = %p, param2 = %p, param3 = %u\n", param1, param2, param3);
    print_backtrace();

    if (param1) {
        log_printf("    [Input] Quaternion components:\n");
        hexdump(param1, sizeof(double)*4);
    }
    // Optionally, dump the u_int array if its size is known.
    unsigned long long* ret = orig_quaternion_transform(param1, param2, param3);
    log_printf("    [Return] Result pointer = %p\n", ret);
    if (ret) {
        hexdump(ret, 64);
    }
    return ret;
}

// Hook for global_transform (FUN_14702e5c0)
float* my_global_transform(long long param1, float *matrix, unsigned long long param3, unsigned long long param4)
{
    log_printf("\n[+] Hooked global_transform (FUN_14702e5c0) called:\n");
    log_printf("    param1 = 0x%llx, matrix = %p, param3 = 0x%llx, param4 = 0x%llx\n",
               param1, matrix, param3, param4);
    print_backtrace();

    if (matrix) {
        log_printf("    [Before] Matrix dump:\n");
        hexdump(matrix, 64);
    }

    float* ret = orig_global_transform(param1, matrix, param3, param4);

    log_printf("    [After] Matrix dump:\n");
    if (matrix) {
        hexdump(matrix, 64);
    }
    return ret;
}

// --------------------------------------------------------------------------
// DLL Main: Set up hooks similar to socket_hook.c example
// --------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        // Open log file in user's home directory.
        char *home = getenv("USERPROFILE");
        if (!home) {
            home = "C:\\";
        }
        char logPath[512];
        sprintf(logPath, "%s\\celestial_dump.log", home);
        g_logFile = fopen(logPath, "a+");
        if (!g_logFile) {
            g_logFile = fopen("celestial_dump.log", "a+");
        }

        // Initialize symbol handler.
        if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
            log_printf("Failed to initialize DbgHelp.\n");
        }

        // Initialize MinHook.
        if (MH_Initialize() != MH_OK) {
            log_printf("Failed to initialize MinHook.\n");
            return FALSE;
        }

        // Create hooks for the three functions.

        if (MH_CreateHook(CELESTIAL_TRANSFORM_ADDR, &my_celestial_transform, (LPVOID*)&orig_celestial_transform) != MH_OK) {
            log_printf("Failed to hook celestial_transform (FUN_146f4e0f0) at %p.\n", CELESTIAL_TRANSFORM_ADDR);
        }
        else {
            log_printf("[+] Hooked celestial_transform (FUN_146f4e0f0) at %p.\n", CELESTIAL_TRANSFORM_ADDR);
        }

        // if (MH_CreateHook(QUATERNION_TRANSFORM_ADDR, &my_quaternion_transform, (LPVOID*)&orig_quaternion_transform) != MH_OK) {
        //     log_printf("Failed to hook quaternion_transform (FUN_14666bb10) at %p.\n", QUATERNION_TRANSFORM_ADDR);
        // }
        // else {
        //     log_printf("[+] Hooked quaternion_transform (FUN_14666bb10) at %p.\n", QUATERNION_TRANSFORM_ADDR);
        // }

        // if (MH_CreateHook(GLOBAL_TRANSFORM_ADDR, &my_global_transform, (LPVOID*)&orig_global_transform) != MH_OK) {
        //     log_printf("Failed to hook global_transform (FUN_14702e5c0) at %p.\n", GLOBAL_TRANSFORM_ADDR);
        // }
        // else {
        //     log_printf("[+] Hooked global_transform (FUN_14702e5c0) at %p.\n", GLOBAL_TRANSFORM_ADDR);
        // }

        // Enable all hooks.
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            log_printf("Failed to enable hooks.\n");
        }
        else {
            log_printf("[+] All hooks enabled.\n");
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
        SymCleanup(GetCurrentProcess());
        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = NULL;
        }
    }
    return TRUE;
}
