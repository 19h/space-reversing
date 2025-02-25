#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dbghelp.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <math.h>
#include <intrin.h>  // For __int64, etc. on MSVC
#include "hook.c"    // MinHook header
#include <direct.h>  // For _mkdir, etc.

//
// Global log file pointer.
// This will point to <user dir>/zonedump.log.
//
static FILE* gLogFile = NULL;

//
// Helper logging function. This works just like printf, but writes to our log file.
// It flushes the file after writing each message.
//
void WriteLog(const char* format, ...)
{
    if (gLogFile)
    {
        va_list args;
        va_start(args, format);
        vfprintf(gLogFile, format, args);
        va_end(args);
        fflush(gLogFile);
    }
}

//--- Forward declaration of the target function.
// Adjust the calling convention and linkage as needed.
extern "C" double __fastcall sub_1470033f0(
    unsigned __int64 a1, double xmm1, double xmm2, const char *a4, ...);

//--- Typedef for the target function pointer.
typedef double (__fastcall *Sub1470033f0_t)(
    unsigned __int64, double, double, const char*, ...);

//--- Pointer to hold the original function.
Sub1470033f0_t fpSub1470033f0 = nullptr;

//--- Our instrumentation detour function.
double __fastcall Detour_sub_1470033f0(
    unsigned __int64 a1, double xmm1, double xmm2, const char *a4, ...)
{
    va_list args;
    va_start(args, a4);

    // Log the fixed part.
    WriteLog("[Hook] Called sub_1470033f0:\n"
             "       a1   = 0x%llX\n"
             "       xmm1 = %f\n"
             "       xmm2 = %f\n"
             "       a4   = %s\n", a1, xmm1, xmm2, a4);

    // Log the variadic parameters.
    // Here we assume exactly 4 extra parameters of type const char* as in our test invocation.
    const char *varArg1 = va_arg(args, const char*);
    const char *varArg2 = va_arg(args, const char*);
    const char *varArg3 = va_arg(args, const char*);
    const char *varArg4 = va_arg(args, const char*);

    WriteLog("[Hook] Variadic arguments:\n"
             "       arg1: %s\n"
             "       arg2: %s\n"
             "       arg3: %s\n"
             "       arg4: %s\n", varArg1, varArg2, varArg3, varArg4);

    // Call the original function, forwarding the extracted variadic parameters.
    double ret = fpSub1470033f0(a1, xmm1, xmm2, a4,
                                   varArg1, varArg2, varArg3, varArg4);

    va_end(args);

    WriteLog("[Hook] Returning: %f\n", ret);

    return ret;
}

/* foo9.c */
#ifdef __cplusplus
extern "C" {
#endif

// Dummy implementation of sub_1470033f0 to resolve linking error.
// In a real-world scenario, this would be provided by the
// module you intend to hook or instrument.
double __fastcall sub_1470033f0(unsigned __int64 a1, double xmm1, double xmm2, const char *a4, ...)
{
    va_list args;
    va_start(args, a4);
    // (Optional) Process additional arguments or add custom logic.
    va_end(args);

    // Return a dummy value.
    return 0.0;
}

#ifdef __cplusplus
}
#endif

DWORD WINAPI HookThread(LPVOID)
{
    // Build the log file path in the user's home directory.
    // The environment variable "USERPROFILE" is used to locate the user folder.
    char *userDir = getenv("USERPROFILE");
    char logFilePath[MAX_PATH] = {0};
    if (userDir)
    {
        snprintf(logFilePath, MAX_PATH, "%s\\zonedump.log", userDir);
    }
    else
    {
        // If USERPROFILE is not available, fallback to the current directory.
        snprintf(logFilePath, MAX_PATH, "zonedump.log");
    }

    // Open the log file in append mode.
    gLogFile = fopen(logFilePath, "a");
    if (!gLogFile)
    {
        // If the log file cannot be opened, output the error to the debugger and abort.
        OutputDebugStringA("Failed to open log file zonedump.log\n");
        return 1;
    }

    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        WriteLog("MH_Initialize failed\n");
        fclose(gLogFile);
        gLogFile = NULL;
        return 1;
    }

    // Create a hook for the target function.
    if (MH_CreateHook(
            reinterpret_cast<LPVOID>(sub_1470033f0),
            reinterpret_cast<LPVOID>(Detour_sub_1470033f0),
            reinterpret_cast<LPVOID*>(&fpSub1470033f0)) != MH_OK)
    {
        WriteLog("MH_CreateHook failed\n");
        MH_Uninitialize();
        fclose(gLogFile);
        gLogFile = NULL;
        return 1;
    }

    // Enable the hook.
    if (MH_EnableHook(reinterpret_cast<LPVOID>(sub_1470033f0)) != MH_OK)
    {
        WriteLog("MH_EnableHook failed\n");
        MH_Uninitialize();
        fclose(gLogFile);
        gLogFile = NULL;
        return 1;
    }

    // --- Example call to the hooked function.
    // Using an actual call with varargs.
    const char *v85 = "ZoneName";
    char v103[256] = {0};
    // Fill v103 with dummy data so that v103, &v103[64], and &v103[128] are valid C-strings.
    memset(v103, 'A', sizeof(v103) - 1);
    v103[sizeof(v103) - 1] = '\0';

    double result = sub_1470033f0(0xDEADBEEF, 1.234, 5.678,
                                      "Zone: %s Pos: %s %s %s", v85, v103, &v103[64], &v103[128]);
    WriteLog("Result: %f\n", result);

    // Remove the hook and uninitialize MinHook.
    //MH_DisableHook(reinterpret_cast<LPVOID>(sub_1470033f0));
    //MH_Uninitialize();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        if (gLogFile)
        {
            fclose(gLogFile);
            gLogFile = NULL;
        }
        break;
    }
    return TRUE;
}
