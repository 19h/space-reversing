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

////////////////////////////////////////////////////////////////////////////////
// Global / external references
////////////////////////////////////////////////////////////////////////////////

// We assume the game’s sub_147000270 has signature: void __fastcall sub_147000270(__int64 a1, __int64 a2, int a3)
typedef void(__fastcall *fn_sub_147000270)(__int64 a1, __int64 a2, int a3);
static fn_sub_147000270 orig_sub_147000270 = nullptr;

// Example global pointer to a zone manager (update for your real project)
static __int64* g_zoneMgrPtr = (__int64*)(0x1497EA428); // placeholder address

// Example zone object vtable layout
struct ZoneObjectVTable {
    // ...
    __int64(__fastcall* GetNext)(void* thisPtr);                              // offset +0x08
    // ...
    void (*GetPositions)(void* thisPtr, double* outX, double* outY, double* outZ); // offset +0xF8 or +0x100 or etc.
    // ...
    __int64(__fastcall* GetZoneName)(void* thisPtr);                          // offset +0x1F0 or so
    // ...
};

struct ZoneObject {
    ZoneObjectVTable* vfptr;
    // other fields...
};

typedef __int64 (__fastcall *fnGetZoneFunc)(void* zoneMgrObj, __int64 zoneID);

////////////////////////////////////////////////////////////////////////////////
// Utility: log_info(...) - Append messages to a log file.
////////////////////////////////////////////////////////////////////////////////
void log_info(const char* format, ...)
{
    const char* home = getenv("HOME");
    if (!home) home = getenv("USERPROFILE");
    if (!home) home = ".";

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s\\hook_log.txt", home);

    FILE* fp = fopen(filepath, "a");
    if (!fp) return;

    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fclose(fp);
}

////////////////////////////////////////////////////////////////////////////////
// Utility: Format a distance as meters or km
////////////////////////////////////////////////////////////////////////////////
static void formatDistance(char* outBuf, size_t outBufSize, double dist)
{
    // If the absolute distance is < 10,000, show as meters.
    // Otherwise, convert to km with more precision.
    double ad = fabs(dist);
    if (ad < 10000.0)
        snprintf(outBuf, outBufSize, "%.2fm", dist);
    else
        snprintf(outBuf, outBufSize, "%.4fkm", dist / 1000.0);
}

////////////////////////////////////////////////////////////////////////////////
// Hooked function: my_sub_147000270
//  - Calls the original function so the game logic still runs
//  - Then replicates and logs the "camera math" and "zone iteration" that
//    we deduced from the reverse-engineered code.
////////////////////////////////////////////////////////////////////////////////
void __fastcall my_sub_147000270(__int64 a1, __int64 a2, int a3)
{
    ////////////////////////////////////////////////////////////////////////////
    // 1. Call the game’s real function to preserve original behavior
    ////////////////////////////////////////////////////////////////////////////
    orig_sub_147000270(a1, a2, a3);

    ////////////////////////////////////////////////////////////////////////////
    // 2. If the debug flag (a3) == 0, skip all extra instrumentation
    ////////////////////////////////////////////////////////////////////////////
    if (a3 == 0) {
        return;
    }

    ////////////////////////////////////////////////////////////////////////////
    // 3. Reconstruct the camera angle math from sub_147000270
    //
    //    The game apparently uses the structure at (a1 + 1232). We'll call that
    //    'camBase'. Offsets are from the final reversed code snippet. Adjust to
    //    your real offsets if they differ.
    ////////////////////////////////////////////////////////////////////////////
    const __int64 camBase = a1 + 1232;

    // The code loads multiple double-precision values, e.g.:
    //   double val40 = *(double *)(camBase + 0x40);   // arcsin input
    //   double val08 = *(double *)(camBase + 0x08);   // used for sign-flip if near ±π/2
    //   double val48 = *(double *)(camBase + 0x48);   // used for first atan2
    //   double val50 = *(double *)(camBase + 0x50);
    //   double val00 = *(double *)(camBase + 0x00);   // used for second atan2 X
    //   double val20 = *(double *)(camBase + 0x20);   // the "default" Y for second atan2
    //
    // For demonstration, let's read a few that matter for the arcsin and the 2x atan2:
    double dVal40 = *(double *)(camBase + 0x40);
    double dVal08 = *(double *)(camBase + 0x08);
    double dVal48 = *(double *)(camBase + 0x48);
    double dVal50 = *(double *)(camBase + 0x50);
    double dVal00 = *(double *)(camBase + 0x00);
    double dVal20 = *(double *)(camBase + 0x20);

    // Step A: Convert dVal40 to float, flip sign bit => -fVal40
    float fVal40 = (float)dVal40;
    float arcInput = -fVal40;

    // Step B: clamp arcInput to [-1, +1], then asinf
    if (arcInput > 1.0f)  arcInput = 1.0f;
    if (arcInput < -1.0f) arcInput = -1.0f;
    float angleAsin = asinf(arcInput);

    // Step C: check if near ±π/2 using double absolute:
    //   tmp = | |angleAsin| - (π/2) |
    //   if tmp < some_threshold => zero out angleAsin, sign-flip (float)dVal08 => fVal20
    float tmp = fabsf(angleAsin);
    tmp = fabsf(tmp - 1.5707964f); // π/2 ~ 1.5707963267
    bool nearPiOver2 = (tmp < 0.01f); // example threshold

    float angleB = 0.0f;   // first atan2, sometimes used
    float fSecondY;        // Y for second atan2

    if (nearPiOver2) {
        // Zero out the arcsin angle
        angleAsin = 0.0f;
        // fVal20 = - (float)dVal08
        float fVal08 = (float)dVal08;
        fSecondY = -fVal08;
    } else {
        // angleB = atan2f( (float)dVal48, (float)dVal50 )
        float fVal48 = (float)dVal48;
        float fVal50 = (float)dVal50;
        angleB = atan2f(fVal48, fVal50);

        // For the second atan2, we keep Y = (float)dVal20
        fSecondY = (float)dVal20;
    }

    // Step D: convert angleAsin and angleB to degrees (if you want)
    float angleAsinDeg = angleAsin * (180.0f / 3.1415926535f);
    float angleBDeg    = angleB    * (180.0f / 3.1415926535f);

    // Step E: unconditionally do the second atan2 => angleC
    float fVal00 = (float)dVal00;
    float angleC = atan2f(fSecondY, fVal00);
    float angleCDeg = angleC * (180.0f / 3.1415926535f);

    // Log what we found
    //log_info("[my_sub_147000270] ---------------------------------------------------\n");
    //log_info("[my_sub_147000270] debugFlag(a3) = %d\n", a3);
    //log_info("[my_sub_147000270] angleAsinDeg = %.4f\n", angleAsinDeg);
    //log_info("[my_sub_147000270] angleB   Deg = %.4f\n", angleBDeg);
    //log_info("[my_sub_147000270] angleC   Deg = %.4f\n\n", angleCDeg);

    ////////////////////////////////////////////////////////////////////////////
    // 4. Iterate over zones if the zone ID at offset +168 != -1
    //    (Matches the reversed logic: if *(int *)(rdi+168) != -1 => do zone logic)
    ////////////////////////////////////////////////////////////////////////////
    log_info("[camBase] %p\n", camBase);
    log_info("[*(int *)(camBase + 0xA8)] %d\n", *(int *)(camBase + 0xA8));
    
    // int zoneID = *(int *)(camBase + 0xA8);
    // if (zoneID == -1) {
    //     return;  // No valid zone
    // }

    // // We get the first zone object by calling a function pointer at offset +104
    // // from the global zoneMgr.  Something like:
    // //    zoneObj = (ZoneObject*)( (*funcPtr)() );
    // log_info("[g_zoneMgrPtr] %p\n", g_zoneMgrPtr);
    // log_info("[*g_zoneMgrPtr] %p\n", *g_zoneMgrPtr);

    // ZoneObject* (*getZonesFunc)() = nullptr;
    // ZoneObject* zone = nullptr;
    // if (g_zoneMgrPtr && *g_zoneMgrPtr) {
    //     // First, get the zone manager instance (object)
    //     void* zoneMgrObj = reinterpret_cast<void*>(*g_zoneMgrPtr);
        
    //     // Now, read the vtable pointer from the object’s first field.
    //     __int64 vtbl = *reinterpret_cast<__int64*>(zoneMgrObj);
    //     log_info("[ZoneMgr::vtable] %p\n", reinterpret_cast<void*>(vtbl));
        
    //     // Now log the function pointer at the correct offset (0x68 = 104 decimal).
    //     log_info("[vtbl offset +0x68] %p\n", *(__int64*)(vtbl + 0x68));
        
    //     // Use the function pointer from offset 0x68 (which was written as 104 in your code)
    //     __int64 funcAddr = *(__int64*)(vtbl + 0x68);
    //     //ZoneObject* (*getZonesFunc)() = reinterpret_cast<ZoneObject*(*)()>(funcAddr);
    //     //ZoneObject* (*getZonesFunc)(void*, signed __int64) = reinterpret_cast<ZoneObject* (*)(void*, signed __int64)>(funcAddr);
    //     fnGetZoneFunc getZonesFunc = reinterpret_cast<fnGetZoneFunc>(funcAddr);

    //     log_info("[getZonesFunc] %p\n", getZonesFunc);

    //     if (getZonesFunc) {
    //         //zone = getZonesFunc();
    //         //zone = getZonesFunc(reinterpret_cast<void*>(*g_zoneMgrPtr), zoneID);
    //         zone = reinterpret_cast<ZoneObject*>(getZonesFunc(reinterpret_cast<void*>(*g_zoneMgrPtr), zoneID));

    //         log_info("[zone] %p\n", zone);

    //         bool firstZone = true;

    //         while (zone) {
    //             log_info("[my_sub_147000270] Processing zone at address: %p\n", zone);

    //             // Pull out the vtable
    //             ZoneObjectVTable* vf = zone->vfptr;
    //             if (!vf) {
    //                 log_info("[my_sub_147000270] VTable pointer is null for zone at address: %p. Exiting loop.\n", zone);
    //                 break;
    //             }
    //             log_info("[my_sub_147000270] Retrieved VTable pointer: %p\n", vf);

    //             // Fetch positions => vtable offset ~ +248 in the original code
    //             // but let's just assume it's stored in "vf->GetPositions"
    //             double X = 0.0, Y = 0.0, Z = 0.0;
    //             if (vf->GetPositions) {
    //                 log_info("[my_sub_147000270] Calling GetPositions for zone at address: %p\n", zone);
    //                 vf->GetPositions(zone, &X, &Y, &Z);
    //                 log_info("[my_sub_147000270] GetPositions returned: X = %f, Y = %f, Z = %f\n", X, Y, Z);
    //             } else {
    //                 log_info("[my_sub_147000270] GetPositions function pointer is null in VTable.\n");
    //             }

    //             // Format distances
    //             char bufX[64] = {0}, bufY[64] = {0}, bufZ[64] = {0};
    //             formatDistance(bufX, sizeof(bufX), X);
    //             formatDistance(bufY, sizeof(bufY), Y);
    //             formatDistance(bufZ, sizeof(bufZ), Z);
    //             log_info("[my_sub_147000270] Formatted distances: bufX = '%s', bufY = '%s', bufZ = '%s'\n", bufX, bufY, bufZ);

    //             // If a3 >= 2 and it's the first zone, do extra logging
    //             if (a3 >= 2 && firstZone) {
    //                 log_info("[my_sub_147000270] debugFlag (a3) >= 2: performing extra camera info logging for the first zone.\n");
    //                 // Example extra logging could include additional camera parameters or recalculated angles.
    //                 firstZone = false;
    //                 log_info("[my_sub_147000270] First zone extra logging has been performed.\n");
    //             }

    //             // Get zone name => offset +496 in original, which we called "GetZoneName"
    //             const char* zoneName = "Unknown";
    //             if (vf->GetZoneName) {
    //                 log_info("[my_sub_147000270] Calling GetZoneName for zone at address: %p\n", zone);
    //                 __int64 pName = vf->GetZoneName(zone);
    //                 if (pName) {
    //                     zoneName = (const char*)pName;
    //                     log_info("[my_sub_147000270] Retrieved zone name: %s\n", zoneName);
    //                 } else {
    //                     log_info("[my_sub_147000270] GetZoneName returned null pointer, defaulting zone name to 'Unknown'.\n");
    //                 }
    //             } else {
    //                 log_info("[my_sub_147000270] GetZoneName function pointer is null in VTable, using default zone name 'Unknown'.\n");
    //             }

    //             // Log zone info
    //             log_info("[my_sub_147000270] Zone Dump:\n");
    //             log_info("    Name: %s\n", zoneName);
    //             log_info("    Pos: %s, %s, %s\n\n", bufX, bufY, bufZ);

    //             // Next zone => offset +8 in the original decomp => “GetNext”
    //             if (vf->GetNext) {
    //                 ZoneObject* nextZone = (ZoneObject*)vf->GetNext(zone);
    //                 log_info("[my_sub_147000270] Retrieved next zone pointer: %p\n", nextZone);
    //                 zone = nextZone;
    //             } else {
    //                 log_info("[my_sub_147000270] GetNext function pointer is null in VTable. Exiting loop.\n");
    //                 break;
    //             }
    //         }
    //     }
    // }
}

typedef double(__fastcall *fnSub_7D58FDA043F0)(unsigned __int64 a1, double xmm1, double xmm2, 
                                                 const char *a4, int arg1, int arg2);
static fnSub_7D58FDA043F0 orig_sub_7D58FDA043F0 = nullptr;
// Our hooked function
double __fastcall my_sub_7D58FDA043F0(unsigned __int64 a1, double xmm1, double xmm2, 
                                       const char *a4, int arg1, int arg2)
{
    // Call the original function using our trampoline provided by MinHook.
    double result = orig_sub_7D58FDA043F0(a1, xmm1, xmm2, a4, arg1, arg2);

    // “Syphon off” the return value – log it, save it, etc.
    log_info("[sub_7D58FDA043F0] returned: %f\n", result);

    // Return the result so the game continues as normal.
    return result;
}

////////////////////////////////////////////////////////////////////////////////
// Hook installation with MinHook
////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI HookThread(LPVOID)
{
    if (MH_Initialize() != MH_OK)
    {
        MessageBoxA(NULL, "MH_Initialize failed!", "Error", MB_ICONERROR);
        return 0;
    }

    // This is where you put the actual address of sub_147000270 in memory.
    // In real usage, you might find this address with a pattern scan or a
    // static offset from the module base.  We'll just pretend it's 0x147000270:
    // void* targetAddr = (void*)0x147000270;

    // // Create the hook, substituting our "my_sub_147000270".
    // if (MH_CreateHook(
    //     targetAddr,
    //     reinterpret_cast<LPVOID>(my_sub_147000270),
    //     reinterpret_cast<LPVOID*>(&orig_sub_147000270)) != MH_OK)
    // {
    //     MessageBoxA(NULL, "MH_CreateHook failed!", "Error", MB_ICONERROR);
    //     return 0;
    // }

    // if (MH_EnableHook(targetAddr) != MH_OK)
    // {
    //     MessageBoxA(NULL, "MH_EnableHook failed!", "Error", MB_ICONERROR);
    //     return 0;
    // }

    void* targetAddr = (void*)0x7D58FDA043F0;  // Replace with the real address.
    if (MH_CreateHook(targetAddr,
                    reinterpret_cast<LPVOID>(my_sub_7D58FDA043F0),
                    reinterpret_cast<LPVOID*>(&orig_sub_7D58FDA043F0)) != MH_OK)
    {
        MessageBoxA(NULL, "MH_CreateHook failed!", "Error", MB_ICONERROR);
        return 0;
    }

    MessageBoxA(NULL, "Hook installed successfully!", "Success", MB_ICONINFORMATION);
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
        break;
    }
    return TRUE;
}
