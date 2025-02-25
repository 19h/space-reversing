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
#include <intrin.h>  /* For __int64, etc. on MSVC */
#include "hook.c"    /* MinHook header */
#include <direct.h>  /* For _mkdir, etc. */

/* Function signature for sub_147000270 */
typedef void (__fastcall *fn_sub_147000270)(__int64 a1, __int64 a2, int a3);
static fn_sub_147000270 orig_sub_147000270 = NULL;

/* Global pointer to zone manager */
static __int64* g_zoneMgrPtr = (__int64*)0x1497EA428; /* Placeholder address, replace with actual */

/* ZoneObjectVTable struct */
struct ZoneObjectVTable {
    __int64 (__fastcall *GetNext)(void* thisPtr);                             /* offset +0x08 */
    void (*GetPositions)(void* thisPtr, double* outX, double* outY, double* outZ); /* offset ~ +0xF8 or +0x100 */
    __int64 (__fastcall *GetZoneName)(void* thisPtr);                         /* offset ~ +0x1F0 */
};

/* ZoneObject struct */
struct ZoneObject {
    struct ZoneObjectVTable* vfptr;
    /* other fields omitted for simplicity */
};

/* Function signature for getting zones */
typedef __int64 (__fastcall *fnGetZoneFunc)(void* zoneMgrObj, __int64 zoneID);

/* Utility: log_info - Append messages to a log file */
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

/* Utility: Format a distance as meters or kilometers */
static void formatDistance(char* outBuf, size_t outBufSize, double dist)
{
    double ad = fabs(dist);
    if (ad < 10000.0)
        snprintf(outBuf, outBufSize, "%.2fm", dist);
    else
        snprintf(outBuf, outBufSize, "%.4fkm", dist / 1000.0);
}

/* Hooked function: my_sub_147000270 */
void __fastcall my_sub_147000270(__int64 a1, __int64 a2, int a3)
{
    /* Call the original function */
    orig_sub_147000270(a1, a2, a3);

    /* Skip if debug flag is 0 */
    if (a3 == 0) {
        return;
    }

    /* Camera angle calculations */
    const __int64 camBase = a1 + 1232;
    double dVal40 = *(double *)(camBase + 0x40);
    double dVal08 = *(double *)(camBase + 0x08);
    double dVal48 = *(double *)(camBase + 0x48);
    double dVal50 = *(double *)(camBase + 0x50);
    double dVal00 = *(double *)(camBase + 0x00);
    double dVal20 = *(double *)(camBase + 0x20);

    float fVal40 = (float)dVal40;
    float arcInput = -fVal40;
    if (arcInput > 1.0f)  arcInput = 1.0f;
    if (arcInput < -1.0f) arcInput = -1.0f;
    float angleAsin = asinf(arcInput);

    float tmp = fabsf(angleAsin);
    tmp = fabsf(tmp - 1.5707964f); /* pi/2 */
    int nearPiOver2 = (tmp < 0.01f); /* 1 if true, 0 if false */

    float angleB = 0.0f;
    float fSecondY;
    if (nearPiOver2) {
        angleAsin = 0.0f;
        float fVal08 = (float)dVal08;
        fSecondY = -fVal08;
    } else {
        float fVal48 = (float)dVal48;
        float fVal50 = (float)dVal50;
        angleB = atan2f(fVal48, fVal50);
        fSecondY = (float)dVal20;
    }

    float angleAsinDeg = angleAsin * (180.0f / 3.1415926535f);
    float angleBDeg    = angleB    * (180.0f / 3.1415926535f);

    float fVal00 = (float)dVal00;
    float angleC = atan2f(fSecondY, fVal00);
    float angleCDeg = angleC * (180.0f / 3.1415926535f);

    /* Zone iteration */
    int zoneID = *(int *)(camBase + 0xA8);
    if (zoneID == -1) {
        return;
    }

    if (g_zoneMgrPtr && *g_zoneMgrPtr) {
        void* zoneMgrObj = (void*)(*g_zoneMgrPtr);
        __int64 vtbl = *( (__int64*)zoneMgrObj );
        __int64 funcAddr = *( (__int64*)(vtbl + 0x68) );
        fnGetZoneFunc getZonesFunc = (fnGetZoneFunc)funcAddr;

        if (getZonesFunc) {
            __int64 zoneAddr = getZonesFunc(zoneMgrObj, zoneID);
            struct ZoneObject* zone = (struct ZoneObject*)zoneAddr;

            int firstZone = 1;

            while (zone) {
                struct ZoneObjectVTable* vf = zone->vfptr;
                if (!vf) {
                    break;
                }

                double X = 0.0, Y = 0.0, Z = 0.0;
                if (vf->GetPositions) {
                    vf->GetPositions(zone, &X, &Y, &Z);
                }

                char bufX[64] = {0}, bufY[64] = {0}, bufZ[64] = {0};
                formatDistance(bufX, sizeof(bufX), X);
                formatDistance(bufY, sizeof(bufY), Y);
                formatDistance(bufZ, sizeof(bufZ), Z);

                if (a3 >= 2 && firstZone) {
                    /* Extra logging can be added here if needed */
                    firstZone = 0;
                }

                const char* zoneName = "Unknown";
                if (vf->GetZoneName) {
                    __int64 pName = vf->GetZoneName(zone);
                    if (pName) {
                        zoneName = (const char*)pName;
                    }
                }

                log_info("[my_sub_147000270] Zone Dump:\n");
                log_info("    Name: %s\n", zoneName);
                log_info("    Pos: %s, %s, %s\n\n", bufX, bufY, bufZ);

                if (vf->GetNext) {
                    __int64 nextZoneAddr = vf->GetNext(zone);
                    zone = (struct ZoneObject*)nextZoneAddr;
                } else {
                    break;
                }
            }
        }
    }
}

/* Hook installation with MinHook */
DWORD WINAPI HookThread(LPVOID param)
{
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "MH_Initialize failed!", "Error", MB_ICONERROR);
        return 0;
    }

    /* Hook sub_147000270 */
    void* targetAddr1 = (void*)0x147000270; /* Replace with actual address */
    if (MH_CreateHook(targetAddr1, (LPVOID)my_sub_147000270, (LPVOID*)&orig_sub_147000270) != MH_OK) {
        MessageBoxA(NULL, "MH_CreateHook for sub_147000270 failed!", "Error", MB_ICONERROR);
        return 0;
    }
    if (MH_EnableHook(targetAddr1) != MH_OK) {
        MessageBoxA(NULL, "MH_EnableHook for sub_147000270 failed!", "Error", MB_ICONERROR);
        return 0;
    }

    MessageBoxA(NULL, "Hooks installed successfully!", "Success", MB_ICONINFORMATION);
    return 0;
}

/* DLL entry point */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
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