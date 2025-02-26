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

// Global log file pointer.
static FILE *g_logFile = NULL;

// Logging helper function.
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

// Function pointer type for the target function.
// Here we assume the target function takes one pointer argument and returns a pointer.
// Adjust the signature if needed.
typedef void* (__fastcall *fnSub146675AD0)(void* entityPtr);
static fnSub146675AD0 orig_sub_146675AD0 = NULL;

// Helper: dump many fields from the entity pointed to by entityPtr.
// The offsets below are taken from the Frida script.
static void dumpEntityFields(void* entityPtr)
{
    if (!entityPtr) {
        log_printf("[dumpEntityFields] entityPtr is NULL\n");
        return;
    }
    
    // Core fields.
    void* vtable = *(void**)entityPtr;
    unsigned long long entityId = *(unsigned long long*)((char*)entityPtr + 0x08);
    log_printf("[Entity Core] vtable: %p, entityId: %llu\n", vtable, entityId);

    // Spatial: World bounds.
    double worldMinX = *(double*)((char*)entityPtr + 0x10);
    double worldMinY = *(double*)((char*)entityPtr + 0x18);
    double worldMinZ = *(double*)((char*)entityPtr + 0x20);
    double worldMaxX = *(double*)((char*)entityPtr + 0x28);
    double worldMaxY = *(double*)((char*)entityPtr + 0x30);
    double worldMaxZ = *(double*)((char*)entityPtr + 0x38);
    log_printf("[Spatial] World Bounds: min(%.2f, %.2f, %.2f)  max(%.2f, %.2f, %.2f)\n",
               worldMinX, worldMinY, worldMinZ, worldMaxX, worldMaxY, worldMaxZ);

    // Spatial: Position.
    double posX = *(double*)((char*)entityPtr + 0x01C0);
    double posY = *(double*)((char*)entityPtr + 0x01C8);
    double posZ = *(double*)((char*)entityPtr + 0x01D0);
    log_printf("[Spatial] Position: (%.2f, %.2f, %.2f)\n", posX, posY, posZ);

    // Spatial: Orientation quaternion.
    float oriX = *(float*)((char*)entityPtr + 0x01D8);
    float oriY = *(float*)((char*)entityPtr + 0x01DC);
    float oriZ = *(float*)((char*)entityPtr + 0x01E0);
    float oriW = *(float*)((char*)entityPtr + 0x01E4);
    log_printf("[Spatial] Orientation: (%.2f, %.2f, %.2f, %.2f)\n", oriX, oriY, oriZ, oriW);

    // Spatial: Scale.
    float scale = *(float*)((char*)entityPtr + 0x01E8);
    log_printf("[Spatial] Scale: %.2f\n", scale);

    // Spatial: Grid cell.
    short gridX = *(short*)((char*)entityPtr + 0x0236);
    short gridY = *(short*)((char*)entityPtr + 0x0238);
    log_printf("[Spatial] Grid cell: (%d, %d)\n", gridX, gridY);

    // Kinematic: Linear velocity.
    float lvx = *(float*)((char*)entityPtr + 0x03C0);
    float lvy = *(float*)((char*)entityPtr + 0x03C4);
    float lvz = *(float*)((char*)entityPtr + 0x03C8);
    log_printf("[Kinematic] Linear velocity: (%.2f, %.2f, %.2f)\n", lvx, lvy, lvz);

    // Kinematic: Cached velocity.
    float cvx = *(float*)((char*)entityPtr + 0x03CC);
    float cvy = *(float*)((char*)entityPtr + 0x03D0);
    float cvz = *(float*)((char*)entityPtr + 0x03D4);
    log_printf("[Kinematic] Cached velocity: (%.2f, %.2f, %.2f)\n", cvx, cvy, cvz);

    // Kinematic: Angular velocity.
    float avx = *(float*)((char*)entityPtr + 0x03D8);
    float avy = *(float*)((char*)entityPtr + 0x03DC);
    float avz = *(float*)((char*)entityPtr + 0x03E0);
    log_printf("[Kinematic] Angular velocity: (%.2f, %.2f, %.2f)\n", avx, avy, avz);

    // Kinematic: Angular speed.
    float angularSpeed = *(float*)((char*)entityPtr + 0x03E4);
    log_printf("[Kinematic] Angular speed: %.2f\n", angularSpeed);

    // Kinematic: External acceleration.
    float eaX = *(float*)((char*)entityPtr + 0x03F0);
    float eaY = *(float*)((char*)entityPtr + 0x03F4);
    float eaZ = *(float*)((char*)entityPtr + 0x03F8);
    log_printf("[Kinematic] External acceleration: (%.2f, %.2f, %.2f)\n", eaX, eaY, eaZ);

    // Physical properties: Inertia tensor.
    float inertiaXX = *(float*)((char*)entityPtr + 0x0478);
    float inertiaYY = *(float*)((char*)entityPtr + 0x047C);
    float inertiaZZ = *(float*)((char*)entityPtr + 0x0480);
    log_printf("[Physical] Inertia tensor: (%.2f, %.2f, %.2f)\n", inertiaXX, inertiaYY, inertiaZZ);

    // Physical properties: Mass and inverse mass.
    float invMass = *(float*)((char*)entityPtr + 0x0484);
    float mass = *(float*)((char*)entityPtr + 0x0488);
    log_printf("[Physical] Mass: %.2f, InvMass: %.2f\n", mass, invMass);

    // Physical simulation parameters.
    float sleepSpeedThreshold = *(float*)((char*)entityPtr + 0x0490);
    float maxTimeStep = *(float*)((char*)entityPtr + 0x049C);
    float dampingRatio = *(float*)((char*)entityPtr + 0x04A0);
    float frictionCoeff = *(float*)((char*)entityPtr + 0x04B4);
    float restitutionCoeff = *(float*)((char*)entityPtr + 0x04B8);
    log_printf("[Physical] SleepSpeedThreshold: %.2f, MaxTimeStep: %.2f, DampingRatio: %.2f, Friction: %.2f, Restitution: %.2f\n",
               sleepSpeedThreshold, maxTimeStep, dampingRatio, frictionCoeff, restitutionCoeff);

    // State flags.
    unsigned int flags = *(unsigned int*)((char*)entityPtr + 0x0520);
    unsigned short stateFlags = *(unsigned short*)((char*)entityPtr + 0x2416);
    unsigned char simulationFlags = *(unsigned char*)((char*)entityPtr + 0x2418);
    unsigned char contactFlags = *(unsigned char*)((char*)entityPtr + 0x2419);
    log_printf("[State] Flags: 0x%X, StateFlags: 0x%X, SimulationFlags: 0x%X, ContactFlags: 0x%X\n",
               flags, stateFlags, simulationFlags, contactFlags);

    // Collision data.
    unsigned int physicalEntityType = *(unsigned int*)((char*)entityPtr + 0x0244);
    log_printf("[Collision] PhysicalEntityType: %u\n", physicalEntityType);
    unsigned short physicalFlags = *(unsigned short*)((char*)entityPtr + 0x0524);
    unsigned short physicalFlagsOR = *(unsigned short*)((char*)entityPtr + 0x0526);
    unsigned char flagsGroupDst = *(unsigned char*)((char*)entityPtr + 0x0530);
    unsigned char flagsGroupSrc = *(unsigned char*)((char*)entityPtr + 0x0531);
    log_printf("[Collision] CollisionFilter: PhysicalFlags: 0x%X, PhysicalFlagsOR: 0x%X, FlagsGroupDst: %u, FlagsGroupSrc: %u\n",
               physicalFlags, physicalFlagsOR, flagsGroupDst, flagsGroupSrc);
    float contactX = *(float*)((char*)entityPtr + 0x0950);
    float contactY = *(float*)((char*)entityPtr + 0x0954);
    float contactZ = *(float*)((char*)entityPtr + 0x0958);
    log_printf("[Collision] ContactPoint: (%.2f, %.2f, %.2f)\n", contactX, contactY, contactZ);

    // References.
    void* ownerEntity = *(void**)((char*)entityPtr + 0x0184);
    void* constraintEntity = *(void**)((char*)entityPtr + 0x2552);
    void* physWorldPtr = *(void**)((char*)entityPtr + 0x0704);
    log_printf("[References] OwnerEntityPtr: %p, ConstraintEntityPtr: %p, PhysWorldPtr: %p\n", ownerEntity, constraintEntity, physWorldPtr);
    void* foliagePtr = *(void**)((char*)entityPtr + 0x1624);
    void* waterPtr = *(void**)((char*)entityPtr + 0x1784);
    log_printf("[References] HasFoliageInteraction: %s, HasWaterInteraction: %s\n",
               foliagePtr ? "Yes" : "No", waterPtr ? "Yes" : "No");
}

// Our hook function that replaces sub_146675AD0.
void* __fastcall my_sub_146675AD0(void* entityPtr)
{
    // Log on entry.
    log_printf("[+] Entering sub_146675AD0, entity pointer: %p\n", entityPtr);
    dumpEntityFields(entityPtr);
    
    // Call the original function.
    void* ret = orig_sub_146675AD0(entityPtr);
    
    // Log on exit.
    log_printf("[+] Leaving sub_146675AD0, return value: %p\n", ret);
    log_printf("[+] Updated entity data:\n");
    dumpEntityFields(entityPtr);
    
    return ret;
}

// A thread to initialize MinHook and install our hook.
DWORD WINAPI HookThread(LPVOID param)
{
    if (MH_Initialize() != MH_OK) {
        log_printf("MH_Initialize failed.\n");
        return 1;
    }

    // Calculate the target address as: (base address of the main module) + 0x6675AD0.
    uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
    uintptr_t target = base + 0x6675AD0;

    if (MH_CreateHook((LPVOID)target, (LPVOID)&my_sub_146675AD0, (LPVOID*)&orig_sub_146675AD0) != MH_OK) {
        log_printf("MH_CreateHook failed.\n");
        return 1;
    }
    if (MH_EnableHook((LPVOID)target) != MH_OK) {
        log_printf("MH_EnableHook failed.\n");
        return 1;
    }
    log_printf("[+] Hook installed successfully on function at %p\n", (LPVOID)target);
    return 0;
}

// DLL entry point.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch(ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            // Open a log file in append mode.
            g_logFile = fopen("hook_log.txt", "a+");
            if (g_logFile) {
                log_printf("[+] Log file opened successfully.\n");
            }
            DisableThreadLibraryCalls(hModule);
            // Create a thread to install the hook.
            CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            MH_Uninitialize();
            if (g_logFile) {
                fclose(g_logFile);
                g_logFile = NULL;
            }
            break;
    }
    return TRUE;
}
