#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <dbghelp.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <setjmp.h>
#include <intrin.h>
#include <signal.h>
#include <math.h>
#include <direct.h>  /* For _mkdir, etc. */
#include "hook.c"    /* MinHook header */

// Thread-local storage for setjmp/longjmp-based exception handling
__thread jmp_buf g_jmpBuf;
__thread volatile sig_atomic_t g_safeToAccess = 0;

// -------------------- Structure Definitions --------------------

// Entity Core Identification
typedef struct {
    void* vtable;
    uint64_t entityId;
} EntityCore;

// Spatial Data (Transformation, Bounds)
typedef struct {
    struct {
        double x, y, z;
    } min;
    struct {
        double x, y, z;
    } max;
    struct {
        double x, y, z;
    } position;
    struct {
        float x, y, z, w;
    } orientation;
    float scale;
    struct {
        int16_t x, y;
    } gridCell;
} EntitySpatial;

// Kinematics State
typedef struct {
    struct {
        float x, y, z;
    } linearVelocity;
    struct {
        float x, y, z;
    } cachedVelocity;
    struct {
        float x, y, z;
    } angularVelocity;
    float angularSpeed;
    struct {
        float x, y, z;
    } externalAcceleration;
} EntityKinematic;

// Physical Properties
typedef struct {
    struct {
        float xx, yy, zz;
    } inertiaTensor;
    float mass;
    float invMass;
    float sleepSpeedThreshold;
    float maxTimeStep;
    float dampingRatio;
    float frictionCoeff;
    float restitutionCoeff;
} EntityPhysical;

// State Flags
typedef struct {
    uint32_t flags;
    uint16_t stateFlags;
    uint8_t simulationFlags;
    uint8_t contactFlags;
    struct {
        bool isDisabled;
        bool isConstrained;
        bool isAutoSleep;
        bool isSleeping;
    } flagsAnalysis;
    struct {
        bool inCollision;
        bool forceApplied;
        bool requiresStep;
        bool timestepActive;
        bool velocityModified;
        bool positionModified;
    } simulationFlagsAnalysis;
} EntityState;

// Collision Data
typedef struct {
    uint32_t physicalEntityType;
    struct {
        uint16_t physicalFlags;
        uint16_t physicalFlagsOR;
        uint8_t flagsGroupDst;
        uint8_t flagsGroupSrc;
    } collisionFilter;
    struct {
        float x, y, z;
    } contactPoint;
} EntityCollision;

// Entity References
typedef struct {
    void* entitiesPtr;
    void* entitiesEndPtr;
    void* entitiesCapacityPtr;
    struct {
        void* vtable;
        uint64_t entityId;
        uint32_t entityType;
        uint32_t entityFlags;
    } physEntity;
    void* ownerEntityPtr;
    bool hasOwner;
    void* constraintEntityPtr;
    bool hasConstraint;
    void* physWorldPtr;
    struct {
        bool hasFoliageInteraction;
        bool hasWaterInteraction;
    } components;
} EntityReferences;

// Debug Metadata
typedef struct {
    struct {
        void* actorEntity;
        void* pEntities;
        void* physEntity;
    } memAddresses;
} EntityDebug;

// Forward declaration with proper type consistency
typedef struct EntityData EntityData;

// Complete Entity Data Structure
struct EntityData {
    EntityCore core;
    EntitySpatial spatial;
    EntityPhysical physical;
    EntityState state;
    EntityKinematic kinematic;
    EntityCollision collision;
    EntityReferences references;
    EntityDebug _debug;
    DWORD timestamp;
    EntityData* next;
};

// -------------------- Global Variables --------------------

static CRITICAL_SECTION g_entityDataCS;
static EntityData* g_entityDataList = NULL;
static FILE* g_logFile = NULL;
static HANDLE g_displayThread = NULL;
static volatile BOOL g_keepRunning = TRUE;
static HANDLE g_displayMutex = NULL;  // Missing synchronization primitive

// Function pointer type for the target function
typedef void* (__fastcall *fnSub146675AD0)(void* actorEntity);
static fnSub146675AD0 orig_sub_146675AD0 = NULL;

// -------------------- Utility Functions --------------------

// Signal handler for SIGSEGV (segmentation fault)
void segv_handler(int sig) {
    // Only longjmp if we're in a read operation (indicated by g_safeToAccess)
    if (g_safeToAccess) {
        g_safeToAccess = 0;  // Reset the flag
        longjmp(g_jmpBuf, 1);  // Jump back to the setjmp point
    }
    
    // If we get here, it's an unexpected SIGSEGV - use default handler
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

// Safe memory validation using VirtualQuery
bool IsValidMemory(const void* ptr, size_t size) {
    if (!ptr) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    
    if (mbi.State != MEM_COMMIT) return false;
    
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) return false;
    
    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end = start + size;
    uintptr_t regionStart = (uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd = regionStart + mbi.RegionSize;
    
    return (start >= regionStart && end <= regionEnd);
}

// Safe pointer reading with setjmp/longjmp for exception handling (MinGW compatible)
bool SafeReadMemory(const void* address, void* buffer, size_t size) {
    if (!IsValidMemory(address, size)) return false;
    
    // Install signal handler temporarily
    void (*old_handler)(int) = signal(SIGSEGV, segv_handler);
    
    // Set recovery point with setjmp
    if (setjmp(g_jmpBuf) == 0) {
        g_safeToAccess = 1;  // Mark that we're in a protected memory read
        memcpy(buffer, address, size);
        g_safeToAccess = 0;  // Mark that we're no longer in a protected read
        signal(SIGSEGV, old_handler);  // Restore original handler
        return true;
    } else {
        // We got here from longjmp in the signal handler
        g_safeToAccess = 0;  // Ensure the flag is cleared
        signal(SIGSEGV, old_handler);  // Restore original handler
        return false;
    }
}

// Type-specific safe readers
bool ReadU64(const void* address, uint64_t* out) {
    return SafeReadMemory(address, out, sizeof(uint64_t));
}

bool ReadU32(const void* address, uint32_t* out) {
    return SafeReadMemory(address, out, sizeof(uint32_t));
}

bool ReadU16(const void* address, uint16_t* out) {
    return SafeReadMemory(address, out, sizeof(uint16_t));
}

bool ReadU8(const void* address, uint8_t* out) {
    return SafeReadMemory(address, out, sizeof(uint8_t));
}

bool ReadPtr(const void* address, void** out) {
    return SafeReadMemory(address, out, sizeof(void*));
}

bool ReadF32(const void* address, float* out) {
    return SafeReadMemory(address, out, sizeof(float));
}

bool ReadF64(const void* address, double* out) {
    return SafeReadMemory(address, out, sizeof(double));
}

bool ReadS16(const void* address, int16_t* out) {
    return SafeReadMemory(address, out, sizeof(int16_t));
}

// Logging function
void LogToFile(const char* format, ...) {
    if (!g_logFile) return;

    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fflush(g_logFile);
}

// -------------------- Entity Data Extraction --------------------

EntityData* ReadEntityFields(void* actorEntityPtr) {
    if (!IsValidMemory(actorEntityPtr, sizeof(void*))) {
        LogToFile("[!] Invalid actorEntity pointer: %p\n", actorEntityPtr);
        return NULL;
    }

    EntityData* data = (EntityData*)calloc(1, sizeof(EntityData));
    if (!data) {
        LogToFile("[!] Memory allocation failed for EntityData\n");
        return NULL;
    }

    data->timestamp = GetTickCount();
    data->_debug.memAddresses.actorEntity = actorEntityPtr;

    // Begin extracting data with proper memory validation
    // ---- Core Entity Identification ----
    void* vtablePtr = NULL;
    if (ReadPtr(actorEntityPtr, &vtablePtr)) {
        data->core.vtable = vtablePtr;
    }

    uint64_t entityId = 0;
    if (ReadU64((char*)actorEntityPtr + 0x0008, &entityId)) {
        data->core.entityId = entityId;
    }

    // ---- Process Dynamic Entity List ----
    void* pEntitiesPtr = NULL;
    if (ReadPtr((char*)actorEntityPtr + 0x2848, &pEntitiesPtr)) {
        data->references.entitiesPtr = pEntitiesPtr;
        data->_debug.memAddresses.pEntities = pEntitiesPtr;

        if (IsValidMemory(pEntitiesPtr, sizeof(void*))) {
            ReadPtr((char*)actorEntityPtr + 0x2856, &data->references.entitiesEndPtr);
            ReadPtr((char*)actorEntityPtr + 0x2864, &data->references.entitiesCapacityPtr);

            void* physEntityPtr = NULL;
            if (ReadPtr(pEntitiesPtr, &physEntityPtr)) {
                data->_debug.memAddresses.physEntity = physEntityPtr;

                if (IsValidMemory(physEntityPtr, sizeof(void*) + sizeof(uint64_t) + sizeof(uint32_t) * 2)) {
                    ReadPtr(physEntityPtr, &data->references.physEntity.vtable);
                    ReadU64((char*)physEntityPtr + 0x08, &data->references.physEntity.entityId);
                    ReadU32((char*)physEntityPtr + 0x10, &data->references.physEntity.entityType);
                    ReadU32((char*)physEntityPtr + 0x14, &data->references.physEntity.entityFlags);
                }
            }
        }
    }

    // ---- Spatial Data ----
    // World bounds (AABB)
    ReadF64((char*)actorEntityPtr + 0x0010, &data->spatial.min.x);
    ReadF64((char*)actorEntityPtr + 0x0018, &data->spatial.min.y);
    ReadF64((char*)actorEntityPtr + 0x0020, &data->spatial.min.z);
    ReadF64((char*)actorEntityPtr + 0x0028, &data->spatial.max.x);
    ReadF64((char*)actorEntityPtr + 0x0030, &data->spatial.max.y);
    ReadF64((char*)actorEntityPtr + 0x0038, &data->spatial.max.z);

    // Position vector
    ReadF64((char*)actorEntityPtr + 0x01C0, &data->spatial.position.x);
    ReadF64((char*)actorEntityPtr + 0x01C8, &data->spatial.position.y);
    ReadF64((char*)actorEntityPtr + 0x01D0, &data->spatial.position.z);

    // Orientation quaternion
    ReadF32((char*)actorEntityPtr + 0x01D8, &data->spatial.orientation.x);
    ReadF32((char*)actorEntityPtr + 0x01DC, &data->spatial.orientation.y);
    ReadF32((char*)actorEntityPtr + 0x01E0, &data->spatial.orientation.z);
    ReadF32((char*)actorEntityPtr + 0x01E4, &data->spatial.orientation.w);

    // Scale factor
    ReadF32((char*)actorEntityPtr + 0x01E8, &data->spatial.scale);

    // Grid cell coordinates
    ReadS16((char*)actorEntityPtr + 0x0236, &data->spatial.gridCell.x);
    ReadS16((char*)actorEntityPtr + 0x0238, &data->spatial.gridCell.y);

    // ---- Kinematic State ----
    ReadF32((char*)actorEntityPtr + 0x03C0, &data->kinematic.linearVelocity.x);
    ReadF32((char*)actorEntityPtr + 0x03C4, &data->kinematic.linearVelocity.y);
    ReadF32((char*)actorEntityPtr + 0x03C8, &data->kinematic.linearVelocity.z);

    ReadF32((char*)actorEntityPtr + 0x03CC, &data->kinematic.cachedVelocity.x);
    ReadF32((char*)actorEntityPtr + 0x03D0, &data->kinematic.cachedVelocity.y);
    ReadF32((char*)actorEntityPtr + 0x03D4, &data->kinematic.cachedVelocity.z);

    ReadF32((char*)actorEntityPtr + 0x03D8, &data->kinematic.angularVelocity.x);
    ReadF32((char*)actorEntityPtr + 0x03DC, &data->kinematic.angularVelocity.y);
    ReadF32((char*)actorEntityPtr + 0x03E0, &data->kinematic.angularVelocity.z);

    ReadF32((char*)actorEntityPtr + 0x03E4, &data->kinematic.angularSpeed);

    ReadF32((char*)actorEntityPtr + 0x03F0, &data->kinematic.externalAcceleration.x);
    ReadF32((char*)actorEntityPtr + 0x03F4, &data->kinematic.externalAcceleration.y);
    ReadF32((char*)actorEntityPtr + 0x03F8, &data->kinematic.externalAcceleration.z);

    // ---- Physical Properties ----
    ReadF32((char*)actorEntityPtr + 0x0478, &data->physical.inertiaTensor.xx);
    ReadF32((char*)actorEntityPtr + 0x047C, &data->physical.inertiaTensor.yy);
    ReadF32((char*)actorEntityPtr + 0x0480, &data->physical.inertiaTensor.zz);

    ReadF32((char*)actorEntityPtr + 0x0488, &data->physical.mass);
    ReadF32((char*)actorEntityPtr + 0x0484, &data->physical.invMass);

    ReadF32((char*)actorEntityPtr + 0x0490, &data->physical.sleepSpeedThreshold);
    ReadF32((char*)actorEntityPtr + 0x049C, &data->physical.maxTimeStep);
    ReadF32((char*)actorEntityPtr + 0x04A0, &data->physical.dampingRatio);
    ReadF32((char*)actorEntityPtr + 0x04B4, &data->physical.frictionCoeff);
    ReadF32((char*)actorEntityPtr + 0x04B8, &data->physical.restitutionCoeff);

    // ---- State Flags and Runtime Status ----
    ReadU32((char*)actorEntityPtr + 0x0520, &data->state.flags);
    ReadU16((char*)actorEntityPtr + 0x2416, &data->state.stateFlags);
    ReadU8((char*)actorEntityPtr + 0x2418, &data->state.simulationFlags);
    ReadU8((char*)actorEntityPtr + 0x2419, &data->state.contactFlags);

    // Decompose flags for easier analysis
    data->state.flagsAnalysis.isDisabled = (data->state.flags & 0x20) != 0;
    data->state.flagsAnalysis.isConstrained = (data->state.flags & 0x40) != 0;
    data->state.flagsAnalysis.isAutoSleep = (data->state.flags & 0x80) != 0;
    data->state.flagsAnalysis.isSleeping = (data->state.flags & 0x100) != 0;

    data->state.simulationFlagsAnalysis.inCollision = (data->state.simulationFlags & 0x01) != 0;
    data->state.simulationFlagsAnalysis.forceApplied = (data->state.simulationFlags & 0x02) != 0;
    data->state.simulationFlagsAnalysis.requiresStep = (data->state.simulationFlags & 0x04) != 0;
    data->state.simulationFlagsAnalysis.timestepActive = (data->state.simulationFlags & 0x08) != 0;
    data->state.simulationFlagsAnalysis.velocityModified = (data->state.simulationFlags & 0x10) != 0;
    data->state.simulationFlagsAnalysis.positionModified = (data->state.simulationFlags & 0x40) != 0;

    // ---- Collision Data ----
    ReadU32((char*)actorEntityPtr + 0x0244, &data->collision.physicalEntityType);

    ReadU16((char*)actorEntityPtr + 0x0524, &data->collision.collisionFilter.physicalFlags);
    ReadU16((char*)actorEntityPtr + 0x0526, &data->collision.collisionFilter.physicalFlagsOR);
    ReadU8((char*)actorEntityPtr + 0x0530, &data->collision.collisionFilter.flagsGroupDst);
    ReadU8((char*)actorEntityPtr + 0x0531, &data->collision.collisionFilter.flagsGroupSrc);

    ReadF32((char*)actorEntityPtr + 0x0950, &data->collision.contactPoint.x);
    ReadF32((char*)actorEntityPtr + 0x0954, &data->collision.contactPoint.y);
    ReadF32((char*)actorEntityPtr + 0x0958, &data->collision.contactPoint.z);

    // ---- Entity References ----
    void* pOwnerEntityPtr = NULL;
    if (ReadPtr((char*)actorEntityPtr + 0x0184, &pOwnerEntityPtr)) {
        data->references.ownerEntityPtr = pOwnerEntityPtr;
        data->references.hasOwner = IsValidMemory(pOwnerEntityPtr, sizeof(void*));
    }

    void* pConstraintEntityPtr = NULL;
    if (ReadPtr((char*)actorEntityPtr + 0x2552, &pConstraintEntityPtr)) {
        data->references.constraintEntityPtr = pConstraintEntityPtr;
        data->references.hasConstraint = IsValidMemory(pConstraintEntityPtr, sizeof(void*));
    }

    void* pPhysWorldPtr = NULL;
    if (ReadPtr((char*)actorEntityPtr + 0x0704, &pPhysWorldPtr)) {
        data->references.physWorldPtr = pPhysWorldPtr;
    }

    // Read component subsystem pointers
    void* tmpPtr;
    if (ReadPtr((char*)actorEntityPtr + 0x1624, &tmpPtr)) {
        data->references.components.hasFoliageInteraction = (tmpPtr != NULL);
    }
    
    if (ReadPtr((char*)actorEntityPtr + 0x1784, &tmpPtr)) {
        data->references.components.hasWaterInteraction = (tmpPtr != NULL);
    }

    return data;
}

// Add entity to the tracking list (with thread safety)
void TrackEntity(EntityData* data) {
    if (!data) return;
    
    EnterCriticalSection(&g_entityDataCS);
    data->next = g_entityDataList;
    g_entityDataList = data;
    LeaveCriticalSection(&g_entityDataCS);
}

// -------------------- Display Thread Function --------------------

// Forward declaration for function used before definition
char* FlagAnalysisToString(EntityData* data);

char* FlagAnalysisToString(EntityData* data) {
    static char buffer[512];
    snprintf(buffer, sizeof(buffer), 
        "Disabled: %s | Constrained: %s | AutoSleep: %s | Sleeping: %s | InCollision: %s | ForceApplied: %s",
        data->state.flagsAnalysis.isDisabled ? "Yes" : "No",
        data->state.flagsAnalysis.isConstrained ? "Yes" : "No",
        data->state.flagsAnalysis.isAutoSleep ? "Yes" : "No",
        data->state.flagsAnalysis.isSleeping ? "Yes" : "No",
        data->state.simulationFlagsAnalysis.inCollision ? "Yes" : "No",
        data->state.simulationFlagsAnalysis.forceApplied ? "Yes" : "No");
    return buffer;
}

DWORD WINAPI DisplayThreadProc(LPVOID lpParameter) {
    // Install thread-specific signal handler
    signal(SIGSEGV, segv_handler);
    
    while (g_keepRunning) {
        DWORD now = GetTickCount();
        
        // Synchronize console access with proper mutex handling
        DWORD dwWaitResult = WaitForSingleObject(g_displayMutex, 1000);
        if (dwWaitResult == WAIT_OBJECT_0) {
            // Clear with direct Win32 API call - more efficient than system()
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hConsole != INVALID_HANDLE_VALUE) {
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
                    DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
                    COORD homeCoords = {0, 0};
                    DWORD count;
                    FillConsoleOutputCharacter(hConsole, ' ', cellCount, homeCoords, &count);
                    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, homeCoords, &count);
                    SetConsoleCursorPosition(hConsole, homeCoords);
                }
            }
            
            // Removed redundant system("cls") call
            
            EnterCriticalSection(&g_entityDataCS);
            
            // Remove expired entities (older than 5 seconds)
            EntityData** pp = &g_entityDataList;
            while (*pp) {
                EntityData* current = *pp;
                if (now - current->timestamp > 5000 || 
                    !IsValidMemory(current->_debug.memAddresses.actorEntity, sizeof(void*))) {
                    *pp = current->next;
                    free(current);
                } else {
                    pp = &(current->next);
                }
            }
            
            // Print header
            printf("===== Entity Tracker (MinHook) =====\n");
            printf("| %-16s | %-10s | %-10s | %-10s | %-12s | %-10s |\n", 
                "Entity", "X", "Y", "Z", "Distance", "Angle(deg)");
            printf("|-----------------|------------|------------|------------|--------------|------------|\n");
            
            // Print entity data
            int entityCount = 0;
            for (EntityData* current = g_entityDataList; current; current = current->next) {
                // Calculate distance from origin (player at 0,0,0)
                double entityX = current->spatial.position.x;
                double entityY = current->spatial.position.y;
                double entityZ = current->spatial.position.z;
                
                double distance = sqrt(entityX*entityX + entityY*entityY + entityZ*entityZ);
                
                // Calculate angle (azimuth) in XY plane (horizontal)
                double azimuthRad = atan2(entityY, entityX);
                // Use explicit constant instead of M_PI which may not be defined
                double azimuthDeg = azimuthRad * (180.0 / 3.14159265358979323846);
                
                // Normalize to 0-360 range
                if (azimuthDeg < 0) azimuthDeg += 360.0;
                
                printf("| %16p | %10.2f | %10.2f | %10.2f | %12.2f | %10.2f |\n",
                    current->_debug.memAddresses.actorEntity,
                    entityX, entityY, entityZ,
                    distance,
                    azimuthDeg);
                
                // Print detailed info for the first entity
                if (entityCount == 0) {
                    // Calculate elevation angle in addition to azimuth
                    double horizontalDist = sqrt(entityX*entityX + entityY*entityY);
                    double elevationRad = atan2(entityZ, horizontalDist);
                    double elevationDeg = elevationRad * (180.0 / 3.14159265358979323846);
                    
                    // Calculate quaternion to Euler angles (Roll-Pitch-Yaw)
                    float qx = current->spatial.orientation.x;
                    float qy = current->spatial.orientation.y;
                    float qz = current->spatial.orientation.z;
                    float qw = current->spatial.orientation.w;
                    
                    float yaw = atan2(2.0f * (qw * qz + qx * qy), 1.0f - 2.0f * (qy * qy + qz * qz));
                    float pitch = asin(2.0f * (qw * qy - qz * qx));
                    float roll = atan2(2.0f * (qw * qx + qy * qz), 1.0f - 2.0f * (qx * qx + qy * qy));
                    
                    // Convert to degrees
                    float yawDeg = yaw * (180.0f / 3.14159265358979323846f);
                    float pitchDeg = pitch * (180.0f / 3.14159265358979323846f);
                    float rollDeg = roll * (180.0f / 3.14159265358979323846f);
                    
                    printf("\nDetailed info for %p:\n", current->_debug.memAddresses.actorEntity);
                    printf("  Flags: %s\n", FlagAnalysisToString(current));
                    printf("  Spatial: Distance=%.2f | Azimuth=%.2f° | Elevation=%.2f°\n",
                        distance,
                        azimuthDeg,
                        elevationDeg);
                    printf("  Velocity: [%.2f, %.2f, %.2f] | Speed: %.2f\n",
                        current->kinematic.linearVelocity.x,
                        current->kinematic.linearVelocity.y,
                        current->kinematic.linearVelocity.z,
                        sqrt(pow(current->kinematic.linearVelocity.x, 2) + 
                                pow(current->kinematic.linearVelocity.y, 2) + 
                                pow(current->kinematic.linearVelocity.z, 2)));
                    printf("  Orientation: Yaw=%.2f° | Pitch=%.2f° | Roll=%.2f° | Scale=%.2f\n",
                        yawDeg, pitchDeg, rollDeg,
                        current->spatial.scale);
                    printf("  EntityID: %llu | Mass: %.2f | PhysType: %u\n",
                        current->core.entityId,
                        current->physical.mass,
                        current->collision.physicalEntityType);
                }
                
                entityCount++;
            }
            
            printf("|-----------------|------------|------------|------------|--------------|------------|\n");
            printf("Total entities: %d\n", entityCount);
            
            LeaveCriticalSection(&g_entityDataCS);
            
            // Release mutex after completing console operations
            ReleaseMutex(g_displayMutex);
        } else {
            // Log mutex acquisition failure with detailed error code
            LogToFile("[!] Failed to acquire display mutex (code: %lu)\n", GetLastError());
        }
        
        // Wait for 500ms
        Sleep(500);
    }
    
    return 0;
}

// -------------------- MinHook Functions --------------------

void* __fastcall HookedSub146675AD0(void* actorEntity) {
    // Log function entry
    LogToFile("[+] Entering sub_146675AD0, entity=%p\n", actorEntity);
    
    // Extract entity data before calling the original function
    EntityData* preCallData = ReadEntityFields(actorEntity);
    if (preCallData) {
        LogToFile("[+] Pre-call entity data extracted successfully\n");
        TrackEntity(preCallData);
    }
    
    // Call original function
    void* retVal = orig_sub_146675AD0(actorEntity);
    
    // Extract entity data after the original function call (to capture any modifications)
    EntityData* postCallData = ReadEntityFields(actorEntity);
    if (postCallData) {
        LogToFile("[+] Post-call entity data extracted successfully\n");
        TrackEntity(postCallData);
    }
    
    // Log function exit
    LogToFile("[+] Exiting sub_146675AD0, retVal=%p\n", retVal);
    
    return retVal;
}

// Hook installer thread
DWORD WINAPI HookInstallerThread(LPVOID lpParameter) {
    // Install thread-specific signal handler
    signal(SIGSEGV, segv_handler);
    
    LogToFile("[*] Beginning hook installation...\n");
    
    // Initialize MinHook
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        LogToFile("[!] MH_Initialize failed with error code %d\n", status);
        return 1;
    }
    
    // Calculate target function address
    uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);
    uintptr_t targetAddress = baseAddress + 0x6675AD0;
    
    LogToFile("[*] Base address: 0x%p\n", (void*)baseAddress);
    LogToFile("[*] Target function address: 0x%p\n", (void*)targetAddress);
    
    // Verify the target function address points to valid executable memory
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)targetAddress, &mbi, sizeof(mbi)) && 
        mbi.State == MEM_COMMIT && 
        (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        
        // Disassemble first few bytes to verify code signature (if possible)
        BYTE codeBytes[16];
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)targetAddress, codeBytes, sizeof(codeBytes), NULL)) {
            LogToFile("[*] Target function signature: %02X %02X %02X %02X %02X %02X\n", 
                     codeBytes[0], codeBytes[1], codeBytes[2], 
                     codeBytes[3], codeBytes[4], codeBytes[5]);
        }
    } else {
        LogToFile("[!] Target address 0x%p is not valid executable memory\n", (void*)targetAddress);
    }
    
    // Create the hook
    status = MH_CreateHook((LPVOID)targetAddress, 
                          (LPVOID)HookedSub146675AD0, 
                          (LPVOID*)&orig_sub_146675AD0);
    if (status != MH_OK) {
        LogToFile("[!] MH_CreateHook failed with error code %d\n", status);
        MH_Uninitialize();
        return 1;
    }
    
    // Enable the hook
    status = MH_EnableHook((LPVOID)targetAddress);
    if (status != MH_OK) {
        LogToFile("[!] MH_EnableHook failed with error code %d\n", status);
        MH_Uninitialize();
        return 1;
    }
    
    LogToFile("[+] Hook installed successfully!\n");
    return 0;
}

// -------------------- DLL Entry Point --------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            
            // Create log directory if it doesn't exist
            _mkdir("C:\\EntityTracker");
            
            // Open log file
            g_logFile = fopen("C:\\EntityTracker\\entity_tracker.log", "a");
            if (g_logFile) {
                time_t t = time(NULL);
                LogToFile("\n\n[%s] === EntityTracker DLL Loaded ===\n", ctime(&t));
            }
            
            // Initialize the signal handler for the main thread
            signal(SIGSEGV, segv_handler);
            
            // Initialize mutex for display thread synchronization
            g_displayMutex = CreateMutex(NULL, FALSE, NULL);
            if (!g_displayMutex) {
                LogToFile("[!] Failed to create display mutex (error: %lu)\n", GetLastError());
                // Continue execution, but display thread will log errors
            }
            
            // Allocate console for display
            BOOL consoleResult = AllocConsole();
            if (!consoleResult) {
                // Fallback to parent console if allocation fails
                AttachConsole(ATTACH_PARENT_PROCESS);
            }

            // Force console window visibility
            HWND consoleWindow = GetConsoleWindow();
            if (consoleWindow) {
                ShowWindow(consoleWindow, SW_SHOW);
                SetForegroundWindow(consoleWindow);
                
                // Configure console buffer
                HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
                if (hStdout != INVALID_HANDLE_VALUE) {
                    DWORD mode = 0;
                    GetConsoleMode(hStdout, &mode);
                    mode |= ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
                    SetConsoleMode(hStdout, mode);
                    
                    // Set distinctive title
                    SetConsoleTitle("Entity Tracker - Debug Console");
                }
            }

            // Redirect STDIO with verification
            FILE* fDummy;
            if (freopen_s(&fDummy, "CONOUT$", "w", stdout) != 0) {
                // Direct output to kernel debugger as fallback
                OutputDebugStringA("Failed to redirect stdout to console");
            }
            
            // Initialize critical section
            InitializeCriticalSection(&g_entityDataCS);
            
            // Start hook installer thread
            CreateThread(NULL, 0, HookInstallerThread, NULL, 0, NULL);
            
            // Start display thread
            g_displayThread = CreateThread(NULL, 0, DisplayThreadProc, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            // Signal threads to terminate
            g_keepRunning = FALSE;
            
            // Wait for display thread to terminate (with timeout)
            if (g_displayThread) {
                WaitForSingleObject(g_displayThread, 1000);
                CloseHandle(g_displayThread);
                g_displayThread = NULL;
            }
            
            // Clean up MinHook
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            
            // Clean up entity list with proper synchronization
            EnterCriticalSection(&g_entityDataCS);
            while (g_entityDataList) {
                EntityData* current = g_entityDataList;
                g_entityDataList = current->next;
                free(current);
            }
            LeaveCriticalSection(&g_entityDataCS);
            
            // Delete critical section
            DeleteCriticalSection(&g_entityDataCS);
            
            // Clean up mutex
            if (g_displayMutex) {
                CloseHandle(g_displayMutex);
                g_displayMutex = NULL;
            }
            
            // Close log file
            if (g_logFile) {
                LogToFile("[*] EntityTracker DLL Unloaded\n");
                fclose(g_logFile);
                g_logFile = NULL;
            }
            
            // Free console
            FreeConsole();
            break;
    }
    
    return TRUE;
}