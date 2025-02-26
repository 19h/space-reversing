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

// ==== Memory Safety Architecture ====
// Thread-local storage for setjmp/longjmp-based exception handling
__thread jmp_buf g_jmpBuf;
__thread volatile sig_atomic_t g_safeToAccess = 0;

// ==== Data Structure Definitions ====
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

// ==== Window Architecture State ====
#define MAX_ENTITIES_DISPLAYED 64
#define ROW_HEIGHT 20
#define WINDOW_WIDTH 1024
#define WINDOW_HEIGHT 768
#define FONT_HEIGHT 16
#define COLOR_TABLE_HEADER RGB(32, 32, 32)
#define COLOR_TABLE_ROW_EVEN RGB(240, 240, 240)
#define COLOR_TABLE_ROW_ODD RGB(220, 220, 220)
#define COLOR_TABLE_TEXT RGB(0, 0, 0)
#define COLOR_TABLE_BORDER RGB(180, 180, 180)
#define COLOR_HIGHLIGHT RGB(100, 149, 237)

// Synchronized window state architecture
static HWND g_hWnd = NULL;
static CRITICAL_SECTION g_windowDataCS;
static EntityData* g_renderEntityList = NULL;
static volatile BOOL g_windowInitialized = FALSE;
static int g_totalEntities = 0;
static int g_selectedEntityIndex = 0;

// ==== Global State Architecture ====
static CRITICAL_SECTION g_entityDataCS;
static EntityData* g_entityDataList = NULL;
static FILE* g_logFile = NULL;
static HANDLE g_displayThread = NULL;
static volatile BOOL g_keepRunning = TRUE;

// Function pointer type for the target function
typedef void* (__fastcall *fnSub146675AD0)(void* actorEntity);
static fnSub146675AD0 orig_sub_146675AD0 = NULL;

// Forward declarations
LRESULT CALLBACK EntityTrackerWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
ATOM RegisterEntityTrackerClass(HINSTANCE hInstance);
void RenderEntityTable(HDC hdc, RECT* clientRect);
void RenderDetailedEntityInfo(HDC hdc, RECT* clientRect, EntityData* entity);
char* FlagAnalysisToString(EntityData* data);

// ==== Memory Safety Implementation ====
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

// ==== Entity Data Extraction ====
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
    
    // Signal window to update
    if (g_windowInitialized && g_hWnd) {
        InvalidateRect(g_hWnd, NULL, FALSE);
    }
}

// ==== Win32 Window Architecture ====

// Window class registration with precise attributes
ATOM RegisterEntityTrackerClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = EntityTrackerWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(IDI_APPLICATION));
    wcex.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(IDC_ARROW));
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"EntityTrackerClass";
    wcex.hIconSm = LoadIconW(NULL, MAKEINTRESOURCEW(IDI_APPLICATION));
    
    return RegisterClassExW(&wcex);
}

// Window procedure with proper message dispatch architecture
LRESULT CALLBACK EntityTrackerWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HDC hdcMem = NULL;
    static HBITMAP hbmMem = NULL;
    static HGDIOBJ hbmOld = NULL;
    static int width = 0, height = 0;
    
    switch (message) {
        case WM_CREATE:
            // Initialize double-buffering surface
            {
                HDC hdc = GetDC(hWnd);
                RECT rect;
                GetClientRect(hWnd, &rect);
                width = rect.right - rect.left;
                height = rect.bottom - rect.top;
                
                hdcMem = CreateCompatibleDC(hdc);
                hbmMem = CreateCompatibleBitmap(hdc, width, height);
                hbmOld = SelectObject(hdcMem, hbmMem);
                
                ReleaseDC(hWnd, hdc);
                
                // Create refresh timer (every 500ms)
                SetTimer(hWnd, 1, 500, NULL);
            }
            return 0;
            
        case WM_SIZE:
            // Resize double-buffer for window size changes
            width = LOWORD(lParam);
            height = HIWORD(lParam);
            
            if (hdcMem) {
                // Clean up old double-buffer
                SelectObject(hdcMem, hbmOld);
                DeleteObject(hbmMem);
                
                // Create new double-buffer
                HDC hdc = GetDC(hWnd);
                hbmMem = CreateCompatibleBitmap(hdc, width, height);
                hbmOld = SelectObject(hdcMem, hbmMem);
                ReleaseDC(hWnd, hdc);
            }
            return 0;
            
        case WM_TIMER:
            // Refresh window content
            InvalidateRect(hWnd, NULL, FALSE);
            
            // Update entity list state
            EnterCriticalSection(&g_entityDataCS);
            
            // Remove expired entities (older than 5 seconds)
            DWORD now = GetTickCount();
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
            
            // Copy entity list to render list
            EnterCriticalSection(&g_windowDataCS);
            
            // First free old render list
            while (g_renderEntityList) {
                EntityData* current = g_renderEntityList;
                g_renderEntityList = current->next;
                free(current);
            }
            
            // Create new render list (deep copy)
            g_totalEntities = 0;
            for (EntityData* src = g_entityDataList; src != NULL; src = src->next) {
                EntityData* copy = (EntityData*)malloc(sizeof(EntityData));
                if (copy) {
                    // Copy entire structure
                    memcpy(copy, src, sizeof(EntityData));
                    
                    // Fix next pointer for the copy
                    copy->next = g_renderEntityList;
                    g_renderEntityList = copy;
                    g_totalEntities++;
                }
            }
            
            // Keep selected index in valid range
            if (g_selectedEntityIndex >= g_totalEntities) {
                g_selectedEntityIndex = g_totalEntities > 0 ? g_totalEntities - 1 : 0;
            }
            
            LeaveCriticalSection(&g_windowDataCS);
            LeaveCriticalSection(&g_entityDataCS);
            
            return 0;
            
        case WM_KEYDOWN:
            // Handle keyboard navigation
            switch (wParam) {
                case VK_UP:
                    g_selectedEntityIndex = max(0, g_selectedEntityIndex - 1);
                    InvalidateRect(hWnd, NULL, FALSE);
                    break;
                    
                case VK_DOWN:
                    g_selectedEntityIndex = min(g_totalEntities - 1, g_selectedEntityIndex + 1);
                    InvalidateRect(hWnd, NULL, FALSE);
                    break;
            }
            return 0;
            
        case WM_PAINT:
            {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);
                
                // Get client area for drawing
                RECT clientRect;
                GetClientRect(hWnd, &clientRect);
                
                // Clear background with GDI
                FillRect(hdcMem, &clientRect, (HBRUSH)GetStockObject(WHITE_BRUSH));
                
                // Draw entity table
                RenderEntityTable(hdcMem, &clientRect);
                
                // Blit double-buffer to screen
                BitBlt(hdc, 0, 0, width, height, hdcMem, 0, 0, SRCCOPY);
                
                EndPaint(hWnd, &ps);
            }
            return 0;
            
        case WM_DESTROY:
            // Clean up double-buffer
            if (hdcMem) {
                SelectObject(hdcMem, hbmOld);
                DeleteObject(hbmMem);
                DeleteDC(hdcMem);
                hdcMem = NULL;
            }
            
            // Kill timer
            KillTimer(hWnd, 1);
            
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// Utility function to draw a table cell with text
void DrawTableCell(HDC hdc, int x, int y, int width, int height, const char* text, 
                  COLORREF bgColor, COLORREF textColor, UINT format) {
    // Draw cell background
    RECT cellRect = {x, y, x + width, y + height};
    HBRUSH hBrush = CreateSolidBrush(bgColor);
    FillRect(hdc, &cellRect, hBrush);
    DeleteObject(hBrush);
    
    // Draw cell border
    HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_TABLE_BORDER);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    Rectangle(hdc, cellRect.left, cellRect.top, cellRect.right, cellRect.bottom);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
    
    // Draw text with specified format
    RECT textRect = {x + 4, y + 2, x + width - 4, y + height - 2};
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, textColor);
    
    // Convert string to wide char for DrawTextW
    int len = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wtext) {
        MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, len);
        DrawTextW(hdc, wtext, -1, &textRect, format);
        free(wtext);
    }
}

// Entity table rendering implementation
void RenderEntityTable(HDC hdc, RECT* clientRect) {
    // Table settings
    int tableTop = 50;
    int tableLeft = 10;
    int tablePadding = 5;
    
    int colWidths[] = {120, 100, 100, 100, 120, 120};
    int numCols = sizeof(colWidths) / sizeof(colWidths[0]);
    int tableWidth = 0;
    
    // Calculate total width
    for (int i = 0; i < numCols; i++) {
        tableWidth += colWidths[i];
    }
    
    // Set up font for drawing
    HFONT hFont = CreateFontW(FONT_HEIGHT, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HFONT hBoldFont = CreateFontW(FONT_HEIGHT, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
    
    // Draw title
    SetTextColor(hdc, RGB(0, 0, 0));
    TextOutW(hdc, tableLeft, tableTop - 30, L"Entity Tracker (MinHook)", 24);
    
    char countText[64];
    sprintf(countText, "Total Entities: %d", g_totalEntities);
    TextOutA(hdc, tableLeft, tableTop - 15, countText, strlen(countText));
    
    // Table headers
    const char* headers[] = {"Entity Ptr", "X", "Y", "Z", "Distance", "Angle(deg)"};
    
    // Draw table headers
    int x = tableLeft;
    SelectObject(hdc, hBoldFont);
    for (int i = 0; i < numCols; i++) {
        DrawTableCell(hdc, x, tableTop, colWidths[i], ROW_HEIGHT, 
                     headers[i], COLOR_TABLE_HEADER, RGB(255, 255, 255), 
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        x += colWidths[i];
    }
    
    // Draw entity rows
    SelectObject(hdc, hFont);
    
    EnterCriticalSection(&g_windowDataCS);
    
    // Get selected entity for detailed view
    EntityData* selectedEntity = NULL;
    int rowIndex = 0;
    
    for (EntityData* current = g_renderEntityList; current != NULL; current = current->next) {
        // Limit display to MAX_ENTITIES_DISPLAYED
        if (rowIndex >= MAX_ENTITIES_DISPLAYED) break;
        
        // Save selected entity for detailed view
        if (rowIndex == g_selectedEntityIndex) {
            selectedEntity = current;
        }
        
        // Calculate spatial info
        double entityX = current->spatial.position.x;
        double entityY = current->spatial.position.y;
        double entityZ = current->spatial.position.z;
        
        double distance = sqrt(entityX*entityX + entityY*entityY + entityZ*entityZ);
        
        double azimuthRad = atan2(entityY, entityX);
        double azimuthDeg = azimuthRad * (180.0 / 3.14159265358979323846);
        
        // Normalize to 0-360 range
        if (azimuthDeg < 0) azimuthDeg += 360.0;
        
        // Format cell values
        char entityPtr[32], xPos[32], yPos[32], zPos[32], distStr[32], angleStr[32];
        sprintf(entityPtr, "%p", current->_debug.memAddresses.actorEntity);
        sprintf(xPos, "%.2f", entityX);
        sprintf(yPos, "%.2f", entityY);
        sprintf(zPos, "%.2f", entityZ);
        sprintf(distStr, "%.2f", distance);
        sprintf(angleStr, "%.2f", azimuthDeg);
        
        const char* cellValues[] = {entityPtr, xPos, yPos, zPos, distStr, angleStr};
        
        // Alternate row colors
        COLORREF rowColor = (rowIndex % 2 == 0) ? COLOR_TABLE_ROW_EVEN : COLOR_TABLE_ROW_ODD;
        
        // Highlight selected row
        if (rowIndex == g_selectedEntityIndex) {
            rowColor = COLOR_HIGHLIGHT;
        }
        
        // Draw row cells
        x = tableLeft;
        int y = tableTop + (rowIndex + 1) * ROW_HEIGHT;
        
        for (int i = 0; i < numCols; i++) {
            DrawTableCell(hdc, x, y, colWidths[i], ROW_HEIGHT, 
                         cellValues[i], rowColor, COLOR_TABLE_TEXT,
                         (i == 0) ? DT_LEFT | DT_VCENTER | DT_SINGLELINE : 
                                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            x += colWidths[i];
        }
        
        rowIndex++;
    }
    
    // Draw detailed view for selected entity
    if (selectedEntity) {
        RECT detailRect = {
            tableLeft, 
            tableTop + (min(g_totalEntities, MAX_ENTITIES_DISPLAYED) + 1) * ROW_HEIGHT + 20, 
            clientRect->right - tableLeft, 
            clientRect->bottom - 10
        };
        
        RenderDetailedEntityInfo(hdc, &detailRect, selectedEntity);
    }
    
    LeaveCriticalSection(&g_windowDataCS);
    
    // Clean up GDI objects
    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
    DeleteObject(hBoldFont);
}

// Format entity flag analysis as string
char* FlagAnalysisToString(EntityData* data) {
    static char buffer[512];
    sprintf(buffer, 
        "Disabled: %s | Constrained: %s | AutoSleep: %s | Sleeping: %s | InCollision: %s | ForceApplied: %s",
        data->state.flagsAnalysis.isDisabled ? "Yes" : "No",
        data->state.flagsAnalysis.isConstrained ? "Yes" : "No",
        data->state.flagsAnalysis.isAutoSleep ? "Yes" : "No",
        data->state.flagsAnalysis.isSleeping ? "Yes" : "No",
        data->state.simulationFlagsAnalysis.inCollision ? "Yes" : "No",
        data->state.simulationFlagsAnalysis.forceApplied ? "Yes" : "No");
    return buffer;
}

// Render detailed entity information
void RenderDetailedEntityInfo(HDC hdc, RECT* rect, EntityData* entity) {
    // Set up font for drawing
    HFONT hFont = CreateFontW(FONT_HEIGHT, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HFONT hBoldFont = CreateFontW(FONT_HEIGHT, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hBoldFont);
    
    // Draw section header
    char headerText[64];
    sprintf(headerText, "Detailed Info for %p:", entity->_debug.memAddresses.actorEntity);
    TextOutA(hdc, rect->left, rect->top, headerText, strlen(headerText));
    
    // Switch to normal font for details
    SelectObject(hdc, hFont);
    
    int y = rect->top + 25;
    
    // Entity flags
    char* flagsText = FlagAnalysisToString(entity);
    TextOutA(hdc, rect->left, y, "Flags:", 6);
    TextOutA(hdc, rect->left + 100, y, flagsText, strlen(flagsText));
    y += 20;
    
    // Calculate spatial analysis
    double entityX = entity->spatial.position.x;
    double entityY = entity->spatial.position.y;
    double entityZ = entity->spatial.position.z;
    
    double distance = sqrt(entityX*entityX + entityY*entityY + entityZ*entityZ);
    double horizontalDist = sqrt(entityX*entityX + entityY*entityY);
    
    double azimuthRad = atan2(entityY, entityX);
    double azimuthDeg = azimuthRad * (180.0 / 3.14159265358979323846);
    if (azimuthDeg < 0) azimuthDeg += 360.0;
    
    double elevationRad = atan2(entityZ, horizontalDist);
    double elevationDeg = elevationRad * (180.0 / 3.14159265358979323846);
    
    // Spatial information
    char spatialText[256];
    sprintf(spatialText, "Distance=%.2f | Azimuth=%.2f° | Elevation=%.2f°", 
            distance, azimuthDeg, elevationDeg);
    TextOutA(hdc, rect->left, y, "Spatial:", 8);
    TextOutA(hdc, rect->left + 100, y, spatialText, strlen(spatialText));
    y += 20;
    
    // Velocity information
    double speed = sqrt(pow(entity->kinematic.linearVelocity.x, 2) + 
                       pow(entity->kinematic.linearVelocity.y, 2) + 
                       pow(entity->kinematic.linearVelocity.z, 2));
    
    char velocityText[256];
    sprintf(velocityText, "[%.2f, %.2f, %.2f] | Speed: %.2f",
            entity->kinematic.linearVelocity.x,
            entity->kinematic.linearVelocity.y,
            entity->kinematic.linearVelocity.z,
            speed);
    TextOutA(hdc, rect->left, y, "Velocity:", 9);
    TextOutA(hdc, rect->left + 100, y, velocityText, strlen(velocityText));
    y += 20;
    
    // Calculate quaternion to Euler angles (Roll-Pitch-Yaw)
    float qx = entity->spatial.orientation.x;
    float qy = entity->spatial.orientation.y;
    float qz = entity->spatial.orientation.z;
    float qw = entity->spatial.orientation.w;
    
    float yaw = atan2(2.0f * (qw * qz + qx * qy), 1.0f - 2.0f * (qy * qy + qz * qz));
    float pitch = asin(2.0f * (qw * qy - qz * qx));
    float roll = atan2(2.0f * (qw * qx + qy * qz), 1.0f - 2.0f * (qx * qx + qy * qy));
    
    // Convert to degrees
    float yawDeg = yaw * (180.0f / 3.14159265358979323846f);
    float pitchDeg = pitch * (180.0f / 3.14159265358979323846f);
    float rollDeg = roll * (180.0f / 3.14159265358979323846f);
    
    // Orientation information
    char orientationText[256];
    sprintf(orientationText, "Yaw=%.2f° | Pitch=%.2f° | Roll=%.2f° | Scale=%.2f",
            yawDeg, pitchDeg, rollDeg, entity->spatial.scale);
    TextOutA(hdc, rect->left, y, "Orientation:", 12);
    TextOutA(hdc, rect->left + 100, y, orientationText, strlen(orientationText));
    y += 20;
    
    // Entity information
    char entityText[256];
    sprintf(entityText, "EntityID: %llu | Mass: %.2f | PhysType: %u",
            entity->core.entityId, entity->physical.mass, entity->collision.physicalEntityType);
    TextOutA(hdc, rect->left, y, "Entity Info:", 12);
    TextOutA(hdc, rect->left + 100, y, entityText, strlen(entityText));
    
    // Clean up GDI objects
    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
    DeleteObject(hBoldFont);
}

// Window thread implementation with proper message dispatch architecture
DWORD WINAPI WindowThreadProc(LPVOID lpParameter) {
    // Install thread-specific signal handler
    signal(SIGSEGV, segv_handler);
    
    LogToFile("[+] Window thread started\n");
    
    HINSTANCE hInstance = (HINSTANCE)GetModuleHandle(NULL);
    
    // Register window class
    if (!RegisterEntityTrackerClass(hInstance)) {
        LogToFile("[!] Failed to register window class: %lu\n", GetLastError());
        return 1;
    }
    
    // Create window with proper Z-order and style attributes
    g_hWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        L"EntityTrackerClass",
        L"Entity Tracker",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInstance, NULL);
    
    if (!g_hWnd) {
        LogToFile("[!] Failed to create window: %lu\n", GetLastError());
        return 1;
    }
    
    // Display window with proper composition attributes
    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);
    
    // Mark window as initialized
    g_windowInitialized = TRUE;
    
    // Message dispatch loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Window terminated
    g_windowInitialized = FALSE;
    g_hWnd = NULL;
    
    LogToFile("[+] Window thread exiting\n");
    return 0;
}

// ==== MinHook Functions ====
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
        
        // Disassemble first few bytes to verify code signature
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

// ==== DLL Entry Point ====
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
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
            
            // Initialize critical sections
            InitializeCriticalSection(&g_entityDataCS);
            InitializeCriticalSection(&g_windowDataCS);
            
            // Start window thread
            HANDLE windowThread = CreateThread(NULL, 0, WindowThreadProc, NULL, 0, NULL);
            if (windowThread) {
                CloseHandle(windowThread);  // We don't need to track this thread
            } else {
                LogToFile("[!] Failed to create window thread\n");
            }
            
            // Start hook installer thread
            HANDLE hookThread = CreateThread(NULL, 0, HookInstallerThread, NULL, 0, NULL);
            if (hookThread) {
                CloseHandle(hookThread);  // We don't need to track this thread
            } else {
                LogToFile("[!] Failed to create hook installer thread\n");
            }
            
            break;
        }
            
        case DLL_PROCESS_DETACH: {
            // Signal threads to terminate
            g_keepRunning = FALSE;
            
            // Send message to terminate window thread (if window exists)
            if (g_hWnd && IsWindow(g_hWnd)) {
                SendMessage(g_hWnd, WM_CLOSE, 0, 0);
            }
            
            // Clean up MinHook
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            
            // Clean up entity lists with proper synchronization
            EnterCriticalSection(&g_entityDataCS);
            while (g_entityDataList) {
                EntityData* current = g_entityDataList;
                g_entityDataList = current->next;
                free(current);
            }
            LeaveCriticalSection(&g_entityDataCS);
            
            EnterCriticalSection(&g_windowDataCS);
            while (g_renderEntityList) {
                EntityData* current = g_renderEntityList;
                g_renderEntityList = current->next;
                free(current);
            }
            LeaveCriticalSection(&g_windowDataCS);
            
            // Delete critical sections
            DeleteCriticalSection(&g_entityDataCS);
            DeleteCriticalSection(&g_windowDataCS);
            
            // Close log file
            if (g_logFile) {
                LogToFile("[*] EntityTracker DLL Unloaded\n");
                fclose(g_logFile);
                g_logFile = NULL;
            }
            
            break;
        }
    }
    
    return TRUE;
}