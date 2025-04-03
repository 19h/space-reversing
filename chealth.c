#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>      // For wide character functions like vfwprintf
#include <stdint.h>
#include <immintrin.h>
#include <initguid.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <stdarg.h>
#include "hook.c" // Use MinHook header

// --- Typedefs (Assuming these are needed and correct) ---
typedef uint64_t EntityId;
typedef __int64 (__fastcall *PFN_HANDLE_COMPONENT_EVENT)(void* this_ptr, void* pEventData);
typedef void (__fastcall *PFN_GET_PLAYER_ENTITY_HANDLE)(void* pSystem, EntityId* pHandleOut);
typedef void* (__fastcall *PFN_GET_COMPONENT_FROM_HANDLE)(EntityId handle);
typedef __m128 (__fastcall *PFN_GET_STAT_VALUE)(void* pComponent, int statIndex);

// --- Globals (Assuming these are needed) ---
HMODULE g_hTargetModule = NULL;
PFN_HANDLE_COMPONENT_EVENT fpOriginalHandleComponentEvent = NULL;
PFN_GET_PLAYER_ENTITY_HANDLE fpGetPlayerEntityHandle = NULL;
PFN_GET_COMPONENT_FROM_HANDLE fpGetComponentFromHandle = NULL;
PFN_GET_STAT_VALUE fpGetStatValue = NULL;
void** g_ppGlobalSystem = NULL;
FILE* g_logFile = NULL; // Global file handle for logging

// --- Configuration (Assuming these are needed) ---
#define TARGET_FUNCTION_OFFSET 0x65E3CD0
#define GLOBAL_SYSTEM_POINTER_OFFSET 0xA3E38A8
#define GET_PLAYER_HANDLE_FUNCTION_OFFSET 0x67EF650
#define GET_COMPONENT_FROM_HANDLE_OFFSET 0x6906D90
#define GET_STAT_VALUE_OFFSET 0x3AE6980
#define HEALTHPOOL_STAT_INDEX 11
const char* TARGET_MODULE_NAME = NULL; // Keep as char* for GetModuleHandleA


// --- Logging Function (Revised for Wide Characters) ---
void LogToFile(const wchar_t *format, ...) { // Changed format to wchar_t*
    if (g_logFile == NULL) {
        // Fallback to debug output (still uses multibyte here for simplicity)
        char debugBufferNarrow[1024];
        wchar_t debugBufferWide[1024];
        va_list args;

        // Format the wide string first
        va_start(args, format);
        // Use _vsnwprintf_s for safety if available, otherwise vswprintf_s
        #if defined(_MSC_VER) || (defined(__MINGW32__) && __MSVCRT_VERSION__ >= 0x800)
            _vsnwprintf_s(debugBufferWide, sizeof(debugBufferWide)/sizeof(wchar_t), _TRUNCATE, format, args);
        #else
            vswprintf(debugBufferWide, sizeof(debugBufferWide)/sizeof(wchar_t), format, args); // Less safe
        #endif
        va_end(args);

        // Ensure null termination after potential truncation
        debugBufferWide[(sizeof(debugBufferWide)/sizeof(wchar_t)) - 1] = L'\0';

        // Convert wide string to narrow string for OutputDebugStringA
        size_t convertedChars = 0;
        errno_t cvt_err = wcstombs_s(&convertedChars, debugBufferNarrow, sizeof(debugBufferNarrow), debugBufferWide, _TRUNCATE);

        OutputDebugStringA("[Hook DLL - Log Error] Log file not open. Message: ");
        if (cvt_err == 0) {
            OutputDebugStringA(debugBufferNarrow);
        } else {
            OutputDebugStringA("(Failed to convert wide log message)");
        }
        OutputDebugStringA("\n");
        return;
    }

    va_list args;
    va_start(args, format);
    // Use vfwprintf for wide character output to the file
    vfwprintf(g_logFile, format, args);
    va_end(args);
    fflush(g_logFile);
}


// --- Helper Function to Get Player Entity (Uses LogToFile with L"" strings) ---
EntityId GetCurrentPlayerEntity() {
    if (g_ppGlobalSystem == NULL || fpGetPlayerEntityHandle == NULL) {
        LogToFile(L"[Hook DLL] Global system or GetPlayerEntityHandle function not resolved.\n"); // Use L""
        return 0;
    }
    void* pSystem = *g_ppGlobalSystem;
    if (pSystem == NULL) {
       LogToFile(L"[Hook DLL] Global system pointer is NULL.\n"); // Use L""
        return 0;
    }
    EntityId playerEntity = 0;
    fpGetPlayerEntityHandle(pSystem, &playerEntity);
    return playerEntity;
}

// --- Helper Function to Get Player Health (Uses LogToFile with L"" strings) ---
float GetPlayerHealth(EntityId playerId) {
    if (playerId == 0 || fpGetComponentFromHandle == NULL || fpGetStatValue == NULL) {
        return -1.0f;
    }
    void* pHealthComponent = fpGetComponentFromHandle(playerId);
    if (pHealthComponent == NULL) {
       LogToFile(L"[Hook DLL] Failed to get health component for player %llu.\n", (unsigned long long)playerId); // Use L""
        return -1.0f;
    }
    __m128 healthResult = fpGetStatValue(pHealthComponent, HEALTHPOOL_STAT_INDEX);
    return _mm_cvtss_f32(healthResult);
}


// --- Detour Function (Uses LogToFile with L"" strings) ---
__int64 __fastcall DetourHandleComponentEvent(void* this_ptr, void* pEventData) {
    EntityId currentPlayerId = GetCurrentPlayerEntity();

    // Use L"" prefix for wide string literals
    LogToFile(L"[Hook DLL] HandleComponentEvent called for component 0x%p. ", this_ptr);
    if (currentPlayerId != 0) {
        float currentHealth = GetPlayerHealth(currentPlayerId);
        LogToFile(L"Current Player Entity ID: %llu (0x%llX). ",
                  (unsigned long long)currentPlayerId,
                  (unsigned long long)currentPlayerId);
        if (currentHealth >= 0.0f) {
             LogToFile(L"Current Health: %.2f\n", currentHealth);
        } else {
             LogToFile(L"Could not retrieve player health.\n");
        }
    } else {
        LogToFile(L"Could not retrieve Player Entity ID.\n");
    }

    if (fpOriginalHandleComponentEvent) {
        return fpOriginalHandleComponentEvent(this_ptr, pEventData);
    } else {
        LogToFile(L"[Hook DLL] ERROR: Original function pointer is NULL!\n");
        return 0; // Or handle error appropriately
    }
}

// --- Hook Initialization (Uses LogToFile with L"" strings) ---
BOOL InitializeHook() {
    // Use GetModuleHandleA since TARGET_MODULE_NAME is char* (NULL means main exe)
    g_hTargetModule = GetModuleHandleA(TARGET_MODULE_NAME);
    if (g_hTargetModule == NULL) {
        // Use %hs for char* in wide printf functions (standard C)
        // or %S (Microsoft specific)
        LogToFile(L"[Hook DLL] [ERROR] Failed to get handle for target module (%hs). Error: %lu\n",
                TARGET_MODULE_NAME ? TARGET_MODULE_NAME : "main executable", GetLastError());
        return FALSE;
    }
    uintptr_t moduleBase = (uintptr_t)g_hTargetModule;
    LogToFile(L"[Hook DLL] Target module base address: 0x%llX\n", (unsigned long long)moduleBase);

    // Calculate absolute addresses
    uintptr_t targetFuncAddr = moduleBase + TARGET_FUNCTION_OFFSET;
    uintptr_t globalSysPtrAddr = moduleBase + GLOBAL_SYSTEM_POINTER_OFFSET;
    uintptr_t getPlayerFuncAddr = moduleBase + GET_PLAYER_HANDLE_FUNCTION_OFFSET;
    uintptr_t getCompFuncAddr = moduleBase + GET_COMPONENT_FROM_HANDLE_OFFSET;
    uintptr_t getStatFuncAddr = moduleBase + GET_STAT_VALUE_OFFSET;

    // Resolve pointers
    g_ppGlobalSystem = (void**)globalSysPtrAddr;
    fpGetPlayerEntityHandle = (PFN_GET_PLAYER_ENTITY_HANDLE)getPlayerFuncAddr;
    fpGetComponentFromHandle = (PFN_GET_COMPONENT_FROM_HANDLE)getCompFuncAddr;
    fpGetStatValue = (PFN_GET_STAT_VALUE)getStatFuncAddr;

    LogToFile(L"[Hook DLL] Target function address: 0x%llX\n", (unsigned long long)targetFuncAddr);
    LogToFile(L"[Hook DLL] Global system pointer address: 0x%llX\n", (unsigned long long)globalSysPtrAddr);
    LogToFile(L"[Hook DLL] Get player handle function address: 0x%llX\n", (unsigned long long)getPlayerFuncAddr);
    LogToFile(L"[Hook DLL] Get component function address: 0x%llX\n", (unsigned long long)getCompFuncAddr);
    LogToFile(L"[Hook DLL] Get stat value function address: 0x%llX\n", (unsigned long long)getStatFuncAddr);

    // Check if pointers were resolved (check g_ppGlobalSystem itself, not *g_ppGlobalSystem yet)
    if (g_ppGlobalSystem == NULL || fpGetPlayerEntityHandle == NULL || fpGetComponentFromHandle == NULL || fpGetStatValue == NULL) {
         LogToFile(L"[Hook DLL] [ERROR] Failed to resolve one or more required function/data pointers based on offsets.\n");
         // It's possible the offsets are wrong, but the pointers might not be strictly NULL.
         // Add checks for validity if needed, e.g., IsBadReadPtr (with caution).
         // For now, just checking the resolved addresses.
         // return FALSE; // Decide if this is fatal
    }

    if (MH_Initialize() != MH_OK) {
        LogToFile(L"[Hook DLL] [ERROR] MH_Initialize failed\n");
        return FALSE;
    }
    LogToFile(L"[Hook DLL] MinHook Initialized.\n");

    // Create and enable the hook
    MH_STATUS status = MH_CreateHook((LPVOID)targetFuncAddr, &DetourHandleComponentEvent,
                                     (LPVOID*)&fpOriginalHandleComponentEvent);
    if (status != MH_OK) {
        LogToFile(L"[Hook DLL] [ERROR] MH_CreateHook failed. Status: %d\n", status);
        MH_Uninitialize();
        return FALSE;
    }
    LogToFile(L"[Hook DLL] Hook Created.\n");

    status = MH_EnableHook((LPVOID)targetFuncAddr);
    if (status != MH_OK) {
        LogToFile(L"[Hook DLL] [ERROR] MH_EnableHook failed. Status: %d\n", status);
        MH_RemoveHook((LPVOID)targetFuncAddr); // Clean up created hook
        MH_Uninitialize();
        return FALSE;
    }
    LogToFile(L"[Hook DLL] Hook Enabled.\n");

    return TRUE;
}

// --- Hook Shutdown (Uses LogToFile with L"" strings) ---
void ShutdownHook() {
    LogToFile(L"[Hook DLL] Shutting down hooks...\n"); // Use L""

    // Disable and remove hooks only if MinHook was initialized and module handle is valid
    if (g_hTargetModule) {
         uintptr_t targetFuncAddr = (uintptr_t)g_hTargetModule + TARGET_FUNCTION_OFFSET;
         // Check if the hook was actually enabled before trying to disable/remove
         // This requires checking the status returned by MH_EnableHook or maintaining state.
         // For simplicity, we attempt disable/remove, MinHook handles errors gracefully.
         MH_DisableHook((LPVOID)targetFuncAddr); // Ignore return value on shutdown
         MH_RemoveHook((LPVOID)targetFuncAddr); // Ignore return value on shutdown
         LogToFile(L"[Hook DLL] Hook disabled and removed (attempted).\n"); // Use L""
    } else {
         LogToFile(L"[Hook DLL] [WARNING] Target module handle is NULL during shutdown, cannot calculate hook address.\n"); // Use L""
    }

    // Uninitialize MinHook regardless of whether hooks were active
    MH_Uninitialize();
    LogToFile(L"[Hook DLL] MinHook Uninitialized.\n"); // Use L""
}


// --- DllMain ---
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    wchar_t* homePathW = NULL;
    wchar_t logFilePathW[MAX_PATH];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Disable DLL_THREAD_ATTACH/DETACH notifications for performance
            DisableThreadLibraryCalls(hinstDLL);

            // Get user's home directory (Profile path) using wide chars
            if (SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &homePathW) == S_OK) {
                // Construct full log file path using wide characters safely
                int written = swprintf_s(logFilePathW, MAX_PATH, L"%s\\chealth_log.txt", homePathW); // Changed filename slightly

                if (written > 0 && written < MAX_PATH) {
                    // Use _wfopen_s and specify UTF-8 encoding for the file content
                    errno_t err = _wfopen_s(&g_logFile, logFilePathW, L"a+, ccs=UTF-8"); // Append mode, UTF-8

                    if (err != 0 || g_logFile == NULL) {
                        g_logFile = NULL; // Ensure it's NULL if open failed
                        // Use OutputDebugStringW for wide char output if possible
                        OutputDebugStringW(L"[Hook DLL] [ERROR] Failed to open log file using _wfopen_s.\n");
                    } else {
                        // Log success using the wide character logging function
                         LogToFile(L"\n----------------------------------------\n");
                         LogToFile(L"[Hook DLL] Log file opened successfully: %s\n", logFilePathW);
                         // No need to fflush here, LogToFile does it
                    }
                } else {
                    OutputDebugStringW(L"[Hook DLL] [ERROR] Failed to construct log file path string.\n");
                }

                CoTaskMemFree(homePathW); // Free the path string allocated by SHGetKnownFolderPath

            } else {
                 OutputDebugStringW(L"[Hook DLL] [ERROR] Failed to get user home directory path.\n");
            }

            // Now attempt initialization, LogToFile will use debug output if file failed to open
            LogToFile(L"[Hook DLL] DLL Attached (PID: %lu).\n", GetCurrentProcessId()); // Use L""
            if (!InitializeHook()) {
                // Log error even if file isn't open (will go to debug output)
                LogToFile(L"[Hook DLL] [FATAL ERROR] Failed to initialize hooks!\n"); // Use L""
                // Optional: Consider returning FALSE from DllMain if init is critical
                // return FALSE;
            }
            break;

        case DLL_THREAD_ATTACH:
            // Typically not needed, especially after DisableThreadLibraryCalls
            break;

        case DLL_THREAD_DETACH:
            // Typically not needed
            break;

        case DLL_PROCESS_DETACH:
            // lpvReserved indicates if process is terminating (non-NULL) or FreeLibrary (NULL)
            LogToFile(L"[Hook DLL] DLL Detaching (lpvReserved: %p).\n", lpvReserved); // Use L""
            ShutdownHook(); // Clean up hooks and MinHook

            if (g_logFile != NULL) {
                LogToFile(L"[Hook DLL] Closing log file.\n"); // Use L""
                fclose(g_logFile);
                g_logFile = NULL;
            }
            break;
    }
    return TRUE; // Must return TRUE for DLL_PROCESS_ATTACH unless fatal error
}