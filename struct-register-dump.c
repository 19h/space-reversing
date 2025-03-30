/**
 * @file struct_register_dump.c
 * @brief DLL for hooking a target function to log structure field metadata.
 *
 * This program uses the MinHook library to intercept calls to a specific
 * function (identified by GET_STRUCTURE_FIELDS_ADDR) within a target process.
 * The hooked function is assumed to retrieve metadata about fields within
 * registered data structures. This hook logs the structure name, field count,
 * and for each field, its inferred name and offset within the parent structure.
 * It employs POSIX signal handling (SIGSEGV) with setjmp/longjmp for basic
 * memory access safety during the logging process, particularly when reading
 * potentially invalid pointers derived from the target function's output.
 *
 * @note This code assumes a specific 64-bit target environment and relies on
 *       empirically derived structure layouts and function addresses. ASLR
 *       (Address Space Layout Randomization) is not explicitly handled;
 *       addresses may need dynamic calculation in ASLR-enabled targets.
 *       The signal handling mechanism used has known limitations regarding
 *       thread safety in complex multi-threaded applications.
 */

// Define feature test macro *before* any standard includes to ensure
// visibility of POSIX extensions like sig_atomic_t if needed by headers.
// While setjmp/longjmp are standard C, defining this is good practice
// when using signal.h extensively. 200809L corresponds to POSIX.1-2008.
#define _POSIX_C_SOURCE 200809L

// Define WIN32_LEAN_AND_MEAN to exclude rarely-used APIs from windows.h,
// potentially reducing compile times and namespace pollution.
#define WIN32_LEAN_AND_MEAN
#include <windows.h> // Core Windows API functions (Handles, Threads, Memory, etc.)
#include <stdio.h>   // Standard I/O functions (fopen, fprintf, snprintf, etc.)
#include <stdlib.h>  // Standard library functions (getenv, etc.)
#include <stdbool.h> // Boolean type (bool, true, false)
#include <stdint.h>  // Fixed-width integer types (uint64_t, uintptr_t, etc.)
#include <string.h>  // String manipulation functions (unused directly, but indirectly via snprintf)
#include <stdarg.h>  // Variable arguments handling (va_list, va_start, va_end)
#include <direct.h>  // Directory creation (_mkdir)
#include <setjmp.h>  // Non-local jumps (jmp_buf, setjmp, longjmp) for exception handling simulation
#include <signal.h>  // Signal handling functions (signal, SIGSEGV, sig_atomic_t)
#include <errno.h>   // System error numbers (errno)

// Include the MinHook *header* file.
// This provides the function prototypes and type definitions for the MinHook library.
// Ensure MinHook.h is accessible in the include path during compilation.
#include "hook.c" // Note: Typically you include .h files, not .c files. Ensure this is intended.

// --- Type Definitions ---

/**
 * @brief Metadata structure for a dynamically sized vector/array.
 *
 * This structure is assumed to represent the internal state of a container
 * similar to std::vector, holding pointers to the beginning, end (one past
 * the last element), and end of allocated capacity. It is passed as the
 * third argument (a3) to the target function GetStructureFields.
 */
typedef struct FieldVectorMeta {
    void** begin;          /**< Pointer to the first element (void*). */
    void** end;            /**< Pointer one past the last valid element. */
    void** capacity_end;   /**< Pointer to the end of the allocated buffer. */
} FieldVectorMeta;

/**
 * @brief Represents the metadata for a single field within a structure.
 *
 * This structure definition is derived from reverse engineering and log analysis.
 * It is assumed to be 40 bytes in size and contains information about a field,
 * including its name, offset, type, and unique identifier. The pointers within
 * are read from the target process memory and require careful validation.
 */
typedef struct FieldDescriptor {
    const char* name;       /**< Offset 0x00: Pointer to a null-terminated string representing the field name. */
    uint64_t id;            /**< Offset 0x08: Unique identifier or hash for the field. */
    uint64_t type_info;     /**< Offset 0x10: Data representing the field's type (e.g., size, category enum). */
    uint64_t field_offset;  /**< Offset 0x18: Offset of the field within its parent structure (in bytes). */
    uint64_t flags;         /**< Offset 0x20: Bitmask or value representing field properties or flags. */
    // Total size assumed to be 40 bytes (5 * 8 bytes).
} FieldDescriptor;

/**
 * @brief Represents the metadata for a registered structure type.
 *
 * This structure is assumed to be returned by FindStructureDescriptorByName
 * and potentially used internally by GetStructureFields. It contains a pointer
 * to an array of FieldDescriptor structures and the count of fields.
 * @note Only members relevant to the analysis are included here.
 */
typedef struct StructDescriptor {
    FieldDescriptor* fields_array;      /**< Offset 0x00: Pointer to the array of field descriptors. */
    uint64_t field_count;               /**< Offset 0x08: Number of direct fields in this struct. */
    uint64_t unknown_16;                /**< Offset 0x10: Unknown or unused 64-bit value. */
    const char* base_struct_name;       /**< Offset 0x18: Pointer to the name of the base structure, if any. */
    // ... other potential members ...
} StructDescriptor;


// --- Function Pointer Typedefs ---

/**
 * @brief Function pointer type for the target function GetStructureFields.
 *
 * This function is responsible for retrieving field descriptors for a given
 * structure, potentially including inherited fields.
 * @param data_core_ptr (a1) Assumed pointer to a data core instance or context.
 * @param struct_name_or_hash (a2) Assumed name or hash identifying the structure.
 * @param out_field_vector_meta (a3) Pointer to a FieldVectorMeta structure to be populated.
 * @param include_inherited (a4) Boolean flag (originally char) indicating whether to include base class fields.
 * @return Implementation-defined value (observed as related to vector state).
 */
typedef __int64 (__fastcall *fnGetStructureFields)(
    __int64 data_core_ptr,
    const char* struct_name_or_hash,
    FieldVectorMeta* out_field_vector_meta,
    bool include_inherited
);

/**
 * @brief Function pointer type for the auxiliary function FindStructureDescriptorByName.
 *
 * This function is assumed to look up a StructDescriptor based on a name or hash.
 * @param data_core_ptr (a1) Assumed pointer to a data core instance or context.
 * @param name_or_hash (a2) Name or hash identifying the structure.
 * @return Pointer to the corresponding StructDescriptor, or NULL if not found.
 */
typedef StructDescriptor* (__fastcall *fnFindStructureDescriptorByName)(
    __int64 data_core_ptr,
    const char* name_or_hash
);

// --- Globals for Original Functions ---

/**
 * @brief Pointer to the original GetStructureFields function.
 *
 * This global variable is populated by MinHook (MH_CreateHook) with a trampoline
 * that allows calling the original, unhooked function code. It MUST be initialized
 * before being called in the detour function.
 */
static fnGetStructureFields orig_GetStructureFields = NULL;

/**
 * @brief Pointer to the original FindStructureDescriptorByName function.
 *
 * Stored for potential future use or analysis, although not directly hooked here.
 * Its address is assumed based on analysis.
 */
static fnFindStructureDescriptorByName pFindStructureDescriptorByName = NULL;

// --- Addresses (Configuration) ---

/**
 * @brief Base memory address of the target function GetStructureFields (sub_1478AEBB0).
 * @warning Must be updated if the target executable changes or if ASLR is enabled.
 */
#define GET_STRUCTURE_FIELDS_ADDR 0x1478AEBB0

/**
 * @brief Base memory address of the auxiliary function FindStructureDescriptorByName (sub_1478AEE80).
 * @warning Must be updated if the target executable changes or if ASLR is enabled.
 */
#define FIND_STRUCT_DESC_ADDR     0x1478AEE80

// --- Signal Handling Globals ---

/**
 * @brief Jump buffer for setjmp/longjmp.
 *
 * Stores the execution context (registers, stack pointer) saved by setjmp.
 * longjmp restores this context to perform a non-local jump, typically used
 * here for recovering from a SIGSEGV signal.
 * @warning This global buffer makes the signal handling mechanism inherently
 *          NOT thread-safe if multiple threads might trigger SIGSEGV while
 *          the handler is active or call functions using this buffer concurrently.
 */
static jmp_buf g_jump_buffer;

/**
 * @brief Flag indicating if a SIGSEGV occurred within a protected code section.
 *
 * This flag is set by the signal handler (`handle_sigsegv`) before calling longjmp.
 * It helps the main code differentiate between a normal return from setjmp (value 0)
 * and a return via longjmp (value 1). `sig_atomic_t` ensures atomic access within
 * the signal handler context, and `volatile` prevents compiler optimizations
 * that might interfere with its checking.
 */
static volatile sig_atomic_t g_segfault_occurred = 0;

// --- Signal Handler Function ---

/**
 * @brief Signal handler for SIGSEGV (Segmentation Fault).
 *
 * This function is registered using `signal()` to catch memory access violations.
 * Upon catching SIGSEGV, it sets a global flag and performs a non-local jump
 * back to the recovery point established by the most recent `setjmp` call
 * using the global `g_jump_buffer`.
 *
 * @param signum The signal number (expected to be SIGSEGV).
 * @warning This handler contains non-async-signal-safe operations
 *          (OutputDebugStringA) and relies on global state, making it unsuitable
 *          for robust use in complex multi-threaded environments without
 *          significant modifications (e.g., using thread-local storage).
 */
void handle_sigsegv(int signum) {
    // Set flag to indicate a SEGV was caught
    g_segfault_occurred = 1;
    // Log to debugger output (relatively safer than file I/O in a handler)
    OutputDebugStringA("!!! SIGSEGV Caught !!!\n");
    // Jump back to the location saved by the most recent setjmp call.
    // The '1' becomes the return value of setjmp upon resuming there.
    longjmp(g_jump_buffer, 1);
}

// --- Logging Utility ---

/**
 * @brief Appends formatted messages to a structure-specific log file.
 *
 * Constructs a path like "%USERPROFILE%\sc-struct-dump\<struct_name>.h",
 * creates the directory if it doesn't exist, opens the file in append mode,
 * writes the formatted string, and closes the file. Includes basic error
 * handling for path construction, directory creation, and file opening.
 *
 * @param struct_name The name of the structure, used for the filename. If NULL
 *                    or empty, "UNKNOWN_STRUCT" is used.
 * @param format The printf-style format string.
 * @param ... Variable arguments corresponding to the format string.
 * @note File I/O operations are generally not async-signal-safe. Directory
 *       creation might fail if permissions are insufficient. Invalid filename
 *       characters in struct_name are not sanitized.
 */
void log_info(const char* struct_name, const char* format, ...)
{
    // Use a default name if the provided one is NULL or empty
    const char* filename_part = (struct_name && struct_name[0] != '\0') ? struct_name : "UNKNOWN_STRUCT";

    // Get the user's profile directory path (e.g., C:\Users\Username)
    const char* home = getenv("USERPROFILE");
    if (!home) {
        home = "."; // Fallback to current directory if USERPROFILE isn't set
    }

    char dirpath[MAX_PATH];
    // Construct the path to the dump directory
    int written = snprintf(dirpath, sizeof(dirpath), "%s\\sc-struct-dump", home);
    if (written < 0 || written >= sizeof(dirpath)) {
         OutputDebugStringA("Error: Log directory path too long.\n");
         return; // Cannot proceed if path is invalid
    }

    // Attempt to create the directory. _mkdir returns 0 on success, -1 on error.
    // ENOENT means a path component doesn't exist (shouldn't happen here unless home is weird).
    // EEXIST means the directory already exists (which is fine).
    if (_mkdir(dirpath) != 0 && errno != EEXIST) {
        char errBuf[128];
        // Use strerror_s for thread-safe error string retrieval on Windows
        if (strerror_s(errBuf, sizeof(errBuf), errno) != 0) {
            strncpy_s(errBuf, sizeof(errBuf), "Unknown error", _TRUNCATE);
        }
        char msgBuf[MAX_PATH + 100];
        snprintf(msgBuf, sizeof(msgBuf), "Error creating directory '%s': %s\n", dirpath, errBuf);
        OutputDebugStringA(msgBuf);
        // Continue anyway, maybe the file can still be created if the dir exists but _mkdir failed weirdly.
    }


    char filepath[MAX_PATH];
    // Construct the full path to the log file using the structure name
    written = snprintf(filepath, sizeof(filepath), "%s\\%s.h", dirpath, filename_part);

    // Check for path construction errors (e.g., path too long)
    if (written < 0 || written >= sizeof(filepath)) {
         OutputDebugStringA("Error: Log file path too long.\n");
         return; // Cannot proceed if path is invalid
    }

    // Open the log file in append mode ("a")
    FILE* fp = fopen(filepath, "a");
    if (!fp) {
        // If opening fails, log error to the debugger output
        char errBuf[128];
        if (strerror_s(errBuf, sizeof(errBuf), errno) != 0) {
            strncpy_s(errBuf, sizeof(errBuf), "Unknown error", _TRUNCATE);
        }
        char msgBuf[MAX_PATH + 100];
        snprintf(msgBuf, sizeof(msgBuf), "Error opening log file '%s': %s\n", filepath, errBuf);
        OutputDebugStringA(msgBuf);
        return; // Cannot log if file cannot be opened
    }

    // Process variable arguments using va_list
    va_list args;
    va_start(args, format);
    // Write the formatted string to the file
    vfprintf(fp, format, args);
    va_end(args);
    // Add a newline after each message for better readability in the log file
    fprintf(fp, "\n");
    // Close the file handle to flush buffers and release resources
    fclose(fp);
}

// --- Helper Function: Pointer Plausibility Check ---

/**
 * @brief Performs a basic heuristic check if a pointer value is plausible.
 *
 * Checks if the pointer is not NULL and falls outside the typical lower
 * memory region (below 64KB) often reserved or unmapped in user space.
 * This helps avoid attempting to dereference small integer values or NULL pointers
 * that might be incorrectly interpreted as valid addresses.
 *
 * @param ptr The pointer value to check.
 * @return `true` if the pointer seems plausible, `false` otherwise.
 */
bool is_plausible_pointer(const void* ptr) {
    // A simple heuristic: valid user-space pointers are typically not NULL
    // and reside at higher addresses than the first 64KB.
    return ptr != NULL && (uintptr_t)ptr > 0x10000;
}


// --- Hooked Function Implementation (Detour) ---

/**
 * @brief Detour function for GetStructureFields.
 *
 * This function replaces the original GetStructureFields. It first calls the
 * original function using the trampoline pointer (`orig_GetStructureFields`).
 * After the original function returns and populates the output vector, this
 * function iterates through the retrieved field descriptors. For each descriptor,
 * it logs the structure name, field count, and attempts to safely read and log
 * the field's name (via DataPtr), offset, ID, type info, and flags.
 * It uses `setjmp`/`longjmp` in conjunction with a SIGSEGV handler for basic
 * protection against crashes caused by dereferencing invalid pointers during logging.
 *
 * @param data_core_ptr (a1) Passed through to the original function.
 * @param struct_name_or_hash (a2) Used for logging and passed through.
 * @param out_field_vector_meta (a3) Passed through; its contents are analyzed after the original call.
 * @param include_inherited (a4) Used for logging and passed through.
 * @return The result returned by the original `orig_GetStructureFields` function.
 */
__int64 __fastcall my_GetStructureFields(
    __int64 data_core_ptr,
    const char* struct_name_or_hash,
    FieldVectorMeta* out_field_vector_meta,
    bool include_inherited)
{
    // Use the struct name for logging, default if NULL
    const char* log_struct_name = struct_name_or_hash ? struct_name_or_hash : "UNKNOWN_STRUCT";

    // Log entry into the detour function with input parameters
    log_info(log_struct_name, ">>> Entering my_GetStructureFields for '%s' (Inherited: %s)",
             struct_name_or_hash ? struct_name_or_hash : "<NULL>", // Log original name even if NULL
             include_inherited ? "Yes" : "No");

    // Ensure the trampoline to the original function is valid
    if (!orig_GetStructureFields) {
         log_info(log_struct_name, "[FATAL ERROR] Original GetStructureFields pointer is NULL! Hook likely failed.");
         // Cannot proceed without calling the original function.
         return 0; // Return an error indicator or default value.
    }

    // Call the original function using the trampoline pointer provided by MinHook.
    // This allows the game's intended logic to execute and populate 'out_field_vector_meta'.
    log_info(log_struct_name, "    Calling original GetStructureFields (0x%p)...", orig_GetStructureFields);
    __int64 result = orig_GetStructureFields(data_core_ptr, struct_name_or_hash, out_field_vector_meta, include_inherited);
    log_info(log_struct_name, "    Original GetStructureFields returned: 0x%llX", result); // Log the original return value

    // --- Post-call analysis and logging ---

    // Use the determined log_struct_name for subsequent logs
    uint64_t field_count = 0; // Initialize field count

    // Log header for the structure being processed
    log_info(log_struct_name, "--------------------------------------------------");
    log_info(log_struct_name, "Structure: %s", log_struct_name);
    log_info(log_struct_name, "  Include Inherited: %s", include_inherited ? "Yes" : "No");

    // Validate the output vector metadata pointer after the original call
    if (!out_field_vector_meta) {
        log_info(log_struct_name, "  Error: Output FieldVectorMeta pointer is NULL after original call!");
        log_info(log_struct_name, "--------------------------------------------------\n");
        log_info(log_struct_name, "<<< Exiting my_GetStructureFields (Error: NULL vector meta)");
        return result; // Return original result, cannot process fields
    }

    // Log the state of the output vector's pointers
    log_info(log_struct_name, "  Output Meta Pointers: begin=0x%p, end=0x%p, capacity_end=0x%p",
             out_field_vector_meta->begin,
             out_field_vector_meta->end,
             out_field_vector_meta->capacity_end);

    // Calculate the number of fields returned by the original function
    if (!out_field_vector_meta->begin || !out_field_vector_meta->end || out_field_vector_meta->end < out_field_vector_meta->begin) {
         log_info(log_struct_name, "  Warning: Invalid begin/end pointers in vector meta. Field count set to 0.");
         field_count = 0; // Treat as empty if pointers are invalid
    } else {
        // Calculate count based on pointer difference
        field_count = (uint64_t)(out_field_vector_meta->end - out_field_vector_meta->begin);
    }

    log_info(log_struct_name, "  Total Fields Found: %llu", field_count);
    log_info(log_struct_name, "--------------------------------------------------");

    // Proceed only if fields were found and the vector start pointer is valid
    if (field_count > 0 && out_field_vector_meta->begin)
    {
        log_info(log_struct_name, "  Fields:");

        // --- Setup Signal Handler for safe memory access ---
        log_info(log_struct_name, "    (Setting up SIGSEGV handler...)");
        void (*previous_handler)(int) = signal(SIGSEGV, handle_sigsegv);
        log_info(log_struct_name, "    (SIGSEGV handler set, previous=0x%p)", previous_handler);

        // Loop through each entry in the output vector
        log_info(log_struct_name, "    (Entering field processing loop - Count: %llu)", field_count);
        for (uint64_t i = 0; i < field_count; ++i)
        {
            // Get the address of the i-th pointer in the vector
            void** p_field_desc_ptr_addr = out_field_vector_meta->begin + i;
            g_segfault_occurred = 0; // Reset fault flag for this iteration
            const char* found_name = "<Unknown>"; // Default name state for this field

            // --- Protected Section Start ---
            // Save execution context. Returns 0 on first call.
            // Returns non-zero (1 in our case) if longjmp jumps back here.
            if (setjmp(g_jump_buffer) == 0)
            {
                // --- Normal Execution Path ---

                // Risky Operation 1: Read the FieldDescriptor pointer from the vector.
                void* current_field_desc_ptr = *p_field_desc_ptr_addr;
                if (!current_field_desc_ptr) {
                    log_info(log_struct_name, "    [%llu] <NULL FieldDescriptor Pointer>", i);
                    goto next_iteration; // Skip this field
                }

                // Treat the pointer as our FieldDescriptor structure
                FieldDescriptor* field_desc = (FieldDescriptor*)current_field_desc_ptr;

                // Risky Operations 2-N: Read members from the FieldDescriptor structure.
                const char* name_ptr_val = field_desc->name; // Offset 0
                uint64_t id_val = field_desc->id;            // Offset 8
                uint64_t type_info_val = field_desc->type_info; // Offset 16
                uint64_t offset_val = field_desc->field_offset; // Offset 24
                uint64_t flags_val = field_desc->flags;       // Offset 32

                // Log the basic descriptor info
                log_info(log_struct_name, "    [%llu] FieldDesc @ 0x%p:", i, current_field_desc_ptr);
                log_info(log_struct_name, "        Offset: 0x%llX (%llu)", offset_val, offset_val);
                log_info(log_struct_name, "        ID/Hash: 0x%llX", id_val);
                log_info(log_struct_name, "        TypeInfo: 0x%llX", type_info_val);
                log_info(log_struct_name, "        Flags: 0x%llX", flags_val);
                log_info(log_struct_name, "        NamePtr (from Offset 0): 0x%p", name_ptr_val);

                // --- Attempt to read name string using the pointer at Offset 0 ---
                if (is_plausible_pointer(name_ptr_val)) {
                    log_info(log_struct_name, "        NamePtr looks plausible. Attempting to read string...");
                    // Risky Operation N+1: Access the string content.
                    char first_char = name_ptr_val[0]; // Read first char to test validity
                    log_info(log_struct_name, "        Successfully read first char ('%c'). Assuming valid name.", first_char ? first_char : '?');
                    found_name = name_ptr_val; // Assign the found name string pointer
                } else {
                     log_info(log_struct_name, "        NamePtr (0x%p) is NULL or invalid.", name_ptr_val);
                     found_name = "<Invalid NamePtr>";
                }
                // Log the final determined name (or error string)
                log_info(log_struct_name, "        -> Name: %s", found_name);

            }
            else // else block for if (setjmp(...) == 0)
            {
                // --- Exception Path (SIGSEGV occurred, handle_sigsegv called longjmp) ---
                log_info(log_struct_name, "    [%llu] Error: SIGSEGV caught while processing FieldDescriptor at 0x%p! Skipping.", i, p_field_desc_ptr_addr);
                // Re-register the signal handler as it might be reset by the OS.
                signal(SIGSEGV, handle_sigsegv);
            }
            // --- Protected Section End ---

        next_iteration:; // Target for 'goto' when skipping a field due to NULL descriptor pointer.
            log_info(log_struct_name, "        --------------------------------"); // Separator between fields
        } // End for loop
        log_info(log_struct_name, "    (Exited field processing loop)");

        // --- Restore Original Signal Handler ---
        log_info(log_struct_name, "    (Restoring previous SIGSEGV handler: 0x%p)", previous_handler);
        signal(SIGSEGV, previous_handler);
        log_info(log_struct_name, "    (Previous SIGSEGV handler restored)");

    } else if (field_count == 0) {
        // Log if the loop was skipped because no fields were returned
        log_info(log_struct_name, "  (No fields found or vector empty)");
    } else {
        // Log if the loop was skipped due to an invalid vector begin pointer
        log_info(log_struct_name, "  (Error: Field count > 0 but vector begin pointer is NULL)");
    }
    log_info(log_struct_name, "--------------------------------------------------\n"); // Footer for this structure's log entry
    log_info(log_struct_name, "<<< Exiting my_GetStructureFields normally");
    // Return the value originally returned by the hooked function
    return result;
}

// --- Hook Installation Thread ---

/**
 * @brief Initializes MinHook and installs the necessary function hook.
 *
 * This function is executed in a separate thread created by DllMain during
 * DLL_PROCESS_ATTACH. It performs the following steps:
 * 1. Initializes the MinHook library.
 * 2. Gets target function addresses (assumed fixed or pre-calculated).
 * 3. Creates the hook using MH_CreateHook, redirecting the target function
 *    to `my_GetStructureFields` and storing the original function trampoline
 *    in `orig_GetStructureFields`.
 * 4. Enables the created hook using MH_EnableHook.
 * 5. Logs success or failure at each step to the default log file.
 *
 * @param param Unused thread parameter.
 * @return 0 on success, 1 on failure.
 */
DWORD WINAPI HookThread(LPVOID param)
{
    // Use a generic name or NULL for logs before a specific struct is known
    log_info(NULL, "[HookThread] Starting...");
    // Initialize the MinHook library. Required before using other MinHook functions.
    log_info(NULL, "[HookThread] Initializing MinHook...");
    if (MH_Initialize() != MH_OK) {
        log_info(NULL, "[HookThread] MH_Initialize failed!");
        MessageBoxA(NULL, "MinHook initialization failed!", "Hook Error", MB_OK | MB_ICONERROR);
        return 1; // Indicate failure
    }
    log_info(NULL, "[HookThread] MinHook initialized successfully.");

    // Define the target function addresses in memory.
    // These are critical and must match the target process.
    LPVOID pTargetGetFields = (LPVOID)GET_STRUCTURE_FIELDS_ADDR;
    LPVOID pTargetFindDesc = (LPVOID)FIND_STRUCT_DESC_ADDR;
    log_info(NULL, "[HookThread] Target GetStructureFields Address: 0x%p", pTargetGetFields);
    log_info(NULL, "[HookThread] Target FindStructureDescriptorByName Address: 0x%p", pTargetFindDesc);

    // Store the original address of FindStructureDescriptorByName (optional)
    pFindStructureDescriptorByName = (fnFindStructureDescriptorByName)pTargetFindDesc;
    log_info(NULL, "[HookThread] Stored pFindStructureDescriptorByName: 0x%p", pFindStructureDescriptorByName);

    // Create the hook for GetStructureFields.
    log_info(NULL, "[HookThread] Creating hook for GetStructureFields...");
    MH_STATUS status = MH_CreateHook(pTargetGetFields, &my_GetStructureFields, (LPVOID*)&orig_GetStructureFields);
    if (status != MH_OK) {
        log_info(NULL, "[HookThread] MH_CreateHook failed! Status: %d", status);
        MessageBoxA(NULL, "Failed to create hook for GetStructureFields!", "Hook Error", MB_OK | MB_ICONERROR);
        MH_Uninitialize(); // Clean up MinHook
        return 1; // Indicate failure
    }
    // Check if the trampoline pointer was successfully stored.
    if (!orig_GetStructureFields) {
         log_info(NULL, "[HookThread] MH_CreateHook succeeded but orig_GetStructureFields is NULL!");
         // This indicates a potential issue with MinHook or the target function.
         MH_RemoveHook(pTargetGetFields); // Attempt to remove the potentially problematic hook
         MH_Uninitialize();
         return 1;
    }
    log_info(NULL, "[HookThread] Hook created. Original function trampoline: 0x%p", orig_GetStructureFields);

    // Enable the hook. Calls to the target address will now be redirected.
    log_info(NULL, "[HookThread] Enabling hook for GetStructureFields...");
    status = MH_EnableHook(pTargetGetFields);
    if (status != MH_OK) {
        log_info(NULL, "[HookThread] MH_EnableHook failed! Status: %d", status);
        MessageBoxA(NULL, "Failed to enable hook for GetStructureFields!", "Hook Error", MB_OK | MB_ICONERROR);
        // Attempt to clean up if enabling fails
        MH_RemoveHook(pTargetGetFields); // Remove the hook
        MH_Uninitialize();
        return 1; // Indicate failure
    }
    log_info(NULL, "[HookThread] Hook enabled successfully.");

    // Log success and notify the user via message box
    log_info(NULL, "[HookThread] Hook installation complete.");
    MessageBoxA(NULL, "Hook installed successfully!\nCheck the sc-struct-dump directory in your user profile.", "Hook Success", MB_OK | MB_ICONINFORMATION);

    log_info(NULL, "[HookThread] Exiting.");
    return 0; // Indicate success
}

// --- DLL Entry Point ---

/**
 * @brief Main entry point for the DLL.
 *
 * This function is called by the Windows loader when the DLL is attached to
 * or detached from a process, or when threads are created or destroyed.
 * For process attachment, it disables thread notifications and creates a
 * separate thread (`HookThread`) to handle MinHook initialization and hook installation.
 * For process detachment, it disables hooks and uninitializes MinHook.
 *
 * @param hModule Handle to the DLL module.
 * @param ul_reason_for_call Reason for the function call (e.g., DLL_PROCESS_ATTACH).
 * @param lpReserved Reserved parameter (context specific).
 * @return TRUE on success, FALSE on failure (primarily for DLL_PROCESS_ATTACH).
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    // Switch based on the reason DllMain is being called
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Log DLL attachment event to debugger output
        OutputDebugStringA("[DllMain] DLL_PROCESS_ATTACH\n");

        // Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications.
        // This can improve performance and avoid potential deadlocks if thread
        // creation/destruction involves loader locks.
        DisableThreadLibraryCalls(hModule);

        // Create a new thread to perform the hook initialization.
        // It's generally unsafe to perform complex tasks directly in DllMain
        // due to the loader lock.
        OutputDebugStringA("[DllMain] Creating HookThread...\n");
        HANDLE hThread = CreateThread(NULL, // Default security attributes
                                      0,    // Default stack size
                                      HookThread, // Thread function
                                      NULL, // Thread parameter
                                      0,    // Default creation flags
                                      NULL); // Thread ID (not needed)
        if (hThread) {
            OutputDebugStringA("[DllMain] HookThread created successfully. Closing handle.\n");
            // Close the handle immediately. The thread will continue to execute.
            // We don't need the handle to wait for or manage the thread further.
            CloseHandle(hThread);
        } else {
            // Log and notify if thread creation failed.
            OutputDebugStringA("[DllMain] Failed to create HookThread!\n");
            MessageBoxA(NULL, "Failed to create hook installation thread!", "DLL Error", MB_OK | MB_ICONERROR);
            // Consider returning FALSE here to indicate DLL initialization failure.
            // return FALSE;
        }
        break;

    case DLL_THREAD_ATTACH:
        // Called when a new thread starts in the process (notifications disabled).
        break;

    case DLL_THREAD_DETACH:
        // Called when a thread exits cleanly (notifications disabled).
        break;

    case DLL_PROCESS_DETACH:
        // Called when the DLL is being unloaded.
        OutputDebugStringA("[DllMain] DLL_PROCESS_DETACH\n");
        // Use a generic name or NULL for logs during detach
        log_info(NULL, "DLL detaching, removing hooks.");

        // Clean up MinHook resources.
        OutputDebugStringA("[DllMain] Disabling hooks and uninitializing MinHook...\n");
        // Disable all hooks installed by this instance of MinHook.
        MH_DisableHook(MH_ALL_HOOKS);
        // Uninitialize MinHook, freeing allocated resources.
        MH_Uninitialize();
        OutputDebugStringA("[DllMain] MinHook cleanup complete.\n");
        break;
    }
    // Return TRUE to indicate successful handling of the notification.
    return TRUE;
}