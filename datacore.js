/*
 * Frida Script for Dumping DataCore Structure Definitions
 *
 * Target: 64-bit Windows Application using the DataCore system.
 * Goal: Replicate the functionality of the provided C++ DLL dumper using Frida.
 *       Hooks DataCore_FindStructDescByName to collect names, then immediately
 *       dumps structure details (name, size, fields with offsets/types) to a file
 *       after initialization. Includes extensive debug logging.
 *
 * How to Use:
 * 1.  **Find Addresses:**
 *     - Determine the base address of the target module (EXE or DLL) containing the DataCore functions.
 *     - Find the runtime address of the global DataCoreRegistry instance (often passed as the first argument 'a1'/'rcx' to core DataCore functions). This requires reverse engineering/debugging.
 * 2.  **Configure Script:**
 *     - Update `TARGET_MODULE_NAME` with the name of the module (e.g., "Game.exe", "Core.dll").
 *     - Update `DATA_CORE_INSTANCE_ADDRESS` with the address found in step 1.
 *     - Verify the function offsets (`FUNC_OFFSETS`) match your target version.
 *     - Set `VERBOSE_DEBUG_LOGGING` to true for maximum detail (can be very noisy).
 * 3.  **Run:**
 *     - Attach Frida to the target process: `frida -f <process_name_or_pid> -l <script_name.js>`
 *     - Or spawn the process with Frida: `frida -f <executable_path> -l <script_name.js --no-pause`
 * 4.  **Observe:** The script will initialize, hook the function, and then immediately attempt to dump the structures found *up to that point*. The dump will be written to `datacore_struct_dump.txt`.
 * 5.  **Review Output:** Examine the generated `datacore_struct_dump.txt` file and the Frida console output. Note that structures looked up *after* the script's initial dump will not be included.
 */

// --- Configuration ---
const TARGET_MODULE_NAME = "StarCitizen.exe"; // Or "YourCore.dll", etc.
// IMPORTANT: Replace with the actual runtime address of the DataCoreRegistry instance
// This MUST be found via reversing/debugging. Often the 'this' pointer or first arg.
//const DATA_CORE_INSTANCE_ADDRESS = ptr("0x14981D2C0"); // Example: ptr("0x149808A00");
let DATA_CORE_INSTANCE_ADDRESS = ptr("0x14981d200").add(0x78).readPointer();

const DUMP_FILE_PATH = "datacore_struct_dump.txt";

// Offsets relative to the target module's base address
const FUNC_OFFSETS = {
    DataCore_FindStructDescByName: 0x14723EDF0 - 0x140000000, // sub_14723EDF0
    DataCore_GetFieldDescriptors: 0x14723EB40 - 0x140000000, // sub_14723EB40
    GetThreadTempAllocator: 0x1403AF4C0 - 0x140000000, // sub_1403AF4C0
    TempAllocator_Free: 0x14039EFB0 - 0x140000000, // sub_14039EFB0
};

// --- Logging Configuration ---
const VERBOSE_DEBUG_LOGGING = true; // Set to true for extremely detailed memory/value logs

// --- End Configuration ---

// --- Globals ---
const g_collectedStructNames = new Set();
let g_targetModuleBase = ptr(0);
let g_originalFunctions = {}; // To store NativeFunction pointers
let g_hooksInitialized = false;
// --- End Globals ---

// --- Type Definitions (Frida Representation) ---

// Represents std::vector<void*> or similar (PointerVector in C++)
// We interact with it via a pointer, reading/writing its members.
const POINTER_VECTOR_SIZE = 0x18; // 3 * pointerSize
const POINTER_VECTOR_OFFSETS = {
    pBegin: 0x00,
    pEnd: 0x08,
    pCapacityEnd: 0x10,
};

// Type Enums (Mirrors C++ version)
const DCType = {
    Unknown: 0, Bool: 1, Int8: 2, Int16: 3, Int32: 4, Int64: 5,
    UInt8: 6, UInt16: 7, UInt32: 8, UInt64: 9, String: 10,
    Float: 11, Double: 12, StringHash: 13, Guid: 14, Enum: 15,
    Struct: 16
};
const DCTypeReverse = Object.fromEntries(Object.entries(DCType).map(([k, v]) => [v, k]));

const DCSubType = {
    Scalar: 0, StructInstancePtr: 1, Map: 2, GuidPtr: 3
};
const DCSubTypeReverse = Object.fromEntries(Object.entries(DCSubType).map(([k, v]) => [v, k]));

const DCFlags = {
    None: 0, IsArray: 1
};

// --- Helper Functions ---
function getTimestamp() {
    return new Date().toISOString();
}

function logDebug(message) {
    if (VERBOSE_DEBUG_LOGGING) {
        console.log(`[${getTimestamp()}] [DEBUG] ${message}`);
    }
}

function logInfo(message) {
    console.log(`[${getTimestamp()}] [INFO] ${message}`);
}

function logError(message, error = null) {
    console.error(`[${getTimestamp()}] [ERROR] ${message}`);
    if (error) {
        console.error(error.stack || error);
    }
}

function logWarn(message) {
    console.warn(`[${getTimestamp()}] [WARN] ${message}`);
}

function formatHex(value, width = 8) {
    if (typeof value === 'number') {
        return '0x' + value.toString(16).toUpperCase().padStart(width, '0');
    } else if (value instanceof NativePointer) {
        return value.toString(); // NativePointer already formats as 0x...
    } else if (value instanceof UInt64 || value instanceof Int64) {
         return '0x' + value.toString(16).toUpperCase().padStart(width, '0');
    }
    return String(value); // Fallback
}

function safeReadUtf8String(ptr, maxLength = 1024) {
    if (!ptr || ptr.isNull()) {
        return "<NULL_PTR>";
    }
    try {
        return ptr.readUtf8String(maxLength);
    } catch (e) {
        logError(`safeReadUtf8String failed at ${ptr}`, e);
        return "<READ_ERROR>";
    }
}

function safeReadPointer(ptr, offset = 0) {
    if (!ptr || ptr.isNull()) {
        return ptr(0); // Return null pointer if base is null
    }
    try {
        return ptr.add(offset).readPointer();
    } catch (e) {
        logError(`safeReadPointer failed at ${ptr.add(offset)}`, e);
        return ptr(0);
    }
}

function safeReadU64(ptr, offset = 0) {
    if (!ptr || ptr.isNull()) {
        return new UInt64(0); // Return 0 if base is null
    }
    try {
        return ptr.add(offset).readU64();
    } catch (e) {
        logError(`safeReadU64 failed at ${ptr.add(offset)}`, e);
        return new UInt64(0);
    }
}

function safeReadU8(ptr, offset = 0) {
    if (!ptr || ptr.isNull()) {
        return 0; // Return 0 if base is null
    }
    try {
        return ptr.add(offset).readU8();
    } catch (e) {
        logError(`safeReadU8 failed at ${ptr.add(offset)}`, e);
        return 0;
    }
}
// --- End Helper Functions ---


// Helper class to read DataCoreFieldDesc from memory
class DataCoreFieldDescReader {
    constructor(ptr) {
        logDebug(`[FieldDescReader] Creating reader for address: ${ptr}`);
        if (!ptr || ptr.isNull()) {
            logError("[FieldDescReader] Attempted to read DataCoreFieldDesc from NULL pointer");
            throw new Error("Attempted to read DataCoreFieldDesc from NULL pointer");
        }
        this.ptr = ptr;

        // Read raw values with logging
        this.pNamePtr = safeReadPointer(this.ptr, 0x00);
        logDebug(`[FieldDescReader] Raw pNamePtr (@${this.ptr.add(0x00)}): ${this.pNamePtr}`);

        this.offsetU64 = safeReadU64(this.ptr, 0x08);
        this.offset = this.offsetU64.toNumber(); // Use toNumber() for offsets
        logDebug(`[FieldDescReader] Raw offset (@${this.ptr.add(0x08)}): ${formatHex(this.offsetU64, 16)} (Number: ${this.offset})`);

        this.typeSpecificData = safeReadU64(this.ptr, 0x10);
        logDebug(`[FieldDescReader] Raw typeSpecificData (@${this.ptr.add(0x10)}): ${formatHex(this.typeSpecificData, 16)}`);

        this.type = safeReadU8(this.ptr, 0x18);
        logDebug(`[FieldDescReader] Raw type (@${this.ptr.add(0x18)}): ${this.type} (${formatHex(this.type, 2)})`);

        this.subType = safeReadU8(this.ptr, 0x19);
        logDebug(`[FieldDescReader] Raw subType (@${this.ptr.add(0x19)}): ${this.subType} (${formatHex(this.subType, 2)})`);

        this.fieldFlags = safeReadU8(this.ptr, 0x1A);
        logDebug(`[FieldDescReader] Raw fieldFlags (@${this.ptr.add(0x1A)}): ${this.fieldFlags} (${formatHex(this.fieldFlags, 2)})`);
    }

    get name() {
        const nameStr = safeReadUtf8String(this.pNamePtr);
        logDebug(`[FieldDescReader] Interpreted name: "${nameStr}"`);
        return nameStr;
    }

    get typeString() {
        const typeStr = DCTypeReverse[this.type] || "Unknown";
        logDebug(`[FieldDescReader] Interpreted typeString: "${typeStr}"`);
        return typeStr;
    }

    get subTypeString() {
        const subTypeStr = DCSubTypeReverse[this.subType] || "Unknown";
        logDebug(`[FieldDescReader] Interpreted subTypeString: "${subTypeStr}"`);
        return subTypeStr;
    }

    get flagsString() {
        let s = "";
        if (this.fieldFlags & DCFlags.IsArray) s += "IsArray ";
        // Add other flags if identified
        const flagsStr = s.length === 0 ? "None" : s.trim();
        logDebug(`[FieldDescReader] Interpreted flagsString: "${flagsStr}"`);
        return flagsStr;
    }
}

// Helper class to read DataCoreStructDesc from memory
class DataCoreStructDescReader {
    constructor(ptr) {
        logDebug(`[StructDescReader] Creating reader for address: ${ptr}`);
        if (!ptr || ptr.isNull()) {
            logError("[StructDescReader] Attempted to read DataCoreStructDesc from NULL pointer");
            throw new Error("Attempted to read DataCoreStructDesc from NULL pointer");
        }
        this.ptr = ptr;

        // Read raw values with logging
        this.pNamePtr = safeReadPointer(this.ptr, 0x00);
        logDebug(`[StructDescReader] Raw pNamePtr (@${this.ptr.add(0x00)}): ${this.pNamePtr}`);

        this.fieldCountU64 = safeReadU64(this.ptr, 0x08);
        this.fieldCount = this.fieldCountU64.toNumber();
        logDebug(`[StructDescReader] Raw fieldCount (@${this.ptr.add(0x08)}): ${formatHex(this.fieldCountU64, 16)} (Number: ${this.fieldCount})`);

        this.pParentNamePtr = safeReadPointer(this.ptr, 0x20);
        logDebug(`[StructDescReader] Raw pParentNamePtr (@${this.ptr.add(0x20)}): ${this.pParentNamePtr}`);

        this.pFields = safeReadPointer(this.ptr, 0x30);
        logDebug(`[StructDescReader] Raw pFields (@${this.ptr.add(0x30)}): ${this.pFields}`);

        this.instanceSizeU64 = safeReadU64(this.ptr, 0x38);
        this.instanceSize = this.instanceSizeU64.toNumber();
        logDebug(`[StructDescReader] Raw instanceSize (@${this.ptr.add(0x38)}): ${formatHex(this.instanceSizeU64, 16)} (Number: ${this.instanceSize})`);
    }

    get name() {
        const nameStr = safeReadUtf8String(this.pNamePtr);
        logDebug(`[StructDescReader] Interpreted name: "${nameStr}"`);
        return nameStr;
    }

     get parentName() {
        const parentNameStr = safeReadUtf8String(this.pParentNamePtr);
        logDebug(`[StructDescReader] Interpreted parentName: "${parentNameStr}"`);
        return parentNameStr;
    }
}

// Represents the opaque TempAllocatorState pointer
// We don't need its internal structure, just the pointer itself.

// --- End Type Definitions ---

// --- Hooked Function Logic ---
function onEnter_DataCore_FindStructDescByName(args) {
    DATA_CORE_INSTANCE_ADDRESS = args[0];

    // args[0] is pDataCoreRegistry (rcx)
    // args[1] is pStructName (rdx)
    const pDataCoreRegistry = args[0];
    const pStructName = args[1];
    logDebug(`[HOOK::FindStructDescByName] ENTER`);
    logDebug(`  this (pDataCoreRegistry): ${pDataCoreRegistry}`);
    logDebug(`  pStructName: ${pStructName}`);

    if (!pStructName.isNull()) {
        try {
            // Use readUtf8String without length limit first, fallback with limit if it fails
            let structName = "";
            try {
                 structName = pStructName.readUtf8String();
            } catch (e1) {
                 logWarn(`[HOOK::FindStructDescByName] readUtf8String failed (maybe unterminated?), trying with limit. Error: ${e1.message}`);
                 try {
                     structName = pStructName.readUtf8String(256); // Try reading up to 256 chars
                 } catch (e2) {
                      logError(`[HOOK::FindStructDescByName] Exception reading struct name from ${pStructName} even with limit`, e2);
                      return; // Exit if name cannot be read
                 }
            }

            logDebug(`  Struct Name Read: "${structName}"`);
            if (structName && structName.length > 0) {
                if (!g_collectedStructNames.has(structName)) {
                    logInfo(`[HOOK::FindStructDescByName] Collected new struct name: "${structName}"`);
                    g_collectedStructNames.add(structName);
                } else {
                    logDebug(`[HOOK::FindStructDescByName] Struct name "${structName}" already collected.`);
                }
            } else {
                 logWarn(`[HOOK::FindStructDescByName] Read empty or null struct name from ${pStructName}`);
            }
        } catch (e) {
            // Catch potential errors from has/add just in case
            logError(`[HOOK::FindStructDescByName] Unexpected error processing struct name from ${pStructName}`, e);
        }
    } else {
         logWarn("[HOOK::FindStructDescByName] pStructName argument is NULL.");
    }
    logDebug(`[HOOK::FindStructDescByName] EXIT`);
}
// --- End Hooked Function Logic ---


// --- Dumping Logic ---
function dumpDataCoreStructs() {
    logInfo("Starting DataCore structure dump...");
    logDebug(`[Dump] dumpDataCoreStructs() called.`);

    if (DATA_CORE_INSTANCE_ADDRESS.isNull()) {
        logError("[Dump] DataCoreRegistry instance address (DATA_CORE_INSTANCE_ADDRESS) is not set or is NULL. Cannot dump.");
        return;
    }
    logInfo(`[Dump] Using DataCoreRegistry instance at: ${DATA_CORE_INSTANCE_ADDRESS}`);

    if (!g_hooksInitialized) {
         logError("[Dump] Hooks are not initialized. Function pointers might be invalid. Aborting dump.");
        return;
    }
    logDebug("[Dump] Hooks appear initialized.");

    const dataCoreRegistryPtr = DATA_CORE_INSTANCE_ADDRESS;
    // IMPORTANT: Get the *current* list of names. Since this runs immediately after init,
    // this list might be small or empty depending on when FindStructDescByName is called by the target.
    const namesToDump = Array.from(g_collectedStructNames).sort();

    logInfo(`[Dump] Found ${namesToDump.length} unique structure names collected so far to dump.`);
    if (namesToDump.length === 0) {
        logWarn("[Dump] No structure names were collected before the dump started. The dump file will be mostly empty.");
        logWarn("[Dump] This might happen if DataCore_FindStructDescByName is not called during early application startup.");
    } else {
        logDebug(`[Dump] Names to dump: ${namesToDump.join(', ')}`);
    }


    let file = null;
    let pAllocatorState = null;

    try {
        logInfo(`[Dump] Opening dump file: ${DUMP_FILE_PATH}`);
        file = new File(DUMP_FILE_PATH, "w");
        file.write(`DataCore Structure Dump (${getTimestamp()})\n`);
        file.write(`Target Module: ${TARGET_MODULE_NAME} @ ${g_targetModuleBase}\n`);
        file.write(`DataCore Instance: ${dataCoreRegistryPtr}\n`);
        file.write(`Found ${namesToDump.length} unique structure names collected before dump started.\n`);
        file.write(`Verbose Debug Logging: ${VERBOSE_DEBUG_LOGGING}\n`);
        file.write("==================================================\n\n");
        file.flush();

        // Get the thread-local allocator state *once* for this dump operation
        logDebug("[Dump] Attempting to get thread temporary allocator state...");
        try {
            // ******** FIXED: Use int64(0) for arguments expected to be Int64 ********
            const arg0 = int64(0), arg1 = int64(0), arg2 = int64(0), arg3 = int64(0);
            logDebug(`[Dump] Calling GetThreadTempAllocator(${arg0}, ${arg1}, ${arg2}, ${arg3})`);
            pAllocatorState = g_originalFunctions.GetThreadTempAllocator(arg0, arg1, arg2, arg3);
            // ***********************************************************************
            logInfo(`[Dump] GetThreadTempAllocator returned: ${pAllocatorState}`);
            if (!pAllocatorState || pAllocatorState.isNull()) {
                logWarn("[Dump] Failed to get thread temporary allocator state (returned NULL)! Field vector memory might not be freed.");
                file.write("[WARNING] Failed to get thread temporary allocator state! Field vector memory might leak.\n\n");
                pAllocatorState = null; // Ensure we don't try to use it later
            } else {
                 logInfo(`[Dump] Obtained TempAllocatorState: ${pAllocatorState}`);
            }
        } catch (e) {
             logError("[Dump] Error calling GetThreadTempAllocator", e); // Error would be caught here
             file.write("[ERROR] Error calling GetThreadTempAllocator! Field vector memory might leak.\n\n");
             pAllocatorState = null;
        }


        for (const name of namesToDump) {
            logInfo(`[Dump] Processing struct: "${name}"`);
            file.write(`Struct: "${name}"\n`);
            file.flush(); // Flush before processing each struct

            let instanceSize = "Unknown";
            let parentName = "<N/A>";
            let pAllocatedNameStr = null;

            // 1. Get the direct descriptor for instance size and parent name
            try {
                logDebug(`[Dump::${name}] Allocating memory for name string.`);
                pAllocatedNameStr = Memory.allocUtf8String(name);
                logDebug(`[Dump::${name}] Allocated name string "${name}" at ${pAllocatedNameStr}`);
                logDebug(`[Dump::${name}] Calling DataCore_FindStructDescByName(${dataCoreRegistryPtr}, ${pAllocatedNameStr})`);

                const pDirectDesc = g_originalFunctions.DataCore_FindStructDescByName(dataCoreRegistryPtr, pAllocatedNameStr);
                logDebug(`[Dump::${name}] DataCore_FindStructDescByName returned: ${pDirectDesc}`);

                if (pDirectDesc && !pDirectDesc.isNull()) {
                    logDebug(`[Dump::${name}] Reading direct struct descriptor from ${pDirectDesc}`);
                    try {
                        const descReader = new DataCoreStructDescReader(pDirectDesc);
                        instanceSize = `${descReader.instanceSize} (${formatHex(descReader.instanceSize, 4)})`;
                        parentName = descReader.parentName; // Already logged inside reader if VERBOSE
                        logDebug(`[Dump::${name}] Read instanceSize=${instanceSize}, parentName="${parentName}"`);
                    } catch (readError) {
                         logError(`[Dump::${name}] Error reading DataCoreStructDesc at ${pDirectDesc}`, readError);
                         instanceSize = "Unknown (Error reading StructDesc)";
                         parentName = "<Error reading StructDesc>";
                    }
                } else {
                    logWarn(`[Dump::${name}] DataCore_FindStructDescByName returned NULL. Cannot get direct info.`);
                    instanceSize = "Unknown (FindStructDescByName failed)";
                }
            } catch (e) {
                logError(`[Dump::${name}] Error calling DataCore_FindStructDescByName`, e);
                instanceSize = "Unknown (Error during FindStructDescByName call)";
            }
            // Note: pAllocatedNameStr is intentionally not freed here, it's small and local.

            file.write(`  Instance Size: ${instanceSize}\n`);
            if (parentName !== "<NO_PARENT>" && parentName !== "<READ_ERROR>" && parentName !== "<N/A>" && parentName !== "<NULL_PTR>") {
                 file.write(`  Parent Struct: "${parentName}"\n`);
            }


            // 2. Get all field descriptors (including inherited)
            let pFieldVec = null;
            let fieldCount = 0;
            let pBegin = ptr(0);
            let pEnd = ptr(0);
            let pCapacityEnd = ptr(0);

            try {
                logDebug(`[Dump::${name}] Allocating memory for PointerVector (size: ${POINTER_VECTOR_SIZE})`);
                pFieldVec = Memory.alloc(POINTER_VECTOR_SIZE);
                logDebug(`[Dump::${name}] Allocated PointerVector at ${pFieldVec}`);
                Memory.writeByteArray(pFieldVec, Array(POINTER_VECTOR_SIZE).fill(0)); // Zero initialize

                logDebug(`[Dump::${name}] Re-allocating memory for name string (for GetFieldDescriptors).`);
                pAllocatedNameStr = Memory.allocUtf8String(name);
                logDebug(`[Dump::${name}] Allocated name string "${name}" at ${pAllocatedNameStr}`);

                const includeInherited = 1; // Use char/int8 for the flag
                logDebug(`[Dump::${name}] Calling DataCore_GetFieldDescriptors(${dataCoreRegistryPtr}, ${pAllocatedNameStr}, ${pFieldVec}, ${includeInherited})`);

                const getFieldsRetVal = g_originalFunctions.DataCore_GetFieldDescriptors(
                    dataCoreRegistryPtr,
                    pAllocatedNameStr,
                    pFieldVec,
                    includeInherited // This is 'int8' in the signature, JS number 1 should implicitly convert correctly
                );
                logDebug(`[Dump::${name}] DataCore_GetFieldDescriptors returned: ${getFieldsRetVal} (type: ${typeof getFieldsRetVal})`);

                logDebug(`[Dump::${name}] Reading PointerVector contents from ${pFieldVec}`);
                pBegin = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pBegin);
                pEnd = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pEnd);
                pCapacityEnd = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pCapacityEnd);
                logDebug(`[Dump::${name}] Read pBegin: ${pBegin}`);
                logDebug(`[Dump::${name}] Read pEnd: ${pEnd}`);
                logDebug(`[Dump::${name}] Read pCapacityEnd: ${pCapacityEnd}`);

                if (!pBegin.isNull() && !pEnd.isNull() && pEnd.compare(pBegin) >= 0) {
                    const byteLength = pEnd.sub(pBegin);
                    if (byteLength.mod(Process.pointerSize).eq(0)) {
                         fieldCount = byteLength.div(Process.pointerSize).toNumber();
                         logDebug(`[Dump::${name}] Calculated field count: ${fieldCount} (bytes: ${byteLength})`);
                    } else {
                        logError(`[Dump::${name}] Invalid field vector size: pEnd (${pEnd}) - pBegin (${pBegin}) = ${byteLength} bytes, not divisible by pointer size (${Process.pointerSize}). Treating as 0 fields.`);
                        fieldCount = 0;
                    }
                } else {
                     logWarn(`[Dump::${name}] Field vector pointers invalid or empty (pBegin=${pBegin}, pEnd=${pEnd}). Assuming 0 fields.`);
                     fieldCount = 0;
                }

            } catch (e) {
                logError(`[Dump::${name}] Error calling or processing DataCore_GetFieldDescriptors`, e);
                file.write("  Fields: <Error calling DataCore_GetFieldDescriptors>\n");
                fieldCount = -1; // Indicate error
            }

            if (fieldCount >= 0) {
                 file.write(`  Fields (${fieldCount} total):\n`);
                 if (fieldCount > 0 && !pBegin.isNull()) {
                    for (let i = 0; i < fieldCount; i++) {
                        const fieldDescPtrAddress = pBegin.add(i * Process.pointerSize);
                        logDebug(`[Dump::${name}::Field ${i}] Reading field descriptor pointer from address: ${fieldDescPtrAddress}`);
                        const pFieldDescPtr = safeReadPointer(fieldDescPtrAddress);
                        logDebug(`[Dump::${name}::Field ${i}] Field descriptor pointer: ${pFieldDescPtr}`);

                        if (!pFieldDescPtr || pFieldDescPtr.isNull()) {
                            logWarn(`[Dump::${name}::Field ${i}] NULL Field Descriptor Pointer found at index ${i}.`);
                            file.write(`    <NULL Field Descriptor Pointer at index ${i}>\n\n`);
                            continue;
                        }
                        try {
                            logDebug(`[Dump::${name}::Field ${i}] Reading field descriptor from ${pFieldDescPtr}`);
                            const fieldReader = new DataCoreFieldDescReader(pFieldDescPtr);
                            const fieldName = fieldReader.name;
                            const fieldOffset = fieldReader.offset;
                            const fieldTypeStr = fieldReader.typeString;
                            const fieldSubTypeStr = fieldReader.subTypeString;
                            const fieldFlagsStr = fieldReader.flagsString;

                            logDebug(`[Dump::${name}::Field ${i}] Parsed - Name: "${fieldName}", Offset: ${fieldOffset}, Type: ${fieldTypeStr}, SubType: ${fieldSubTypeStr}, Flags: ${fieldFlagsStr}`);

                            file.write(`    - Name:   "${fieldName}"\n`);
                            file.write(`      Offset: ${fieldOffset} (${formatHex(fieldOffset, 4)})\n`);
                            file.write(`      Type:   ${fieldTypeStr.padEnd(12)} (Enum Val: ${fieldReader.type})\n`);
                            file.write(`      SubType:${fieldSubTypeStr.padEnd(12)} (Enum Val: ${fieldReader.subType})\n`);
                            file.write(`      Flags:  ${fieldFlagsStr.padEnd(12)} (Bitmask: ${formatHex(fieldReader.fieldFlags, 2)})\n`);
                            if (fieldReader.type === DCType.Enum) {
                                file.write(`      EnumSz: ${fieldReader.typeSpecificData.toString()}\n`);
                                logDebug(`[Dump::${name}::Field ${i}] Enum size (typeSpecificData): ${fieldReader.typeSpecificData}`);
                            } else if (fieldReader.type === DCType.Struct) {
                                file.write(`      StruDesc:${formatHex(fieldReader.typeSpecificData, 16)}\n`);
                                logDebug(`[Dump::${name}::Field ${i}] Struct Desc Ptr (typeSpecificData): ${formatHex(fieldReader.typeSpecificData, 16)}`);
                            }
                            file.write("\n");
                        } catch (readError) {
                             logError(`[Dump::${name}::Field ${i}] Error reading field descriptor at index ${i} (ptr: ${pFieldDescPtr})`, readError);
                             file.write(`    <Error reading field descriptor at index ${i}: ${readError.message}>\n\n`);
                        }
                    }
                 } else if (fieldCount === 0) {
                     logDebug(`[Dump::${name}] Struct has 0 fields.`);
                     file.write("    <No fields found>\n\n");
                 } else { // fieldCount > 0 but pBegin is null
                     logError(`[Dump::${name}] Field count is ${fieldCount} but pBegin is NULL. Cannot read fields.`);
                     file.write("    <Error: Field vector start pointer is NULL>\n\n");
                 }
            }

            // 3. Free the memory allocated by DataCore_GetFieldDescriptors using TempAllocator_Free
            if (!pBegin.isNull() && pAllocatorState && !pCapacityEnd.isNull() && pCapacityEnd.compare(pBegin) >= 0) {
                try {
                    const capacityBytes = pCapacityEnd.sub(pBegin); // This is UInt64, matching the signature
                    logDebug(`[Dump::${name}] Preparing to free field vector memory.`);
                    logDebug(`  Allocator State: ${pAllocatorState}`);
                    logDebug(`  Memory Address (pBegin): ${pBegin}`);
                    logDebug(`  Capacity End (pCapacityEnd): ${pCapacityEnd}`);
                    logDebug(`  Calculated Size (bytes): ${capacityBytes}`);

                    if (capacityBytes.compare(0) > 0) {
                        // ******** FIXED: Ensure the last argument is Int64 ********
                        const freeArg3 = int64(0); // Unused alignment argument? Should be int64
                        // **********************************************************
                        logDebug(`[Dump::${name}] Calling TempAllocator_Free(${pAllocatorState}, ${pBegin}, ${capacityBytes}, ${freeArg3})`);
                        const freeRetVal = g_originalFunctions.TempAllocator_Free(
                            pAllocatorState, // pointer
                            pBegin,          // pointer
                            capacityBytes,   // uint64
                            freeArg3         // int64
                        );
                        logDebug(`[Dump::${name}] TempAllocator_Free returned: ${freeRetVal} (type: ${typeof freeRetVal})`);
                    } else {
                        logDebug(`[Dump::${name}] Field vector capacity is zero or negative (${capacityBytes} bytes). Skipping free.`);
                    }
                } catch (e) {
                    logError(`[Dump::${name}] Error calling TempAllocator_Free`, e);
                    file.write("    <Warning: Error calling TempAllocator_Free for field vector>\n\n");
                }
            } else if (!pBegin.isNull()) {
                 logWarn(`[Dump::${name}] Could not free field vector memory (Addr: ${pBegin}). Reason: pAllocatorState=${pAllocatorState}, pCapacityEnd=${pCapacityEnd}`);
                 file.write("    <Warning: Could not free field vector memory - allocator state missing or capacity end NULL/invalid>\n\n");
            } else {
                 logDebug(`[Dump::${name}] No field vector memory to free (pBegin is NULL).`);
            }

            file.write("--------------------------------------------------\n\n");
            file.flush(); // Flush after each struct
            logInfo(`[Dump] Finished processing struct: "${name}"`);
        } // End loop over namesToDump

        logInfo("[Dump] Dump finished successfully.");
        file.write("\n================ END OF DUMP ================\n");
        file.flush();

    } catch (e) {
        logError("[Dump] An critical error occurred during the dumping process", e);
        if (file) {
            try { file.write(`\n\n[FATAL ERROR DURING DUMP: ${e.message}]\n${e.stack}\n`); } catch (_) {}
        }
    } finally {
        if (file) {
            try {
                logInfo(`[Dump] Closing dump file: ${DUMP_FILE_PATH}`);
                file.close();
            } catch (closeError) {
                logError(`[Dump] Error closing dump file`, closeError)
            }
        }
        logDebug("[Dump] dumpDataCoreStructs() finished.");
    }
}
// --- End Dumping Logic ---


// --- Initialization ---
function initializeHooks() {
    logInfo("[Init] Starting initialization...");
    logInfo(`[Init] Attempting to find module: ${TARGET_MODULE_NAME}`);
    const targetModule = Process.findModuleByName(TARGET_MODULE_NAME);
    if (!targetModule) {
        logError(`[Init] Module ${TARGET_MODULE_NAME} not found. Ensure the target process is running and the name is correct.`);
        return false;
    }
    g_targetModuleBase = targetModule.base;
    logInfo(`[Init] Found ${TARGET_MODULE_NAME} at base address: ${g_targetModuleBase}`);
    logDebug(`[Init] Module path: ${targetModule.path}`);
    logDebug(`[Init] Module size: ${targetModule.size}`);

    // Resolve absolute function addresses
    const addresses = {};
    let allOffsetsValid = true;
    for (const funcName in FUNC_OFFSETS) {
        const offset = FUNC_OFFSETS[funcName];
        if (typeof offset !== 'number' || offset < 0) {
             logError(`[Init] Invalid offset configured for ${funcName}: ${offset}`);
             allOffsetsValid = false;
             continue;
        }
        addresses[funcName] = g_targetModuleBase.add(offset);
        logInfo(`[Init] Resolved ${funcName} address: ${addresses[funcName]} (Base: ${g_targetModuleBase} + Offset: ${formatHex(offset)})`);
    }

    if (!allOffsetsValid) {
        logError("[Init] Aborting initialization due to invalid offsets.");
        return false;
    }

    // Prepare NativeFunction pointers for originals we need to call
    logDebug("[Init] Creating NativeFunction objects...");
    try {
        g_originalFunctions.DataCore_FindStructDescByName = new NativeFunction(
            addresses.DataCore_FindStructDescByName,
            'pointer', // DataCoreStructDesc*
            ['pointer', 'pointer'], // (DataCoreRegistry*, const char*)
            'win64'
        );
        logDebug(`[Init] Created NativeFunction for DataCore_FindStructDescByName`);

         g_originalFunctions.DataCore_GetFieldDescriptors = new NativeFunction(
            addresses.DataCore_GetFieldDescriptors,
            'int64', // Return type (likely unused)
            ['pointer', 'pointer', 'pointer', 'int8'], // (DataCoreRegistry*, const char*, PointerVector*, char includeInherited)
            'win64'
        );
        logDebug(`[Init] Created NativeFunction for DataCore_GetFieldDescriptors`);

         g_originalFunctions.GetThreadTempAllocator = new NativeFunction(
            addresses.GetThreadTempAllocator,
            'pointer', // TempAllocatorState*
            ['int64', 'int64', 'int64', 'int64'], // Args expected to be int64
            'win64'
        );
        logDebug(`[Init] Created NativeFunction for GetThreadTempAllocator`);

         g_originalFunctions.TempAllocator_Free = new NativeFunction(
            addresses.TempAllocator_Free,
            'int64', // Return type (likely unused)
            ['pointer', 'pointer', 'uint64', 'int64'], // (TempAllocatorState*, void* mem, size_t size, __int64 alignment/unused)
            'win64'
        );
        logDebug(`[Init] Created NativeFunction for TempAllocator_Free`);

    } catch (e) {
        logError("[Init] Failed to create NativeFunction objects. Check addresses, signatures, and calling conventions.", e);
        return false;
    }
    logInfo("[Init] NativeFunction objects created successfully.");

    // Attach the interceptor hook
    logDebug("[Init] Attaching Interceptor hook...");
    try {
        Interceptor.attach(addresses.DataCore_FindStructDescByName, {
            onEnter: onEnter_DataCore_FindStructDescByName
        });
        logInfo(`[Init] Hook attached successfully to DataCore_FindStructDescByName at ${addresses.DataCore_FindStructDescByName}.`);
    } catch (e) {
        logError(`[Init] Failed to attach hook to DataCore_FindStructDescByName at ${addresses.DataCore_FindStructDescByName}.`, e);
        return false;
    }

    g_hooksInitialized = true;
    logInfo("[Init] Initialization complete.");
    return true;
}

// --- Main Execution ---
logInfo("Frida script loaded. Starting main execution...");

if (initializeHooks()) {
    logInfo("Initialization successful. Hooks are active.");
    logInfo("Passively collecting structure names via DataCore_FindStructDescByName hook...");
    if (DATA_CORE_INSTANCE_ADDRESS.isNull()) {
         logWarn("DATA_CORE_INSTANCE_ADDRESS is currently NULL or not set. Dumping will fail.");
    } else {
         logInfo(`DataCoreRegistry instance currently assumed at: ${DATA_CORE_INSTANCE_ADDRESS}`);
    }

    // --- IMMEDIATE DUMP ---
    logInfo("Attempting immediate dump of collected structures...");
    // Use setImmediate to allow any pending hook events triggered *during* init to potentially fire first
    setImmediate(() => {
        dumpDataCoreStructs();
        logInfo("Immediate dump process finished. Script will remain attached for potential future debugging/hook logs.");
    });
    // --- END IMMEDIATE DUMP ---

} else {
    logError("Initialization failed. Script will not function correctly. Check previous errors.");
}
logInfo("Script main execution finished. Waiting for hooks (if any) and potential async dump completion.");
