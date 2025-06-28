/*
 * Frida Script for Interacting with DataCore Structures (REPL Version)
 * Target: 64-bit Windows/Linux Application (adjust addresses/layouts as needed)
 * Author: AI Assistant based on User Analysis
 * Date: 2025-04-14
 * Version: 4.1 (Excessive Logging Added)
 *
 * Description:
 * Provides a JavaScript API to list DataCore structures and their fields.
 * Includes extensive debugging logs to trace execution flow and pointer values.
 * Designed for use with the Frida REPL (e.g., via Gadget).
 *
 * Usage from REPL:
 * 1. Load this script.
 * 2. Wait for "[DataCore API] Ready." message.
 * 3. Use the global `dcApi` object.
 * 4. Examples:
 *    > dcApi.listCollectedStructNames();
 *    > const details = dcApi.getStructDetails("Vec3");
 *    > console.log(JSON.stringify(details, null, 2));
 *
 * !!! CRITICAL ASSUMPTIONS !!!
 * - Function offsets in FUNC_OFFSETS are correct.
 * - NativeFunction signatures and ABI are correct.
 * - std::vector<DCFieldDesc*> control block size/layout is standard MSVC x64 (24 bytes). VERIFY.
 * - All DCStructDesc and DCFieldDesc offsets MUST be verified via static analysis.
 * - Assumes x64 architecture.
 */

'use strict';

(function () { // Wrap in a function scope

    // --- Configuration ---
    const TARGET_MODULE_NAME = "StarCitizen.exe";
    const VERBOSE_DEBUG_LOGGING = true; // ENABLED FOR MAXIMUM DETAIL

    const FUNC_OFFSETS = {
        DataCore_FindStructDescByName: 0x723EDF0,
        DataCore_GetFieldDescriptors: 0x723EB40,
        GetThreadTempAllocator: 0x3AF4C0,
        TempAllocator_Free: 0x39EFB0,
    };

    // --- Inferred Structure Offsets (VERIFY THESE) ---
    const DCStructDescOffsets = {
        FIELDS_ARRAY: ptr(0x0), FIELD_COUNT: ptr(0x8), BASE_CLASS_NAME_PTR: ptr(0x18),
        NAME_PTR: ptr(0x28), GUID: ptr(0x34), INSTANCE_SIZE: ptr(0x38),
    };
    const DCFieldDescOffsets = {
        NAME_PTR: ptr(0x0), OFFSET: ptr(0x8), ELEMENT_SIZE: ptr(0x10), TYPE: ptr(0x18),
        SUB_TYPE: ptr(0x19), FLAGS: ptr(0x1A), STRUCT_DESC_PTR: ptr(0x20),
    };
    const DCFieldDescSize = 40;
    const POINTER_VECTOR_SIZE = 0x18;
    const POINTER_VECTOR_OFFSETS = { pBegin: 0x00, pEnd: 0x08, pCapacityEnd: 0x10 };

    // --- Enums ---
    const FieldType = { 1: 'Bool', 2: 'Int8', 3: 'Int16', 4: 'Int32', 5: 'Int64', 6: 'UInt8', 7: 'UInt16', 8: 'UInt32', 9: 'UInt64', 10: 'String', 11: 'Float', 12: 'Double', 13: 'LocID', 14: 'GUID', 15: 'Enum', 16: 'StructOrPointer', 17: 'WeakPointer', UNKNOWN: 'Unknown' };
    const FieldSubType = { 0: 'EmbeddedStruct', 1: 'StrongPointer', 2: 'WeakPointerMap', 3: 'Reference', UNKNOWN: 'Unknown' };
    const FieldFlags = { None: 0, IsOptional: 1, IsArray: 2, IsIgnored: 4, IsMaster: 8, IsDefault: 16, FullyInstanced: 32 };
    const DCTypeReverse = Object.fromEntries(Object.entries(FieldType).map(([k, v]) => [v, k]));

    // --- Globals ---
    const g_collectedStructNames = new Set();
    let g_targetModuleBase = ptr(0);
    let g_dataCoreInstancePtr = ptr(0);
    let g_nativeFunctions = {};
    let g_apiInitialized = false;
    let g_pAllocatorState = null;

    // --- Helper Functions ---
    function getTimestamp() { return new Date().toISOString(); }
    function logDebug(message) { if (VERBOSE_DEBUG_LOGGING) { console.log(`[${getTimestamp()}] [DEBUG] ${message}`); } }
    function logInfo(message) { console.log(`[${getTimestamp()}] [INFO] ${message}`); }
    function logError(message, error = null) { console.error(`[${getTimestamp()}] [ERROR] ${message}`); if (error) { console.error(error.stack || error); } }
    function logWarn(message) { console.warn(`[${getTimestamp()}] [WARN] ${message}`); }
    function formatHex(value, width = 8) { if (typeof value === 'number') { return '0x' + value.toString(16).toUpperCase().padStart(width, '0'); } else if (value instanceof NativePointer) { return value.toString(); } else if (value instanceof UInt64 || value instanceof Int64) { return '0x' + value.toString(16).toUpperCase().padStart(width, '0'); } return String(value); }
    function safeReadUtf8String(ptr, maxLength = 1024) { if (!ptr || ptr.isNull()) { return null; } try { return ptr.readUtf8String(maxLength); } catch (e) { logDebug(`safeReadUtf8String failed at ${ptr}: ${e.message}`); return "<READ_ERROR>"; } }
    function safeReadPointer(ptr, offset = 0) { if (!ptr || ptr.isNull()) { return ptr(0); } try { return ptr.add(offset).readPointer(); } catch (e) { logDebug(`safeReadPointer failed at ${ptr.add(offset)}: ${e.message}`); return ptr(0); } }
    function safeReadU64(ptr, offset = 0) { if (!ptr || ptr.isNull()) { return new UInt64(0); } try { return ptr.add(offset).readU64(); } catch (e) { logDebug(`safeReadU64 failed at ${ptr.add(offset)}: ${e.message}`); return new UInt64(0); } }
    function safeReadU8(ptr, offset = 0) { if (!ptr || ptr.isNull()) { return 0; } try { return ptr.add(offset).readU8(); } catch (e) { logDebug(`safeReadU8 failed at ${ptr.add(offset)}: ${e.message}`); return 0; } }
    function readGuid(ptr) { if (!ptr || ptr.isNull()) return null; try { const d1 = ptr.readU32(); const d2 = ptr.add(4).readU16(); const d3 = ptr.add(6).readU16(); const d4Bytes = ptr.add(8).readByteArray(8); const d4Hex = Array.from(new Uint8Array(d4Bytes)).map(b => b.toString(16).padStart(2, '0')).join(''); return `{${d1.toString(16).padStart(8, '0')}-${d2.toString(16).padStart(4, '0')}-${d3.toString(16).padStart(4, '0')}-${d4Hex.substring(0, 4)}-${d4Hex.substring(4)}}`; } catch (e) { return null; } }
    function fieldTypeToString(typeValue) { return FieldType[typeValue] || FieldType.UNKNOWN; }
    function fieldSubTypeToString(subTypeValue) { return FieldSubType[subTypeValue] || FieldSubType.UNKNOWN; }
    function parseFlags(flagsValue) { const flags = []; for (const flagName in FieldFlags) { if (flagName !== 'None' && (flagsValue & FieldFlags[flagName])) { flags.push(flagName); } } return flags.length > 0 ? flags.join(' | ') : 'None'; }

    // --- Structure Parsers ---
    class DCFieldDescReader {
        constructor(ptr) {
            logDebug(`[FieldDescReader @ ${ptr}] Constructor called.`);
            if (!ptr || ptr.isNull()) { logError("[FieldDescReader] NULL pointer passed to constructor."); throw new Error("NULL pointer"); }
            this.ptr = ptr;
            // Read all fields immediately with checks
            this.pNamePtr = safeReadPointer(this.ptr, DCFieldDescOffsets.NAME_PTR);
            this.offsetU64 = safeReadU64(this.ptr, DCFieldDescOffsets.OFFSET);
            this.offset = this.offsetU64.toNumber();
            this.typeSpecificData = safeReadU64(this.ptr, DCFieldDescOffsets.ELEMENT_SIZE);
            this.type = safeReadU8(this.ptr, DCFieldDescOffsets.TYPE);
            this.subType = safeReadU8(this.ptr, DCFieldDescOffsets.SUB_TYPE);
            this.fieldFlags = safeReadU8(this.ptr, DCFieldDescOffsets.FLAGS);
            logDebug(`[FieldDescReader @ ${ptr}] Initial read complete. NamePtr: ${this.pNamePtr}, Offset: ${this.offset}, Type: ${this.type}`);
        }
        isValid() { return !this.ptr.isNull(); } // Basic check
        getName() { return safeReadUtf8String(this.pNamePtr); }
        getOffset() { return this.offsetU64; }
        getElementSize() { return this.typeSpecificData; } // Renamed for clarity
        getTypeRaw() { return this.type; }
        getType() { return fieldTypeToString(this.type); }
        getSubTypeRaw() { return this.subType; }
        getSubType() { return fieldSubTypeToString(this.subType); }
        getFlagsRaw() { return this.fieldFlags; }
        getFlags() { return parseFlags(this.fieldFlags); }
        isArray() { return (this.fieldFlags & FieldFlags.IsArray) !== 0; }
        isOptional() { return (this.fieldFlags & FieldFlags.IsOptional) !== 0; }
        getNestedStructDescPtr() { return safeReadPointer(this.ptr, DCFieldDescOffsets.STRUCT_DESC_PTR); }
        getDetails() {
            if (!this.isValid()) return null;
            let typeStr = this.getType(); if (this.type === 16) { typeStr += ` (${this.getSubType()})`; }
            return { address: this.ptr.toString(), name: this.getName(), offset: this.getOffset()?.toString(16), type: typeStr, typeRaw: this.type, subTypeRaw: this.subType, flags: this.getFlags(), flagsRaw: this.fieldFlags, isArray: this.isArray(), isOptional: this.isOptional(), elementSize: this.getElementSize()?.toString(), nestedStructDesc: this.getNestedStructDescPtr().toString() };
        }
     }
    class DCStructDescReader {
        constructor(ptr) {
            logDebug(`[StructDescReader @ ${ptr}] Constructor called.`);
            if (!ptr || ptr.isNull()) { logError("[StructDescReader] NULL pointer passed to constructor."); throw new Error("NULL pointer"); }
            this.ptr = ptr;
            // Read all fields immediately
            this.pNamePtr = safeReadPointer(this.ptr, DCStructDescOffsets.NAME_PTR);
            this.fieldCountU64 = safeReadU64(this.ptr, DCStructDescOffsets.FIELD_COUNT);
            this.fieldCount = this.fieldCountU64.toNumber();
            this.pParentNamePtr = safeReadPointer(this.ptr, DCStructDescOffsets.BASE_CLASS_NAME_PTR);
            this.pFields = safeReadPointer(this.ptr, DCStructDescOffsets.FIELDS_ARRAY);
            this.instanceSizeU64 = safeReadU64(this.ptr, DCStructDescOffsets.INSTANCE_SIZE);
            this.instanceSize = this.instanceSizeU64.toNumber();
            this.guid = readGuid(this.ptr.add(DCStructDescOffsets.GUID)); // Read GUID here
            logDebug(`[StructDescReader @ ${ptr}] Initial read complete. NamePtr: ${this.pNamePtr}, FieldCount: ${this.fieldCount}, ParentNamePtr: ${this.pParentNamePtr}, FieldsPtr: ${this.pFields}, Size: ${this.instanceSize}, GUID: ${this.guid}`);
        }
        isValid() { return !this.ptr.isNull(); }
        getName() { return safeReadUtf8String(this.pNamePtr); }
        getBaseClassName() { return safeReadUtf8String(this.pParentNamePtr); }
        getFieldCount() { return this.fieldCount; }
        getFieldsArrayPtr() { return this.pFields; }
        getGuid() { return this.guid; }
        getInstanceSize() { return this.instanceSize; }
        getFields() {
            const fields = []; if (!this.isValid()) return fields;
            const fieldArrayPtr = this.getFieldsArrayPtr(); const count = this.getFieldCount();
            logDebug(`[StructDescReader @ ${this.ptr}] getFields called. ArrayPtr: ${fieldArrayPtr}, Count: ${count}`);
            if (fieldArrayPtr.isNull() || count === 0 || count > 10000) { if (count > 10000) logWarn(`Suspiciously large field count (${count}) for struct ${this.getName() || this.ptr}`); return fields; }
            try {
                for (let i = 0; i < count; i++) {
                    const fieldPtr = fieldArrayPtr.add(i * DCFieldDescSize);
                    logDebug(`[StructDescReader @ ${this.ptr}] Reading field ${i} at address ${fieldPtr}`);
                    try {
                        const fieldDesc = new DCFieldDescReader(fieldPtr);
                        fields.push(fieldDesc);
                    } catch (fieldReadError) {
                        logError(`[StructDescReader @ ${this.ptr}] Failed to read field descriptor at index ${i} (ptr: ${fieldPtr})`, fieldReadError);
                    }
                }
            } catch (e) { logError(`Error iterating fields for struct ${this.getName() || this.ptr}: ${e}`); }
            logDebug(`[StructDescReader @ ${this.ptr}] getFields finished. Found ${fields.length} valid fields.`);
            return fields;
        }
        getDetails() { if (!this.isValid()) return null; const fields = this.getFields(); return { address: this.ptr.toString(), name: this.getName(), guid: this.getGuid(), baseClassName: this.getBaseClassName(), instanceSize: this.getInstanceSize(), fieldCount: fields.length, fields: fields.map(f => f.getDetails()) }; }
     }

    // --- Hooking Logic ---
    function onEnter_DataCore_FindStructDescByName(args) {
        logDebug(`[HOOK::FindStructDescByName @ ${this.threadId}] ENTER`);
        const pDataCoreRegistry = args[0];
        const pStructName = args[1];
        logDebug(`  this (pDataCoreRegistry): ${pDataCoreRegistry}`);
        logDebug(`  pStructName: ${pStructName}`);

        if (g_dataCoreInstancePtr.isNull() && !pDataCoreRegistry.isNull()) {
            g_dataCoreInstancePtr = pDataCoreRegistry;
            logInfo(`[HOOK] Captured DataCore instance pointer: ${g_dataCoreInstancePtr}`);
            if (g_nativeFunctions.GetThreadTempAllocator) {
                 try {
                     const arg0 = int64(0), arg1 = int64(0), arg2 = int64(0), arg3 = int64(0);
                     g_pAllocatorState = g_nativeFunctions.GetThreadTempAllocator(arg0, arg1, arg2, arg3);
                     if (!g_pAllocatorState || g_pAllocatorState.isNull()) { logWarn("[HOOK] GetThreadTempAllocator returned NULL."); g_pAllocatorState = null; }
                     else { logInfo(`[HOOK] Obtained TempAllocatorState: ${g_pAllocatorState}`); }
                 } catch (e) { logError("[HOOK] Error calling GetThreadTempAllocator", e); g_pAllocatorState = null; }
            }
            // Signal readiness after first capture
            if (!g_apiInitialized && g_nativeFunctions.DataCore_GetFieldDescriptors) { // Check if functions are ready too
                 g_apiInitialized = true;
                 logInfo("[DataCore API] Ready.");
            }
        } else if (!g_dataCoreInstancePtr.isNull() && !pDataCoreRegistry.equals(g_dataCoreInstancePtr)) {
            logWarn(`[HOOK] Different DataCore instance detected? Expected ${g_dataCoreInstancePtr}, got ${pDataCoreRegistry}`);
        }

        if (!pStructName.isNull()) {
            try {
                const structName = safeReadUtf8String(pStructName);
                logDebug(`  Struct Name Read: "${structName}"`);
                if (structName && structName.length > 0 && !structName.startsWith('<')) {
                    if (!g_collectedStructNames.has(structName)) {
                        logDebug(`[HOOK] Collected new struct name: "${structName}"`);
                        g_collectedStructNames.add(structName);
                    }
                } else { logWarn(`[HOOK] Read empty or invalid struct name from ${pStructName}`); }
            } catch (e) { logError(`[HOOK] Unexpected error processing struct name from ${pStructName}`, e); }
        } else { logWarn("[HOOK] pStructName argument is NULL."); }
        logDebug(`[HOOK::FindStructDescByName @ ${this.threadId}] EXIT`);
    }

    // --- Initialization ---
    function initializeApi() {
        logInfo("[Init] Starting initialization...");
        try { g_targetModuleBase = Process.getModuleByName(TARGET_MODULE_NAME).base; }
        catch (e) { logError(`[Init] Failed to find module ${TARGET_MODULE_NAME}. Trying main module...`); try { g_targetModuleBase = Process.enumerateModules()[0].base; logInfo(`[Init] Using main module base: ${g_targetModuleBase}`); } catch (e2) { logError(`[Init] Failed to get main module base. Aborting.`, e2); return false; } }
        logInfo(`[Init] Using module base address: ${g_targetModuleBase}`);

        const addresses = {}; let allOffsetsValid = true;
        for (const funcName in FUNC_OFFSETS) {
            try { addresses[funcName] = g_targetModuleBase.add(FUNC_OFFSETS[funcName]); logInfo(`[Init] Resolved ${funcName} address: ${addresses[funcName]}`); }
            catch (e) { logError(`[Init] Invalid offset for ${funcName}: ${FUNC_OFFSETS[funcName]}`); allOffsetsValid = false; }
        }
        if (!allOffsetsValid) { logError("[Init] Aborting initialization due to invalid offsets."); return false; }

        logDebug("[Init] Creating NativeFunction objects...");
        try {
            g_nativeFunctions.DataCore_FindStructDescByName = new NativeFunction(addresses.DataCore_FindStructDescByName, 'pointer', ['pointer', 'pointer'], 'win64');
            g_nativeFunctions.DataCore_GetFieldDescriptors = new NativeFunction(addresses.DataCore_GetFieldDescriptors, 'int64', ['pointer', 'pointer', 'pointer', 'int8'], 'win64');
            if (addresses.GetThreadTempAllocator && addresses.TempAllocator_Free) {
                g_nativeFunctions.GetThreadTempAllocator = new NativeFunction(addresses.GetThreadTempAllocator, 'pointer', ['int64', 'int64', 'int64', 'int64'], 'win64');
                g_nativeFunctions.TempAllocator_Free = new NativeFunction(addresses.TempAllocator_Free, 'void', ['pointer', 'pointer', 'uint64', 'int64'], 'win64');
                logInfo("[Init] Allocator functions mapped.");
            } else { logWarn("[Init] Allocator functions not configured/found. Vector memory cleanup will be skipped."); }
        } catch (e) { logError("[Init] Failed to create NativeFunction objects.", e); return false; }
        logInfo("[Init] NativeFunction objects created successfully.");

        logDebug("[Init] Attaching Interceptor hook...");
        try { Interceptor.attach(addresses.DataCore_FindStructDescByName, { onEnter: onEnter_DataCore_FindStructDescByName }); logInfo(`[Init] Hook attached successfully to DataCore_FindStructDescByName at ${addresses.DataCore_FindStructDescByName}.`); }
        catch (e) { logError(`[Init] Failed to attach hook to DataCore_FindStructDescByName.`, e); return false; }

        // API is not fully ready until instance pointer is captured by the hook
        logInfo("[Init] Initialization complete. Waiting for hook to capture instance pointer...");
        return true;
    }

    // --- Core Functionality ---
    function getFieldsForStruct(structName, includeBase = true) {
        logDebug(`[API::getFields] Called for "${structName}", includeBase=${includeBase}`);
        if (!g_apiInitialized || g_dataCoreInstancePtr.isNull()) { logError("[API::getFields] API not ready (Instance pointer not captured yet or init failed)."); return null; }
        if (!g_nativeFunctions.DataCore_GetFieldDescriptors) { logError("[API::getFields] GetStructDataFields function pointer not initialized."); return null; }

        let pFieldVec = null; let pAllocatedNameStr = null; let resultFields = []; let returnedCount = 0;
        let pBegin = ptr(0), pEnd = ptr(0), pCapacityEnd = ptr(0); // Initialize to NULL

        try {
            logDebug(`[API::getFields] Allocating vector control block (size: ${POINTER_VECTOR_SIZE})`);
            pFieldVec = Memory.alloc(POINTER_VECTOR_SIZE);
            Memory.writeByteArray(pFieldVec, Array(POINTER_VECTOR_SIZE).fill(0)); // Zero initialize
            logDebug(`[API::getFields] Allocated vector control block at ${pFieldVec}`);

            logDebug(`[API::getFields] Allocating name string for "${structName}"`);
            pAllocatedNameStr = Memory.allocUtf8String(structName);
            logDebug(`[API::getFields] Allocated name string at ${pAllocatedNameStr}`);

            const includeBaseFlag = includeBase ? 1 : 0;

            logDebug(`[API::getFields] Calling GetStructDataFields(${g_dataCoreInstancePtr}, ${pAllocatedNameStr}, ${pFieldVec}, ${includeBaseFlag})`);
            const retVal = g_nativeFunctions.DataCore_GetFieldDescriptors(g_dataCoreInstancePtr, pAllocatedNameStr, pFieldVec, includeBaseFlag);
            returnedCount = retVal.toNumber();
            logInfo(`[API::getFields] Native function returned: ${retVal} (${returnedCount}) for "${structName}"`);

            logDebug(`[API::getFields] Reading vector pointers from control block at ${pFieldVec}`);
            pBegin = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pBegin);
            pEnd = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pEnd);
            pCapacityEnd = safeReadPointer(pFieldVec, POINTER_VECTOR_OFFSETS.pCapacityEnd);
            logInfo(`[API::getFields] Vector state: Begin=${pBegin}, End=${pEnd}, CapacityEnd=${pCapacityEnd}`);

            // *** ACCESS VIOLATION CHECK ***
            if (pBegin.isNull()) {
                logError(`[API::getFields] pBegin pointer read from vector control block is NULL. Cannot proceed.`);
                if (returnedCount > 0) logWarn(`  Native function returned count ${returnedCount} but pBegin is NULL!`);
                return []; // Return empty array on failure
            }
             if (pEnd.isNull()) {
                logError(`[API::getFields] pEnd pointer read from vector control block is NULL. Cannot calculate count.`);
                 if (returnedCount > 0) logWarn(`  Native function returned count ${returnedCount} but pEnd is NULL!`);
                return []; // Return empty array on failure
            }
            // *****************************

            let calculatedCount = 0;
            if (pEnd.compare(pBegin) >= 0) {
                const byteLength = pEnd.sub(pBegin);
                if (byteLength.mod(Process.pointerSize).eq(0)) {
                     calculatedCount = byteLength.div(Process.pointerSize).toNumber();
                } else { logError(`[API::getFields] Invalid vector size: ${byteLength} bytes.`); }
            } else { logError(`[API::getFields] pEnd (${pEnd}) is before pBegin (${pBegin}). Invalid vector state.`); }

            const fieldCount = returnedCount; // Trust the return value
            if (fieldCount !== calculatedCount && calculatedCount >= 0) { logWarn(`[API::getFields] Count mismatch for ${structName}: Returned=${fieldCount}, Calculated=${calculatedCount}. Using returned count.`); }
            logInfo(`[API::getFields] Processing ${fieldCount} fields for "${structName}".`);

            if (fieldCount > 0) {
                for (let i = 0; i < fieldCount; i++) {
                    const fieldDescPtrAddress = pBegin.add(i * Process.pointerSize);
                    logDebug(`[API::getFields::Field ${i}] Reading field descriptor pointer from address: ${fieldDescPtrAddress}`);
                    // *** ACCESS VIOLATION CHECK ***
                    if (!isReadable(fieldDescPtrAddress, Process.pointerSize)) {
                        logError(`[API::getFields::Field ${i}] Memory at ${fieldDescPtrAddress} (for field pointer) is not readable! Aborting field loop.`);
                        break; // Stop processing fields for this struct
                    }
                    // *****************************
                    const pFieldDescPtr = safeReadPointer(fieldDescPtrAddress);
                    logDebug(`[API::getFields::Field ${i}] Field descriptor pointer: ${pFieldDescPtr}`);

                    if (!pFieldDescPtr || pFieldDescPtr.isNull()) { logWarn(`[API::getFields::Field ${i}] NULL Field Descriptor Pointer found at index ${i}.`); continue; }
                    // *** ACCESS VIOLATION CHECK ***
                    if (!isReadable(pFieldDescPtr, DCFieldDescSize)) {
                         logError(`[API::getFields::Field ${i}] Memory at ${pFieldDescPtr} (for field descriptor) is not readable! Skipping field.`);
                         continue;
                    }
                    // *****************************
                    try { resultFields.push(new DCFieldDescReader(pFieldDescPtr)); }
                    catch (readError) { logError(`[API::getFields::Field ${i}] Error reading field descriptor at index ${i} (ptr: ${pFieldDescPtr})`, readError); }
                }
            }

            // --- Cleanup Vector Buffer ---
            if (!pBegin.isNull() && g_pAllocatorState && g_nativeFunctions.TempAllocator_Free) {
                 if (!pCapacityEnd.isNull() && pCapacityEnd.compare(pBegin) >= 0) {
                    const capacityBytes = pCapacityEnd.sub(pBegin);
                    if (capacityBytes.compare(0) > 0) {
                        try {
                            const freeArg3 = int64(0);
                            logDebug(`[API::getFields] Calling TempAllocator_Free(${g_pAllocatorState}, ${pBegin}, ${capacityBytes}, ${freeArg3})`);
                            g_nativeFunctions.TempAllocator_Free(g_pAllocatorState, pBegin, capacityBytes, freeArg3);
                        } catch (e) { logError(`[API::getFields] Error calling TempAllocator_Free`, e); }
                    } else { logDebug(`[API::getFields] Vector capacity is zero. Skipping free.`); }
                 } else { logWarn(`[API::getFields] Cannot free vector memory: pCapacityEnd (${pCapacityEnd}) invalid relative to pBegin (${pBegin}).`); }
            } else if (!pBegin.isNull()) { logWarn(`[API::getFields] Could not free field vector memory (Addr: ${pBegin}). Allocator state or function missing.`); }

        } catch (e) { logError(`[API::getFields] Error processing "${structName}": ${e}\n${e.stack}`); return null; }
        finally { /* Memory.free(pFieldVec); // Optional */ }

        logDebug(`[API::getFields] Finished processing "${structName}". Returning ${resultFields.length} fields.`);
        return resultFields;
    }

    // --- REPL API Object ---
    global.dcApi = {
        isReady: function() { return g_apiInitialized && !g_dataCoreInstancePtr.isNull(); },
        listCollectedStructNames: function() { return Array.from(g_collectedStructNames).sort(); },
        getStructDetails: function(structName, includeBase = true) {
            if (!this.isReady()) { return { error: "API not ready. Was FindStructDescByName hooked?" }; }
            logInfo(`[API] Getting details for struct: "${structName}" (Inherited: ${includeBase})`);
            let directDesc = null; let pAllocatedNameStr = null; let instanceSize = "N/A"; let parentName = "<N/A>"; let structAddr = "N/A";
            try {
                 pAllocatedNameStr = Memory.allocUtf8String(structName);
                 const pDirectDescPtr = g_nativeFunctions.DataCore_FindStructDescByName(g_dataCoreInstancePtr, pAllocatedNameStr);
                 if (!pDirectDescPtr.isNull()) {
                     structAddr = pDirectDescPtr.toString();
                     directDesc = new DCStructDescReader(pDirectDescPtr);
                     instanceSize = directDesc.getInstanceSize(); parentName = directDesc.parentName;
                 } else { logWarn(`[API::getStructDetails] FindStructDescByName returned NULL for "${structName}".`); }
            } catch(e) { logError(`Error finding direct descriptor for ${structName}`, e); instanceSize = "<Error>"; parentName = "<Error>"; }

            const fields = getFieldsForStruct(structName, includeBase);
            if (fields === null && !directDesc) { return { error: `Failed to retrieve any information for struct "${structName}".` }; }
            if (fields === null) { logWarn(`Failed to retrieve fields for "${structName}", returning basic info only.`); return { name: structName, address: structAddr, instanceSize: instanceSize, parentName: parentName, fieldCount: "Error", fields: [] }; }

            return { name: structName, address: structAddr, instanceSize: instanceSize, parentName: parentName, fieldCount: fields.length, retrievedWithInheritance: includeBase, fields: fields.map(f => f.getDetails()) };
        },
        findField: function(structName, fieldName, includeBase = true) {
            if (!this.isReady()) { console.error("[API::findField] API not ready."); return null; }
            const fields = getFieldsForStruct(structName, includeBase);
            if (!fields) return null;
            const found = fields.find(f => f.getName() === fieldName);
            return found ? found.getDetails() : null;
        }
    };

    // --- Initialization ---
    console.log("[DataCore Explorer REPL] Initializing...");
    if (!initializeApi()) { console.error("[DataCore Explorer REPL] Initialization failed. Check errors."); }

    // --- Example Usage Function ---
    global.main = function() { /* ... same as before ... */
         if (!global.dcApi || !global.dcApi.isReady()) { console.error("DataCore API not initialized."); return; }
        console.log("\n--- Running REPL Example ---");
        const collectedNames = global.dcApi.listCollectedStructNames();
        console.log(`\nFound ${collectedNames.length} unique struct names via hook:`);
        collectedNames.slice(0, 30).forEach(name => console.log(` - ${name}`));
        if (collectedNames.length > 30) { console.log("  ... (truncated)"); }

        const exampleStructName = "Vec3";
        if (collectedNames.includes(exampleStructName)) {
            console.log(`\nGetting details for struct: ${exampleStructName}`);
            const details = global.dcApi.getStructDetails(exampleStructName);
            if (details && !details.error) {
                console.log(JSON.stringify(details, (key, value) => {
                    if (value instanceof NativePointer) { return value.toString(); }
                    if (typeof value === 'bigint') { return "0x" + value.toString(16); }
                    return value;
                }, 2));
            } else { console.log(`Could not get details for ${exampleStructName}. Error: ${details?.error}`); }
        } else { console.log(`\nStruct '${exampleStructName}' not collected by hook (yet?), skipping details.`); }
        console.log("--- REPL Example Finished ---");
     };

})(); // End wrapper function scope

console.log("[DataCore Explorer REPL] Script Loaded. Waiting for hook hits to capture instance pointer, then use 'dcApi'.");