/*
 * Frida Script for Interacting with Inferred DataCore Structures (REPL Version)
 * Target: 64-bit Windows/Linux Application (adjust addresses/layouts as needed)
 * Author: AI Assistant based on User Analysis
 * Date: 2025-04-14
 * Version: 2.0 (Using derived offsets)
 *
 * Description:
 * Provides a JavaScript API to list DataCore structures and their fields
 * by reading internal engine data structures directly, without function hooking.
 * Designed for use with the Frida REPL (e.g., via Gadget).
 *
 * Usage from REPL:
 * 1. Load this script: `frida -U -p PID -l datacore_explorer_repl.js` (or attach at launch)
 * 2. Wait for initialization messages in the console.
 * 3. If initialization succeeded, you can use the global `dcApi` object.
 * 4. Examples:
 *    > const structs = dcApi.listAllStructs();
 *    > console.log(JSON.stringify(structs, null, 2));
 *    > const details = dcApi.getStructDetailsByName("SomeStructName"); // Replace with actual name
 *    > console.log(JSON.stringify(details, null, 2));
 *    > const detailsByAddr = dcApi.getStructDetailsByAddress("0xADDRESS_OF_STRUCT_DESC"); // Replace with actual address
 *    > console.log(JSON.stringify(detailsByAddr, null, 2));
 *    > main(); // Run the example function defined below
 *
 * !!! CRITICAL ASSUMPTIONS !!!
 * 1. GLOBAL_DATACORE_POINTER_ADDR points to the *global variable* holding the CDataCore instance pointer.
 * 2. STRUCT_MAP_OFFSET is the correct offset within CDataCore to a std::map<Key, DCStructDesc*>.
 *    Based on analysis of sub_147229160, likely candidates are 0x78 (Name map) or 0x130 (Hash map).
 *    WE ARE USING 0x78 AS THE PRIMARY CANDIDATE. TRY 0x130 IF THIS FAILS.
 * 3. The std::map iteration logic assumes a common MSVC x64 layout. VERIFY THIS.
 * 4. All DCStructDesc and DCFieldDesc offsets MUST be verified via static analysis.
 * 5. Assumes x64 architecture.
 */

'use strict';

(function () { // Wrap in a function scope

    // --- Configuration ---
    // !! VERIFY THESE WITH YOUR ANALYSIS !!
    const MODULE_NAME = null; // Optional: Name of the module containing DataCore globals. Set to null to search all modules.
    const GLOBAL_DATACORE_POINTER_ADDR = ptr('0x14981d200').add(0x78).readPointer(); // Address OF the global pointer variable holding the CDataCore*

    // *** Offset of the map containing DCStructDesc* pointers ***
    // Based on analysis of sub_147229160, likely candidates are:
    // 0x78 (Name map - chosen as primary candidate)
    // 0x130 (Hash map)
    // 0x8 (GUID map - less likely to contain *all* struct types)
    // !! TRY 0x130 IF 0x78 DOES NOT WORK !!
    const STRUCT_MAP_OFFSET = ptr('0x78');

    // --- Inferred Structure Offsets (VERIFY THESE) ---
    const DCStructDescOffsets = {
        FIELDS_ARRAY: ptr(0x0),
        FIELD_COUNT: ptr(0x8),
        BASE_CLASS_NAME_PTR: ptr(0x18), // Offset +24 (0x18) holds const char*
        NAME_PTR: ptr(0x28),            // Offset +40 (0x28) holds const char*
        GUID: ptr(0x34),                // Offset +52 (0x34) holds GUID (16 bytes)
        // Add other offsets if known (e.g., total_size, hash)
    };

    const DCFieldDescOffsets = {
        NAME_PTR: ptr(0x0),
        OFFSET: ptr(0x8),
        ELEMENT_SIZE: ptr(0x10), // Or potentially DCEnumDesc* for enums
        TYPE: ptr(0x18),         // Offset +24 (0x18) holds FieldType (byte)
        SUB_TYPE: ptr(0x19),     // Offset +25 (0x19) holds FieldSubType (byte)
        FLAGS: ptr(0x1A),        // Offset +26 (0x1A) holds FieldFlags (byte)
        STRUCT_DESC_PTR: ptr(0x20), // Offset +32 (0x20) holds DCStructDesc* for nested/pointer types
    };
    const DCFieldDescSize = 40; // Sizeof the struct

    // --- Enums ---
    const FieldType = {
        1: 'Bool', 2: 'Int8', 3: 'Int16', 4: 'Int32', 5: 'Int64',
        6: 'UInt8', 7: 'UInt16', 8: 'UInt32', 9: 'UInt64', 10: 'String',
        11: 'Float', 12: 'Double', 13: 'LocID', 14: 'GUID', 15: 'Enum',
        16: 'StructOrPointer', // Further differentiated by SubType
        17: 'WeakPointer',     // Assumed based on analysis
        UNKNOWN: 'Unknown'
    };

    const FieldSubType = {
        0: 'EmbeddedStruct', 1: 'StrongPointer', 2: 'WeakPointerMap', 3: 'Reference',
        UNKNOWN: 'Unknown'
    };

    const FieldFlags = {
        None: 0,
        IsOptional: 1 << 0,
        IsArray: 1 << 1,
        IsIgnored: 1 << 2,
        IsMaster: 1 << 3,
        IsDefault: 1 << 4,
        FullyInstanced: 1 << 5,
    };

    // --- Helper Functions ---
    function readGuid(ptr) {
        if (!ptr || ptr.isNull()) return null;
        try {
            const d1 = ptr.readU32();
            const d2 = ptr.add(4).readU16();
            const d3 = ptr.add(6).readU16();
            const d4Bytes = ptr.add(8).readByteArray(8);
            const d4Hex = Array.from(new Uint8Array(d4Bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
            return `{${d1.toString(16).padStart(8, '0')}-${d2.toString(16).padStart(4, '0')}-${d3.toString(16).padStart(4, '0')}-${d4Hex.substring(0, 4)}-${d4Hex.substring(4)}}`;
        } catch (e) { console.error(`Error reading GUID at ${ptr}: ${e}`); return null; }
    }

    function fieldTypeToString(typeValue) { return FieldType[typeValue] || FieldType.UNKNOWN; }
    function fieldSubTypeToString(subTypeValue) { return FieldSubType[subTypeValue] || FieldSubType.UNKNOWN; }
    function parseFlags(flagsValue) {
        const flags = [];
        for (const flagName in FieldFlags) {
            if (flagName !== 'None' && (flagsValue & FieldFlags[flagName])) { flags.push(flagName); }
        }
        return flags.length > 0 ? flags.join(' | ') : 'None';
    }
    function safeReadUtf8String(ptr) {
        if (!ptr || ptr.isNull()) return null;
        try { return ptr.readUtf8String(); }
        catch (e) { return null; }
    }

    // --- Structure Parsers ---
    class DCFieldDesc {
        constructor(ptr) { this.ptr = ptr; }
        isValid() { return !this.ptr.isNull(); }
        getName() {
            if (!this.isValid()) return null;
            try { const namePtr = this.ptr.add(DCFieldDescOffsets.NAME_PTR).readPointer(); return safeReadUtf8String(namePtr); }
            catch (e) { console.error(`Error reading field name at ${this.ptr}: ${e}`); return null; }
        }
        getOffset() {
            if (!this.isValid()) return null;
            try { return this.ptr.add(DCFieldDescOffsets.OFFSET).readU64(); }
            catch (e) { console.error(`Error reading field offset at ${this.ptr}: ${e}`); return null; }
        }
        getElementSize() {
            if (!this.isValid()) return null;
            try { return this.ptr.add(DCFieldDescOffsets.ELEMENT_SIZE).readU64(); }
            catch (e) { console.error(`Error reading field element size at ${this.ptr}: ${e}`); return null; }
        }
        getTypeRaw() {
            if (!this.isValid()) return null;
            try { return this.ptr.add(DCFieldDescOffsets.TYPE).readU8(); }
            catch (e) { console.error(`Error reading field type at ${this.ptr}: ${e}`); return null; }
        }
        getType() { return fieldTypeToString(this.getTypeRaw()); }
        getSubTypeRaw() {
            if (!this.isValid()) return null;
            try { return this.ptr.add(DCFieldDescOffsets.SUB_TYPE).readU8(); }
            catch (e) { console.error(`Error reading field sub-type at ${this.ptr}: ${e}`); return null; }
        }
        getSubType() { return fieldSubTypeToString(this.getSubTypeRaw()); }
        getFlagsRaw() {
            if (!this.isValid()) return null;
            try { return this.ptr.add(DCFieldDescOffsets.FLAGS).readU8(); }
            catch (e) { console.error(`Error reading field flags at ${this.ptr}: ${e}`); return null; }
        }
        getFlags() { return parseFlags(this.getFlagsRaw()); }
        isArray() { const f = this.getFlagsRaw(); return f !== null && (f & FieldFlags.IsArray) !== 0; }
        isOptional() { const f = this.getFlagsRaw(); return f !== null && (f & FieldFlags.IsOptional) !== 0; }
        getNestedStructDescPtr() {
            if (!this.isValid()) return NULL;
            try { return this.ptr.add(DCFieldDescOffsets.STRUCT_DESC_PTR).readPointer(); }
            catch (e) { console.error(`Error reading nested struct desc ptr at ${this.ptr}: ${e}`); return NULL; }
        }
        getDetails() {
            if (!this.isValid()) return null;
            const typeRaw = this.getTypeRaw(); const subTypeRaw = this.getSubTypeRaw(); const flagsRaw = this.getFlagsRaw();
            let typeStr = this.getType(); if (typeRaw === 16) { typeStr += ` (${this.getSubType()})`; }
            return {
                address: this.ptr.toString(), name: this.getName(), offset: this.getOffset()?.toString(16),
                type: typeStr, typeRaw: typeRaw, subTypeRaw: subTypeRaw, flags: parseFlags(flagsRaw), flagsRaw: flagsRaw,
                isArray: this.isArray(), isOptional: this.isOptional(), elementSize: this.getElementSize()?.toString(),
                nestedStructDesc: this.getNestedStructDescPtr().toString()
            };
        }
    }

    class DCStructDesc {
        constructor(ptr) { this.ptr = ptr; }
        isValid() { return !this.ptr.isNull(); }
        getName() {
            if (!this.isValid()) return null;
            try { const namePtr = this.ptr.add(DCStructDescOffsets.NAME_PTR).readPointer(); return safeReadUtf8String(namePtr); }
            catch (e) { console.error(`Error reading struct name at ${this.ptr}: ${e}`); return null; }
        }
        getBaseClassName() {
            if (!this.isValid()) return null;
            try { const namePtr = this.ptr.add(DCStructDescOffsets.BASE_CLASS_NAME_PTR).readPointer(); return safeReadUtf8String(namePtr); }
            catch (e) { console.error(`Error reading base class name at ${this.ptr}: ${e}`); return null; }
        }
        getFieldCount() {
            if (!this.isValid()) return 0;
            try { const count = this.ptr.add(DCStructDescOffsets.FIELD_COUNT).readU64(); return count.toNumber(); }
            catch (e) { console.error(`Error reading field count at ${this.ptr}: ${e}`); return 0; }
        }
        getFieldsArrayPtr() {
            if (!this.isValid()) return NULL;
            try { return this.ptr.add(DCStructDescOffsets.FIELDS_ARRAY).readPointer(); }
            catch (e) { console.error(`Error reading fields array ptr at ${this.ptr}: ${e}`); return NULL; }
        }
        getGuid() { if (!this.isValid()) return null; return readGuid(this.ptr.add(DCStructDescOffsets.GUID)); }
        getFields() {
            const fields = []; if (!this.isValid()) return fields;
            const fieldArrayPtr = this.getFieldsArrayPtr(); const count = this.getFieldCount();
            if (fieldArrayPtr.isNull() || count === 0 || count > 10000) {
                if (count > 10000) console.warn(`Suspiciously large field count (${count}) for struct ${this.getName() || this.ptr}`);
                return fields;
            }
            try {
                for (let i = 0; i < count; i++) {
                    const fieldPtr = fieldArrayPtr.add(i * DCFieldDescSize);
                    const fieldDesc = new DCFieldDesc(fieldPtr);
                    if (fieldDesc.isValid()) { fields.push(fieldDesc); }
                    else { console.warn(`Found invalid field descriptor at index ${i} for struct ${this.getName() || this.ptr}`); }
                }
            } catch (e) { console.error(`Error iterating fields for struct ${this.getName() || this.ptr}: ${e}`); }
            return fields;
        }
        getDetails() {
            if (!this.isValid()) return null; const fields = this.getFields();
            return {
                address: this.ptr.toString(), name: this.getName(), guid: this.getGuid(), baseClassName: this.getBaseClassName(),
                fieldCount: fields.length, fields: fields.map(f => f.getDetails())
            };
        }
    }

    // --- Map Iteration (ASSUMES MSVC std::map LAYOUT) ---
    // !! VERIFY AND ADAPT THIS FUNCTION FOR YOUR TARGET !!
    function* iterateStdMap(mapPtr, valueOffsetInPair = 8) {
        const OFFSET_NODE_LEFT = ptr(0x0); const OFFSET_NODE_PARENT = ptr(0x8); const OFFSET_NODE_RIGHT = ptr(0x10);
        const OFFSET_NODE_PAIR_START = ptr(0x20);

        if (!mapPtr || mapPtr.isNull()) { console.error("Map pointer is NULL."); return; }
        try {
            const headerNodePtr = mapPtr.readPointer(); if (headerNodePtr.isNull()) { console.warn("Map header node pointer is NULL."); return; }
            const mapSize = mapPtr.add(8).readU64(); if (mapSize.equals(0)) { return; }
            let currentNodePtr = headerNodePtr.add(OFFSET_NODE_LEFT).readPointer(); // Begin node
            if (currentNodePtr.equals(headerNodePtr)) { console.warn("Map begin node points back to header."); return; }

            let count = 0; const maxCount = mapSize.toNumber() + 10;
            while (!currentNodePtr.equals(headerNodePtr) && count < maxCount) {
                count++;
                const valuePtr = currentNodePtr.add(OFFSET_NODE_PAIR_START).add(valueOffsetInPair).readPointer();
                if (!valuePtr.isNull()) { yield valuePtr; }

                let nextNodePtr = currentNodePtr.add(OFFSET_NODE_RIGHT).readPointer();
                if (!nextNodePtr.isNull() && !nextNodePtr.equals(headerNodePtr)) {
                    currentNodePtr = nextNodePtr; let leftPtr = currentNodePtr.add(OFFSET_NODE_LEFT).readPointer();
                    while (!leftPtr.isNull() && !leftPtr.equals(headerNodePtr)) { currentNodePtr = leftPtr; leftPtr = currentNodePtr.add(OFFSET_NODE_LEFT).readPointer(); }
                } else {
                    nextNodePtr = currentNodePtr.add(OFFSET_NODE_PARENT).readPointer();
                    while (!nextNodePtr.isNull() && !nextNodePtr.equals(headerNodePtr) && currentNodePtr.equals(nextNodePtr.add(OFFSET_NODE_RIGHT).readPointer())) {
                        currentNodePtr = nextNodePtr; nextNodePtr = currentNodePtr.add(OFFSET_NODE_PARENT).readPointer();
                    }
                    if (nextNodePtr.isNull() || nextNodePtr.equals(headerNodePtr)) { break; }
                    currentNodePtr = nextNodePtr;
                }
            }
            if (count >= maxCount) { console.error(`Map iteration exceeded expected size (${mapSize}) + safety margin at ${mapPtr}.`); }
        } catch (e) { console.error(`Error iterating std::map at ${mapPtr}: ${e}\n${e.stack}`); }
    }

    // --- Main API Class ---
    class DataCoreAPI {
        constructor() {
            this.baseAddr = NULL; this.dataCoreInstancePtr = NULL; this.isInitialized = false;
            try {
                const range = Process.findRangeByAddress(GLOBAL_DATACORE_POINTER_ADDR);
                 if (!range || !range.base) {
                     const mainModule = Process.enumerateModules()[0];
                     if (mainModule && GLOBAL_DATACORE_POINTER_ADDR.compare(mainModule.base) >= 0 && GLOBAL_DATACORE_POINTER_ADDR.compare(mainModule.base.add(mainModule.size)) < 0) {
                         this.baseAddr = mainModule.base; console.log(`[DataCoreAPI] Found global pointer within main module at ${mainModule.base}`);
                     } else { throw new Error(`Global pointer ${GLOBAL_DATACORE_POINTER_ADDR} not found in any module range.`); }
                } else { this.baseAddr = range.base; console.log(`[DataCoreAPI] Found global pointer within module range: ${range.name || 'unknown'} at ${this.baseAddr}`); }

                const globalPtrAddr = GLOBAL_DATACORE_POINTER_ADDR;
                this.dataCoreInstancePtr = Memory.readPointer(globalPtrAddr);
                if (this.dataCoreInstancePtr.isNull()) { throw new Error(`CDataCore instance pointer at ${globalPtrAddr} is NULL.`); }
                console.log(`[DataCoreAPI] CDataCore instance found at: ${this.dataCoreInstancePtr}`);
                this.isInitialized = true;
            } catch (e) { console.error(`[DataCoreAPI] Failed to initialize: ${e}`); this.dataCoreInstancePtr = NULL; }
        }
        isReady() { return this.isInitialized && !this.dataCoreInstancePtr.isNull(); }

        listAllStructs() {
            if (!this.isReady()) { console.error("[DataCoreAPI] Not ready."); return []; }
            const structs = []; const seenAddresses = new Set();
            try {
                const mapPtr = this.dataCoreInstancePtr.add(STRUCT_MAP_OFFSET);
                console.log(`[DataCoreAPI] Attempting to iterate map at ${mapPtr} (Offset: ${STRUCT_MAP_OFFSET})...`);
                // *** Assuming the map at STRUCT_MAP_OFFSET stores DCStructDesc* as values ***
                // *** The value offset within the std::pair depends on the key type ***
                // If key is string (often std::string), value offset might be ~0x20 within the pair.
                // If key is hash (u64), value offset is likely 0x8 within the pair.
                // !! ADJUST valueOffsetInPair BASED ON YOUR MAP KEY TYPE !!
                const iterator = iterateStdMap(mapPtr, 8); // Assuming 64-bit hash key, so value is at +8 in pair

                for (const structDescPtr of iterator) {
                    if (structDescPtr.isNull() || seenAddresses.has(structDescPtr.toString())) { continue; }
                    seenAddresses.add(structDescPtr.toString());
                    const structDesc = new DCStructDesc(structDescPtr);
                    const name = structDesc.getName(); const guid = structDesc.getGuid();
                    if (name) { structs.push({ name: name, address: structDescPtr, guid: guid }); }
                }
                console.log(`[DataCoreAPI] Found ${structs.length} potential structs via map at offset ${STRUCT_MAP_OFFSET}.`);
            } catch (e) { console.error(`[DataCoreAPI] Error listing structs: ${e}\n${e.stack}`); }
            structs.sort((a, b) => a.name.localeCompare(b.name));
            return structs;
        }

        getStructDetailsByName(structName) {
            if (!this.isReady()) { console.error("[DataCoreAPI] Not ready."); return null; }
            if (!structName) { console.error("[DataCoreAPI] Struct name must be provided."); return null; }
            try {
                const mapPtr = this.dataCoreInstancePtr.add(STRUCT_MAP_OFFSET);
                const iterator = iterateStdMap(mapPtr, 8); // Adjust offset if needed
                for (const structDescPtr of iterator) {
                    if (structDescPtr.isNull()) continue;
                    const structDesc = new DCStructDesc(structDescPtr);
                    const name = structDesc.getName();
                    if (name === structName) { return structDesc.getDetails(); }
                }
            } catch (e) { console.error(`[DataCoreAPI] Error finding struct "${structName}": ${e}\n${e.stack}`); }
            console.warn(`[DataCoreAPI] Struct "${structName}" not found in the map.`); return null;
        }

        getStructDetailsByAddress(structAddress) {
             if (!this.isReady()) { console.error("[DataCoreAPI] Not ready."); return null; }
             const ptr = ptr(structAddress); if (ptr.isNull()) { console.error("[DataCoreAPI] Invalid address provided."); return null; }
             try {
                 const structDesc = new DCStructDesc(ptr); if (!structDesc.isValid()) return null;
                 if (structDesc.getName() === null) { console.warn(`[DataCoreAPI] Address ${ptr} may not be a valid DCStructDesc.`); /* Allow proceeding */ }
                 return structDesc.getDetails();
             } catch(e) { console.error(`[DataCoreAPI] Error getting struct details for address ${ptr}: ${e}`); return null; }
        }
    }

    // --- Initialization and Global Exposure ---
    console.log("[DataCore Explorer REPL] Initializing...");
    global.dcApi = new DataCoreAPI(); // Expose API globally

    if (global.dcApi.isReady()) {
        console.log("[DataCore Explorer REPL] API ready. Use 'dcApi' object.");
        console.log("Example: const structs = dcApi.listAllStructs(); console.log(JSON.stringify(structs, null, 2));");
        console.log("Example: const details = dcApi.getStructDetailsByName('Vec3'); console.log(JSON.stringify(details, null, 2));");
        console.log("Example: main(); // To run the example function");
    } else {
        console.error("[DataCore Explorer REPL] API failed to initialize. Check configuration and target state.");
    }

    // --- Example Usage Function (Callable from REPL) ---
    global.main = function() {
        if (!global.dcApi || !global.dcApi.isReady()) { console.error("DataCore API not initialized."); return; }
        console.log("\n--- Running REPL Example ---");
        const structs = global.dcApi.listAllStructs();
        console.log(`\nFound ${structs.length} structs:`);
        structs.slice(0, 30).forEach(s => console.log(` - ${s.name} (GUID: ${s.guid || 'N/A'}) @ ${s.address}`));
        if (structs.length > 30) { console.log("  ... (truncated)"); }

        const exampleStructName = "Vec3"; // Common struct name
        if (structs.some(s => s.name === exampleStructName)) {
            console.log(`\nGetting details for struct: ${exampleStructName}`);
            const details = global.dcApi.getStructDetailsByName(exampleStructName);
            if (details) {
                console.log(JSON.stringify(details, (key, value) => {
                    if (value instanceof NativePointer) { return value.toString(); }
                    if (typeof value === 'bigint') { return "0x" + value.toString(16); }
                    return value;
                }, 2));
            } else { console.log(`Could not get details for ${exampleStructName}`); }
        } else { console.log(`\nStruct '${exampleStructName}' not found, skipping details.`); }
        console.log("--- REPL Example Finished ---");
    }

})(); // End of wrapper function scope