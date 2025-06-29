// data_core_struct_dump.js
//
// Frida Script to Capture C++ Struct VTable Addresses and Dump Field Information
//
// Purpose:
// This script hooks into a game engine's C++ reflection system (referred to as DataCore)
// to achieve two main goals:
// 1. Capture the virtual table (vtable) address associated with various C++ structs
//    during their registration process. This involves hooking the registration function(s).
// 2. Dump detailed information about the member fields (name, offset, size, type)
//    for each registered struct by calling a native function provided by the reflection system.
//
// The script combines these two pieces of information into a single, well-formatted JSON output,
// keyed by the struct name.
//
// Features:
// - Indirect Hooking: Hooks a "get instance" function first to reliably find the
//   actual registration function address used for different instances.
// - Optimized Field Dumping: Uses pre-allocated buffers to minimize overhead when
//   calling the native function to retrieve field information repeatedly.
// - VTable Capture: Stores the captured vtable address for each struct.
// - Name Resolution: Attempts to reliably read the struct name during registration.
// - Fallback Name Retrieval: Uses the DataCore's internal name map as a fallback
//   to process structs whose vtables might not have been captured correctly.
// - Formatted JSON Output: Generates a single JSON object containing metadata and
//   a structured representation of each processed struct, its fields, and its vtable.
// - Detailed Field Information: Includes raw and sanitized names, offset, size,
//   type information (enum, derived type name), flags, pointers, etc.
//
// Requirements:
// - Frida tooling installed (https://frida.re/)
// - Target application (likely a 64-bit Windows executable)
// - Correct memory addresses for configuration constants (obtained via reverse engineering).
//


"use strict";

// --- Configuration ---
// These values MUST be updated based on reverse engineering the target application.
// Addresses are likely specific to a particular build of the target.

const ptrSize = Process.pointerSize; // Auto-detect: 4 for 32-bit, 8 for 64-bit

// --- Field Dumping Configuration ---
// Address of the native function used to retrieve field info (e.g., DataCore::GetStructFieldPtrs)
const kDataCoreGetStructFieldPtrsAddr = ptr("0x7FF76505EB40");
// Address of the global environment pointer (e.g., gEnv)
const gEnv = ptr("0x7FF76763D200");
// Offset within the global environment structure to find the pointer to the DataCore instance
const kDataCoreInstanceOffset = ptr("0x78");

// --- VTable Capture Configuration ---
// Address of the pointer to the global registry/manager object (e.g., &qword_14981D2C0)
// !!! CRITICAL: UPDATE THIS ADDRESS FOR YOUR TARGET !!!
const kGlobalRegistryPtrAddr = ptr("0x7FF76763D2C0");
// Offset within the global registry's vtable for the function that returns specific instances
// (e.g., the function called via `(*(_QWORD *)qword_14981D2C0 + 576LL)` -> offset 0x240)
const kGetInstanceVTableOffset = 0x240;
// Offset within the *specific instance's* vtable for the actual struct registration function
// (e.g., the function called via `(*(_QWORD *)v9 + 264LL)` -> offset 0x108)
const kRegistrationFunctionVTableOffset = 0x108;
// Duration (in milliseconds) to wait for VTable capture hooks to run before proceeding to field dumping.
// Adjust based on target application's startup time and registration phase.
const collectionDurationMs = 20000; // 20 seconds

// --- Map Iteration Configuration (for fallback name retrieval) ---
// Offsets relative to the DataCore instance pointer for accessing its internal struct name map.
const kStructNameMapControlOffset = 0x130; // Offset to the map control structure
const kMapControlPtrOffset = 0x0;          // Offset within control struct to bucket control bytes (uint8_t*)
const kMapDataPtrOffset = 0x8;             // Offset within control struct to bucket data array (Slot*)
const kMapMaskOffset = 0x18;            // Offset within control struct to the capacity mask (uint64)
const kMapSlotSize = 72;                // Size of each slot in the bucket data array
const kMapSlotKeyPtrOffset = 0x0;          // Offset within a slot to the pointer to the key (struct name string)
const kMapControlByteEmptyOrDeleted = 0x80;// Control byte value indicating an empty or deleted slot

// --- Field Info Structure Offsets ---
// Offsets within the native 'FieldInfo' struct returned by GetStructFieldPtrs.
const F = {
    name:             0x00, // Pointer to field name (char*)
    offset:           0x08, // Offset of the field within the struct (uint64)
    size:             0x10, // Size of the field (uint64)
    type:             0x18, // Enum representing the basic data type (uint8)
    flags:            0x19, // Various flags (uint8)
    isArrayOrPointer: 0x1a, // Indicator for arrays/pointers (uint8, 0=value, 1=DynArray, >1=?)
    typeSpecificIndex:0x1c, // Index used for enums/structs into type tables (uint32)
    defaultValue:     0x20, // Pointer to default value or nested type name (void*)
};


// --- Globals ---
let gDataCoreInstance = NULL; // Pointer to the main DataCore instance obtained via gEnv
let kGetStructFieldPtrs = null; // NativeFunction object for calling the field dumper

// VTable Capture Globals
// Stores captured data: key=vtableAddrString, value={ name: string|null, vtable: string }
let gRegisteredStructData = {};
let gRegistrationFuncAddr = null; // Address of the actual registration function once found
let gRegistrationHook = null;     // Interceptor handle for the registration function
let gGetInstanceHook = null;      // Interceptor handle for the temporary GetInstance hook
let gVTableInterceptCount = 0;    // Counter for how many times the registration hook is hit

// --- Pre-allocated Buffers for Optimization ---
const MAX_FIELDS_EXPECTED = 2048; // Max fields anticipated per struct
const MAX_STRUCT_NAME_LEN = 512;  // Max anticipated length for struct names
let gFieldProcessingBuffer = null; // Reusable buffer for the field pointer vector
let gFieldProcessingVec = null;    // Reusable pointer to the std::vector-like structure {begin, end, capacity_end}
let gFieldProcessingNamePtr = null;// Reusable buffer for passing the struct name to the native function


// --- Helper Functions ---

/**
 * Checks if a Frida NativePointer is valid (non-null, within reasonable address space).
 * @param {NativePointer} p - The pointer to check.
 * @returns {boolean} True if the pointer appears valid, false otherwise.
 */
function isValidPointer(p) {
    try {
        const MinValid = ptr("0x10000"); // Avoid lower addresses often used for null/errors
        const MaxValid = ptr("0x7FFFFFFFFFFF"); // Basic check against excessively high addresses
        return p && typeof p === 'object' && p instanceof NativePointer && !p.isNull() && p.compare(MinValid) >= 0 && p.compare(MaxValid) <= 0;
    } catch (e) {
        // Catch potential errors if 'p' is not a valid object for comparison
        return false;
    }
}

/**
 * Dumps a region of memory as a hexdump string for debugging.
 * @param {NativePointer} ptr - The starting address to dump.
 * @param {number} [size=64] - The number of bytes to dump.
 * @param {string} [context=""] - Optional context string for error messages.
 * @returns {string} The hexdump string or an error message.
 */
function dumpMemory(ptr, size = 64, context = "") {
    if (!isValidPointer(ptr)) {
        return `Invalid pointer for memory dump (${context})`;
    }
    try {
        return hexdump(ptr, { length: size, ansi: false }); // ansi: false for plain text
    } catch (e) {
        return `Error dumping memory at ${ptr} (${context}): ${e.message}`;
    }
}

/**
 * Attempts to read a string from a pointer, trying CString, UTF-8, and Pointer-to-CString.
 * Prioritizes simple CString with high printable ASCII ratio.
 * @param {NativePointer} ptr - The pointer potentially pointing to a string or a pointer to a string.
 * @param {string} [context=""] - Optional context for logging.
 * @returns {string | null} The successfully read string, or null if no valid string is found.
 */
function readNameFromArg1(ptr, context = "") {
    // console.log(`[readNameFromArg1][${context}] Attempting read from pointer: ${ptr}`);
    if (!isValidPointer(ptr)) {
        // console.warn(`[readNameFromArg1][${context}] Received invalid pointer: ${ptr}`);
        return null;
    }

    // 1. Direct CString read (often used for identifiers)
    try {
        const s = ptr.readCString();
        if (s && s.length > 0) {
             let printableCount = 0;
             for(let i=0; i<s.length; ++i) { const code = s.charCodeAt(i); if (code >= 32 && code < 127) printableCount++; }
             if (printableCount / s.length > 0.85) { // High confidence heuristic
                // console.log(`[readNameFromArg1][${context}] SUCCESS (CString): "${s}"`);
                return s;
             } else {
                 // console.log(`[readNameFromArg1][${context}] CString read, but low printable ratio: "${s}"`);
             }
        }
    } catch (e) { /* Ignore read errors */ }

     // 2. Direct UTF-8 read
    try {
        const s = ptr.readUtf8String();
        // Avoid strings containing the Unicode replacement character, often indicating decode failure
        if (s && s.length > 0 && !s.includes('�')) {
             // console.log(`[readNameFromArg1][${context}] SUCCESS (UTF-8): "${s}"`);
             return s;
        }
    } catch (e) { /* Ignore read errors */ }

    // 3. Read as Pointer-to-CString (handle indirection)
    try {
        const innerPtr = ptr.readPointer();
        if (isValidPointer(innerPtr)) {
            // console.log(`[readNameFromArg1][${context}] Pointer is indirect (${innerPtr}), reading CString from there.`);
            const s = innerPtr.readCString();
             if (s && s.length > 0) {
                 let printableCount = 0; for(let i=0; i<s.length; ++i) { const code = s.charCodeAt(i); if (code >= 32 && code < 127) printableCount++; }
                 if (printableCount / s.length > 0.85) {
                    // console.log(`[readNameFromArg1][${context}] SUCCESS (Pointer->CString): "${s}"`);
                    return s;
                 }
            }
        }
    } catch (e) { /* Ignore read errors */ }

    // If all attempts failed
    console.warn(`[readNameFromArg1][${context}] FAILED to read valid name string from ${ptr}.`);
    console.log(`[readNameFromArg1][${context}] Memory dump @${ptr}:\n${dumpMemory(ptr)}`);
    return null;
}

/**
 * Sanitizes a string to be suitable as a variable name (letters, numbers, underscores).
 * @param {string} name - The raw name string.
 * @returns {string} The sanitized name.
 */
function sanitizeName(name) {
    if (!name || typeof name !== "string" || name.length === 0) return "invalid_or_empty_name";
    // Replace disallowed characters with underscore
    let s = name.replace(/[^A-Za-z0-9_]+/g, "_");
    // Remove leading/trailing underscores
    s = s.replace(/^_+|_+$/g, "");
    // Prepend underscore if starts with a digit
    if (/^[0-9]/.test(s)) {
        s = "_" + s;
    }
    // Handle cases where sanitization results in an empty string
    if (s.length === 0) {
        return "sanitized_empty_name";
    }
    return s;
}

/**
 * Converts internal DataCore type information into a readable C++-like type name.
 * @param {number} typeEnum - The internal type enum value.
 * @param {number} size - The size of the field.
 * @param {number} isArrPtr - The array/pointer indicator (0=value, 1=DynArray, >1=?).
 * @param {number} flags - Field flags (currently unused in this function).
 * @param {NativePointer} defaultValuePtr - Pointer potentially holding nested type name for structs/enums.
 * @returns {string} A derived type name string.
 */
function getFieldTypeName(typeEnum, size, isArrPtr, flags, defaultValuePtr) {
    const t = typeof typeEnum === "number" ? typeEnum : typeEnum.toNumber();
    let sz = typeof size === 'number' ? size : Number(size.toString());
    const arrPtr = typeof isArrPtr === "number" ? isArrPtr : isArrPtr.toNumber();

    let baseType = "";
    switch (t) {
        case 1: baseType = "bool"; break;
        case 2: baseType = "int8_t"; break;
        case 3: baseType = "int16_t"; break;
        case 4: baseType = "int32_t"; break;
        case 5: baseType = "int64_t"; break;
        case 6: baseType = "uint8_t"; break;
        case 7: baseType = "uint16_t"; break;
        case 8: baseType = "uint32_t"; break;
        case 9: baseType = "uint64_t"; break;
        case 10: baseType = "CryStringT"; break; // Assumed name
        case 11: baseType = "float"; break;
        case 12: baseType = "double"; break;
        case 13: baseType = "CLocId"; break; // Assumed name
        case 14: baseType = "CryGUID"; break; // Assumed name
        case 15: // Enum type
            baseType = (sz === 1) ? "uint8_t" :
                       (sz === 2) ? "uint16_t" :
                       (sz === 4) ? "uint32_t" :
                       (sz === 8) ? "uint64_t" : "uint8_t"; // Base integer type
            baseType += " /* Enum */";
            break;
        case 16: // Struct or Array/Pointer to Struct
            const nestedStructName = readNameFromArg1(defaultValuePtr, `Type 16 StructName`);
            const finalName = nestedStructName || `UnknownStruct_${defaultValuePtr}`; // Use placeholder if read fails
            // Determine if it's an array/pointer based on isArrPtr
            if (arrPtr === 1) {
                baseType = `DynArray<${finalName}>`; // Common dynamic array pattern
            } else if (arrPtr > 1) {
                 // Higher values might indicate pointer-to-array or multi-dimensional arrays.
                 // This requires more specific knowledge of the system. Defaulting to pointer.
                 baseType = `DynArray<${finalName}>*`;
            } else {
                // If not array/pointer indicator, check flags? Or assume value type.
                // Example: Check if flags indicate it's a pointer (e.g., if (flags & 1))
                baseType = finalName; // Assume value type by default
            }
            break;
        default:
            baseType = `uint8_t /* UnknownType:${t} */`;
            break;
    }
    return baseType;
}

/**
 * Retrieves a list of all known struct names by iterating DataCore's internal hash map.
 * Used as a fallback/cross-reference mechanism.
 * @returns {string[]} An array of struct names found in the map.
 */
function getAllStructNames() {
    if (!isValidPointer(gDataCoreInstance)) {
        console.error("DataCore instance is invalid in getAllStructNames.");
        return [];
    }
    try {
        const mapControlPtr = gDataCoreInstance.add(kStructNameMapControlOffset);
        const pCtrl = mapControlPtr.add(kMapControlPtrOffset).readPointer();
        const pData = mapControlPtr.add(kMapDataPtrOffset).readPointer();
        const capacity = mapControlPtr.add(kMapMaskOffset).readU64().add(1).toNumber(); // Capacity = Mask + 1

        if (!isValidPointer(pCtrl) || !isValidPointer(pData) || capacity <= 0 || capacity > 50000) { // Sanity checks
             console.error(`Invalid map parameters: pCtrl=${pCtrl}, pData=${pData}, capacity=${capacity}`);
             return [];
        }

        const structNames = [];
        for (let i = 0; i < capacity; i++) {
            const controlByte = pCtrl.add(i).readU8();
            // Skip empty or deleted slots based on the control byte
            if (controlByte !== kMapControlByteEmptyOrDeleted) {
                const slotAddr = pData.add(i * kMapSlotSize);
                const keyPtr = slotAddr.add(kMapSlotKeyPtrOffset).readPointer();
                const name = readNameFromArg1(keyPtr, `StructMap Slot ${i}`); // Use robust reading
                if (name) {
                    structNames.push(name);
                } else {
                    // console.warn(`Failed to read name from map slot ${i}, ptr: ${keyPtr}`);
                }
            }
        }
        console.log(`Found ${structNames.length} potential struct names from map.`);
        return structNames;
    } catch (e) {
        console.error(`Error in getAllStructNames: ${e.message}\n${e.stack}`);
        return [];
    }
}

// --- VTable Capture Logic ---

/**
 * Callback function attached to the identified struct registration function.
 * Extracts vtable pointer and attempts to read the struct name.
 * Stores the mapping in gRegisteredStructData.
 * @param {InvocationArguments} args - Arguments passed to the native registration function.
 */
const registrationCallback = {
    onEnter: function(args) {
        gVTableInterceptCount++;
        const structNamePtr = args[1]; // RDX - Expected pointer to struct name
        const vtableInfoPtr = args[2]; // R8 - Expected pointer to the pointer to the vtable (&off_XXXX)

        if (!isValidPointer(vtableInfoPtr)) {
            return; // Cannot proceed without this
        }

        let vtableActualPtr = null;
        try {
            // Dereference args[2] to get the actual vtable address
            vtableActualPtr = vtableInfoPtr.readPointer();
            if (!isValidPointer(vtableActualPtr)) {
                 return; // VTable address itself is invalid
            }
        } catch (e) {
            return; // Error reading the vtable pointer
        }

        const vtableAddrString = vtableActualPtr.toString();

        // Avoid redundant processing if we've already captured this vtable
        if (gRegisteredStructData[vtableAddrString]) {
            return;
        }

        // --- Attempt to get the name from args[1] ---
        const foundName = readNameFromArg1(structNamePtr, `Reg Hook #${gVTableInterceptCount}`);

        // Store the result, keyed by the vtable address string
        gRegisteredStructData[vtableAddrString] = {
             name: foundName, // Store the found name (can be null if read failed)
             vtable: vtableAddrString
        };
        // Optional: Log capture success/failure
        // console.log(`[Reg Hook] Stored VTable ${vtableAddrString}. Name: ${foundName ? `"${foundName}"` : "[Failed]"}`);
    },
    // onLeave: function(retval) { /* Optional */ }
};

/**
 * Sets up the VTable capture hooks using an indirect approach.
 * Hooks the "GetInstance" function first to find the target registration function.
 */
function setupVTableHooks() {
    console.log("Setting up VTable hooks...");
    try {
        // 1. Get pointer to the global registry object
        const globalRegistryPtr = kGlobalRegistryPtrAddr.readPointer();
        if (!isValidPointer(globalRegistryPtr)) throw new Error("Failed to read global registry pointer");

        // 2. Get the vtable of the global registry object
        const globalVTablePtr = globalRegistryPtr.readPointer();
        if (!isValidPointer(globalVTablePtr)) throw new Error("Failed to read global vtable pointer");

        // 3. Get the address of the "GetInstance" function from the global vtable
        const getInstanceFuncAddr = globalVTablePtr.add(kGetInstanceVTableOffset).readPointer();
        if (!isValidPointer(getInstanceFuncAddr)) throw new Error("Failed to read 'get instance' function pointer");

        console.log(`Attaching temporary hook to GetInstance @ ${getInstanceFuncAddr}`);
        // 4. Attach a temporary hook to the GetInstance function
        gGetInstanceHook = Interceptor.attach(getInstanceFuncAddr, {
            onLeave: function(retval) {
                // 5. Get the specific instance pointer returned by GetInstance
                const specificInstance = retval;
                if (!isValidPointer(specificInstance)) return;

                // 6. Only proceed if we haven't already found and hooked the registration function
                if (gRegistrationHook === null) { // Check the *hook handle*, not just address
                    try {
                        // 7. Get the vtable of the specific instance
                        const instanceVTable = specificInstance.readPointer();
                        if (!isValidPointer(instanceVTable)) return;

                        // 8. Get the address of the registration function from the instance vtable
                        const regFuncAddr = instanceVTable.add(kRegistrationFunctionVTableOffset).readPointer();
                        if (isValidPointer(regFuncAddr)) {

                            // 9. Avoid re-hooking the same function if already successfully hooked
                            if (gRegistrationFuncAddr && gRegistrationFuncAddr.equals(regFuncAddr) && gRegistrationHook !== null) {
                                return;
                            }

                            gRegistrationFuncAddr = regFuncAddr; // Store the identified address
                            console.log(`Identified Registration Func @ ${gRegistrationFuncAddr} via instance ${specificInstance}`);

                            // 10. Attach the main hook to the actual registration function
                            try {
                                Interceptor.revert(gRegistrationFuncAddr); // Ensure no leftover hooks on this address
                                Interceptor.flush();
                                gRegistrationHook = Interceptor.attach(gRegistrationFuncAddr, registrationCallback);
                                console.log(" --> Successfully attached hook to Registration Func.");

                                // 11. Detach the temporary GetInstance hook as it's no longer needed
                                if(gGetInstanceHook) {
                                    gGetInstanceHook.detach();
                                    gGetInstanceHook = null; // Prevent future detach attempts
                                    console.log(" <-- Detached GetInstance hook.");
                                }
                            } catch(e_reg) {
                                 console.error(`Failed attaching hook to Registration Func ${gRegistrationFuncAddr}: ${e_reg.message}`);
                                 gRegistrationHook = null; // Ensure handle is null on failure
                            }
                        }
                    } catch (e_read) {
                        // Ignore errors reading vtable/func ptr from specific instances, might be transient/invalid
                        // console.error(`Error reading VTable/FuncPtr from instance ${specificInstance}: ${e_read.message}`);
                    }
                }
            } // End onLeave
        }); // End attach GetInstance
        console.log("GetInstance hook attached. Waiting for calls...");

    } catch (e) {
        console.error(`[Error] Failed during VTable hook setup: ${e.message}`);
        // Continue without vtable capture if setup fails, field dumping might still work partially
    }
}

// --- OPTIMIZED Field Dumping Function ---
/**
 * Calls the native DataCore::GetStructFieldPtrs function to retrieve field info.
 * Uses pre-allocated global buffers for performance.
 * @param {string} structName - The name of the struct to process.
 * @returns {object[] | null} An array of field information objects, or null on error, or [] if no fields.
 */
function tryProcessStructOptimized(structName) {
    // Check if prerequisites are initialized
    if (!isValidPointer(gDataCoreInstance) || !kGetStructFieldPtrs ||
        !gFieldProcessingBuffer || !gFieldProcessingVec || !gFieldProcessingNamePtr) {
        console.error("Pre-requisite missing for tryProcessStructOptimized.");
        return null;
    }

    // Update the shared name buffer safely
    try {
        gFieldProcessingNamePtr.writeUtf8String(structName);
    } catch (e) {
        console.error(`Error writing struct name "${structName}" to buffer: ${e.message}`);
        return null; // Cannot proceed if name write fails
    }

    // Reset vector pointers (native func should overwrite, but good practice)
    gFieldProcessingVec.writePointer(gFieldProcessingBuffer); // begin = buffer start
    gFieldProcessingVec.add(ptrSize).writePointer(gFieldProcessingBuffer); // end = buffer start (initially empty)

    try {
        // Call the native function: GetStructFieldPtrs(this, structName*, vector*, includeInherited)
        kGetStructFieldPtrs(gDataCoreInstance, gFieldProcessingNamePtr, gFieldProcessingVec, 1);

        // Read the pointers returned in the vector structure
        const beginPtr = gFieldProcessingVec.readPointer(); // Pointer to the start of the field info pointer array
        const endPtr = gFieldProcessingVec.add(ptrSize).readPointer(); // Pointer to one past the end

        // Validate returned pointers
        if (!isValidPointer(beginPtr) || !isValidPointer(endPtr) || endPtr.compare(beginPtr) < 0) {
             // console.warn(`[tryProcessStructOptimized] Invalid vector pointers returned for "${structName}". Begin: ${beginPtr}, End: ${endPtr}`);
             return null; // Indicate failure
        }

        const fieldPtrSize = ptrSize; // Assuming the vector contains pointers
        const count = Math.floor(Number(endPtr.sub(beginPtr)) / fieldPtrSize);

        // Validate field count
        if (count < 0 || count > MAX_FIELDS_EXPECTED * 2) { // Allow some buffer
            // console.warn(`[tryProcessStructOptimized] Unreasonable field count ${count} for "${structName}".`);
            return null; // Indicate likely error
        }
        if (count == 0) {
             return []; // Struct has no registered fields, return empty array
        }

        // Process the fields
        const fields = [];
        const names = new Set(); // To track sanitized names for uniqueness within this struct
        for (let i = 0; i < count; i++) {
            const fieldInfoPtrAddress = beginPtr.add(i * fieldPtrSize);
            const fPtr = fieldInfoPtrAddress.readPointer(); // Read pointer to the FieldInfo struct
            if (!isValidPointer(fPtr)) {
                // console.warn(`[tryProcessStructOptimized][${structName}] Invalid field pointer at index ${i}`);
                continue; // Skip this field
            }

            // Read name pointer from FieldInfo struct
            const namePtr = fPtr.add(F.name).readPointer();
            const rawName = readNameFromArg1(namePtr, `Field ${i}`) || `<field_${i}_read_error>`;

            // Sanitize name to ensure uniqueness within this struct's context
            const sanitized = (() => {
                let base = sanitizeName(rawName), candidate = base, j = 1;
                while (names.has(candidate)) candidate = `${base}_${j++}`;
                names.add(candidate);
                return candidate;
            })();

            // Read other field properties from FieldInfo struct
            const offset = Number(fPtr.add(F.offset).readU64().toString());
            const size = Number(fPtr.add(F.size).readU64().toString());
            const type = fPtr.add(F.type).readU8();
            const flags = fPtr.add(F.flags).readU8();
            const isArrPtr = fPtr.add(F.isArrayOrPointer).readU8(); // Indicator: 0=value, 1=DynArray, >1=?
            const typeSpecificIndex = fPtr.add(F.typeSpecificIndex).readU32(); // Index for enums/structs
            const defaultValuePtr = fPtr.add(F.defaultValue).readPointer(); // Ptr to default val / nested type name

            // Construct the field object in the requested format
            fields.push({
                fieldIndex: i,
                fPtr: fPtr.toString(), // Address of the FieldInfo struct
                namePtr: isValidPointer(namePtr) ? namePtr.toString() : null, // Address of the name string
                rawName: rawName,
                sanitizedName: sanitized,
                offset: offset,
                size: size,
                type: type,
                flags: flags,
                isArrPtr: isArrPtr, // Keep original name for clarity
                typeSpecificIndex: typeSpecificIndex,
                defaultValuePtr: defaultValuePtr.toString(), // Address of default value/nested info
                derivedTypeName: getFieldTypeName(type, size, isArrPtr, flags, defaultValuePtr) // Readable type name
            });
        }
        return fields; // Return the array of processed fields
    } catch (e) {
        console.error(`[Error] During field processing for "${structName}": ${e.message}\n${e.stack}`);
        return null; // Indicate failure
    }
}


// --- Main Execution ---
function main() {
    console.log("Starting combined dumper v11 (target format)...");

    // 1. Initialize components required for field dumping
    try {
        const globalEnvPtr = gEnv;
        if (!isValidPointer(globalEnvPtr)) throw new Error("gEnv pointer is invalid");
        const instanceAddrPtr = globalEnvPtr.add(kDataCoreInstanceOffset);
        gDataCoreInstance = instanceAddrPtr.readPointer();
        if (!isValidPointer(gDataCoreInstance)) throw new Error("Failed to read DataCore instance pointer");
        kGetStructFieldPtrs = new NativeFunction(kDataCoreGetStructFieldPtrsAddr, "pointer", ["pointer", "pointer", "pointer", "int8"], "win64");
        console.log(`DataCore Instance: ${gDataCoreInstance}`);
        console.log(`GetStructFieldPtrs Func: ${kDataCoreGetStructFieldPtrsAddr}`);

        // Allocate reusable buffers for optimized field processing
        gFieldProcessingBuffer = Memory.alloc(MAX_FIELDS_EXPECTED * ptrSize);
        gFieldProcessingVec = Memory.alloc(ptrSize * 3);
        gFieldProcessingNamePtr = Memory.alloc(MAX_STRUCT_NAME_LEN);
        console.log("Allocated reusable buffers.");

    } catch (e) {
        console.error(`[Fatal] Failed to initialize for field dumping: ${e.message}. Aborting.`);
        return;
    }

    // 2. Setup VTable hooks asynchronously to capture registration data
    setupVTableHooks();

    console.log(`Waiting ${collectionDurationMs / 1000} seconds for VTable capture...`);

    // 3. Schedule the main dumping phase after the capture duration
    setTimeout(() => {
        console.log("\n--- Starting Field Dumping Phase ---");
        // Detach the temporary GetInstance hook if it's still active (means reg func wasn't found/hooked)
        if(gGetInstanceHook) {
             gGetInstanceHook.detach();
             console.warn("GetInstance hook detached now (registration function likely not hooked).");
        }

        // Get struct names from the map as a potential fallback/superset
        const allStructNamesFromMap = getAllStructNames();

        // This object will hold the final structured data for JSON output
        const finalOutputStructs = {};
        let processedCount = 0; // Structs where field processing succeeded
        let mapOnlyCount = 0;   // Structs only found via name map
        let failedCount = 0;    // Structs where name/field processing failed
        let namesProcessedFromVTableMap = new Set(); // Track names handled via vtable capture

        // 4. Process structs identified during VTable capture
        console.log(`Processing ${Object.keys(gRegisteredStructData).length} structs found via vtable capture...`);
        for (const vtableAddrStr in gRegisteredStructData) {
            const entry = gRegisteredStructData[vtableAddrStr];
            const originalName = entry.name; // The name read during registration (might be null)
            const vtable = entry.vtable;
            const sanitizedName = originalName ? sanitizeName(originalName) : null;

            if (originalName) {
                 namesProcessedFromVTableMap.add(originalName); // Mark as handled
                 // console.log(`Processing fields for (vtable capture): "${originalName}"`);
                 const fields = tryProcessStructOptimized(originalName); // Use the captured name

                 // Structure the output according to the requested format
                 finalOutputStructs[originalName] = { // Use originalName as the key
                     originalName: originalName,
                     sanitizedName: sanitizedName,
                     fieldCount: (fields === null) ? 0 : fields.length,
                     vtable: vtable,
                     fields: fields // Store null, [], or the array of fields
                 };

                 if (fields !== null) processedCount++; else failedCount++;

            } else {
                 // Name resolution failed during capture for this vtable
                 const key = `_vtable_${vtableAddrStr}`; // Use vtable address as fallback key
                 finalOutputStructs[key] = {
                     originalName: null, // Explicitly null
                     sanitizedName: null,
                     fieldCount: 0,
                     vtable: vtable,
                     fields: null // Cannot get fields without a name
                 };
                 failedCount++;
            }
        }

        // 5. Process remaining structs found only in the name map
        const remainingMapNames = allStructNamesFromMap.filter(name => name && !namesProcessedFromVTableMap.has(name));
        console.log(`Processing ${remainingMapNames.length} remaining structs found only via name map...`);
        for (const structName of remainingMapNames) {
             mapOnlyCount++;
             // console.log(`Processing fields for (map only): "${structName}"`);
             const fields = tryProcessStructOptimized(structName); // Attempt to get fields

             finalOutputStructs[structName] = { // Use name from map as the key
                 originalName: structName,
                 sanitizedName: sanitizeName(structName),
                 fieldCount: (fields === null) ? 0 : fields.length,
                 vtable: null, // Indicate vtable wasn't captured via hook
                 fields: fields,
                 _source: "name_map_only" // Optional field indicating source
             };

             if (fields !== null) processedCount++; else failedCount++;
        }

        console.log("\n--- Field Dumping Finished ---");
        console.log(`Processed fields for: ${processedCount} structs.`);
        console.log(`Failed processing fields/name for: ${failedCount} structs.`);
        console.log(`Processed from name map only: ${mapOnlyCount} structs.`);

        // 6. Construct the final JSON object
        const jsonOutput = {
            metadata: {
                timestamp: new Date().toISOString(),
                structsInOutput: Object.keys(finalOutputStructs).length, // Total entries in the final JSON
                vtableInterceptHits: gVTableInterceptCount,
                vtableMappingsCaptured: Object.keys(gRegisteredStructData).length, // Unique vtables seen by hook
                mapNamesTotal: allStructNamesFromMap.length, // Total names found in map scan
            },
            structs: finalOutputStructs // The main data object
        };

        console.log("\n--- Dumping Final JSON Output ---");
        // Print the single, large JSON object, pretty-printed with 2-space indent
        console.log(JSON.stringify(jsonOutput, null, 2));

        // 7. Detach hooks if they are still active
        if (gRegistrationHook) {
             gRegistrationHook.detach();
             console.log("Detached registration function hook.");
        }

    }, collectionDurationMs); // End of setTimeout callback
}

// --- Script Entry Point ---
setImmediate(main); // Use setImmediate to ensure Frida runtime is ready