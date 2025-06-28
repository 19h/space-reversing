/**
 * Integrated Entity Component System Name Extractor and Player Tracker for x86_64 Target
 *
 * This script combines player ID detection via function hooking with automated
 * component name extraction by analyzing vtable structures and string references.
 * It hooks GetPlayerIdFromContext to detect the player, finds the corresponding
 * entity, and then performs component analysis on that entity.
 */

"use strict";

const PTR_SIZE = Process.pointerSize;

// Configuration constants
const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x9B4FBE0");
const GET_PLAYER_ID_FUNC_ADDR = ptr("0x1469FC730"); // Replace with actual address
const COMPONENT_LIST_OFFSET = 0x240;
const COMPONENT_POINTER_SIZE = 8;
const POINTER_TAG_MASK = uint64("0x0000FFFFFFFFFFFF");

// Analysis state tracking
const extractedComponents = new Map(); // Stores componentAddr -> primaryName
const typeIdToName = new Map(); // Global mapping for type IDs to component names
let currentPlayerId = null;
let playerEntity = null;

const VERBOSE_LOGGING = false; // Set to true for more detailed console output during extraction

// Helper to extract lower 48 bits of a pointer
function extractLower48(ptrVal) {
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

// Helper to read a C-style UTF-8 string pointer
function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
}

// Helper to call a virtual method by vtable index
function callVFunc(thisPtr, index, returnType, argTypes, args = []) {
    const vtable = thisPtr.readPointer();
    const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
    const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
    return fn(thisPtr, ...args);
}

// Vector3 struct
class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
}

// Wrapper for CEntity (size: 0x02B8)
class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // id at 0x10
    get id() {
        return this.ptr.add(0x10).readS64();
    }

    // name at 0x298 (const char*)
    get name() {
        const namePtr = this.ptr.add(0x298).readPointer();
        return readCString(namePtr);
    }

    // Virtual slot 0 => Function0
    function0() {
        callVFunc(this.ptr, 0, "void", []);
    }
}

// Wrapper for CEntityArray<T> where T = CEntity*
class CEntityArray {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // max_size_ at 0x00
    get maxSize() {
        return this.ptr.readS64();
    }

    // curr_size_ at 0x08
    get currSize() {
        return this.ptr.add(0x08).readS64();
    }

    // data_ pointer at 0x18
    get dataPtr() {
        return this.ptr.add(0x18).readPointer();
    }

    // Access element i as raw pointer (needs extractLower48)
    at(i) {
        if (i < 0 || i >= this.maxSize) return null;
        const elementPtr = this.dataPtr.add(i * PTR_SIZE).readPointer();
        const realPtr = extractLower48(elementPtr);
        return realPtr.isNull() ? null : new CEntity(realPtr);
    }

    // Iterate only the non-null entries
    toArray() {
        const out = [];
        for (let i = 0; i < this.maxSize; i++) {
            const e = this.at(i);
            if (e) out.push(e);
        }
        return out;
    }
}

// Wrapper for CEntitySystem (size: 0x8A0)
class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Direct memory for entity_array_ at offset 0x148
    get entityArray() {
        const arrPtr = this.ptr.add(0x148);
        return new CEntityArray(arrPtr);
    }
}

// Wrapper for global environment GEnv (size: 0x440)
class GEnv {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // entity_system_ at 0x00A0
    get entitySystem() {
        const sysPtr = this.ptr.add(0x00a0).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }
}

/**
 * Hook GetPlayerIdFromContext function to capture player ID
 */
function hookGetPlayerIdFromContext() {
    try {
        const hook = Interceptor.attach(GET_PLAYER_ID_FUNC_ADDR, {
            onEnter: function(args) {
                console.log(`\n[HOOK] GetPlayerIdFromContext ENTER`);
                console.log(`[HOOK] Context Base: ${args[0]}`);
                console.log(`[HOOK] Output Pointer: ${args[1]}`);

                this.contextBase = args[0];
                this.outputPtr = args[1];
            },

            onLeave: function(retval) {
                if (!this.outputPtr.isNull()) {
                    const playerId = this.outputPtr.readS64();
                    console.log(`[HOOK] GetPlayerIdFromContext EXIT - Player ID: ${playerId}`);
                    console.log(`[PLAYER_INFO] Extracted Player ID: ${playerId} (0x${playerId.toString(16)})`);

                    currentPlayerId = playerId;
                    // Trigger entity lookup and component analysis
                    setTimeout(() => {
                        findPlayerEntityAndAnalyze();
                    }, 100);
                } else {
                    console.log(`[HOOK] GetPlayerIdFromContext EXIT - No output`);
                }
            }
        });

        console.log('[HOOK_MANAGER] Successfully hooked GetPlayerIdFromContext');

    } catch (e) {
        console.log(`[ERROR] Failed to hook GetPlayerIdFromContext: ${e.message}`);
    }
}

/**
 * Find the player entity by ID and trigger component analysis
 */
function findPlayerEntityAndAnalyze() {
    if (!currentPlayerId) {
        console.log("[ERROR] No player ID available for entity lookup");
        return;
    }

    const gEnv = new GEnv(GENV_ADDR);
    const entitySystem = gEnv.entitySystem;

    if (!entitySystem) {
        console.log("[ERROR] Entity system not available");
        return;
    }

    console.log(`[PLAYER_LOOKUP] Searching for entity with ID: ${currentPlayerId}`);

    const allEntities = entitySystem.entityArray.toArray();
    console.log(`[PLAYER_LOOKUP] Searching through ${allEntities.length} entities`);

    for (const entity of allEntities) {
        try {
            if (entity.id.toString() === currentPlayerId.toString()) {
                console.log(`[PLAYER_FOUND] Found player entity at ${entity.ptr}`);
                console.log(`[PLAYER_FOUND] Player name: ${entity.name || "<no-name>"}`);

                playerEntity = entity;
                // Trigger component analysis on this entity
                extractPlayerComponentNames(entity.ptr);
                break;
            }
        } catch (e) {
            // Skip entities that can't be read
        }
    }

    if (!playerEntity) {
        console.log(`[PLAYER_LOOKUP] Player entity with ID ${currentPlayerId} not found`);
    }
}

/**
 * Extracts component names by analyzing ALL virtual functions
 * of each component's vtable for string references.
 *
 * @param {NativePointer} componentPtr - Untagged component pointer
 * @returns {Object} Component analysis results, including:
 *                   - mostFrequentName: The most likely primary name.
 *                   - allPossibleNamesWithCounts: An object { name: count } for all candidates.
 */
function analyzeComponentVtable(componentPtr) {
    const result = {
        componentAddress: componentPtr.toString(), // Store as string for JSON
        vtableAddress: null,
        analyzedVfuncs: 0,
        mostFrequentName: null,
        allPossibleNamesWithCounts: {},
        rttiName: null, // To store a name found via RTTI, if any
        error: null
    };

    try {
        const componentRange = Process.findRangeByAddress(componentPtr);
        //if (!componentRange || !componentRange.protection.includes('r')) {
        //    result.error = `Component address ${componentPtr} is not readable.`;
        //    return result;
        //}
        //if (componentPtr.add(Process.pointerSize).compare(componentRange.base.add(componentRange.size)) > 0) {
        //     result.error = `Component address ${componentPtr} readable range too small for vtable pointer.`;
        //     return result;
        //}

        const vtablePtr = componentPtr.readPointer();
        if (vtablePtr.isNull()) {
            result.error = "Null vtable pointer";
            return result;
        }
        result.vtableAddress = vtablePtr.toString();

        const vtableInfo = analyzeVtableStructure(vtablePtr); // analyzeVtableStructure now returns { virtualFunctions, typeInfoAddress, error, stopReason }
        if (!vtableInfo) {
            result.error = `Vtable analysis returned null for vtable at ${vtablePtr}`;
            return result;
        }
        if (vtableInfo.error) {
             result.error = `Vtable analysis error for ${vtablePtr}: ${vtableInfo.error} (Stop reason: ${vtableInfo.stopReason})`;
             return result;
        }
        if (vtableInfo.virtualFunctions.length === 0) {
            result.error = `No executable virtual functions found for vtable at ${vtablePtr}. (Stop reason: ${vtableInfo.stopReason})`;
            result.analyzedVfuncs = vtableInfo.functionCount;
            return result;
        }
        result.analyzedVfuncs = vtableInfo.virtualFunctions.length;

        const stringCounts = new Map();

        // Attempt to get RTTI name first (MSVC specific example)
        if (vtableInfo.typeInfoAddress && !vtableInfo.typeInfoAddress.isNull()) {
            try {
                // This is a simplified RTTI parsing attempt for MSVC.
                // It assumes typeInfoAddress points to a _TypeDescriptor or something similar
                // where the name is at a fixed offset (e.g., 0x10 or via pTypeDescriptor in COL).
                // A more robust RTTI parser would be needed for general use.
                // Example: For MSVC _TypeDescriptor, name is often at typeInfoAddress + sizeof(void*) * 2 + sizeof(int)
                // Or if it's a _CompleteObjectLocator, it's more involved.
                // Let's try a common offset for the name in _TypeDescriptor (after vfptr and spare):
                const rttiNamePtrAddr = vtableInfo.typeInfoAddress.add(Process.pointerSize * 2); // Heuristic
                if (Process.findRangeByAddress(rttiNamePtrAddr)?.protection.includes('r')) {
                    const rttiNamePtr = rttiNamePtrAddr.readPointer();
                     if (!rttiNamePtr.isNull() && rttiNamePtr.compare(0x10000) > 0) { // Basic pointer check
                        const rttiNameRaw = tryReadString(rttiNamePtr, 128); // Read potential mangled or direct name
                        if (rttiNameRaw) {
                            let rttiCleanName = rttiNameRaw;
                            if (rttiNameRaw.startsWith(".?AV")) { // MSVC mangled name
                                rttiCleanName = rttiNameRaw.substring(4);
                                const atIndex = rttiCleanName.indexOf("@@");
                                if (atIndex !== -1) rttiCleanName = rttiCleanName.substring(0, atIndex);
                                rttiCleanName = rttiCleanName.replace(/@@$/, ""); // Remove trailing @@
                            } else if (rttiNameRaw.startsWith("_ZTVN")) { // GCC/Clang Itanium ABI mangled name (for vtable, name is complex)
                                // Proper demangling is hard. This is a placeholder.
                                // Often the class name is after N...E
                                const match = rttiNameRaw.match(/\d+([A-Za-z_0-9]+)/g); // Extracts length-prefixed names
                                if (match) rttiCleanName = match.pop(); // Take the last one as a guess
                            }
                            // Filter the cleaned RTTI name
                            if (rttiCleanName && (rttiCleanName.match(/^[A-Z][a-zA-Z0-9_]{1,64}(?:Component|Pool|Entity|System)/) ||
                                                rttiCleanName.match(/^I[A-Z][a-zA-Z0-9_]{1,64}/) ||
                                                rttiCleanName.match(/^[a-z_0-9]+::[A-Z][a-zA-Z0-9_]{1,64}/) // For namespaced C++ names
                                                )) {
                                result.rttiName = rttiCleanName;
                                stringCounts.set(rttiCleanName, (stringCounts.get(rttiCleanName) || 0) + 1000); // Heavily boost RTTI name
                                if (VERBOSE_LOGGING) console.log(`    RTTI derived name: "${rttiCleanName}" (from ${rttiNameRaw})`);
                            }
                        }
                    }
                }
            } catch (e) { /* console.log(`  RTTI parsing error: ${e.message}`); */ }
        }


        for (const vfunc of vtableInfo.virtualFunctions) {
            const stringRefs = extractStringReferencesFromFunction(vfunc.address);
            const filteredAndCleanedNames = stringRefs.map(fullStr => {
                let match = null;
                // Regexps updated to be a bit more flexible with underscores and potentially namespaces
                const componentRegex = /([a-zA-Z_0-9::]*[A-Z][a-zA-Z0-9_]{1,64}(?:Component|Pool|Entity|System))/;
                const interfaceRegex = /(I[A-Z][a-zA-Z0-9_]{1,64})/;

                let found = fullStr.match(componentRegex);
                if (found) match = found[1];
                else {
                    found = fullStr.match(interfaceRegex);
                    if (found) match = found[1];
                }
                return match; // This is the potential component name part
            }).filter(name => {
                if (name) {
                    if (name.length > 68) return false;
                    let nonAlphaNumOrScope = name.replace(/[a-zA-Z0-9_:]/g, "").length; // Allow colons for namespaces
                    if (nonAlphaNumOrScope > name.length * 0.3) return false; // Slightly more permissive
                    return true;
                }
                return false;
            });

            filteredAndCleanedNames.forEach(name => {
                stringCounts.set(name, (stringCounts.get(name) || 0) + 1);
            });
        }

        // Populate allPossibleNamesWithCounts
        stringCounts.forEach((count, name) => {
            result.allPossibleNamesWithCounts[name] = count;
        });

        // Determine mostFrequentName using the refined tie-breaking
        if (stringCounts.size > 0) {
            let bestName = null;
            let maxCount = -1; // Initialize to -1 to ensure first valid name is picked

            stringCounts.forEach((count, name) => {
                if (count > maxCount) {
                    maxCount = count;
                    bestName = name;
                } else if (count === maxCount && bestName) {
                    const isNameGeneric = (name === "EntityComponent" || name === "IEntityComponent" || name.startsWith("IEntity"));
                    const isBestNameGeneric = (bestName === "EntityComponent" || bestName === "IEntityComponent" || bestName.startsWith("IEntity"));

                    if (isBestNameGeneric && !isNameGeneric) {
                        bestName = name;
                    } else if (!isBestNameGeneric && isNameGeneric) {
                        // Keep current bestName
                    } else if (name.endsWith("Component") && !bestName.endsWith("Component")) {
                        bestName = name;
                    } else if (!name.endsWith("Component") && bestName.endsWith("Component")) {
                        // Keep current bestName
                    } else if (name.length < bestName.length) {
                        bestName = name;
                    }
                }
            });
            result.mostFrequentName = bestName;
        }

    } catch (e) {
        result.error = `Analysis exception for ${componentPtr}: ${e.message} (at ${e.fileName}:${e.lineNumber})`;
    }
    return result;
}

/**
 * Extracts string references from a function.
 * @param {NativePointer} funcPtr - Function pointer to analyze
 * @returns {Array<string>} Array of discovered strings
 */
function extractStringReferencesFromFunction(funcPtr) {
    const strings = new Set();
    const MAX_BYTES_TO_ANALYZE_FUNC = 0x200; // Analyze up to 512 bytes per function

    try {
        const disassembledStrings = disassembleForStrings(funcPtr, MAX_BYTES_TO_ANALYZE_FUNC);
        disassembledStrings.forEach(str => strings.add(str));
    } catch (e) {
        // console.log(`Disassembly failed for ${funcPtr}: ${e.message}`);
    }

    try {
        const leaStrings = scanForLeaStringsOptimized(funcPtr, MAX_BYTES_TO_ANALYZE_FUNC);
        leaStrings.forEach(str => strings.add(str));
    } catch (e) {
        // console.log(`LEA scan failed for ${funcPtr}: ${e.message}`);
    }
    return Array.from(strings);
}

/**
 * Disassembles function looking for string reference patterns
 */
function disassembleForStrings(funcPtr, maxBytes) {
    const strings = [];
    let currentPtr = funcPtr;
    let bytesProcessed = 0;
    const endAddress = funcPtr.add(maxBytes);

    while (currentPtr.compare(endAddress) < 0 && bytesProcessed < maxBytes) {
        try {
            const insn = Instruction.parse(currentPtr);
            if (!insn || insn.size === 0) break;

            if ((insn.mnemonic === 'lea' || insn.mnemonic === 'mov') && insn.operands.length >= 2) {
                const src = insn.operands[1];
                if (src.type === 'mem' && src.reg === 'rip' && typeof src.disp !== 'undefined') {
                    const effectiveAddr = currentPtr.add(insn.size).add(src.disp);
                    const possibleString = tryReadString(effectiveAddr);
                    if (possibleString) strings.push(possibleString);
                } else if (src.type === 'imm') {
                     try {
                        const immPtr = ptr(src.value);
                        if (!immPtr.isNull() && immPtr.compare(0x10000) > 0) { // Heuristic for pointer
                             const possibleString = tryReadString(immPtr);
                             if (possibleString) strings.push(possibleString);
                        }
                    } catch (e) { /* not a valid pointer */ }
                }
            }
            bytesProcessed += insn.size;
            currentPtr = currentPtr.add(insn.size);
            if (insn.mnemonic === 'ret' || insn.mnemonic.startsWith('jmp') || insn.mnemonic.startsWith('call')) {
                 // Stop if function returns, jumps away, or makes a call that might not return predictably here
                 // For 'call', this might be too aggressive, but helps limit analysis depth.
                 break;
            }
        } catch (e) {
            break;
        }
    }
    return strings;
}

/**
 * Optimized pattern scanning with batched memory reads for LEA RIP-relative
 */
function scanForLeaStringsOptimized(funcPtr, maxBytes) {
    const strings = [];
    let funcBytes;
    try {
        const range = Process.findRangeByAddress(funcPtr);
        if (!range || !range.protection.includes('x')) return strings; // Not executable
        const availableBytes = Math.min(maxBytes, range.base.add(range.size).sub(funcPtr).toInt32());
        if (availableBytes <= 0) return strings;
        funcBytes = funcPtr.readByteArray(availableBytes);
    } catch (e) {
        return strings;
    }

    const buffer = new Uint8Array(funcBytes);
    const leaRipPatterns = [0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D];

    for (let i = 0; i < buffer.length - 6; i++) {
        const rexByte = buffer[i];
        const opcodeByte1 = buffer[i+1];
        const opcodeByte2 = buffer[i+2];

        if ((rexByte >= 0x48 && rexByte <= 0x4F) && opcodeByte1 === 0x8D) {
            if (leaRipPatterns.includes(opcodeByte2)) {
                const disp32 = buffer[i + 3] | (buffer[i + 4] << 8) | (buffer[i + 5] << 16) | (buffer[i + 6] << 24);
                const instructionSize = 7;
                const nextInstructionAddress = funcPtr.add(i + instructionSize);
                const targetAddr = nextInstructionAddress.add(disp32);
                const str = tryReadString(targetAddr);
                if (str) strings.push(str);
            }
        }
    }
    return strings;
}

/**
 * Safely attempts to read a C string from an address
 */
function tryReadString(addr, maxLength = 256) {
    try {
        if (!addr || addr.isNull() || addr.compare(0x10000) < 0) return null;

        // Attempt direct read, relying on try-catch for safety
        const str = addr.readCString(maxLength);

        if (str === null || str.length === 0) return null;

        // Basic printable ASCII check (allow common whitespace)
        let printableChars = 0;
        let nonPrintableButCommon = 0;
        const checkLength = Math.min(str.length, 32); // Check a decent portion for printability

        for (let i = 0; i < checkLength; i++) {
            const charCode = str.charCodeAt(i);
            if (charCode >= 0x20 && charCode <= 0x7E) { // Printable ASCII
                printableChars++;
            } else if (charCode === 0x09 || charCode === 0x0A || charCode === 0x0D) { // Tab, LF, CR
                nonPrintableButCommon++;
            } else if (charCode === 0x00 && i > 0) { // Null terminator after some content
                break;
            } else if (i < 4 && charCode > 0x7E) { // Allow some high-ASCII/UTF-8 at the beginning if it's not all garbage
                 printableChars++; // Count it as potentially valid for short strings
            } else if (i >=4 && charCode > 0x7E) { // Stricter for non-initial high-ASCII
                return null; // Likely not a simple component name string
            }
             else if (i < 2 && charCode === 0x00) { // Starting with nulls is suspicious for short names
                return null;
            }
        }
        // Heuristic: if mostly printable or common whitespace, consider it a string.
        // Avoids overly aggressive filtering of names with underscores or numbers.
        if (printableChars > 0 && (printableChars + nonPrintableButCommon) / checkLength > 0.7) {
             // Further clean up: trim trailing non-alphanumeric that are not part of a valid name pattern
            let cleanedStr = str.replace(/[\x00-\x1F\x7F-\xFF]+$/g, ''); // Trim trailing control/extended ASCII
            cleanedStr = cleanedStr.trim(); // Trim whitespace
            return cleanedStr.length > 1 ? cleanedStr : null; // Must have some content left
        }
    } catch (e) { /* console.warn(`tryReadString direct read error for ${addr}: ${e.message}`); */ }
    return null;
}

/**
 * Analyzes vtable structure to identify virtual function pointers.
 */
function analyzeVtableStructure(vtablePtr) {
    const vtableInfo = {
        address: vtablePtr,
        functionCount: 0, // Counts functions it attempts to process / considers valid entries
        typeInfoAddress: null,
        virtualFunctions: [], // Stores only valid, executable function pointers
        error: null,
        stopReason: "Scan did not start"
    };

    try {
        // Check for RTTI (optional, can be wrapped in try-catch too if problematic)
        try {
            const potentialTypeInfoPtrAddr = vtablePtr.sub(Process.pointerSize);
            const typeInfoPtr = potentialTypeInfoPtrAddr.readPointer();
            if (!typeInfoPtr.isNull()) {
                 // Basic check if typeInfoPtr looks like a valid pointer in a readable region
                if (Process.findRangeByAddress(typeInfoPtr)?.protection.includes('r')) {
                    vtableInfo.typeInfoAddress = typeInfoPtr;
                }
            }
        } catch (e) { /* RTTI read failed, continue without it */ }

        let offset = 0;
        const MAX_VTABLE_FUNCTIONS = 64;
        let consecutiveNullFuncs = 0;

        for (let i = 0; i < MAX_VTABLE_FUNCTIONS; i++) {
            const currentFuncPtrAddr = vtablePtr.add(offset);
            let funcPtr;
            try {
                funcPtr = currentFuncPtrAddr.readPointer();
            } catch (e) {
                vtableInfo.stopReason = `Failed to read vfunc pointer at offset 0x${offset.toString(16)}: ${e.message}`;
                break; // Cannot read from vtable, stop
            }
            vtableInfo.functionCount++;

            if (funcPtr.isNull()) {
                consecutiveNullFuncs++;
                if (consecutiveNullFuncs >= 3) {
                    vtableInfo.stopReason = "3+ consecutive null function pointers.";
                    break;
                }
                offset += Process.pointerSize;
                continue;
            }
            consecutiveNullFuncs = 0;

            // Check if funcPtr points to executable memory (this check is usually reliable)
            const range = Process.findRangeByAddress(funcPtr);
            if (!range || !range.protection.includes('x')) {
                vtableInfo.stopReason = `Vfunc at offset 0x${offset.toString(16)} (ptr: ${funcPtr}) is not in executable memory.`;
                // Optionally, decide if this is a hard stop or if you want to log and continue
                // For now, let's treat it as a likely end of valid vfuncs.
                break;
            }
            vtableInfo.virtualFunctions.push({ index: i, address: funcPtr, offset: offset });
            offset += Process.pointerSize;
        }
         if (vtableInfo.virtualFunctions.length > 0 || vtableInfo.functionCount > 0) {
             vtableInfo.stopReason = "Scan completed or stopped by limit/condition.";
        }

    } catch (e) { // Catch errors from vtablePtr.sub or other unexpected issues
        vtableInfo.error = `Vtable analysis exception for ${vtablePtr}: ${e.message}`;
        vtableInfo.stopReason = "Exception during analysis";
    }
    return vtableInfo;
}

/**
 * Enhanced component analysis using type ID correlation.
 */
function analyzeComponentWithTypeId(componentPtr) {
    const result = analyzeComponentVtable(componentPtr);

    if (typeIdToName.size > 0 && !result.error) { // Only try if base analysis was somewhat successful
        try {
            const potentialTypeIdAddr = componentPtr.add(Process.pointerSize);
            const range = Process.findRangeByAddress(potentialTypeIdAddr);
            if (range && range.protection.includes('r') &&
                potentialTypeIdAddr.add(2).compare(range.base.add(range.size)) <= 0) { // Check for 2 bytes (U16)
                const potentialTypeId = potentialTypeIdAddr.readU16();
                if (typeIdToName.has(potentialTypeId)) {
                    const mappedName = typeIdToName.get(potentialTypeId);
                    console.log(`  Type ID match for ${componentPtr}: 0x${potentialTypeId.toString(16)} = "${mappedName}"`);
                    if (mappedName !== result.mostFrequentName) {
                        // console.log(`    Type ID name ("${mappedName}") differs or preferred over vtable name ("${result.mostFrequentName || 'None'}").`);
                        result.mostFrequentName = mappedName;
                        result.allPossibleNamesWithCounts[mappedName] = (result.allPossibleNamesWithCounts[mappedName] || 0) + 1000;
                    } else if (!result.mostFrequentName && mappedName) {
                         result.mostFrequentName = mappedName;
                         result.allPossibleNamesWithCounts[mappedName] = 1000;
                    }
                }
            }
        } catch (e) { /* console.log(`  Type ID correlation error for ${componentPtr}: ${e.message}`); */ }
    }
    return result;
}

/**
 * Main extraction routine for player entity components
 */
function extractPlayerComponentNames(entityPtr) {
    console.log("=== Player Entity Component Name Extraction (Full Vtable Scan) ===");
    console.log(`Player entity base: ${entityPtr}`);
    extractedComponents.clear();

    let componentListPtr;
    try {
        const componentListBaseAddr = entityPtr.add(COMPONENT_LIST_OFFSET);
        componentListPtr = componentListBaseAddr.readPointer();
        console.log(`Component list pointer candidate: ${componentListPtr} (read from ${componentListBaseAddr})`);
        if (componentListPtr.isNull()) {
            console.error("Component list pointer is null.");
            return;
        }
    } catch (e) {
        console.error(`Failed to read component list pointer from ${entityPtr.add(COMPONENT_LIST_OFFSET)}: ${e.message}.`);
        return;
    }

    let componentIndex = 0;
    let consecutiveReadFailures = 0;
    const MAX_CONSECUTIVE_READ_FAILURES = 15;
    const MAX_COMPONENTS_TO_SCAN = 300; // Adjust as needed for performance/thoroughness

    while (consecutiveReadFailures < MAX_CONSECUTIVE_READ_FAILURES && componentIndex < MAX_COMPONENTS_TO_SCAN) {
        const componentPtrAddr = componentListPtr.add(componentIndex * COMPONENT_POINTER_SIZE);
        let taggedPtr;

        try {
            taggedPtr = componentPtrAddr.readPointer();
            if (taggedPtr.isNull()) {
                consecutiveReadFailures++;
                componentIndex++;
                continue;
            }
            consecutiveReadFailures = 0;

            const componentPtr = ptr(taggedPtr.and(POINTER_TAG_MASK));

            console.log(`\n[Component ${componentIndex}]`);
            console.log(`  Tagged pointer: ${taggedPtr} (from ${componentPtrAddr})`);
            console.log(`  Actual pointer: ${componentPtr}`);

            if (componentPtr.isNull()) {
                console.log(`  Untagged pointer is NULL. Skipping.`);
                componentIndex++;
                continue;
            }

            if (extractedComponents.has(componentPtr.toString())) {
                console.log(`  Already analyzed. Primary Name: "${extractedComponents.get(componentPtr.toString()).mostFrequentName}"`);
                componentIndex++;
                continue;
            }

            let analysisResult;
            if (typeIdToName.size > 0) { // Assuming typeIdToName might be populated by hooks
                analysisResult = analyzeComponentWithTypeId(componentPtr);
            } else {
                analysisResult = analyzeComponentVtable(componentPtr);
            }

            // Store the full analysis result, not just the primary name
            extractedComponents.set(componentPtr.toString(), analysisResult);

            if (analysisResult.error) {
                console.log(`  Error analyzing component ${componentPtr}: ${analysisResult.error}`);
            } else {
                console.log(`  Vtable: ${analysisResult.vtableAddress}, Analyzed ${analysisResult.analyzedVfuncs} vfuncs.`);
                if (analysisResult.rttiName) {
                    console.log(`  RTTI Name: "${analysisResult.rttiName}"`);
                }
                if (analysisResult.mostFrequentName) {
                    console.log(`  Primary Name: "${analysisResult.mostFrequentName}" (Score: ${analysisResult.allPossibleNamesWithCounts[analysisResult.mostFrequentName] || 0})`);
                } else {
                    console.log(`  No primary component name identified (vfuncs: ${analysisResult.analyzedVfuncs}).`);
                }
                if (VERBOSE_LOGGING || Object.keys(analysisResult.allPossibleNamesWithCounts).length > 1) {
                    console.log("    All potential names found:");
                    for (const name in analysisResult.allPossibleNamesWithCounts) {
                        console.log(`      - "${name}" (Count: ${analysisResult.allPossibleNamesWithCounts[name]})`);
                    }
                }
            }
        } catch (e) {
            console.log(`  Failed to read component pointer from list at ${componentPtrAddr} (index ${componentIndex}): ${e.message}`);
            consecutiveReadFailures++;
        }
        componentIndex++;
    }

    console.log(`\n=== Extraction Summary ===`);
    console.log(`Total component slots processed up to index: ${componentIndex -1}`);
    console.log(`Stopped after ${consecutiveReadFailures} consecutive read failures or max components.`);
    console.log(`Components with any analysis data: ${extractedComponents.size}`);

    if (extractedComponents.size > 0) {
        console.log("\nExtracted Primary Component Names:");
        extractedComponents.forEach((result, addr) => {
            console.log(`  ${addr}: "${result.mostFrequentName || 'N/A'}" ${result.rttiName ? '(RTTI: "'+result.rttiName+'")' : ''}`);
        });
    }
}

/**
 * Alternative approach: Hook the name registration function if found
 */
function hookNameRegistration() {
    const REGISTRY_BASE_ADDRESS_STRING = "0x149B4FC88";
    const REGISTER_FUNCTION_OFFSET = 0x10;

    try {
        // Basic checks for address validity before trying to read
        const registryBasePtr = ptr(REGISTRY_BASE_ADDRESS_STRING);
        if (registryBasePtr.isNull()) {
            console.log(`Registration hook: Registry base address ${registryBasePtr} invalid or not readable.`);
            return;
        }
        const registryPtr = registryBasePtr.readPointer();
        if (registryPtr.isNull()) {
            console.log("Registration hook: Registry pointer is null.");
            return;
        }

        const registerFuncAddr = registryPtr.add(REGISTER_FUNCTION_OFFSET).readPointer();
        if (registerFuncAddr.isNull()) {
            console.log(`Registration hook: Register function at ${registerFuncAddr} is null or not executable.`);
            return;
        }

        console.log(`Attempting to hook name registration function at: ${registerFuncAddr}`);
        Interceptor.attach(registerFuncAddr, {
            onEnter: function(args) {
                try {
                    const nameStrPtr = args[2]; // Assuming name is 3rd arg (0-indexed)
                    if (nameStrPtr && !nameStrPtr.isNull()) {
                        const nameStr = nameStrPtr.readCString();
                        if (nameStr) {
                            console.log(`[Registry Hook] Component registered: "${nameStr}"`);
                            this.componentName = nameStr;
                        }
                    }
                } catch (e) { /* console.log(`[Registry Hook] Error reading name: ${e.message}`); */ }
            },
            onLeave: function(retval) {
                if (this.componentName) {
                    try {
                        const typeId = retval.toInt32() & 0xFFFF; // Assuming type ID in lower 16 bits of RAX
                        console.log(`  [Registry Hook] Type ID: 0x${typeId.toString(16)} for "${this.componentName}"`);
                        typeIdToName.set(typeId, this.componentName);
                    } catch (e) { /* console.log(`[Registry Hook] Error reading type ID: ${e.message}`); */ }
                }
            }
        });
        console.log(`Successfully hooked name registration function at ${registerFuncAddr}.`);
    } catch (e) {
        console.log(`Failed to set up registration hook: ${e.message}`);
    }
}

hookNameRegistration();

// Global exception handler to prevent script crashes
// Process.setExceptionHandler((exception) => {
//     console.log("=== EXCEPTION CAUGHT ===");
//     console.log(`Name: ${exception.name}`);
//     console.log(`Message: ${exception.message}`);
//     console.log(`Type: ${exception.type}`);
//     console.log(`Address: ${exception.address}`);

//     // Log stack trace if available
//     if (exception.stack) {
//         console.log("Stack trace:");
//         console.log(exception.stack);
//     }

//     // Log memory access details for memory-related exceptions
//     if (exception.memory) {
//         console.log(`Memory operation: ${exception.memory.operation}`);
//         console.log(`Memory address: ${exception.memory.address}`);
//     }

//     console.log("========================");

//     // Return true to indicate we've handled the exception
//     return true;
// });

// --- Main Execution ---
console.log("[*] Integrated Player Tracker and Component Analyzer initialized.");
hookGetPlayerIdFromContext(); // Start by hooking the player ID function
// hookNameRegistration(); // Call if a known registration function exists

// --- RPC Exports ---
rpc.exports = {
    getCurrentPlayerId: () => {
        return currentPlayerId;
    },
    getPlayerEntity: () => {
        return playerEntity ? playerEntity.ptr.toString() : null;
    },
    getExtractedComponents: () => {
        // Return a more structured object for easier parsing client-side
        const componentsData = {};
        extractedComponents.forEach((result, addr) => {
            componentsData[addr] = {
                primaryName: result.mostFrequentName,
                rttiName: result.rttiName,
                allNamesWithCounts: result.allPossibleNamesWithCounts,
                vtable: result.vtableAddress,
                analyzedVfuncs: result.analyzedVfuncs,
                error: result.error
            };
        });
        return componentsData;
    },
    extractComponentsAt: (entityAddrStr) => {
        try {
            const entityPtr = ptr(entityAddrStr);
            console.log(`RPC: Analyzing components for entity at ${entityPtr}`);
            extractPlayerComponentNames(entityPtr); // This will clear extractedComponents internally
            return rpc.exports.getExtractedComponents(); // Reuse the getter
        } catch (e) {
            return { error: `Failed in extractComponentsAt: ${e.message}` };
        }
    },
    analyzeSingleComponent: (componentAddrStr) => { // Renamed from analyzeComponent to avoid conflict
        try {
            const componentPtr = ptr(componentAddrStr);
            let analysisResult;
            if (typeIdToName.size > 0) {
                analysisResult = analyzeComponentWithTypeId(componentPtr);
            } else {
                analysisResult = analyzeComponentVtable(componentPtr);
            }
            // NativePointer values in result are already stringified by analyzeComponentVtable
            return JSON.stringify(analysisResult, null, 2);
        } catch (e) {
            return JSON.stringify({ error: `Failed in analyzeSingleComponent: ${e.message}` }, null, 2);
        }
    },
    hookRegistrationFuncRpc: (regBaseAddrStr, regFuncOffsetHex) => { // Renamed to avoid conflict
        // This is a simplified version for RPC; hookNameRegistration is more complete
        try {
            const registryBasePtr = ptr(regBaseAddrStr);
            const offset = parseInt(regFuncOffsetHex, 16);
            const registryPtr = registryBasePtr.readPointer();
            const registerFunc = registryPtr.add(offset).readPointer();
            console.log(`RPC: Attempting to hook name registration function at: ${registerFunc}`);
            // Re-implement attach logic here or call a shared internal function
            Interceptor.attach(registerFunc, { /* ... same as hookNameRegistration ... */ });
            return `Hooked registration function at ${registerFunc}`;
        } catch (e) {
            return `Failed to hook via RPC: ${e.message}`;
        }
    },
    manualPlayerLookup: () => {
        findPlayerEntityAndAnalyze();
        return "Manual player lookup triggered";
    }
};

console.log("Script loaded. Player ID hook active. RPC exports are available.");
