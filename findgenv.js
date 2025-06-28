"use strict";

/**
 * Heuristic-based Global Environment (GEnv) discovery module for Star Citizen
 *
 * This module implements a multi-stage heuristic algorithm to dynamically locate
 * the GEnv structure within process memory, eliminating dependency on hardcoded
 * addresses that vary between game versions and runtime sessions.
 */

const PTR_SIZE = Process.pointerSize;
const IS_64BIT = PTR_SIZE === 8;

/**
 * Validates pointer alignment and addressability
 * @param {NativePointer} ptr - Pointer to validate
 * @returns {boolean} True if pointer appears valid for heap/data access
 */
function isValidDataPointer(ptr) {
    try {
        if (ptr.isNull()) return false;

        // Ensure pointer is aligned to pointer size
        const ptrValue = IS_64BIT ? ptr.toUInt32() : ptr.toUInt32();
        if (ptrValue % PTR_SIZE !== 0) return false;

        // Verify pointer falls within valid memory range
        const range = Process.findRangeByAddress(ptr);
        if (!range) return false;

        // Must be readable
        if (!range.protection.includes('r')) return false;

        // Typical heap/data pointers are in read-write regions
        return range.protection.includes('w');
    } catch (e) {
        return false;
    }
}

/**
 * Validates virtual function table structure
 * @param {NativePointer} vtablePtr - Pointer to potential vtable
 * @param {number} minEntries - Minimum expected vtable entries
 * @returns {boolean} True if structure resembles a valid vtable
 */
function isValidVTable(vtablePtr, minEntries = 10) {
    try {
        if (!isValidDataPointer(vtablePtr)) return false;

        // VTables typically reside in read-only executable sections
        const range = Process.findRangeByAddress(vtablePtr);
        if (!range || !range.protection.includes('r')) return false;

        // Verify vtable contains valid function pointers
        for (let i = 0; i < minEntries; i++) {
            const funcPtr = vtablePtr.add(i * PTR_SIZE).readPointer();
            if (funcPtr.isNull()) continue; // Some slots may be null

            const funcRange = Process.findRangeByAddress(funcPtr);
            if (!funcRange || !funcRange.protection.includes('x')) {
                return false; // Function pointers must point to executable memory
            }
        }

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Validates CEntitySystem structure at given pointer
 * @param {NativePointer} ptr - Potential CEntitySystem pointer
 * @returns {boolean} True if structure matches expected CEntitySystem layout
 */
function validateEntitySystem(ptr) {
    try {
        if (!isValidDataPointer(ptr)) return false;

        // CEntitySystem has vtable as first member
        const vtablePtr = ptr.readPointer();
        if (!isValidVTable(vtablePtr, 25)) return false; // Expecting at least 25 virtual methods

        // entity_array_ at offset 0x148 - validate array structure
        const entityArrayPtr = ptr.add(0x148);
        const maxSize = entityArrayPtr.readS64();
        const currSize = entityArrayPtr.add(0x08).readS64();
        const dataPtr = entityArrayPtr.add(0x18).readPointer();

        // Sanity checks on array dimensions
        if (maxSize < 0 || maxSize > 1000000) return false; // Unreasonable entity count
        if (currSize < 0 || currSize > maxSize) return false;
        if (!isValidDataPointer(dataPtr)) return false;

        // entity_class_registry_ at 0x898 should be a valid pointer
        const registryPtr = ptr.add(0x898).readPointer();
        if (!isValidDataPointer(registryPtr)) return false;

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Validates CRenderer structure at given pointer
 * @param {NativePointer} ptr - Potential CRenderer pointer
 * @returns {boolean} True if structure matches expected CRenderer layout
 */
function validateRenderer(ptr) {
    try {
        if (!isValidDataPointer(ptr)) return false;

        // CRenderer has vtable as first member
        const vtablePtr = ptr.readPointer();
        if (!isValidVTable(vtablePtr, 70)) return false; // ProjectToScreen is at slot 66

        // Additional validation: check if vtable slot 66 points to executable code
        const projectToScreenPtr = vtablePtr.add(66 * PTR_SIZE).readPointer();
        const funcRange = Process.findRangeByAddress(projectToScreenPtr);
        if (!funcRange || !funcRange.protection.includes('x')) return false;

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Validates CGame structure at given pointer
 * @param {NativePointer} ptr - Potential CGame pointer
 * @returns {boolean} True if structure matches expected CGame layout
 */
function validateGame(ptr) {
    try {
        if (!isValidDataPointer(ptr)) return false;

        // CGame should have vtable
        const vtablePtr = ptr.readPointer();
        if (!isValidVTable(vtablePtr, 10)) return false;

        // player_ at 0xC08 - should be null or valid pointer
        const playerPtr = ptr.add(0xC08).readPointer();
        if (!playerPtr.isNull() && !isValidDataPointer(playerPtr)) return false;

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Primary heuristic validation for GEnv candidate
 * @param {NativePointer} candidatePtr - Potential GEnv structure pointer
 * @returns {Object|null} Validated component pointers or null if invalid
 */
function validateGEnvCandidate(candidatePtr) {
    try {
        // Extract potential component pointers
        const components = {
            zoneSystem: candidatePtr.add(0x08).readPointer(),
            game: candidatePtr.add(0x98).readPointer(),
            entitySystem: candidatePtr.add(0xA0).readPointer(),
            engineScheduler: candidatePtr.add(0xA8).readPointer(),
            system: candidatePtr.add(0xC0).readPointer(),
            renderer: candidatePtr.add(0xF8).readPointer()
        };

        // Validate critical components
        if (!validateEntitySystem(components.entitySystem)) return null;
        if (!validateRenderer(components.renderer)) return null;
        if (!validateGame(components.game)) return null;

        // Additional coherence checks
        if (!isValidDataPointer(components.zoneSystem)) return null;
        if (!isValidDataPointer(components.engineScheduler)) return null;
        if (!isValidDataPointer(components.system)) return null;

        return components;
    } catch (e) {
        return null;
    }
}

/**
 * Scans process memory for GEnv structure using heuristic analysis
 * @returns {NativePointer|null} Address of discovered GEnv or null
 */
function findGEnvHeuristic() {
    console.log("[*] Initiating heuristic search for GEnv structure...");

    const moduleBase = Process.enumerateModulesSync()[0].base;
    const moduleSize = Process.enumerateModulesSync()[0].size;

    console.log(`[*] Primary module: ${moduleBase} (size: 0x${moduleSize.toString(16)})`);

    // Phase 1: Identify candidate memory regions
    const candidateRanges = Process.enumerateRanges('r-x').filter(range => {
        // Focus on data sections likely to contain global structures
        // Exclude stack regions (typically have very high addresses)
        const rangeBase = parseInt(range.base.toString());
        const moduleBaseInt = parseInt(moduleBase.toString());

        // GEnv typically resides in .data or .rdata sections near the module base
        return rangeBase >= moduleBaseInt &&
               rangeBase < moduleBaseInt + moduleSize * 2 && // Within reasonable distance
               range.size >= 0x1000 && // At least one page
               range.size <= 0x1000000; // Not unreasonably large
    });

    console.log(`[*] Identified ${candidateRanges.length} candidate memory regions`);

    // Phase 2: Pattern-based search within candidate regions
    let genvAddress = null;
    let searchedBytes = 0;

    for (const range of candidateRanges) {
        console.log(`[*] Scanning range: ${range.base} - ${range.base.add(range.size)} (${range.protection})`);

        try {
            // Scan byte by byte for potential GEnv structures
            const maxOffset = Math.min(range.size, 0x100000); // Limit scan size per range

            for (let offset = 0; offset < maxOffset; offset++) {
                const candidatePtr = range.base.add(offset);
                searchedBytes++;

                // Quick pre-filter: Check if offset 0xA0 contains a plausible pointer
                const quickCheckPtr = candidatePtr.add(0xA0).readPointer();
                if (quickCheckPtr.isNull() || quickCheckPtr.and(0xFFFF).toInt32() !== 0) {
                    continue; // Most pointers are page-aligned
                }

                // Full validation
                const components = validateGEnvCandidate(candidatePtr);
                if (components) {
                    console.log(`[+] Found valid GEnv candidate at: ${candidatePtr}`);
                    console.log(`    EntitySystem: ${components.entitySystem}`);
                    console.log(`    Renderer: ${components.renderer}`);
                    console.log(`    Game: ${components.game}`);

                    genvAddress = candidatePtr;
                    break;
                }

                // Progress indicator every MB
                if (searchedBytes % 0x100000 === 0) {
                    console.log(`[*] Searched ${(searchedBytes / 0x100000).toFixed(1)} MB...`);
                }
            }

            if (genvAddress) break;

        } catch (e) {
            console.log(`[!] Error scanning range ${range.base}: ${e.message}`);
        }
    }

    if (!genvAddress) {
        console.log("[!] GEnv structure not found via heuristic search");

        // Phase 3: Fallback - search for cross-references
        console.log("[*] Attempting cross-reference search...");
        genvAddress = findGEnvByXref();
    }

    return genvAddress;
}

/**
 * Alternative search method using cross-reference analysis
 * @returns {NativePointer|null} Address of discovered GEnv or null
 */
function findGEnvByXref() {
    // Search for common access patterns to GEnv members
    // Pattern: MOV RAX, [RIP+offset] ; MOV RCX, [RAX+0xA0] (accessing entity_system_)
    const pattern = "48 8B 05 ?? ?? ?? ?? 48 8B 88 A0 00 00 00";

    const matches = Memory.scanSync(Process.enumerateModulesSync()[0].base,
                                   Process.enumerateModulesSync()[0].size,
                                   pattern);

    console.log(`[*] Found ${matches.length} potential GEnv access patterns`);

    for (const match of matches) {
        try {
            // Calculate RIP-relative address
            const instruction = match.address;
            const ripOffset = instruction.add(3).readS32();
            const genvCandidate = instruction.add(7).add(ripOffset);

            console.log(`[*] Checking xref candidate at: ${genvCandidate}`);

            const components = validateGEnvCandidate(genvCandidate);
            if (components) {
                console.log(`[+] Validated GEnv via cross-reference at: ${genvCandidate}`);
                return genvCandidate;
            }
        } catch (e) {
            // Invalid memory access, continue
        }
    }

    return null;
}

/**
 * Caches discovered GEnv address for session persistence
 */
let cachedGEnvAddress = null;

/**
 * Primary API: Get GEnv with automatic discovery
 * @returns {Object} GEnv wrapper instance
 */
function getGEnv() {
    if (!cachedGEnvAddress) {
        cachedGEnvAddress = findGEnvHeuristic();

        if (!cachedGEnvAddress) {
            throw new Error("Failed to locate GEnv structure - heuristic search unsuccessful");
        }

        console.log(`[+] GEnv discovered and cached at: ${cachedGEnvAddress}`);
    }

    // Return wrapped GEnv instance (assuming GEnv class from original code)
    return new GEnv(cachedGEnvAddress);
}

// Export discovery functions for RPC access
rpc.exports.discoverGEnv = function() {
    try {
        const addr = findGEnvHeuristic();
        if (addr) {
            return {
                success: true,
                address: addr.toString(),
                components: {
                    zoneSystem: addr.add(0x08).readPointer().toString(),
                    game: addr.add(0x98).readPointer().toString(),
                    entitySystem: addr.add(0xA0).readPointer().toString(),
                    engineScheduler: addr.add(0xA8).readPointer().toString(),
                    system: addr.add(0xC0).readPointer().toString(),
                    renderer: addr.add(0xF8).readPointer().toString()
                }
            };
        } else {
            return { success: false, error: "GEnv structure not found" };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
};

// Integration with existing code - replace hardcoded address
const gEnv = getGEnv();
console.log("[+] GEnv discovery complete - system ready");
