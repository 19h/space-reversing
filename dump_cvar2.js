/**
 * Explores the VTable of an ICVar object to help identify method offsets.
 */
function exploreICVarVTable(cvarName = "cl_fov") {
    // --- Configuration ---
    const moduleName = "StarCitizen.exe";
    const g_pCVarManagerOffset = ptr("0x980F190");
    const findCVarVTableOffset = 0x48; // 72 (Offset for FindCVar in CVarManager VTable)

    // Known ICVar VTable Offsets (for reference)
    const knownOffsets = {
        0x28: "GetStringValue (Value)", // Actually gets value string
        0x58: "GetFlags",
        0x70: "GetName (Name)"          // Actually gets name string
    };

    // Range of offsets to explore (adjust as needed)
    const startOffset = 0x0;
    const endOffset = 0xC0; // Explore up to offset 192 (adjust if needed)
    const step = Process.pointerSize; // Usually 8 on x64

    console.log(`[*] Attempting to explore ICVar VTable using CVar "${cvarName}"...`);

    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error(`[!] Module "${moduleName}" not found.`);
        return;
    }
    console.log(`[*] Module "${moduleName}" found at: ${baseAddr}`);

    /** Basic check if a pointer points within the module's likely code range. */
    function _isValidCodePointer(ptr) {
        if (!ptr || ptr.isNull()) return false;
        // Adjust range as needed, very basic sanity check
        return ptr.compare(baseAddr) >= 0 && ptr.compare(baseAddr.add(0x20000000)) < 0;
    }

    try {
        const pGlobalPtr = baseAddr.add(g_pCVarManagerOffset);
        const pMgr = pGlobalPtr.readPointer();
        if (pMgr.isNull()) {
            console.error(`[!] CVarManager instance pointer is NULL.`);
            return;
        }
        console.log(`[*] CVarManager instance address: ${pMgr}`);

        const pMgrVTable = pMgr.readPointer();
        if (pMgrVTable.isNull()) {
            console.error(`[!] CVarManager VTable pointer is NULL.`);
            return;
        }
        console.log(`[*] CVarManager VTable address: ${pMgrVTable}`);

        const pfnFindCVarPtr = pMgrVTable.add(findCVarVTableOffset).readPointer();
        if (pfnFindCVarPtr.isNull() || !_isValidCodePointer(pfnFindCVarPtr)) {
            console.error(`[!] FindCVar function pointer is NULL or invalid.`);
            return;
        }
        console.log(`[*] FindCVar function address: ${pfnFindCVarPtr}`);
        const nativeFindCVar = new NativeFunction(pfnFindCVarPtr, 'pointer', ['pointer', 'pointer'], 'win64');

        // --- Get a sample ICVar ---
        const pNameArg = Memory.allocUtf8String(cvarName);
        const pICVar = nativeFindCVar(pMgr, pNameArg);
        if (pICVar.isNull() || pICVar.compare(ptr(0x10000)) <= 0) {
            console.error(`[!] Could not find ICVar "${cvarName}" to explore its VTable.`);
            return;
        }
        console.log(`[*] Found ICVar "${cvarName}" at address: ${pICVar}`);

        // --- Get the VTable ---
        const pVTable = pICVar.readPointer();
        if (pVTable.isNull() || !_isValidCodePointer(pVTable)) { // Check VTable validity
            console.error(`[!] Invalid VTable pointer ${pVTable} found for ICVar at ${pICVar}`);
            return;
        }
        console.log(`[*] ICVar VTable address: ${pVTable}`);
        console.log("\n--- Exploring VTable ---");
        console.log("Offset (Hex) | Offset (Dec) | Function Address | Symbol Information");
        console.log("---------------------------------------------------------------------");

        // --- Iterate through offsets ---
        for (let offset = startOffset; offset <= endOffset; offset += step) {
            try {
                const pFuncPtr = pVTable.add(offset).readPointer();
                let symbolInfo = "[Invalid Ptr]";

                if (_isValidCodePointer(pFuncPtr)) {
                    try {
                        const symbol = DebugSymbol.fromAddress(pFuncPtr);
                        symbolInfo = `${symbol.name} (+${pFuncPtr.sub(symbol.address)}) [${symbol.moduleName}]`;
                    } catch (e) {
                        symbolInfo = "[No Symbol]"; // Valid pointer, but no symbol found
                    }
                } else if (pFuncPtr.isNull()) {
                    symbolInfo = "[NULL Ptr]";
                }

                const offsetHex = `0x${offset.toString(16).padStart(2, '0')}`;
                const known = knownOffsets[offset] ? ` <-- ${knownOffsets[offset]}` : "";

                console.log(`${offsetHex.padEnd(12)} | ${offset.toString().padEnd(12)} | ${pFuncPtr.toString().padEnd(16)} | ${symbolInfo}${known}`);

            } catch (e) {
                console.error(`[!] Error reading VTable at offset 0x${offset.toString(16)}: ${e.message}`);
            }
        }

        console.log("\n--- VTable Exploration Complete ---");
        console.log("Look for functions near GetStringValue (0x28) that might be SetStringValue (often 0x30 or 0x38).");
        console.log("Look for functions near GetFlags (0x58) that might be SetFlags (often 0x60 or 0x68).");

    } catch (e) {
        console.error(`[!] An critical error occurred: ${e.message}\n${e.stack}`);
    }
}

// --- Run ---
exploreICVarVTable("cl_fov"); // Use a common CVar like cl_fov
