/**
 * CVarManager Class
 * Provides an interface to interact with Star Citizen's CVar system.
 */
class CVarManager {
    /**
     * Initializes the CVarManager by finding necessary pointers and functions.
     * @param {string} moduleName - The name of the main game module (e.g., "StarCitizen.exe").
     */
    constructor(moduleName = "StarCitizen.exe") {
        // --- Configuration ---
        this.moduleName = moduleName;
        this.g_pCVarManagerOffset = ptr("0x981A190");
        this.enumCVarsVTableOffset = 0x180; // 384 (Returns list of name pointers)
        this.findCVarVTableOffset = 0x48;  // 72  (Confirmed: Finds ICVar* by name)

        // VTable offsets relative to ICVar's VTable - *** CORRECTED ***
        this.getNameVTableOffset = 0x70;    // 112 (Confirmed: Returns name pointer)
        this.getFlagsVTableOffset = 0x58;   // 88  (Confirmed: Returns flags uint32)
        this.getStringVTableOffset = 0x28;  // 40  (Confirmed: Returns value pointer)
        this.setStringVTableOffset = 0x40;  // 64  (Confirmed: Sets value from string)
        this.setFlagsVTableOffset = 0x60;   // 96  (Confirmed: Sets flags)

        // CVar Flags (Common examples, might need adjustment based on engine specifics)
        this.FLAGS = {
            VF_NONE: 0x0,                    // Default
            VF_CHEAT: 0x2,                   // Usually requires sv_cheats or similar
            VF_READONLY: 0x8,                // Cannot be changed by user
            VF_REQUIRE_APP_RESTART: 0x100,   // Requires application restart to take effect
            VF_NO_HELP: 0x200,               // Not shown in help
            VF_WHITELIST_FLAG_2: 0x40,       // Checked in config load whitelist logic
            VF_WHITELIST_FLAG_1: 0x400,      // Checked in config load whitelist logic
            VF_DUMPTODISK: 0x1000,           // Saved to disk
            VF_INVISIBLE: 0x4000,            // Hidden from console auto-completion etc.
            VF_CONST_CVAR: 0x8000,           // Cannot be changed after registration
            VF_NODUMP: 0x10000,              // Not dumped to disk / included in dumps
            VF_MODIFIED_BY_CONFIG: 0x20000,  // Set during config load after successful validation
            VF_BITFIELD: 0x40000,            // Used for int64 string parsing and console formatting
            VF_CONTEXT_FLAG_1: 0x80000,      // Set during config load based on context
            VF_DEPRECATED: 0x100000,         // Marked as deprecated in console output
            VF_ALWAYS_NOTIFY: 0x200000,      // Forces validation/update even if value seems unchanged
            VF_BADGECHECK: 0x10000000,       // Allows client override of VF_NET_SYNCED under certain conditions
            VF_NO_CONFIG_LOAD: 0x40000000,   // Prevents modification during config load unless forced
            VF_NET_SYNCED: 0x80000000        // Prevents client modification unless overridden
        };

        // --- Initialization ---
        this.baseAddr = Module.findBaseAddress(this.moduleName);
        if (!this.baseAddr) {
            throw new Error(`Module "${this.moduleName}" not found.`);
        }

        const pGlobalPtr = this.baseAddr.add(this.g_pCVarManagerOffset);
        this.pMgr = pGlobalPtr.readPointer();
        if (this.pMgr.isNull()) {
            throw new Error(`CVarManager instance pointer is NULL (at offset ${this.g_pCVarManagerOffset}).`);
        }

        this.pMgrVTable = this.pMgr.readPointer();
        if (this.pMgrVTable.isNull()) {
            throw new Error(`CVarManager VTable pointer is NULL.`);
        }

        // Resolve Manager-level functions
        this._resolveManagerFunctions();

        console.log(`[*] CVarManager initialized. Module: ${this.moduleName}@${this.baseAddr}, Manager: ${this.pMgr}`);
    }

    /**
     * Resolves and stores NativeFunction pointers for CVarManager methods.
     * @private
     */
    _resolveManagerFunctions() {
        const pfnEnumCVarsPtr = this.pMgrVTable.add(this.enumCVarsVTableOffset).readPointer();
        if (pfnEnumCVarsPtr.isNull() || !this._isValidCodePointer(pfnEnumCVarsPtr)) {
            throw new Error(`EnumCVars function pointer is NULL or invalid (at VTable offset ${this.enumCVarsVTableOffset}).`);
        }
        this.nativeEnumCVars = new NativeFunction(
            pfnEnumCVarsPtr, 'uint64', ['pointer', 'pointer', 'uint64', 'pointer'], 'win64'
        );

        const pfnFindCVarPtr = this.pMgrVTable.add(this.findCVarVTableOffset).readPointer();
        if (pfnFindCVarPtr.isNull() || !this._isValidCodePointer(pfnFindCVarPtr)) {
            throw new Error(`FindCVar function pointer is NULL or invalid (at VTable offset ${this.findCVarVTableOffset}).`);
        }
        this.nativeFindCVar = new NativeFunction(
            pfnFindCVarPtr, 'pointer', ['pointer', 'pointer'], 'win64'
        );
    }

    /**
     * Basic check if a pointer points within the module's likely code range.
     * @private
     */
    _isValidCodePointer(ptr) {
        if (!ptr || ptr.isNull()) return false;
        // Adjust range as needed, this is a basic sanity check
        return ptr.compare(this.baseAddr) >= 0 && ptr.compare(this.baseAddr.add(0x20000000)) < 0;
    }

    /**
     * Finds the ICVar object pointer for a given CVar name.
     * @param {string} name - The name of the CVar.
     * @returns {NativePointer | null} The pointer to the ICVar object, or null if not found.
     * @private
     */
    _getICVar(name) {
        if (!name || typeof name !== 'string') {
            console.error(`[!] _getICVar: Invalid name provided.`);
            return null;
        }
        try {
            const pNameArg = Memory.allocUtf8String(name); // Pass a C-string pointer
            const pICVar = this.nativeFindCVar(this.pMgr, pNameArg);

            if (pICVar.isNull() || pICVar.compare(ptr(0x10000)) <= 0) {
                // console.warn(`[?] CVar "${name}" not found by FindCVar.`);
                return null;
            }
            return pICVar;
        } catch (e) {
            console.error(`[!] Error in _getICVar for "${name}": ${e.message}`);
            return null;
        }
    }

    /**
     * Retrieves the VTable and function pointers for a specific ICVar method.
     * Caches the NativeFunction object for efficiency.
     * @param {NativePointer} pICVar - Pointer to the ICVar object.
     * @param {string} methodName - Name of the method (e.g., 'getName', 'getStringValue').
     * @param {number} offset - VTable offset for the method.
     * @param {string} retType - Frida NativeFunction return type.
     * @param {string[]} argTypes - Frida NativeFunction argument types (first is always 'pointer').
     * @returns {NativeFunction | null} The NativeFunction object or null on error.
     * @private
     */
    _getICVarMethod(pICVar, methodName, offset, retType, argTypes) {
        // Simple caching mechanism (could be more robust)
        if (!pICVar._methodCache) {
            pICVar._methodCache = {};
        }
        if (pICVar._methodCache[methodName]) {
            return pICVar._methodCache[methodName];
        }

        try {
            const pVTable = pICVar.readPointer();
            if (pVTable.isNull() || !this._isValidCodePointer(pVTable)) { // Check VTable validity
                 // console.error(`[!] Invalid VTable pointer ${pVTable} for ICVar at ${pICVar}`);
                 return null;
            }

            const pFuncPtr = pVTable.add(offset).readPointer();
            if (pFuncPtr.isNull() || !this._isValidCodePointer(pFuncPtr)) {
                 // console.error(`[!] Invalid function pointer ${pFuncPtr} for ${methodName} (offset ${offset}) on ICVar at ${pICVar}`);
                 return null;
            }

            const nativeFunc = new NativeFunction(pFuncPtr, retType, argTypes, 'win64');
            pICVar._methodCache[methodName] = nativeFunc; // Cache it
            return nativeFunc;

        } catch (e) {
            console.error(`[!] Error resolving method ${methodName} for ICVar at ${pICVar}: ${e.message}`);
            return null;
        }
    }

    /**
     * Gets the string value of a CVar.
     * @param {string} name - The name of the CVar.
     * @returns {string | null} The value as a string, or null if not found or error.
     */
    getValue(name) {
        const pICVar = this._getICVar(name);
        if (!pICVar) return null;

        const nativeGetStringValue = this._getICVarMethod(pICVar, 'getStringValue', this.getStringVTableOffset, 'pointer', ['pointer']);
        if (!nativeGetStringValue) return null;

        try {
            const valuePtr = nativeGetStringValue(pICVar);
            console.log(valuePtr, name);

            // Handle the case where GetStringValue returns the static buffer
            // We need to read it immediately before another call overwrites it.
            // A more robust solution might involve intercepting/hooking, but this works for simple gets.
            return valuePtr.isNull() ? null : valuePtr.readCString();
        } catch (e) {
            console.error(`[!] Error reading value for CVar "${name}": ${e.message}`);
            return null;
        }
    }

    /**
     * Gets the name of a CVar (useful for verifying case sensitivity or finding the canonical name).
     * @param {string} name - The name used to find the CVar.
     * @returns {string | null} The canonical name as a string, or null if not found or error.
     */
    getName(name) {
        const pICVar = this._getICVar(name);
        if (!pICVar) return null;

        const nativeGetName = this._getICVarMethod(pICVar, 'getName', this.getNameVTableOffset, 'pointer', ['pointer']);
        if (!nativeGetName) return null;

        try {
            const namePtr = nativeGetName(pICVar);
            return namePtr.isNull() ? null : namePtr.readCString();
        } catch (e) {
            console.error(`[!] Error reading name for CVar "${name}": ${e.message}`);
            return null;
        }
    }

    /**
     * Gets the flags of a CVar as a number.
     * @param {string} name - The name of the CVar.
     * @returns {number | null} The flags as a uint32 number, or null if not found or error.
     */
    getFlags(name) {
        const pICVar = this._getICVar(name);
        if (!pICVar) return null;

        const nativeGetFlags = this._getICVarMethod(pICVar, 'getFlags', this.getFlagsVTableOffset, 'uint32', ['pointer']);
        if (!nativeGetFlags) return null;

        try {
            return nativeGetFlags(pICVar);
        } catch (e) {
            console.error(`[!] Error reading flags for CVar "${name}": ${e.message}`);
            return null;
        }
    }

    /**
     * Converts CVar flags (number) to a human-readable string.
     * @param {number} flags - The flags value.
     * @returns {string} A string representation of the flags.
     */
    flagsToString(flags) {
        if (flags === null || flags === undefined) return "[N/A]";
        let parts = [];
        for (const flagName in this.FLAGS) {
            if ((flags & this.FLAGS[flagName]) !== 0) {
                parts.push(flagName);
            }
        }
        return parts.length > 0 ? parts.join(' | ') : 'VF_NONE';
    }

    /**
     * Sets the string value of a CVar.
     * @param {string} name - The name of the CVar.
     * @param {string} value - The new value to set (must be a string).
     * @returns {boolean} True if successful, false otherwise.
     */
    setValue(name, value) {
        if (typeof value !== 'string') {
             console.error(`[!] setValue Error: Value for "${name}" must be a string (received ${typeof value}). Convert numbers/booleans to strings first.`);
             return false;
        }

        const pICVar = this._getICVar(name);
        if (!pICVar) return false;

        // Check READONLY/CONST flags before attempting to set
        const currentFlags = this.getFlags(name); // Use internal getFlags
        if (currentFlags !== null) {
            if (currentFlags & this.FLAGS.VF_READONLY) {
                console.error(`[!] Cannot set value for CVar "${name}": It has the VF_READONLY flag.`);
                return false;
            }
            if (currentFlags & this.FLAGS.VF_CONST_CVAR) {
                console.error(`[!] Cannot set value for CVar "${name}": It has the VF_CONST_CVAR flag.`);
                return false;
            }
        } else {
             console.warn(`[?] Could not read flags for CVar "${name}" before setting value.`);
             // Proceed with caution
        }

        // Assume void SetStringValue(pointer pThis, pointer pszValue)
        const nativeSetStringValue = this._getICVarMethod(pICVar, 'setStringValue', this.setStringVTableOffset, 'void', ['pointer', 'pointer']);
        if (!nativeSetStringValue) return false;

        try {
            const pValueArg = Memory.allocUtf8String(value);
            nativeSetStringValue(pICVar, pValueArg);
            // Assume success if no exception
            // console.log(`[*] Set CVar "${name}" = "${value}"`); // Optional success log
            return true;
        } catch (e) {
            console.error(`[!] Error setting value for CVar "${name}": ${e.message}`);
            return false;
        }
    }

    /**
     * Sets the flags of a CVar.
     * WARNING: Modifying flags can destabilize the game if done incorrectly. Use with caution!
     * @param {string} name - The name of the CVar.
     * @param {number} flags - The new flags value (uint32).
     * @returns {boolean} True if successful, false otherwise.
     */
    setFlags(name, flags) {
        console.warn(`[!] setFlags: Modifying CVar flags can be unstable. Use with caution.`);
        const pICVar = this._getICVar(name);
        if (!pICVar) return false;

        // Assume void SetFlags(pointer pThis, uint32 flags)
        const nativeSetFlags = this._getICVarMethod(pICVar, 'setFlags', this.setFlagsVTableOffset, 'void', ['pointer', 'uint32']);
        if (!nativeSetFlags) return false;

        try {
            nativeSetFlags(pICVar, flags);
            // Assume success if no exception
            console.log(`[*] Set flags for CVar "${name}" = 0x${flags.toString(16)} (${this.flagsToString(flags)})`);
            return true;
        } catch (e) {
            console.error(`[!] Error setting flags for CVar "${name}": ${e.message}`);
            return false;
        }
    }

    /**
     * Lists the names of all registered CVars.
     * @returns {string[] | null} An array of CVar names, or null on error.
     */
    listCVars() {
        let pNameListBuffer = null;
        try {
            const cvarCount = this.nativeEnumCVars(this.pMgr, ptr(0), 0, ptr(0));
            if (cvarCount.equals(0)) {
                console.warn("[-] listCVars: EnumCVars returned 0.");
                return [];
            }

            const bufferSize = cvarCount * Process.pointerSize;
            pNameListBuffer = Memory.alloc(bufferSize);
            this.nativeEnumCVars(this.pMgr, pNameListBuffer, cvarCount, ptr(0));

            const names = [];
            for (let i = 0; i < cvarCount.toNumber(); i++) {
                const pName = pNameListBuffer.add(i * Process.pointerSize).readPointer();
                if (!pName.isNull()) {
                    try {
                        const nameStr = pName.readCString();
                        if (nameStr) {
                            names.push(nameStr);
                        }
                    } catch (e) {
                        // Ignore errors reading individual names
                    }
                }
            }
            return names;
        } catch (e) {
            console.error(`[!] Error listing CVars: ${e.message}`);
            return null;
        } finally {
            // Frida's Memory.alloc might GC, but being explicit is safer if needed later
            // if (pNameListBuffer) { Memory.free(pNameListBuffer); }
        }
    }

    /**
     * Dumps all CVars to the console or returns as an object, including VF_NODUMP CVars.
     * @param {boolean} logToConsole - If true, logs to console. If false, returns an object.
     * @returns {object | void} An object mapping CVar names to values if logToConsole is false.
     */
    dump(logToConsole = true) {
        const names = this.listCVars();
        if (!names) {
            console.error("[!] Failed to list CVars for dumping.");
            return;
        }

        if (logToConsole) console.log(`\n--- CVar Dump (${names.length} total CVars found) ---`);
        let cvarDump = {};
        let nodumpCvars = {};
        let dumpedCount = 0;
        let nodumpCount = 0;
        let errorCount = 0;

        for (const name of names) {
            try {
                const flags = this.getFlags(name);
                if (flags === null) {
                    errorCount++;
                    continue;
                }

                const value = this.getValue(name); // Use internal getValue
                if (value !== null) {
                    const flagsString = this.flagsToString(flags);
                    
                    if ((flags & this.FLAGS.VF_NODUMP) !== 0) {
                        // This is a NODUMP cvar - collect it separately
                        if (logToConsole) {
                            // We'll log these later in their own section
                        } else {
                            nodumpCvars[name] = {
                                value: value,
                                flags: flags,
                                flagsString: flagsString
                            };
                        }
                        nodumpCount++;
                    } else {
                        // Regular cvar
                        if (logToConsole) {
                            console.log(`${name} = ${value} [Flags: 0x${flags.toString(16)} (${flagsString})]`);
                        } else {
                            cvarDump[name] = {
                                value: value,
                                flags: flags,
                                flagsString: flagsString
                            };
                        }
                        dumpedCount++;
                    }
                } else {
                    if (logToConsole) {
                        console.log(`${name} = [ERROR READING VALUE] [Flags: 0x${flags.toString(16)} (${this.flagsToString(flags)})]`);
                    }
                    errorCount++;
                }
            } catch(e) {
                console.warn(`[?] Error processing CVar "${name}" during dump: ${e.message}`);
                errorCount++;
            }
        }

        // Log the NODUMP cvars in their own section
        if (logToConsole && nodumpCount > 0) {
            console.log(`\n--- Hidden CVars (VF_NODUMP) ---`);
            for (const name of names) {
                try {
                    const flags = this.getFlags(name);
                    if (flags !== null && (flags & this.FLAGS.VF_NODUMP) !== 0) {
                        const value = this.getValue(name);
                        if (value !== null) {
                            console.log(`${name} = ${value} [Flags: 0x${flags.toString(16)} (${this.flagsToString(flags)})]`);
                        }
                    }
                } catch(e) {
                    // Already counted in error count
                }
            }
        }

        console.log(`\n--- Dump Complete ---`);
        console.log(`[*] Regular CVars Dumped: ${dumpedCount}`);
        console.log(`[*] Hidden CVars (VF_NODUMP): ${nodumpCount}`);
        console.log(`[*] Errors: ${errorCount}`);

        if (!logToConsole) {
            return {
                regular: cvarDump,
                hidden: nodumpCvars
            };
        }
    }
}

try {
    const cvarMgr = new CVarManager();

    // Dump all CVars to console
    cvarMgr.dump();

    const tryFlipFlagNeg = (cvarName, flag) => {
        let currentFlags = cvarMgr.getFlags(cvarName);
    
        if (!currentFlags) {
            console.log(`${cvarName} not found`);
            return;
        }
    
        let readonly = 0x8;
        cvarMgr.setFlags(cvarName, currentFlags & ~flag);
    }

    const tryFlipFlagPos = (cvarName, flag) => {
        let currentFlags = cvarMgr.getFlags(cvarName);
        
        if (!currentFlags) {
            console.log(`${cvarName} not found`);
            return;
        }
        
        let readonly = 0x8;
        cvarMgr.setFlags(cvarName, currentFlags | readonly);
    }
    
    const process = (varName, value) => {
        tryFlipFlagNeg(varName, cvarMgr.FLAGS.VF_READONLY);
        tryFlipFlagNeg(varName, cvarMgr.FLAGS.VF_BADGECHECK);
        tryFlipFlagNeg(varName, cvarMgr.FLAGS.VF_NET_SYNCED);
        cvarMgr.setValue(varName, value);
        tryFlipFlagPos(varName, cvarMgr.FLAGS.VF_READONLY);
    };

    process("pl_corpse.disableDropHeldItemOnDeath", "2");
    process("pl_corpse.disableLandingZoneRescue", "1");
    process("pl_corpse.enableDelayedRespawnEntitlement", "1");
    process("pl_corpse.enableItemRecoveryFlow", "2");
    process("pl_corpse.keepAllItems", "1");
    process("pl_corpse.keepMobiGlas", "1");
    process("pl_corpse.maxCorpsesPerPlayer", "10");
    process("sys_skipInactiveSleep", "1");
    process("ai_MovementSystemDebugDraw", "1");
    process("debugGUI_enable", "1");
    process("ea_player.log", "1");
} catch (e) {
    console.error(`[!] Initialization failed: ${e.message}`);
}