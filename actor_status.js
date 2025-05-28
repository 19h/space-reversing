/*
 * Frida Script for Intercepting CSCActorStatus Stat Updates in StarCitizen.exe
 * Target: UpdateStatValueAndCacheHit, AdjustActorStat, OnStatVariableChanged.
 * Goal: Log detailed information about arguments and pointed-to data structures
 *       as a structured JSON object for each hooked function.
 * Author: [Your Name/Alias]
 * Date: [Current Date]
 * Version: 1.6 - Implemented AdjustActorStat and OnStatVariableChanged hooks
 *
 * Based on analysis of pseudo-C code for functions around 0x1436BB520.
 */

'use strict';

// --- Configuration ---
const TARGET_MODULE = "StarCitizen.exe";
const STATIC_BASE_ADDRESS = ptr("0x140000000"); // Assumed base address during static analysis

// Function Offsets from Static Base Address
const OFFSETS = {
    UpdateStatValueAndCacheHit: ptr("0x1436BB520").sub(STATIC_BASE_ADDRESS), // Primary target
    AdjustActorStat: ptr("0x143681DC0").sub(STATIC_BASE_ADDRESS),           // Calls UpdateStatValueAndCacheHit
    OnStatVariableChanged: ptr("0x1436A0690").sub(STATIC_BASE_ADDRESS),     // Calls UpdateStatValueAndCacheHit (non-authoritative)
    // sub_142655150_GetStatName: ptr("0x142655150").sub(STATIC_BASE_ADDRESS) // Less reliable than map
};

// Known Stat Index Mapping (derived from sub_142655150 analysis)
const STAT_INDEX_MAP = {
    0: "Hunger", 1: "Thirst", 2: "BloodDrugLevel", 3: "OverdoseLevel",
    4: "BodyTemperature", 5: "SuitTemperature", 6: "Stun", 7: "Distortion",
    8: "Pressure", 9: "GasSaturationO2", 10: "DownedDamage", 11: "HealthPool",
    12: "HealthHead", 13: "HealthTorso", 14: "HealthLeftArm", 15: "HealthRightArm",
    16: "HealthLeftLeg", 17: "HealthRightLeg", 18: "WearHead", 19: "WearTorso",
    20: "WearLeftArm", 21: "WearRightArm", 22: "WearLeftLeg", 23: "WearRightLeg",
    24: "BodyRadiation", 25: "SuitRadiation", 26: "GasSaturationCO2",
    27: "GasSaturationCO", 28: "Hygiene"
    // 29 appears to be a default/invalid index
};

// --- Utility Functions ---

/**
 * Safely reads memory and returns a hexdump string or an error message.
 * @param {NativePointer} ptr The pointer to read from.
 * @param {number} length The number of bytes to dump.
 * @param {string} description Optional description for logging.
 * @returns {string} Hexdump string or error indicator.
 */
function safeHexdump(ptr, length = 64, description = "") {
    const prefix = description ? `[${description}] ` : "";
    if (!ptr || ptr.isNull()) {
        return `${prefix}(NULL Pointer)`;
    }
    try {
        Memory.readU8(ptr); // Probe read access first
        return hexdump(ptr, { length: length, header: false, ansi: false });
    } catch (e) {
        // console.error(`[-] Error during hexdump for ${description} at ${ptr}: ${e.message}`);
        return `${prefix}(Read Error: ${e.message})`;
    }
}

/**
 * Safely reads a value of a specific type from memory.
 * @param {NativePointer} ptr The pointer to read from.
 * @param {string} type Frida memory access type (e.g., 'Float', 'Pointer', 'U32', 'U8', 'U16').
 * @param {string} description Optional description for logging.
 * @returns {any | string} The value or an error indicator string.
 */
function safeReadValue(ptr, type, description = "") {
    const prefix = description ? `[${description}] ` : "";
    if (!ptr || ptr.isNull()) {
        return `${prefix}(NULL Pointer)`;
    }
    try {
        const readMethod = `read${type}`;
        if (typeof ptr[readMethod] === 'function') {
            return ptr[readMethod]();
        } else {
            return `${prefix}(Invalid type: ${type})`;
        }
    } catch (e) {
        // console.error(`[-] Error reading ${type} for ${description} at ${ptr}: ${e.message}`);
        return `${prefix}(Read Error: ${e.message})`;
    }
}

/**
 * Attempts to resolve a stat index to its name.
 * @param {number} index The stat index.
 * @returns {string} The stat name or "Unknown".
 */
function getStatName(index) {
    return STAT_INDEX_MAP[index] || `Unknown (${index})`;
}

/**
 * Formats a pointer for logging, handling NULL.
 * @param {NativePointer} ptr
 * @returns {string}
 */
function formatPointer(ptr) {
    if (!ptr || ptr.isNull()) {
        return "NULL";
    }
    // Ensure it's treated as a pointer before calling toString()
    return ptr instanceof NativePointer ? ptr.toString() : `(Not a Pointer: ${ptr})`;
}

/**
 * Populates common fields for hook data objects.
 * @param {InvocationContext} hookContext
 * @param {NativePointer} funcAddr
 * @returns {object}
 */
function createBaseHookObject(hookContext, funcAddr) {
     const obj = {
        timestamp: new Date().toISOString(),
        threadId: hookContext.threadId,
        functionAddress: formatPointer(funcAddr),
        returnAddress: formatPointer(hookContext.returnAddress),
        arguments: {},
        context: {}
    };

    // --- Register Context ---
    if (hookContext.context) { // Check if context is available
        const regs = ['rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
                      'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
        regs.forEach(reg => {
            obj.context[reg] = formatPointer(hookContext.context[reg]);
        });
        const xmms = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']; // Log first 8
        xmms.forEach(reg => {
            const val = hookContext.context[reg];
            obj.context[reg] = val ? val.toString() : 'undefined';
        });
    } else {
        obj.context.error = "(Hook context unavailable)";
    }

    delete obj.context;
    return obj;
}

/**
 * Populates actor status data into the main object.
 * @param {object} obj The main hook object.
 * @param {NativePointer} actorStatusPtr
 */
function populateActorStatusData(obj, actorStatusPtr) {
    obj.actorStatusData = {};
     if (actorStatusPtr && !actorStatusPtr.isNull()) {
        obj.actorStatusData.entityHandle = formatPointer(safeReadValue(actorStatusPtr.add(0x50), 'Pointer', 'ActorStatus+0x50'));
        obj.actorStatusData.statArrayBase = formatPointer(safeReadValue(actorStatusPtr.add(0x88), 'Pointer', 'ActorStatus+0x88'));
        obj.actorStatusData.someOtherPtr = formatPointer(safeReadValue(actorStatusPtr.add(0x298), 'Pointer', 'ActorStatus+0x298'));
        //obj.actorStatusData.rawValue = safeHexdump(actorStatusPtr, 128, "ActorStatus");
    } else {
        //obj.actorStatusData.rawValue = "(NULL Pointer)";
    }
}

/**
 * Builds a structured JS object for UpdateStatValueAndCacheHit.
 * @param {InvocationContext} hookContext The 'this' context from onEnter.
 * @param {InvocationArguments} args The 'args' from onEnter.
 * @param {NativePointer} funcAddr The address of the hooked function.
 * @returns {object} The structured data object.
 */
function buildStatUpdateObject(hookContext, args, funcAddr) {
    const obj = createBaseHookObject(hookContext, funcAddr);
    obj.statData = {};
    obj.sourceHandleData = {};

    // --- Arguments ---
    obj.arguments.actorStatusPtr = formatPointer(args[0]);
    obj.arguments.statIndex = args[1].toUInt32();
    obj.arguments.statName = getStatName(obj.arguments.statIndex);
    obj.arguments.statDataPtr = formatPointer(args[2]);
    obj.arguments.adjustmentValue = "(Failed to read - Access Violation or Frida issue)"; // Default error

    // --- Stack Arguments ---
    let stackBase = null;
    let stackReadError = null;
    if (!hookContext.context || !hookContext.context.rsp) {
        stackReadError = hookContext.context ? "(Hook context.rsp unavailable)" : "(Hook context unavailable)";
    } else {
        stackBase = hookContext.context.rsp;
    }

    let sourceHandle = stackReadError; // Initialize with potential error
    if (stackBase) {
        obj.arguments.cacheHitFlag1 = safeReadValue(stackBase.add(0x28), 'U8', 'cacheHitFlag1');
        obj.arguments.cacheHitFlag2 = safeReadValue(stackBase.add(0x30), 'U8', 'cacheHitFlag2');
        sourceHandle = safeReadValue(stackBase.add(0x38), 'Pointer', 'sourceHandle'); // Read into temp var
        obj.arguments.hitId = safeReadValue(stackBase.add(0x40), 'U16', 'hitId');

        obj.arguments.cacheHitFlag1 = typeof obj.arguments.cacheHitFlag1 === 'number' ? (obj.arguments.cacheHitFlag1 !== 0) : obj.arguments.cacheHitFlag1;
        obj.arguments.cacheHitFlag2 = typeof obj.arguments.cacheHitFlag2 === 'number' ? (obj.arguments.cacheHitFlag2 !== 0) : obj.arguments.cacheHitFlag2;
        obj.arguments.sourceHandle = formatPointer(sourceHandle); // Format for arguments section
    } else {
        obj.arguments.cacheHitFlag1 = stackReadError;
        obj.arguments.cacheHitFlag2 = stackReadError;
        obj.arguments.sourceHandle = stackReadError;
        obj.arguments.hitId = stackReadError;
    }

    // --- Data from statDataPtr ---
    const statDataPtr = args[2];
    if (statDataPtr && !statDataPtr.isNull()) {
        obj.statData.currentValue = safeReadValue(statDataPtr.add(0), 'Float', 'StatData+0x0');
        obj.statData.previousValue = safeReadValue(statDataPtr.add(4), 'Float', 'StatData+0x4');
        obj.statData.maxValue = safeReadValue(statDataPtr.add(8), 'Float', 'StatData+0x8');
        obj.statData.minValue = safeReadValue(statDataPtr.add(12), 'Float', 'StatData+0xC');
        obj.statData.flags = safeReadValue(statDataPtr.add(16), 'U8', 'StatData+0x10');
        obj.statData.relatedPtr = formatPointer(safeReadValue(statDataPtr.add(24), 'Pointer', 'StatData+0x18'));
        //obj.statData.rawValue = safeHexdump(statDataPtr, 64, "StatData");
    } else {
        //obj.statData.rawValue = "(NULL Pointer)";
    }

    // --- Data from actorStatusPtr ---
    populateActorStatusData(obj, args[0]);

    // --- Data from sourceHandle (if pointer) ---
    // if (typeof sourceHandle !== 'string' && sourceHandle instanceof NativePointer && !sourceHandle.isNull()) {
    //    if (sourceHandle.compare(ptr("0x10000")) > 0) {
    //        obj.sourceHandleData.rawValue = safeHexdump(sourceHandle, 128, "SourceHandle");
    //    } else {
    //        obj.sourceHandleData.rawValue = `(Likely an ID [${sourceHandle}], not dumping memory)`;
    //    }
    //} else {
    //     obj.sourceHandleData.rawValue = formatPointer(sourceHandle); // Will be "NULL" or error string
    //}

    return obj;
}

/**
 * Builds a structured JS object for AdjustActorStat.
 * @param {InvocationContext} hookContext The 'this' context from onEnter.
 * @param {InvocationArguments} args The 'args' from onEnter.
 * @param {NativePointer} funcAddr The address of the hooked function.
 * @returns {object} The structured data object.
 */
function buildAdjustStatObject(hookContext, args, funcAddr) {
    const obj = createBaseHookObject(hookContext, funcAddr);
    obj.sourceHandleData = {};

    // --- Arguments (RCX, RDX, XMM2, R9, Stack[0x28]) ---
    obj.arguments.actorStatusPtr = formatPointer(args[0]);
    obj.arguments.statIndex = args[1].toUInt32();
    obj.arguments.statName = getStatName(obj.arguments.statIndex);
    obj.arguments.adjustmentValue = "(Failed to read - XMM2 access issue?)"; // Default error for float
    obj.arguments.sourceHandle = formatPointer(args[3]); // R9

    // --- Stack Argument ---
    let stackBase = null;
    let stackReadError = null;
    if (!hookContext.context || !hookContext.context.rsp) {
        stackReadError = hookContext.context ? "(Hook context.rsp unavailable)" : "(Hook context unavailable)";
    } else {
        stackBase = hookContext.context.rsp;
    }

    let sourceHandle = args[3]; // Get R9 value for later use
    if (stackBase) {
        obj.arguments.hitId = safeReadValue(stackBase.add(0x28), 'U16', 'hitId');
    } else {
        obj.arguments.hitId = stackReadError;
    }

    // --- Data from actorStatusPtr ---
    populateActorStatusData(obj, args[0]);

    // --- Data from sourceHandle (if pointer) ---
    // if (typeof sourceHandle !== 'string' && sourceHandle instanceof NativePointer && !sourceHandle.isNull()) {
    //    if (sourceHandle.compare(ptr("0x10000")) > 0) {
    //        obj.sourceHandleData.rawValue = safeHexdump(sourceHandle, 128, "SourceHandle");
    //    } else {
    //        obj.sourceHandleData.rawValue = `(Likely an ID [${sourceHandle}], not dumping memory)`;
    //    }
    //} else {
    //     obj.sourceHandleData.rawValue = formatPointer(sourceHandle); // Will be "NULL" or error string
    //}

    return obj;
}

/**
 * Builds a structured JS object for OnStatVariableChanged.
 * @param {InvocationContext} hookContext The 'this' context from onEnter.
 * @param {InvocationArguments} args The 'args' from onEnter.
 * @param {NativePointer} funcAddr The address of the hooked function.
 * @returns {object} The structured data object.
 */
function buildOnStatVariableChangedObject(hookContext, args, funcAddr) {
    const obj = createBaseHookObject(hookContext, funcAddr);
    obj.statChangeInfoData = {};

    // --- Arguments (RCX, RDX) ---
    obj.arguments.actorStatusPtr = formatPointer(args[0]);
    obj.arguments.statChangeInfoPtr = formatPointer(args[1]);

    // --- Data from actorStatusPtr ---
    populateActorStatusData(obj, args[0]);

    // --- Data from statChangeInfoPtr ---
    const statChangeInfoPtr = args[1];
    if (statChangeInfoPtr && !statChangeInfoPtr.isNull()) {
        obj.statChangeInfoData.statIndex = safeReadValue(statChangeInfoPtr.add(8), 'U32', 'StatChangeInfo+0x8');
        if (typeof obj.statChangeInfoData.statIndex === 'number') {
             obj.statChangeInfoData.statName = getStatName(obj.statChangeInfoData.statIndex);
        }
        obj.statChangeInfoData.newValue = safeReadValue(statChangeInfoPtr.add(12), 'Float', 'StatChangeInfo+0xC');
        obj.statChangeInfoData.sourceHandle = formatPointer(safeReadValue(statChangeInfoPtr.add(24), 'Pointer', 'StatChangeInfo+0x18'));
        obj.statChangeInfoData.timestamp = safeReadValue(statChangeInfoPtr.add(56), 'U64', 'StatChangeInfo+0x38');
        //obj.statChangeInfoData.rawValue = safeHexdump(statChangeInfoPtr, 128, "StatChangeInfo");
    } else {
        //obj.statChangeInfoData.rawValue = "(NULL Pointer)";
    }

    return obj;
}


// --- Main Script Logic ---

console.log("[*] Starting StarCitizen Actor Status Hook Script v1.6...");

const targetModule = Process.findModuleByName(TARGET_MODULE);
if (!targetModule) {
    console.error(`[-] Module ${TARGET_MODULE} not found in process. Ensure the game is running and the module name is correct.`);
    console.log("[-] Script will exit.");
} else {
    const baseAddr = targetModule.base;
    console.log(`[+] Found ${TARGET_MODULE} at base address: ${baseAddr}`);

    // Calculate runtime addresses
    const funcAddrs = {};
    for (const funcName in OFFSETS) {
        funcAddrs[funcName] = baseAddr.add(OFFSETS[funcName]);
        console.log(`[*]   Address for ${funcName}: ${funcAddrs[funcName]}`);
    }

    // --- Hook Definition: UpdateStatValueAndCacheHit ---
    if (funcAddrs.UpdateStatValueAndCacheHit) {
        try {
            Interceptor.attach(funcAddrs.UpdateStatValueAndCacheHit, {
                onEnter: function(args) {
                    try {
                        // console.log(`[*] Hook triggered for UpdateStatValueAndCacheHit by ${this.returnAddress} on thread ${this.threadId}`);
                        if (!this.context || !this.context.rsp) {
                             console.error(`[-] Context/RSP unavailable for UpdateStatValueAndCacheHit hook (Thread: ${this.threadId}, Caller: ${this.returnAddress})`);
                             // Log basic args if needed for context
                             // console.log(`    Args[0]: ${args[0]}, Args[1]: ${args[1]}, Args[2]: ${args[2]}`);
                             // return; // Decide whether to return or proceed with partial data
                        }
                        const statUpdateObject = buildStatUpdateObject(this, args, funcAddrs.UpdateStatValueAndCacheHit);
                        console.log("--- UpdateStatValueAndCacheHit ---");
                        console.log(JSON.stringify(statUpdateObject, null, 2));
                    } catch (e) {
                        console.error(`[-] Error in onEnter for UpdateStatValueAndCacheHit: ${e.message}\n${e.stack}`);
                        console.log(`  Thread ID: ${this.threadId}, Return Address: ${this.returnAddress}`);
                        console.log(`  Args[0]: ${args[0]}, Args[1]: ${args[1]}, Args[2]: ${args[2]}`);
                    }
                }
            });
            console.log(`[+] Successfully attached to UpdateStatValueAndCacheHit.`);
        } catch (error) {
            console.error(`[-] Failed to attach to UpdateStatValueAndCacheHit: ${error.message}\n${error.stack}`);
        }
    } else {
        console.warn(`[-] Address for UpdateStatValueAndCacheHit not found or calculated.`);
    }

    // --- Hook Definition: AdjustActorStat ---
    if (funcAddrs.AdjustActorStat) {
        try {
            Interceptor.attach(funcAddrs.AdjustActorStat, {
                onEnter: function(args) {
                     try {
                        // console.log(`[*] Hook triggered for AdjustActorStat by ${this.returnAddress} on thread ${this.threadId}`);
                        if (!this.context || !this.context.rsp) {
                             console.error(`[-] Context/RSP unavailable for AdjustActorStat hook (Thread: ${this.threadId}, Caller: ${this.returnAddress})`);
                        }
                        const adjustStatObject = buildAdjustStatObject(this, args, funcAddrs.AdjustActorStat);
                        console.log("--- AdjustActorStat ---");
                        console.log(JSON.stringify(adjustStatObject, null, 2));
                    } catch (e) {
                        console.error(`[-] Error in onEnter for AdjustActorStat: ${e.message}\n${e.stack}`);
                        console.log(`  Thread ID: ${this.threadId}, Return Address: ${this.returnAddress}`);
                        console.log(`  Args[0]: ${args[0]}, Args[1]: ${args[1]}, Args[3]: ${args[3]}`);
                    }
                }
            });
            console.log(`[+] Successfully attached to AdjustActorStat.`);
        } catch (error) {
            console.error(`[-] Failed to attach to AdjustActorStat: ${error.message}\n${error.stack}`);
        }
    } else {
        console.warn(`[-] Address for AdjustActorStat not found or calculated.`);
    }

    // --- Hook Definition: OnStatVariableChanged ---
    if (funcAddrs.OnStatVariableChanged) {
        try {
            Interceptor.attach(funcAddrs.OnStatVariableChanged, {
                onEnter: function(args) {
                     try {
                        // console.log(`[*] Hook triggered for OnStatVariableChanged by ${this.returnAddress} on thread ${this.threadId}`);
                         if (!this.context) { // Only need context for registers, RSP not used for args here
                             console.warn(`[-] Context unavailable for OnStatVariableChanged hook (Thread: ${this.threadId}, Caller: ${this.returnAddress})`);
                         }
                        const statChangedObject = buildOnStatVariableChangedObject(this, args, funcAddrs.OnStatVariableChanged);
                        console.log("--- OnStatVariableChanged ---");
                        console.log(JSON.stringify(statChangedObject, null, 2));
                    } catch (e) {
                        console.error(`[-] Error in onEnter for OnStatVariableChanged: ${e.message}\n${e.stack}`);
                        console.log(`  Thread ID: ${this.threadId}, Return Address: ${this.returnAddress}`);
                        console.log(`  Args[0]: ${args[0]}, Args[1]: ${args[1]}`);
                    }
                }
            });
            console.log(`[+] Successfully attached to OnStatVariableChanged.`);
        } catch (error) {
            console.error(`[-] Failed to attach to OnStatVariableChanged: ${error.message}\n${error.stack}`);
        }
    } else {
        console.warn(`[-] Address for OnStatVariableChanged not found or calculated.`);
    }


    console.log("[*] Hooks installed. Waiting for function calls...");
}