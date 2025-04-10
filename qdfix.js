/*
 * Frida Hook Script for Star Citizen Quantum Drive State Modification (Detailed Logging Version 2)
 * ===============================================================================================
 *
 * Target Module: StarCitizen.exe
 * Target Function: SetQuantumDriveState (Inferred name)
 *
 * Functionality:
 * 1. Locates the SetQuantumDriveState function using a memory signature.
 * 2. Intercepts calls to this function using Interceptor.replace.
 * 3. Implements a NativeCallback to replace the original function temporarily.
 * 4. Inside the callback:
 *    - Logs entry, arguments, and internal steps with extreme detail.
 *    - ***NEW: Reads and logs numerous inferred data members from the QuantumDriveComponent structure.***
 *    - Checks if a party-based Quantum Travel synchronization is likely active.
 *    - Conditionally overrides preparatory states to Flight_In_Progress for solo play.
 *    - Calls the original SetQuantumDriveState function with the final state value.
 *    - Logs the return value and exit.
 *
 * Purpose:
 * To accelerate solo Quantum Travel initiation while preserving party jump functionality,
 * AND to provide a detailed snapshot of the QD component's state and data
 * at the exact moment a state transition is requested, aiding debugging and analysis.
 *
 * WARNINGS & DISCLAIMERS:
 * - Anti-Cheat Risk: HIGHLY LIKELY TO BE DETECTED. Use at your own risk.
 * - Network Desync: State skipping WILL cause client-server desynchronization.
 * - Game Updates: Signature and offsets WILL break. Requires constant maintenance and RE.
 * - Stability: Forcing states or reading incorrect offsets can cause crashes/glitches.
 * - Educational Use Only.
 *
 */

(function() {
    "use strict";

    const SCRIPT_NAME = "QuantumHookDetailedLog";
    console.log(`[${SCRIPT_NAME}] Initializing Frida script...`);

    // --- Configuration ---
    const MODULE_NAME = "StarCitizen.exe";
    const ENABLE_QD_MOD = true; // Master switch for the modification logic
    const SKIP_SOLO_SPOOL_ALIGN = true; // Enable state skipping for solo play

    // --- Memory Signature for SetQuantumDriveState ---
    // IMPORTANT: VERIFY AND UPDATE FOR YOUR GAME VERSION!
    const quantumSig = "89 54 24 10 48 89 4C 24 08 55 56 57 48 81 EC C0 07 00 00 48 8D 6C 24 60";
    console.log(`[${SCRIPT_NAME}] Using SetState Signature: ${quantumSig}`);

    // --- Inferred Offsets within QuantumDriveComponent Structure ---
    // IMPORTANT: VERIFY AND UPDATE VIA REVERSE ENGINEERING! Offsets are in HEX.
    const OFFSETS = {
        STATE: 0xF50,           // 3920 dec - QD state enum/int (uint32)
        TARGET_HANDLE: 0x608,   // 1544 dec - Current target handle/ptr (pointer) - VERIFIED AS LIKELY CORRECT
        TRAVEL_ENVELOPE: 0x680, // 1664 dec - Handle/ptr to calculated path data (pointer)
        ACTIVE_SPLINE: 0x840,   // 2112 dec - Handle/ptr to active spline object (pointer)
        SPLINE_DATA_PTR: 0xDE8, // 3584 dec - Pointer to spline point data? (pointer)
        SPLINE_VALID_FLAG: 0xDF0,// 3592 dec - Flag indicating spline readiness (uint8/bool)
        SPOOL_PROGRESS: 0xF10,  // 3856 dec - Current spool progress (0.0-1.0) (float)
        ALIGN_PROGRESS: 0x6A8,  // 1704 dec - Current alignment progress/error (float)
        TRAVEL_COMPLETION_PCT: 0x8BC, // 2196 dec - Overall travel progress (0.0-1.0) (float)
        FAILURE_FLAGS: 0xD4C,   // 3404 dec - Bitfield for failure reasons (uint32)
        STATUS_FLAGS_1: 0xEDC,  // 3812 dec - Bitfield for operational status (uint16/uint32?)
        STATUS_FLAGS_2: 0xD49,  // 3401 dec - Bitfield for other status (char/uint8)
        PARTY_LIST_BEGIN: 0x728,// 1832 dec - Inferred party list begin pointer/iterator (pointer) - VERIFIED AS LIKELY CORRECT
        PARTY_LIST_END: 0x730,  // 1840 dec - Inferred party list end pointer/iterator (pointer) - VERIFIED AS LIKELY CORRECT
        INTERDICTION_SOURCE: 0x688, // 1672 dec - Handle/ptr to interdictor? (pointer)
        INTERDICTOR_HANDLE: 0x6E8, // 1768 dec - Handle/ptr to interdictor? (pointer)
        INTERDICTION_STAGE: 0x718, // 1816 dec - Stage/type of interdiction (int?)
        IS_UPDATING_FLAG: 0xD48, // 3400 dec - Bool/char flag (uint8)

        TARGET_TYPE: 0x638,      // 1592 dec - Integer/enum indicating target type (uint32?) - NEEDS VERIFICATION
        TARGET_ENTITY_ID: 0xD60, // 3424 dec - Likely the 64-bit unique ID of the target entity (uint64) - NEEDS VERIFICATION
        TARGET_POS_DATA: 0x610   // 1552 dec - Pointer to position/transform data (pointer) - NEEDS VERIFICATION
    };
    console.log(`[${SCRIPT_NAME}] Using Offsets: ${JSON.stringify(OFFSETS, (k, v) => typeof v === 'number' ? '0x' + v.toString(16) : v)}`);


    // --- Quantum Drive State Enum (JavaScript Representation) ---
    const QuantumDriveState = {
        Off: 0, Idle: 1, Aligning: 2, Pre_Ramp_Up: 3, Ramp_Up: 4,
        Flight_In_Progress: 5, Ramp_Down: 6, Post_Ramp_Down: 7,
        End_Travel: 8, Abort: 9, Cooldown: 10, UNDEFINED: 99
    };
    console.log(`[${SCRIPT_NAME}] QuantumDriveState Enum defined.`);

    // Helper to get state name from enum value
    function GetStateName(stateValue) {
        for (const name in QuantumDriveState) {
            if (QuantumDriveState[name] === stateValue) {
                return name;
            }
        }
        return `UNKNOWN (${stateValue})`;
    }

    // --- Safe Memory Reading Helpers ---
    function safeReadPointer(ptr, offset) {
        try {
            return ptr.add(offset).readPointer();
        } catch (e) {
            // console.warn(`[SafeRead] Error reading pointer at offset 0x${offset.toString(16)}: ${e.message}`);
            return NULL; // Return Frida's NULL pointer
        }
    }

    function safeReadFloat(ptr, offset) {
        try {
            return ptr.add(offset).readFloat();
        } catch (e) {
            // console.warn(`[SafeRead] Error reading float at offset 0x${offset.toString(16)}: ${e.message}`);
            return NaN;
        }
    }

    function safeReadDouble(ptr, offset) {
        try {
            return ptr.add(offset).readDouble();
        } catch (e) {
            // console.warn(`[SafeRead] Error reading double at offset 0x${offset.toString(16)}: ${e.message}`);
            return NaN;
        }
    }

    function safeReadInt(ptr, offset, type = 'int32') { // type: 'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64'
        try {
            switch (type.toLowerCase()) {
                case 'int8': return ptr.add(offset).readS8();
                case 'uint8': return ptr.add(offset).readU8();
                case 'int16': return ptr.add(offset).readS16();
                case 'uint16': return ptr.add(offset).readU16();
                case 'int32': return ptr.add(offset).readS32();
                case 'uint32': return ptr.add(offset).readU32();
                case 'int64': return ptr.add(offset).readS64();
                case 'uint64': return ptr.add(offset).readU64();
                default: return ptr.add(offset).readS32(); // Default to int32
            }
        } catch (e) {
            // console.warn(`[SafeRead] Error reading ${type} at offset 0x${offset.toString(16)}: ${e.message}`);
            if (type.includes('64')) return null; // Return null for 64-bit types on error
            return NaN; // Return NaN for others
        }
    }

    function safeReadBool(ptr, offset) {
        return safeReadInt(ptr, offset, 'uint8') !== 0 && !isNaN(safeReadInt(ptr, offset, 'uint8'));
    }

    function formatHex(value) {
         if (value === null || typeof value === 'undefined') return 'null';
         if (typeof value === 'object' && value.isNull && value.isNull()) return '0x0'; // Handle Frida NULL pointer
         if (typeof value === 'object' && value.toUInt32) return '0x' + value.toUInt32().toString(16); // Handle Int64/UInt64
         if (typeof value === 'number') return '0x' + value.toString(16);
         if (typeof value === 'string' && value.startsWith('0x')) return value; // Already formatted pointer string
         return value.toString(); // Fallback
    }

    // --- Global variable to hold the pointer to the original function ---
    let originalSetStateFn = null;
    console.log(`[${SCRIPT_NAME}] Global 'originalSetStateFn' initialized to null.`);

    // --- Main Hooking Logic ---
    function applyHook() {
        const logPrefix = `[${SCRIPT_NAME} ApplyHook] `;
        console.log(`${logPrefix}Starting hook application...`);

        console.log(`${logPrefix}Searching for module: ${MODULE_NAME}`);
        const module = Process.findModuleByName(MODULE_NAME);
        if (!module) {
            console.error(`${logPrefix}Error: Module ${MODULE_NAME} not found. Script cannot proceed.`);
            return;
        }
        console.log(`${logPrefix}Module ${MODULE_NAME} found: Base=${module.base}, Size=${module.size}`);

        console.log(`${logPrefix}Scanning for SetState signature in module memory...`);
        let results;
        try {
            results = Memory.scanSync(module.base, module.size, quantumSig);
            console.log(`${logPrefix}Memory scan completed. Found ${results.length} potential match(es).`);
        } catch (scanError) {
            console.error(`${logPrefix}Error during memory scan: ${scanError}`);
            console.error(scanError.stack);
            return;
        }

        if (results.length === 0) {
            console.error(`${logPrefix}Error: SetState signature not found! Hook cannot be applied. Verify signature and game version.`);
            return;
        }
        if (results.length > 1) {
            console.warn(`${logPrefix}Warning: Found ${results.length} matches for the signature. Using the first one found at ${results[0].address}.`);
        }

        const targetAddr = results[0].address;
        console.log(`${logPrefix}Target SetState function identified at address: ${targetAddr}`);

        try {
            console.log(`${logPrefix}Attempting to create NativeFunction wrapper for original function at ${targetAddr}...`);
            originalSetStateFn = new NativeFunction(targetAddr, 'int64', ['pointer', 'uint32'], 'win64');
            console.log(`${logPrefix}NativeFunction wrapper created successfully.`);

            console.log(`${logPrefix}Attempting to create NativeCallback for replacement function...`);
            const replacementCallback = new NativeCallback((quantumDrivePtr, requestedStateInt) => {
                const detourLogPrefix = `[${SCRIPT_NAME} Detour] `;
                const dataLogPrefix = `[QD Data Snapshot @ ${quantumDrivePtr}] `;
                console.log(`\n${detourLogPrefix}========== Intercepted SetState Call ==========`);
                console.log(`${detourLogPrefix}Args: quantumDrivePtr=${quantumDrivePtr}, requestedStateInt=${requestedStateInt}`);

                let finalStateInt = requestedStateInt;
                let requestedState = QuantumDriveState.UNDEFINED;
                let finalState = QuantumDriveState.UNDEFINED;
                let isPartyQTSyncActive = false;
                let currentState = QuantumDriveState.UNDEFINED;

                try {
                    // --- State Conversion & Initial Logging ---
                    console.log(`${detourLogPrefix}Converting requestedStateInt (${requestedStateInt}) to enum...`);
                    if (Object.values(QuantumDriveState).includes(requestedStateInt)) {
                         requestedState = requestedStateInt;
                         console.log(`${detourLogPrefix}Converted to known state: ${GetStateName(requestedState)}`);
                    } else {
                         console.warn(`${detourLogPrefix}requestedStateInt (${requestedStateInt}) does not match a known QuantumDriveState enum value.`);
                         requestedState = QuantumDriveState.UNDEFINED;
                    }
                    finalState = requestedState;
                    finalStateInt = requestedStateInt;

                    // --- Detailed Data Logging ---
                    if (!quantumDrivePtr.isNull()) {
                        console.log(`${dataLogPrefix}--- Reading Component Data ---`);

                        // Current State (before potential change by original function)
                        try {
                            currentState = safeReadInt(quantumDrivePtr, OFFSETS.STATE, 'uint32');
                            console.log(`${dataLogPrefix}Current State (Offset 0x${OFFSETS.STATE.toString(16)}): ${GetStateName(currentState)} (${currentState})`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Current State: ${e.message}`); }

                        // Progress Indicators
                        try {
                            const spoolProg = safeReadFloat(quantumDrivePtr, OFFSETS.SPOOL_PROGRESS);
                            console.log(`${dataLogPrefix}Spool Progress (Offset 0x${OFFSETS.SPOOL_PROGRESS.toString(16)}): ${spoolProg.toFixed(4)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Spool Progress: ${e.message}`); }
                        try {
                            const alignProg = safeReadFloat(quantumDrivePtr, OFFSETS.ALIGN_PROGRESS);
                            console.log(`${dataLogPrefix}Align Progress/Error (Offset 0x${OFFSETS.ALIGN_PROGRESS.toString(16)}): ${alignProg.toFixed(4)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Align Progress: ${e.message}`); }
                        try {
                            const travelPct = safeReadFloat(quantumDrivePtr, OFFSETS.TRAVEL_COMPLETION_PCT);
                            console.log(`${dataLogPrefix}Travel Completion %% (Offset 0x${OFFSETS.TRAVEL_COMPLETION_PCT.toString(16)}): ${travelPct.toFixed(4)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Travel Completion %: ${e.message}`); }

                        // Flags
                        try {
                            const failFlags = safeReadInt(quantumDrivePtr, OFFSETS.FAILURE_FLAGS, 'uint32');
                            console.log(`${dataLogPrefix}Failure Flags (Offset 0x${OFFSETS.FAILURE_FLAGS.toString(16)}): ${formatHex(failFlags)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Failure Flags: ${e.message}`); }
                        try {
                            const statusFlags1 = safeReadInt(quantumDrivePtr, OFFSETS.STATUS_FLAGS_1, 'uint32'); // Assuming uint32 for safety
                            console.log(`${dataLogPrefix}Status Flags 1 (Offset 0x${OFFSETS.STATUS_FLAGS_1.toString(16)}): ${formatHex(statusFlags1)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Status Flags 1: ${e.message}`); }
                         try {
                            const statusFlags2 = safeReadInt(quantumDrivePtr, OFFSETS.STATUS_FLAGS_2, 'uint8');
                            console.log(`${dataLogPrefix}Status Flags 2 (Offset 0x${OFFSETS.STATUS_FLAGS_2.toString(16)}): ${formatHex(statusFlags2)}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Status Flags 2: ${e.message}`); }
                        try {
                            const splineValid = safeReadBool(quantumDrivePtr, OFFSETS.SPLINE_VALID_FLAG);
                            console.log(`${dataLogPrefix}Spline Valid Flag (Offset 0x${OFFSETS.SPLINE_VALID_FLAG.toString(16)}): ${splineValid}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Spline Valid Flag: ${e.message}`); }
                         try {
                            const isUpdating = safeReadBool(quantumDrivePtr, OFFSETS.IS_UPDATING_FLAG);
                            console.log(`${dataLogPrefix}IsUpdating Flag (Offset 0x${OFFSETS.IS_UPDATING_FLAG.toString(16)}): ${isUpdating}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading IsUpdating Flag: ${e.message}`); }

                        // --- NEW: Target Information Logging ---
                        console.log(`${dataLogPrefix}--- Target Data ---`);
                        try {
                            const targetHandlePtr = safeReadPointer(quantumDrivePtr, OFFSETS.TARGET_HANDLE);
                            console.log(`${dataLogPrefix}Target Handle/Ptr (Offset 0x${OFFSETS.TARGET_HANDLE.toString(16)}): ${targetHandlePtr}`);

                            if (!targetHandlePtr.isNull()) {
                                // Extract likely entity pointer (lower 48 bits)
                                // Note: NativePointer doesn't directly support bitwise AND with large masks easily.
                                // We might need to read as UInt64 and then process, or use CModule for precision.
                                // Simple approach (might lose precision on 32-bit Frida, but okay for logging):
                                try {
                                    const targetHandleVal = targetHandlePtr.toUInt32(); // Example, might need .readU64() + processing
                                    const entityPtrVal = targetHandleVal & 0xFFFFFFFFFFFF; // Conceptual - needs proper 64bit handling
                                    console.log(`${dataLogPrefix}  -> Extracted Entity Ptr (approx): 0x${entityPtrVal.toString(16)}`);

                                    // --- Advanced Target Info (Requires RE of Game Functions) ---
                                    // Placeholder: Find and call game functions using the entity pointer
                                    // const entityPtr = ptr("0x" + entityPtrVal.toString(16)); // Reconstruct pointer
                                    // try {
                                    //     // Example: Assuming GetEntityName(pointer) returns NativePointer to CString
                                    //     const getNameFunc = new NativeFunction(ptr("0xGAME_GETNAME_ADDR"), 'pointer', ['pointer']);
                                    //     const namePtr = getNameFunc(entityPtr);
                                    //     console.log(`${dataLogPrefix}  -> Target Name (RE Required): ${namePtr.readCString()}`);
                                    // } catch (nameErr) { console.warn(`${dataLogPrefix}  -> Failed to get Target Name: ${nameErr.message}`); }
                                    //
                                    // try {
                                    //     // Example: Assuming GetEntityClassName(pointer) returns NativePointer to CString
                                    //     const getClassNameFunc = new NativeFunction(ptr("0xGAME_GETCLASS_ADDR"), 'pointer', ['pointer']);
                                    //     const classNamePtr = getClassNameFunc(entityPtr);
                                    //     console.log(`${dataLogPrefix}  -> Target Class Name (RE Required): ${classNamePtr.readCString()}`);
                                    // } catch (classErr) { console.warn(`${dataLogPrefix}  -> Failed to get Target Class Name: ${classErr.message}`); }
                                    // --- End Advanced Target Info ---

                                } catch (ptrConvErr) { console.warn(`${dataLogPrefix}  -> Error processing target handle value: ${ptrConvErr.message}`); }
                            }
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Target Handle: ${e.message}`); }

                        try {
                            const targetTypeAddr = quantumDrivePtr.add(OFFSETS.TARGET_TYPE);
                            console.log(`${dataLogPrefix}  Attempting readU32 from address: ${targetTypeAddr}`);
                            const targetType = targetTypeAddr.readU32(); // Assuming uint32
                            console.log(`${dataLogPrefix}Target Type Enum (Offset 0x${OFFSETS.TARGET_TYPE.toString(16)}): ${targetType} (Meaning RE Required)`);
                        } catch (e) {
                            console.error(`${dataLogPrefix}Error reading Target Type at offset 0x${OFFSETS.TARGET_TYPE.toString(16)}: ${e.message}`);
                            console.error(e.stack);
                        }
    
                        try {
                            const targetEntityIdAddr = quantumDrivePtr.add(OFFSETS.TARGET_ENTITY_ID);
                            console.log(`${dataLogPrefix}  Attempting readU64 from address: ${targetEntityIdAddr}`);
                            const targetEntityId = targetEntityIdAddr.readU64(); // Read as UInt64 object
                            console.log(`${dataLogPrefix}Target Entity ID (Offset 0x${OFFSETS.TARGET_ENTITY_ID.toString(16)}): ${targetEntityId.toString()}`);
                        } catch (e) {
                            console.error(`${dataLogPrefix}Error reading Target Entity ID at offset 0x${OFFSETS.TARGET_ENTITY_ID.toString(16)}: ${e.message}`);
                            console.error(e.stack);
                        }

                        try {
                            const targetPosPtrAddr = quantumDrivePtr.add(OFFSETS.TARGET_POS_DATA);
                            console.log(`${dataLogPrefix}  Attempting readPointer from address: ${targetPosPtrAddr}`);
                            const targetPosPtr = targetPosPtrAddr.readPointer(); // Use direct read here for clarity
                            console.log(`${dataLogPrefix}Target Pos Data Ptr (Offset 0x${OFFSETS.TARGET_POS_DATA.toString(16)}): ${targetPosPtr}`);
    
                            if (!targetPosPtr.isNull()) {
                                // Basic sanity check (adjust range as needed for the game)
                                const ptrVal = targetPosPtr.toUInt32(); // Use toUInt32 for simple range check, aware of limitations
                                if (ptrVal > 0x10000 && ptrVal < 0x7FFFFFFFFFFF) { // Very basic user-space check
                                    console.log(`${dataLogPrefix}  -> Pointer seems potentially valid. Attempting to read Vec3...`);
                                    try {
                                        const x = targetPosPtr.readFloat();
                                        const y = targetPosPtr.add(4).readFloat();
                                        const z = targetPosPtr.add(8).readFloat();
                                        console.log(`${dataLogPrefix}  -> Target Pos (X,Y,Z - Inferred): ${x.toFixed(2)}, ${y.toFixed(2)}, ${z.toFixed(2)}`);
                                    } catch (posReadErr) {
                                        console.warn(`${dataLogPrefix}  -> Failed to read Vec3 from Target Pos Ptr: ${posReadErr.message}`);
                                        // Optionally log raw bytes on failure
                                        try {
                                            console.log(`${dataLogPrefix}  -> Raw bytes @ ${targetPosPtr}: ${Memory.readByteArray(targetPosPtr, 16)}`);
                                        } catch (rawReadErr) { console.warn(`${dataLogPrefix}  -> Failed to read raw bytes: ${rawReadErr.message}`); }
                                    }
                                } else {
                                    console.warn(`${dataLogPrefix}  -> Pointer value ${targetPosPtr} seems outside expected user-space range. Not attempting dereference.`);
                                }
                            } else {
                                 console.log(`${dataLogPrefix}  -> Target Pos Data Ptr is NULL.`);
                            }
                        } catch (e) {
                            console.error(`${dataLogPrefix}Error reading Target Pos Data Ptr at offset 0x${OFFSETS.TARGET_POS_DATA.toString(16)}: ${e.message}`);
                            console.error(e.stack);
                        }

                        console.log(`${dataLogPrefix}--- End Target Data ---`);
                        // --- End Target Information Logging ---

                        // Pointers / Handles
                        try {
                            const travelEnvelope = safeReadPointer(quantumDrivePtr, OFFSETS.TRAVEL_ENVELOPE);
                            console.log(`${dataLogPrefix}Travel Envelope Ptr (Offset 0x${OFFSETS.TRAVEL_ENVELOPE.toString(16)}): ${travelEnvelope}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Travel Envelope Ptr: ${e.message}`); }
                        try {
                            const activeSpline = safeReadPointer(quantumDrivePtr, OFFSETS.ACTIVE_SPLINE);
                            console.log(`${dataLogPrefix}Active Spline Ptr (Offset 0x${OFFSETS.ACTIVE_SPLINE.toString(16)}): ${activeSpline}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Active Spline Ptr: ${e.message}`); }
                        try {
                            const splineDataPtr = safeReadPointer(quantumDrivePtr, OFFSETS.SPLINE_DATA_PTR);
                            console.log(`${dataLogPrefix}Spline Data Ptr (Offset 0x${OFFSETS.SPLINE_DATA_PTR.toString(16)}): ${splineDataPtr}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Spline Data Ptr: ${e.message}`); }
                        try {
                            const interdictionSrc = safeReadPointer(quantumDrivePtr, OFFSETS.INTERDICTION_SOURCE);
                            console.log(`${dataLogPrefix}Interdiction Source (Offset 0x${OFFSETS.INTERDICTION_SOURCE.toString(16)}): ${interdictionSrc}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Interdiction Source: ${e.message}`); }
                         try {
                            const interdictorHdl = safeReadPointer(quantumDrivePtr, OFFSETS.INTERDICTOR_HANDLE);
                            console.log(`${dataLogPrefix}Interdictor Handle (Offset 0x${OFFSETS.INTERDICTOR_HANDLE.toString(16)}): ${interdictorHdl}`);
                        } catch (e) { console.error(`${dataLogPrefix}Error reading Interdictor Handle: ${e.message}`); }

                        console.log(`${dataLogPrefix}--- End Component Data ---`);
                    } else {
                        console.warn(`${dataLogPrefix}quantumDrivePtr is NULL, skipping detailed data logging.`);
                    }
                    // --- End Detailed Data Logging ---


                    // --- Party Detection Logic (Same as before, with logging) ---
                    console.log(`${detourLogPrefix}Performing party detection...`);
                    if (!quantumDrivePtr.isNull()) {
                        try {
                            const partyListBeginAddr = quantumDrivePtr.add(OFFSETS.PARTY_LIST_BEGIN);
                            const partyListEndAddr = quantumDrivePtr.add(OFFSETS.PARTY_LIST_END);
                            // console.log(`${detourLogPrefix}  Reading party list begin pointer from: ${partyListBeginAddr}`);
                            const partyListBeginPtr = partyListBeginAddr.readPointer();
                            // console.log(`${detourLogPrefix}  Party List Begin Ptr Value: ${partyListBeginPtr}`);
                            // console.log(`${detourLogPrefix}  Reading party list end pointer from: ${partyListEndAddr}`);
                            const partyListEndPtr = partyListEndAddr.readPointer();
                            // console.log(`${detourLogPrefix}  Party List End Ptr Value: ${partyListEndPtr}`);
                            isPartyQTSyncActive = !partyListBeginPtr.equals(partyListEndPtr);
                            console.log(`${detourLogPrefix}  Party Check Result: Begin=${partyListBeginPtr}, End=${partyListEndPtr}, PartyActive=${isPartyQTSyncActive}`);
                        } catch (memError) {
                            console.error(`${detourLogPrefix}Memory access error during party check for Ptr ${quantumDrivePtr}: ${memError.message}`);
                            isPartyQTSyncActive = true; // Fail-safe
                            console.warn(`${detourLogPrefix}Assuming party might be active due to error (fail-safe).`);
                        }
                    } else {
                        isPartyQTSyncActive = true; // Fail-safe
                    }
                    console.log(`${detourLogPrefix}Party detection complete. isPartyQTSyncActive = ${isPartyQTSyncActive}`);
                    // --- End Party Detection ---


                    // --- Conditional State Skipping (Same as before, with logging) ---
                    console.log(`${detourLogPrefix}Evaluating conditions for state skipping...`);
                    const isTargetState = (requestedState === QuantumDriveState.Aligning ||
                                           requestedState === QuantumDriveState.Pre_Ramp_Up ||
                                           requestedState === QuantumDriveState.Ramp_Up);
                    console.log(`${detourLogPrefix}  Is Requested State Aligning(2)/PreRampUp(3)/RampUp(4)? ${isTargetState}`);

                    if (ENABLE_QD_MOD && SKIP_SOLO_SPOOL_ALIGN && !isPartyQTSyncActive && isTargetState)
                    {
                        finalState = QuantumDriveState.Flight_In_Progress;
                        finalStateInt = QuantumDriveState.Flight_In_Progress;
                        console.log(`${detourLogPrefix}*** OVERRIDE TRIGGERED (Solo Play Detected) ***`);
                        console.log(`${detourLogPrefix}  Changing final state to: ${GetStateName(finalState)} (${finalStateInt})`);
                    } else {
                         if (isPartyQTSyncActive && isTargetState) {
                             console.log(`${detourLogPrefix}Override skipped: Party QT Sync detected.`);
                        } else if (!isTargetState) {
                             console.log(`${detourLogPrefix}Override skipped: Requested state (${GetStateName(requestedState)}) is not a target for skipping.`);
                        } else {
                             console.log(`${detourLogPrefix}Override skipped: Mod flags disabled.`);
                        }
                        console.log(`${detourLogPrefix}Proceeding with originally requested state: ${GetStateName(requestedState)} (${finalStateInt})`);
                    }
                    // --- End Conditional State Skipping ---


                    // --- Call Original Function ---
                    console.log(`${detourLogPrefix}Preparing to call original SetState function...`);
                    if (originalSetStateFn) {
                        console.log(`${detourLogPrefix}  Calling originalSetStateFn(Ptr: ${quantumDrivePtr}, State: ${finalStateInt})`);
                        let result;
                        try {
                            result = originalSetStateFn(quantumDrivePtr, finalStateInt);
                            console.log(`${detourLogPrefix}  Original function returned: ${result}`);
                            console.log(`${detourLogPrefix}========== SetState Call Complete ==========`);
                            return result;
                        } catch (callError) {
                            console.error(`${detourLogPrefix}Error calling original SetState function: ${callError.message}`);
                            console.error(callError.stack);
                            console.log(`${detourLogPrefix}========== SetState Call Failed ==========`);
                            return ptr(0);
                        }
                    } else {
                        console.error(`${detourLogPrefix}CRITICAL ERROR: originalSetStateFn pointer is null! Cannot call original function.`);
                        console.log(`${detourLogPrefix}========== SetState Call Failed ==========`);
                        return ptr(0);
                    }
                    // --- End Call Original Function ---

                } catch (e) {
                    console.error(`${detourLogPrefix}FATAL ERROR inside NativeCallback: ${e.message}`);
                    console.error(e.stack);
                    if (originalSetStateFn) {
                        try {
                            console.warn(`${detourLogPrefix}Attempting to call original function with *requested* state after error...`);
                            return originalSetStateFn(quantumDrivePtr, requestedStateInt);
                        } catch (e2) {
                            console.error(`${detourLogPrefix}Error calling original function during fallback: ${e2.message}`);
                        }
                    }
                    console.log(`${detourLogPrefix}========== SetState Call Failed Hard ==========`);
                    return ptr(0);
                }
            }, 'int64', ['pointer', 'uint32'], 'win64');
            console.log(`${logPrefix}NativeCallback created successfully.`);

            console.log(`${logPrefix}Applying Interceptor.replace to target address ${targetAddr}...`);
            Interceptor.replace(targetAddr, replacementCallback);
            console.log(`${logPrefix}Interceptor.replace applied successfully.`);
            console.log(`[${SCRIPT_NAME}] Hook is active. Monitoring Quantum Drive state changes with detailed logging.`);

        } catch (e) {
            console.error(`${logPrefix}Error during hook setup: ${e.message}`);
            console.error(e.stack);
            originalSetStateFn = null;
        }
    }

    // --- Script Entry Point ---
    const INITIALIZATION_DELAY_MS = 1000;
    console.log(`[${SCRIPT_NAME}] Scheduling hook application in ${INITIALIZATION_DELAY_MS}ms...`);
    setTimeout(applyHook, INITIALIZATION_DELAY_MS);

})(); // End of IIFE