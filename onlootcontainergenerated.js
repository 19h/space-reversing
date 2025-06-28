/*
 * Frida Script to Hook and Analyze sub_144776C30
 * Target Audience: Reverse Engineers
 * Description: This script hooks the function at 0x144776C30 in a 64-bit process.
 *              It intercepts calls to this function, extracts relevant parameters
 *              and computed values, and logs them in a structured format.
 *              It leverages knowledge derived from the provided decompiled C++ code.
 * Version: 1.3 - Fixed address calculation assuming provided values are absolute.
 *
 * Assumptions:
 * - Running on Windows x64.
 * - Frida is attached to the target process.
 * - The addresses provided in the configuration (TARGET_FUNCTION_ADDR, etc.)
 *   are ABSOLUTE addresses in the target process space.
 * - The structure offsets and function behaviors observed in the decompilation
 *   are accurate for the target binary.
 *
 * Key Functionality:
 * - Hooks the main function `sub_144776C30`.
 * - Extracts `ContainerId` from the second argument (`a2`).
 * - Iterates through the container/map passed via the third argument (`a3`)
 *   by calling the native function `sub_1402B30A0` to calculate `TotalItemCount`.
 *   Optionally collects details for `RefreshContents`.
 * - Hooks `sub_14474DA70` to intercept the call determining `locName`. It then
 *   calls the `AK::WriteBytesMem::Bytes` method to retrieve the name string.
 * - Reads the `locPos` (x, y, z) coordinates from the stack frame of
 *   `sub_144776C30` in `onLeave`, based on the observed stack layout in the
 *   decompilation (`dst` variable).
 * - Consolidates and logs all extracted information upon leaving `sub_144776C30`.
 */

'use strict';

(function() {

    // --- Configuration ---
    // ** IMPORTANT: These are assumed to be ABSOLUTE addresses **
    const MODULE_NAME_FOR_LOGGING = "StarCitizen.exe"; // Used for confirmation logging only
    const TARGET_FUNCTION_ADDR = 0x144776C30;

    // Absolute addresses of helper functions needed for analysis
    const ITERATE_MAP_NODE_ADDR = 0x1402B30A0; // sub_1402B30A0
    const GET_LOC_NAME_ADDR = 0x14474DA70;     // sub_14474DA70
    const GET_BYTES_METHOD_ADDR = 0x1402A1E80; // ?Bytes@WriteBytesMem@AK@@UEBAPEAEXZ

    // Offset of the 'dst' variable (holding locPos x,y,z) relative to RBP
    // Found by analyzing the stack frame layout in the decompilation of sub_144776C30
    // _QWORD dst[3]; // [rsp+F0h] [rbp-278h] BYREF -> offset is 0x278 from RBP
    const LOCPOS_DST_RBP_OFFSET = 0x278;

    // --- End Configuration ---

    // --- Globals & Helper Functions ---
    let moduleBaseForLogging = ptr(0); // Only for logging confirmation
    let targetFunctionAddr = ptr(0);
    let iterateMapNodeFunc = null;
    let getLocNameAddr = ptr(0);
    let getBytesMethodFunc = null;

    // Global store for communication between hooks (keyed by threadId)
    if (typeof global.locNameStore === 'undefined') {
        global.locNameStore = {};
    }


    /**
     * Initializes function pointers/addresses using the configured ABSOLUTE addresses.
     * Optionally logs the detected module base for confirmation.
     * @returns {boolean} True if successful, false otherwise.
     */
    function initializeAddresses() {
        // --- Use configured addresses directly ---
        targetFunctionAddr = ptr(TARGET_FUNCTION_ADDR);
        const iterateMapNodeAddrResolved = ptr(ITERATE_MAP_NODE_ADDR);
        getLocNameAddr = ptr(GET_LOC_NAME_ADDR);
        const getBytesMethodAddrResolved = ptr(GET_BYTES_METHOD_ADDR);

        console.log(`[*] Using configured ABSOLUTE addresses:`);
        console.log(`    Target function (sub_144776C30): ${targetFunctionAddr}`);
        console.log(`    Helper iterateMapNode (sub_1402B30A0): ${iterateMapNodeAddrResolved}`);
        console.log(`    Helper getLocName (sub_14474DA70): ${getLocNameAddr}`);
        console.log(`    Helper getBytesMethod (?Bytes@...): ${getBytesMethodAddrResolved}`);

        // --- Optional: Log detected module base for confirmation ---
        try {
            const targetModule = Process.findModuleByAddress(targetFunctionAddr);
            if (targetModule) {
                moduleBaseForLogging = targetModule.base;
                console.log(`[*] CONFIRMATION: Target address ${targetFunctionAddr} is within module "${targetModule.name}" (Base: ${targetModule.base}, Size: 0x${targetModule.size.toString(16)})`);
                // Check if the detected base matches the implicit base of our addresses (heuristic)
                const implicitBase = targetFunctionAddr.and(ptr("0xFFFFFFFFFFF00000")); // Rough estimate
                if (!targetModule.base.equals(implicitBase) && targetModule.base.toString().startsWith("0x14")) {
                     // If the detected base isn't 0x14... but our addresses are, it's a strong sign they were absolute rebased addresses.
                     console.warn(`[!] Detected module base ${targetModule.base} differs from the implicit base of configured addresses (around ${implicitBase}). Using configured absolute addresses.`);
                } else if (targetModule.base.toString(16).toUpperCase().startsWith(MODULE_NAME_FOR_LOGGING.split('.')[0].toUpperCase())) {
                     // Or if base matches module name prefix (less reliable)
                     console.log(`[*] Detected module base seems consistent with configured addresses.`);
                }
            } else {
                console.warn(`[!] Could not find a loaded module containing the target address ${targetFunctionAddr}. Proceeding with the absolute address.`);
            }
        } catch (e) {
            console.warn(`[!] Error during module confirmation check: ${e.message}`);
        }
        // --- End Optional Logging ---


        // --- Create NativeFunction wrappers ---
        try {
            // __int64* __fastcall sub_1402B30A0(__int64 *a1)
            iterateMapNodeFunc = new NativeFunction(
                iterateMapNodeAddrResolved,
                'pointer', // Returns pointer to the node structure (__int64 *) in rax
                ['pointer'], // Takes pointer to pointer to node (__int64 *)
                'win64' // Assuming default Windows x64 ABI
            );

            // unsigned __int8 *__fastcall AK::WriteBytesMem::Bytes(AK::WriteBytesMem *this)
            getBytesMethodFunc = new NativeFunction(
                getBytesMethodAddrResolved,
                'pointer', // Returns pointer to unsigned __int8 (char*)
                ['pointer'], // Takes 'this' pointer (AK::WriteBytesMem *)
                'win64'
            );

            // Basic validation
            if (!targetFunctionAddr || targetFunctionAddr.isNull() ||
                !iterateMapNodeFunc ||
                !getLocNameAddr || getLocNameAddr.isNull() ||
                !getBytesMethodFunc) {
                throw new Error("One or more functions failed to resolve or initialize from configured addresses.");
            }

            return true;

        } catch (e) {
           console.error(`[!] Error creating NativeFunction objects: ${e}`);
           console.error(`    Check if the configured absolute addresses are correct and accessible.`);
           return false;
        }
    }

    /**
     * Safely reads a C string from a pointer.
     * @param {NativePointer} ptr Address of the string.
     * @param {number} [maxLength=1024] Optional max length to read.
     * @returns {string | null} The string or null if pointer is invalid.
     */
    function readCStringSafe(ptr, maxLength = 1024) {
        if (!ptr || ptr.isNull()) {
            return null;
        }
        try {
            // Check readability first
            Memory.protect(ptr, 1, 'r--'); // Check at least 1 byte
            return ptr.readCString(maxLength);
        } catch (e) {
            // Try reading as UTF8 as a fallback
            try {
                Memory.protect(ptr, 1, 'r--');
                return ptr.readUtf8String(maxLength);
            } catch (e2) {
                 console.error(`[!] Error reading string at ${ptr}: ${e.message} / ${e2.message}`);
                 return "[!] Error reading string";
            }
        }
    }

    /**
     * Safely reads a U64 value from a pointer.
     * @param {NativePointer} ptr Address of the U64.
     * @returns {UInt64 | string} The U64 value or an error string.
     */
    function readU64Safe(ptr) {
        if (!ptr || ptr.isNull()) {
            return "[!] Invalid pointer";
        }
        try {
            // Ensure the pointer is valid before reading
            Memory.protect(ptr, 8, 'r--'); // Check readability, size 8 for U64
            return ptr.readU64();
        } catch (e) {
             console.error(`[!] Error reading U64 at ${ptr}: ${e.message}`);
            return "[!] Error reading U64";
        }
    }

     /**
     * Safely reads a double value from a pointer.
     * @param {NativePointer} ptr Address of the double.
     * @returns {number | string} The double value or an error string.
     */
    function readDoubleSafe(ptr) {
        if (!ptr || ptr.isNull()) {
            return "[!] Invalid pointer";
        }
        try {
             Memory.protect(ptr, 8, 'r--'); // Check readability, size 8 for double
            return ptr.readDouble();
        } catch (e) {
             console.error(`[!] Error reading double at ${ptr}: ${e.message}`);
            return "[!] Error reading double";
        }
    }

    // --- Hooking Logic ---

    /**
     * Hook for sub_14474DA70 to capture the location name.
     * Uses the address directly for Interceptor.attach.
     */
    function attachGetLocNameHook() {
        if (!getLocNameAddr || getLocNameAddr.isNull()) {
            console.error("[!] Cannot attach hook: getLocNameAddr is invalid.");
            return;
        }
         if (!getBytesMethodFunc) {
             console.error("[!] Cannot attach hook: getBytesMethodFunc is not initialized.");
             return;
         }

        console.log(`[*] Attaching hook to getLocName (sub_14474DA70) address: ${getLocNameAddr}`);
        try {
            Interceptor.attach(getLocNameAddr, {
                onEnter: function(args) {
                    // Store the pointer to the ContainerId (_QWORD* a2 from the caller)
                    // which is the 3rd argument (a3) to sub_14474DA70.
                    this.caller_a2_ptr = args[2]; // ContainerId*
                    // The actual result object is passed as the second argument (a2)
                    // and also returned by the function. Let's capture it here.
                    // This is the pointer to the structure initialized by sub_1402A0CB0
                    // In sub_144776C30, this is the `v34` buffer on the stack.
                    this.resultObjectPtr = args[1];
                },
                onLeave: function(retval) {
                    // retval should be the same pointer as args[1] (this.resultObjectPtr)
                    const resultObj = retval;

                    if (getBytesMethodFunc && resultObj && !resultObj.isNull()) {
                        try {
                            // Call the virtual function ?Bytes@WriteBytesMem@AK@@UEBAPEAEXZ
                            // The actual implementation address is GET_BYTES_METHOD_ADDR (0x1402A1E80)
                            // We call it directly using the NativeFunction wrapper.
                            const bytesPtr = getBytesMethodFunc(resultObj); // Call Bytes(resultObj)

                            const locName = readCStringSafe(bytesPtr);

                            const threadId = this.threadId;
                            global.locNameStore[threadId] = locName;
                            // console.log(`[*] [TID: ${threadId}] Captured locName: ${locName}`);

                        } catch (e) {
                            console.error(`[!] Error calling Bytes() method or reading locName in TID ${this.threadId}: ${e}`);
                            const threadId = this.threadId;
                            global.locNameStore[threadId] = "[!] Error retrieving locName";
                        }
                    } else {
                         const threadId = this.threadId;
                         global.locNameStore[threadId] = "[!] Invalid result object or getBytesMethodFunc";
                         if (!getBytesMethodFunc) console.warn("getBytesMethodFunc was null");
                         if (!resultObj) console.warn("resultObj was null");
                         else if (resultObj.isNull()) console.warn("resultObj was null pointer");
                    }
                }
            });
             console.log(`[*] Successfully attached hook to getLocName address ${getLocNameAddr}`);
        } catch(e) {
             console.error(`[!] Failed to attach hook to getLocName address ${getLocNameAddr}: ${e}`);
             console.error(e.stack); // Print stack trace for attach failure
        }
    }


    /**
     * Main hook for sub_144776C30.
     */
    function attachMainHook() {
        if (!targetFunctionAddr || targetFunctionAddr.isNull()) {
             console.error("[!] Cannot attach hook: targetFunctionAddr is invalid.");
            return;
        }
        if (!iterateMapNodeFunc) {
            console.error("[!] Cannot attach hook: iterateMapNodeFunc is not initialized.");
            return;
        }

        console.log(`[*] Attaching hook to target function sub_144776C30 at ${targetFunctionAddr}`);

        try {
            Interceptor.attach(targetFunctionAddr, {
                onEnter: function(args) {
                    this.startTime = new Date().getTime();
                    this.threadId = this.threadId;
                    this.rbp = this.context.rbp;
                    this.a1_context = args[0];
                    this.a2_containerIdPtr = args[1];
                    this.a3_mapHandlePtr = args[2];

                    if (global.locNameStore && global.locNameStore[this.threadId]) {
                        delete global.locNameStore[this.threadId];
                    }

                    this.hookData = {
                        contextPtr: this.a1_context,
                        containerId: "[Reading...]",
                        totalItemCount: 0,
                        refreshContentsDetails: [],
                        locName: "[Waiting...]",
                        locPosX: NaN,
                        locPosY: NaN,
                        locPosZ: NaN,
                        stackReadSuccess: false
                    };

                    // --- Extract ContainerId ---
                    try {
                        if (this.a2_containerIdPtr && !this.a2_containerIdPtr.isNull()) {
                            this.hookData.containerId = readU64Safe(this.a2_containerIdPtr);
                        } else {
                            this.hookData.containerId = "[!] Invalid pointer (a2)";
                        }
                    } catch (e) {
                        this.hookData.containerId = `[!] Error reading ContainerId: ${e}`;
                    }

                    // --- Calculate TotalItemCount ---
                    let currentMapNodePtrPtr = this.a3_mapHandlePtr;
                    if (iterateMapNodeFunc && currentMapNodePtrPtr && !currentMapNodePtrPtr.isNull()) {
                        try {
                            let mapHandle = currentMapNodePtrPtr.readPointer();
                            if (mapHandle && !mapHandle.isNull()) {
                                let currentNodePtrContainer = Memory.alloc(Process.pointerSize);
                                currentNodePtrContainer.writePointer(mapHandle.readPointer());
                                let nodeAddress = currentNodePtrContainer.readPointer();
                                let iterationCount = 0;
                                const maxIterations = 10000;

                                while (nodeAddress && !nodeAddress.isNull() && iterationCount < maxIterations) {
                                    let breakConditionByte;
                                    try {
                                        Memory.protect(nodeAddress.add(25), 1, 'r--');
                                        breakConditionByte = nodeAddress.add(25).readU8();
                                    } catch (e) {
                                        console.warn(`[!] Error reading node break condition byte at ${nodeAddress.add(25)} (Node: ${nodeAddress}). Stopping iteration. Error: ${e.message}`);
                                        break;
                                    }
                                    if (breakConditionByte !== 0) break;

                                    try {
                                        Memory.protect(nodeAddress.add(48), 4, 'r--');
                                        let itemCount = nodeAddress.add(48).readU32();
                                        this.hookData.totalItemCount += itemCount;
                                    } catch (e) {
                                        console.error(`[!] Error reading item count/data at node ${nodeAddress}: ${e.message}`);
                                        break;
                                    }

                                    try {
                                        iterateMapNodeFunc(currentNodePtrContainer);
                                        nodeAddress = currentNodePtrContainer.readPointer();
                                    } catch (e) {
                                        console.error(`[!] Error calling iterateMapNodeFunc: ${e.message}`);
                                        break;
                                    }
                                    iterationCount++;
                                }
                                if (iterationCount >= maxIterations) {
                                     console.warn(`[!] Map iteration exceeded max iterations (${maxIterations}). Result might be incomplete.`);
                                }
                            } else {
                                 console.warn(`[!] Map handle (*a3) is null or points to null.`);
                                 this.hookData.totalItemCount = "[!] Invalid map handle";
                            }
                        } catch (e) {
                            console.error(`[!] Error iterating map/container: ${e}`);
                            this.hookData.totalItemCount = "[!] Iteration Error";
                        }
                    } else {
                        this.hookData.totalItemCount = "[!] Cannot iterate map (invalid args or helper func)";
                    }
                }, // End onEnter

                onLeave: function(retval) {
                    const duration = new Date().getTime() - this.startTime;

                    // --- Retrieve Captured locName ---
                    if (global.locNameStore && typeof global.locNameStore[this.threadId] !== 'undefined') {
                        this.hookData.locName = global.locNameStore[this.threadId];
                        delete global.locNameStore[this.threadId];
                    } else {
                        this.hookData.locName = "[!] Not captured";
                    }

                    // --- Extract locPos (x, y, z) from stack ---
                    try {
                        if (this.rbp && !this.rbp.isNull()) {
                            const dstStackPtr = this.rbp.sub(LOCPOS_DST_RBP_OFFSET);
                            this.hookData.locPosX = readDoubleSafe(dstStackPtr);
                            this.hookData.locPosY = readDoubleSafe(dstStackPtr.add(8));
                            this.hookData.locPosZ = readDoubleSafe(dstStackPtr.add(16));
                            this.hookData.stackReadSuccess = true;
                        } else {
                            throw new Error("RBP not captured or invalid");
                        }
                    } catch (e) {
                        console.error(`[!] Error reading locPos from stack (RBP: ${this.rbp}, Offset: ${LOCPOS_DST_RBP_OFFSET}): ${e.message}`);
                        this.hookData.locPosX = "[!] Stack Read Error";
                        this.hookData.locPosY = "[!] Stack Read Error";
                        this.hookData.locPosZ = "[!] Stack Read Error";
                        this.hookData.stackReadSuccess = false;
                    }

                    // --- Log Collected Data ---
                    console.log("============================================================");
                    console.log(`[+] Hooked sub_144776C30 Finished (TID: ${this.threadId}, Duration: ${duration}ms)`);
                    console.log(`    Context Ptr (a1):       ${this.hookData.contextPtr}`);
                    console.log(`    ContainerId Ptr (a2):   ${this.a2_containerIdPtr}`);
                    console.log(`    ContainerId Value:      ${this.hookData.containerId}`);
                    console.log(`    Map Handle Ptr (a3):    ${this.a3_mapHandlePtr}`);
                    console.log(`    TotalItemCount:         ${this.hookData.totalItemCount}`);
                    console.log(`    locName (from hook):    ${this.hookData.locName}`);
                    console.log(`    locPos Stack Addr:      ${this.hookData.stackReadSuccess ? this.rbp.sub(LOCPOS_DST_RBP_OFFSET) : '[N/A]'}`);
                    console.log(`    locPos.x (from stack):  ${this.hookData.locPosX}`);
                    console.log(`    locPos.y (from stack):  ${this.hookData.locPosY}`);
                    console.log(`    locPos.z (from stack):  ${this.hookData.locPosZ}`);
                    console.log("============================================================");

                } // End onLeave
            });
             console.log(`[*] Successfully attached hook to target function ${targetFunctionAddr}`);
        } catch (e) {
            console.error(`[!] Failed to attach hook to target function ${targetFunctionAddr}: ${e}`);
            console.error(e.stack); // Print stack trace for attach failure
        }
    }

    // --- Main Execution ---
    console.log("[*] Starting Frida script for sub_144776C30...");

    if (!Process.pointerSize) {
        console.error("[!] Failed to get Process.pointerSize. Is Frida attached?");
        return;
    }

    setImmediate(() => {
        console.log("[*] Initialization starting...");
        if (initializeAddresses()) {
            console.log("[*] Initialization complete. Attaching hooks...");
            attachGetLocNameHook();
            attachMainHook();
            console.log("[*] Hook attachment process finished. Waiting for calls...");
        } else {
            console.error("[!] Initialization failed. Hooks not attached.");
        }
    });

})();
