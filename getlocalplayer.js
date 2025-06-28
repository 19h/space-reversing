// --- Helper Functions (from previous script, slightly adapted) ---
function getProtection(address, context = "") {
    try {
        if (!address || address.isNull()) return `${context}N/A (NULL Address)`;
        const range = Process.findRangeByAddress(address);
        return range ? `${context}Protection: ${range.protection}` : `${context}Protection: N/A (No Range)`;
    } catch (e) {
        return `${context}Protection Error: ${e.message}`;
    }
}

function getModuleInfo(address, context = "") {
    if (!address || address.isNull()) {
        return `${context}Address is NULL.`;
    }
    const mod = Process.findModuleByAddress(address);
    if (mod) {
        return `${context}Address ${address} in module: ${mod.name} (Base: ${mod.base}, Size: ${mod.size}, Path: ${mod.path})`;
    }
    const range = Process.findRangeByAddress(address);
    if (range) {
         return `${context}Address ${address} in memory range: ${range.base} - ${range.base.add(range.size)} (Protection: ${range.protection}, File: ${range.file ? range.file.path : 'N/A'})`;
    }
    return `${context}Address ${address} not in any known module or mapped range.`;
}

function hexdumpSafe(address, length = 32, context = "") {
    if (!address || address.isNull()) {
        return `${context}Cannot hexdump NULL address.`;
    }
    try {
        let dump = `${context}Hexdump of ${address} (${getProtection(address)} Length: ${length}):\n`;
        dump += hexdump(address, { length: length, header: true, ansi: false });
        return dump;
    } catch (e) {
        return `${context}Error hexdumping ${address}: ${e.message}`;
    }
}

// --- Main Function ---
function getLocalPlayerAddressVTablePoll(maxRetries = 15, retryDelayMs = 1000, vtablePollRetries = 10, vtablePollDelayMs = 200) {
    const SCRIPT_NAME = "GetLocalPlayerFridaVTablePoll";
    console.log(`\n[${SCRIPT_NAME}] ======================================================================`);
    console.log(`[${SCRIPT_NAME}] Starting attempt with VTable polling...`);
    console.log(`[${SCRIPT_NAME}] Max Retries (Overall): ${maxRetries}, Delay: ${retryDelayMs}ms`);
    console.log(`[${SCRIPT_NAME}] Max Retries (VTable Poll): ${vtablePollRetries}, Delay: ${vtablePollDelayMs}ms`);
    console.log(`[${SCRIPT_NAME}] ======================================================================`);

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        console.log(`\n[${SCRIPT_NAME}] ---------- Overall Attempt #${attempt} / ${maxRetries} ----------`);
        try {
            const objectInstanceAddress = ptr('0x149B4FBE0').add(0xA0);
            console.log(`[${SCRIPT_NAME}] 1. Object Instance Address: ${objectInstanceAddress} (${getModuleInfo(objectInstanceAddress)})`);
            console.log(hexdumpSafe(objectInstanceAddress, 16, `   Content at instance: `));

            if (objectInstanceAddress.isNull()) {
                console.error(`[${SCRIPT_NAME}] CRITICAL: objectInstanceAddress is NULL.`);
                if (attempt === maxRetries) return NULL;
                Thread.sleep(retryDelayMs / 1000); continue;
            }

            const vtableAddress = objectInstanceAddress.readPointer();
            console.log(`[${SCRIPT_NAME}] 2. VTable Address read: ${vtableAddress} (${getModuleInfo(vtableAddress, "VTable ")})`);
            console.log(hexdumpSafe(vtableAddress, 16, `   Content at VTable base: `));


            if (vtableAddress.isNull()) {
                console.error(`[${SCRIPT_NAME}] ERROR: VTable Address is NULL.`);
                if (attempt === maxRetries) return NULL;
                Thread.sleep(retryDelayMs / 1000); continue;
            }

            const getPlayerFuncVTableOffset = 0x120;
            const getPlayerFuncSlotAddress = vtableAddress.add(getPlayerFuncVTableOffset);
            console.log(`[${SCRIPT_NAME}] 3. Target VTable Slot Address: ${getPlayerFuncSlotAddress} (${getProtection(getPlayerFuncSlotAddress, "Slot ")})`);
            console.log(hexdumpSafe(getPlayerFuncSlotAddress, Process.pointerSize * 3, `   Content at/around slot: `));


            let getPlayerFuncTargetAddress = NULL;

            // Poll the VTable slot specifically
            for (let pollAttempt = 1; pollAttempt <= vtablePollRetries; pollAttempt++) {
                console.log(`[${SCRIPT_NAME}]    VTable Slot Poll Attempt #${pollAttempt} / ${vtablePollRetries} for slot ${getPlayerFuncSlotAddress}`);
                try {
                    getPlayerFuncTargetAddress = getPlayerFuncSlotAddress.readPointer();
                    console.log(`[${SCRIPT_NAME}]    Slot ${getPlayerFuncSlotAddress} content: ${getPlayerFuncTargetAddress}`);
                    if (!getPlayerFuncTargetAddress.isNull()) {
                        console.log(`[${SCRIPT_NAME}]    SUCCESS: VTable slot ${getPlayerFuncSlotAddress} now contains non-NULL value: ${getPlayerFuncTargetAddress}`);
                        break; // Exit poll loop
                    }
                } catch (readErr) {
                     console.warn(`[${SCRIPT_NAME}]    WARNING: Error reading VTable slot ${getPlayerFuncSlotAddress} during poll: ${readErr.message}. This might indicate the VTable memory itself became invalid.`);
                     // We might want to break the outer loop too if the vtable address itself becomes invalid.
                }

                if (pollAttempt === vtablePollRetries) {
                    console.warn(`[${SCRIPT_NAME}]    Max VTable slot poll retries reached. Slot still NULL or unreadable.`);
                    break; // Exit poll loop, will be caught by outer NULL check
                }
                Thread.sleep(vtablePollDelayMs / 1000);
            }

            if (getPlayerFuncTargetAddress.isNull()) {
                console.warn(`[${SCRIPT_NAME}] WARNING (Overall Attempt ${attempt}): Failed to get non-NULL getPlayerFunc address from VTable slot ${getPlayerFuncSlotAddress} after polling.`);
                if (attempt === maxRetries) {
                    console.error(`[${SCRIPT_NAME}] Max overall retries reached. Failed to get function pointer.`);
                    return NULL;
                }
                Thread.sleep(retryDelayMs / 1000);
                continue; // Go to next overall attempt
            }

            console.log(`[${SCRIPT_NAME}] 4. Acquired getPlayerFunc Target Address: ${getPlayerFuncTargetAddress} (${getModuleInfo(getPlayerFuncTargetAddress, "FuncTarget ")})`);
            console.log(hexdumpSafe(getPlayerFuncTargetAddress, 32, `   Content at FuncTarget: `));

            const getPlayerFunc = new NativeFunction(
                getPlayerFuncTargetAddress,
                'void', ['pointer', 'pointer', 'int64'], 'win64'
            );
            console.log(`[${SCRIPT_NAME}] 5. NativeFunction created.`);

            const outPlayerPtrStorage = Memory.alloc(Process.pointerSize);
            console.log(`[${SCRIPT_NAME}] 6. Allocated output storage: ${outPlayerPtrStorage}`);

            console.log(`[${SCRIPT_NAME}] 7. Calling getPlayerFunc(${objectInstanceAddress}, ${outPlayerPtrStorage}, 0)...`);
            getPlayerFunc(objectInstanceAddress, outPlayerPtrStorage, int64(0));
            console.log(`[${SCRIPT_NAME}]    Call completed.`);

            const localPlayerAddress = outPlayerPtrStorage.readPointer();
            console.log(`[${SCRIPT_NAME}] 8. Read from output storage: ${localPlayerAddress}`);

            if (localPlayerAddress.isNull()) {
                console.warn(`[${SCRIPT_NAME}] (Attempt ${attempt}) getPlayerFunc returned NULL player pointer.`);
                return NULL;
            }

            console.log(`[+] SUCCESS (Attempt ${attempt}): Local player address: ${localPlayerAddress} (${getModuleInfo(localPlayerAddress, "PlayerObj ")})`);
            return localPlayerAddress;

        } catch (e) {
            console.error(`[!] ${SCRIPT_NAME} EXCEPTION (Overall Attempt ${attempt}): ${e.message}`);
            if (e.stack) console.error(`[!] Stack: ${e.stack}`);
            if (attempt === maxRetries) {
                console.error(`[${SCRIPT_NAME}] Max overall retries reached. Aborting due to exception.`);
                return NULL;
            }
            Thread.sleep(retryDelayMs / 1000);
        }
    }
    console.error(`[${SCRIPT_NAME}] CRITICAL FAILURE: Failed after ${maxRetries} overall attempts.`);
    return NULL;
}

// --- Main execution ---
const localPlayer = getLocalPlayerAddressVTablePoll();

if (localPlayer && !localPlayer.isNull()) {
    console.log(`\n>>> FINAL RESULT: Local Player Object is at: ${localPlayer}`);
} else {
    console.log("\n>>> FINAL RESULT: Failed to get local player address or player not found.");
}