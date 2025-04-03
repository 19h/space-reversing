'use strict';

console.log("[*] Script starting...");

// --- Robust Module Finding ---
const TARGET_MODULE_NAME = "StarCitizen.exe";
let baseAddr = Module.findBaseAddress(TARGET_MODULE_NAME);

if (!baseAddr) {
    console.warn(`[!] Module.findBaseAddress("${TARGET_MODULE_NAME}") failed initially. Enumerating modules...`);
    const modules = Process.enumerateModules();
    let foundModule = null;
    for (let i = 0; i < modules.length; i++) {
        console.log(`    - Module ${i}: Name=${modules[i].name}, Path=${modules[i].path}, Base=${modules[i].base}, Size=${modules[i].size}`);
        // Case-insensitive comparison just in case
        if (modules[i].name.toLowerCase() === TARGET_MODULE_NAME.toLowerCase()) {
            foundModule = modules[i];
            break;
        }
    }
    if (foundModule) {
        console.log(`[+] Found module "${TARGET_MODULE_NAME}" via enumeration.`);
        baseAddr = foundModule.base;
    } else {
         console.error(`[-] Could not find module "${TARGET_MODULE_NAME}" even after enumeration. Exiting.`);
         // You might want to throw an error here or return depending on how the script is run
         throw new Error(`Could not find base address for module: ${TARGET_MODULE_NAME}`);
         // return;
    }
}

console.log(`[+] Using Module ${TARGET_MODULE_NAME} base address: ${baseAddr}`);


// --- Configuration - Addresses relative to the module base ---
// (Keep the relative address definitions as before)
const G_P_SOME_SYSTEM_ADDR_REL = ptr('0xA3E38A8');
const GET_PLAYER_ENTITY_HANDLE_ADDR_REL = ptr('0x67EF650');
const GET_COMPONENT_FROM_HANDLE_ADDR_REL = ptr('0x6906D90');
const GET_CURRENT_HEALTH_ADDR_REL = ptr('0x65D2B60');
const GET_MAX_HEALTH_ADDR_REL = ptr('0x65D4D30');

// Calculate absolute addresses
const g_pSomeSystemPtrAddr = baseAddr.add(G_P_SOME_SYSTEM_ADDR_REL);
const GetPlayerEntityHandleAddr = baseAddr.add(GET_PLAYER_ENTITY_HANDLE_ADDR_REL);
const GetComponentFromHandleAddr = baseAddr.add(GET_COMPONENT_FROM_HANDLE_ADDR_REL);
const GetCurrentHealthAddr = baseAddr.add(GET_CURRENT_HEALTH_ADDR_REL);
const GetMaxHealthAddr = baseAddr.add(GET_MAX_HEALTH_ADDR_REL);


// --- Native Function Signatures ---
// (Keep the NativeFunction definitions as before)
const nativeGetPlayerEntityHandle = new NativeFunction(GetPlayerEntityHandleAddr, 'void', ['pointer', 'pointer']);
const nativeGetComponentFromHandle = new NativeFunction(GetComponentFromHandleAddr, 'pointer', ['uint64']);
const nativeGetCurrentHealth = new NativeFunction(GetCurrentHealthAddr, 'float', ['pointer']);
const nativeGetMaxHealth = new NativeFunction(GetMaxHealthAddr, 'float', ['pointer']);

// --- Potentially Missing Native Function Definitions (Need Addresses) ---
// These addresses are GUESSED based on function names in disassembly.
// They are likely INCORRECT and need verification from the user/reversing.
// If these functions are not needed or their addresses are unknown,
// the corresponding NativeFunction definitions and calls should be removed or adjusted.
const SUB_1403AD870_ADDR_REL = ptr('0x03AD870'); // GUESS based on disassembly name sub_1403AD870
const SUB_143AE6980_ADDR_REL = ptr('0x3AE6980'); // GUESS based on disassembly name sub_143AE6980

let nativeSub1403AD870 = null;
let nativeSub143AE6980 = null;

try {
    const sub_1403AD870_Addr = baseAddr.add(SUB_1403AD870_ADDR_REL);
    // Signature: bool __fastcall sub_1403AD870(__int64 *a1)
    // Takes a pointer to the handle, returns bool (represented as int/uint8 in JS)
    nativeSub1403AD870 = new NativeFunction(sub_1403AD870_Addr, 'bool', ['pointer']);
    console.log(`[+] NativeFunction for sub_1403AD870 created at ${sub_1403AD870_Addr}`);
} catch (e) {
    console.warn(`[!] Failed to create NativeFunction for sub_1403AD870 (Address: ${baseAddr.add(SUB_1403AD870_ADDR_REL)}). Address might be invalid or function signature incorrect. Validation check in js_sub_1465D2B60 will be skipped. Error: ${e}`);
}

try {
    const sub_143AE6980_Addr = baseAddr.add(SUB_143AE6980_ADDR_REL);
    // Signature: __m128 __fastcall sub_143AE6980(__int64 a1, int a2)
    // Takes component ptr, int index. Returns float (__m128 lower dword)
    nativeSub143AE6980 = new NativeFunction(sub_143AE6980_Addr, 'float', ['pointer', 'int']);
     console.log(`[+] NativeFunction for sub_143AE6980 created at ${sub_143AE6980_Addr}`);
} catch (e) {
    console.warn(`[!] Failed to create NativeFunction for sub_143AE6980 (Address: ${baseAddr.add(SUB_143AE6980_ADDR_REL)}). Address might be invalid or function signature incorrect. Final value retrieval in js_sub_1465D2B60 might fail. Error: ${e}`);
}


// --- JS Re-implementation of sub_1465D2B60 ---
// This function attempts to replicate the logic of the C++ function sub_1465D2B60
// based on the provided disassembly.
//
// NOTE: This JS implementation relies on calling other native functions:
//   - nativeSub1403AD870 (for validation)
//   - nativeGetComponentFromHandle (for sub_146906D90)
//   - nativeSub143AE6980 (for final float retrieval)
//
// The addresses for nativeSub1403AD870 and nativeSub143AE6980 are GUESSED
// and may be incorrect. If they are incorrect or the NativeFunction creation failed,
// this JS function's behavior will deviate significantly from the original C++ code.
//
// In most cases, calling the original native function directly via
// `nativeGetCurrentHealth` (which points to sub_1465D2B60's address)
// is preferred over using this JS reimplementation.
function js_sub_1465D2B60(a1) {
    // Default return value corresponds to `vxorps xmm0, xmm0, xmm0`
    let result = 0.0;

    try {
        // Read handle: v2[0] = *(_QWORD *)(a1 + 616); (offset 0x268)
        const handlePtr = a1.add(0x268);
        const handle = handlePtr.readU64(); // Read the 64-bit handle value

        // Perform validation check: if ( (unsigned __int8)sub_1403AD870(v2) )
        let isValid = false;
        if (nativeSub1403AD870) {
            // sub_1403AD870 takes a pointer to the handle (__int64 *a1)
            const pHandle = Memory.alloc(8);
            pHandle.writeU64(handle);
            isValid = nativeSub1403AD870(pHandle);
        } else {
            // If the validation function isn't available, we cannot replicate the check.
            // Defaulting to false (no execution) is safer than assuming true.
            console.warn(`[!] Skipping validation step in js_sub_1465D2B60: nativeSub1403AD870 unavailable.`);
            isValid = false;
        }

        if (isValid) {
            // Mask handle: v2[1] = v2[0] & 0xFFFFFFFFFFFFLL;
            const maskedHandle = handle.and(new UInt64('0xFFFFFFFFFFFF'));

            // Get component pointer: v3 = sub_146906D90(v2[0] & 0xFFFFFFFFFFFFLL);
            // We use the existing nativeGetComponentFromHandle which corresponds to sub_146906D90
            const v3 = nativeGetComponentFromHandle(maskedHandle); // Takes uint64, returns pointer

            if (!v3.isNull()) {
                 // Get final float value: sub_143AE6980(v3, 11LL);
                 if (nativeSub143AE6980) {
                    result = nativeSub143AE6980(v3, 11); // Takes pointer, int, returns float
                 } else {
                     // If the final value retrieval function isn't available, return 0.0
                     console.warn(`[!] Cannot retrieve final value in js_sub_1465D2B60: nativeSub143AE6980 unavailable.`);
                     result = 0.0;
                 }
            } else {
                // If GetComponentFromHandle returns null, the original code likely leads to
                // the xorps path eventually, so return 0.0
                console.warn(`[-] nativeGetComponentFromHandle returned NULL for masked handle ${maskedHandle} in js_sub_1465D2B60.`);
                result = 0.0;
            }
        } else {
            // Validation failed or was skipped, result remains 0.0
        }

    } catch (e) {
        console.error(`[!] Error encountered within js_sub_1465D2B60: ${e}`);
        console.error(e.stack);
        result = 0.0; // Return 0.0 on error
    }

    return result;
}



// --- Main Logic ---
// (Keep the getPlayerHealth function exactly as in the PREVIOUS revision - Revision 3)
function getPlayerHealth() {
    let pHealthComponent = ptr(0);
    let playerEntityId = new UInt64(0);
    let maskedPlayerEntityId = new UInt64(0);
    let currentHealth = NaN;
    let maxHealth = NaN;

    try {
        console.log(`[*] Reading system pointer from ${g_pSomeSystemPtrAddr}...`);
        const pSomeSystem = g_pSomeSystemPtrAddr.readPointer();
        if (pSomeSystem.isNull()) {
            console.error(`[-] System pointer at ${g_pSomeSystemPtrAddr} is NULL.`);
            return;
        }
        console.log(`[+] Found system pointer: ${pSomeSystem}`);

        const pEntityIdOut = Memory.alloc(8);
        console.log(`[*] Calling GetPlayerEntityHandle(${pSomeSystem}, ${pEntityIdOut})...`);
        nativeGetPlayerEntityHandle(pSomeSystem, pEntityIdOut);

        playerEntityId = pEntityIdOut.readU64();
        if (playerEntityId.equals(0) || playerEntityId.equals(0xFFFFFFFFFFFFFFFF)) {
             console.warn(`[-] GetPlayerEntityHandle returned invalid ID: ${playerEntityId}`);
             return;
        }
        console.log(`[+] Found Player Entity ID: ${playerEntityId}`);

        const maskValue = new UInt64('0xFFFFFFFFFFFF');
        maskedPlayerEntityId = playerEntityId.and(maskValue);
        console.log(`[+] Masked Player Entity ID: ${maskedPlayerEntityId}`);

        console.log(`[*] Calling GetComponentFromHandle(${maskedPlayerEntityId})...`);
        pHealthComponent = nativeGetComponentFromHandle(maskedPlayerEntityId);

        if (pHealthComponent.isNull()) {
            console.error(`[-] Could not get CSCBodyHealthComponent for ID ${maskedPlayerEntityId}.`);
            return;
        }
        console.log(`[+] Found CSCBodyHealthComponent pointer: ${pHealthComponent}`);

        try {
            currentHealth = js_sub_1465D2B60(pHealthComponent);
            console.log(`[+] GetCurrentHealth successful.`);
            console.log(`  Current Health:  ${currentHealth.toFixed(2)}`);
        } catch (e) {
            console.error(`[-] Error in js_sub_1465D2B60: ${e}`);
            console.error(e.stack);
        }

        // --- Attempt to read health IMMEDIATELY ---
        try {
            pHealthComponent.readU8();
            console.log(`[*] Memory at ${pHealthComponent} seems initially accessible.`);

            console.log(`[*] Calling GetCurrentHealth(${pHealthComponent})...`);
            currentHealth = nativeGetCurrentHealth(pHealthComponent);
            console.log(`[+] GetCurrentHealth successful.`);

            console.log(`[*] Calling GetMaxHealth(${pHealthComponent})...`);
            maxHealth = nativeGetMaxHealth(pHealthComponent);
            console.log(`[+] GetMaxHealth successful.`);

        } catch (e) {
            console.error(`[-] Access violation or error using pHealthComponent (${pHealthComponent}): ${e}`);
            console.error(`[!] The component pointer likely became invalid after retrieval.`);
             console.log(`[*] Dumping memory near pHealthComponent (${pHealthComponent}) if possible:`);
             try {
                  console.log(hexdump(pHealthComponent.sub(0x100), { length: 0x300, ansi: true }));
             } catch (dumpError) {
                 console.warn(`[!] Could not dump memory near ${pHealthComponent}: ${dumpError.message}`);
             }
            currentHealth = NaN;
            maxHealth = NaN;
            pHealthComponent = ptr(0);
        }

        // --- Final Output ---
        console.log(`\n=======================================`);
        console.log(`  Player Health Information`);
        console.log(`---------------------------------------`);
        console.log(`  Entity ID:       ${playerEntityId} (Masked: ${maskedPlayerEntityId})`);
        console.log(`  Health Comp Ptr: ${pHealthComponent}`);
        console.log(`  Current Health:  ${currentHealth.toFixed(2)}`);
        console.log(`  Max Health:      ${maxHealth.toFixed(2)}`);
        console.log(`=======================================\n`);

    } catch (e) {
        console.error(`[-] An error occurred outside health calls: ${e}`);
        console.error(e.stack);
    }
}


// --- Execution ---
console.log("[*] Script loaded. Attempting to get player health...");
getPlayerHealth();

/*
rpc.exports = {
    gethealth: getPlayerHealth
};
console.log("[*] RPC export 'gethealth' ready.");
*/