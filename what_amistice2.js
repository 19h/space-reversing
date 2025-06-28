/**
 * Document:      Hook_sub_1415A5370.js
 * Version:       1.0
 * Author:        Advanced RE Analyst
 * Target:        sub_1415A5370
 * Architecture:  x86-64
 * Platform:      Windows
 * Objective:     Non-invasively replace the target function to enforce a static return value of 0.0,
 *                bypassing the original function body entirely.
 */

// Verify that the script is running in the intended environment.
if (Process.arch !== 'x64' || Process.platform !== 'windows') {
    throw new Error("This script is designed exclusively for x64 Windows targets.");
}

// Define the target function's Effective Address (EA).
// This address must be the absolute virtual address within the target process's address space.
const targetAddress = ptr('0x1415A5370');

// Log the address for verification purposes.
console.log(`[INFO] Target function address identified at: ${targetAddress}`);

try {
    // Use Interceptor.replace to substitute the function's implementation.
    // This is the correct API for completely bypassing the original function logic.
    Interceptor.replace(targetAddress, new NativeCallback(
        /**
         * This is the JavaScript implementation of our replacement function.
         * It accepts the same number of arguments as the original function to maintain
         * a valid function signature, although they are unused in this implementation.
         *
         * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
         * @param {NativePointer} a2 - Corresponds to the original __int64 a2 (in RDX).
         * @param {NativePointer} a3 - Corresponds to the original __int64* a3 (in R8).
         * @returns {number} - A double-precision floating-point value.
         */
        function (a1, a2, a3) {
            // Log the invocation of the hook for real-time analysis and confirmation.
            // This demonstrates that our replacement is being called instead of the original.
            console.log(`[HOOKED] sub_1415A5370(${a1}, ${a2}, ${a3}) called. Forcing return value to 0.0.`);

            // Return the required value. JavaScript's number type is treated as a
            // double-precision float (64-bit) by the Frida bridge, which correctly
            // maps to the 'double' return type. This value will be placed in the
            // XMM0 register as per the ABI.
            return 0.0;
        },
        // The return type of the native function. Must match the original.
        'double',
        // An array of strings specifying the types of the native function's arguments.
        ['pointer', 'pointer', 'pointer'],
        // The Application Binary Interface (ABI). 'win64' is the correct specifier
        // for the __fastcall convention on 64-bit Windows. This is critical for
        // ensuring correct argument passing and stack handling.
        'win64'
    ));

    console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress}.`);
    console.log("[INFO] The original function will no longer be executed. All calls will be redirected to the replacement.");

} catch (error) {
    // Provide detailed error reporting if the hook fails.
    console.error(`[FATAL] Failed to apply hook at ${targetAddress}.`);
    console.error(`[FATAL] Error details: ${error.message}`);
    console.error(`[FATAL] Stack trace: \n${error.stack}`);
}

// Define the address for the second target function sub_141599A90
const targetAddress2 = ptr('0x141599A90');

console.log(`[INFO] Second target function address identified at: ${targetAddress2}`);

try {
    // Hook sub_141599A90 to intercept and log the original return value
    Interceptor.replace(targetAddress2, new NativeCallback(
        /**
         * Replacement function for sub_141599A90.
         * Original function allocates and initializes GreenZoneComponentParams structures.
         * This replacement calls the original function and logs its return value.
         *
         * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
         * @param {NativePointer} a2 - Corresponds to the original unsigned __int64 a2 (in RDX).
         * @returns {NativePointer} - Returns the pointer from the original function.
         */
        function (a1, a2) {
            console.log(`[HOOKED] sub_141599A90(${a1}, ${a2}) called.`);

            // Call the original function to get its return value
            const originalFunction = new NativeFunction(targetAddress2, 'pointer', ['pointer', 'uint64'], 'win64');
            const returnValue = originalFunction(a1, a2);

            console.log(`[INFO] Original function returned pointer: ${returnValue}`);

            return returnValue;
        },
        // Return type: pointer to GreenZoneComponentParams
        'pointer',
        // Argument types: __int64 and unsigned __int64
        ['pointer', 'uint64'],
        // ABI specification for x64 Windows
        'win64'
    ));

    console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress2}.`);
    console.log("[INFO] GreenZoneComponentParams allocation will be monitored and logged.");

} catch (error) {
    console.error(`[FATAL] Failed to apply hook at ${targetAddress2}.`);
    console.error(`[FATAL] Error details: ${error.message}`);
    console.error(`[FATAL] Stack trace: \n${error.stack}`);
}

// Define the address for the third target function sub_141593F80
const targetAddress3 = ptr('0x141593F80');

console.log(`[INFO] Third target function address identified at: ${targetAddress3}`);

try {
    // Hook sub_141593F80 to return a static value of 0
    Interceptor.replace(targetAddress3, new NativeCallback(
        /**
         * Replacement function for sub_141593F80.
         * This replacement bypasses the original function entirely and returns 0.
         *
         * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
         * @returns {number} - Returns 0 as a char value.
         */
        function (a1) {
            console.log(`[HOOKED] sub_141593F80(${a1}) called. Forcing return value to 0.`);

            // Return 0, bypassing the original function entirely
            return 1;
        },
        // Return type: char
        'char',
        // Argument types: __int64
        ['pointer'],
        // ABI specification for x64 Windows
        'win64'
    ));

    console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress3}.`);
    console.log("[INFO] The original function will no longer be executed. All calls will return 0.");

} catch (error) {
    console.error(`[FATAL] Failed to apply hook at ${targetAddress3}.`);
    console.error(`[FATAL] Error details: ${error.message}`);
    console.error(`[FATAL] Stack trace: \n${error.stack}`);
}

// Define the address for the fourth target function sub_145D26710
const targetAddress4 = ptr('0x145D26710');

console.log(`[INFO] Fourth target function address identified at: ${targetAddress4}`);

try {
    // Hook sub_145D26710 to intercept and log the original return value
    Interceptor.replace(targetAddress4, new NativeCallback(
        /**
         * Replacement function for sub_145D26710.
         * This replacement calls the original function and logs its return value.
         *
         * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
         * @param {NativePointer} a2 - Corresponds to the original unsigned __int64 a2 (in RDX).
         * @returns {number} - Returns the char value from the original function.
         */
        function (a1, a2) {
            //console.log(`[HOOKED] sub_145D26710(${a1.and(ptr(0xFFFFFFFFFFFF))}, ${a2}) called.`);

            // Call the original function to get its return value
            const originalFunction = new NativeFunction(targetAddress4, 'char', ['pointer', 'uint64'], 'win64');
            const returnValue = originalFunction(a1, a2);

            //console.log(`[INFO] Original function returned char value: ${returnValue}`);

            //return returnValue;
            return 1;
        },
        // Return type: char
        'char',
        // Argument types: __int64 and unsigned __int64
        ['pointer', 'uint64'],
        // ABI specification for x64 Windows
        'win64'
    ));

    console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress4}.`);
    console.log("[INFO] Function calls will be monitored and logged.");

} catch (error) {
    console.error(`[FATAL] Failed to apply hook at ${targetAddress4}.`);
    console.error(`[FATAL] Error details: ${error.message}`);
    console.error(`[FATAL] Stack trace: \n${error.stack}`);
}

/**
 * Frida Script for Armistice Zone Bypass - Final, Confirmed Method
 *
 * After extensive analysis, it's clear that a single function, sub_141593F80,
 * acts as the primary gatekeeper for Armistice Zone restrictions on the player.
 * This script hooks this one function and forces its return value to 0,
 * signaling that no restrictions are active and preventing the weapon
 * holstering action.
 *
 * All other systems (GreenZone flags, Interaction Conditions, CVars) are
 * secondary or irrelevant to this specific on-foot player action.
 */

// --- [1] CONFIGURATION ---
const config = {
    logging: {
        enabled: true,
    },
    bypass: {
        enabled: true,
        // The value to return to signal "no restrictions active".
        // Based on user testing, this is 0.
        permissiveReturnValue: 0
    }
};

// --- [2] ADDRESS DEFINITION ---
const TARGET_MODULE = 'StarCitizen.exe';
const offsets = {
    // This is the function confirmed by the user to have an effect.
    // Its likely name is CanPerformActionInCurrentZone or similar.
    RestrictionGatekeeper: ptr('0x1593F80')
};

// --- [3] SCRIPT CORE ---
try {
    console.log(`[+] Starting Armistice Zone Bypass (Final Method)...`);
    const module = Process.findModuleByName(TARGET_MODULE);
    if (!module) throw new Error(`Module ${TARGET_MODULE} not found.`);
    const base = module.base;

    const targetAddress = base.add(offsets.RestrictionGatekeeper);

    console.log(`[+] Installing final hook on Restriction Gatekeeper at ${targetAddress}`);

    Interceptor.attach(targetAddress, {
        onEnter: function(args) {
            // We can log arguments if we want to understand what state
            // it's checking. For now, we only care about the return.
            if (config.logging.enabled) {
                console.log(`[GATEKEEPER] Restriction function ${targetAddress} called.`);
                // You can add console.log(args[0], args[1], ...) here to inspect inputs.
            }
        },
        onLeave: function(retval) {
            const originalRet = retval.toInt32();
            if (config.logging.enabled) {
                console.log(`    > Original return value: ${originalRet}`);
            }

            if (config.bypass.enabled) {
                retval.replace(ptr(config.bypass.permissiveReturnValue));
                console.warn(`    > [BYPASS APPLIED] Forced return value to ${config.bypass.permissiveReturnValue}.`);
            }
        }
    });

    console.log('[SUCCESS] Bypass installed. Armistice zone should be disabled.');

} catch (error) {
    console.error(`[-] An error occurred: ${error.message}\n${error.stack}`);
}
