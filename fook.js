//// frida-hook-actionname.js
//
//// --- Configuration ---
//// The name of the game's main executable.
//// This might be StarCitizen.exe, Squadron42.exe, or similar.
//const MODULE_NAME = "StarCitizen.exe";
//
//// The RVA (Relative Virtual Address) of the function to hook.
//// RVA = Full Address - Default Image Base
//// RVA = 0x145991850 - 0x140000000 = 0x5991850
//const HOOK_TARGET_RVA = 0x5991850;
//
//// The RVA of the helper function needed to get the string.
//// RVA = 0x14037FC70 - 0x140000000 = 0x37FC70
//const STRING_HELPER_RVA = 0x37FC70;
//// -------------------
//
//console.log("[*] Starting InputAction dumper script...");
//
//// Use a Set to store unique action names to avoid spamming the console.
//const foundActionNames = new Set();
//// Wait for the target module to be loaded into memory.
//const module = Process.findModuleByName(MODULE_NAME);
//if (!module) {
//    console.error(`[!] Module "${MODULE_NAME}" not found. Is the game running?`);
//} else {
//    console.log(`[+] Found module "${MODULE_NAME}" at address: ${module.base}`);
//
//    // Calculate the absolute memory addresses of our functions.
//    const hookTargetAddress = module.base.add(HOOK_TARGET_RVA);
//    const stringHelperAddress = module.base.add(STRING_HELPER_RVA);
//
//    console.log(`[+] Hooking sub_145991850 at absolute address: ${hookTargetAddress}`);
//    console.log(`[+] String helper sub_14037FC70 is at: ${stringHelperAddress}`);
//
//    // Create a NativeFunction object for the helper. This allows us to call it from JavaScript.
//    // Signature from analysis: const char* __fastcall sub_14037FC70(__int64 pStringStruct)
//    // Frida mapping: 'pointer' for const char*, 'pointer' for __int64
//    const getStringFromStruct = new NativeFunction(
//        stringHelperAddress,
//        'pointer', // Return type: const char*
//        ['pointer']  // Argument types: [__int64 pStringStruct]
//    );
//
//    // Attach the interceptor to our target function.
//    Interceptor.attach(hookTargetAddress, {
//        // onEnter is called when the function is entered.
//        // 'args' is an array of pointers to the function's arguments.
//        onEnter: function(args) {
//            try {
//                // For x64 __fastcall, the first argument is in RCX, which corresponds to args[0].
//                // This is the pointer to the InputAction object.
//                const pInputActionObject = args[0];
//
//                // From the analysis, the pointer to the managed string structure is at offset +8.
//                const pStringStruct = pInputActionObject.add(8);
//
//                // Call the native helper function to get the raw C-style string pointer.
//                const pActionNameString = getStringFromStruct(pStringStruct);
//
//                // Read the null-terminated string from the pointer returned by the helper.
//                const actionName = pActionNameString.readCString();
//
//                // If we got a valid string and it's one we haven't seen before, log it.
//                if (actionName && !foundActionNames.has(actionName)) {
//                    console.log(`[+] Found InputAction: ${actionName}`);
//                    foundActionNames.add(actionName);
//
//                    // Log an elaborate backtrace
//                    console.log(`\tCall stack for ${actionName}:`);
//                    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
//                        .map(address => {
//                            const symbol = DebugSymbol.fromAddress(address);
//                            let location = symbol.toString();
//                            if (symbol.moduleName) {
//                                const relativeAddress = address.sub(Module.findBaseAddress(symbol.moduleName));
//                                location = `${symbol.moduleName}!${symbol.name} (+0x${relativeAddress.toString(16)}) [${address}]`;
//                            } else if (symbol.name) {
//                                location = `${symbol.name} [${address}]`;
//                            } else {
//                                location = address.toString();
//                            }
//                            return `\t  -> ${location}`;
//                        })
//                        .join('\n');
//                    console.log(backtrace);
//                }
//            } catch (e) {
//                // Log any errors that occur inside the hook to avoid crashing the game.
//                console.error(`[!] Error in hook: ${e.message}`);
//                // Optionally log the stack trace of the error itself
//                // console.error(e.stack);
//            }
//        }
//        // We don't need onLeave for this task, so it's omitted.
//    });
//
//    console.log("[*] Hook is active. Waiting for the game to load InputAction data...");
//    console.log("[*] Actions will be printed as they are processed by the game engine.");
//}

// frida-force-logging.js

console.log("[*] Starting CLog::LogV hook script...");

const logFuncAddr = ptr(0x1475CBC40);
console.log(`[+] Hooking CLog::LogV at absolute address: ${logFuncAddr}`);

Interceptor.attach(logFuncAddr, {
    onEnter: function(args) {
        try {
            // The first argument (RCX) is the 'this' pointer to the CLog object.
            const pCLogObject = args[0];

            // From analysis, a pointer to the settings struct is at offset 0x4A0.
            const pSettingsStruct = pCLogObject.add(0x4A0).readPointer();

            if (pSettingsStruct.isNull()) {
                return; // Not initialized yet.
            }

            // --- Defeat the Verbosity Check ---
            // We write '4' (log everything) to the verbosity level locations.
            // These offsets are relative to the pSettingsStruct.
            const CONSOLE_VERBOSITY_OFFSET = 0x138; // 0x4E * 4
            const FILE_VERBOSITY_OFFSET = 0x188;    // 0x62 * 4
            const CALLBACK_VERBOSITY_OFFSET = 0x160;  // 0x58 * 4

            pSettingsStruct.add(CONSOLE_VERBOSITY_OFFSET).writeInt(4);
            pSettingsStruct.add(FILE_VERBOSITY_OFFSET).writeInt(4);
            pSettingsStruct.add(CALLBACK_VERBOSITY_OFFSET).writeInt(4);

            // --- Defeat the Spam/Throttle Check ---
            // The throttle time is read from offset 0x278 in the settings struct.
            // By setting it to 0.0, the `if (*v28 > 0.0)` check will fail,
            // bypassing the entire spam filter block.
            const THROTTLE_TIME_OFFSET = 0x278;
            pSettingsStruct.add(THROTTLE_TIME_OFFSET).writeFloat(0.0);

            // Optional: Log a message to confirm the hook is working.
            // this.isHooked is a custom property to prevent recursive logging.
            if (!this.isHooked) {
                //console.log(`[+] CLog object at ${pCLogObject} patched for full logging.`);
                this.isHooked = true;
            }

        } catch (e) {
            console.error(`[!] Error in CLog hook: ${e.message}`);
        }
    }
});
