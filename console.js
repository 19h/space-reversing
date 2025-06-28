/*
 * Frida Script to Enable Developer Console Commands (Ultimate "God Mode" Patch)
 * Target: StarEngine Executable
 * Method: Performs a single, direct in-memory machine code patch on the console's
 *         gatekeeper function, forcing it to always return 'true'. This globally
 *         enables all commands and features gated by this check, including
 *         auto-completion, without altering any other engine state.
 */

try {
    const baseAddr = Process.getModuleByName("StarCitizen.exe").base;

    // Address of the gatekeeper function that checks command flags.
    // sub_1475EC910 -> 0x1475EC910 - 0x140000000 = 0x75EC910
    const gatekeeperFuncPtr = baseAddr.add(0x75EC910);

    console.log(`[+] Located Gatekeeper Function at: ${gatekeeperFuncPtr}`);

    // The machine code to force the function to return true (1).
    // B0 01   -> mov al, 1
    // C3      -> ret
    const patchBytes = [0xB0, 0x01, 0xC3];

    // Use Memory.patchCode for a safe, transactional patch.
    // It handles memory permissions (RWX) automatically.
    Memory.patchCode(gatekeeperFuncPtr, patchBytes.length, codePtr => {
        codePtr.writeByteArray(patchBytes);
    });

    console.log(`[SUCCESS] Gatekeeper function has been patched.`);
    console.log("[+] All developer commands and CVars should now be fully available with auto-completion.");
    console.log("[+] You can now type commands like 'pl_showStatus' or 'gotoPlayer' directly into the in-game console.");

} catch (e) {
    console.error(`[FATAL] Script failed: ${e.message}`);
}

/*
 * Frida Script for Developer Console Commands (Final, Definitive Executor)
 * Target: StarEngine Executable
 * Method: 1. Hooks all known CVar and Command registration functions to strip the
 *            VF_DEVELOPMENT flag, making them visible to the engine's parser.
 *         2. Exposes an RPC function that calls the engine's internal ExecuteString
 *            function, which correctly handles argument parsing and dispatch.
 */

function initialize() {
    try {
        const baseAddr = Process.getModuleByName("StarCitizen.exe").base;
        const VF_DEVELOPMENT = 0x10000000;

        // --- Part 1: Comprehensive Flag-Stripping Hooks ---

        const registrationFunctions = {
            // CVars (flags at arg 4)
            'CVar(int)':    { ptr: baseAddr.add(0x75E3000), argIdx: 4 },
            'CVar(float)':  { ptr: baseAddr.add(0x75E2D80), argIdx: 4 },
            'CVar(string)': { ptr: baseAddr.add(0x75E26E0), argIdx: 4 },
            // Commands (flags at arg 3)
            'Command':      { ptr: baseAddr.add(0x75761B0), argIdx: 3 },
            'CommandEx':    { ptr: baseAddr.add(0x75763D0), argIdx: 3 }
        };

        for (const name in registrationFunctions) {
            const info = registrationFunctions[name];
            Interceptor.attach(info.ptr, {
                onEnter: function(args) {
                    try {
                        const originalFlags = args[info.argIdx].toInt32();
                        if ((originalFlags & VF_DEVELOPMENT) !== 0) {
                            args[info.argIdx] = ptr(originalFlags & ~VF_DEVELOPMENT);
                        }
                    } catch (e) { /* Suppress errors for signature mismatches */ }
                }
            });
        }
        console.log("[+] All flag-stripping hooks installed successfully.");

    } catch (e) {
        console.error(`[FATAL] Initialization failed: ${e.message}`);
    }
}

// --- Part 2: RPC Export for Command Execution ---

rpc.exports = {
    /**
     * Executes any command string via the engine's internal, high-level parser.
     * @param {string} commandLine The full command line to execute.
     */
    execute: function(commandLine) {
        try {
            const baseAddr = Process.getModuleByName("StarCitizen.exe").base;
            const consolePtrAddr = baseAddr.add(0x9B4FC90);
            const pConsole = consolePtrAddr.readPointer();

            if (pConsole.isNull()) {
                return "ERROR: IConsole instance is not yet available.";
            }

            const executeStringInternalPtr = baseAddr.add(0x759F710);
            const executeStringInternal = new NativeFunction(executeStringInternalPtr,
                'void', ['pointer', 'pointer', 'uint8', 'int64', 'pointer'], 'win64'
            );

            console.log(`[EXEC] Sending to engine: "${commandLine}"`);
            const cmdToRun = Memory.allocUtf8String(commandLine);
            executeStringInternal(pConsole, cmdToRun, 0, int64(0), NULL);

            return `SUCCESS: Command "${commandLine}" was dispatched.`;
        } catch (e) {
            return `ERROR executing "${commandLine}": ${e.message}\n${e.stack}`;
        }
    }
};

// Run initialization immediately.
initialize();
