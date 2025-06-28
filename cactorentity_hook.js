/**
 * Frida Hook Script - Generic Function Logger
 * Target: Any function specified by offset in a module.
 * Goal: Log function calls with readable, heuristically determined details.
 *       Makes assumptions based on common x64 calling conventions.
 */

(function () {
    console.log("[*] Generic Frida Function Logger Loaded");

    // --- Configuration ---
    // MODIFY THESE FOR YOUR TARGET
    const moduleName = "StarCitizen.exe";
    const targetOffset = ptr("0x3681C35"); // Offset from module base (e.g., from IDA)
    // --- End Configuration ---

    const maxStringLen = 128;    // Max characters of a string to show
    const maxHexdumpLen = 32;     // Max bytes of other data to show as hex
    const stackArgsToShow = 4;    // How many potential stack arguments (qwords) to show
    const stackDumpLines = 8;     // Lines for the general stack dump

    // --- Platform/Architecture Detection ---
    // @ts-ignore
    const isWindows = Process.platform === 'windows';
    // @ts-ignore
    const isLinux = Process.platform === 'linux';
    // @ts-ignore
    const isMac = Process.platform === 'darwin';
    // @ts-ignore
    const is64Bit = Process.arch === 'x64';

    // Determine assumed ABI and argument locations
    let assumedAbi = "unknown";
    let argRegisters = [];
    let stackArgOffset = ptr(0); // Offset from RSP where stack args begin

    if (is64Bit) {
        if (isWindows) {
            assumedAbi = "win64";
            argRegisters = ['rcx', 'rdx', 'r8', 'r9'];
            // After return address (8 bytes) and shadow space (32 bytes)
            stackArgOffset = ptr(0x28);
        } else if (isLinux || isMac) {
            assumedAbi = "sysv";
            argRegisters = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];
            // After return address (8 bytes)
            stackArgOffset = ptr(0x8);
        } else {
            console.error("[-] Unsupported 64-bit platform for ABI detection.");
        }
    } else {
        console.error("[-] This script is primarily designed for x64. ABI detection for 32-bit is not implemented.");
        // Could add ia32 assumptions here (cdecl, stdcall, fastcall) but it's more complex
    }
    console.log(`[*] Assuming ABI: ${assumedAbi} (Platform: ${Process.platform}, Arch: ${Process.arch})`);


    // --- Helper Functions ---

    /** Logs a message with indentation */
    function logInfo(message, indent = 0) {
        console.log(`${' '.repeat(indent * 2)}${message}`);
    }

    /** Formats a number or pointer for display */
    function formatValue(val) {
        // @ts-ignore
        if (val === null || typeof val === 'undefined') return "null";
        // @ts-ignore
        if (typeof val === 'number' || typeof val === 'bigint') {
            // @ts-ignore
            return `0x${val.toString(16)} (${val.toString()})`; // Hex and decimal
        }
        // @ts-ignore // Assume NativePointer
        return val.toString(); // Address
    }

    /** Tries to figure out what a pointer points to (human-readable focus) */
    function interpretPointer(ptr, name = "Data") {
        // @ts-ignore
        if (!ptr || ptr.isNull()) {
            return `${name}: null pointer`;
        }
        try {
            // @ts-ignore
            const range = Process.findRangeByAddress(ptr);
            if (!range || !range.protection.startsWith('r')) {
                return `${name}: points to unreadable memory (${range ? range.protection : 'no range'})`;
            }

            // 1. Try reading as a CString
            try {
                // @ts-ignore
                const str = ptr.readCString(maxStringLen);
                if (str && str.length > 0) {
                    let looksLikeString = true;
                    for (let i = 0; i < Math.min(str.length, 16); i++) {
                        const charCode = str.charCodeAt(i);
                        if ((charCode < 32 && ![9, 10, 13].includes(charCode)) || charCode > 126) {
                            looksLikeString = false;
                            break;
                        }
                    }
                    if (looksLikeString) {
                        return `${name} (String?): "${str.replace(/\n/g, '\\n').replace(/\r/g, '\\r').slice(0, maxStringLen)}${str.length > maxStringLen ? '...' : ''}"`;
                    }
                }
            } catch (e) { /* Ignore */ }

            // 2. Try reading as a UTF16 string (common on Windows)
            if (isWindows) {
                try {
                    // @ts-ignore
                    const str = ptr.readUtf16String(maxStringLen);
                     if (str && str.length > 0) {
                        let looksLikeString = true;
                        for (let i = 0; i < Math.min(str.length, 16); i++) {
                            const charCode = str.charCodeAt(i);
                            if ((charCode < 32 && ![9, 10, 13].includes(charCode)) || charCode > 126) {
                                // Allow null terminators within the string length
                                if (charCode !== 0) {
                                    looksLikeString = false;
                                    break;
                                }
                            }
                        }
                        if (looksLikeString) {
                            return `${name} (UTF16?): "${str.replace(/\n/g, '\\n').replace(/\r/g, '\\r').slice(0, maxStringLen)}${str.length > maxStringLen ? '...' : ''}"`;
                        }
                    }
                } catch (e) { /* Ignore */ }
            }

            // 3. Try reading as a pointer
            try {
                // @ts-ignore
                const pointedToPtr = ptr.readPointer();
                // @ts-ignore
                if (!pointedToPtr.isNull()) { // Avoid showing pointers to NULL
                     // @ts-ignore
                     const pointedToRange = Process.findRangeByAddress(pointedToPtr);
                     if (pointedToRange) { // Check if it points somewhere valid
                        return `${name} (Pointer?): -> ${pointedToPtr}`;
                     }
                }
            } catch(e) {}

            // 4. Show a small hexdump as a fallback
            try {
                // @ts-ignore
                const bytes = Memory.readByteArray(ptr, Math.min(maxHexdumpLen, range.size - ptr.sub(range.base).toInt32()));
                if (bytes) {
                    // @ts-ignore
                    return `${name} (Hex Data):\n${hexdump(ptr, { length: Math.min(maxHexdumpLen, bytes.byteLength), ansi: false })}`;
                }
            } catch (e) { /* Ignore */ }

            return `${name}: points to readable memory (unknown content)`;

        } catch (e) {
            // @ts-ignore
            return `${name}: (error reading pointer: ${e.message})`;
        }
    }

    /** Displays key CPU registers */
    function displayRegisters(context) {
        logInfo("Registers:", 1);
        const regsToShow = is64Bit
            ? ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']
            : ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip']; // Basic 32-bit regs

        regsToShow.forEach(reg => {
            // @ts-ignore
            logInfo(`${reg.toUpperCase()}:`.padEnd(5) + ` ${formatValue(context[reg])}`, 2);
        });
    }

    /** Displays a portion of the stack */
    function displayStack(context) {
        logInfo("Stack Sample:", 1);
        try {
            // @ts-ignore
            const sp = context.rsp || context.esp; // Handle both x64/ia32
            // @ts-ignore
            console.log(hexdump(sp, {
                // @ts-ignore
                length: stackDumpLines * Process.pointerSize * 2, // Show more lines for 64-bit
                header: true,
                ansi: false
            }));
        } catch (e) {
            // @ts-ignore
            logInfo(`Error dumping stack: ${e.message}`, 2);
        }
    }

    /** Displays the call stack */
    function displayBacktrace(context) {
        logInfo("Call Stack (Backtrace):", 1);
        try {
            // @ts-ignore
            console.log(Thread.backtrace(context, Backtracer.ACCURATE) // Or FUZZY
                // @ts-ignore
                .map(addr => {
                    const sym = DebugSymbol.fromAddress(addr);
                    // @ts-ignore
                    const moduleOffset = sym.address ? addr.sub(sym.address) : ptr(0);
                    // @ts-ignore
                    const moduleInfo = sym.moduleName ? `${sym.moduleName}!${sym.name || '??'} (+0x${moduleOffset.toString(16)})` : '';
                    return `  -> ${formatValue(addr)} ${moduleInfo}`;
                }).join("\n"));
        } catch (btError) {
             // @ts-ignore
             logInfo(`Error getting backtrace: ${btError.message}`, 2);
        }
    }

    /** Performs the actual hooking */
    function hookFunction(moduleBase) {
        // @ts-ignore
        const targetAddress = moduleBase.add(targetOffset);
        // @ts-ignore
        const targetSymbol = DebugSymbol.fromAddress(targetAddress);
        // @ts-ignore
        const functionName = targetSymbol.name || `sub_${targetAddress.sub(moduleBase).toString(16)}`;
        // @ts-ignore
        const relativeOffset = targetAddress.sub(moduleBase);

        logInfo(`Hooking ${functionName} at ${targetAddress} (offset ${relativeOffset} from ${moduleBase})`);

        try {
            Interceptor.attach(targetAddress, {
                // --- Function Entry ---
                onEnter: function (args) { // Note: args array isn't reliable for register-based args
                    console.log("\n============================================================");
                    logInfo(`---> Entering ${functionName} at ${targetAddress}`);
                    logInfo(`Time: ${new Date().toISOString()}`, 1);
                    // @ts-ignore
                    logInfo(`Thread ID: ${this.threadId}`, 1);
                    console.log("------------------------------------------------------------");

                    // --- Arguments (Heuristic based on assumed ABI) ---
                    logInfo(`Arguments (Guessed based on ${assumedAbi} ABI):`, 1);
                    if (argRegisters.length > 0) {
                        logInfo("Register Arguments:", 2);
                        argRegisters.forEach((reg, index) => {
                            // @ts-ignore
                            const regValue = this.context[reg];
                            logInfo(`${index + 1}. ${reg.toUpperCase()}: ${formatValue(regValue)}`, 3);
                            logInfo(interpretPointer(regValue, `Reg Arg ${index + 1}`), 4);
                        });
                    } else {
                        logInfo("No standard argument registers for this ABI/Arch.", 2);
                    }

                    logInfo("Potential Stack Arguments:", 2);
                    try {
                        // @ts-ignore
                        const sp = this.context.rsp || this.context.esp;
                        for (let i = 0; i < stackArgsToShow; i++) {
                            // @ts-ignore
                            const offset = stackArgOffset.add(i * Process.pointerSize);
                            // @ts-ignore
                            const stackAddr = sp.add(offset);
                            // @ts-ignore
                            const stackValue = stackAddr.readPointer(); // Assume pointers/large integers
                            logInfo(`${argRegisters.length + i + 1}. Stack[${formatValue(offset)}]: ${formatValue(stackValue)} @ ${stackAddr}`, 3);
                            logInfo(interpretPointer(stackValue, `Stack Arg ${i}`), 4);
                        }
                    } catch (e) {
                        // @ts-ignore
                        logInfo(`Error reading stack arguments: ${e.message}`, 3);
                    }

                    console.log("------------------------------------------------------------");

                    // --- Context ---
                    displayRegisters(this.context);
                    console.log("------------------------------------------------------------");
                    displayStack(this.context);
                    console.log("------------------------------------------------------------");
                    displayBacktrace(this.context);
                    console.log("============================================================");
                },

                // --- Function Exit ---
                onLeave: function (retval) {
                    console.log("============================================================");
                    logInfo(`<--- Leaving ${functionName} from ${targetAddress}`);
                    logInfo(`Time: ${new Date().toISOString()}`, 1);

                    // Return value is typically in RAX (x64) or EAX (ia32)
                    // @ts-ignore
                    const retReg = is64Bit ? 'rax' : 'eax';
                    // @ts-ignore // retval is a NativePointer wrapper around the value in the return register
                    logInfo(`Return Value (${retReg.toUpperCase()}): ${formatValue(retval)}`, 1);
                    logInfo(interpretPointer(retval, "Return Value"), 2); // Interpret potential pointer

                    // Optionally log XMM0 for potential float returns
                    // try { // @ts-ignore
                    //     logInfo(`XMM0 (float?): ${this.context.xmm0.readFloat()}`, 1);
                    //     logInfo(`XMM0 (double?): ${this.context.xmm0.readDouble()}`, 1);
                    // } catch(e) {}

                    console.log("============================================================\n");
                }
            });
            logInfo(`Successfully attached hook to ${functionName} at ${targetAddress}`);
        } catch (error) {
            // @ts-ignore
            console.error(`[-] Failed to hook ${functionName} at ${targetAddress}: ${error.message}`);
            // @ts-ignore
            console.error(error.stack);
        }
    }

    /** Waits for the target module to load if needed */
    function waitForModuleAndHook() {
        logInfo(`Searching for module: ${moduleName}...`);
        // @ts-ignore
        let module = Process.findModuleByName(moduleName);
        if (module) {
            logInfo(`Module ${moduleName} found at ${module.base}. Hooking.`);
            hookFunction(module.base);
        } else {
            logInfo(`Module ${moduleName} not loaded yet. Waiting for it to load...`);
            // @ts-ignore
            const loaderFunctionName = isWindows ? "LoadLibraryW" : "dlopen";
            // @ts-ignore
            const loaderFunction = Module.findExportByName(null, loaderFunctionName);

            if (!loaderFunction) {
                console.error(`[-] Cannot find ${loaderFunctionName} to monitor module loading. Aborting.`);
                return;
            }
            logInfo(`Intercepting ${loaderFunctionName} at ${loaderFunction} to detect module load.`);

            // @ts-ignore
            const loaderInterceptor = Interceptor.attach(loaderFunction, {
                onEnter: function(args) {
                    // @ts-ignore
                    const path = isWindows ? args[0].readUtf16String() : args[0].readCString();
                    // @ts-ignore
                    const checkName = isWindows ? moduleName.toLowerCase() : moduleName;
                    // @ts-ignore
                    const checkPath = path ? (isWindows ? path.toLowerCase() : path) : "";

                    if (checkPath && checkPath.includes(checkName)) {
                        this.found = true;
                        logInfo(`${loaderFunctionName} called for target module: ${path}`);
                    }
                },
                onLeave: function(retval) {
                    // @ts-ignore
                    if (this.found && !retval.isNull()) {
                        logInfo(`Module ${moduleName} should be loaded now.`);
                        // @ts-ignore
                        const loadedModule = Process.findModuleByName(moduleName);
                        if (loadedModule) {
                            logInfo(`Found ${moduleName} at ${loadedModule.base}. Proceeding with hook.`);
                            hookFunction(loadedModule.base);
                            loaderInterceptor.detach();
                            logInfo(`Detached from ${loaderFunctionName}.`);
                        } else {
                            console.error(`[-] Error: ${moduleName} was loaded but couldn't be found immediately after.`);
                        }
                    }
                    this.found = false; // Reset flag
                }
            });
        }
     }

    // --- Start Execution ---
    // @ts-ignore
    if (!is64Bit && assumedAbi === "unknown") {
         console.warn("[!] Warning: Running on 32-bit without a specific ABI assumption. Argument guessing will be less reliable.");
    } else if (assumedAbi === "unknown") {
         console.warn("[!] Warning: Could not determine a standard ABI. Argument guessing might be inaccurate.");
    }
    // @ts-ignore
    setImmediate(waitForModuleAndHook);

})();
