/**
 * Frida Hook Script - Generic Function Logger
 * Target: Any function specified by offset in a module.
 * Goal: Log function calls with backtrace information.
 */

(function () {
    console.log("[*] Frida Backtrace Logger Loaded");

    // --- Configuration ---
    // MODIFY THESE FOR YOUR TARGET
    const moduleName = "StarCitizen.exe";
    const targetOffset = ptr("0x02A1E30"); // Offset from module base (e.g., from IDA)
    // --- End Configuration ---

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
                onEnter: function (args) {
                    console.log("\n============================================================");
                    logInfo(`---> Entering ${functionName} at ${targetAddress}`);
                    logInfo(`Time: ${new Date().toISOString()}`, 1);
                    // @ts-ignore
                    logInfo(`Thread ID: ${this.threadId}`, 1);
                    console.log("------------------------------------------------------------");
                    
                    // Register values
                    logInfo("CPU Registers:", 1);
                    console.log(`  RAX: ${formatValue(this.context.rax)}`);
                    console.log(`  RCX: ${formatValue(this.context.rcx)}`);
                    console.log(`  RDX: ${formatValue(this.context.rdx)}`);
                    console.log(`  RBX: ${formatValue(this.context.rbx)}`);
                    console.log(`  RSP: ${formatValue(this.context.rsp)}`);
                    console.log(`  RBP: ${formatValue(this.context.rbp)}`);
                    console.log(`  RSI: ${formatValue(this.context.rsi)}`);
                    console.log(`  RDI: ${formatValue(this.context.rdi)}`);
                    console.log(`  R8:  ${formatValue(this.context.r8)}`);
                    console.log(`  R9:  ${formatValue(this.context.r9)}`);
                    console.log(`  R10: ${formatValue(this.context.r10)}`);
                    console.log(`  R11: ${formatValue(this.context.r11)}`);
                    console.log(`  R12: ${formatValue(this.context.r12)}`);
                    console.log(`  R13: ${formatValue(this.context.r13)}`);
                    console.log(`  R14: ${formatValue(this.context.r14)}`);
                    console.log(`  R15: ${formatValue(this.context.r15)}`);
                    console.log(`  RIP: ${formatValue(this.context.rip)}`);
                    console.log("------------------------------------------------------------");
                    
                    // Display the backtrace
                    displayBacktrace(this.context);
                    console.log("============================================================");
                },

                // --- Function Exit ---
                onLeave: function (retval) {
                    // No output on function exit
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
    const isWindows = Process.platform === 'windows';
    // @ts-ignore
    setImmediate(waitForModuleAndHook);

})();