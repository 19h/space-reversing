'use strict';

const interceptedFilePaths = new Set();

const FRAMEWORK_CONFIGURATION = Object.freeze({
    // Keep your existing config
    // ...
    CRT_STDIO_MODULE: 'api-ms-win-crt-stdio-l1-1-0.dll',
    CRT_MATH_MODULE: 'api-ms-win-crt-math-l1-1-0.dll',
    KERNEL32_MODULE: 'KERNEL32.DLL', // Added for clarity
    BACKTRACE_DEPTH: 16,
    LOGGING_PREFIXES: Object.freeze({
        MONITOR: '[FILE_IO_MONITOR]',
        ERROR: '[INTERCEPTION_ERROR]',
        SUCCESS: '[INTERCEPTION_SUCCESS]',
        STACKTRACE: '[CALL_STACK_ANALYSIS]'
    })
});

function captureAndLogFileAccess(filePath, functionIdentifier, cpuContext, returnValue) {
    const uniqueIdentifier = `${functionIdentifier}|${filePath}`;
    if (interceptedFilePaths.has(uniqueIdentifier)) {
        return;
    }
    interceptedFilePaths.add(uniqueIdentifier);

    const resultLog = returnValue ? `| Result: ${returnValue}` : '';
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Function: ${functionIdentifier} | Target: ${filePath} ${resultLog}`);
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.STACKTRACE}`);

    try {
        // TRY THIS FIRST: Change ACCURATE to FUZZY
        const stackFrames = Thread.backtrace(cpuContext, Backtracer.FUZZY);
        if (stackFrames.length > 0) {
            const symbolizedFrames = stackFrames.map(DebugSymbol.fromAddress);
            console.log(symbolizedFrames.join('\n'));
        } else {
            console.log('Backtrace was empty. The call might be from an unusual context (e.g., a fiber or heavily optimized code).');
        }
    } catch (exception) {
        console.log(`Stack trace acquisition failure: ${exception.message}`);
    }
}

// Replace your INTERCEPTION_SPECIFICATIONS with this.
// The key change is moving from Interceptor.replace to Interceptor.attach for CreateFileW.
const INTERCEPTION_SPECIFICATIONS = Object.freeze([
    {
        functionName: 'CreateFileW',
        targetModule: FRAMEWORK_CONFIGURATION.KERNEL32_MODULE,
        // NOTE: We are no longer defining the interceptor here.
        // The logic will be handled in the initialization loop.
    },
    // ... you can add other KERNEL32 functions here in the same simple format
    // { functionName: 'CreateFileA', targetModule: FRAMEWORK_CONFIGURATION.KERNEL32_MODULE },
    // { functionName: 'ReadFile', targetModule: FRAMEWORK_CONFIGURATION.KERNEL32_MODULE },
]);

// ==================================================================
// REWRITTEN INITIALIZATION LOGIC
// ==================================================================
function initializeInterceptionFramework() {
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Initializing file I/O interception framework`);
    let successfulInterceptionCount = 0;

    INTERCEPTION_SPECIFICATIONS.forEach(spec => {
        const functionAddress = Module.findExportByName(spec.targetModule, spec.functionName);
        if (!functionAddress) {
            return; // Silently skip if not found
        }

        try {
            Interceptor.attach(functionAddress, {
                onEnter: function(args) {
                    // 'args' is an array of NativePointer objects for the arguments.
                    // We save the arguments we care about to 'this' context
                    // so we can access them in onLeave.
                    this.xcontext = this.context; // Keep the CPU context for backtracing

                    if (spec.functionName === 'CreateFileW') {
                        this.filePath = args[0].readUtf16String();
                    } else if (spec.functionName === 'CreateFileA') {
                        this.filePath = args[0].readAnsiString();
                    } else if (spec.functionName === 'ReadFile') {
                        // For ReadFile, the "target" is the handle.
                        // We can create a map of handles to filenames for better logging.
                        this.filePath = `HANDLE:${args[0]}`;
                    }
                },
                onLeave: function(retval) {
                    // 'retval' is a NativePointer to the return value.
                    // 'this.filePath' is what we saved in onEnter.
                    if (this.filePath) {
                        captureAndLogFileAccess(this.filePath, spec.functionName, this.xcontext, retval);

                        // You can still have specific logic here
                        if (spec.functionName === 'CreateFileW' && this.filePath.toLowerCase().includes('data.p4k')) {
                            const INVALID_HANDLE_VALUE = new NativePointer('-1');
                            if (!retval.equals(INVALID_HANDLE_VALUE)) {
                                console.log(`[!!!] Successfully opened Data.p4k with handle: ${retval}`);
                            }
                        }
                    }
                }
            });

            console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.SUCCESS} Successfully intercepted: ${spec.functionName} at ${functionAddress}`);
            successfulInterceptionCount++;
        } catch (e) {
            console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.ERROR} Interception failed for ${spec.functionName}: ${e.message}`);
        }
    });

    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Interception framework initialization complete`);
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Successful interceptions: ${successfulInterceptionCount}`);
}

// Your deinitialization function is fine as is.
function deinitializeInterceptionFramework() {
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Deinitializing interception framework`);
    Interceptor.detachAll();
    interceptedFilePaths.clear();
    console.log(`${FRAMEWORK_CONFIGURATION.LOGGING_PREFIXES.MONITOR} Deinitialization complete`);
}

// Start the script
initializeInterceptionFramework();
Script.bindWeak(globalThis, deinitializeInterceptionFramework);
