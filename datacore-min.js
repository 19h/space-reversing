/*
 * Minimal Frida Script for Dumping DataCore Structure Names
 * 
 * This script hooks DataCore_FindStructDescByName to collect structure names
 * containing "Item" and logs detailed information to the console.
 * It also tracks backtraces and generates a graphviz visualization.
 */

// Configuration
const TARGET_MODULE_NAME = "StarCitizen.exe";

// Function offsets relative to the target module's base address
const FUNC_OFFSET = {
    DataCore_FindStructDescByName: 0x14723EDF0 - 0x140000000
};

// Globals
const g_collectedStructNames = new Set();
let g_targetModuleBase = null;
let g_dataCoreRegistryPtr = null;
let g_hookedFuncAddress = null;

// Backtrace tracking
const g_backtraceGraph = new Map(); // Map of caller->callee relationships
let g_lastDotDumpTime = Date.now();
let g_isDumpScheduled = false; // Flag to track if a dump is pending

// Helper function to get timestamp
function getTimestamp() {
    return new Date().toISOString();
}

// Helper function to get symbol name for an address
function getSymbolForAddress(address) {
    try {
        const sym = DebugSymbol.fromAddress(ptr(address));
        return sym.name || "unknown";
    } catch (e) {
        return "unknown";
    }
}

// Initialize the hook
function initializeHook() {
    console.log(`[${getTimestamp()}] [INFO] Starting initialization...`);
    
    // Find the target module
    const targetModule = Process.findModuleByName(TARGET_MODULE_NAME);
    if (!targetModule) {
        console.error(`[${getTimestamp()}] [ERROR] Module ${TARGET_MODULE_NAME} not found!`);
        return false;
    }
    
    g_targetModuleBase = targetModule.base;
    console.log(`[${getTimestamp()}] [INFO] Found ${TARGET_MODULE_NAME} at base address: ${g_targetModuleBase}`);
    
    // Calculate the function address
    const funcAddress = g_targetModuleBase.add(FUNC_OFFSET.DataCore_FindStructDescByName);
    g_hookedFuncAddress = funcAddress.toString();
    console.log(`[${getTimestamp()}] [INFO] DataCore_FindStructDescByName address: ${funcAddress}`);
    
    // Attach the interceptor
    try {
        Interceptor.attach(funcAddress, {
            onEnter: function(args) {
                //console.log(`[${getTimestamp()}] [DEBUG] Hook onEnter triggered for ${funcAddress}`);
                // args[0] is pDataCoreRegistry (rcx)
                // args[1] is pStructName (rdx)
                const pDataCoreRegistry = args[0];
                const pStructName = args[1];
                
                // Store the DataCoreRegistry pointer for potential future use
                if (!g_dataCoreRegistryPtr) {
                    g_dataCoreRegistryPtr = pDataCoreRegistry;
                    console.log(`[${getTimestamp()}] [INFO] Captured DataCoreRegistry pointer: ${g_dataCoreRegistryPtr}`);
                }
                
                // Capture and process backtrace
                const backtraceData = Thread.backtrace(this.context, Backtracer.ACCURATE);

                if (!pStructName.isNull()) {
                    try {
                        let structName = "";
                        try {
                            structName = pStructName.readUtf8String();
                        } catch (e1) {
                            console.warn(`[${getTimestamp()}] [WARN] readUtf8String failed, trying with limit`);
                            structName = pStructName.readUtf8String(256);
                        }
                        
                        if (structName && structName.length > 0) {
                                console.log(`[${getTimestamp()}] [INFO] New struct found: "${structName}"`);
                                
                                // Log additional details about the struct
                                try {
                                    const pStructDesc = this.returnValue;

                                    console.log(`[${getTimestamp()}] [INFO] pStructDesc: ${pStructDesc}`);
                                    // Print registers in an ASCII table format
                                    // Helper function to pad register values to a fixed width
                                    function padRegisterValue(value, width = 27) {
                                        const strValue = String(value);
                                        return strValue + ' '.repeat(Math.max(0, width - strValue.length));
                                    }
                                    
                                    console.log("┌─────────────────────────────────────────────────────────────────────┐");
                                    console.log("│                             CPU REGISTERS                           │");
                                    console.log("├───────────┬─────────────────────────────┬───────────────────────────┤");
                                    console.log(`│ rax       │ ${padRegisterValue(this.context.rax)} │ Return value              │`);
                                    console.log(`│ rcx       │ ${padRegisterValue(this.context.rcx)} │ First argument (this ptr) │`);
                                    console.log(`│ rdx       │ ${padRegisterValue(this.context.rdx)} │ Second argument           │`);
                                    console.log(`│ rbx       │ ${padRegisterValue(this.context.rbx)} │ Callee-saved register     │`);
                                    console.log(`│ rsp       │ ${padRegisterValue(this.context.rsp)} │ Stack pointer             │`);
                                    console.log(`│ rbp       │ ${padRegisterValue(this.context.rbp)} │ Frame pointer             │`);
                                    console.log(`│ rsi       │ ${padRegisterValue(this.context.rsi)} │ Source index              │`);
                                    console.log(`│ rdi       │ ${padRegisterValue(this.context.rdi)} │ Destination index         │`);
                                    console.log(`│ r8        │ ${padRegisterValue(this.context.r8)} │ Third argument            │`);
                                    console.log(`│ r9        │ ${padRegisterValue(this.context.r9)} │ Fourth argument           │`);
                                    console.log(`│ r10       │ ${padRegisterValue(this.context.r10)} │ Volatile register         │`);
                                    console.log(`│ r11       │ ${padRegisterValue(this.context.r11)} │ Volatile register         │`);
                                    console.log(`│ r12       │ ${padRegisterValue(this.context.r12)} │ Callee-saved register     │`);
                                    console.log(`│ r13       │ ${padRegisterValue(this.context.r13)} │ Callee-saved register     │`);
                                    console.log(`│ r14       │ ${padRegisterValue(this.context.r14)} │ Callee-saved register     │`);
                                    console.log(`│ r15       │ ${padRegisterValue(this.context.r15)} │ Callee-saved register     │`);
                                    console.log(`│ rip       │ ${padRegisterValue(this.context.rip)} │ Instruction pointer       │`);
                                    console.log("└───────────┴─────────────────────────────┴───────────────────────────┘");

                                    // Get backtrace information
                                    const backtraceData = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                        .map((addr, index) => {
                                            let symbolInfo = "";
                                            try {
                                                const sym = DebugSymbol.fromAddress(addr);
                                                symbolInfo = sym.name || "???";
                                            } catch (e) {
                                                symbolInfo = "???";
                                            }
                                            return { index, addr, symbolInfo };
                                        });
                                    
                                    // Print backtrace in an ASCII table format
                                    console.log("┌─────────────────────────────────────────────────────────────────────┐");
                                    console.log("│                              BACKTRACE                              │");
                                    console.log("├───────────┬─────────────────────────────┬───────────────────────────┤");
                                    
                                    backtraceData.forEach(frame => {
                                        // Pad the symbol info to a fixed width
                                        const symbolInfo = String(frame.symbolInfo);
                                        const maxSymbolLength = 27;
                                        const paddedSymbol = symbolInfo.length <= maxSymbolLength 
                                            ? symbolInfo + ' '.repeat(maxSymbolLength - symbolInfo.length)
                                            : symbolInfo.substring(0, maxSymbolLength - 3) + '...';
                                        
                                        console.log(`│ [${frame.index.toString().padEnd(7)}] │ ${frame.addr.toString().padEnd(27)} │ ${paddedSymbol} │`);
                                    });
                                    
                                    console.log("└───────────┴─────────────────────────────┴───────────────────────────┘");

                                    if (pStructDesc && !pStructDesc.isNull()) {
                                        const pNamePtr = pStructDesc.readPointer();
                                        const name = pNamePtr.readUtf8String();
                                        const fieldCount = pStructDesc.add(0x08).readU64().toNumber();
                                        const instanceSize = pStructDesc.add(0x38).readU64().toNumber();
                                        
                                        console.log(`[${getTimestamp()}] [DETAIL] Struct: "${name}"`);
                                        console.log(`[${getTimestamp()}] [DETAIL]   Size: ${instanceSize} (0x${instanceSize.toString(16).toUpperCase()})`);
                                        console.log(`[${getTimestamp()}] [DETAIL]   Fields: ${fieldCount}`);
                                    }
                                } catch (e) {
                                    console.error(`[${getTimestamp()}] [ERROR] Failed to read struct details: ${e.message}`);
                                }
                        }
                    } catch (e) {
                        console.error(`[${getTimestamp()}] [ERROR] Error processing struct name: ${e.message}`);
                    }
                }
            },
            onLeave: function(retval) {
                // Store the return value for use in onEnter
                this.returnValue = retval;
            }
        });
        console.log(`[${getTimestamp()}] [INFO] Hook attached successfully`);
    } catch (e) {
        console.error(`[${getTimestamp()}] [ERROR] Failed to attach hook: ${e.message}`);
        return false;
    }
    
    return true;
}

// Main execution
console.log(`[${getTimestamp()}] [INFO] Script loaded`);

if (initializeHook()) {
    console.log(`[${getTimestamp()}] [INFO] Initialization successful. Collecting structure names...`);
} else {
    console.error(`[${getTimestamp()}] [ERROR] Initialization failed!`);
}
