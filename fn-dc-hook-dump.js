/*
 * Frida Script for Dumping DataCore Structure Names and Arguments
 * 
 * This script hooks DataCore_FindStructDescByName and also sub_14723EB40,
 * dumping all arguments, structure names, and detailed information to the console.
 */

const TARGET_MODULE_NAME = "StarCitizen.exe";

// Function offsets relative to the target module's base address
const FUNC_OFFSET = {
    DataCore_FindStructDescByName: 0x14723EDF0 - 0x140000000,
    DataCore_GetStructDataFields:  0x14723EB40 - 0x140000000
};

let g_targetModuleBase = null;
let g_hookedFuncAddress = null;
let g_hookedGetFieldsAddress = null;

function getTimestamp() {
    return new Date().toISOString();
}

function getSymbolForAddress(address) {
    try {
        const sym = DebugSymbol.fromAddress(ptr(address));
        return sym.name || "unknown";
    } catch (e) {
        return "unknown";
    }
}

function tryReadUtf8(ptrVal) {
    try {
        return ptrVal.readUtf8String();
    } catch (e) {
        try {
            return ptrVal.readUtf8String(256);
        } catch (e2) {
            return "<unreadable>";
        }
    }
}

function dumpRegisterTable(context) {
    function padRegisterValue(value, width = 27) {
        const strValue = String(value);
        return strValue + ' '.repeat(Math.max(0, width - strValue.length));
    }
    console.log("┌─────────────────────────────────────────────────────────────────────┐");
    console.log("│                             CPU REGISTERS                           │");
    console.log("├───────────┬─────────────────────────────┬───────────────────────────┤");
    console.log(`│ rax       │ ${padRegisterValue(context.rax)} │ Return value              │`);
    console.log(`│ rcx       │ ${padRegisterValue(context.rcx)} │ First argument (this ptr) │`);
    console.log(`│ rdx       │ ${padRegisterValue(context.rdx)} │ Second argument           │`);
    console.log(`│ rbx       │ ${padRegisterValue(context.rbx)} │ Callee-saved register     │`);
    console.log(`│ rsp       │ ${padRegisterValue(context.rsp)} │ Stack pointer             │`);
    console.log(`│ rbp       │ ${padRegisterValue(context.rbp)} │ Frame pointer             │`);
    console.log(`│ rsi       │ ${padRegisterValue(context.rsi)} │ Source index              │`);
    console.log(`│ rdi       │ ${padRegisterValue(context.rdi)} │ Destination index         │`);
    console.log(`│ r8        │ ${padRegisterValue(context.r8)} │ Third argument            │`);
    console.log(`│ r9        │ ${padRegisterValue(context.r9)} │ Fourth argument           │`);
    console.log(`│ r10       │ ${padRegisterValue(context.r10)} │ Volatile register         │`);
    console.log(`│ r11       │ ${padRegisterValue(context.r11)} │ Volatile register         │`);
    console.log(`│ r12       │ ${padRegisterValue(context.r12)} │ Callee-saved register     │`);
    console.log(`│ r13       │ ${padRegisterValue(context.r13)} │ Callee-saved register     │`);
    console.log(`│ r14       │ ${padRegisterValue(context.r14)} │ Callee-saved register     │`);
    console.log(`│ r15       │ ${padRegisterValue(context.r15)} │ Callee-saved register     │`);
    console.log(`│ rip       │ ${padRegisterValue(context.rip)} │ Instruction pointer       │`);
    console.log("└───────────┴─────────────────────────────┴───────────────────────────┘");
}

function dumpBacktrace(context) {
    const backtraceData = Thread.backtrace(context, Backtracer.ACCURATE)
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
    console.log("┌─────────────────────────────────────────────────────────────────────┐");
    console.log("│                              BACKTRACE                              │");
    console.log("├───────────┬─────────────────────────────┬───────────────────────────┤");
    backtraceData.forEach(frame => {
        const symbolInfo = String(frame.symbolInfo);
        const maxSymbolLength = 27;
        const paddedSymbol = symbolInfo.length <= maxSymbolLength 
            ? symbolInfo + ' '.repeat(maxSymbolLength - symbolInfo.length)
            : symbolInfo.substring(0, maxSymbolLength - 3) + '...';
        console.log(`│ [${frame.index.toString().padEnd(7)}] │ ${frame.addr.toString().padEnd(27)} │ ${paddedSymbol} │`);
    });
    console.log("└───────────┴─────────────────────────────┴───────────────────────────┘");
}

function dumpArgumentsDataCoreGetStructDataFields(args, context) {
    // __int64 __fastcall sub_14723EB40(__int64 a1, __int64 rdx0, char **a3, char a4)
    // rcx = a1, rdx = rdx0, r8 = a3, r9 = a4
    const a1 = args[0];
    const rdx0 = args[1];
    const a3 = args[2];
    const a4 = args[3];

    console.log(`[${getTimestamp()}] [ARGS] sub_14723EB40 called:`);
    console.log(`  a1  (rcx):  ${a1}`);
    console.log(`  rdx0(rdx):  ${rdx0}`);
    console.log(`  a3  (r8):   ${a3}`);
    console.log(`  a4  (r9):   ${a4} (as int: ${a4.toInt32()})`);

    // Try to dump a3 as pointer to pointer to char (char **)
    try {
        if (!a3.isNull()) {
            const ptr0 = a3.readPointer();
            const ptr1 = a3.add(Process.pointerSize).readPointer();
            console.log(`  *a3[0]: ${ptr0}`);
            console.log(`  *a3[1]: ${ptr1}`);
            // Try to read as string if plausible
            if (!ptr0.isNull()) {
                const s0 = tryReadUtf8(ptr0);
                console.log(`  *a3[0] as string: "${s0}"`);
            }
            if (!ptr1.isNull()) {
                const s1 = tryReadUtf8(ptr1);
                console.log(`  *a3[1] as string: "${s1}"`);
            }
        }
    } catch (e) {
        console.log(`  [WARN] Could not dump a3 contents: ${e}`);
    }
    dumpRegisterTable(context);
    dumpBacktrace(context);
}

function dumpArgumentsDataCoreFindStructDescByName(args, context) {
    // rcx = pDataCoreRegistry, rdx = pStructName
    const pDataCoreRegistry = args[0];
    const pStructName = args[1];
    console.log(`[${getTimestamp()}] [ARGS] DataCore_FindStructDescByName called:`);
    console.log(`  pDataCoreRegistry (rcx): ${pDataCoreRegistry}`);
    console.log(`  pStructName      (rdx): ${pStructName}`);
    if (!pStructName.isNull()) {
        const structName = tryReadUtf8(pStructName);
        console.log(`  pStructName as string: "${structName}"`);
    }
    dumpRegisterTable(context);
    dumpBacktrace(context);
}

function initializeHooks() {
    console.log(`[${getTimestamp()}] [INFO] Starting initialization...`);
    const targetModule = Process.findModuleByName(TARGET_MODULE_NAME);
    if (!targetModule) {
        console.error(`[${getTimestamp()}] [ERROR] Module ${TARGET_MODULE_NAME} not found!`);
        return false;
    }
    g_targetModuleBase = targetModule.base;
    console.log(`[${getTimestamp()}] [INFO] Found ${TARGET_MODULE_NAME} at base address: ${g_targetModuleBase}`);

    // Hook DataCore_FindStructDescByName
    const funcAddress = g_targetModuleBase.add(FUNC_OFFSET.DataCore_FindStructDescByName);
    g_hookedFuncAddress = funcAddress.toString();
    console.log(`[${getTimestamp()}] [INFO] DataCore_FindStructDescByName address: ${funcAddress}`);

    try {
        Interceptor.attach(funcAddress, {
            onEnter: function(args) {
                dumpArgumentsDataCoreFindStructDescByName(args, this.context);
                // Save for onLeave
                this.pStructName = args[1];
            },
            onLeave: function(retval) {
                // Dump struct details if possible
                const pStructDesc = retval;
                if (pStructDesc && !pStructDesc.isNull()) {
                    try {
                        const pNamePtr = pStructDesc.readPointer();
                        const name = tryReadUtf8(pNamePtr);
                        const fieldCount = pStructDesc.add(0x08).readU64().toNumber();
                        const instanceSize = pStructDesc.add(0x38).readU64().toNumber();
                        console.log(`[${getTimestamp()}] [DETAIL] Struct: "${name}"`);
                        console.log(`[${getTimestamp()}] [DETAIL]   Size: ${instanceSize} (0x${instanceSize.toString(16).toUpperCase()})`);
                        console.log(`[${getTimestamp()}] [DETAIL]   Fields: ${fieldCount}`);
                    } catch (e) {
                        console.error(`[${getTimestamp()}] [ERROR] Failed to read struct details: ${e.message}`);
                    }
                }
            }
        });
        console.log(`[${getTimestamp()}] [INFO] Hooked DataCore_FindStructDescByName`);
    } catch (e) {
        console.error(`[${getTimestamp()}] [ERROR] Failed to attach hook to DataCore_FindStructDescByName: ${e.message}`);
        return false;
    }

    // Hook sub_14723EB40 (DataCore_GetStructDataFields)
    const getFieldsAddress = g_targetModuleBase.add(FUNC_OFFSET.DataCore_GetStructDataFields);
    g_hookedGetFieldsAddress = getFieldsAddress.toString();
    console.log(`[${getTimestamp()}] [INFO] DataCore_GetStructDataFields address: ${getFieldsAddress}`);

    try {
        Interceptor.attach(getFieldsAddress, {
            onEnter: function(args) {
                dumpArgumentsDataCoreGetStructDataFields(args, this.context);
            },
            onLeave: function(retval) {
                // Optionally, dump the return value
                console.log(`[${getTimestamp()}] [RET] DataCore_GetStructDataFields returned: ${retval}`);
            }
        });
        console.log(`[${getTimestamp()}] [INFO] Hooked DataCore_GetStructDataFields`);
    } catch (e) {
        console.error(`[${getTimestamp()}] [ERROR] Failed to attach hook to DataCore_GetStructDataFields: ${e.message}`);
        return false;
    }

    return true;
}

// Main execution
console.log(`[${getTimestamp()}] [INFO] Script loaded`);

if (initializeHooks()) {
    console.log(`[${getTimestamp()}] [INFO] Initialization successful. Hooks are active.`);
} else {
    console.error(`[${getTimestamp()}] [ERROR] Initialization failed!`);
}
