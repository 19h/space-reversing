"use strict";

// --- Configuration ---
const MODULE_NAME = "StarCitizen.exe"; // Or null for the main executable
const FUNCTION_OFFSET = ptr("0x4DCF650");
const FUNCTION_NAME = "CEntityComponentCommodityUIProvider_SendCommoditySellRequest"; // Original: sub_144DCF650

// --- Constants for Structure Sizes (Approximations/Placeholders) ---
// These are hard to get perfectly without full headers, but help in hexdumps.
const SIZEOF_M256 = 32;
const SIZEOF_OWORD = 16;

// --- Utility Functions ---

function getTimestamp() {
    return new Date().toISOString();
}

function logMessage(threadId, message) {
    const T_PREFIX = `[${FUNCTION_NAME} #${threadId || Thread.id} @ ${getTimestamp()}] `;
    console.log(T_PREFIX + message);
}

function logError(threadId, message, error) {
    const T_PREFIX = `[${FUNCTION_NAME} #${threadId || Thread.id} @ ${getTimestamp()}] ERROR: `;
    console.error(T_PREFIX + message);
    if (error) {
        console.error(T_PREFIX + (error.stack || error));
    }
}

function safeReadString(address, type = 'cstring', maxLength = 256) {
    if (!address || address.isNull()) {
        return "NULL_PTR_STRING";
    }
    try {
        if (type === 'utf8string') return address.readUtf8String(maxLength);
        return address.readCString(maxLength); // Default to CString
    } catch (e) {
        return `READ_STRING_ERROR: ${e.message}`;
    }
}

function safeReadPointer(address) {
    if (!address || address.isNull()) return "NULL_PTR_FIELD";
    try {
        return address.readPointer();
    } catch (e) {
        return `READ_PTR_ERROR: ${e.message}`;
    }
}

function formatGuid(guidPtr) {
    if (!guidPtr || guidPtr.isNull()) return "NULL_GUID_PTR";
    try {
        // Assuming standard GUID layout: {DWORD}-{WORD}-{WORD}-{BYTE[2]}-{BYTE[6]}
        const d1 = guidPtr.readU32();
        const d2 = guidPtr.add(4).readU16();
        const d3 = guidPtr.add(6).readU16();
        const d4_0 = guidPtr.add(8).readU8();
        const d4_1 = guidPtr.add(9).readU8();
        const d4_2 = guidPtr.add(10).readU8();
        const d4_3 = guidPtr.add(11).readU8();
        const d4_4 = guidPtr.add(12).readU8();
        const d4_5 = guidPtr.add(13).readU8();
        const d4_6 = guidPtr.add(14).readU8();
        const d4_7 = guidPtr.add(15).readU8();

        return "{" +
               d1.toString(16).padStart(8, '0') + "-" +
               d2.toString(16).padStart(4, '0') + "-" +
               d3.toString(16).padStart(4, '0') + "-" +
               d4_0.toString(16).padStart(2, '0') + d4_1.toString(16).padStart(2, '0') + "-" +
               d4_2.toString(16).padStart(2, '0') + d4_3.toString(16).padStart(2, '0') +
               d4_4.toString(16).padStart(2, '0') + d4_5.toString(16).padStart(2, '0') +
               d4_6.toString(16).padStart(2, '0') + d4_7.toString(16).padStart(2, '0') +
               "}";
    } catch (e) {
        return `GUID_READ_ERROR: ${e.message}`;
    }
}

function dumpField(threadId, basePtr, offset, type, description, options = {}) {
    const address = basePtr.add(offset);
    let valueStr = "N/A";
    let rawValue = null;

    try {
        switch (type) {
            case 'ptr':
                rawValue = address.readPointer();
                valueStr = rawValue.toString();
                break;
            case 'qword': // unsigned 64-bit
                rawValue = address.readU64();
                valueStr = `0x${rawValue.toString(16)} (${rawValue.toString()})`;
                break;
            case 'sqword': // signed 64-bit
                rawValue = address.readS64();
                valueStr = `${rawValue.toString()} (0x${rawValue.toString(16)})`;
                break;
            case 'dword': // unsigned 32-bit
                rawValue = address.readU32();
                valueStr = `0x${rawValue.toString(16)} (${rawValue.toString()})`;
                break;
            case 'sdword': // signed 32-bit
                rawValue = address.readS32();
                valueStr = `${rawValue.toString()} (0x${rawValue.toString(16)})`;
                break;
            case 'word': // unsigned 16-bit
                rawValue = address.readU16();
                valueStr = `0x${rawValue.toString(16)} (${rawValue.toString()})`;
                break;
            case 'sword': // signed 16-bit
                rawValue = address.readS16();
                valueStr = `${rawValue.toString()} (0x${rawValue.toString(16)})`;
                break;
            case 'byte': // unsigned 8-bit
                rawValue = address.readU8();
                valueStr = `0x${rawValue.toString(16)} (${rawValue.toString()})`;
                break;
            case 'sbyte': // signed 8-bit
                rawValue = address.readS8();
                valueStr = `${rawValue.toString()} (0x${rawValue.toString(16)})`;
                break;
            case 'float':
                rawValue = address.readFloat();
                valueStr = rawValue.toString();
                break;
            case 'double':
                rawValue = address.readDouble();
                valueStr = rawValue.toString();
                break;
            case 'guid':
                rawValue = address; // The raw value is the pointer itself for formatting
                valueStr = formatGuid(address);
                break;
            case 'm256': // __m256 (YMM register content)
                rawValue = address;
                valueStr = `(See hexdump below)\n${hexdump(address, { length: SIZEOF_M256, ansi: true })}`;
                break;
            case 'oword': // _OWORD (XMM register content or 16-byte struct)
                rawValue = address;
                valueStr = `(See hexdump below)\n${hexdump(address, { length: SIZEOF_OWORD, ansi: true })}`;
                break;
            case 'cstring_ptr': // A pointer to a C string
                rawValue = address.readPointer();
                if (rawValue.isNull()) {
                    valueStr = "NULL_STRING_PTR";
                } else {
                    valueStr = `points to ${rawValue}, value: "${safeReadString(rawValue, 'cstring', options.maxLength || 256)}"`;
                }
                break;
            case 'struct_ptr': // A pointer to another structure
                rawValue = address.readPointer();
                 if (rawValue.isNull()) {
                    valueStr = "NULL_STRUCT_PTR";
                } else {
                    valueStr = `points to ${rawValue}\n${hexdump(rawValue, { length: options.dumpLength || 64, ansi: true })}`;
                }
                break;
            default:
                valueStr = `UNKNOWN_TYPE (${type})`;
        }
    } catch (e) {
        valueStr = `READ_ERROR (${type} @ ${address}): ${e.message}`;
        rawValue = null; // Ensure rawValue is null on error
    }

    logMessage(threadId, `  ${description.padEnd(55)} | Offset: 0x${offset.toString(16).padEnd(4)} | Address: ${address.toString().padEnd(18)} | Value: ${valueStr}`);

    // Optional: Further dereference if it was a simple 'ptr' and not handled by cstring_ptr or struct_ptr
    if (type === 'ptr' && rawValue instanceof NativePointer && !rawValue.isNull()) {
        try {
            logMessage(threadId, `    -> Dereferenced ${rawValue}:`);
            logMessage(threadId, hexdump(rawValue, { length: 64, ansi: true, ansiColor: 'blue' }));
        } catch (e_deref) {
            logMessage(threadId, `    -> DEREF_ERROR for ${rawValue}: ${e_deref.message}`);
        }
    }
}

function logRegisters(threadId, context) {
    logMessage(threadId, "Registers:");
    const regs = [
        'rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
    ];
    regs.forEach(reg => {
        if (context[reg]) {
            logMessage(threadId, `  ${reg.toUpperCase().padEnd(3)}: ${context[reg]}`);
        }
    });
}

function logStack(threadId, context, numQwords = 16) {
    logMessage(threadId, `Stack dump (around RSP ${context.rsp}, ${numQwords * 8} bytes):`);
    try {
        const stackPtr = context.rsp;
        for (let i = 0; i < numQwords; i++) {
            const currentAddr = stackPtr.add(i * 8);
            let valueOutput = "READ_ERROR";
            try {
                const val = currentAddr.readPointer(); // Read as pointer, could be data too
                valueOutput = val.toString();
                const symbol = DebugSymbol.fromAddress(val);
                if (symbol && symbol.name) {
                    valueOutput += ` (${symbol.name})`;
                }
            } catch (e) { /* ignore read error for individual stack entry */ }
            logMessage(threadId, `  ${currentAddr} (+${(i * 8).toString().padStart(3)}): ${valueOutput}`);
        }
    } catch (e) {
        logError(threadId, "Failed to dump stack", e);
    }
}

// --- Main Hooking Logic ---

function attachToFunction(baseAddr) {
    const targetAddress = baseAddr.add(FUNCTION_OFFSET);
    logMessage(null, `Attempting to hook ${FUNCTION_NAME} at ${targetAddress}`);

    Interceptor.attach(targetAddress, {
        onEnter: function (args) {
            const threadId = this.threadId;
            logMessage(threadId, `>>> Entering ${FUNCTION_NAME} at ${targetAddress}`);
            logMessage(threadId, `Called from: ${this.returnAddress} (${DebugSymbol.fromAddress(this.returnAddress).name || 'N/A'})`);

            logRegisters(threadId, this.context);
            logStack(threadId, this.context, 16);

            const a1 = args[0]; // RCX on x64 __fastcall
            logMessage(threadId, `Argument a1 (RCX): ${a1}`);

            if (a1 && !a1.isNull()) {
                logMessage(threadId, "--- Dumping CEntityComponentCommodityUIProvider structure (pointed to by a1) ---");

                // Based on C++ code analysis and previous Frida output:
                // General/Early Checks
                dumpField(threadId, a1, 0x8,    'ptr', "Ptr for sub_144CCC580 (PlayerEntity?)");
                dumpField(threadId, a1, 0x1C0,  'ptr', "Ptr to Shop Handle for Handle::IsValid");

                // Commodity Array/Index
                dumpField(threadId, a1, 0x14F0, 'qword', "Commodity Array Base Ptr?");
                dumpField(threadId, a1, 0x14F8, 'qword', "Commodity Array End Ptr?");
                dumpField(threadId, a1, 0x15C8, 'qword', "Selected Commodity Index");

                // State Flags & Data (Buy/Sell/Transfer/Request)
                // dumpField(threadId, a1, 0x1A68, 'struct_ptr', "Struct for Buy/Sell Mode UI", { dumpLength: 32 }); // Size unknown
                dumpField(threadId, a1, 0x1A90, 'byte',  "Buy/Sell Mode Active Flag");
                dumpField(threadId, a1, 0x1AB0, 'qword', "Buy/Sell Mode Type (0=Buy, 1=Sell, 2=Transfer?)");

                // dumpField(threadId, a1, 0x1B18, 'struct_ptr', "Struct for Request State UI", { dumpLength: 32 }); // Size unknown
                dumpField(threadId, a1, 0x1B40, 'byte',  "Request State Active Flag");
                dumpField(threadId, a1, 0x1B60, 'qword', "Request State Type (0=None, 1=BuyPend, 2=SellPend)");

                // Values for vcvtsi2sd
                dumpField(threadId, a1, 0x1CE0, 'sqword', "Value for vcvtsi2sd (Type 1)");
                dumpField(threadId, a1, 0x1D30, 'sqword', "Value for vcvtsi2sd (Type 4/5)");

                // IDs and Flags
                dumpField(threadId, a1, 0x1D80, 'dword', "Kiosk ID");
                dumpField(threadId, a1, 0x1FA1, 'byte',  "AutoLoading Flag");

                // Floats for Type 1 logic
                dumpField(threadId, a1, 0x1FEC, 'float', "Float Value for Type 1 (a8 in sub_14045E790)");
                dumpField(threadId, a1, 0x2034, 'float', "Float Value for Type 1 (a9 in sub_14045E790)");

                // Transaction Mode Display
                // dumpField(threadId, a1, 0x20F8, 'struct_ptr', "Struct for Transaction Mode Display UI", { dumpLength: 32 });
                dumpField(threadId, a1, 0x2120, 'byte',  "Transaction Mode Display Active Flag");
                dumpField(threadId, a1, 0x2140, 'qword', "Transaction Mode Display Type");

                // Core Data for Request Building
                dumpField(threadId, a1, 0x21A8, 'm256',  "__m256 Data (YMM content)");
                dumpField(threadId, a1, 0x21C8, 'dword', "Check Value for Type 2 Branch (0xB0?)");

                dumpField(threadId, a1, 0x2200, 'oword', "OWORD src__1 (Type 2 specific)");
                dumpField(threadId, a1, 0x2210, 'qword', "QWORD part of src__1 or related");
                dumpField(threadId, a1, 0x2218, 'dword', "Amount/Count");
                dumpField(threadId, a1, 0x2220, 'guid',  "Resource GUID"); // This is `src` in logging
                dumpField(threadId, a1, 0x2230, 'dword', "Transaction Mode Enum / Shop Type");
                dumpField(threadId, a1, 0x2238, 'double',"Quantity / Price");
                // dumpField(threadId, a1, 0x2240, 'struct_ptr', "Data for sub_145DC8AD0", { dumpLength: 32 });
                dumpField(threadId, a1, 0x2250, 'cstring_ptr', "Transaction Mode String Ptr (or ID if low value)");
                dumpField(threadId, a1, 0x2258, 'struct_ptr', "Ptr to std::tree v46 (Cargo Boxes)", { dumpLength: 128 });
                dumpField(threadId, a1, 0x2268, 'dword', "ECommoditySubSourceType");
                dumpField(threadId, a1, 0x226C, 'dword', "Unknown DWORD (used with Type 1)");
                dumpField(threadId, a1, 0x2270, 'dword', "Value for Type 2 logic");
                // dumpField(threadId, a1, 0x2278, 'struct_ptr', "Data for sub_1404A0EA0 (Type 3)", { dumpLength: 32 });
                // dumpField(threadId, a1, 0x2290, 'struct_ptr', "Data for sub_14045E790 (Type 4/5)", { dumpLength: 32 });

                // Inventory Display
                // dumpField(threadId, a1, 0x22D0, 'struct_ptr', "Struct for Inventory Display UI", { dumpLength: 32 });
                dumpField(threadId, a1, 0x22F8, 'byte',  "Inventory Display Active Flag");
                dumpField(threadId, a1, 0x2311, 'byte',  "Inventory Display Type (0=Zone, 1=Inventory)");

                // Finalization Data
                // dumpField(threadId, a1, 0x27F0, 'struct_ptr', "Data for sub_144C90550", { dumpLength: 32 });
                dumpField(threadId, a1, 0x2868, 'dword', "Final Request State (set to 7)");
                dumpField(threadId, a1, 0x2880, 'qword', "Shop ID (or Ptr)");

                logMessage(threadId, "--- End of CEntityComponentCommodityUIProvider structure dump ---");

                // General hexdump for broader context
                logMessage(threadId, "General hexdump of a1 (first 256 bytes):");
                logMessage(threadId, hexdump(a1, { length: 256, ansi: true }));

            } else {
                logMessage(threadId, "Argument a1 is NULL.");
            }
            logMessage(threadId, "--- End of onEnter ---");
            this.a1_onEnter = a1; // Save for onLeave if needed
        },

        onLeave: function (retval) {
            const threadId = this.threadId;
            logMessage(threadId, `<<< Leaving ${FUNCTION_NAME}`);
            // Function is void, so retval is not meaningful in terms of application logic.
            // Frida's retval here will be the content of RAX.
            logMessage(threadId, `RAX on exit: ${this.context.rax}`);
            // You could re-dump parts of a1 if you suspect they changed and want to see the after-state.
            // For example:
            // if (this.a1_onEnter && !this.a1_onEnter.isNull()) {
            //     logMessage(threadId, "State of key fields in a1 on exit:");
            //     dumpField(threadId, this.a1_onEnter, 0x2868, 'dword', "Final Request State (on exit)");
            // }
            logMessage(threadId, "--- End of onLeave ---");
        }
    });
    logMessage(null, `Hook for ${FUNCTION_NAME} at ${targetAddress} is now active.`);
}

// --- Script Entry Point ---
function main() {
    logMessage(null, "Frida script starting...");
    Process.setExceptionHandler(function (details) {
        logError(null, `Unhandled Exception: ${details.type} at ${details.address} (Context RIP: ${details.context.rip})`, details);
        return true; // Let the process's default handler run, or false to terminate.
    });

    let baseAddr;
    if (MODULE_NAME) {
        const module = Process.findModuleByName(MODULE_NAME);
        if (!module) {
            logError(null, `Module ${MODULE_NAME} not found. Script will not run.`);
            return;
        }
        baseAddr = module.base;
        logMessage(null, `Module ${MODULE_NAME} found at ${baseAddr}.`);
    } else {
        baseAddr = Module.findBaseAddress(null); // Main executable
        if (!baseAddr) {
            logError(null, `Could not determine base address for the main executable. Script will not run.`);
            return;
        }
        logMessage(null, `Using main executable's base address: ${baseAddr}.`);
    }

    try {
        attachToFunction(baseAddr);
    } catch (e) {
        logError(null, "Failed to attach main hook", e);
    }
}

// Run main safely
setImmediate(main);
