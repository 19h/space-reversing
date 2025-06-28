/**
 * Comprehensive Frida Script for sub_1403627A0 Structure Analysis
 * Target Function: sub_1403627A0 @ 0x1403627A0
 *
 * This script performs exhaustive runtime analysis of structure initialization,
 * capturing all parameters and dumping complete memory layout with type-aware
 * interpretation of all fields.
 */

// Configuration constants
const TARGET_FUNCTION_OFFSET = 0x3627A0;
const STRUCT_SIZE = 0x160;
const PAGE_SIZE = Process.pageSize;

// Float interpretation helper
function interpretFloat(dwordValue) {
    const buffer = Memory.alloc(4);
    buffer.writeU32(dwordValue);
    return buffer.readFloat();
}

// Double interpretation helper
function interpretDouble(ptr) {
    try {
        return ptr.readDouble();
    } catch (e) {
        return "Invalid double read";
    }
}

// OWORD (128-bit) interpretation helper
function interpret128BitValue(ptr) {
    try {
        const low = ptr.readU64();
        const high = ptr.add(8).readU64();
        return {
            low: low.toString(16),
            high: high.toString(16),
            combined: `0x${high.toString(16).padStart(16, '0')}${low.toString(16).padStart(16, '0')}`
        };
    } catch (e) {
        return { error: "Invalid 128-bit read" };
    }
}

// Validate pointer helper
function isValidPointer(ptr) {
    if (ptr.isNull()) return false;
    try {
        const range = Process.findRangeByAddress(ptr);
        return range !== null && range.protection.includes('r');
    } catch (e) {
        return false;
    }
}

// Get module information for pointer
function getModuleInfo(ptr) {
    if (!isValidPointer(ptr)) return "Invalid/NULL";
    return ptr;
    try {
        const module = Process.findModuleByAddress(ptr);
        if (module) {
            const offset = ptr.sub(module.base);
            return `${module.name}+0x${offset.toString(16)}`;
        }
        return ptr.toString();
    } catch (e) {
        return ptr.toString();
    }
}

// Symbol resolution helper
function resolveSymbol(ptr) {
    if (!isValidPointer(ptr)) return null;
    try {
        const symbol = DebugSymbol.fromAddress(ptr);
        return symbol ? symbol.name : null;
    } catch (e) {
        return null;
    }
}

// Main function to dump complete structure
function dumpCompleteStructure(basePtr, params) {
    console.log("\n" + "=".repeat(80));
    console.log("COMPREHENSIVE STRUCTURE DUMP @ " + basePtr);
    console.log("=".repeat(80));

    // Parameter analysis
    console.log("\nINPUT PARAMETERS:");
    console.log("-".repeat(40));
    console.log(`a1 (struct ptr): ${basePtr}`);
    console.log(`a2 (primary id): 0x${params.a2.toString(16)} [${getModuleInfo(ptr(params.a2))}]`);
    console.log(`a3 (pointer): ${params.a3} [${getModuleInfo(params.a3)}]`);
    console.log(`a4 (pointer): ${params.a4} [${getModuleInfo(params.a4)}]`);
    console.log(`a5 (data src): ${params.a5} [${getModuleInfo(params.a5)}]`);
    console.log(`a6 (float): ${params.a6}`);
    console.log(`a7 (int): ${params.a7}`);
    console.log(`a8 (int): ${params.a8}`);
    console.log(`a9 (int): ${params.a9}`);
    console.log(`a10 (pointer): ${params.a10} [${getModuleInfo(params.a10)}]`);
    console.log(`a11 (data src): ${params.a11} [${getModuleInfo(params.a11)}]`);
    console.log(`a12 (data src): ${params.a12} [${getModuleInfo(params.a12)}]`);
    console.log(`a13 (data src): ${params.a13} [${getModuleInfo(params.a13)}]`);

    // Dump source data structures if valid
    console.log("\nSOURCE DATA STRUCTURES:");
    console.log("-".repeat(40));

    if (isValidPointer(params.a5)) {
        console.log("a5 source data:");
        console.log(`  +0x08 (OWORD): ${JSON.stringify(interpret128BitValue(params.a5.add(8)))}`);
        console.log(`  +0x18 (double): ${interpretDouble(params.a5.add(0x18))}`);
    }

    if (isValidPointer(params.a11)) {
        console.log("a11 source data:");
        console.log(`  +0x00 (OWORD): ${JSON.stringify(interpret128BitValue(params.a11))}`);
        console.log(`  +0x10 (double): ${interpretDouble(params.a11.add(0x10))}`);
    }

    if (isValidPointer(params.a12)) {
        console.log("a12 source data:");
        console.log(`  +0x00 (double): ${interpretDouble(params.a12)}`);
        console.log(`  +0x08 (DWORD): 0x${params.a12.add(8).readU32().toString(16)}`);
    }

    if (isValidPointer(params.a13)) {
        console.log("a13 source data:");
        console.log(`  +0x00 (double): ${interpretDouble(params.a13)}`);
        console.log(`  +0x08 (DWORD): 0x${params.a13.add(8).readU32().toString(16)}`);
    }

    // Complete structure field dump
    console.log("\nINITIALIZED STRUCTURE FIELDS:");
    console.log("-".repeat(40));

    // Helper for field dumping
    function dumpField(offset, size, type, description) {
        const addr = basePtr.add(offset);
        let value = "";
        let interpretation = "";

        try {
            switch (type) {
                case "QWORD":
                    const qval = addr.readU64();
                    value = `0x${qval.toString(16).padStart(16, '0')}`;
                    if (!qval.equals(0)) {
                        const ptrInfo = getModuleInfo(ptr(qval));
                        const symbol = resolveSymbol(ptr(qval));
                        interpretation = ptrInfo;
                        if (symbol) interpretation += ` [${symbol}]`;
                    }
                    break;

                case "DWORD":
                    const dval = addr.readU32();
                    value = `0x${dval.toString(16).padStart(8, '0')}`;
                    // Check for float patterns
                    if ((dval & 0x7F800000) === 0x3F800000 || (dval & 0x7F800000) === 0x40000000) {
                        interpretation = `float: ${interpretFloat(dval)}`;
                    } else if (dval === 0xFFFFFFFF) {
                        interpretation = "signed: -1";
                    } else if (dval === 0x800000) {
                        interpretation = "fixed-point/flag constant";
                    }
                    break;

                case "WORD":
                    const wval = addr.readU16();
                    value = `0x${wval.toString(16).padStart(4, '0')}`;
                    break;

                case "BYTE":
                    const bval = addr.readU8();
                    value = `0x${bval.toString(16).padStart(2, '0')}`;
                    interpretation = bval ? "true" : "false";
                    break;

                case "float":
                    const fval = addr.readFloat();
                    value = fval.toString();
                    interpretation = `hex: 0x${addr.readU32().toString(16).padStart(8, '0')}`;
                    break;

                case "double":
                    const dblval = interpretDouble(addr);
                    value = dblval.toString();
                    break;

                case "OWORD":
                    const oval = interpret128BitValue(addr);
                    value = oval.combined || JSON.stringify(oval);
                    break;
            }

            console.log(`[0x${offset.toString(16).padStart(3, '0')}] ${type.padEnd(6)} | ${value.padEnd(20)} | ${description.padEnd(25)} ${interpretation ? '| ' + interpretation : ''}`);

        } catch (e) {
            console.log(`[0x${offset.toString(16).padStart(3, '0')}] ${type.padEnd(6)} | ERROR: ${e.message}`);
        }
    }

    // Dump all fields in order
    dumpField(0x00, 8, "QWORD", "Primary ID/Pointer");
    dumpField(0x08, 8, "QWORD", "Secondary Pointer");
    dumpField(0x10, 8, "QWORD", "Tertiary Pointer");
    dumpField(0x18, 8, "QWORD", "Reserved Null #1");
    dumpField(0x20, 8, "QWORD", "Reserved Null #2");
    dumpField(0x28, 4, "DWORD", "Status Flag");
    dumpField(0x30, 8, "QWORD", "Reserved Null #3");
    dumpField(0x38, 8, "QWORD", "VTable Pointer #1");
    dumpField(0x40, 16, "OWORD", "128-bit Data Block #1");
    dumpField(0x50, 8, "double", "Float Value #1");
    dumpField(0x58, 4, "DWORD", "Unity Constant #1");
    dumpField(0x5C, 8, "QWORD", "Anomalous Float Storage");
    dumpField(0x64, 4, "float", "Input Float #1");
    dumpField(0x68, 4, "float", "Input Float #2 (dup)");
    dumpField(0x6C, 4, "DWORD", "Unity Constant #2");
    dumpField(0x70, 4, "DWORD", "Integer Param a7");
    dumpField(0x74, 4, "DWORD", "Integer Param a9");
    dumpField(0x78, 4, "DWORD", "Integer Param a8");
    dumpField(0x7C, 4, "DWORD", "Reserved Zero #1");
    dumpField(0x80, 1, "BYTE", "Boolean Flag #1");
    dumpField(0x88, 8, "QWORD", "Pointer Param a10");
    dumpField(0x90, 16, "OWORD", "128-bit Data Block #2");
    dumpField(0xA0, 8, "double", "Float Value #2");
    dumpField(0xA8, 8, "double", "Float Value #3");
    dumpField(0xB0, 4, "DWORD", "Integer Value #1");
    dumpField(0xB4, 8, "double", "Float Value #4");
    dumpField(0xBC, 4, "DWORD", "Integer Value #2");
    dumpField(0xC0, 8, "QWORD", "Reserved Null #4");
    dumpField(0xC8, 8, "QWORD", "Reserved Null #5");
    dumpField(0xD0, 8, "QWORD", "Reserved Null #6");
    dumpField(0xD8, 4, "DWORD", "Unity Constant #3");
    dumpField(0xDC, 8, "QWORD", "Reserved Null #7");
    dumpField(0xE4, 8, "QWORD", "Reserved Null #8");
    dumpField(0xEC, 2, "WORD", "Short Flag #1");
    dumpField(0xF0, 8, "QWORD", "Reserved Null #9");
    dumpField(0xF8, 8, "QWORD", "Reserved Null #10");
    dumpField(0x100, 8, "QWORD", "Reserved Null #11");
    dumpField(0x108, 1, "BYTE", "Boolean Flag #2");
    dumpField(0x110, 8, "QWORD", "VTable Pointer #2");
    dumpField(0x118, 8, "QWORD", "Reserved Null #12");
    dumpField(0x120, 8, "QWORD", "Reserved Null #13");
    dumpField(0x128, 8, "QWORD", "Reserved Null #14");
    dumpField(0x130, 8, "QWORD", "Reserved Null #15");
    dumpField(0x138, 4, "DWORD", "Counter/Status #1");
    dumpField(0x13C, 2, "WORD", "Short Flag #2");
    dumpField(0x140, 4, "DWORD", "Counter/Status #2");
    dumpField(0x144, 4, "DWORD", "Fixed Value #1");
    dumpField(0x148, 4, "DWORD", "Fixed Value #2");
    dumpField(0x14C, 4, "DWORD", "Fixed Value #3");
    dumpField(0x150, 4, "DWORD", "Fixed Value #4");
    dumpField(0x154, 2, "WORD", "Computed Value");
    dumpField(0x158, 8, "QWORD", "Terminal Null");

    console.log("=".repeat(80) + "\n");
}

// Hook implementation
function hookStructInitializer() {
    // Find base module
    const mainModule = Process.enumerateModules()[0];
    const targetAddr = mainModule.base.add(TARGET_FUNCTION_OFFSET);

    console.log(`[*] Hooking sub_1403627A0 at ${targetAddr}`);
    console.log(`[*] Module: ${mainModule.name} @ ${mainModule.base}`);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log(`\n[+] sub_1403627A0 called from ${this.returnAddress} [${getModuleInfo(this.returnAddress)}]`);
            console.log(`[+] Thread ID: ${Process.getCurrentThreadId()}`);

            // Store parameters for onLeave
            this.structPtr = args[0];
            this.params = {
                a2: uint64(args[1].toString()),
                a3: args[2],
                a4: args[3],
                a5: args[4],
                a6: args[5].readFloat ? args[5].readFloat() : parseFloat(args[5]),
                a7: args[6].toInt32(),
                a8: args[7].toInt32(),
                a9: args[8].toInt32(),
                a10: args[9],
                a11: args[10],
                a12: args[11],
                a13: args[12]
            };

            console.log("[*] Pre-initialization structure state:");
            // Optionally dump pre-init state
        },

        onLeave: function(retval) {
            console.log(`[+] sub_1403627A0 completed, return value: ${retval}`);

            if (this.structPtr && !this.structPtr.isNull()) {
                dumpCompleteStructure(this.structPtr, this.params);

                // Additional analysis - check for vtable calls
                const vtablePtr1 = this.structPtr.add(0x38).readPointer();
                const vtablePtr2 = this.structPtr.add(0x110).readPointer();

                if (isValidPointer(vtablePtr1)) {
                    console.log("\nVTABLE ANALYSIS:");
                    console.log("-".repeat(40));
                    console.log(`VTable @ ${vtablePtr1}:`);
                    for (let i = 0; i < 10; i++) {
                        try {
                            const vfuncPtr = vtablePtr1.add(i * 8).readPointer();
                            if (isValidPointer(vfuncPtr)) {
                                const symbol = resolveSymbol(vfuncPtr);
                                console.log(`  [${i}] ${vfuncPtr} ${symbol ? '- ' + symbol : ''}`);
                            }
                        } catch (e) {
                            break;
                        }
                    }
                }
            }
        }
    });
}

// Execute hook
hookStructInitializer();
console.log("[*] Script loaded successfully. Waiting for function calls...");

// Optional: Hook sub_1403B3F00 to understand the computed value at offset 0x154
const sub_1403B3F00_OFFSET = 0x3B3F00;
const sub_1403B3F00_addr = Process.enumerateModules()[0].base.add(sub_1403B3F00_OFFSET);

Interceptor.attach(sub_1403B3F00_addr, {
    onEnter: function(args) {
        console.log(`\n[SUB] sub_1403B3F00 called with:`);
        console.log(`  arg1 (result ptr): ${args[0]}`);
        console.log(`  arg2 (value): 0x${uint64(args[1].toString()).toString(16)}`);
        this.resultPtr = args[0];
    },

    onLeave: function(retval) {
        if (this.resultPtr && !this.resultPtr.isNull()) {
            try {
                const result = this.resultPtr.readU16();
                console.log(`[SUB] sub_1403B3F00 returned, result value: 0x${result.toString(16)}`);
            } catch (e) {
                console.log(`[SUB] sub_1403B3F00 returned, unable to read result`);
            }
        }
    }
});
