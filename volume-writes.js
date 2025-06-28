// Frida script for comprehensive microSCU volume data extraction and analysis
// Target: x64 Windows binary with item management system

const moduleBase = Process.enumerateModules()[0].base; // Adjust if not main module

// Function addresses (adjust based on actual base address)
const ADDRESSES = {
    sub_1448EB510: ptr('0x1448EB510'),
    sub_1448FF5F0: ptr('0x1448FF5F0'),
    sub_14056A7D0: ptr('0x14056A7D0'),
    sub_14035D3E0: ptr('0x14035D3E0'),
    sub_140343300: ptr('0x140343300'),
    allocWithProfilerInfo: ptr('0x147605A30'),
    AK_WriteBytesMem_Bytes: ptr('0x1402A24F0') // Placeholder - needs verification
};

// Data structure for tracking item information
const itemDataMap = new Map();
let allocationTracker = new Map();

// Hook 1: Primary storage function - sub_1448EB510
// This function stores the microSCU volume data in the object structure
Interceptor.attach(ADDRESSES.sub_1448EB510, {
    onEnter: function(args) {
        this.a1 = args[0];
        this.a2 = args[1];
        this.a3 = args[2];
        this.p_ItemCount = args[3];
        this.a5 = args[4];
        this.p_ItemVolumeMicroSCU = args[5];
        this.a7 = args[6];

        // Store context for onLeave
        this.itemData = {
            targetObject: this.a1,
            itemCountPtr: this.p_ItemCount,
            volumeIdentifier: this.p_ItemVolumeMicroSCU.readCString(),
            volumeDataPtr: this.a7
        };

        console.log('\n[sub_1448EB510] Item Storage Function Called');
        console.log(`  Target Object: ${this.a1}`);
        console.log(`  Item Count Ptr: ${this.p_ItemCount}`);
        console.log(`  Volume Identifier: ${this.itemData.volumeIdentifier}`);
        console.log(`  Volume Data Ptr: ${this.a7}`);

        // Read the actual volume value from a7
        if (!this.a7.isNull()) {
            const volumeValue = this.a7.readU64();
            console.log(`  Volume Value (raw): 0x${volumeValue.toString(16)}`);

            // Attempt to interpret as pointer and read data
            try {
                const volumePtr = ptr(volumeValue.toString());
                if (!volumePtr.isNull()) {
                    console.log(`  Volume data at ${volumePtr}:`);
                    console.log(hexdump(volumePtr, {
                        offset: 0,
                        length: 64,
                        header: true,
                        ansi: true
                    }));
                }
            } catch (e) {
                console.log(`  Volume value appears to be direct data, not pointer`);
            }
        }

        // Read a5 data (appears to be a DWORD value)
        if (!this.a5.isNull()) {
            const a5Value = this.a5.readU32();
            console.log(`  a5 Value: ${a5Value} (0x${a5Value.toString(16)})`);
        }
    },

    onLeave: function(retval) {
        console.log(`[sub_1448EB510] Completed, return: ${retval}`);

        // Store in tracking map
        itemDataMap.set(this.a1.toString(), {
            ...this.itemData,
            structureOffsets: {
                qword_0x00: this.a1.readPointer(),
                volumeIdentifier_0x08: this.a1.add(0x08).readPointer(),
                dword_0x10: this.a1.add(0x10).readU32(),
                itemCount_0x18: this.a1.add(0x18).readPointer(),
                vectorData_0x20: this.a1.add(0x20).readPointer()
            }
        });

        // Dump the constructed object structure
        console.log('  Constructed Object Structure:');
        console.log(hexdump(this.a1, {
            offset: 0,
            length: 0x40,
            header: true,
            ansi: true
        }));
    }
});

// Hook 2: Data extraction function - sub_1448FF5F0
// This function processes source data and extracts volume information
Interceptor.attach(ADDRESSES.sub_1448FF5F0, {
    onEnter: function(args) {
        this.a1 = args[0];
        this.a2 = args[1];
        this.src = args[2];

        console.log('\n[sub_1448FF5F0] Data Extraction Function Called');
        console.log(`  a1: ${this.a1}`);
        console.log(`  a2 (output): ${this.a2}`);
        console.log(`  src: ${this.src}`);

        // Read source data structure
        if (!this.src.isNull()) {
            console.log('  Source Data Structure:');
            console.log(hexdump(this.src, {
                offset: 0,
                length: 0x40,
                header: true,
                ansi: true
            }));

            // Extract specific fields based on decompiled code
            const volumeValue = this.src.add(0x10).readU32(); // src[4] in DWORD terms
            console.log(`  Volume Value at src[4]: ${volumeValue} (0x${volumeValue.toString(16)})`);

            // Extract bytes from src + 24 (src + 6 DWORDs)
            const bytesPtr = this.src.add(0x18);
            console.log('  Bytes data at src+6:');
            console.log(hexdump(bytesPtr, {
                offset: 0,
                length: 32,
                header: true,
                ansi: true
            }));
        }
    },

    onLeave: function(retval) {
        console.log(`[sub_1448FF5F0] Completed, return: ${retval}`);

        // Dump the populated output structure
        if (!this.a2.isNull()) {
            console.log('  Output Structure:');
            console.log(hexdump(this.a2, {
                offset: 0,
                length: 0x60,
                header: true,
                ansi: true
            }));
        }
    }
});

// Hook 3: Type mapping function - sub_14056A7D0
// This appears to map item types/categories
//Interceptor.attach(ADDRESSES.sub_14056A7D0, {
//    onEnter: function(args) {
//        this.inputChar = args[0].toInt32() & 0xFF;
//    },
//
//    onLeave: function(retval) {
//        const outputChar = retval.toInt32() & 0xFF;
//        if (this.inputChar !== 0 && outputChar !== 0) {
//            console.log(`[sub_14056A7D0] Type Mapping: 0x${this.inputChar.toString(16)} -> 0x${outputChar.toString(16)}`);
//        }
//    }
//});

// Hook 4: Memory allocation tracking - allocWithProfilerInfo
// Track allocations to understand data lifecycle
//Interceptor.attach(ADDRESSES.allocWithProfilerInfo, {
//    onEnter: function(args) {
//        this.allocSize = args[0].toInt32();
//        this.profilerInfo = args[1];
//    },
//
//    onLeave: function(retval) {
//        if (!retval.isNull()) {
//            allocationTracker.set(retval.toString(), {
//                size: this.allocSize,
//                timestamp: Date.now(),
//                callstack: Thread.backtrace(this.context, Backtracer.ACCURATE)
//                    .map(DebugSymbol.fromAddress)
//                    .filter(s => s.name)
//                    .slice(0, 5)
//            });
//
//            if (this.allocSize >= 100 && this.allocSize <= 10000) {
//                console.log(`[allocWithProfilerInfo] Allocation: ${retval} size: ${this.allocSize}`);
//            }
//        }
//    }
//});

// Hook 5: Vector construction - sub_14035D3E0
// This constructs vectors that may contain item data
//Interceptor.attach(ADDRESSES.sub_14035D3E0, {
//    onEnter: function(args) {
//        this.outputVector = args[0];
//        this.inputData = args[1];
//
//        console.log('\n[sub_14035D3E0] Vector Construction');
//        console.log(`  Output: ${this.outputVector}`);
//        console.log(`  Input: ${this.inputData}`);
//    },
//
//    onLeave: function(retval) {
//        // Dump constructed vector structure
//        console.log('  Constructed Vector:');
//        console.log(hexdump(this.outputVector, {
//            offset: 0,
//            length: 0x18,
//            header: true,
//            ansi: true
//        }));
//    }
//});

// Advanced stalker-based tracing for detailed volume data flow
function traceMicroSCUFlow(targetThreadId) {
    const moduleMap = new ModuleMap();
    const mainModule = Process.enumerateModules()[0];
    moduleMap.add(mainModule.base, mainModule.size);

    Stalker.follow(targetThreadId || Process.getCurrentThreadId(), {
        events: {
            call: true,
            ret: false,
            exec: false,
            block: false,
            compile: false
        },

        onReceive: function(events) {
            const parsed = Stalker.parse(events);
            parsed.forEach(event => {
                if (event[0] === 'call') {
                    const target = event[2];

                    // Check if call target is one of our functions of interest
                    Object.entries(ADDRESSES).forEach(([name, addr]) => {
                        if (target.equals(addr)) {
                            console.log(`[Stalker] Call to ${name} from ${event[1]}`);
                        }
                    });
                }
            });
        },

        transform: function(iterator) {
            let instruction;

            while ((instruction = iterator.next()) !== null) {
                // Look for memory writes that might be volume data
                if (instruction.mnemonic === 'mov' &&
                    instruction.operands.length === 2 &&
                    instruction.operands[0].type === 'mem') {

                    const memOp = instruction.operands[0];
                    const srcOp = instruction.operands[1];

                    // Insert callout to log memory writes
                    iterator.putCallout(function(context) {
                        if (memOp.value.base && srcOp.type === 'imm') {
                            const baseReg = context[memOp.value.base];
                            const address = baseReg.add(memOp.value.disp);

                            // Check if this might be volume data based on value patterns
                            const value = srcOp.value;
                            if (value > 1000 && value < 1000000) {
                                console.log(`[Stalker] Potential volume write: [${address}] = ${value}`);
                            }
                        }
                    });
                }

                iterator.keep();
            }
        }
    });
}

// Utility function to dump all tracked item data
function dumpAllItemData() {
    console.log('\n=== ITEM DATA SUMMARY ===');
    itemDataMap.forEach((data, address) => {
        console.log(`\nItem at ${address}:`);
        console.log(`  Volume Identifier: ${data.volumeIdentifier}`);
        console.log(`  Structure Offsets:`);
        Object.entries(data.structureOffsets).forEach(([key, value]) => {
            console.log(`    ${key}: ${value}`);
        });
    });

    console.log('\n=== ALLOCATION SUMMARY ===');
    const relevantAllocs = Array.from(allocationTracker.entries())
        .filter(([addr, info]) => info.size >= 100 && info.size <= 10000)
        .sort((a, b) => b[1].timestamp - a[1].timestamp)
        .slice(0, 10);

    relevantAllocs.forEach(([addr, info]) => {
        console.log(`\nAllocation at ${addr}:`);
        console.log(`  Size: ${info.size} bytes`);
        console.log(`  Stack trace:`);
        info.callstack.forEach(sym => {
            console.log(`    ${sym}`);
        });
    });
}

// Export functions for interactive use
rpc.exports = {
    dumpItemData: dumpAllItemData,
    startTracing: traceMicroSCUFlow,
    stopTracing: () => Stalker.unfollow(),
    getItemAtAddress: (address) => {
        const data = itemDataMap.get(address);
        return data || null;
    }
};

console.log('[MicroSCU Volume Tracker] Hooks installed successfully');
console.log('Available RPC functions: dumpItemData(), startTracing(), stopTracing(), getItemAtAddress(addr)');
