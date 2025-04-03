// --- Configuration ---
const TARGET_MODULE = "StarCitizen.exe"; // <-- *** REPLACE THIS *** with the game's main executable name
const FUNCTION_ADDRESS = ptr("0x145811AD0"); // The absolute address from your analysis
const DUMP_SIZE = 512; // Bytes to hexdump from pAmmoContainerComponent

// --- Helper Function ---
function safeReadPointer(address) {
    try {
        return address.readPointer();
    } catch (e) {
        return null; // Return null if read fails
    }
}

function safeReadString(address) {
    try {
        const ptrValue = address.readPointer();
        if (ptrValue.isNull()) {
            return "NULL";
        }
        return ptrValue.readCString();
    } catch (e) {
        return "READ_ERROR";
    }
}

function safeReadU32(address) {
    try {
        return address.readU32();
    } catch (e) {
        return "READ_ERROR";
    }
}

function safeReadU64(address) {
    try {
        return address.readU64();
    } catch (e) {
        return "READ_ERROR";
    }
}

function safeReadFloat(address) {
    try {
        return address.readFloat();
    } catch (e) {
        return "READ_ERROR";
    }
}


// --- Main Logic ---
console.log("[+] Starting Ammo Inspector Script...");

// Find the module base address
const moduleBase = Module.findBaseAddress(TARGET_MODULE);
if (!moduleBase) {
    console.error(`[-] Could not find module: ${TARGET_MODULE}`);
} else {
    console.log(`[+] Found module ${TARGET_MODULE} at base: ${moduleBase}`);

    // Calculate the target function's address relative to the module base
    // This assumes the provided FUNCTION_ADDRESS is absolute and the base was 0x140000000
    // Adjust the base assumption if needed based on your disassembler/debugger
    const assumedBase = ptr("0x140000000");
    const functionOffset = FUNCTION_ADDRESS.sub(assumedBase);
    const targetAddr = moduleBase.add(functionOffset);

    console.log(`[+] Calculated target address for SetAmmoCountAndUpdateState: ${targetAddr}`);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log("\n=====================================================");
            console.log(`SetAmmoCountAndUpdateState @ ${targetAddr} called`);

            // args[0] is pAmmoContainerComponent (RCX)
            // args[1] is newAmmoCountRaw (RDX)
            // args[2] is notificationFlag (R8) - Frida handles the char size automatically
            const pAmmoContainerComponent = args[0];
            const newAmmoCountRaw = args[1].toInt32(); // Read as signed 32-bit int
            const notificationFlag = args[2].toUInt32(); // Read as uint, effectively getting the byte

            console.log(`  pAmmoContainerComponent: ${pAmmoContainerComponent}`);
            console.log(`  newAmmoCountRaw:         ${newAmmoCountRaw}`);
            console.log(`  notificationFlag:        ${notificationFlag} (0=Never, 1=OnChange, 2=Always)`);

            if (pAmmoContainerComponent.isNull()) {
                console.log("  pAmmoContainerComponent is NULL. Skipping dump and inference.");
                console.log("=====================================================\n");
                return;
            }

            // 1) Hexdump pAmmoContainerComponent
            console.log(`\n--- Hexdump pAmmoContainerComponent (${pAmmoContainerComponent}, ${DUMP_SIZE} bytes) ---`);
            try {
                console.log(hexdump(pAmmoContainerComponent, { length: DUMP_SIZE, ansi: false }));
            } catch (e) {
                console.log(`  Failed to hexdump: ${e}`);
            }
            console.log("--- End Hexdump ---");


            // 2) Print inferred information
            console.log(`\n--- Inferred Data from pAmmoContainerComponent (${pAmmoContainerComponent}) ---`);
            try {
                // Read fields from pAmmoContainerComponent
                console.log(`  +0x008 (Entity Handle):        ${safeReadU64(pAmmoContainerComponent.add(0x8))}`);
                console.log(`  +0x0F0 (Ammo Capacity):        ${safeReadU32(pAmmoContainerComponent.add(0xF0))}`);
                console.log(`  +0x0F4 (Current Ammo Count):   ${safeReadU32(pAmmoContainerComponent.add(0xF4))}`);
                console.log(`  +0x0D8 (Total Ammo Storage?):  ${safeReadU32(pAmmoContainerComponent.add(0xD8))}`);
                console.log(`  +0x108 (Listener Set Ptr?):    ${safeReadPointer(pAmmoContainerComponent.add(0x108))}`);
                console.log(`  +0x138 (Float State Obj Ptr?): ${safeReadPointer(pAmmoContainerComponent.add(0x138))}`);
                console.log(`  +0x140 (Fallback List Start?): ${safeReadPointer(pAmmoContainerComponent.add(0x140))}`);
                console.log(`  +0x148 (Fallback List End?):   ${safeReadPointer(pAmmoContainerComponent.add(0x148))}`);
                console.log(`  +0x158 (Primary List Start?):  ${safeReadPointer(pAmmoContainerComponent.add(0x158))}`);
                console.log(`  +0x160 (Primary List End?):    ${safeReadPointer(pAmmoContainerComponent.add(0x160))}`);
                console.log(`  +0x170 (Lock Structure Addr?): ${pAmmoContainerComponent.add(0x170)}`); // Just show address

                // Read related component pointer
                const pRelatedComponent = safeReadPointer(pAmmoContainerComponent.add(0x40));
                console.log(`  +0x040 (Related Component Ptr): ${pRelatedComponent}`);

                if (pRelatedComponent && !pRelatedComponent.isNull()) {
                    console.log(`    --- Inferred Data from Related Component (${pRelatedComponent}) ---`);
                    console.log(`    +0x58 (Field 88 for Notify?): ${safeReadU32(pRelatedComponent.add(0x58))}`);
                    console.log(`    +0x5A (Float for SSE?):       ${safeReadFloat(pRelatedComponent.add(0x5A))}`);
                    const strPtrAddr = pRelatedComponent.add(0x60);
                    const strPtr = safeReadPointer(strPtrAddr);
                    const strVal = strPtr ? (strPtr.isNull() ? "NULL" : strPtr.readCString()) : "READ_ERROR";
                    console.log(`    +0x60 (String Ptr for Geom?): ${strPtr} -> "${strVal}"`);
                    console.log(`    +0x98 (List Info Ptr?):       ${safeReadPointer(pRelatedComponent.add(0x98))}`);
                    console.log(`    +0xB0 (Field 176 Ptr?):       ${safeReadPointer(pRelatedComponent.add(0xB0))}`);
                    console.log(`    +0xE0 (Field 224 Ptr?):       ${safeReadPointer(pRelatedComponent.add(0xE0))}`);
                    console.log(`    --- End Related Component Data ---`);
                } else {
                    console.log("    Related Component Pointer is NULL or read error.");
                }

            } catch (e) {
                console.error(`  Error reading inferred data: ${e}`);
                console.error(e.stack); // Print stack trace for debugging
            }
            console.log("--- End Inferred Data ---");
            console.log("=====================================================\n");
        },

        onLeave: function(retval) {
            // Optional: Log return value if needed
            // console.log(`SetAmmoCountAndUpdateState returned: ${retval}`);
        }
    });

    console.log("[+] Hook attached successfully. Waiting for calls...");
}