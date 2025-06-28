// Frida script to hook and analyze sub_144CF80B0 function
// This function appears to handle deposit operations in a kiosk shop provider

var targetAddress = ptr("0x144CF80B0");

// Hook the main function
Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        console.log("[+] sub_144CF80B0 called");
        console.log("    a1 (object ptr): " + args[0]);
        console.log("    a2 (DWORD ptr): " + args[1]);

        // Store context for onLeave
        this.a1 = args[0];
        this.a2 = args[1];

        // Read the state value at offset 0x1C0
        var state = Memory.readU32(args[0].add(0x1C0));
        console.log("    Current state: " + state);

        // Read the value pointed to by a2
        if (args[1] && !args[1].isNull()) {
            try {
                var a2_value = Memory.readU32(args[1]);
                console.log("    *a2 value: " + a2_value);
            } catch (e) {
                console.log("    Failed to read *a2: " + e.message);
            }
        }

        // Log which branch will be taken
        if (state === 4) {
            console.log("    -> Branch: State is 4, function will return early");
        } else if (state === 3) {
            console.log("    -> Branch: State is 3, checking deposit conditions");

            // Try to get the size comparison value
            try {
                var sizePtr = args[0].add(0x5B0);
                console.log("    WriteBytesMem at: " + sizePtr);
            } catch (e) {
                console.log("    Failed to access WriteBytesMem: " + e.message);
            }
        } else {
            console.log("    -> Branch: State is " + state + ", kiosk not ready");
        }
    },

    onLeave: function(retval) {
        console.log("[+] sub_144CF80B0 returning");

        // Check if state changed during execution
        try {
            var finalState = Memory.readU32(this.a1.add(0x1C0));
            console.log("    Final state: " + finalState);
        } catch (e) {
            console.log("    Failed to read final state: " + e.message);
        }
    }
});

// Hook the callback function sub_144E071C0 if it gets called
var callbackAddress = ptr("0x144E071C0");
Interceptor.attach(callbackAddress, {
    onEnter: function(args) {
        console.log("[+] Callback sub_144E071C0 triggered");
        console.log("    This indicates successful deposit processing");
    }
});

// Hook the logging function invokeGlobalCallbackAndMaskStatusBits
var loggingFunctions = [
    "invokeGlobalCallbackAndMaskStatusBits",
    "getThreadLogContextSlot",
    "sub_144BE9480",
    "sub_140A5ABB0"
];

// Try to find and hook common logging/error handling functions
loggingFunctions.forEach(function(funcName) {
    try {
        var funcPtr = Module.findExportByName(null, funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    console.log("[!] " + funcName + " called - likely an error condition");
                    if (args.length > 2) {
                        try {
                            var errorMsg = Memory.readCString(args[2]);
                            console.log("    Error context: " + errorMsg);
                        } catch (e) {
                            console.log("    Could not read error message");
                        }
                    }
                }
            });
        }
    } catch (e) {
        // Function not found, continue
    }
});

// // Hook memory operations to track important data structures
// var memoryOperations = [
//     "sub_140525200",  // Appears to be initialization
//     "sub_144BB21F0",  // Appears to be configuration
//     "sub_1403B0A70",  // Appears to be entity handling
//     "sub_1402A3D30"   // Appears to be cleanup
// ];

// memoryOperations.forEach(function(funcName) {
//     try {
//         var funcPtr = ptr("0x" + funcName.substring(4)); // Remove "sub_" prefix
//         Interceptor.attach(funcPtr, {
//             onEnter: function(args) {
//                 console.log("[*] " + funcName + " called");
//                 console.log("    arg0: " + args[0]);
//                 if (args.length > 1) {
//                     console.log("    arg1: " + args[1]);
//                 }
//             }
//         });
//     } catch (e) {
//         // Address not valid, continue
//     }
// });

// Monitor specific memory regions for changes
function monitorMemoryRegion(basePtr, offset, size, name) {
    try {
        var addr = basePtr.add(offset);
        var originalValue = Memory.readByteArray(addr, size);

        // Set up a periodic check (this is a simplified approach)
        setInterval(function() {
            try {
                var currentValue = Memory.readByteArray(addr, size);
                if (JSON.stringify(originalValue) !== JSON.stringify(currentValue)) {
                    console.log("[~] " + name + " changed at " + addr);
                    console.log("    Old: " + hexdump(originalValue));
                    console.log("    New: " + hexdump(currentValue));
                    originalValue = currentValue;
                }
            } catch (e) {
                // Memory no longer accessible
            }
        }, 1000);
    } catch (e) {
        console.log("Failed to monitor " + name + ": " + e.message);
    }
}

// Helper function to dump relevant memory regions when the function is called
function dumpKioskState(objectPtr) {
    try {
        console.log("[DEBUG] Kiosk Object State Dump:");
        console.log("  State (0x1C0): " + Memory.readU32(objectPtr.add(0x1C0)));
        console.log("  Request ID (0x1C8): " + Memory.readU64(objectPtr.add(0x1C8)));
        console.log("  Entity ID (0x3A8): " + Memory.readU64(objectPtr.add(0x3A8)));
        console.log("  Flags (0x3B0): " + Memory.readU16(objectPtr.add(0x3B0)));
        console.log("  Function ptr (0x390): " + Memory.readPointer(objectPtr.add(0x390)));
        console.log("  Function type (0x398): " + Memory.readU64(objectPtr.add(0x398)));
    } catch (e) {
        console.log("[DEBUG] Failed to dump kiosk state: " + e.message);
    }
}

console.log("[*] Frida script loaded - monitoring CPrisonDepositKioskShopProvider::DepositAllPersonalCommodities");
console.log("[*] Target function: " + targetAddress);
