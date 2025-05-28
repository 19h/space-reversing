// Comprehensive Frida hook for sub_14627E2E0 - CSCLocalPlayerPersonalThoughtComponent::AddInventoryManagementMove
// This function appears to handle inventory management operations for a player

const MODULE_BASE = Process.enumerateModulesSync()[0].base;

// Global state tracking
let hookState = {
    callCount: 0,
    activeInvocations: new Map(),
    inventoryHistory: []
};

// Helper function to safely read strings
function safeReadString(ptr) {
    try {
        if (ptr.isNull()) return "NULL";
        return ptr.readUtf8String() || ptr.readAnsiString() || "INVALID_STRING";
    } catch (e) {
        return `ERROR_READING_STRING@${ptr}`;
    }
}

// Helper function to safely read pointers
function safeReadPointer(ptr) {
    try {
        if (ptr.isNull()) return ptr("0x0");
        return ptr.readPointer();
    } catch (e) {
        return ptr("0x0");
    }
}

// Helper function to read entity handle and extract entity info
function readEntityHandle(handlePtr) {
    try {
        if (handlePtr.isNull()) return { handle: "NULL", entity: null, name: "NULL" };
        
        // Read the handle value (8 bytes)
        const handle = handlePtr.readU64();
        // Mask to lower 48 bits to get actual pointer
        const mask = uint64("0xFFFFFFFFFFFF");
        const maskedValue = handle.and(mask);
        const maskedHandle = ptr(maskedValue.toString());

        console.log(`Handle: 0x${handle.toString(16)}, Mask: 0x${mask.toString(16)}, Masked: 0x${maskedValue.toString(16)} -> ${maskedHandle}`);
        
        if (maskedHandle.equals(ptr("0x0"))) {
            return { handle: handle.toString(16), entity: null, name: "NULL" };
        }
        
        // Try to read actor entity at masked handle + 8
        const actorEntityPtr = maskedHandle.add(0x8).readPointer();
        if (!actorEntityPtr.isNull()) {
            // Read entity pointer at offset 0xC0 in CActorEntity
            const entityPtr = actorEntityPtr.add(0xC0).readPointer();
            if (!entityPtr.isNull()) {
                // Try to read entity name at offset 0x3E8
                const namePtr = entityPtr.add(0x298).readPointer();
                const name = safeReadString(namePtr);
                return { 
                    handle: handle.toString(16), 
                    entity: entityPtr.toString(), 
                    name: name 
                };
            }
        }
        
        return { handle: handle.toString(16), entity: "INVALID", name: "INVALID" };
    } catch (e) {
        console.log(`[!] Error reading entity handle: ${e}`);
        console.log(e.stack);
        return { handle: "ERROR", entity: "ERROR", name: "ERROR" };
    }
}

// Helper to read inventory data structure (24 bytes)
function readInventoryData(ptr) {
    try {
        if (ptr.isNull()) return "NULL_INVENTORY";
        
        const data = {
            field1: ptr.readU64().toString(16),
            field2: ptr.add(0x8).readU64().toString(16),
            field3: ptr.add(0x10).readU64().toString(16)
        };
        
        return `{${data.field1}, ${data.field2}, ${data.field3}}`;
    } catch (e) {
        return "ERROR_READING_INVENTORY";
    }   
}

// Hook the function
const targetAddress = MODULE_BASE.add(0x627E2E0);

console.log(`[*] Hooking CSCLocalPlayerPersonalThoughtComponent::AddInventoryManagementMove at ${targetAddress}`);

Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        const invocationId = ++hookState.callCount;
        const startTime = Date.now();
        const threadId = Process.getCurrentThreadId();
        
        console.log("\n=== CSCLocalPlayerPersonalThoughtComponent::AddInventoryManagementMove ===");
        
        // a1: this pointer (CSCLocalPlayerPersonalThoughtComponent)
        const thisPtr = args[0];
        console.log(`[+] this: ${thisPtr}`);
        
        // Try to read player entity from this+8
        const playerHandle = readEntityHandle(thisPtr.add(0x8));
        console.log(`[+] Player Entity: Handle=${playerHandle.handle}, Entity=${playerHandle.entity}, Name="${playerHandle.name}"`);
        
        // a2: operation type (int)
        const operationType = args[1].toInt32();
        console.log(`[+] Operation Type: ${operationType}`);
        
        // src: source inventory data (24 bytes)
        const srcInventory = readInventoryData(args[2]);
        console.log(`[+] Source Inventory: ${srcInventory}`);
        
        // a4: pointer to some handle/entity data
        const a4Ptr = args[3];
        let a4Handle = null;
        if (!a4Ptr.isNull()) {
            a4Handle = readEntityHandle(a4Ptr);
            console.log(`[+] A4 Entity: Handle=${a4Handle.handle}, Entity=${a4Handle.entity}, Name="${a4Handle.name}"`);
        } else {
            console.log(`[+] A4 Entity: NULL`);
        }
        
        // src_1: target inventory data (24 bytes)
        const targetInventory = readInventoryData(args[4]);
        console.log(`[+] Target Inventory: ${targetInventory}`);
        
        // a6: another pointer to handle/entity data
        const a6Ptr = args[5];
        let a6Handle = null;
        if (!a6Ptr.isNull()) {
            a6Handle = readEntityHandle(a6Ptr);
            console.log(`[+] A6 Entity: Handle=${a6Handle.handle}, Entity=${a6Handle.entity}, Name="${a6Handle.name}"`);
        } else {
            console.log(`[+] A6 Entity: NULL`);
        }
        
        // Try to read additional context from the component
        let componentFields = {};
        try {
            // Read some fields from the component structure
            componentFields.field368 = safeReadPointer(thisPtr.add(0x368));
            componentFields.field380 = safeReadPointer(thisPtr.add(0x380));
            componentFields.field3A8 = safeReadPointer(thisPtr.add(0x3A8));
            componentFields.field2F0 = safeReadPointer(thisPtr.add(0x2F0));
            
            console.log(`[+] Component Fields: 0x368=${componentFields.field368}, 0x380=${componentFields.field380}, 0x3A8=${componentFields.field3A8}, 0x2F0=${componentFields.field2F0}`);
        } catch (e) {
            console.log(`[!] Error reading component fields: ${e}`);
        }
        
        // Store invocation data in the Map using thread ID as key
        hookState.activeInvocations.set(threadId, {
            invocationId,
            startTime,
            thisPtr: thisPtr,
            operationType: operationType,
            srcInventory: srcInventory,
            targetInventory: targetInventory,
            playerHandle: playerHandle,
            a4Handle: a4Handle,
            a6Handle: a6Handle,
            componentFields: componentFields
        });
    },
    
    onLeave: function(retval) {
        const threadId = Process.getCurrentThreadId();
        const invocationData = hookState.activeInvocations.get(threadId);
        
        if (!invocationData) {
            console.error('[!] No invocation data found for thread ' + threadId);
            return;
        }
        
        const duration = Date.now() - invocationData.startTime;
        const requestId = retval.toInt32();
        console.log(`[+] Request ID returned: ${requestId}`);
        
        // Try to read any state changes in the component
        try {
            const field2F0After = safeReadPointer(invocationData.thisPtr.add(0x2F0));
            console.log(`[+] Component field 0x2F0 after: ${field2F0After}`);
        } catch (e) {
            console.log(`[!] Error reading post-call state: ${e}`);
        }
        
        console.log(`[+] Inventory move operation completed: Type=${invocationData.operationType}, RequestID=${requestId}, Duration=${duration}ms`);
        console.log("=== End AddInventoryManagementMove ===\n");
        
        // Store in history
        hookState.inventoryHistory.push({
            timestamp: Date.now(),
            invocationId: invocationData.invocationId,
            operationType: invocationData.operationType,
            requestId: requestId,
            duration: duration,
            playerName: invocationData.playerHandle.name
        });
        
        // Keep only last 100 entries
        if (hookState.inventoryHistory.length > 100) {
            hookState.inventoryHistory.shift();
        }
        
        // Clean up the invocation data
        hookState.activeInvocations.delete(threadId);
    }
});

// Also hook some related functions that might be called
const relatedFunctions = [
    //{ name: "sub_1402AE3D0", offset: 0x02AE3D0 },  // Logging/context setup
    //{ name: "sub_14190ED50", offset: 0x190ED50 },  // Some data structure operation
    { name: "sub_146265B10", offset: 0x6265B10 },  // Request ID generation
    { name: "sub_14626A6F0", offset: 0x626A6F0 },  // Handle processing
];

for (const func of relatedFunctions) {
    try {
        const addr = MODULE_BASE.add(func.offset);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log(`[→] ${func.name} called with args: ${args[0]}, ${args[1]}, ${args[2]}`);
            }
        });
        console.log(`[*] Hooked ${func.name} at ${addr}`);
    } catch (e) {
        console.log(`[!] Failed to hook ${func.name}: ${e}`);
    }
}

// Command interface for runtime analysis
rpc.exports = {
    getInventoryHistory: function() {
        return hookState.inventoryHistory;
    },
    
    getCallCount: function() {
        return hookState.callCount;
    },
    
    resetStats: function() {
        hookState.callCount = 0;
        hookState.inventoryHistory = [];
        console.log('[*] Inventory statistics reset');
    }
};

console.log("[*] All hooks installed for inventory management system");
