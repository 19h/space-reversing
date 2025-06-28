// /*
//  * Frida Interceptor for Remote Method Call (RPC) Analysis - v2 (Corrected)
//  * =========================================================================
//  *
//  * Target: Game/Application using the analyzed engine.
//  * Hook Address: 0x142432A30 (CEntityComponentNetwork::RecvRemoteMethodCall)
//  *
//  * Purpose:
//  * This script intercepts incoming remote method calls to provide detailed
//  * metadata. This version corrects pointer dereferencing based on analysis
//  * of the initial script's output and a deeper look at the decompiled code.
//  *
//  * Changelog from v1:
//  *  - Correctly resolves the SerializedComponent pointer from the NetworkComponent.
//  *  - Correctly reads the Entity Descriptor from the SerializedComponent.
//  *  - Correctly dereferences the stream object to find the true payload buffer.
//  *  - Correctly calculates payload size and locates the payload data.
//  *  - Added more robust error checking for null pointers.
//  */

// // --- Configuration ---
var MAX_CALLS = 50e100; // Detach after this many calls.
var PAYLOAD_DUMP_LENGTH = 64; // Number of bytes to hexdump.
var BASE_ADDRESS = Module.findBaseAddress('StarCitizen.exe'); // Adjust if needed.

// --- Globals ---
var interceptorHandle = null;
var callCount = 0;
var shouldDetach = false;

// --- Helper Functions (Unchanged, they were correct) ---

const PTR_SIZE = Process.pointerSize;

// Helper to extract lower 48 bits of a pointer
function extractLower48(ptrVal) {
    // Mask with 0xFFFFFFFFFFFF
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

// Helper to read a C-style UTF-8 string pointer
function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
}

// Helper to call a virtual method by vtable index
function callVFunc(thisPtr, index, returnType, argTypes, args = [], name = null) {
    try {
        if (thisPtr.isNull()) {
            throw new Error("Null pointer passed to callVFunc");
        }

        const vtable = thisPtr.readPointer();
        if (vtable.isNull()) {
            throw new Error("Null vtable pointer");
        }

        const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
        if (fnPtr.isNull()) {
            throw new Error(`Null function pointer at vtable index ${index}`);
        }

        const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
        console.log(fnPtr, name);
        return fn(thisPtr, ...args);
    } catch (e) {
        console.log(`callVFunc error at index ${index}${name ? ` (${name})` : ''}: ${e.message}`);
        throw e;
    }
}

class CEntityClass {
    constructor(ptr) { this.ptr = ptr; }
    get name() {
        const namePtr = this.ptr.add(0x10).readPointer();
        return readCString(namePtr);
    }
}

class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // flags_   at 0x08
    get flags() {
        return this.ptr.add(0x08).readS64();
    }

    // id_      at 0x10
    get id() {
        return this.ptr.add(0x10).readS64();
    }

    // entity_class_ at 0x20 (CEntityClass*)
    get entityClassPtr() {
        const raw = this.ptr.add(0x20).readPointer();
        return extractLower48(raw);
    }

    get entityClass() {
        const clsPtr = this.entityClassPtr;
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }

    // render_handle_ at 0x1E0
    get renderHandlePtr() {
        return this.ptr.add(0x1E0);
    }

    get renderHandle() {
        return this.renderHandlePtr.readPointer();
    }

    // x_local_pos_, y_local_pos_, z_local_pos_ at offsets 0xF8, 0x100, 0x108
    get zonePos() {
        const x = this.ptr.add(0xF8).readDouble();
        const y = this.ptr.add(0x100).readDouble();
        const z = this.ptr.add(0x108).readDouble();
        return new DVec3(x, y, z);
    }

    // name_ at 0x298 (const char*)
    get name() {
        const namePtr = this.ptr.add(0x298).readPointer();
        return readCString(namePtr);
    }
}

function readGuid(ptr) {
    try {
        if (ptr.isNull()) return "NULL_GUID";
        var bytes = ptr.readByteArray(16);
        var guid = new Uint8Array(bytes);
        var s = (i, len) => Array.from(guid.slice(i, i + len)).map(b => b.toString(16).padStart(2, '0')).join('');
        return `${s(0,4)}-${s(4,2)}-${s(6,2)}-${s(8,2)}-${s(10,6)}`;
    } catch (e) {
        return "INVALID_GUID_PTR";
    }
}

function readEntityDescriptor(ptr) {
    try {
        if (ptr.isNull()) return { raw: "0x0", id: "NULL", type: "NULL" };
        var descriptor = ptr.readU64();
        var entityId = descriptor.and(ptr('0xFFFFFFFFFFFF'));
        var entityType = descriptor.shr(48).and(0xFFFF);
        return {
            raw: descriptor,
            id: entityId,
            type: '0x' + entityType.toString(16).padStart(4, '0')
        };
    } catch (e) {
        return { raw: "INVALID_PTR", id: "ERROR", type: "ERROR" };
    }
}

/**
 * Resolves a method index to its name.
 * @param {NativePointer} serializedComponentPtr Pointer to the CSerializedComponent instance.
 * @param {number} methodIndex The index of the method to look up.
 * @returns {string} The method name or an error/unknown string.
 */
function getMethodName(serializedComponentPtr, methodIndex) {
    try {
        // The method table is directly within the SerializedComponent.
        // Offsets are relative to this component.
        var methodsBase = serializedComponentPtr.add(0x1E * 8).readPointer(); // offset 0x1E = a1[0x1E]
        var methodsEnd = serializedComponentPtr.add(0x1F * 8).readPointer();  // offset 0x1F = a1[0x1F]
        if (methodsBase.isNull()) return "MethodsBaseIsNull";

        var methodEntrySize = 0x38;
        var numMethods = methodsEnd.sub(methodsBase).toInt32() / methodEntrySize;

        if (methodIndex >= numMethods) {
            return `IndexOutOfBounds (${methodIndex} >= ${numMethods})`;
        }

        var methodEntry = methodsBase.add(methodIndex * methodEntrySize);
        var methodNamePtr = methodEntry.readPointer();

        return methodNamePtr.readCString() || "UnnamedMethod";
    } catch (e) {
        return `ErrorResolvingName: ${e.message}`;
    }
}

// --- Main Interceptor ---

var targetAddress = BASE_ADDRESS.add(0x142432A30 - 0x140000000);

console.log(`[+] Attaching to RPC handler at ${targetAddress}`);

interceptorHandle = Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        callCount++;
        if (shouldDetach) return;

        try {
            // --- Argument Parsing & Pointer Correction ---
            // args[0] (a1): `this` pointer for CEntityComponentNetwork
            // args[1] (a2): Pointer to the sender's __int128 network node ID
            // args[2] (a3): Pointer to a stream object
            var networkComponentPtr = args[0];
            var fromNodeIdPtr = args[1];
            var streamObjectPtr = args[2];

            // [FIX #1] Get the SerializedComponent from the NetworkComponent.
            var serializedComponentPtr = networkComponentPtr.add(0x98).readPointer();
            if (serializedComponentPtr.isNull()) {
                console.log(`\n[RPC Call #${callCount}] - SKIPPED (SerializedComponent is NULL)`);
                return;
            }

            // [FIX #2] Get the Entity Descriptor from the SerializedComponent.
            //var entityDescriptor = readEntityDescriptor(serializedComponentPtr.add(0x8));
            //var fromNodeId = readGuid(fromNodeIdPtr);
            const entity = new CEntity(networkComponentPtr.add(0x90).readPointer());
            const entity_name = entity.name;

            // --- Data Buffer Parsing ---
            // The method index is at offset +16 bytes (a3[8]) in the stream object.
            var methodIndex = streamObjectPtr.add(16).readU16();
            var methodName = getMethodName(serializedComponentPtr, methodIndex);

            // [FIX #3] Dereference the stream object to get the actual data buffer.
            var dataBuffer = streamObjectPtr.readPointer();
            if (dataBuffer.isNull()) {
                console.log(`\n[RPC Call #${callCount}] - SKIPPED (Data Buffer is NULL)`);
                return;
            }

            // [FIX #4] Read size and get payload pointer from the correct buffer.
            // The size is in BITS.
            var payloadSizeInBits = dataBuffer.readU32();
            var payloadSizeInBytes = Math.ceil(payloadSizeInBits / 8);
            // The payload starts 8 bytes into the data buffer.
            var payloadPtr = dataBuffer.add(8);

            // --- Logging ---
            console.log("\n" + `[RPC Call #${callCount}]`.padEnd(80, '-'));
            console.log(`  \x1b[36mTo Entity:\x1b[0m      ${entity.ptr} (${entity_name} Class: ${entity.entityClass.name})`);
            console.log(`  \x1b[33mMethod:\x1b[0m         ${methodName} (Index: ${methodIndex})`);
            console.log(`  \x1b[32mPayload Size:\x1b[0m   ${payloadSizeInBytes} bytes (${payloadSizeInBits} bits)`);

            if (payloadSizeInBytes > 0 && !payloadPtr.isNull()) {
                console.log(hexdump(payloadPtr, {
                    offset: 0, // Show relative offset
                    length: Math.min(payloadSizeInBytes, PAYLOAD_DUMP_LENGTH),
                    header: true,
                    ansi: true
                }));
            }

        } catch (e) {
            console.error(`[!] Error in onEnter for call #${callCount}: ${e.message}\n${e.stack}`);
        }

        // Auto-detach logic
        if (callCount >= MAX_CALLS) {
            console.log(`\n*** Auto-detaching interceptor after ${MAX_CALLS} calls. ***`);
            shouldDetach = true;
            setImmediate(function() {
                interceptorHandle.detach();
            });
        }
    }
});

console.log("[+] Interceptor attached. Waiting for remote method calls...");

// // Hook for CReplicationModel::SendRemoteMethodCall (sub_146E38130)
// var sendRpcAddress = BASE_ADDRESS.add(0x146E38130 - 0x140000000);

// console.log(`[+] Attaching to Send RPC handler at ${sendRpcAddress}`);

// var sendInterceptorHandle = Interceptor.attach(sendRpcAddress, {
//     onEnter: function(args) {
//         try {
//             // Function signature: __int64 __fastcall sub_146E38130(__int64 a1, __int64 a2, __int64 a3)
//             var thisPtr = args[0];        // a1 - CReplicationModel pointer
//             var entityPtr = args[1];      // a2 - Entity pointer/ID (encoded)
//             var methodCallPtr = args[2];  // a3 - Method call data pointer

//             console.log("\n" + `[SEND RPC Call]`.padEnd(80, '='));
//             console.log(`  \x1b[35mThis Ptr:\x1b[0m       ${thisPtr}`);
//             console.log(`  \x1b[36mEntity Handle:\x1b[0m  ${entityPtr}`);
//             console.log(`  \x1b[33mMethod Call:\x1b[0m    ${methodCallPtr}`);
//             console.log(methodCallPtr.readPointer(), methodCallPtr.readPointer().add(0x8));

//             // Try to decode entity information if pointer is valid
//             if (!entityPtr.isNull()) {
//                 try {
//                     // Extract entity ID from the encoded pointer (lower 48 bits)
//                     var entityPtr = entityPtr.and(ptr("0xFFFFFFFFFFFF"));
//                     var entityType = entityPtr.shr(48).and(0xFFFF);

//                     console.log(`  \x1b[32mEntity Ptr:\x1b[0m     ${entityPtr}`);
//                     console.log(`  \x1b[32mEntity Type:\x1b[0m    0x${entityType.toString(16).padStart(4, '0')}`);

//                     // Try to read entity name if it's a valid entity pointer
//                     if ((entityPtr.and(ptr("0xF000000000000000")).compare(ptr(0)) !== 0)) {
//                         // Entity has type encoding, try to get the actual pointer
//                         var actualEntityPtr = entityPtr;
//                         if (!actualEntityPtr.isNull()) {
//                             try {
//                                 var entity = new CEntity(actualEntityPtr);
//                                 var entityName = entity.name;
//                                 var entityClassName = entity.entityClass ? entity.entityClass.name : "Unknown";
//                                 console.log(`  \x1b[34mEntity Name:\x1b[0m    ${entityName || 'Unnamed'}`);
//                                 console.log(`  \x1b[34mEntity Class:\x1b[0m   ${entityClassName}`);
//                             } catch (e) {
//                                 console.log(`  \x1b[31mEntity Parse Error:\x1b[0m ${e.message}`);
//                             }
//                         }
//                     }
//                 } catch (e) {
//                     console.log(`  \x1b[31mEntity Decode Error:\x1b[0m ${e.message}`);
//                 }
//             }

//             // Try to read method call data
//             if (!methodCallPtr.isNull()) {
//                 try {
//                     // Dump first 32 bytes of method call data
//                     console.log(`  \x1b[33mMethod Call Data:\x1b[0m`);
//                     console.log(hexdump(methodCallPtr, {
//                         offset: 0,
//                         length: 32,
//                         header: true,
//                         ansi: true
//                     }));
//                 } catch (e) {
//                     console.log(`  \x1b[31mMethod Call Data Error:\x1b[0m ${e.message}`);
//                 }
//             }

//         } catch (e) {
//             console.error(`[!] Error in Send RPC onEnter: ${e.message}\n${e.stack}`);
//         }
//     },

//     onLeave: function(retval) {
//         try {
//             console.log(`  \x1b[37mReturn Value:\x1b[0m   ${retval}`);
//         } catch (e) {
//             console.error(`[!] Error in Send RPC onLeave: ${e.message}`);
//         }
//     }
// });

// console.log("[+] Send RPC Interceptor attached. Waiting for outgoing method calls...");
