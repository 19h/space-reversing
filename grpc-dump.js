// Strict mode for better error handling and security
'use strict';
/**
 * @fileoverview
 * Frida script for hooking and dumping bidirectional gRPC communication in StarCitizen.exe.
 *
 * Purpose: Intercepts receive (do_read) and send (write_slice) functions to parse and log gRPC slices.
 * This aids in debugging network traffic, such as protobuf-encoded messages in games using gRPC.
 *
 * Usage:
 * - Attach Frida to the process: frida -U -f StarCitizen.exe -l this_script.js --no-pause
 * - Adjust signatures if the game version changes (verify via disassembler like IDA/Ghidra).
 *
 * Caveats:
 * - Assumes x64 architecture and Windows environment.
 * - Signatures are used to find function addresses dynamically.
 * - Filters out slices containing '123presence' (case-insensitive) to reduce noise (e.g., presence heartbeats).
 * - Logs to console; redirect output if needed (e.g., frida-trace > log.txt).
 */
// Constants for clarity and easy maintenance
const MODULE_NAME = 'StarCitizen.exe';
const DO_READ_SIG = '40 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 4C 8B F2 48 8B F9';
const WRITE_SLICE_SIG = '40 56 57 41 56 41 57 48 83 EC ?? 4C 8B 79';
const FILTER_KEYWORD_EXCLUDE = ['presence'];
const FILTER_KEYWORD_INCLUDE = [];
const FILTER_KEYWORD_HARD_BLOCK = ['@timestamp', 'traceproduct'];
const ENABLE_HARD_BLOCK = true; // Set to false to disable hard blocking
// Helper function to get module base address with error handling
function getModuleBase() {
    const module = Process.getModuleByName(MODULE_NAME);
    if (!module) {
        throw new Error(`Could not find module: ${MODULE_NAME}`);
    }
    return module.base;
}
/**
 * Checks if a slice should be hard blocked based on keywords.
 *
 * @param {NativePointer} slicePtr - Pointer to the grpc_slice structure.
 * @returns {boolean} - Returns true if the slice should be blocked.
 */
function shouldBlockSlice(slicePtr) {
    if (!ENABLE_HARD_BLOCK || FILTER_KEYWORD_HARD_BLOCK.length === 0) {
        return false;
    }
    try {
        const refcountPtr = slicePtr.readPointer();
        let dataPtr;
        let dataLen;
        if (refcountPtr.isNull()) {
            // Inlined slice: length at +8 (1 byte), data at +9
            dataLen = slicePtr.add(8).readU8();
            dataPtr = slicePtr.add(9);
        } else {
            // Refcounted slice: length at +8 (uint64), data pointer at +16
            dataLen = slicePtr.add(8).readU64();
            dataPtr = slicePtr.add(16).readPointer();
        }
        if (dataPtr.isNull() || dataLen === 0) {
            return false; // Don't block empty or invalid slices
        }
        // Read data as byte array and convert to string for filtering
        const bufferData = dataPtr.readByteArray(dataLen);
        const bufferString = Array.from(new Uint8Array(bufferData))
            .map(byte => String.fromCharCode(byte))
            .join('')
            .toLowerCase();
        // Check if any hard block keyword is found
        return FILTER_KEYWORD_HARD_BLOCK.some(keyword => bufferString.includes(keyword));
    } catch (error) {
        return false; // Don't block on error to be safe
    }
}
/**
 * Parses and dumps a gRPC slice.
 *
 * @param {NativePointer} slicePtr - Pointer to the grpc_slice structure.
 * @param {string} direction - 'RECV' or 'SEND' for logging prefix.
 * @returns {boolean} - Returns true if the slice was logged, false if filtered out.
 */
function dumpGrpcSlice(slicePtr, direction) {
    try {
        const refcountPtr = slicePtr.readPointer();
        let dataPtr;
        let dataLen;
        if (refcountPtr.isNull()) {
            // Inlined slice: length at +8 (1 byte), data at +9
            dataLen = slicePtr.add(8).readU8();
            dataPtr = slicePtr.add(9);
        } else {
            // Refcounted slice: length at +8 (uint64), data pointer at +16
            dataLen = slicePtr.add(8).readU64();
            dataPtr = slicePtr.add(16).readPointer();
        }
        if (dataPtr.isNull() || dataLen === 0) {
            return false; // Skip empty or invalid slices
        }
        // Read data as byte array and convert to string for filtering
        const bufferData = dataPtr.readByteArray(dataLen);
        const bufferString = Array.from(new Uint8Array(bufferData))
            .map(byte => String.fromCharCode(byte))
            .join('')
            .toLowerCase();
        if (FILTER_KEYWORD_INCLUDE.length && !FILTER_KEYWORD_INCLUDE.some(keyword => bufferString.includes(keyword))) {
            return false;
        }
        if (FILTER_KEYWORD_EXCLUDE.length && FILTER_KEYWORD_EXCLUDE.some(keyword => bufferString.includes(keyword))) {
            return false;
        }
        // Log with timestamp for traceability
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${direction}] Slice @ ${slicePtr}: Length=${dataLen}`);
        console.log(hexdump(dataPtr, { length: dataLen, ansi: true }));
        return true;
    } catch (error) {
        console.error(`[${new Date().toISOString()}] [!] Error parsing slice at ${slicePtr}: ${error.message}`);
        console.error(error.stack);
        return false;
    }
}
/**
 * Main initialization function to set up hooks.
 */
function initializeHooks() {
    const baseAddr = getModuleBase();
    const module = Process.getModuleByName(MODULE_NAME);
    const size = module.size;

    // Scan for do_read function
    const doReadMatches = Memory.scanSync(baseAddr, size, DO_READ_SIG);
    if (doReadMatches.length !== 1) {
        throw new Error(`Error: Found ${doReadMatches.length} matches for do_read signature (expected 1)`);
    }
    const doReadPtr = doReadMatches[0].address;

    // Scan for write_slice function
    const writeSliceMatches = Memory.scanSync(baseAddr, size, WRITE_SLICE_SIG);
    if (writeSliceMatches.length !== 1) {
        throw new Error(`Error: Found ${writeSliceMatches.length} matches for write_slice signature (expected 1)`);
    }
    const writeSlicePtr = writeSliceMatches[0].address;

    console.log(`[+] Module base address: ${baseAddr}`);
    console.log(`[+] Found and hooking RECEIVE function (do_read) at: ${doReadPtr}`);
    console.log(`[+] Hard blocking enabled: ${ENABLE_HARD_BLOCK}`);
    if (ENABLE_HARD_BLOCK && FILTER_KEYWORD_HARD_BLOCK.length > 0) {
        console.log(`[+] Found and replacing SEND function (write_slice) at: ${writeSlicePtr} with blocking implementation`);
        // Store original function for non-blocked messages
        const originalWriteSlice = new NativeFunction(writeSlicePtr, 'void', ['pointer', 'pointer']);
        // Replace the write_slice function with our blocking implementation
        Interceptor.replace(writeSlicePtr, new NativeCallback((transportObj, slicePtr) => {
            // Check if this slice should be blocked
            if (shouldBlockSlice(slicePtr)) {
                const timestamp = new Date().toISOString();
                console.log(`[${timestamp}] [!] BLOCKING outgoing message containing hard-block keywords`);
                return; // Block the message by not calling the original function
            } else {
                // Allow the message to pass through
                originalWriteSlice(transportObj, slicePtr);
                // Still log it if it passes other filters
                if (shouldLogSlice(slicePtr)) {
                    const timestamp = new Date().toISOString();
                    console.log(`\n[${timestamp}] --> [SEND] Queuing data for sending (chttp2_writing_buffer_add)`);
                    dumpGrpcSlice(slicePtr, 'SEND');
                    console.log(`[${timestamp}] --> [SEND] End of sent data\n`);
                }
            }
        }, 'void', ['pointer', 'pointer']));
    } else {
        console.log(`[+] Found and hooking SEND function (write_slice) at: ${writeSlicePtr}`);
        // Hook for SENDING data (chttp2_writing_buffer_add) - non-blocking mode
        Interceptor.attach(writeSlicePtr, {
            onEnter: function (args) {
                const sliceToAppendPtr = args[1];
                if (shouldLogSlice(sliceToAppendPtr)) {
                    const timestamp = new Date().toISOString();
                    console.log(`\n[${timestamp}] --> [SEND] Queuing data for sending (chttp2_writing_buffer_add)`);
                    dumpGrpcSlice(sliceToAppendPtr, 'SEND');
                    console.log(`[${timestamp}] --> [SEND] End of sent data\n`);
                }
            }
        });
    }
    // Hook for RECEIVING data (chttp2_transport_do_read)
    Interceptor.attach(doReadPtr, {
        onEnter: function (args) {
            const transportObj = args[0];
            const errorPtr = args[1];
            // Check if the read was successful (error pointer is null)
            if (errorPtr.readPointer().isNull()) {
                // The incoming buffer list is at offset 0x1A8 from the transport object.
                // The structure contains:
                // - 0x1B0: Pointer to the array of grpc_slice structures
                // - 0x1B8: The number of slices in the array
                const bufferArrayPtr = transportObj.add(0x1B0).readPointer();
                const bufferCount = transportObj.add(0x1B8).readU64().toNumber();
                if (bufferCount > 0) {
                    let hasLoggedData = false;
                    const timestamp = new Date().toISOString();
                    for (let i = 0; i < bufferCount; i++) {
                        // Each entry in the array is a grpc_slice structure (size 0x20)
                        const slicePtr = bufferArrayPtr.add(i * 0x20);
                        if (!hasLoggedData) {
                            // Check if any slice will be logged before printing header
                            for (let j = i; j < bufferCount; j++) {
                                const testSlicePtr = bufferArrayPtr.add(j * 0x20);
                                if (shouldLogSlice(testSlicePtr)) {
                                    console.log(`\n[${timestamp}] <-- [RECEIVE] Data received, ${bufferCount} buffer(s) available.`);
                                    hasLoggedData = true;
                                    break;
                                }
                            }
                        }
                        dumpGrpcSlice(slicePtr, 'RECV');
                    }
                    if (hasLoggedData) {
                        console.log(`[${timestamp}] <-- [RECEIVE] End of received data\n`);
                    }
                }
            }
        }
        // onLeave is no longer needed for this hook.
    });
}
/**
 * Helper function to check if a slice should be logged based on filters.
 *
 * @param {NativePointer} slicePtr - Pointer to the grpc_slice structure.
 * @returns {boolean} - Returns true if the slice should be logged.
 */
function shouldLogSlice(slicePtr) {
    try {
        const refcountPtr = slicePtr.readPointer();
        let dataPtr;
        let dataLen;
        if (refcountPtr.isNull()) {
            // Inlined slice: length at +8 (1 byte), data at +9
            dataLen = slicePtr.add(8).readU8();
            dataPtr = slicePtr.add(9);
        } else {
            // Refcounted slice: length at +8 (uint64), data pointer at +16
            dataLen = slicePtr.add(8).readU64();
            dataPtr = slicePtr.add(16).readPointer();
        }
        if (dataPtr.isNull() || dataLen === 0) {
            return false; // Skip empty or invalid slices
        }
        // Read data as byte array and convert to string for filtering
        const bufferData = dataPtr.readByteArray(dataLen);
        const bufferString = Array.from(new Uint8Array(bufferData))
            .map(byte => String.fromCharCode(byte))
            .join('')
            .toLowerCase();
        if (FILTER_KEYWORD_INCLUDE.length && !FILTER_KEYWORD_INCLUDE.some(keyword => bufferString.includes(keyword))) {
            return false;
        }
        if (FILTER_KEYWORD_EXCLUDE.length && FILTER_KEYWORD_EXCLUDE.some(keyword => bufferString.includes(keyword))) {
            return false;
        }
        return true;
    } catch (error) {
        return false;
    }
}
// Execute initialization
try {
    initializeHooks();
} catch (error) {
    console.error(`[!] Initialization failed: ${error.message}`);
    console.error(error.stack);
}
