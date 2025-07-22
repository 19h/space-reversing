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
 * - Adjust MODULE_BASE and offsets if the game version changes (verify via disassembler like IDA/Ghidra).
 *
 * Caveats:
 * - Assumes x64 architecture and Windows environment.
 * - Offsets are relative to the module's image base (0x140000000).
 * - Filters out slices containing '123presence' (case-insensitive) to reduce noise (e.g., presence heartbeats).
 * - Logs to console; redirect output if needed (e.g., frida-trace > log.txt).
 */

// Constants for clarity and easy maintenance
const MODULE_NAME = 'StarCitizen.exe';
const MODULE_BASE = ptr('0x140000000');
const DO_READ_OFFSET = ptr('0x14791E9E0').sub(MODULE_BASE);
const WRITE_SLICE_OFFSET = ptr('0x1478E0950').sub(MODULE_BASE);
const FILTER_KEYWORD = 'presence'; // Skip dumping if slice contains this (lowercase match)

// Helper function to get module base address with error handling
function getModuleBase() {
    const module = Process.getModuleByName(MODULE_NAME);
    if (!module) {
        throw new Error(`Could not find module: ${MODULE_NAME}`);
    }
    return module.base;
}

/**
 * Parses and dumps a gRPC slice.
 *
 * @param {NativePointer} slicePtr - Pointer to the grpc_slice structure.
 * @param {string} direction - 'RECV' or 'SEND' for logging prefix.
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
            return; // Skip empty or invalid slices
        }

        // Read data as byte array and convert to string for filtering
        const bufferData = dataPtr.readByteArray(dataLen);
        const bufferString = Array.from(new Uint8Array(bufferData))
            .map(byte => String.fromCharCode(byte))
            .join('')
            .toLowerCase();

        // Filter: Skip if contains specific keyword (e.g., noise reduction)
        if (bufferString.includes(FILTER_KEYWORD)) {
            return;
        }

        // Log with timestamp for traceability
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${direction}] Slice @ ${slicePtr}: Length=${dataLen}`);
        console.log(hexdump(dataPtr, { length: dataLen, ansi: true }));
    } catch (error) {
        console.error(`[${new Date().toISOString()}] [!] Error parsing slice at ${slicePtr}: ${error.message}`);
        console.error(error.stack);
    }
}

/**
 * Main initialization function to set up hooks.
 */
function initializeHooks() {
    const baseAddr = getModuleBase();
    const doReadPtr = baseAddr.add(DO_READ_OFFSET);
    const writeSlicePtr = baseAddr.add(WRITE_SLICE_OFFSET);

    console.log(`[+] Module base address: ${baseAddr}`);
    console.log(`[+] Hooking RECEIVE function (do_read) at: ${doReadPtr}`);
    console.log(`[+] Hooking SEND function (write_slice) at: ${writeSlicePtr}`);

    // Hook for RECEIVING data (chttp2_transport_do_read)
    Interceptor.attach(doReadPtr, {
        onEnter: function (args) {
            const errorPtr = args[1];
            const errorValue = errorPtr.readPointer();

            if (errorValue.isNull()) {
                this.transportObj = args[0]; // Preserve transport object
            }
        },
        onLeave: function () {
            if (!this.transportObj) {
                return; // No valid transport object
            }

            const transportObj = this.transportObj;
            const bufferArrayPtr = transportObj.add(0x1B0).readPointer();
            const bufferCount = transportObj.add(0x1B8).readU64();

            if (bufferCount > 0) {
                const timestamp = new Date().toISOString();
                console.log(`\n[${timestamp}] <-- [RECEIVE] chttp2_transport_do_read called with ${bufferCount} buffer(s)`);
                for (let i = 0; i < bufferCount; i++) {
                    const slicePtr = bufferArrayPtr.add(i * 0x20);
                    dumpGrpcSlice(slicePtr, 'RECV');
                }
                console.log(`[${timestamp}] <-- [RECEIVE] End of received data\n`);
            }
        }
    });

    // Hook for SENDING data (chttp2_writing_buffer_add)
    Interceptor.attach(writeSlicePtr, {
        onEnter: function (args) {
            const sliceToAppendPtr = args[1];
            const timestamp = new Date().toISOString();
            console.log(`\n[${timestamp}] --> [SEND] Queuing data for sending (chttp2_writing_buffer_add)`);
            dumpGrpcSlice(sliceToAppendPtr, 'SEND');
            console.log(`[${timestamp}] --> [SEND] End of sent data\n`);
        }
    });
}

// Execute initialization
try {
    initializeHooks();
} catch (error) {
    console.error(`[!] Initialization failed: ${error.message}`);
    console.error(error.stack);
}
