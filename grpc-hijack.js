// grpc_injector.js

console.log("[*] Starting gRPC injector for Star Citizen...");

const baseAddr = Process.getModuleByName('StarCitizen.exe').base;
if (!baseAddr) {
    throw new Error("Could not find base address for StarCitizen.exe.");
}

const moduleBase = ptr("0x140000000");
const writeSliceOffset = ptr("0x1478E0950").sub(moduleBase);
const writeSlicePtr = baseAddr.add(writeSliceOffset);

// --- Globals to store the context of the last RPC ---
let lastTransportObj = null;
let lastStreamId = 0;

// --- Create a NativeFunction for the game's internal send function ---
const writeSliceFunc = new NativeFunction(writeSlicePtr, 'void', ['pointer', 'pointer']);
console.log(`[+] NativeFunction for write_slice created at ${writeSlicePtr}`);

/**
 * Creates a `grpc_slice` structure in memory containing the given payload.
 * This mimics the internal structure used by gRPC's C-core.
 * @param {ArrayBuffer} payload - The raw bytes to be wrapped in a slice.
 * @returns {Pointer} A pointer to the allocated grpc_slice structure.
 */
function createGrpcSlice(payload) {
    const payloadBytes = new Uint8Array(payload);
    const payloadLen = payloadBytes.length;

    // 1. Allocate memory for the payload itself
    const payloadMem = Memory.alloc(payloadLen);
    payloadMem.writeByteArray(payloadBytes);

    // 2. Allocate memory for the refcount object. It's a simple structure.
    // We just need to allocate it; its contents aren't critical for this purpose.
    const refcountMem = Memory.alloc(16); // A small buffer is fine

    // 3. Allocate memory for the grpc_slice structure itself (size is 0x18 or 24 bytes)
    const sliceMem = Memory.alloc(24);

    // 4. Populate the grpc_slice structure
    sliceMem.writePointer(refcountMem);      // offset 0x0: pointer to refcount
    sliceMem.add(8).writeU64(payloadLen);    // offset 0x8: length of the data
    sliceMem.add(16).writePointer(payloadMem); // offset 0x10: pointer to the data

    return sliceMem;
}

/**
 * Constructs the full HTTP/2 DATA frame and injects it.
 * @param {Pointer} transportObj - The active transport object pointer.
 * @param {number} streamId - The active stream ID for the RPC.
 * @param {Array} payloadBytes - The raw Protobuf payload as an array of bytes.
 */
function sendGrpcMessage(transportObj, streamId, payloadBytes) {
    if (!transportObj || streamId === 0) {
        console.error("[!] Cannot inject: No valid transport or stream ID captured yet.");
        console.error("[!] Please trigger an in-game action that makes a gRPC call first.");
        return;
    }

    console.log(`[*] Preparing to inject ${payloadBytes.length} byte payload on stream ${streamId}...`);

    // 1. Create the gRPC Length-Prefixed Frame
    const grpcFrameLen = 5 + payloadBytes.length;
    const grpcFrame = new ArrayBuffer(grpcFrameLen);
    const grpcView = new DataView(grpcFrame);
    grpcView.setUint8(0, 0x00); // Compression flag: uncompressed
    grpcView.setUint32(1, payloadBytes.length, false); // Message length (big-endian)
    new Uint8Array(grpcFrame, 5).set(payloadBytes);

    // 2. Create the HTTP/2 DATA Frame
    const http2FrameLen = 9 + grpcFrameLen;
    const http2Frame = new ArrayBuffer(http2FrameLen);
    const http2View = new DataView(http2Frame);
    // Frame Length (24-bit, big-endian)
    http2View.setUint8(0, (grpcFrameLen >> 16) & 0xFF);
    http2View.setUint16(1, grpcFrameLen & 0xFFFF, false);
    http2View.setUint8(3, 0x00); // Frame Type: DATA
    http2View.setUint8(4, 0x00); // Flags: None (more data might follow)
    http2View.setUint32(5, streamId, false); // Stream ID (big-endian)
    new Uint8Array(http2Frame, 9).set(new Uint8Array(grpcFrame));

    console.log("[*] Constructed HTTP/2 DATA frame:");
    console.log(hexdump(http2Frame, { ansi: true }));

    // 3. Create the grpc_slice and call the native function
    const sliceToSend = createGrpcSlice(http2Frame);
    console.log(`[*] Calling writeSliceFunc(${transportObj}, ${sliceToSend})`);
    writeSliceFunc(transportObj, sliceToSend);
    console.log("[+] Injection call complete!");
}

// --- Hook the send function to capture context ---
Interceptor.attach(writeSlicePtr, {
    onEnter: function(args) {
        const transportObj = args[0];
        const slicePtr = args[1];

        // Read the slice to see if it's a HEADERS frame, from which we can get a stream ID
        try {
            const refcountPtr = slicePtr.readPointer();
            if (!refcountPtr.isNull()) {
                const dataLen = slicePtr.add(8).readU64().toNumber();
                const dataPtr = slicePtr.add(16).readPointer();

                if (dataLen >= 9) {
                    const frameType = dataPtr.add(3).readU8();
                    if (frameType === 0x1) { // HTTP/2 HEADERS frame
                        const streamId = dataPtr.add(5).readU32(); // Stream ID is big-endian
                        if (streamId % 2 !== 0) { // Client streams are odd
                            console.log(`[*] Captured new client stream context: transport=${transportObj}, streamId=${streamId}`);
                            lastTransportObj = transportObj;
                            lastStreamId = streamId;
                        }
                    }
                }
            }
        } catch (e) { /* Ignore errors, we only care about valid frames */ }
    }
});

// --- Expose the injection function to be called from the Frida REPL ---
rpc.exports = {
    /**
     * Injects a gRPC message.
     * @param {Array} payload - An array of bytes representing the serialized Protobuf message.
     */
    inject: function(payload) {
        sendGrpcMessage(lastTransportObj, lastStreamId, payload);
    }
};
