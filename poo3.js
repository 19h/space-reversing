// Frida interceptor for gRPC slice buffer manipulation functions.
// Based on the provided assembly, we hook key functions in the gRPC slice buffer
// implementation to log buffer state and trace slice moves.

// --- Protobuf parsing helpers ---

// Reads a varint from the given Uint8Array at the specified offset.
// Returns an object with the decoded value and the number of bytes read.
function readVarint(view, offset) {
    var value = 0;
    var shift = 0;
    var length = 0;
    while (true) {
        var byte = view[offset + length];
        value |= (byte & 0x7F) << shift;
        length++;
        if ((byte & 0x80) === 0)
            break;
        shift += 7;
    }
    return { value: value, length: length };
}

// Parses a protobuf message from an ArrayBuffer.
// Returns an array of field objects { fieldNumber, wireType, value }.
// (For simplicity, 64-bit and 32-bit values are returned as byte arrays.)
function parseProtobufMessage(buffer) {
    var view = new Uint8Array(buffer);
    var offset = 0;
    var fields = [];
    while (offset < view.length) {
        var keyInfo = readVarint(view, offset);
        var key = keyInfo.value;
        offset += keyInfo.length;
        var fieldNumber = key >> 3;
        var wireType = key & 0x07;
        var field = { fieldNumber: fieldNumber, wireType: wireType };
        switch (wireType) {
            case 0: // varint
                var varintInfo = readVarint(view, offset);
                field.value = varintInfo.value;
                offset += varintInfo.length;
                break;
            case 1: // 64-bit
                field.value = Array.from(view.slice(offset, offset + 8));
                offset += 8;
                break;
            case 2: // length-delimited
                var lenInfo = readVarint(view, offset);
                var len = lenInfo.value;
                offset += lenInfo.length;
                field.value = Array.from(view.slice(offset, offset + len));
                offset += len;
                break;
            case 5: // 32-bit
                field.value = Array.from(view.slice(offset, offset + 4));
                offset += 4;
                break;
            default:
                console.log("Unsupported wire type: " + wireType);
                return fields;
        }
        fields.push(field);
    }
    return fields;
}

// --- gRPC frame parser ---

// Parses a gRPC frame from a given pointer. The gRPC frame header is 5 bytes:
//   [1 byte: compressed flag][4 bytes: payload length (big-endian)]
// The remainder is the protobuf-encoded payload.
function parseGRPCFrame(framePtr) {
    // Read header fields.
    var compressed = Memory.readU8(framePtr);
    // Read the next 4 bytes manually as big-endian.
    var b0 = Memory.readU8(framePtr.add(1));
    var b1 = Memory.readU8(framePtr.add(2));
    var b2 = Memory.readU8(framePtr.add(3));
    var b3 = Memory.readU8(framePtr.add(4));
    var payloadLen = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    console.log("gRPC frame header: compressed=" + compressed + ", payload length=" + payloadLen);

    // Get pointer to payload and dump its raw bytes.
    var payloadPtr = framePtr.add(5);
    console.log("Payload hex dump:\n" +
        hexdump(payloadPtr, { length: payloadLen, header: true, ansi: false }));

    // Read payload into an ArrayBuffer.
    var payloadBuffer = Memory.readByteArray(payloadPtr, payloadLen);
    // Parse payload as a protobuf message.
    var parsedFields = parseProtobufMessage(payloadBuffer);
    console.log("Parsed Protobuf fields:\n" + JSON.stringify(parsedFields, null, 2));
}

// Helper: hex dump a memory region (using Frida's built-in hexdump)
function dumpMemory(ptr, len) {
    return hexdump(ptr, { offset: 0, length: len, header: true, ansi: false });
}

//---------------------------------------------------------------------
// Hook: sub_1475D7F10 – Main slice move function
// Signature: void __fastcall sub_1475D7F10(slice_buf_t* src, uint64_t n, slice_buf_t* dst)
const GRPC_SLICE_MOVE = ptr("0x1475D7F10");
Interceptor.attach(GRPC_SLICE_MOVE, {
    onEnter: function(args) {
        // args[0]: pointer to source slice buffer structure
        // args[1]: number of bytes to move (n)
        // args[2]: pointer to destination slice buffer structure
        this.src = args[0];
        this.n   = args[1].toInt32();
        this.dst = args[2];

        // Read source and destination lengths (offset +32 holds total length)
        const srcLen = Memory.readU64(this.src.add(32));
        const dstLen = Memory.readU64(this.dst.add(32));

        console.log("[sub_1475D7F10] Called:");
        console.log("  src: " + this.src + " (length: " + srcLen + ")");
        console.log("  n: " + this.n);
        console.log("  dst: " + this.dst + " (length: " + dstLen + ")");

        // Optionally, dump the first 64 bytes of the underlying data if pointer at offset 0 is valid
        const srcData = Memory.readPointer(this.src);
        const dstData = Memory.readPointer(this.dst);
        if (!srcData.isNull()) {
            console.log("  src data dump:\n" + dumpMemory(srcData, 64));
        }
        if (!dstData.isNull()) {
            console.log("  dst data dump:\n" + dumpMemory(dstData, 64));
        }
    },
    onLeave: function(retval) {
        // Log updated lengths after slice move.
        const newSrcLen = Memory.readU64(this.src.add(32));
        const newDstLen = Memory.readU64(this.dst.add(32));
        console.log("[sub_1475D7F10] Return: updated src length: " + newSrcLen +
                    ", dst length: " + newDstLen);
    }
});

//---------------------------------------------------------------------
// Hook: sub_1475D8D20 – Direct slice move when src->length == n
// Signature: __int64 __fastcall sub_1475D8D20(slice_buf_t* src, slice_buf_t* dst)
const GRPC_SLICE_MOVE_DIRECT = ptr("0x1475D8D20");
Interceptor.attach(GRPC_SLICE_MOVE_DIRECT, {
    onEnter: function(args) {
        this.src = args[0];
        this.dst = args[1];
        console.log("[sub_1475D8D20] Called: src: " + this.src + ", dst: " + this.dst);
    },
    onLeave: function(retval) {
        console.log("[sub_1475D8D20] Return: " + retval);
    }
});

//---------------------------------------------------------------------
// Hook: sub_1475D88A0 – Slice copy into destination buffer
// Signature: __int64 __fastcall sub_1475D88A0(slice_buf_t* dst, slice_t* slice)
// Note: 'slice_t' is represented as two __int128 values.
// const GRPC_SLICE_COPY = ptr("0x1475D88A0");
// Interceptor.attach(GRPC_SLICE_COPY, {
//     onEnter: function(args) {
//         this.dst = args[0];
//         this.slicePtr = args[1];
//         console.log("[sub_1475D88A0] Called: dst: " + this.dst + ", slice data at: " + this.slicePtr);
//         // Optionally, dump the raw slice data (32 bytes)
//         console.log("  Slice dump:\n" + dumpMemory(this.slicePtr, 32));
//     },
//     onLeave: function(retval) {
//         console.log("[sub_1475D88A0] Return: " + retval);
//     }
// });
Interceptor.attach(ptr("0x1475D88A0"), {
    onEnter: function(args) {
        // args[1] points to the slice data (which holds the gRPC frame).
        this.slicePtr = args[1];
        console.log("[sub_1475D88A0] Called: attempting to parse gRPC frame at: " + this.slicePtr);
        parseGRPCFrame(this.slicePtr);
    },
    onLeave: function(retval) {
        console.log("[sub_1475D88A0] Return: " + retval);
    }
});

//---------------------------------------------------------------------
// Hook: sub_1475B4360 – Slice splitting function
// Signature: volatile signed __int64** __fastcall sub_1475B4360(dst, src, split, flag)
const GRPC_SLICE_SPLIT = ptr("0x1475B4360");
Interceptor.attach(GRPC_SLICE_SPLIT, {
    onEnter: function(args) {
        console.log("[sub_1475B4360] Called:");
        console.log("  dst struct: " + args[0]);
        console.log("  src slice: " + args[1]);
        console.log("  split length: " + args[2].toInt32() +
                    ", flag: " + args[3].toInt32());
        // Optionally dump the source slice (if length permits)
        console.log("  src slice dump:\n" + dumpMemory(args[1], 32));
    },
    onLeave: function(retval) {
        console.log("[sub_1475B4360] Return: " + retval);
    }
});

//---------------------------------------------------------------------
// Hook: sub_1475D9250 – Move a slice from src to dst and update src buffer
// Signature: __int64 __fastcall sub_1475D9250(slice_buf_t* src, slice_t* slice)
const GRPC_SLICE_MOVE_UPDATE = ptr("0x1475D9250");
Interceptor.attach(GRPC_SLICE_MOVE_UPDATE, {
    onEnter: function(args) {
        this.src = args[0];
        this.slicePtr = args[1];
        console.log("[sub_1475D9250] Called: src: " + this.src + ", slice: " + this.slicePtr);
        console.log("  Slice dump:\n" + dumpMemory(this.slicePtr, 32));
    },
    onLeave: function(retval) {
        console.log("[sub_1475D9250] Return: " + retval);
    }
});

//---------------------------------------------------------------------
// Hook: sub_1475D8590 – Slice buffer reallocation/move
// Signature: void* __fastcall sub_1475D8590(slice_buf_t* buf, ...)
// (Note: This function is invoked when the buffer needs expansion or data movement.)
const GRPC_REALLOC = ptr("0x1475D8590");
Interceptor.attach(GRPC_REALLOC, {
    onEnter: function(args) {
        console.log("[sub_1475D8590] Called with buf: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[sub_1475D8590] Return: " + retval);
    }
});
