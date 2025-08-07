/**
 * @fileoverview
 * Frida script for symmetrical, payload-level hooking of bidirectional gRPC
 * communication in StarCitizen.exe.
 *
 * @description
 * This script achieves true symmetrical interception by hooking the gRPC CHTTP2
 * transport layer at the point where complete message payloads are processed,
 * both for sending and receiving.
 *
 * It uses an asynchronous logging pattern via `setTimeout` to prevent deadlocks
 * in the multi-threaded gRPC core, which can occur when performing slow I/O
 * operations (like console logging) inside a critical, lock-holding function.
 *
 * A key feature is the reconstruction of protocol frames for both outgoing (SEND)
 * and incoming (RECV) payloads. The hooks intercept the raw message payload
 * *after* it has been reassembled from TCP chunks but *before* it has been
 * fully processed or framed. This script manually adds the gRPC and HTTP/2
 * headers to the raw payload, allowing the visualizer to parse and display
 * it symmetrically.
 *
 * This script hooks:
 *  1. `chttp2_transport_perform_stream_op`: Captures outgoing message payloads
 *     at the transport layer by reading the raw `grpc_slice_buffer`.
 *  2. `grpc_deframe_unprocessed_incoming_frames`: Captures incoming complete
 *     message payloads after they have been assembled from the stream's
 *     internal frame storage buffer.
 *
 * This method provides a clean, message-level view of all traffic.
 *
 * @usage
 * Attach Frida: `frida -U -f StarCitizen.exe -l this_script.js --no-pause`
 */

// ===========================================================================
//
// TECHNICAL DEEP DIVE & REVERSE ENGINEERING JOURNEY
//
// This script is the result of an iterative reverse engineering process.
// Understanding the journey is key to understanding why the final hooks
// were chosen.
//
// ---------------------------------------------------------------------------
// Part 1: How the gRPC C-Core Transport Works (A Conceptual Overview)
// ---------------------------------------------------------------------------
//
// gRPC has a layered architecture. For our purposes, the flow is:
//
//   Application <--> C++ API <--> C-Core Filters <--> CHTTP2 Transport <--> TCP Socket
//
// Our goal is to hook at the CHTTP2 Transport layer, which gives us the clean,
// unencrypted, and uncompressed message payloads.
//
// ### Outgoing (SEND) Data Flow:
// 1.  The application creates a message (e.g., a Protobuf object).
// 2.  The gRPC C++ library serializes this into a `grpc_byte_buffer`.
// 3.  The operation travels down a "filter stack". Each filter can inspect or
//     modify the data.
// 4.  The CHTTP2 Transport receives the final operation in a struct called
//     `grpc_transport_stream_op_batch`. This contains the raw payload in a
//     `grpc_slice_buffer`.
// 5.  **[SEND HOOK POINT: `chttp2_transport_perform_stream_op`]**
//     At this point, we intercept the complete, raw message payload.
// 6.  The transport then adds the 5-byte gRPC header (compression flag + length).
// 7.  It then adds the 9-byte HTTP/2 DATA frame header.
// 8.  The fully framed data is written to the TCP socket.
//
// ### Incoming (RECV) Data Flow:
// 1.  The TCP socket receives a raw, continuous stream of bytes.
// 2.  An initial low-level read function (`chttp2_transport_do_read`) gets these
//     raw, and often fragmented, chunks of data.
// 3.  The internal HTTP/2 parser (`grpc_chttp2_perform_read`) consumes these
//     chunks and reassembles them into complete HTTP/2 frames.
// 4.  When a complete DATA frame is available, its payload (which includes the
//     5-byte gRPC header) is passed to `grpc_chttp2_data_parser_parse`.
// 5.  This function adds the data to the stream's `frame_storage` buffer and
//     calls the "deframer".
// 6.  **[RECV HOOK POINT: `grpc_deframe_unprocessed_incoming_frames`]**
//     The deframer is called. It reads the `frame_storage` buffer, strips the
//     5-byte gRPC header, and places the clean, raw message payload into an
//     output `grpc_slice_buffer`. We hook the exit of this function to capture
//     this final, clean payload.
// 7.  The payload travels up the filter stack to the application.
//
// ---------------------------------------------------------------------------
// Part 2: The Reverse Engineering Timeline & "Aha!" Moments
// ---------------------------------------------------------------------------
//
// 1.  **Attempt 1: The Deadlock.**
//     - Goal: Hook a high-level function and use a game engine helper to dump data.
//     - Problem: Instant deadlock.
//     - Aha! Moment #1: We were inside a `CallCombiner` (gRPC's per-call mutex).
//       A thread holding a non-reentrant lock cannot call another function that
//       tries to acquire the same lock.
//     - Learning: Never perform blocking or re-entrant API calls from within a
//       gRPC hook. Use `setTimeout` for I/O and read memory directly.
//
// 2.  **Attempt 2: The Silent SEND Hook.**
//     - Goal: Hook the public C-API `grpc_call_start_batch`.
//     - Problem: `RECV` worked (by hooking low-level `chttp2_transport_do_read`),
//       but `SEND` was silent.
//     - Aha! Moment #2: The C++ gRPC stack doesn't always use the public C-API.
//       It often bypasses it and talks to lower-level transport functions directly.
//       The hooks must be symmetrical.
//     - Learning: For reliable interception, hook at the lowest practical layer
//       where data is still in a clean state. The transport layer is the sweet spot.
//
// 3.  **Attempt 3: The Fragmented RECV Hook.**
//     - Goal: Hook `chttp2_transport_do_read` for RECV.
//     - Problem: The visualizer only worked for some packets (like PINGs). Most
//       data appeared as "Unrecognized frame format."
//     - Aha! Moment #3: We were seeing raw TCP chunks, not complete HTTP/2 frames.
//       The hook was *too low*. It was seeing the data before gRPC's own parser
//       had reassembled it.
//     - Learning: Hooking raw socket reads requires implementing your own stream
//       reassembly logic, which is complex and unnecessary if a higher-level
//       hook is available.
//
// 4.  **Attempt 4: The Parser Hook and the Empty Buffer.**
//     - Goal: Hook `grpc_chttp2_data_parser_parse`, which receives complete frames.
//     - Problem: The `RECV` hook was still not capturing data reliably. Debugging
//       showed the buffer we were reading (`s->frame_storage`) was often empty.
//     - Aha! Moment #4: The parser function immediately calls another function
//       (`grpc_chttp2_maybe_complete_recv_message`) which *consumes* the data
//       from the buffer. By the time our hook's `onEnter` finished, the data was gone.
//     - Learning: We must hook the function that *produces* the final, clean
//       output, not the one that just receives the raw input.
//
// 5.  **Attempt 5: The Final Symmetrical Hooks (The Solution).**
//     - Goal: Find the symmetrical points for complete, raw message payloads.
//     - SEND Hook: `chttp2_transport_perform_stream_op`. This is correct because
//       it's where the transport *receives* a complete message to be sent.
//     - RECV Hook: `grpc_deframe_unprocessed_incoming_frames`.
//     - Aha! Moment #5: This is the function that *produces* a complete,
//       reassembled message for the layers above. Hooking its `onLeave` gives us
//       the final, clean payload in the output buffer argument, after the C++
//       code has finished populating it.
//     - Learning: The perfect hook is often on the function that *transforms*
//       data from one state to another (e.g., from a raw byte stream to a
//       structured message).
//
// ---------------------------------------------------------------------------
// Part 3: Investigated gRPC Source Files
// ---------------------------------------------------------------------------
//
// - `include/grpc/impl/slice_type.h`: Defined `grpc_slice` and `grpc_slice_buffer`.
// - `src/core/lib/transport/transport.h`: Defined `grpc_transport_stream_op_batch`
//   and its payload struct.
// - `src/core/ext/transport/chttp2/transport/chttp2_transport.cc`: The main
//   implementation file for the CHTTP2 transport, containing the logic for
//   our hook targets.
// - `src/core/ext/transport/chttp2/transport/frame_data.cc`: Implementation of
//   the DATA frame parsers, including our final `RECV` hook target.
//
// ===========================================================================

'use strict';

// ---------------------------------------------------------------------------
// SCRIPT CONFIGURATION
// ---------------------------------------------------------------------------

// The target module name for the script - specifically targeting StarCitizen.exe
const MODULE_NAME = 'StarCitizen.exe';

// Function signature patterns used to locate target functions within the loaded module
// These byte patterns correspond to the start of specific gRPC C-core functions
// and are identified using reverse engineering tools like IDA Pro or x64dbg.
const SIGNATURES = {
    // Pattern for chttp2_transport_perform_stream_op (SEND hook)
    // This function handles stream operations in the CHTTP2 transport layer
    SEND_PERFORM_STREAM_OP: '48 89 5C 24 ?? 55 56 57 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 33 ED 49 8B D8',

    // Pattern for grpc_deframe_unprocessed_incoming_frames (RECV hook)
    // This function processes complete incoming gRPC message payloads,
    // deframing them from their transport format for consumption by the application.
    RECV_DEFRAME: '40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 4C 89 4C 24 ?? 4D 8B F0 4C 8B E2'
};

// Configuration used to filter or include specific message contents based on keyword matching
// Currently empty but can be populated for targeted interception if needed.
const FILTER_EXCLUDE = ['presence']; // Array of keywords for message exclusion
const FILTER_INCLUDE = []; // Array of keywords for focused message inclusion

// Flag that determines whether detailed payload visualization should be logged.
// When enabled, messages are displayed with breakdown of HTTP/2 and gRPC framing information.
const VISUALISE_PAYLOADS = true;

// The maximum number of bytes to dump per payload in hexdump format. This prevents extremely large
// outputs when inspecting message contents.
const MAX_DUMP_SIZE = 2048;

// ---------------------------------------------------------------------------
// CONSOLE COLOR DEFINITIONS
// ---------------------------------------------------------------------------

// Color codes used for styling console output. Based on 256-color ANSI escape codes,
// enabling clearer and more informative traffic inspection logs.
const C = {
    HTTP2: "\x1b[38;5;45m",   // Cyan/blue color for HTTP/2 frame details
    GRPC:  "\x1b[38;5;82m",   // Green color for gRPC specific information
    RAW:   "\x1b[38;5;245m",  // Gray color for raw or unrecognized payload information
    RESET: "\x1b[0m"          // Resets color to default terminal color
};

// Utility function to colorize a given text using ANSI escape sequences.
// @param {string} col - The color code to apply.
// @param {string} txt - The text content to colorize.
// @returns {string} - Returns a colorized string that can be output to console.
function colour(col, txt) {
    return `${col}${txt}${C.RESET}`;
}

// ---------------------------------------------------------------------------
// MEMORY LAYOUTS & OFFSETS (gRPC v1.49.2, 64-bit)
// ---------------------------------------------------------------------------

/**
 * @struct grpc_transport_stream_op_batch
 * @source src/core/lib/transport/transport.h
 * @description Top-level container for a batch of stream operations passed to the transport.
 *              This is the `args[2]` pointer in our SEND hook.
 *
 * @layout
 *   struct grpc_transport_stream_op_batch {
 *     grpc_closure* on_complete;
 *     grpc_transport_stream_op_batch_payload* payload;
 *     bool send_initial_metadata : 1;
 *     bool send_trailing_metadata : 1;
 *     bool send_message : 1;
 *     // ... other boolean bitfields ...
 *   };
 *
 * | Offset | Field Name      | Type                                      | Notes                                                      |
 * |--------|-----------------|-------------------------------------------|------------------------------------------------------------|
 * | 0x00   | on_complete     | `grpc_closure*`                           | Callback for when non-recv ops are done. Not used by us.   |
 * | 0x08   | payload         | `grpc_transport_stream_op_batch_payload*` | **CRITICAL**: Pointer to the struct holding the actual data. |
 * | 0x10   | (Bitfield Byte) | `uint8_t`                                 | Contains all the boolean flags packed as bitfields.        |
 */

/**
 * @struct grpc_transport_stream_op_batch_payload
 * @source src/core/lib/transport/transport.h
 * @description Holds the data pointers for the operations specified in the batch.
 *              Pointed to by the `payload` field of the batch struct.
 *
 * @layout
 *   struct grpc_transport_stream_op_batch_payload {
 *     struct { grpc_metadata_batch* send_initial_metadata; ... } send_initial_metadata;
 *     struct { grpc_metadata_batch* send_trailing_metadata; ... } send_trailing_metadata;
 *     struct { grpc_core::SliceBuffer* send_message; ... } send_message;
 *     // ... other operation data structs ...
 *   };
 *
 * | Offset | Field Name         | Type                        | Notes                                                              |
 * |--------|--------------------|-----------------------------|--------------------------------------------------------------------|
 * | 0x00   | send_initial_meta  | (struct)                    | Size: 16 bytes (`grpc_metadata_batch*` + `gpr_atm*`).              |
 * | 0x10   | send_trailing_meta | (struct)                    | Size: 16 bytes (`grpc_metadata_batch*` + `bool*`).                 |
 * | 0x20   | send_message       | `grpc_slice_buffer*`        | **CRITICAL**: Pointer to the slice buffer for the outgoing message.|
 */

/**
 * @struct grpc_slice_buffer
 * @source include/grpc/impl/slice_type.h
 * @description An expandable array of slices, representing a single contiguous payload.
 *              This is the raw data container at the transport layer.
 *
 * @layout
 *   typedef struct grpc_slice_buffer {
 *     grpc_slice* base_slices;
 *     grpc_slice* slices;
 *     size_t count;
 *     size_t capacity;
 *     size_t length;
 *     // ...
 *   } grpc_slice_buffer;
 *
 * | Offset | Field Name | Type          | Notes                                                              |
 * |--------|------------|---------------|--------------------------------------------------------------------|
 * | 0x00   | base_slices| `grpc_slice*` | Internal use.                                                      |
 * | 0x08   | slices     | `grpc_slice*` | **CRITICAL**: Pointer to the array of `grpc_slice` structs.        |
 * | 0x10   | count      | `size_t`      | **CRITICAL**: The number of `grpc_slice` structs in the array.     |
 * | 0x18   | capacity   | `size_t`      | Allocated size of the `slices` array.                              |
 * | 0x20   | length     | `size_t`      | **CRITICAL**: Total size of the payload in bytes across all slices.|
 */

/**
 * @struct grpc_slice
 * @source include/grpc/impl/slice_type.h
 * @description A reference-counted, contiguous array of bytes. Can be inlined for small
 *              payloads or reference a larger, shared buffer. `sizeof(grpc_slice)` is 32 bytes.
 *
 * @layout
 *   struct grpc_slice {
 *     struct grpc_slice_refcount* refcount;
 *     union {
 *       struct { size_t length; uint8_t* bytes; } refcounted;
 *       struct { uint8_t length; uint8_t bytes[...]; } inlined;
 *     } data;
 *   };
 *
 * | Offset | Field Name | Type        | Notes                                                              |
 * |--------|------------|-------------|--------------------------------------------------------------------|
 * | 0x00   | refcount   | `refcount*` | If NULL, the slice is inlined. Otherwise, it's ref-counted.        |
 * | 0x08   | data       | (union)     | The `readGrpcSlice` function correctly handles this union logic.   |
 */

/**
 * @struct chttp2_stream
 * @description Internal state for a CHTTP2 stream.
 *
 * | Offset | Field Name      | Type                | Notes                                                        |
 * |--------|-----------------|---------------------|--------------------------------------------------------------|
 * | 0x28   | id              | `uint32_t`          | The unique HTTP/2 Stream Identifier.                         |
 * | 0x6B0  | frame_storage   | `grpc_slice_buffer` | Buffer where incoming DATA frame slices are stored.          |
 */
// Offset for accessing the HTTP/2 Stream ID within the chttp2_stream structure
const STREAM_ID_OFFSET = 0x28;
// NOTE: The offset for frame_storage (0x6B0) was determined through reverse engineering
// of this specific binary. It may change in different builds or versions of the application.
const STREAM_FRAME_STORAGE_OFFSET = 0x6B0;

// ---------------------------------------------------------------------------
// PAYLOAD PARSING & ANALYSIS HELPERS
// ---------------------------------------------------------------------------

/**
 * Parses an individual `grpc_slice` structure from memory.
 * Handles the distinction between inlined slices (small payloads) and
 * reference-counted slices (larger externally managed data buffers).
 *
 * In gRPC, a slice is a fundamental data structure that represents a contiguous
 * block of memory. The `grpc_slice` struct is designed to efficiently handle both
 * small payloads that fit within the structure itself (inlined slices) and large
 * payloads that require external memory management (reference-counted slices).
 *
 * The importance of distinguishing between these two types lies in how memory is
 * accessed and managed:
 * - Inlined slices directly embed their data within the struct. This means reading
 *   the data requires no additional pointer dereferencing or memory allocation tracking,
 *   making them faster to process but inherently size-limited.
 * - Reference-counted slices store a pointer to an external memory block. These slices
 *   allow gRPC to handle arbitrarily large data payloads with optimized memory sharing
 *   and reduced copying. Reading their data requires careful pointer dereferencing to
 *   avoid unsafe memory access in a hooked runtime environment.
 *
 * Safety Notes:
 * - When reading slices from memory, corruption or partial initialization can lead to
 *   invalid pointers or unreasonable lengths. This function performs bounds checks to
 *   ensure memory reads won't cause Frida to crash or hang.
 * - `readByteArray` is used for safe data extraction without triggering memory violations.
 *
 * @param {NativePointer} slicePtr - Pointer to a grpc_slice structure in memory.
 *                                   Must not be null and should point to readable memory.
 * @returns {Object|null} - Returns a dictionary containing:
 *                          - `ptr`: Pointer to the slice struct (as string for logging).
 *                          - `len`: Length of payload data in bytes.
 *                          - `data`: An ArrayBuffer of the actual payload content.
 *                          Returns `null` if:
 *                          - The slice pointer is invalid.
 *                          - Lengths are out of bounds.
 *                          - Memory cannot be safely read.
 *
 * @example
 * // Example of an inlined slice:
 * // grpc_slice =
 * //   refcount: NULL (0x0)
 * //   data:
 * //     inlined:
 * //       length: 0x5 (5 bytes)
 * //       bytes: [0x01, 0x02, 0x03, 0x04, 0x05] (embedded directly within struct)
 * //
 * // Example of a reference-counted slice:
 * // grpc_slice =
 * //   refcount: 0x1234567890ABCDEF (non-null, indicates external memory)
 * //   data:
 * //     refcounted:
 * //       length: 0x2000 (8192 bytes)
 * //       bytes: 0xFEDCBA0987654321 -> [...8KB of external payload data...]
 */
function readGrpcSlice(slicePtr) {
    try {
        const refcount = slicePtr.readPointer();
        if (!refcount.isNull()) {
            // Reference-counted slice: Read from external memory segment
            const dataLen = slicePtr.add(8).readU64().toNumber();
            const dataPtr = slicePtr.add(16).readPointer();
            if (dataPtr.isNull() || dataLen > 0x1000000) return null; // Sanity check for huge lengths
            return { ptr: slicePtr, len: dataLen, data: dataPtr.readByteArray(dataLen) };
        } else {
            // Inlined slice: Data content exists in the slice itself
            const dataLen = slicePtr.add(8).readU8();
            const dataPtr = slicePtr.add(9);
            if (dataLen > 0xFF) return null; // Byte limit for inline slices
            return { ptr: slicePtr, len: dataLen, data: dataPtr.readByteArray(dataLen) };
        }
    } catch (e) {
        return null; // Error encountered during memory reading
    }
}

/**
 * Reads all slices from a `grpc_slice_buffer` and reconstructs them into a single payload.
 *
 * This function aggregates fragmented message data represented as multiple `grpc_slice` elements
 * into one contiguous data buffer. This allows us to log the complete message as it would appear
 * prior to having HTTP/2 and gRPC framing appended.
 *
 * The reconstruction process involves:
 * - Reading the slice count and validating it
 * - Allocating a Uint8Array with the size of the total payload length
 * - Iterating through each slice and copying its data into the buffer
 *
 * The function is designed with safety checks to prevent crashes or memory over-reads. It validates
 * buffer pointer integrity, checks for null or invalid slice counts, and enforces a maximum payload
 * size threshold (currently 16MB) to prevent abnormal memory allocation.
 *
 * In gRPC, a slice buffer (`grpc_slice_buffer`) may contain multiple slices (`grpc_slice`) of varying
 * sizes. Each slice represents either a reference-counted block of memory or an inlined buffer of up
 * to 255 bytes. This function abstracts that complexity by combining all slices into one coherent
 * buffer that captures the full message content as it exists during transport processing.
 *
 * @param {NativePointer} sliceBufferPtr - Pointer to the slice buffer in memory
 * @returns {Object|null} - Returns an object with the payload as ArrayBuffer and total length, or null on error
 *
 * @example
 * // Given grpc_slice_buffer layout:
 * //   slices: [ptr to slice1, ptr to slice2]
 * //   count: 2
 * //   length: 10 (5 bytes from each slice)
 * // The function reconstructs this as one continuous 10-byte buffer
 *
 * The function also logs errors to the console in cases where the slice buffer appears to be malformed
 * or unusually large, helping users identify potential hook misalignment or memory corruption during runtime.
 */
function dumpSliceBuffer(sliceBufferPtr) {
    if (sliceBufferPtr.isNull()) {
        return null; // Skip null buffers
    }
    const SLICES_PTR_OFFSET = 0x08;
    const SLICE_COUNT_OFFSET = 0x10;
    const TOTAL_LENGTH_OFFSET = 0x20;

    // Read key structural information from the slice buffer
    const slicesPtr = sliceBufferPtr.add(SLICES_PTR_OFFSET).readPointer();
    const sliceCount = sliceBufferPtr.add(SLICE_COUNT_OFFSET).readU64().toNumber();
    const totalLength = sliceBufferPtr.add(TOTAL_LENGTH_OFFSET).readU64().toNumber();

    // Early exit conditions for zero-sized or invalid buffers
    if (sliceCount === 0 || totalLength === 0 || slicesPtr.isNull()) {
        return { payload: new ArrayBuffer(0), totalLength: 0 };
    }
    if (totalLength > 0x1000000) { // 16MB safety cutoff to prevent issues with overly large messages
        console.error(`[dumpSliceBuffer] Sanity check failed: totalLength is too large (${totalLength}).`);
        return null;
    }

    // Reconstruct full payload from individual slices
    const fullPayload = new Uint8Array(totalLength);
    let bytesCopied = 0;
    const SLICE_STRUCT_SIZE = 0x20; // sizeof(grpc_slice) is 32 bytes in this version of gRPC
    for (let i = 0; i < sliceCount; i++) {
        const curSlicePtr = slicesPtr.add(i * SLICE_STRUCT_SIZE); // Locate each slice
        const slice = readGrpcSlice(curSlicePtr); // Read the slice
        if (slice && slice.len > 0) {
            fullPayload.set(new Uint8Array(slice.data), bytesCopied); // Copy bytes to contiguous buffer
            bytesCopied += slice.len;
        }
    }
    return { payload: fullPayload.buffer, totalLength: totalLength };
}

/**
 * Constructs a manually framed buffer that simulates the HTTP/2 and gRPC transport headers.
 *
 * Since we are intercepting messages *before* they are framed by the transport layer, we add
 * standard header information back manually. This allows external tools to parse and visualize
 * our captured payloads consistently with full frames.
 *
 * The function constructs:
 *  1. An HTTP/2 DATA frame header (9 bytes).
 *  2. A gRPC message header (5 bytes).
 *  3. The raw payload content.
 *
 * This fake-framing approach is essential for:
 * - Visual debugging in console output
 * - Compatibility with external tools like protocol dissectors
 * - Maintaining consistent format between SEND/RECV paths
 *
 * The artificial framing enables:
 * - Accurate size reporting for dissectors expecting完整frames
 * - Unified handling of messages regardless of interception point
 * - Preservation of stream context (Stream ID) for multiplexing analysis
 *
 * @param {ArrayBuffer} rawPayload - The actual gRPC message content without framing
 * @param {number} streamId - The HTTP/2 stream identifier associated with this message
 * @returns {ArrayBuffer} - A fully (but artificially) framed ArrayBuffer suitable for logging
 *
 * @example
 * // Input: 5-byte payload [0x01, 0x02, 0x03, 0x04, 0x05], streamId = 1
 * // Output:
 * //   [0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01] // HTTP/2 DATA frame header
 * //   [0x00, 0x00, 0x00, 0x00, 0x05]                         // gRPC header
 * //   [0x01, 0x02, 0x03, 0x04, 0x05]                         // Original payload
 *
 * HTTP/2 DATA Frame Header Format (9 bytes):
 * +-----------------------------------------------+
 * |        Length (24)           |  Type  | Flags |
 * +-----------------------------------------------+
 * |              Reserved (1) + Stream Identifier (31)             |
 * +---------------------------------------------------------------+
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Length (24)                 |
 * +---------------------------------------------+
 * |   Type (8)  |   Flags (8)   |
 * +---------------------------------------------+
 * |              Reserved (1) + Stream Identifier (31)             |
 * +---------------------------------------------------------------+
 *
 * gRPC Message Header Format (5 bytes):
 * +-----------------------------------------------+
 * | Compression Flag (8) |      Message Length (32)      |
 * +-----------------------------------------------+
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C|      Reserved (1) + Message Length (31)      |
 * +---------------------------------------------------------------+
 */
function constructFakeFramedBuffer(rawPayload, streamId) {
    const payloadLength = rawPayload.byteLength;
    const grpcHeaderLength = 5; // Standard gRPC header (1 byte compression flag, 4 bytes message length)
    const http2HeaderLength = 9; // HTTP/2 frame header (length, type, flags, stream ID)
    const grpcFrameLength = grpcHeaderLength + payloadLength;
    const totalLength = http2HeaderLength + grpcFrameLength;
    const buffer = new ArrayBuffer(totalLength);
    const view = new DataView(buffer);
    const u8 = new Uint8Array(buffer);

    // Build HTTP/2 DATA frame header
    view.setUint8(0, (grpcFrameLength >> 16) & 0xFF);  // Length high byte
    view.setUint8(1, (grpcFrameLength >> 8) & 0xFF);   // Length mid byte
    view.setUint8(2, grpcFrameLength & 0xFF);         // Length low byte
    view.setUint8(3, 0x0);                            // Frame type: DATA (0x0)
    view.setUint8(4, 0x0);                            // Flags (none set)
    view.setUint32(5, streamId & 0x7FFFFFFF, false); // Stream ID

    // Build gRPC message header
    view.setUint8(http2HeaderLength, 0x0);                                // Compression flag (0 = uncompressed)
    view.setUint32(http2HeaderLength + 1, payloadLength, false);           // Message length

    // Embed actual payload data
    u8.set(new Uint8Array(rawPayload), http2HeaderLength + grpcHeaderLength);
    return buffer;
}

/**
 * Parses HTTP/2 frame information from a raw buffer at a specific offset.
 *
 * HTTP/2 frames have a standardized 9-byte header:
 * Length (3 bytes), Type (1 byte), Flags (1 byte), Reserved + Stream ID (4 bytes).
 *
 * This function extracts only the essential headers required for visualization.
 *
 * The following frame types are recognized:
 * - DATA (0x0): Contains the payload of the gRPC message
 * - HEADERS (0x1): Compressed/uncompressed headers metadata
 * - SETTINGS (0x4): Connection-wide configuration settings
 * - PING (0x6): Connection keep-alive mechanism
 * - WINDOW_UPDATE (0x8): Flow control window advertisement
 *
 * @param {ArrayBuffer} buf - Buffer containing framed message data
 * @param {number} off - Offset within the buffer where the frame header begins
 * @returns {Object|null} - Parsed frame details or null on invalid header
 *
 * @example
 * // Given input buffer starting with HTTP/2 frame header:
 * // [0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03]
 * // Decodes to:
 * //   length: 5
 * //   type: 0 (DATA)
 * //   flags: 1 (END_STREAM)
 * //   stream: 3
 * //   payloadOffset: 9
 *
 * Frame Header Structure (9 bytes):
 * +-----------------------------------------------+
 * | 0x00 0x00 0x05 | 0x00 | 0x01 | 0x00 0x00 0x00 0x03 |
 * +--------+--------+----+----+-----+---------------+
 *          |              |    |          |
 *       Length (24)    Type Flags   Stream Identifier
 *
 * Field details:
 * - Length (3 bytes): The length of the frame payload (not including the 9-byte header).
 * - Type (1 byte): The type of the frame. e.g., 0x0 for DATA, 0x1 for HEADERS.
 * - Flags (1 byte): Flags specific to the frame type. e.g., END_STREAM, END_HEADERS, PADDED.
 * - Stream Identifier (4 bytes): The ID of the stream associated with the frame.
 *   Bit 31 (MSB) is reserved and must be cleared. IDs are 31-bit unsigned integers.
 */
function parseHTTP2Frame(buf, off = 0) {
    if (buf.byteLength < off + 9) return null; // Frame header insufficient byte length
    const view = new DataView(buf);
    const length = view.getUint32(off, false) >> 8; // HTTP/2 uses big-endian; frame length is 24 bits in the header
    const type = view.getUint8(off + 3);
    if (type > 0x9) return null; // Invalid or unlikely HTTP/2 frame types
    const flags = view.getUint8(off + 4);
    const stream = view.getUint32(off + 5, false) & 0x7FFFFFFF; // Clear reserved bit
    return { length, type, flags, stream, payloadOffset: off + 9 };
}

/**
 * Parses a gRPC message header from the payload block of an HTTP/2 DATA frame.
 *
 * Every gRPC message has a 5-byte prefix:
 * Compression flag (1 byte) and message length (4 bytes).
 *
 * This header is part of the gRPC wire format specification and is used to allow the receiver
 * to correctly interpret the following message payload. It is independent of the HTTP/2 framing
 * layer, which is handled by `parseHTTP2Frame`.
 *
 * The gRPC message header structure is as follows:
 * +---------------------------------------------------------------+
 * |C|      Reserved (1) + Message Length (31)      |
 * +---------------------------------------------------------------+
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C|      Reserved (1) + Message Length (31)      |
 * +---------------------------------------------------------------+
 *
 * Compression flag (1 byte):
 * - 0x0: Message payload is uncompressed. Most common in regular RPC calls.
 * - 0x1: Message payload is compressed using the negotiated compression algorithm.
 *        Compression is typically enabled at the channel or service level and is
 *        commonly gzip or deflate. Rare in many gRPC applications unless explicitly
 *        configured.
 *
 * Message Length (4 bytes):
 * - Big-endian unsigned 32-bit integer indicating the size of the following message
 *   payload in bytes.
 * - Example: If the message length is `0x00001042` (4162 in decimal), the next 4162
 *   bytes in the stream constitute the message body.
 *
 * Safety Notes:
 * - The buffer must contain at least 5 bytes from the given offset; otherwise, parsing
 *   fails.
 * - Malformed or partial buffers can be encountered during interception if timing or
 *   memory alignment is off. This function guards against over-reads and invalid headers
 *   by returning `null` in such cases.
 * - Although gRPC supports message compression, StarCitizen.exe rarely uses it. This
 *   script defaults to treating messages as uncompressed unless the flag is set.
 *
 * @param {ArrayBuffer} buf - The buffer containing gRPC message data
 * @param {number} off - Offset where the gRPC header begins
 * @returns {Object|null} - Parsed gRPC details or null on invalid header
 *
 * @example
 * // When given buffer of [0x00, 0x00, 0x00, 0x10, 0x42, ...rest]
 * // Returns:
 * //   compressed: 0 (false)
 * //   msgLen: 4162 (0x1042)
 */
function parseGRPCHeader(buf, off = 0) {
    if (buf.byteLength < off + 5) return null; // Header is too short
    const view = new DataView(buf);
    const compressed = view.getUint8(off); // 0x0 means uncompressed
    const msgLen = view.getUint32(off + 1, false); // Big endian message length
    return { compressed, msgLen };
}

/**
 * Converts a raw framed payload into a visual tree representation of HTTP/2 and
 * gRPC headers.
 *
 * This function serves as a critical debugging aid by visually reconstructing the
 * encapsulation hierarchy of intercepted gRPC messages. During the reverse engineering
 * process, it was observed that raw message payloads from hooks lacked framing context,
 * making it difficult to confirm adherence to gRPC and HTTP/2 wire format expectations.
 * The `visualisePayload` function fills this gap by simulating full message framing
 * and presenting it in a structured, human-readable format.
 *
 * The visualization allows:
 * - Manual verification of hook correctness at the framing layer
 * - Confirmation of stream identifier and frame type associations
 * - Easier analysis in terminal logs by grouping related header fields
 * - Debugging malformed or unexpected message structures in intercepted traffic
 * - Compatibility with Wireshark or similar tools for payload import
 *
 * Each visualized entry includes:
 * - Frame type (with symbolic names for known types, hexadecimal otherwise)
 * - Flags byte (denoting options like END_STREAM or ACK in hex)
 * - Stream identifier (key for tracking multiplexed calls)
 * - Frame payload length (total size of payload section)
 * - gRPC-specific compression flag (plain or compressed)
 * - gRPC message length (size of the embedded Protobuf object)
 *
 * Handling Multiple Frames:
 * - Since some intercepted buffers may contain concatenated frames (especially in bulk
 *   or sequential I/O scenarios), this function traverses all detectable frame boundaries
 *   in the payload, reporting each individually.
 * - This ensures complete visibility of message streams that might be fragmented or batched
 *   within a single buffer.
 *
 * Safety Considerations:
 * - The function gracefully exits on frame parsing errors to prevent log corruption or
 *   crashes.
 * - It is designed to never read beyond buffer boundaries or assume fixed message chunking.
 * - It includes fallback handling for completely unparseable or raw content.
 *
 * @param {ArrayBuffer} buf - The raw framed message payload to be visualized, typically
 *                            constructed by `constructFakeFramedBuffer`.
 * @returns {string} - A tree-formatted string that visually breaks down the framing
 *                     layers, suitable for console output or log inspection.
 *
 * @example
 * // For a buffer containing:
 * // [0x00 0x00 0x05 0x00 0x01 0x00 00 00 01] [0x00 0x00 0x00 0x00 0x02] [0x08 0x01]
 * // [0x00 0x00 0x08 0x06 0x00 0x00 00 00 00] [0xAB 0xCD 0xEF 0x12 0x34 0x56 0x78 0x90]
 * //
 * // Visualization Output:
 * // │   └─ [HTTP/2] DATA flags=0x1 stream=1 len=5
 * // │       └─ [gRPC] plain msgLen=2
 * // └─ [HTTP/2] PING flags=0x0 stream=0 len=8
 *
 * @see {@link constructFakeFramedBuffer} for the framing simulation logic.
 * @see {@link parseHTTP2Frame} for the structure of HTTP/2 frame headers.
 * @see {@link parseGRPCHeader} for the structure of gRPC message headers.
 */
function visualisePayload(buf) {
    const lines = [];
    let offset = 0;

    // Traverse incoming buffer looking for complete HTTP/2 frames
    while (offset < buf.byteLength) {
        const frame = parseHTTP2Frame(buf, offset); // Attempt to parse next HTTP/2 frame
        if (!frame) break; // Break early if parsing fails (malformed/misaligned content)

        // Translate frame type codes into symbolic labels, if available
        const typeNames = {
            0x0: "DATA",           // Standard data transmission frame
            0x1: "HEADERS",        // Header block fragments (e.g., metadata)
            0x4: "SETTINGS",       // Connection configuration parameters
            0x6: "PING",           // Connection liveness and RTT measurement
            0x8: "WINDOW_UPDATE"   // Flow control window advertisement
        };

        // Fallback to hexadecimal output if unknown frame type is encountered
        const typeStr = typeNames[frame.type] || `type=0x${frame.type.toString(16)}`;

        // Prefix control: allow tree structuring when multiple frames are involved
        const prefix = offset > 0 ? " " : "│";
        lines.push(colour(C.HTTP2, `${prefix}   └─ [HTTP/2] ${typeStr} flags=0x${frame.flags.toString(16)} stream=${frame.stream} len=${frame.length}`));

        // If this is a DATA frame, attempt to dive one layer deeper into gRPC header parsing
        if (frame.type === 0x0) {
            const payload = buf.slice(frame.payloadOffset, frame.payloadOffset + frame.length); // Isolate payload block
            const grpc = parseGRPCHeader(payload); // Try parsing as gRPC message header
            if (grpc) {
                // Report compression status and message body length
                const comp = grpc.compressed ? "compressed" : "plain";
                lines.push(colour(C.GRPC, `│       └─ [gRPC] ${comp} msgLen=${grpc.msgLen}`));
            }
        }
        offset = frame.payloadOffset + frame.length; // Advance to the next frame in sequence
    }

    // Return structured framing visualization if at least one frame was detected
    if (lines.length > 0) {
        return lines.join("\n");
    }

    // If no valid frames were found, try to display some raw content context
    const previewBytes = buf.slice(0, 40); // Cap preview to 40 bytes
    const preview = Array.from(new Uint8Array(previewBytes))
        .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.') // Print ASCII or placeholder
        .join('');

    // Fallback output showing raw content structure
    lines.push(colour(C.RAW, `[Raw Payload] Unrecognized frame format. Preview: "${preview}..."`));
    return lines.join("\n");
}

// ---------------------------------------------------------------------------
// LOGGING AND MAIN HOOK LOGIC
// ---------------------------------------------------------------------------

/**
 * Evaluates a raw data payload to determine whether it should be logged.
 *
 * Performs lightweight heuristic-based filtering using include and exclude keyword lists.
 * Used to reduce log spam and focus on specific RPC message contents (e.g., login, telemetry).
 *
 * Filtering logic:
 * - If both lists are empty, log everything
 * - If include list exists, only log matching content
 * - If exclude list exists, don't log matching content
 *
 * The comparison is case-insensitive for flexibility in keyword matching.
 *
 * Implementation details:
 * - The function converts the raw byte array into a lowercase string for efficient substring matching
 * - It uses JavaScript's built-in `Array.some()` method for optimal short-circuit evaluation
 * - Keyword matching is performed using simple string inclusion (`.includes()`) for broad matching
 * - Filters are applied in a two-stage process: inclusion followed by exclusion for logical consistency
 *
 * Performance considerations:
 * - The string conversion is done once and reused for all keyword checks
 * - Early exits are implemented to avoid unnecessary processing when filtering conditions are met
 * - The function is designed to be synchronous and lightweight to maintain hooking performance
 *
 * @param {Uint8Array} bufU8 - The raw message content for inspection
 * @returns {boolean} - True if the packet should be logged, false otherwise
 *
 * @example
 * // Setting FILTER_INCLUDE=["login"] will only log packets containing "login"
 * // Setting FILTER_EXCLUDE=["ping"] will skip packets containing "ping"
 *
 * @see {@link FILTER_INCLUDE} for the list of inclusion keywords
 * @see {@link FILTER_EXCLUDE} for the list of exclusion keywords
 */
function shouldLog(bufU8) {
    if (FILTER_INCLUDE.length === 0 && FILTER_EXCLUDE.length === 0) return true; // Default: log everything
    const str = Array.from(bufU8).map(b => String.fromCharCode(b)).join('').toLowerCase();

    // If any positive inclusion filters are defined, apply them first
    if (FILTER_INCLUDE.length > 0 && !FILTER_INCLUDE.some(kw => str.includes(kw))) return false;

    // Then apply exclusion filters if any are defined
    if (FILTER_EXCLUDE.length > 0 && FILTER_EXCLUDE.some(kw => str.includes(kw))) return false;

    return true;
}

/**
 * Handles the asynchronous logging of a pre-formatted log object to the console.
 *
 * This function is designed to be called from a `setTimeout` callback to ensure that
 * slow console I/O does not block the application's critical gRPC threads. It takes
 * an object containing already-formatted strings and prints them.
 *
 * All data processing, memory reading, and string formatting should be done
 * synchronously within the hook, before creating the `logObject`. This function's
 * only job is to perform the final, potentially slow, `console.log` operations.
 *
 * @param {Object|null} logObject - A pre-formatted object containing all necessary strings for logging.
 *   - {string} header: The main log line (timestamp, direction, pointer, length).
 *   - {string} hexdump: The formatted hexdump of the payload.
 *   - {string|null} omitted: A message indicating truncated data, or null.
 *   - {string|null} visualization: The formatted frame visualization, or null.
 */
function logPacket(logObject) {
    if (!logObject) return;

    console.log(logObject.header);
    console.log(logObject.hexdump);

    if (logObject.omitted) {
        console.log(logObject.omitted);
    }

    if (logObject.visualization) {
        console.log(colour(C.RESET, "\n--- Encapsulation view ------------------------------------------------"));
        console.log(logObject.visualization);
        console.log(colour(C.RESET, "--------------------------------------------------------------------\n"));
    }
}

/**
 * Core logic of the interception script. Locates gRPC transport functions based on byte
 * signatures, and installs Frida runtime hooks on them.
 *
 * This function is invoked at script startup to immediately begin capturing message flows.
 * It performs pattern-based function resolution within the target process module and then
 * attaches interceptors to those resolved addresses in order to monitor gRPC communication
 * at a low, transport-level layer that ensures both efficiency and message completeness.
 *
 * Hook architecture:
 * - SIGNATURES.SEND_PERFORM_STREAM_OP -> capture outbound payload at transport pre-frame stage
 * - SIGNATURES.RECV_DEFRAME -> capture inbound payload at transport post-frame strip stage
 *
 * Each hook is strategically placed:
 * - The SEND hook (`chttp2_transport_perform_stream_op`) is invoked directly by higher-level
 *   transport code when a new message batch is ready for transmission. It receives a
 *   `grpc_transport_stream_op_batch` struct, which contains a bitfield indicating which
 *   operations are in the batch and a pointer to a payload container.
 * - The RECV hook (`grpc_deframe_unprocessed_incoming_frames`) is part of the gRPC CHTTP2
 *   transport's data consumption pipeline, triggered after HTTP/2 frames have been parsed
 *   and reassembled from TCP data. This function outputs the final, deframed message payload
 *   that is about to be passed upward to application code.
 *
 * Safety features:
 * - Memory validation prior to reading: Every pointer accessed during hook execution undergoes
 *   null checks to avoid invalid memory dereferences.
 * - Synchronous hook processing with asynchronous logging to avoid blocking gRPC execution:
 *   Inside the hooks, we gather pointers and minimal metadata synchronously and then use
 *   `setTimeout` to asynchronously execute slower I/O such as hexdumps and frame parsing,
 *   preventing lock contention.
 * - Error handling wrapped around all memory accesses to prevent termination: Try-catch blocks
 *   ensure that memory read errors or malformed data do not crash the interception script.
 *
 * Thread-safety note: While JavaScript in Frida runs in a single-threaded context,
 * we're hooking functions called from multiple gRPC C-core threads. setTimeout ensures
 * that logging work (I/O) occurs after the original hooked function has completed,
 * reducing the chance of CallCombiner lock-related deadlocks by avoiding operations that
 * might cause a re-call to hooks during their invocation or interfere with pending gRPC operations.
 *
 * Memory struct layout accesses:
 * - BATCH_FLAGS_OFFSET (0x10): Used to determine which stream operations exist in the current batch.
 *   This is a bit-packed byte where each bit corresponds to an operation. For SEND, we check
 *   SEND_MESSAGE_BIT (2nd bit) to confirm we're dealing with a real message dispatch.
 * - PAYLOAD_PTR_OFFSET (0x08): Points to the payload structure containing actual data pointers.
 * - SEND_MESSAGE_PAYLOAD_OFFSET (0x20): Within the payload struct, this points to the slice buffer
 *   that holds the raw message to be sent. `dumpSliceBuffer` is used to reconstruct the data.
 * - STREAM_ID_OFFSET (0x28): Within the chttp2_stream struct, this identifies the stream associated
 *   with the message. Essential for reconstructing full gRPC/HTTP/2 frames for visualization.
 *
 * Return value access during RECV (grpc_error handling):
 * - The return structure of `grpc_deframe_unprocessed_incoming_frames` is a `grpc_error*`, which
 *   may indicate readiness or success/failure state. We check:
 *   - `retval.readPointer().isNull()`: A null primary pointer often means "no error" or successful processing.
 *   - `!retval.add(8).readPointer().isNull()`: A non-null secondary field indicates readiness or actionable result.
 *
 * Payload reconstruction in the RECV path:
 * - Unlike SEND where we intercept just prior to framing, the RECV hook occurs post-framing.
 *   The `streamOutPtr` arg already points to a finalized slice buffer containing the decoded Protobuf object.
 *   This means `dumpSliceBuffer` gives us the clean message payload ready for logging, just as we expect.
 *
 * Asynchronous logging via setTimeout:
 * - The `setTimeout(..., 0)` mechanism leverages JavaScript's event loop to defer logging.
 *   This ensures that slow I/O operations (`console.log`) are not executed within the critical
 *   section of gRPC logic. It provides non-blocking behavior critical for stable interception
 *   in concurrent or high-volume gRPC environments.
 */
function installHooks() {
    const mod = Process.getModuleByName(MODULE_NAME);
    if (!mod) throw new Error(`Module not found: ${MODULE_NAME}`); // Module validity check
    const base = mod.base;
    const size = mod.size;

    // --- Install the SEND message interception hook ---
    // Locate the chttp2_transport_perform_stream_op function by byte signature scanning
    const performOpMatches = Memory.scanSync(base, size, SIGNATURES.SEND_PERFORM_STREAM_OP);
    if (performOpMatches.length === 0) throw new Error(`SEND_PERFORM_STREAM_OP signature not found`); // Failsafe for unmatched signatures
    const performOpPtr = performOpMatches[0].address;
    console.log(`[+] SEND hook (chttp2_transport_perform_stream_op) @ ${performOpPtr}`);

    Interceptor.attach(performOpPtr, {
        onEnter: function (args) {
            // Stream-specific arguments available to transport functions
            const streamPtr = args[1];
            const batchPtr = args[2];
            if (batchPtr.isNull() || streamPtr.isNull()) return; // Null pointer early exit

            try {
                // Offsets used to navigate batch structure details
                const BATCH_FLAGS_OFFSET = 0x10;
                const PAYLOAD_PTR_OFFSET = 0x08;
                const SEND_MESSAGE_PAYLOAD_OFFSET = 0x20;
                const SEND_MESSAGE_BIT = 2; // Bit mask position for send_message flag

                const flagsByte = batchPtr.add(BATCH_FLAGS_OFFSET).readU8();
                const hasSendMessage = (flagsByte & (1 << SEND_MESSAGE_BIT)) !== 0; // Check the bitfield

                // Only act on messages that have actual send operations
                if (hasSendMessage) {
                    const payloadStructPtr = batchPtr.add(PAYLOAD_PTR_OFFSET).readPointer();
                    if (payloadStructPtr.isNull()) return;

                    const sliceBufferPtr = payloadStructPtr.add(SEND_MESSAGE_PAYLOAD_OFFSET).readPointer();
                    if (sliceBufferPtr.isNull()) return;

                    const result = dumpSliceBuffer(sliceBufferPtr);
                    if (result && result.totalLength > 0) {
                        // Perform all memory reads and data processing synchronously
                        const streamId = streamPtr.add(STREAM_ID_OFFSET).readU32();
                        const framedData = constructFakeFramedBuffer(result.payload, streamId);

                        // Filter now to avoid unnecessary work
                        if (!shouldLog(new Uint8Array(result.payload))) return;

                        // Pre-format all strings for the log object
                        const timestamp = new Date().toISOString();
                        const logObject = {
                            header: `\n[${timestamp}] --> [SEND] Payload @ ${sliceBufferPtr}: Length=${result.totalLength}`,
                            hexdump: hexdump(framedData, { length: Math.min(framedData.byteLength, MAX_DUMP_SIZE), ansi: true }),
                            omitted: framedData.byteLength > MAX_DUMP_SIZE ? colour(C.RESET, `… (${framedData.byteLength - MAX_DUMP_SIZE} more bytes omitted)`) : null,
                            visualization: VISUALISE_PAYLOADS ? visualisePayload(framedData) : null
                        };

                        // Defer only the slow console I/O operation
                        setTimeout(() => logPacket(logObject), 0);
                    }
                }
            } catch (e) {
                console.error(`[SEND] Exception in hook: ${e.message}\n${e.stack}`);
            }
        }
    });

    // --- Install the RECV message interception hook ---
    // Locate grpc_deframe_unprocessed_incoming_frames using signature scanning
    const deframeMatches = Memory.scanSync(base, size, SIGNATURES.RECV_DEFRAME);
    if (deframeMatches.length === 0) throw new Error(`RECV_DEFRAME signature not found`);
    const deframePtr = deframeMatches[0].address;
    console.log(`[+] RECV hook (grpc_deframe_unprocessed_incoming_frames) @ ${deframePtr}`);

    Interceptor.attach(deframePtr, {
        onEnter: function (args) {
            // Assign arguments based on the hooked signature
            this.streamPtr = args[1];
            this.streamOutPtr = args[3];
        },
        onLeave: function (retval) {
            // The function returns a Poll<grpc_error_handle> object by value. In 64-bit C++,
            // this is typically returned via registers (RAX for the first 8 bytes, RDX for the second).
            // Frida represents this as a NativePointer `retval`.
            // A Poll object has two members:
            //   - `absl::variant<Pending, T> state_`: at offset 0x0. Contains the error handle if ready.
            //   - `bool ready_`: at offset 0x8.
            // A successful poll with a ready value that is an OK status (nullptr error handle)
            // means a message was successfully deframed.
            const isReady = !retval.add(8).readPointer().isNull(); // Checks poll->ready_
            const isOk = retval.readPointer().isNull(); // Checks if the error handle in the variant is null

            // Early exit unless this represents successful packet completion
            if (!isReady || !isOk || this.streamOutPtr.isNull() || this.streamPtr.isNull()) {
                return;
            }

            try {
                const result = dumpSliceBuffer(this.streamOutPtr);

                if (result && result.totalLength > 0) {
                    // Perform all memory reads and data processing synchronously
                    const streamId = this.streamPtr.add(STREAM_ID_OFFSET).readU32();
                    const framedData = constructFakeFramedBuffer(result.payload, streamId);

                    // Filter now to avoid unnecessary work
                    if (!shouldLog(new Uint8Array(result.payload))) return;

                    // Pre-format all strings for the log object
                    const timestamp = new Date().toISOString();
                    const logObject = {
                        header: `\n[${timestamp}] <-- [RECV] Payload @ ${this.streamPtr}: Length=${result.totalLength}`,
                        hexdump: hexdump(framedData, { length: Math.min(framedData.byteLength, MAX_DUMP_SIZE), ansi: true }),
                        omitted: framedData.byteLength > MAX_DUMP_SIZE ? colour(C.RESET, `… (${framedData.byteLength - MAX_DUMP_SIZE} more bytes omitted)`) : null,
                        visualization: VISUALISE_PAYLOADS ? visualisePayload(framedData) : null
                    };

                    // Defer only the slow console I/O operation
                    setTimeout(() => logPacket(logObject), 0);
                }
            } catch (e) {
                console.error(`[RECV] Exception in hook: ${e.message}\n${e.stack}`);
            }
        }
    });

    console.log('[+] Symmetrical hooks installed successfully. Waiting for traffic...');
}

try {
    installHooks(); // Install hooks immediately upon script execution
} catch (e) {
    console.error(`[!] Failed to initialise hooks: ${e.message}`);
    console.error(e.stack);
}
