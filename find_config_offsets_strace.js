// frida -U -f StarCitizen.exe -l find_config_offsets.js --no-pause

const moduleName = "StarCitizen.exe";
// Make sure this offset is correct for your game version!
// This is sub_140458D70 in IDA when the base is 0x140000000
// So the offset relative to the actual base is 0x458D70.
const functionOffset = 0x458D70;

const baseAddr = Module.findBaseAddress(moduleName);
if (!baseAddr) {
    console.error(`[-] Could not find base address for ${moduleName}`);
} else {
    const targetFuncPtr = baseAddr.add(functionOffset);
    console.log(`[*] Found base address of ${moduleName}: ${baseAddr}`);
    console.log(`[*] Target function address (offset ${functionOffset}): ${targetFuncPtr}`);

    // Store found offsets to avoid duplicates per function call
    let foundOffsetsInCall = {};
    let structBaseAddress = null; // Will hold the value of RCX (a1) during the call

    Interceptor.attach(targetFuncPtr, {
        onEnter: function(args) {
            // Assuming standard x64 calling convention: RCX is the first argument
            structBaseAddress = args[0];
            console.log(`\n[+] Entered target function at ${targetFuncPtr}`);
            console.log(` |  Structure base address (rcx): ${structBaseAddress}`);
            foundOffsetsInCall = {}; // Reset for this specific call

            // --- Stalker Setup ---
            // We need to follow the execution flow within this function
            Stalker.follow(this.threadId, {
                events: {
                    call: false, // Don't log function calls made by the target
                    ret: false,  // Don't log returns from functions called by the target
                    exec: true,  // Log every instruction executed
                    block: false,// Don't log basic blocks
                    compile: true // REQUIRED for accessing instruction details (operands, etc.)
                },

                // --- Transform Callback ---
                // This function is called for each instruction *before* it's executed
                transform (iterator) {
                    let instruction;
                    while ((instruction = iterator.next()) !== null) {
                        const currentAddress = instruction.address;
                        const mnemonic = instruction.mnemonic;
                        const opStr = instruction.opStr;

                        // Optimization: Quickly skip instructions unlikely to be relevant
                        if (!mnemonic.startsWith('mov') || !opStr.includes('[rcx')) {
                            iterator.keep();
                            continue;
                        }

                        // We are interested in instructions that write to memory relative to rcx
                        // e.g., mov [rcx + offset], value
                        // Check if Capstone details are available (requires compile: true)
                        if (instruction.details &&
                            mnemonic.startsWith('mov') && // Includes mov, movss, movsd, etc.
                            opStr.includes('[rcx') &&     // Memory operand involves rcx
                            !opStr.startsWith('rcx')) {   // Ensure rcx is part of the *memory* operand, not the source/dest register

                            const details = instruction.details;
                            let offset = null;
                            let size = 0;
                            let isWrite = false;

                            // Analyze operands to find the memory write details
                            if (details.operands && details.operands.length > 0) {
                                const memOp = details.operands[0]; // Usually the destination for mov

                                // Check if the first operand is memory, based on rcx, and is being written to
                                if (memOp.type === 'mem' && memOp.access === 'write' && memOp.value && memOp.value.base === 'rcx') {
                                    offset = memOp.value.disp; // Displacement (the offset)
                                    size = memOp.size;         // Size of the write (1, 2, 4, 8, etc.)
                                    isWrite = true;
                                }
                            }

                            // If we found a write to [rcx + offset]
                            if (isWrite && offset !== null && size > 0) {

                                // Insert a callout *after* the instruction executes.
                                // This allows us to read the value that was just written.
                                iterator.putCallout(function(context) {
                                    // structBaseAddress is captured in onEnter
                                    if (!structBaseAddress || structBaseAddress.isNull()) {
                                        // console.warn(`[!] Skipping callout at ${currentAddress}: structBaseAddress is null.`);
                                        return; // Should not happen if onEnter worked
                                    }
                                    if (foundOffsetsInCall[offset]) {
                                        return; // Already logged this offset during this function call
                                    }

                                    let dataType = `Unknown (${size} bytes)`;
                                    let valueRead = 'N/A';
                                    let valueHex = 'N/A';
                                    let valueString = ''; // For potential string pointers
                                    let flagName = 'Unknown';
                                    let nameSource = 'N/A';

                                    try {
                                        const valuePtr = structBaseAddress.add(offset);

                                        // --- Determine Data Type and Read Value ---
                                        if (mnemonic === 'movss') { // Single-precision float (4 bytes)
                                            dataType = 'Float';
                                            valueRead = valuePtr.readFloat();
                                            valueHex = '0x' + valuePtr.readU32().toString(16).padStart(8, '0');
                                        } else if (mnemonic === 'movsd') { // Double-precision float (8 bytes)
                                            dataType = 'Double';
                                            valueRead = valuePtr.readDouble();
                                            valueHex = '0x' + valuePtr.readU64().toString(16).padStart(16, '0');
                                        } else if (size === 1) {
                                            dataType = 'Byte/Bool';
                                            valueRead = valuePtr.readU8();
                                            valueHex = '0x' + valueRead.toString(16).padStart(2, '0');
                                        } else if (size === 2) {
                                            dataType = 'WORD';
                                            valueRead = valuePtr.readS16(); // Assume signed for display
                                            valueHex = '0x' + valuePtr.readU16().toString(16).padStart(4, '0');
                                        } else if (size === 4) {
                                            dataType = 'DWORD'; // Could be Int32, UInt32
                                            valueRead = valuePtr.readS32(); // Assume signed for display
                                            valueHex = '0x' + valuePtr.readU32().toString(16).padStart(8, '0');
                                            // Could potentially be a float if moved via general purpose register
                                            // let potentialFloat = valuePtr.readFloat();
                                            // valueString = ` (Potential Float: ${potentialFloat})`;
                                        } else if (size === 8) {
                                            dataType = 'QWORD'; // Could be Int64, UInt64, Double, or Pointer
                                            valueRead = valuePtr.readS64(); // Assume signed for display
                                            const u64Value = valuePtr.readU64();
                                            valueHex = '0x' + u64Value.toString(16).padStart(16, '0');
                                            try {
                                                // Attempt to read as pointer -> string (common pattern)
                                                const pointedAddr = valuePtr.readPointer();
                                                // Basic sanity check: not null, not a tiny value, potentially points somewhere valid
                                                if (!pointedAddr.isNull() && pointedAddr.compare(ptr(0x10000)) > 0) {
                                                    // Try reading as CString
                                                    let possibleString = "N/A";
                                                    try {
                                                        possibleString = `"${pointedAddr.readCString()}"`;
                                                    } catch(e_str) {
                                                        possibleString = `(readCString error: ${e_str.message})`;
                                                    }
                                                    valueString = ` (Points to: ${pointedAddr} -> ${possibleString})`;
                                                    dataType = 'Pointer?'; // More likely a pointer
                                                }
                                            } catch (e_ptr) { /* Ignore if not a valid pointer */ }
                                        } else if (size === 16) {
                                            // Could be XMM register content (e.g., movaps)
                                            dataType = 'XMM/16 Bytes';
                                            valueRead = 'Raw Bytes';
                                            valueHex = '0x' + valuePtr.readByteArray(16).hexSlice();
                                        }
                                        // Add more sizes (e.g., 10 for FPU) if needed

                                        // --- Attempt to Find Flag Name (Heuristic) ---
                                        // Common Pattern: A pointer to the name string is stored just before the value.
                                        // Often 8 bytes before for 64-bit pointers.
                                        const potentialNamePtrOffset = offset - 8;
                                        if (potentialNamePtrOffset >= 0) {
                                            try {
                                                const namePtrAddr = structBaseAddress.add(potentialNamePtrOffset);
                                                const namePtr = namePtrAddr.readPointer(); // Read the potential pointer to the name string location
                                                nameSource = `[rcx + 0x${potentialNamePtrOffset.toString(16)}] -> ${namePtr}`;

                                                // Sanity check the pointer
                                                if (!namePtr.isNull() && namePtr.compare(ptr(0x10000)) > 0) {
                                                    // Sometimes the structure holds a pointer to the name string directly.
                                                    // Sometimes it holds a pointer to *another pointer* which then points to the string.
                                                    // Let's try reading the string at namePtr first.
                                                    try {
                                                        let directName = namePtr.readCString();
                                                        if (directName && directName.length > 0 && directName.length < 100) { // Basic sanity check on string
                                                            flagName = directName;
                                                            nameSource += ` (Direct Read)`;
                                                        } else {
                                                            throw new Error("Direct read yielded invalid string");
                                                        }
                                                    } catch (e_direct) {
                                                        // If direct read fails or seems invalid, try the double pointer pattern
                                                        try {
                                                            const nameAddr = namePtr.readPointer(); // Dereference the pointer
                                                            nameSource += ` -> ${nameAddr}`;
                                                            if (!nameAddr.isNull() && nameAddr.compare(ptr(0x10000)) > 0) {
                                                                flagName = nameAddr.readCString() || 'Read Error';
                                                                if (flagName === 'Read Error' || flagName.length === 0 || flagName.length > 100) {
                                                                    flagName = 'Invalid String?';
                                                                }
                                                            } else {
                                                                nameSource += ' (Invalid Name Addr?)';
                                                                flagName = 'Invalid Name Addr?';
                                                            }
                                                        } catch (e_double) {
                                                            nameSource += ` (Double Ptr Read Error: ${e_double.message})`;
                                                            flagName = 'Name Read Error';
                                                        }
                                                    }
                                                } else {
                                                     nameSource += ' (Invalid Ptr?)';
                                                     flagName = 'Invalid Name Ptr?';
                                                }
                                            } catch (e_name) {
                                                nameSource = `[rcx + 0x${potentialNamePtrOffset.toString(16)}] (Read Error: ${e_name.message})`;
                                                flagName = 'Name Ptr Read Error';
                                            }
                                        } else {
                                            nameSource = 'Offset < 8 (No preceding pointer assumed)';
                                        }


                                        // --- Print Results ---
                                        console.log(`  >> Offset: 0x${offset.toString(16).toUpperCase().padStart(4, '0')} (${offset})`);
                                        console.log(`     Instruction: ${currentAddress} ${mnemonic} ${opStr}`);
                                        console.log(`     Data Type: ${dataType}`);
                                        console.log(`     Value: ${valueRead} (Hex: ${valueHex})${valueString}`);
                                        console.log(`     Potential Name: "${flagName}" (Source: ${nameSource})`);
                                        console.log(`     -----------------------------------------------------`);

                                        foundOffsetsInCall[offset] = true; // Mark as processed for this call

                                    } catch (e) {
                                        console.error(`  >> Error processing offset 0x${offset.toString(16)} at instruction ${currentAddress}: ${e.message}\n${e.stack}`);
                                        foundOffsetsInCall[offset] = true; // Mark as processed to avoid repeated errors
                                    }
                                }); // End of putCallout
                            } // End if (isWrite)
                        } // End if (instruction.details)

                        iterator.keep(); // Keep the original instruction in the execution flow
                    } // end while loop
                } // end transform
            }); // end Stalker.follow
        }, // end onEnter

        onLeave: function(retval) {
            Stalker.unfollow(this.threadId);
            // Optional: Trigger garbage collection to free Stalker resources sooner
            Stalker.garbageCollect();
            console.log(`[-] Left target function at ${targetFuncPtr}`);
            structBaseAddress = null; // Clear base address after function exits
        } // end onLeave
    }); // end Interceptor.attach

    console.log("[*] Hook installed successfully.");
    console.log("[*] Waiting for the game to call the target function...");
    console.log("[!] Stalker is active. Game performance may be impacted while the function is executing.");

} // end else (baseAddr found)