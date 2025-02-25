// Frida script to monitor and xhexdump decrypted buffers in gRPC secure transport
const DEBUG = true;

function xhexdump(buffer, size) {
    try {
        // Safety check on size
        if (!buffer || size <= 0 || size > 8192) {
            return `[Invalid buffer or size: ${buffer}, ${size}]`;
        }
        
        // Safely read memory with try/catch
        let bytes;
        try {
            bytes = new Uint8Array(buffer.readByteArray(size));
        } catch (e) {
            return `[Error reading memory: ${e.message}]`;
        }
        
        let result = '';
        let ascii = '';
        
        for (let i = 0; i < bytes.length; i++) {
            if (i % 16 === 0) {
                if (i !== 0) result += ' ' + ascii + '\n';
                result += '0x' + i.toString(16).padStart(8, '0') + ': ';
                ascii = '';
            }
            
            result += bytes[i].toString(16).padStart(2, '0') + ' ';
            ascii += (bytes[i] >= 32 && bytes[i] <= 126) ? 
                     String.fromCharCode(bytes[i]) : '.';
        }
        
        const remaining = bytes.length % 16;
        if (remaining !== 0) {
            for (let i = 0; i < (16 - remaining); i++) {
                result += '   ';
            }
        }
        
        result += ' ' + ascii;
        return result;
    } catch (e) {
        return `[xHexdump error: ${e.message}]`;
    }
}

function logWithTimestamp(message) {
    if (!DEBUG) return;
    try {
        const now = new Date();
        console.log(`[${now.toISOString()}] ${message}`);
    } catch (e) {
        console.log(`[Log error: ${e.message}]`);
    }
}

function main() {
    try {
        // Define the base address of the module
        const baseAddr = Process.enumerateModulesSync().shift().base;
        if (!baseAddr) {
            console.error('Base module not found');
            return;
        }
        
        logWithTimestamp(`Base address: ${baseAddr}`);
        
        // Target the unwrap/decryption function with corrected offset
        const unwrapFuncAddr = baseAddr.add(0x76D0FD0);
        
        Interceptor.attach(unwrapFuncAddr, {
            onEnter(args) {
                try {
                    this.securityContext = args[0];
                    this.inputBuffer = args[2];
                    this.outputBuffer = args[3];
                    this.outputSizePtr = args[4];
                    
                    //logWithTimestamp(`Unwrap function called with security context: ${this.securityContext}`);
                } catch (e) {
                    logWithTimestamp(`Error in unwrap onEnter: ${e.message}`);
                }
            },
            onLeave(retval) {
                try {
                    // Only proceed if decryption was successful
                    if (retval.equals(0)) {
                        // Make sure the pointer is valid
                        if (this.outputSizePtr && !this.outputSizePtr.isNull()) {
                            // Use the correct method: readU32() not readUInt32()
                            const outputSize = this.outputSizePtr.readU32();
                            
                            if (outputSize > 0 && outputSize < 8192) {
                                //logWithTimestamp(`Decrypted ${outputSize} bytes`);
                                // Check if the buffer contains "PresenceUpdated" before dumping
                                const bufferContent = this.outputBuffer.readCString(outputSize);
                                if (!bufferContent.includes("PresenceUpdated")) {
                                    console.log(xhexdump(this.outputBuffer, outputSize));
                                    console.log('--------------------------------');
                                }
                            } else {
                                //logWithTimestamp(`Unusual output size: ${outputSize}`);
                            }
                        } else {
                            logWithTimestamp('Output size pointer is null or invalid');
                        }
                    } else {
                        logWithTimestamp(`Decryption failed with error: ${retval}`);
                    }
                } catch (e) {
                    logWithTimestamp(`Error in unwrap onLeave: ${e.message}`);
                }
            }
        });
        
        // Hook the main secure read function with corrected offset
        const secureReadFuncAddr = baseAddr.add(0x773EDC0);
        
        Interceptor.attach(secureReadFuncAddr, {
            onEnter(args) {
                try {
                    this.endpoint = args[0];
                    //logWithTimestamp(`Secure read function called for endpoint: ${this.endpoint}`);
                } catch (e) {
                    logWithTimestamp(`Error in secure read onEnter: ${e.message}`);
                }
            },
            onLeave(retval) {
                try {
                    //logWithTimestamp(`Secure read function completed with result: ${retval}`);
                } catch (e) {
                    logWithTimestamp(`Error in secure read onLeave: ${e.message}`);
                }
            }
        });
        
        logWithTimestamp('Instrumentation complete - waiting for secure communications');
    } catch (e) {
        console.log(`Main error: ${e.message}`);
    }
}

// Execute main function - wrapped in try/catch for safety
try {
    main();
} catch (e) {
    console.log(`Fatal error: ${e.message}`);
}