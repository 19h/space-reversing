/*
 * Frida Memory Monitoring Script for Windows x64
 * 
 * Features:
 * 1. Hooks and replaces malloc
 * 2. Monitors memory ranges allocated by malloc
 * 3. Hexdumps changes to the console with metadata
 */

// Store information about allocated memory blocks
const memoryBlocks = new Map();
// Keep track of previous memory states for change detection
const memoryStates = new Map();
// Configure monitoring interval (ms)
const MONITOR_INTERVAL = 500;

// Helper function to generate hexdump
function xhexdump(memory, options) {
    options = options || {};
    
    const bytes = Memory.readByteArray(memory, options.length || 0x10);
    const buf = new Uint8Array(bytes);
    
    let result = '';
    let ascii = '';
    let offset = options.offset || 0;
    
    for (let i = 0; i < buf.length; i++) {
        // Print offset at the beginning of each line
        if (i % 16 === 0) {
            if (i !== 0) {
                result += '  ' + ascii + '\n';
                ascii = '';
            }
            result += '0x' + (offset + i).toString(16).padStart(8, '0') + ': ';
        }
        
        const byte = buf[i];
        // Add hex representation
        result += byte.toString(16).padStart(2, '0') + ' ';
        
        // Add to ASCII representation if printable, otherwise add a dot
        ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        
        // Add extra space in the middle of each line
        if (i % 8 === 7) {
            result += ' ';
        }
    }
    
    // Pad the last line if needed
    const remaining = buf.length % 16;
    if (remaining !== 0) {
        const padding = 16 - remaining;
        for (let i = 0; i < padding; i++) {
            result += '   ';
            if ((remaining + i) % 8 === 7) {
                result += ' ';
            }
        }
    }
    
    // Add the final ASCII representation
    result += '  ' + ascii;
    
    return result;
}

// Compare two memory buffers and return true if they differ
function memoryChanged(address, size, previousState) {
    if (!previousState) return true; // No previous state, consider as changed
    
    try {
        // Safety check - if size is unreasonably large, limit it
        const safeSize = Math.min(size, 1024 * 1024); // Limit to 1MB
        
        const currentState = Memory.readByteArray(address, safeSize);
        const current = new Uint8Array(currentState);
        const previous = new Uint8Array(previousState);
        
        if (current.length !== previous.length) return true;
        
        // For large buffers, sample the data rather than checking every byte
        if (current.length > 10000) {
            // Sample at regular intervals and the beginning/end
            const intervals = [
                // First 100 bytes
                ...Array.from({length: 100}, (_, i) => i),
                // Last 100 bytes
                ...Array.from({length: 100}, (_, i) => current.length - 100 + i),
                // Sample throughout the buffer (every 1000 bytes)
                ...Array.from({length: Math.floor(current.length / 1000)}, (_, i) => i * 1000)
            ];
            
            const uniqueIntervals = [...new Set(intervals)].filter(i => i < current.length);
            
            for (const i of uniqueIntervals) {
                if (current[i] !== previous[i]) return true;
            }
        } else {
            // For smaller buffers, check every byte
            for (let i = 0; i < current.length; i++) {
                if (current[i] !== previous[i]) return true;
            }
        }
        
        return false;
    } catch (e) {
        console.log('[!] Error in memoryChanged: ' + e.message);
        return true; // Consider it changed if we had an error
    }
}

// Function to monitor memory for changes
function monitorMemory() {
    // Create a copy of the keys to avoid modification during iteration
    const addressesToCheck = Array.from(memoryBlocks.keys());
    
    for (const address of addressesToCheck) {
        // Skip if the address is no longer in our map (could have been removed)
        if (!memoryBlocks.has(address)) continue;
        
        const info = memoryBlocks.get(address);
        
        // Validate the address before proceeding
        if (!address || typeof address !== 'string') {
            console.log('[!] Invalid address format detected, removing from monitoring');
            memoryBlocks.delete(address);
            memoryStates.delete(address);
            continue;
        }
        
        try {
            // Convert string address to pointer
            const addressPtr = ptr(address);
            const size = info.size;
            const previousState = memoryStates.get(address);
            
            // Check if memory is accessible before comparing
            try {
                // Attempt to read 1 byte to verify memory is accessible
                Memory.readByteArray(addressPtr, 1);
            } catch (accessError) {
                console.log('[!] Memory at ' + address + ' is no longer accessible, removing from monitoring');
                memoryBlocks.delete(address);
                memoryStates.delete(address);
                continue;
            }
            
            // Check for changes
            if (memoryChanged(addressPtr, size, previousState)) {
                const currentState = Memory.readByteArray(addressPtr, size);
                
                console.log('\n[*] Memory changed at ' + address);
                console.log('[+] Allocation metadata:');
                console.log('    Size: ' + size + ' bytes');
                console.log('    Timestamp: ' + info.timestamp);
                console.log('    Thread ID: ' + info.threadId);
                console.log('    Backtrace: ' + info.backtrace);
                
                // Print only up to 128 bytes for large allocations
                const dumpSize = Math.min(size, 128);
                console.log('[+] Current memory content (first ' + dumpSize + ' bytes):');
                console.log(xhexdump(addressPtr, { length: dumpSize, offset: parseInt(address, 16) }));
                
                // Store current state for future comparison
                memoryStates.set(address, currentState);
            }
        } catch (e) {
            console.log('[!] Error monitoring memory at ' + address + ': ' + e.message);
            // Clean up invalid memory references
            memoryBlocks.delete(address);
            memoryStates.delete(address);
        }
    }
    
    // Schedule next monitoring cycle
    setTimeout(monitorMemory, MONITOR_INTERVAL);
}

// Start the instrumentation when the script is loaded
function main() {
    console.log('[+] Memory monitoring script loaded');
    
    // Find the appropriate malloc implementation
    let mallocImpl;
    
    // Define possible locations for malloc
    const possibleModules = [
        'api-ms-win-crt-heap-l1-1-0.dll',  // API Set forwarding shim
        'ucrtbase.dll',                    // Universal CRT implementation
        'msvcrt.dll'                       // Older MSVCRT
    ];
    
    // Try each module until we find malloc
    for (const moduleName of possibleModules) {
        try {
            if (Process.getModuleByName(moduleName)) {
                mallocImpl = Module.getExportByName(moduleName, 'malloc');
                console.log(`[+] Found malloc in ${moduleName}`);
                break;
            }
        } catch (e) {
            console.log(`[!] malloc not found in ${moduleName}`);
        }
    }
    
    // If no standard library has malloc, try the main executable
    if (!mallocImpl) {
        const mainModule = Process.enumerateModules()[0];
        try {
            mallocImpl = Module.getExportByName(mainModule.name, 'malloc');
            console.log(`[+] Found malloc in main module: ${mainModule.name}`);
        } catch (e) {
            console.error('[!] Could not find malloc implementation in any module');
            return;
        }
    }
    
    console.log('[+] Found malloc at: ' + mallocImpl);
    
    // Hook the malloc function
    Interceptor.attach(mallocImpl, {
        onEnter: function(args) {
            // Store the requested size
            this.size = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                const allocAddress = retval.toString();
                
                // Get backtrace for additional context
                const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .filter((sym, i) => i > 0) // Skip the malloc call itself
                    .slice(0, 3) // Take only 3 frames for brevity
                    .join(' <- ');
                
                // Store information about this allocation
                memoryBlocks.set(allocAddress, {
                    size: this.size,
                    timestamp: new Date().toISOString(),
                    threadId: this.threadId,
                    backtrace: backtrace
                });
                
                // Store initial memory state
                memoryStates.set(allocAddress, Memory.readByteArray(retval, this.size));
                
                //console.log('[+] Malloc: ' + this.size + ' bytes at ' + allocAddress);
            }
        }
    });
    
    // Hook free to remove monitored blocks
    let freeImpl;
    
    // Define possible locations for free (same as for malloc)
    const possibleFreeModules = [
        'api-ms-win-crt-heap-l1-1-0.dll',
        'ucrtbase.dll',
        'msvcrt.dll'
    ];
    
    // Try each module until we find free
    for (const moduleName of possibleFreeModules) {
        try {
            if (Process.getModuleByName(moduleName)) {
                freeImpl = Module.getExportByName(moduleName, 'free');
                console.log(`[+] Found free in ${moduleName}`);
                break;
            }
        } catch (e) {
            console.log(`[!] free not found in ${moduleName}`);
        }
    }
    
    // If no standard library has free, try the main executable
    if (!freeImpl) {
        const mainModule = Process.enumerateModules()[0];
        try {
            freeImpl = Module.getExportByName(mainModule.name, 'free');
            console.log(`[+] Found free in main module: ${mainModule.name}`);
        } catch (e) {
            console.error('[!] Could not find free implementation in any module');
        }
    }
    
    if (freeImpl) {
        console.log('[+] Found free at: ' + freeImpl);
        
        Interceptor.attach(freeImpl, {
            onEnter: function(args) {
                if (args[0].isNull()) {
                    // Skip null pointers (valid in C/C++ to free null)
                    return;
                }
                
                try {
                    const address = args[0].toString();
                    
                    // Look for exact matches first
                    if (memoryBlocks.has(address)) {
                        //console.log('[+] Free: memory at ' + address);
                        memoryBlocks.delete(address);
                        memoryStates.delete(address);
                        return;
                    }
                    
                    // If exact match not found, search for address in our tracked blocks
                    // This helps catch cases where pointer arithmetic was used
                    let foundMatch = false;
                    memoryBlocks.forEach((info, blockAddr) => {
                        const blockStart = parseInt(blockAddr, 16);
                        const blockEnd = blockStart + info.size;
                        const freeAddr = parseInt(address, 16);
                        
                        // If the freed address is within any tracked block
                        if (freeAddr >= blockStart && freeAddr < blockEnd) {
                            //console.log(`[+] Free: memory at ${address} matches tracked block ${blockAddr}`);
                            memoryBlocks.delete(blockAddr);
                            memoryStates.delete(blockAddr);
                            foundMatch = true;
                        }
                    });
                    
                    if (!foundMatch) {
                        // This might be freeing memory we're not tracking
                        // Or it might be an address allocated before we started
                        //console.log(`[*] Free called on untracked address: ${address}`);
                    }
                } catch (e) {
                    console.log('[!] Error in free hook: ' + e.message);
                }
            }
        });
    }
    
    // Start monitoring thread
    setTimeout(monitorMemory, MONITOR_INTERVAL);
    
    console.log('[+] Memory monitoring started, checking every ' + MONITOR_INTERVAL + 'ms');
}

// Execute main function
main();