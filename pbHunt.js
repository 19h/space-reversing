/*
 * Low-Impact Protobuf Buffer Identification Script
 * 
 * This refined approach uses progressive instrumentation with careful error handling
 * to prevent destabilizing the target process.
 */

(function() {
    'use strict';

    // ================ Configuration Parameters ================
    const CONFIG = {
        // Buffer size thresholds for protobuf messages
        minBufferSize: 16,
        maxBufferSize: 65536,
        
        // Output directory for dumped buffers (will be created if it doesn't exist)
        outputDir: Process.getHomeDir() + '\\Downloads\\dump\\',
        
        // Logging level (0-3)
        logLevel: 1,
        
        // Delay initial scanning to let the process initialize
        initialDelayMs: 5000,
        
        // Only scan main executable and certain modules
        scanAllModules: false,
        
        // Focused mode - only use specific targeting strategies
        focusedMode: true
    };

    // ================ Utility Functions ================
    const Utils = {
        log: function(level, message) {
            if (level <= CONFIG.logLevel) {
                console.log(`[${level}] ${message}`);
            }
        },
        
        hexdump: function(buffer, maxLength = 64) {
            try {
                return hexdump(buffer, { length: Math.min(buffer.byteLength, maxLength) });
            } catch (e) {
                return `[Error generating hexdump: ${e}]`;
            }
        },
        
        saveBuffer: function(buffer, prefix) {
            try {
                let outputPath = CONFIG.outputDir;
                
                const filename = `${outputPath}${prefix}_${new Date().getTime()}.bin`;
                const file = new File(filename, "wb");
                file.write(buffer);
                file.flush();
                file.close();
                this.log(1, `Saved buffer to ${filename}`);
                return filename;
            } catch (e) {
                this.log(0, `Failed to save buffer: ${e}`);
                return null;
            }
        },
        
        // Safe function to get backtrace that won't crash if it fails
        getBacktrace: function(context) {
            try {
                return Thread.backtrace(context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n\t');
            } catch (e) {
                return `[Failed to get backtrace: ${e}]`;
            }
        },
        
        // Process-safe way to check if memory is likely protobuf data
        isLikelyProtobuf: function(buffer) {
            if (!buffer || buffer.byteLength < 8) return false;
            
            try {
                // Simple heuristic: Look for bytes with MSB set followed by bytes with MSB not set
                // This pattern is common in protobuf varint encoding
                let varintPatterns = 0;
                
                for (let i = 0; i < Math.min(buffer.byteLength - 1, 64); i++) {
                    // Look for a byte with MSB set followed by byte with MSB not set
                    if ((buffer[i] & 0x80) && !(buffer[i+1] & 0x80)) {
                        varintPatterns++;
                    }
                    
                    // Check if there's a potential valid field tag
                    // In protobuf, the last 3 bits are the wire type, which should be 0-5
                    const wireType = buffer[i] & 0x07;
                    if (wireType <= 5 && wireType >= 0) {
                        varintPatterns++;
                    }
                }
                
                return varintPatterns >= 5;
            } catch (e) {
                return false;
            }
        },
        
        // Safe memory reading that won't crash the process
        safeReadMemory: function(address, size) {
            try {
                return Memory.readByteArray(address, size);
            } catch (e) {
                return null;
            }
        },
        
        // Convert string to pattern bytes for memory scanning
        stringToBytes: function(str) {
            const result = [];
            for (let i = 0; i < str.length; i++) {
                result.push(str.charCodeAt(i) & 0xFF);
            }
            return result;
        }
    };

    // ================ Network Monitoring Strategy ================
    // This is a minimal approach that just hooks common networking functions
    const NetworkMonitor = {
        init: function() {
            Utils.log(1, "Initializing network monitoring");
            
            setTimeout(() => {
                try {
                    this.hookNetworkFunctions();
                } catch (e) {
                    Utils.log(0, `Error initializing network hooks: ${e}`);
                }
            }, CONFIG.initialDelayMs);
        },
        
        hookNetworkFunctions: function() {
            // Focus on common recv/read functions that would contain decrypted data
            const recvFunctions = [
                { name: "recv", module: null },
                { name: "WSARecv", module: "WS2_32.dll" },
                { name: "PR_Read", module: null },  // Mozilla NSS
                { name: "SSL_read", module: null }  // OpenSSL
            ];
            
            let hookedCount = 0;
            
            for (const funcInfo of recvFunctions) {
                try {
                    const funcPtr = funcInfo.module ? 
                        Module.findExportByName(funcInfo.module, funcInfo.name) :
                        Module.findExportByName(null, funcInfo.name);
                    
                    if (funcPtr) {
                        Utils.log(2, `Hooking network function: ${funcInfo.name} at ${funcPtr}`);
                        
                        Interceptor.attach(funcPtr, {
                            onEnter: function(args) {
                                this.buffer = args[1];
                            },
                            onLeave: function(retval) {
                                const size = retval.toInt32();
                                
                                if (size > CONFIG.minBufferSize && size < CONFIG.maxBufferSize) {
                                    try {
                                        const buffer = Memory.readByteArray(this.buffer, size);
                                        
                                        if (Utils.isLikelyProtobuf(buffer)) {
                                            Utils.log(0, `[FOUND] Potential protobuf data from ${funcInfo.name} (${size} bytes)`);
                                            Utils.log(1, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                            Utils.saveBuffer(buffer, `proto_net_${funcInfo.name}`);
                                        }
                                    } catch (e) {
                                        // Just silently skip errors reading the buffer
                                    }
                                }
                            }
                        });
                        
                        hookedCount++;
                    }
                } catch (e) {
                    Utils.log(1, `Failed to hook ${funcInfo.name}: ${e}`);
                }
            }
            
            Utils.log(1, `Hooked ${hookedCount} network functions`);
        }
    };

    // ================ String Search Strategy ================
    // Improved string searching with proper byte pattern conversion
    const StringSearcher = {
        init: function() {
            Utils.log(1, "Initializing protobuf string search");
            
            // Delay the string searching to allow the process to initialize
            setTimeout(() => {
                try {
                    this.findProtobufStrings();
                } catch (e) {
                    Utils.log(0, `Error in string searching: ${e}`);
                }
            }, CONFIG.initialDelayMs);
        },
        
        findProtobufStrings: function() {
            // Select modules to scan
            let modulesToScan = [];
            
            if (CONFIG.scanAllModules) {
                modulesToScan = Process.enumerateModules();
            } else {
                // Only scan the main module and a few likely candidates
                const mainModule = Process.getModuleByName(Process.enumerateModules()[0].name);
                modulesToScan.push(mainModule);
                
                // Try to add a few other modules that might contain protobuf
                const additionalModules = [
                    "protobuf.dll",
                    "libprotobuf.dll", 
                    "grpc.dll",
                    "libgrpc.dll"
                ];
                
                for (const modName of additionalModules) {
                    try {
                        const mod = Process.getModuleByName(modName);
                        if (mod) {
                            modulesToScan.push(mod);
                        }
                    } catch (e) {
                        // Module not found, just skip it
                    }
                }
            }
            
            Utils.log(1, `Scanning ${modulesToScan.length} modules for protobuf strings`);
            
            // Common protobuf-related strings
            const protoKeywords = [
                "google.protobuf",
                "protobuf::internal",
                ".proto",
                "message_lite",
                "ParseFromArray",
                "SerializeToArray"
            ];
            
            for (const module of modulesToScan) {
                Utils.log(2, `Scanning module ${module.name}`);
                
                for (const keyword of protoKeywords) {
                    try {
                        // Convert the string to a proper byte pattern
                        const pattern = Utils.stringToBytes(keyword);
                        
                        // Use a more resilient approach with smaller ranges to avoid crashing
                        this.scanModuleInChunks(module, pattern, keyword);
                    } catch (e) {
                        Utils.log(1, `Error scanning for "${keyword}" in ${module.name}: ${e}`);
                    }
                }
            }
        },
        
        // Scan a module in smaller chunks to prevent crashes
        scanModuleInChunks: function(module, pattern, originalString) {
            const chunkSize = 1024 * 1024; // 1MB chunks
            let matchCount = 0;
            
            for (let offset = 0; offset < module.size; offset += chunkSize) {
                const scanSize = Math.min(chunkSize, module.size - offset);
                const scanAddress = module.base.add(offset);
                
                try {
                    const matches = Memory.scanSync(scanAddress, scanSize, pattern);
                    
                    for (const match of matches) {
                        matchCount++;
                        Utils.log(1, `Found string "${originalString}" at ${match.address}`);
                        
                        // Hook functions near the string references
                        this.findReferencingFunctions(match.address, module);
                        
                        // Limit the number of matches to avoid too many hooks
                        if (matchCount >= 10) break;
                    }
                } catch (e) {
                    Utils.log(2, `Error scanning chunk at ${scanAddress}: ${e}`);
                }
                
                // Limit the matches to avoid overloading
                if (matchCount >= 10) break;
            }
            
            if (matchCount > 0) {
                Utils.log(0, `[FOUND] ${matchCount} occurrences of "${originalString}" in ${module.name}`);
            }
        },
        
        // Find functions that reference the found strings
        findReferencingFunctions: function(stringAddr, module) {
            try {
                // Just check a few common known function patterns near the string
                const commonPrefixes = [
                    // push rbp; mov rbp, rsp
                    [0x55, 0x48, 0x89, 0xe5],
                    // sub rsp, XX
                    [0x48, 0x83, 0xec],
                    // mov rax, rsp
                    [0x48, 0x89, 0xe0]
                ];
                
                // Look backward for common function prologues
                const checkRange = 128; // Look at most 128 bytes backward
                
                for (let offset = 0; offset < checkRange; offset++) {
                    try {
                        const checkAddr = stringAddr.sub(offset);
                        const bytes = Utils.safeReadMemory(checkAddr, 4);
                        
                        if (!bytes) continue;
                        
                        // Check each prefix pattern
                        for (const prefix of commonPrefixes) {
                            let matched = true;
                            for (let i = 0; i < prefix.length; i++) {
                                if (bytes[i] !== prefix[i]) {
                                    matched = false;
                                    break;
                                }
                            }
                            
                            if (matched) {
                                Utils.log(1, `Found potential function at ${checkAddr}`);
                                this.hookPoiFunction(checkAddr);
                                return; // Found a match, so stop looking
                            }
                        }
                    } catch (e) {
                        // Skip inaccessible memory
                    }
                }
            } catch (e) {
                Utils.log(1, `Error finding referencing functions: ${e}`);
            }
        },
        
        // Hook a potential function of interest
        hookPoiFunction: function(address) {
            try {
                Utils.log(2, `Installing hook at ${address}`);
                
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        this.args = args;
                    },
                    onLeave: function(retval) {
                        // Check if return value points to a buffer
                        if (!retval.isNull()) {
                            try {
                                // Just check the first few bytes
                                const previewData = Utils.safeReadMemory(retval, 32);
                                
                                if (previewData && Utils.isLikelyProtobuf(previewData)) {
                                    Utils.log(0, `[FOUND] Function at ${address} returned potential protobuf data`);
                                    
                                    // Try to read a larger portion to get the full message
                                    const fullData = Utils.safeReadMemory(retval, 1024);
                                    if (fullData) {
                                        Utils.log(1, `Buffer preview:\n${Utils.hexdump(fullData)}`);
                                        Utils.saveBuffer(fullData, "proto_func_ret");
                                    }
                                }
                            } catch (e) {
                                // Ignore errors in reading returned data
                            }
                        }
                        
                        // Also check the first few arguments to see if they look like buffer pointers
                        for (let i = 0; i < 4; i++) {
                            try {
                                const arg = this.args[i];
                                if (!arg.isNull()) {
                                    const argData = Utils.safeReadMemory(arg, 32);
                                    
                                    if (argData && Utils.isLikelyProtobuf(argData)) {
                                        Utils.log(0, `[FOUND] Function arg[${i}] at ${address} contains protobuf data`);
                                        
                                        const fullArgData = Utils.safeReadMemory(arg, 1024);
                                        if (fullArgData) {
                                            Utils.log(1, `Buffer preview:\n${Utils.hexdump(fullArgData)}`);
                                            Utils.saveBuffer(fullArgData, `proto_func_arg${i}`);
                                        }
                                    }
                                }
                            } catch (e) {
                                // Ignore errors in argument checking
                            }
                        }
                    }
                });
            } catch (e) {
                Utils.log(1, `Failed to hook function at ${address}: ${e}`);
            }
        }
    };

    // ================ Memory Allocation Monitoring ================
    // Monitors malloc/new for potential protobuf buffers
    const MemoryMonitor = {
        init: function() {
            if (CONFIG.focusedMode) {
                Utils.log(1, "Skipping memory allocation monitoring in focused mode");
                return;
            }
            
            Utils.log(1, "Initializing memory allocation monitoring");
            
            setTimeout(() => {
                try {
                    this.hookAllocators();
                } catch (e) {
                    Utils.log(0, `Error initializing memory hooks: ${e}`);
                }
            }, CONFIG.initialDelayMs + 1000);  // Add extra delay for this more invasive method
        },
        
        hookAllocators: function() {
            // Target malloc as the primary allocator to watch
            const mallocPtr = Module.findExportByName(null, "malloc");
            
            if (mallocPtr) {
                Utils.log(2, `Hooking malloc at ${mallocPtr}`);
                
                Interceptor.attach(mallocPtr, {
                    onEnter: function(args) {
                        this.size = args[0].toInt32();
                        
                        // Only track reasonably sized allocations
                        this.interesting = (this.size >= CONFIG.minBufferSize && 
                                           this.size <= CONFIG.maxBufferSize);
                    },
                    onLeave: function(retval) {
                        if (this.interesting && !retval.isNull()) {
                            // Set up a one-time check for this allocation after a short delay
                            // to see if it gets filled with protobuf data
                            setTimeout(() => {
                                try {
                                    const buffer = Utils.safeReadMemory(retval, this.size);
                                    
                                    if (buffer && Utils.isLikelyProtobuf(buffer)) {
                                        Utils.log(0, `[FOUND] malloc(${this.size}) returned buffer with protobuf data at ${retval}`);
                                        Utils.log(1, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                        Utils.saveBuffer(buffer, "proto_malloc");
                                    }
                                } catch (e) {
                                    // Ignore errors checking the allocation
                                }
                            }, 100);  // Short delay to let the buffer be filled
                        }
                    }
                });
            }
        }
    };

    // ================ Main Initialization ================
    function initialize() {
        Utils.log(0, "Starting minimized protobuf exfiltration script");
        
        try {
            // Start with network monitoring as the least invasive approach
            NetworkMonitor.init();
            
            // Then do string searching
            StringSearcher.init();
            
            // Finally, do memory allocation monitoring if not in focused mode
            MemoryMonitor.init();
            
            Utils.log(0, "Initialization complete - waiting for protobuf messages");
        } catch (e) {
            Utils.log(0, `Critical error during initialization: ${e}`);
        }
    }
    
    // Add a delay before starting to let the process initialize
    setTimeout(initialize, 1000);
})();
