/*
 * Advanced Protobuf Buffer Identification and Exfiltration Script
 * 
 * This script employs multiple neuroanatomical analysis vectors to identify and 
 * intercept protobuf messages at the integration point between decryption and parsing.
 */

(function() {
    'use strict';

    // ================ Configuration Parameters ================
    const CONFIG = {
        // Buffer size thresholds for protobuf messages
        minBufferSize: 16,
        maxBufferSize: 65536,
        
        // Memory scanning parameters
        scanIterations: 3,
        scanIntervalMs: 5000,
        
        // Output directory for dumped buffers
        outputDir: '/data/local/tmp/',
        
        // Logging verbosity (0-3)
        verbosity: 2,
        
        // Maximum number of hooks to install
        maxHooks: 100,
        
        // Memory region scanning
        scanSystemModules: false
    };

    // ================ Utility Functions ================
    const Utils = {
        log: function(level, message) {
            if (level <= CONFIG.verbosity) {
                console.log(`[${level}] ${message}`);
            }
        },
        
        hexdump: function(buffer, maxLength = 64) {
            return hexdump(buffer, { length: Math.min(buffer.byteLength, maxLength) });
        },
        
        saveBuffer: function(buffer, prefix) {
            try {
                const filename = `${CONFIG.outputDir}${prefix}_${new Date().getTime()}.bin`;
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
        
        getBacktrace: function(context) {
            return Thread.backtrace(context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n\t');
        },
        
        // Advanced classification of potential protobuf buffers
        isLikelyProtobuf: function(buffer) {
            if (buffer.byteLength < 8) return false;
            
            // Heuristic 1: Examine varint distribution patterns
            let varintCount = 0;
            let fieldTagCount = 0;
            
            // Protobuf often has consecutive bytes with MSB set followed by byte with MSB not set (varint encoding)
            for (let i = 0; i < Math.min(buffer.byteLength, 32); i++) {
                if ((buffer[i] & 0x80) === 0) {
                    varintCount++;
                    
                    // Check if this varint could be a valid field tag
                    const wireType = buffer[i-1] & 0x07;  // Last 3 bits
                    if (wireType <= 5) {
                        fieldTagCount++;
                    }
                }
            }
            
            // Heuristic 2: Check for field number distribution
            let validFieldTags = 0;
            for (let i = 0; i < Math.min(buffer.byteLength - 1, 64); i++) {
                const byte1 = buffer[i];
                const wireType = byte1 & 0x07;  // Last 3 bits
                const fieldNumber = byte1 >> 3;
                
                // Common wire types and reasonably small field numbers are more likely in protobuf
                if (wireType <= 5 && fieldNumber > 0 && fieldNumber < 100) {
                    validFieldTags++;
                }
            }
            
            // Heuristic 3: Entropy calculation for buffer
            let entropy = this.calculateEntropy(buffer);
            
            // Combine heuristics into a confidence score
            const confidence = (varintCount > 3 ? 0.3 : 0) +
                              (fieldTagCount > 2 ? 0.3 : 0) +
                              (validFieldTags > 5 ? 0.3 : 0) +
                              (entropy > 3.5 && entropy < 6.5 ? 0.2 : 0);
            
            return confidence > 0.5;
        },
        
        // Calculate Shannon entropy of buffer
        calculateEntropy: function(buffer) {
            const frequencies = new Array(256).fill(0);
            
            // Count byte frequencies
            for (let i = 0; i < buffer.byteLength; i++) {
                frequencies[buffer[i]]++;
            }
            
            // Calculate entropy
            let entropy = 0;
            for (let i = 0; i < 256; i++) {
                if (frequencies[i] > 0) {
                    const p = frequencies[i] / buffer.byteLength;
                    entropy -= p * Math.log2(p);
                }
            }
            
            return entropy;
        },
        
        // Extract strings from binary data
        extractStrings: function(buffer, minLength = 4) {
            const strings = [];
            let currentString = '';
            
            for (let i = 0; i < buffer.byteLength; i++) {
                const byte = buffer[i];
                if (byte >= 32 && byte <= 126) {  // ASCII printable
                    currentString += String.fromCharCode(byte);
                } else {
                    if (currentString.length >= minLength) {
                        strings.push(currentString);
                    }
                    currentString = '';
                }
            }
            
            if (currentString.length >= minLength) {
                strings.push(currentString);
            }
            
            return strings;
        }
    };

    // ================ Protobuf Hunting Strategies ================
    
    // Strategy 1: Find and hook functions that reference protobuf-related strings
    const StringHunter = {
        protoKeywords: [
            'protobuf', 'proto\\x00', '.proto', 'google::protobuf',
            'ParseFromString', 'SerializeToString', 'ParseFromArray',
            'SerializeToArray', 'MergeFrom', 'ClearField',
            'wire_format', 'WIRETYPE_', 'DiscardUnknownFields'
        ],
        
        init: function() {
            Utils.log(1, "Initializing string-based protobuf function detection");
            this.findProtobufStrings();
        },
        
        findProtobufStrings: function() {
            const modules = Process.enumerateModules();
            
            for (const module of modules) {
                // Skip system modules unless configured to scan them
                if (!CONFIG.scanSystemModules && 
                    (module.name.startsWith('lib') || module.name.includes('/system/'))) {
                    continue;
                }
                
                Utils.log(2, `Scanning module ${module.name} for protobuf strings`);
                
                for (const keyword of this.protoKeywords) {
                    try {
                        const matches = Memory.scanSync(module.base, module.size, keyword);
                        
                        if (matches.length > 0) {
                            Utils.log(1, `Found ${matches.length} occurrences of "${keyword}" in ${module.name}`);
                            
                            for (const match of matches) {
                                Utils.log(2, `String "${keyword}" found at ${match.address}`);
                                this.findReferencingFunctions(match.address, module);
                            }
                        }
                    } catch (e) {
                        Utils.log(0, `Error scanning for "${keyword}" in ${module.name}: ${e}`);
                    }
                }
            }
        },
        
        findReferencingFunctions: function(stringAddr, module) {
            // Multi-stage process to find functions that reference the strings
            
            // 1. First look for direct references (pointers to our string)
            const pageSize = 4096;
            const totalPages = Math.ceil(module.size / pageSize);
            
            for (let i = 0; i < totalPages; i++) {
                const pageAddr = module.base.add(i * pageSize);
                const scanSize = Math.min(pageSize, module.size - (i * pageSize));
                
                try {
                    // Search for pointers to our string in this page
                    const addressPattern = this.addressToPattern(stringAddr);
                    const matches = Memory.scanSync(pageAddr, scanSize, addressPattern);
                    
                    for (const match of matches) {
                        Utils.log(2, `Found reference to protobuf string at ${match.address}`);
                        
                        // Search backward for function prologue
                        const funcAddr = this.findFunctionStart(match.address, module, 256);
                        if (funcAddr) {
                            Utils.log(1, `Identified potential protobuf function at ${funcAddr}`);
                            HookManager.hookFunction(funcAddr, "string_ref");
                        }
                    }
                } catch (e) {
                    // Skip inaccessible memory regions
                }
            }
            
            // 2. Look for immediate loads of the string address (e.g., lea rax, [string_addr])
            // This is more complex and architecture-specific
            // For x64, common patterns include lea instructions with RIP-relative addressing
            // We would need a disassembler for full accuracy here
        },
        
        // Convert address to pattern bytes for memory scanning
        addressToPattern: function(address) {
            const addressValue = address.toString();
            const bytes = [];
            
            // For 64-bit pointers, create a pattern of the 8 bytes
            for (let i = 0; i < Process.pointerSize; i++) {
                const byteVal = address.add(i).readU8();
                bytes.push(byteVal);
            }
            
            return bytes;
        },
        
        // Search backward for function prologue
        findFunctionStart: function(refAddr, module, maxDistance) {
            // Common x64 function prologues:
            // - 55 48 89 e5: push rbp; mov rbp, rsp
            // - 53 48 83 ec: push rbx; sub rsp, XX
            // - 48 83 ec XX: sub rsp, XX
            // - 48 89 5c 24: mov [rsp+XX], rbx
            
            const prologues = [
                [0x55, 0x48, 0x89, 0xe5],  // push rbp; mov rbp, rsp
                [0x53, 0x48, 0x83, 0xec],  // push rbx; sub rsp, XX
                [0x48, 0x83, 0xec],        // sub rsp, XX
                [0x48, 0x89, 0x5c, 0x24]   // mov [rsp+XX], rbx
            ];
            
            // Start search from refAddr and go backward
            for (let offset = 0; offset < maxDistance; offset++) {
                try {
                    const checkAddr = refAddr.sub(offset);
                    
                    // Make sure we're still within the module
                    if (checkAddr.compare(module.base) < 0) {
                        break;
                    }
                    
                    // Read enough bytes to check for all prologue patterns
                    const bytes = Memory.readByteArray(checkAddr, 4);
                    
                    // Check each prologue pattern
                    for (const pattern of prologues) {
                        let match = true;
                        for (let i = 0; i < pattern.length; i++) {
                            if (bytes[i] !== pattern[i]) {
                                match = false;
                                break;
                            }
                        }
                        
                        if (match) {
                            return checkAddr;
                        }
                    }
                } catch (e) {
                    // Skip inaccessible memory
                }
            }
            
            return null;
        }
    };
    
    // Strategy 2: Memory allocation monitoring for potential protobuf buffers
    const MemoryHunter = {
        activeMonitors: new Map(),
        hookCounts: {},
        
        init: function() {
            Utils.log(1, "Initializing memory allocation monitoring");
            this.hookAllocators();
        },
        
        hookAllocators: function() {
            // Common allocator functions to hook
            const allocators = [
                { name: "malloc", argSize: 0 },
                { name: "calloc", argSize: -1 },  // Special case: size = arg0 * arg1
                { name: "realloc", argSize: 1 },
                { name: "operator new", argSize: 0 },
                { name: "operator new[]", argSize: 0 }
            ];
            
            for (const allocator of allocators) {
                const func = Module.findExportByName(null, allocator.name);
                if (func) {
                    Utils.log(2, `Hooking allocator: ${allocator.name} at ${func}`);
                    
                    Interceptor.attach(func, {
                        onEnter: function(args) {
                            // Determine size argument based on allocator type
                            let size;
                            if (allocator.argSize === -1) {  // calloc
                                size = args[0].toInt32() * args[1].toInt32();
                            } else {
                                size = args[allocator.argSize].toInt32();
                            }
                            
                            // Only track allocations within our size range of interest
                            if (size >= CONFIG.minBufferSize && size <= CONFIG.maxBufferSize) {
                                this.size = size;
                                this.interesting = true;
                                this.allocator = allocator.name;
                                
                                // Get caller information
                                this.returnAddr = this.returnAddress;
                                
                                if (CONFIG.verbosity >= 3) {
                                    this.backtrace = Utils.getBacktrace(this.context);
                                }
                            }
                        },
                        onLeave: function(retval) {
                            if (this.interesting && !retval.isNull()) {
                                Utils.log(2, `${this.allocator}(${this.size}) at ${retval} from ${this.returnAddr}`);
                                
                                // Monitor this memory for potential protobuf content
                                MemoryHunter.monitorAllocation(retval, this.size, this.returnAddr);
                            }
                        }
                    });
                }
            }
        },
        
        monitorAllocation: function(address, size, callerAddr) {
            // Create unique ID for this allocation
            const monitorId = `${address}_${size}`;
            
            // Make sure we're not already monitoring this address
            if (this.activeMonitors.has(monitorId)) {
                return;
            }
            
            // Start monitoring this memory region
            try {
                const memoryAccessMonitor = MemoryAccessMonitor.enable(address, size, {
                    onAccess: function(details) {
                        // We're primarily interested in write operations that could be filling
                        // the buffer with protobuf data
                        if (details.operation === 'write') {
                            Utils.log(3, `Write to monitored buffer at ${details.address} from ${details.from}`);
                            
                            // After a memory write, schedule a check to see if the buffer now contains protobuf data
                            setTimeout(() => {
                                MemoryHunter.checkBufferForProtobuf(address, size, details.from);
                            }, 100);
                        }
                    }
                });
                
                // Keep track of the monitor
                this.activeMonitors.set(monitorId, {
                    monitor: memoryAccessMonitor,
                    address: address,
                    size: size,
                    callerAddr: callerAddr,
                    startTime: Date.now()
                });
                
                // Set a timeout to remove the monitor after a while
                setTimeout(() => {
                    this.removeMonitor(monitorId);
                }, 10000);
                
            } catch (e) {
                Utils.log(0, `Failed to monitor allocation at ${address}: ${e}`);
            }
        },
        
        removeMonitor: function(monitorId) {
            const monitorData = this.activeMonitors.get(monitorId);
            if (monitorData) {
                try {
                    monitorData.monitor.disable();
                } catch (e) {
                    // Monitor might have already been disabled
                }
                this.activeMonitors.delete(monitorId);
            }
        },
        
        checkBufferForProtobuf: function(address, size, writerAddr) {
            try {
                const buffer = Memory.readByteArray(address, size);
                
                // Check if this now looks like a protobuf buffer
                if (Utils.isLikelyProtobuf(buffer)) {
                    Utils.log(1, `Identified potential protobuf buffer written at ${address} (${size} bytes) from ${writerAddr}`);
                    Utils.log(2, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                    
                    // Save buffer to file
                    Utils.saveBuffer(buffer, "proto_buf");
                    
                    // Hook the function that wrote to this buffer
                    const writerModule = Process.findModuleByAddress(writerAddr);
                    if (writerModule) {
                        // Check if we've already hooked too many functions from this module
                        const moduleName = writerModule.name;
                        this.hookCounts[moduleName] = (this.hookCounts[moduleName] || 0) + 1;
                        
                        if (this.hookCounts[moduleName] <= CONFIG.maxHooks) {
                            // Find the function that performed the write
                            const functionStart = this.findNearestFunction(writerAddr, writerModule);
                            if (functionStart) {
                                Utils.log(1, `Hooking protobuf writer function at ${functionStart}`);
                                HookManager.hookFunction(functionStart, "memory_writer");
                            }
                        }
                    }
                }
            } catch (e) {
                // Memory might no longer be accessible
            }
        },
        
        findNearestFunction: function(codeAddr, module) {
            // Simplified function finder - look backward for common function prologues
            return StringHunter.findFunctionStart(codeAddr, module, 128);
        },
        
        // Periodically scan memory for protobuf patterns
        scanMemoryForProtobufPatterns: function() {
            Utils.log(1, "Scanning memory regions for protobuf patterns");
            
            const modules = Process.enumerateModules();
            for (const module of modules) {
                // Skip system libraries and very large modules
                if ((!CONFIG.scanSystemModules && 
                    (module.name.startsWith('lib') || module.name.includes('/system/'))) ||
                    module.size > 50 * 1024 * 1024) {
                    continue;
                }
                
                Utils.log(2, `Scanning ${module.name} (${module.size} bytes) for protobuf patterns`);
                
                // Sample the module's memory in chunks
                const chunkSize = 4096;
                const totalChunks = Math.ceil(module.size / chunkSize);
                const sampleInterval = Math.max(1, Math.floor(totalChunks / 100));  // Sample ~1% of chunks
                
                for (let i = 0; i < totalChunks; i += sampleInterval) {
                    const chunkAddr = module.base.add(i * chunkSize);
                    try {
                        const chunk = Memory.readByteArray(chunkAddr, Math.min(chunkSize, module.size - (i * chunkSize)));
                        
                        // Check if this chunk looks like protobuf data
                        if (Utils.isLikelyProtobuf(chunk)) {
                            Utils.log(1, `Found potential protobuf buffer at ${chunkAddr}`);
                            Utils.log(2, `Buffer preview:\n${Utils.hexdump(chunk)}`);
                            
                            // Save the buffer
                            Utils.saveBuffer(chunk, "proto_scan");
                            
                            // Set up a monitor for this memory region
                            MemoryHunter.monitorAllocation(chunkAddr, chunkSize, ptr(0));
                        }
                    } catch (e) {
                        // Skip inaccessible memory
                    }
                }
            }
        }
    };
    
    // Strategy 3: Hook SSL/TLS functions to find decrypted network data
    const NetworkHunter = {
        init: function() {
            Utils.log(1, "Initializing network/SSL function monitoring");
            this.hookNetworkFunctions();
            this.hookSSLFunctions();
        },
        
        hookNetworkFunctions: function() {
            // Higher-level network functions that might handle already-decrypted data
            const networkFunctions = [
                "BIO_read", "BIO_write",   // OpenSSL BIO functions
                "receive", "send",         // Socket functions (might be internal names)
                "WSARecv", "WSASend"       // Windows socket functions
            ];
            
            for (const funcName of networkFunctions) {
                const func = Module.findExportByName(null, funcName);
                if (func) {
                    Utils.log(2, `Hooking network function: ${funcName} at ${func}`);
                    
                    Interceptor.attach(func, {
                        onEnter: function(args) {
                            // For most network functions:
                            // arg0: handle/context
                            // arg1: buffer
                            // arg2: length
                            this.buffer = args[1];
                            this.isRead = funcName.includes("read") || funcName.includes("Recv");
                        },
                        onLeave: function(retval) {
                            const size = retval.toInt32();
                            
                            // Check data that was just received (not sent)
                            if (size > 0 && this.isRead) {
                                Utils.log(3, `${funcName} received ${size} bytes`);
                                
                                try {
                                    const buffer = Memory.readByteArray(this.buffer, size);
                                    
                                    // Check if the data looks like protobuf
                                    if (Utils.isLikelyProtobuf(buffer)) {
                                        Utils.log(1, `Network function ${funcName} received potential protobuf data (${size} bytes)`);
                                        Utils.log(2, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                        
                                        // Save the buffer
                                        Utils.saveBuffer(buffer, "proto_net");
                                        
                                        // Track who reads from this buffer next
                                        MemoryHunter.monitorAllocation(this.buffer, size, this.returnAddress);
                                    }
                                } catch (e) {
                                    Utils.log(0, `Error reading network buffer: ${e}`);
                                }
                            }
                        }
                    });
                }
            }
        },
        
        hookSSLFunctions: function() {
            // Common SSL/TLS functions
            const sslFunctions = [
                // OpenSSL
                "SSL_read", "SSL_write",
                "SSL_read_ex", "SSL_write_ex",
                
                // Newer OpenSSL
                "DTLS_read", "DTLS_write",
                
                // mbedTLS
                "mbedtls_ssl_read", "mbedtls_ssl_write",
                
                // WolfSSL
                "wolfSSL_read", "wolfSSL_write",
                
                // Botan
                "Botan::TLS::Channel::send", "Botan::TLS::Channel::receive"
            ];
            
            for (const funcName of sslFunctions) {
                const func = Module.findExportByName(null, funcName);
                if (func) {
                    Utils.log(2, `Hooking SSL function: ${funcName} at ${func}`);
                    
                    Interceptor.attach(func, {
                        onEnter: function(args) {
                            // For most SSL implementations:
                            // arg0: SSL context
                            // arg1: buffer
                            // arg2: length
                            this.buffer = args[1];
                            this.isRead = funcName.includes("read") || funcName.includes("receive");
                        },
                        onLeave: function(retval) {
                            const size = retval.toInt32();
                            
                            // Check data that was just decrypted (not encrypted)
                            if (size > 0 && this.isRead) {
                                Utils.log(3, `${funcName} processed ${size} bytes`);
                                
                                try {
                                    const buffer = Memory.readByteArray(this.buffer, size);
                                    
                                    // Check if the decrypted data looks like protobuf
                                    if (Utils.isLikelyProtobuf(buffer)) {
                                        Utils.log(1, `SSL function ${funcName} decrypted potential protobuf data (${size} bytes)`);
                                        Utils.log(2, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                        
                                        // Save the buffer
                                        Utils.saveBuffer(buffer, "proto_ssl");
                                        
                                        // Track who reads from this buffer next
                                        MemoryHunter.monitorAllocation(this.buffer, size, this.returnAddress);
                                    }
                                } catch (e) {
                                    Utils.log(0, `Error reading SSL buffer: ${e}`);
                                }
                            }
                        }
                    });
                }
            }
        }
    };
    
    // Strategy 4: Identify and hook functions with protobuf parsing patterns
    const CodePatternHunter = {
        init: function() {
            Utils.log(1, "Initializing code pattern analysis for protobuf parsers");
            this.findCodePatterns();
        },
        
        findCodePatterns: function() {
            // This is a simplified approach. A comprehensive solution would use
            // disassembly to look for specific instruction patterns
            
            const modules = Process.enumerateModules();
            for (const module of modules) {
                // Skip system libraries
                if (!CONFIG.scanSystemModules && 
                    (module.name.startsWith('lib') || module.name.includes('/system/'))) {
                    continue;
                }
                
                Utils.log(2, `Analyzing code patterns in ${module.name}`);
                
                // Look for mangled C++ protobuf-related symbols
                this.findMangledSymbols(module);
                
                // Advanced option: Sample functions and analyze their code for protobuf parsing patterns
                // Omitted for brevity but would involve disassembly of functions to look for
                // wire type handling, varint decoding, field tag processing, etc.
            }
        },
        
        findMangledSymbols: function(module) {
            // Mangled C++ names that might indicate protobuf methods
            const mangledPatterns = [
                "_ZN6google8protobuf",     // google::protobuf namespace
                "_ZNK6google8protobuf",    // const methods in google::protobuf
                "_ZN5proto",               // proto namespace (common in games)
                "protobuf::internal",      // Internal namespace
                "ParseFromArray",          // Common method names
                "ParseFrom"
            ];
            
            try {
                // Get all exports from the module
                const exports = module.enumerateExports();
                
                for (const exp of exports) {
                    for (const pattern of mangledPatterns) {
                        if (exp.name.indexOf(pattern) !== -1) {
                            Utils.log(1, `Found potential protobuf method: ${exp.name} at ${exp.address}`);
                            HookManager.hookFunction(exp.address, "cpp_proto");
                            break;
                        }
                    }
                }
                
                // Also check imports
                const imports = module.enumerateImports();
                
                for (const imp of imports) {
                    for (const pattern of mangledPatterns) {
                        if (imp.name.indexOf(pattern) !== -1) {
                            Utils.log(1, `Found imported protobuf method: ${imp.name} at ${imp.address}`);
                            HookManager.hookFunction(imp.address, "cpp_proto_import");
                            break;
                        }
                    }
                }
            } catch (e) {
                Utils.log(0, `Error analyzing symbols in ${module.name}: ${e}`);
            }
        }
    };
    
    // Strategy 5: Function argument and return type analysis
    const TypeAnalysisHunter = {
        hookedFunctions: new Set(),
        
        init: function() {
            Utils.log(1, "Initializing function argument type analysis");
            this.hookInterestingFunctions();
        },
        
        // Hook functions that might be processing buffer data
        hookInterestingFunctions: function() {
            // Common buffer processing function names
            const bufferFunctions = [
                "Process", "ProcessMessage", "HandleMessage", "ParseMessage",
                "Decode", "DecodeMessage", "Parse", "ParseBuffer",
                "Deserialize", "DeserializeMessage", "FromBytes", "FromBuffer"
            ];
            
            const modules = Process.enumerateModules();
            for (const module of modules) {
                // Skip system libraries
                if (!CONFIG.scanSystemModules && 
                    (module.name.startsWith('lib') || module.name.includes('/system/'))) {
                    continue;
                }
                
                Utils.log(2, `Looking for buffer processing functions in ${module.name}`);
                
                // Look for strings that might be function names
                for (const funcName of bufferFunctions) {
                    try {
                        const matches = Memory.scanSync(module.base, module.size, funcName);
                        
                        for (const match of matches) {
                            Utils.log(2, `Found potential function name ${funcName} at ${match.address}`);
                            
                            // Look for references to this string that might be loading the function
                            StringHunter.findReferencingFunctions(match.address, module);
                        }
                    } catch (e) {
                        // Skip inaccessible memory regions
                    }
                }
            }
        },
        
        // Analyze argument types when called
        analyzeArgumentTypes: function(args, context) {
            const potentialBuffers = [];
            
            // Check the first 6 arguments
            for (let i = 0; i < 6; i++) {
                const arg = args[i];
                
                try {
                    if (!arg.isNull()) {
                        // Try to read memory at the pointer
                        const memTest = Memory.readByteArray(arg, 32);
                        
                        // If we can read the memory, check if it looks like a valid buffer
                        if (memTest && memTest.byteLength > 0) {
                            // Check if it looks like a C++ string
                            // In many C++ implementations, the first 16/24/32 bytes of a std::string
                            // contain length and capacity, followed by either inline storage or a pointer
                            let potentialSize = 0;
                            
                            // Try common std::string layouts
                            if (Process.pointerSize === 8) {  // 64-bit
                                // MSVC layout: [pointer to data][size][capacity]
                                potentialSize = arg.add(8).readUInt();
                                
                                if (potentialSize > 0 && potentialSize < 10000) {
                                    const strPtr = arg.readPointer();
                                    if (!strPtr.isNull()) {
                                        const strData = Memory.readByteArray(strPtr, Math.min(potentialSize, 1024));
                                        potentialBuffers.push({
                                            address: strPtr,
                                            size: potentialSize,
                                            data: strData,
                                            type: "cpp_string"
                                        });
                                    }
                                }
                                
                                // libstdc++ layout: [pointer/inline][size][capacity] (if size > SSO)
                                potentialSize = arg.add(8).readUInt();
                                if (potentialSize > 0 && potentialSize < 10000) {
                                    // Check if string is using SSO (small string optimization)
                                    if ((potentialSize & 1) === 0) {  // External storage
                                        const strPtr = arg.readPointer();
                                        if (!strPtr.isNull()) {
                                            const strData = Memory.readByteArray(strPtr, Math.min(potentialSize, 1024));
                                            potentialBuffers.push({
                                                address: strPtr,
                                                size: potentialSize,
                                                data: strData,
                                                type: "cpp_string_libstdcpp"
                                            });
                                        }
                                    }
                                }
                            }
                            
                            // Direct buffer check
                            if (Utils.isLikelyProtobuf(memTest)) {
                                let size = CONFIG.maxBufferSize;
                                
                                // Try to determine actual size
                                for (let s = 32; s < CONFIG.maxBufferSize; s *= 2) {
                                    try {
                                        Memory.readByteArray(arg.add(s - 4), 4);
                                    } catch (e) {
                                        size = s;
                                        break;
                                    }
                                }
                                
                                const bufferData = Memory.readByteArray(arg, Math.min(size, 1024));
                                potentialBuffers.push({
                                    address: arg,
                                    size: size,
                                    data: bufferData,
                                    type: "direct_buffer"
                                });
                            }
                        }
                    }
                } catch (e) {
                    // Not a readable pointer
                }
            }
            
            return potentialBuffers;
        }
    };
    
    // Central hook management
    const HookManager = {
        hookedFunctions: new Set(),
        
        hookFunction: function(address, source) {
            const addrStr = address.toString();
            
            // Don't hook the same function multiple times
            if (this.hookedFunctions.has(addrStr)) {
                return;
            }
            this.hookedFunctions.add(addrStr);
            
            Utils.log(2, `Hooking function at ${address} (source: ${source})`);
            
            Interceptor.attach(address, {
                onEnter: function(args) {
                    this.args = args;
                    this.source = source;
                    this.address = address;
                    
                    if (CONFIG.verbosity >= 3) {
                        this.backtrace = Utils.getBacktrace(this.context);
                    }
                    
                    // Analyze argument types
                    this.potentialBuffers = TypeAnalysisHunter.analyzeArgumentTypes(args, this.context);
                    
                    if (this.potentialBuffers.length > 0) {
                        Utils.log(2, `Function at ${address} received ${this.potentialBuffers.length} potential protobuf buffer(s)`);
                        
                        // Dump the most promising buffer
                        for (const buffer of this.potentialBuffers) {
                            if (Utils.isLikelyProtobuf(buffer.data)) {
                                Utils.log(1, `Found protobuf buffer in argument to function at ${address}`);
                                Utils.log(2, `Buffer preview:\n${Utils.hexdump(buffer.data)}`);
                                Utils.saveBuffer(buffer.data, `proto_arg_${buffer.type}`);
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    // Check if return value might be a buffer or pointer to buffer
                    if (!retval.isNull()) {
                        try {
                            const returnedData = Memory.readByteArray(retval, 32);
                            
                            if (Utils.isLikelyProtobuf(returnedData)) {
                                Utils.log(1, `Function at ${this.address} returned potential protobuf buffer`);
                                
                                // Try to read a larger portion
                                const fullData = Memory.readByteArray(retval, 1024);
                                Utils.log(2, `Buffer preview:\n${Utils.hexdump(fullData)}`);
                                Utils.saveBuffer(fullData, "proto_return");
                            }
                        } catch (e) {
                            // Not a readable pointer
                        }
                    }
                    
                    // If this function call produced protobuf data, hook the caller too
                    if (this.potentialBuffers.length > 0) {
                        const callerAddress = this.returnAddress;
                        if (callerAddress) {
                            const callerModule = Process.findModuleByAddress(callerAddress);
                            if (callerModule) {
                                const functionStart = StringHunter.findFunctionStart(callerAddress, callerModule, 128);
                                if (functionStart && !HookManager.hookedFunctions.has(functionStart.toString())) {
                                    Utils.log(2, `Hooking caller function at ${functionStart}`);
                                    HookManager.hookFunction(functionStart, "caller_of_proto");
                                }
                            }
                        }
                    }
                }
            });
        }
    };
    
    // Main initialization
    function initialize() {
        Utils.log(0, "Starting protobuf exfiltration script");
        
        // Setup output directory
        try {
            const fs = new File(CONFIG.outputDir, "r");
            if (!fs) {
                Utils.log(0, `Output directory ${CONFIG.outputDir} does not exist, using /data/local/tmp/ instead`);
                CONFIG.outputDir = "/data/local/tmp/";
            }
            fs.close();
        } catch (e) {
            Utils.log(0, `Output directory issue: ${e}, using /data/local/tmp/ instead`);
            CONFIG.outputDir = "/data/local/tmp/";
        }
        
        // Initialize all hunting strategies
        StringHunter.init();
        NetworkHunter.init();
        MemoryHunter.init();
        CodePatternHunter.init();
        TypeAnalysisHunter.init();
        
        // Setup periodic memory scanning
        for (let i = 0; i < CONFIG.scanIterations; i++) {
            setTimeout(() => {
                MemoryHunter.scanMemoryForProtobufPatterns();
            }, CONFIG.scanIntervalMs * (i + 1));
        }
        
        Utils.log(0, "Protobuf hunters deployed, waiting for messages...");
    }
    
    // Start the hunting process
    initialize();
})();
