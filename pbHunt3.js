/*
 * Advanced Protobuf Buffer Identification and Exfiltration Script
 * 
 * Employs multiple parallel analytical vectors with sophisticated
 * protobuf identification algorithms while maintaining process stability.
 */

(function() {
    'use strict';

    // ================ Configuration Parameters ================
    const CONFIG = {
        // Buffer size thresholds for protobuf messages
        minBufferSize: 16,
        maxBufferSize: 256 * 1024,  // Increased to 256KB
        
        // Output directory for dumped buffers
        outputDir: Process.getHomeDir() + '\\Downloads\\dump\\',
        
        // Logging level (0-3)
        logLevel: 1,
        
        // Initialization delay parameters
        initialDelayMs: 3000,
        staggeredDelayMs: 1000,
        
        // Module scanning parameters
        scanMainModule: true,
        scanSystemModules: false,
        scanAdditionalModules: [
            "libprotobuf", "protobuf",
            "grpc", "libgrpc",
            "network", "libnetwork",
            "ssl", "crypto",
            "http", "service"
        ],
        
        // Function hook limits to prevent saturation
        maxHooksPerModule: 50,
        maxTotalHooks: 500,
        
        // Advanced protobuf detection parameters
        protoDetection: {
            minVarintPatterns: 3,        // Minimum varint patterns to consider
            minValidFieldTags: 2,        // Minimum valid field tags
            minStringPatterns: 1,        // Minimum potential string fields
            entropyLowerBound: 3.5,      // Lower bound for entropy check
            entropyUpperBound: 7.0,      // Upper bound for entropy check
            lengthFieldCorrelation: 0.7, // Required correlation for length-delimited fields
            confidenceThreshold: 0.65    // Confidence threshold for classification
        },
        
        // Feature flags
        enableNetworkMonitoring: true,
        enableStringSearching: true,
        enableMemoryMonitoring: true,
        enableExportScanning: true,
        enableNativeFunctionHooking: true
    };

    // ================ Global State ================
    const STATE = {
        hookedFunctions: new Set(),
        hookCount: {
            total: 0,
            byModule: {}
        },
        foundBuffers: new Set(),
        startTime: Date.now()
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
            if (!buffer || buffer.byteLength === 0) return null;
            
            // Generate a hash of the buffer to prevent saving duplicates
            const hash = this.simpleHash(buffer);
            const bufferKey = `${prefix}_${buffer.byteLength}_${hash}`;
            
            // Check if we've already saved this buffer
            if (STATE.foundBuffers.has(bufferKey)) {
                this.log(2, `Buffer ${bufferKey} already saved previously`);
                return null;
            }
            
            try {
                // Make sure the directory exists
                let outputPath = CONFIG.outputDir;
                
                const filename = `${outputPath}${prefix}_${new Date().getTime()}_${hash}.bin`;
                const file = new File(filename, "wb");
                file.write(buffer);
                file.flush();
                file.close();
                
                // Mark this buffer as found
                STATE.foundBuffers.add(bufferKey);
                
                this.log(1, `Saved buffer to ${filename}`);
                return filename;
            } catch (e) {
                this.log(0, `Failed to save buffer: ${e}`);
                return null;
            }
        },
        
        // Simple hash function for buffer deduplication
        simpleHash: function(buffer) {
            let hash = 0;
            const step = Math.max(1, Math.floor(buffer.byteLength / 32)); // Sample the buffer
            
            for (let i = 0; i < buffer.byteLength; i += step) {
                hash = ((hash << 5) - hash) + buffer[i];
                hash = hash & hash; // Convert to 32bit integer
            }
            
            return Math.abs(hash).toString(16);
        },
        
        // Safe function to get backtrace that won't crash
        getBacktrace: function(context) {
            try {
                return Thread.backtrace(context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n\t');
            } catch (e) {
                return `[Failed to get backtrace: ${e}]`;
            }
        },
        
        // Safe memory reading
        safeReadMemory: function(address, size) {
            try {
                return Memory.readByteArray(address, size);
            } catch (e) {
                return null;
            }
        },
        
        // Convert string to bytes for memory scanning
        stringToBytes: function(str) {
            const result = [];
            for (let i = 0; i < str.length; i++) {
                result.push(str.charCodeAt(i) & 0xFF);
            }
            return result;
        },
        
        // Enhanced protobuf detection with multiple heuristics
        isLikelyProtobuf: function(buffer) {
            if (!buffer || buffer.byteLength < 8) return false;
            
            // Allocate points for various protobuf characteristics
            let confidence = 0;
            const config = CONFIG.protoDetection;
            
            // ---- 1. Varint Pattern Analysis ----
            const varintResult = this.analyzeVarintPatterns(buffer);
            if (varintResult.count >= config.minVarintPatterns) {
                confidence += 0.25;
            }
            if (varintResult.validFieldTags >= config.minValidFieldTags) {
                confidence += 0.20;
            }
            
            // ---- 2. Length-Delimited Field Analysis ----
            const lengthFieldResult = this.analyzeLengthDelimitedFields(buffer);
            if (lengthFieldResult.correlation >= config.lengthFieldCorrelation) {
                confidence += 0.20;
            }
            
            // ---- 3. String Field Detection ----
            const stringFieldResult = this.detectStringFields(buffer);
            if (stringFieldResult.count >= config.minStringPatterns) {
                confidence += 0.15;
            }
            
            // ---- 4. Entropy Analysis ----
            const entropy = this.calculateEntropy(buffer);
            if (entropy >= config.entropyLowerBound && entropy <= config.entropyUpperBound) {
                confidence += 0.10;
            }
            
            // ---- 5. Field Number Distribution ----
            if (this.hasReasonableFieldNumberDistribution(buffer)) {
                confidence += 0.10;
            }
            
            // Debug logging for high confidence buffers
            if (confidence >= 0.5) {
                this.log(3, `Protobuf confidence: ${confidence.toFixed(2)} - ` + 
                           `varints: ${varintResult.count}, ` + 
                           `fieldTags: ${varintResult.validFieldTags}, ` +
                           `lenCorr: ${lengthFieldResult.correlation.toFixed(2)}, ` +
                           `strings: ${stringFieldResult.count}, ` +
                           `entropy: ${entropy.toFixed(2)}`);
            }
            
            return confidence >= config.confidenceThreshold;
        },
        
        // Analyze varint encoding patterns and field tags
        analyzeVarintPatterns: function(buffer) {
            let varintCount = 0;
            let validFieldTags = 0;
            
            // Look for valid varint patterns
            for (let i = 0; i < Math.min(buffer.byteLength - 1, 128); i++) {
                // Check for varint pattern (MSB set in all bytes except the last)
                if ((buffer[i] & 0x80) !== 0) {
                    let j = i + 1;
                    while (j < buffer.byteLength && (buffer[j] & 0x80) !== 0) {
                        j++;
                    }
                    
                    // If we found a complete varint (including last byte with MSB=0)
                    if (j < buffer.byteLength) {
                        varintCount++;
                        i = j; // Skip to the end of this varint
                    }
                }
                
                // Check for valid field tag (wire type 0-5)
                const wireType = buffer[i] & 0x07;
                if (wireType >= 0 && wireType <= 5) {
                    // Extract field number (shifted right by 3)
                    const fieldNumber = buffer[i] >> 3;
                    // Field numbers should typically be reasonable (not huge)
                    if (fieldNumber > 0 && fieldNumber < 100000) {
                        validFieldTags++;
                    }
                }
            }
            
            return { count: varintCount, validFieldTags: validFieldTags };
        },
        
        // Analyze length-delimited fields (wire type 2)
        analyzeLengthDelimitedFields: function(buffer) {
            let validLengthFields = 0;
            let totalLengthFields = 0;
            
            for (let i = 0; i < Math.min(buffer.byteLength - 2, 128); i++) {
                const wireType = buffer[i] & 0x07;
                
                // If this is a length-delimited field (wire type 2)
                if (wireType === 2) {
                    totalLengthFields++;
                    
                    // Try to read the length varint
                    let length = 0;
                    let shift = 0;
                    let j = i + 1;
                    
                    // Parse the length varint
                    while (j < buffer.byteLength) {
                        const byte = buffer[j];
                        length |= (byte & 0x7F) << shift;
                        shift += 7;
                        j++;
                        if ((byte & 0x80) === 0) break; // Last byte of varint
                    }
                    
                    // Check if the length makes sense
                    if (length > 0 && length < 1000 && j + length <= buffer.byteLength) {
                        validLengthFields++;
                        
                        // Skip past this field (header + length + content)
                        i = j + length - 1;
                    }
                }
            }
            
            // Calculate correlation - how many length fields are valid
            const correlation = totalLengthFields > 0 ? 
                validLengthFields / totalLengthFields : 0;
                
            return { valid: validLengthFields, total: totalLengthFields, correlation: correlation };
        },
        
        // Detect potential string fields
        detectStringFields: function(buffer) {
            let stringFields = 0;
            
            for (let i = 0; i < Math.min(buffer.byteLength - 10, 128); i++) {
                const wireType = buffer[i] & 0x07;
                
                // If this is a length-delimited field (wire type 2)
                if (wireType === 2) {
                    // Try to read the length varint
                    let length = 0;
                    let shift = 0;
                    let j = i + 1;
                    
                    // Parse the length varint
                    while (j < buffer.byteLength) {
                        const byte = buffer[j];
                        length |= (byte & 0x7F) << shift;
                        shift += 7;
                        j++;
                        if ((byte & 0x80) === 0) break; // Last byte of varint
                    }
                    
                    // Check if this might be a string: reasonable length and contains printable ASCII
                    if (length > 2 && length < 1000 && j + length <= buffer.byteLength) {
                        let asciiChars = 0;
                        for (let k = j; k < j + length; k++) {
                            const byte = buffer[k];
                            if (byte >= 32 && byte <= 126) { // Printable ASCII
                                asciiChars++;
                            }
                        }
                        
                        // If more than 90% is printable ASCII, consider it a string
                        if (asciiChars > length * 0.9) {
                            stringFields++;
                        }
                    }
                }
            }
            
            return { count: stringFields };
        },
        
        // Calculate Shannon entropy of the buffer
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
        
        // Check if field number distribution is reasonable
        hasReasonableFieldNumberDistribution: function(buffer) {
            const fieldNumbers = new Map();
            
            // Collect potential field numbers
            for (let i = 0; i < Math.min(buffer.byteLength, 64); i++) {
                const wireType = buffer[i] & 0x07;
                if (wireType >= 0 && wireType <= 5) {
                    // Simple field number extraction (first byte only)
                    const fieldNumber = buffer[i] >> 3;
                    if (fieldNumber > 0 && fieldNumber < 1000) {
                        fieldNumbers.set(fieldNumber, (fieldNumbers.get(fieldNumber) || 0) + 1);
                    }
                }
            }
            
            // Check if we have a reasonable number of distinct fields (at least 2)
            if (fieldNumbers.size < 2) return false;
            
            // Check if field numbers are "clustered" in a reasonable way
            // Protobuf typically has sequential or nearly-sequential field numbers
            const sortedFields = Array.from(fieldNumbers.keys()).sort((a, b) => a - b);
            
            // Calculate average gap between field numbers
            let totalGap = 0;
            for (let i = 1; i < sortedFields.length; i++) {
                totalGap += sortedFields[i] - sortedFields[i-1];
            }
            const avgGap = totalGap / (sortedFields.length - 1);
            
            // Reasonable average gap should be less than 20
            return avgGap < 20;
        },
        
        // Enhanced function to check multiple buffers for protobuf content
        checkMultipleBuffersForProtobuf: function(address, functionName, argIndex, context) {
            // Array of potential sizes to check
            const sizesToCheck = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];
            
            for (const size of sizesToCheck) {
                try {
                    const buffer = Memory.readByteArray(address, size);
                    
                    if (buffer && this.isLikelyProtobuf(buffer)) {
                        this.log(0, `[FOUND] Protobuf data in ${functionName} arg[${argIndex}], size: ${size}`);
                        this.log(1, `Buffer preview:\n${this.hexdump(buffer)}`);
                        this.saveBuffer(buffer, `proto_${functionName}_arg${argIndex}`);
                        
                        // No need to check larger sizes if we already found a match
                        return true;
                    }
                } catch (e) {
                    // Stop if we hit an invalid memory region
                    break;
                }
            }
            
            return false;
        }
    };

    // ================ Network Monitoring Strategy ================
    const NetworkMonitor = {
        init: function() {
            if (!CONFIG.enableNetworkMonitoring) return;
            
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
            // Target a broader range of network functions
            const networkFunctions = [
                // Socket functions
                { name: "recv", module: null },
                { name: "recvfrom", module: null },
                { name: "read", module: null },
                { name: "WSARecv", module: "WS2_32.dll" },
                { name: "WSARecvFrom", module: "WS2_32.dll" },
                
                // SSL functions
                { name: "SSL_read", module: null },
                { name: "SSL_read_ex", module: null },
                { name: "BIO_read", module: null },
                { name: "mbedtls_ssl_read", module: null },
                { name: "wolfSSL_read", module: null },
                { name: "gnutls_record_recv", module: null },
                
                // HTTP functions
                { name: "nghttp2_session_mem_recv", module: null },
                { name: "curl_easy_recv", module: null }
            ];
            
            let hookedCount = 0;
            
            for (const funcInfo of networkFunctions) {
                try {
                    const funcPtr = funcInfo.module ? 
                        Module.findExportByName(funcInfo.module, funcInfo.name) :
                        Module.findExportByName(null, funcInfo.name);
                    
                    if (funcPtr && !STATE.hookedFunctions.has(funcPtr.toString())) {
                        STATE.hookedFunctions.add(funcPtr.toString());
                        
                        Utils.log(2, `Hooking network function: ${funcInfo.name} at ${funcPtr}`);
                        
                        Interceptor.attach(funcPtr, {
                            onEnter: function(args) {
                                this.funcName = funcInfo.name;
                                this.buffer = args[1];  // Most network functions have buffer as 2nd arg
                                this.context = this.context;
                            },
                            onLeave: function(retval) {
                                const size = retval.toInt32();
                                
                                if (size > CONFIG.minBufferSize && size < CONFIG.maxBufferSize) {
                                    try {
                                        const buffer = Memory.readByteArray(this.buffer, size);
                                        
                                        if (Utils.isLikelyProtobuf(buffer)) {
                                            Utils.log(0, `[FOUND] Potential protobuf data from ${this.funcName} (${size} bytes)`);
                                            Utils.log(1, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                            Utils.saveBuffer(buffer, `proto_net_${this.funcName}`);
                                            
                                            // Add advanced backtrace info at higher verbosity
                                            if (CONFIG.logLevel >= 2) {
                                                Utils.log(2, `Backtrace:\n${Utils.getBacktrace(this.context)}`);
                                            }
                                        }
                                    } catch (e) {
                                        // Just silently skip errors reading the buffer
                                    }
                                }
                            }
                        });
                        
                        hookedCount++;
                        STATE.hookCount.total++;
                    }
                } catch (e) {
                    Utils.log(2, `Failed to hook ${funcInfo.name}: ${e}`);
                }
            }
            
            Utils.log(1, `Hooked ${hookedCount} network functions`);
        }
    };

    // ================ String Search Strategy ================
    const StringSearcher = {
        init: function() {
            if (!CONFIG.enableStringSearching) return;
            
            Utils.log(1, "Initializing protobuf string search");
            
            setTimeout(() => {
                try {
                    this.findProtobufStrings();
                } catch (e) {
                    Utils.log(0, `Error in string searching: ${e}`);
                }
            }, CONFIG.initialDelayMs + CONFIG.staggeredDelayMs);
        },
        
        findProtobufStrings: function() {
            // Select modules to scan
            let modulesToScan = [];
            
            if (CONFIG.scanMainModule) {
                try {
                    const mainModule = Process.getModuleByName(Process.enumerateModules()[0].name);
                    modulesToScan.push(mainModule);
                } catch (e) {
                    Utils.log(0, `Error getting main module: ${e}`);
                }
            }
            
            // Try to add other modules that might contain protobuf
            for (const modNamePattern of CONFIG.scanAdditionalModules) {
                try {
                    // Find modules matching the pattern
                    const matchingModules = Process.enumerateModules().filter(mod => 
                        mod.name.toLowerCase().includes(modNamePattern.toLowerCase()));
                    
                    for (const mod of matchingModules) {
                        // Skip if we already have this module
                        if (modulesToScan.some(m => m.name === mod.name)) continue;
                        
                        // Skip system libraries unless specifically configured to include them
                        if (!CONFIG.scanSystemModules && 
                            (mod.path.includes('/system/') || 
                             mod.path.includes('\\Windows\\') || 
                             mod.path.includes('\\System32\\'))) {
                            continue;
                        }
                        
                        modulesToScan.push(mod);
                    }
                } catch (e) {
                    // Module not found, just skip it
                }
            }
            
            Utils.log(1, `Scanning ${modulesToScan.length} modules for protobuf strings`);
            
            // Expanded list of protobuf-related strings
            const protoKeywords = [
                "protobuf", 
                "google.protobuf",
                "google::protobuf",
                "proto2",
                "proto3",
                ".proto",
                "message_lite",
                "MessageLite",
                "ParseFromArray",
                "SerializeToArray",
                "ParseFromString",
                "SerializeToString",
                "wire_format",
                "WireFormat",
                "Clear",
                "MergeFrom",
                "descriptor.proto"
            ];
            
            for (const module of modulesToScan) {
                Utils.log(2, `Scanning module ${module.name}`);
                STATE.hookCount.byModule[module.name] = STATE.hookCount.byModule[module.name] || 0;
                
                for (const keyword of protoKeywords) {
                    try {
                        // Convert the string to a proper byte pattern
                        const pattern = Utils.stringToBytes(keyword);
                        
                        // Use a more resilient approach with smaller ranges
                        this.scanModuleInChunks(module, pattern, keyword);
                        
                        // Check if we've reached the hook limit for this module
                        if (STATE.hookCount.byModule[module.name] >= CONFIG.maxHooksPerModule) {
                            Utils.log(1, `Reached maximum hooks (${CONFIG.maxHooksPerModule}) for module ${module.name}`);
                            break;
                        }
                    } catch (e) {
                        Utils.log(2, `Error scanning for "${keyword}" in ${module.name}: ${e}`);
                    }
                }
            }
        },
        
        // Scan a module in smaller chunks to prevent crashes
        scanModuleInChunks: function(module, pattern, originalString) {
            const chunkSize = 1024 * 1024; // 1MB chunks
            let matchCount = 0;
            
            for (let offset = 0; offset < module.size; offset += chunkSize) {
                if (STATE.hookCount.total >= CONFIG.maxTotalHooks) {
                    Utils.log(1, `Reached maximum total hooks (${CONFIG.maxTotalHooks})`);
                    return;
                }
                
                const scanSize = Math.min(chunkSize, module.size - offset);
                const scanAddress = module.base.add(offset);
                
                try {
                    const matches = Memory.scanSync(scanAddress, scanSize, pattern);
                    
                    for (const match of matches) {
                        matchCount++;
                        Utils.log(2, `Found string "${originalString}" at ${match.address}`);
                        
                        // Hook functions near the string references
                        this.findReferencingFunctions(match.address, module);
                        
                        // Limit the number of matches per string to avoid too many hooks
                        if (matchCount >= 5) break;
                    }
                } catch (e) {
                    Utils.log(3, `Error scanning chunk at ${scanAddress}: ${e}`);
                }
                
                // Limit the matches to avoid overloading
                if (matchCount >= 5) break;
                
                // Stop if we've added too many hooks for this module
                if (STATE.hookCount.byModule[module.name] >= CONFIG.maxHooksPerModule) break;
            }
            
            if (matchCount > 0) {
                Utils.log(1, `Found ${matchCount} occurrences of "${originalString}" in ${module.name}`);
            }
        },
        
        // Find functions that reference the found strings
        findReferencingFunctions: function(stringAddr, module) {
            try {
                // Check for references to this string
                this.findStringReferences(stringAddr, module);
                
                // Also look for functions near the string
                this.findNearbyFunctions(stringAddr, module);
            } catch (e) {
                Utils.log(2, `Error finding referencing functions: ${e}`);
            }
        },
        
        // Find references to a string address
        findStringReferences: function(stringAddr, module) {
            // For each potential match, scan back for function prologues
            const maxDistance = 128; // Look back this many bytes maximum
            const pageSize = 4096;
            
            // Range to scan for references
            const scanRange = Math.min(module.size, 10 * 1024 * 1024); // First 10MB of module
            
            // Convert the address to a pattern to search for
            const addrValue = stringAddr.toUInt32();
            const addrBytes = [];
            for (let i = 0; i < Process.pointerSize; i++) {
                addrBytes.push((addrValue >> (i * 8)) & 0xFF);
            }
            
            try {
                // Scan for references to this address
                const matches = Memory.scanSync(module.base, scanRange, addrBytes);
                
                for (const match of matches) {
                    Utils.log(2, `Found reference to string at ${match.address}`);
                    
                    // Find the function start
                    const funcStart = this.findFunctionStart(match.address, module, maxDistance);
                    if (funcStart) {
                        Utils.log(1, `Found function referencing protobuf string at ${funcStart}`);
                        HookManager.hookFunction(funcStart, "string_ref", module);
                    }
                }
            } catch (e) {
                Utils.log(2, `Error searching for references: ${e}`);
            }
        },
        
        // Look for functions near the string definition
        findNearbyFunctions: function(stringAddr, module) {
            const commonPrefixes = [
                // push rbp; mov rbp, rsp
                [0x55, 0x48, 0x89, 0xe5],
                // sub rsp, XX
                [0x48, 0x83, 0xec],
                // push rbx
                [0x53, 0x48],
                // mov rdi, rsi
                [0x48, 0x89, 0xf7]
            ];
            
            // Look both backward and forward
            const checkRange = 256;
            
            for (let offset = -checkRange; offset < checkRange; offset += 4) {
                try {
                    const checkAddr = stringAddr.add(offset);
                    
                    // Make sure we're still within the module
                    if (checkAddr.compare(module.base) < 0 || 
                        checkAddr.compare(module.base.add(module.size)) >= 0) {
                        continue;
                    }
                    
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
                            Utils.log(1, `Found potential function near protobuf string at ${checkAddr}`);
                            HookManager.hookFunction(checkAddr, "near_string", module);
                            return; // Just hook one function per string
                        }
                    }
                } catch (e) {
                    // Skip inaccessible memory
                }
            }
        },
        
        // Find the start of a function containing the given address
        findFunctionStart: function(refAddr, module, maxDistance) {
            const commonPrefixes = [
                // push rbp; mov rbp, rsp
                [0x55, 0x48, 0x89, 0xe5],
                // sub rsp, XX
                [0x48, 0x83, 0xec],
                // push rbx
                [0x53, 0x48],
                // push r15
                [0x41, 0x57],
                // push r14
                [0x41, 0x56]
            ];
            
            // Look backward for function prologues
            for (let offset = 0; offset < maxDistance; offset += 4) {
                try {
                    const checkAddr = refAddr.sub(offset);
                    
                    // Make sure we're still within the module
                    if (checkAddr.compare(module.base) < 0) {
                        break;
                    }
                    
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

    // ================ Memory Allocation Monitoring ================
    const MemoryMonitor = {
        init: function() {
            if (!CONFIG.enableMemoryMonitoring) return;
            
            Utils.log(1, "Initializing memory allocation monitoring");
            
            setTimeout(() => {
                try {
                    this.hookAllocators();
                } catch (e) {
                    Utils.log(0, `Error initializing memory hooks: ${e}`);
                }
            }, CONFIG.initialDelayMs + CONFIG.staggeredDelayMs * 2);
        },
        
        hookAllocators: function() {
            // Target both C and C++ allocators
            const allocators = [
                { name: "malloc", argSize: 0 },
                { name: "operator new", argSize: 0 },
                { name: "operator new[]", argSize: 0 }
            ];
            
            for (const allocator of allocators) {
                try {
                    const funcPtr = Module.findExportByName(null, allocator.name);
                    
                    if (funcPtr && !STATE.hookedFunctions.has(funcPtr.toString())) {
                        STATE.hookedFunctions.add(funcPtr.toString());
                        
                        Utils.log(2, `Hooking allocator: ${allocator.name} at ${funcPtr}`);
                        
                        Interceptor.attach(funcPtr, {
                            onEnter: function(args) {
                                this.size = args[allocator.argSize].toInt32();
                                
                                // Only track reasonably sized allocations that might be protobuf messages
                                this.interesting = (
                                    this.size >= CONFIG.minBufferSize && 
                                    this.size <= CONFIG.maxBufferSize
                                );
                                
                                // Get caller information
                                if (this.interesting && CONFIG.logLevel >= 3) {
                                    this.returnAddr = this.returnAddress;
                                    this.backtrace = Utils.getBacktrace(this.context);
                                }
                            },
                            onLeave: function(retval) {
                                if (this.interesting && !retval.isNull()) {
                                    // Remember this allocation to check later
                                    setTimeout(() => {
                                        try {
                                            const buffer = Utils.safeReadMemory(retval, this.size);
                                            
                                            if (buffer && Utils.isLikelyProtobuf(buffer)) {
                                                Utils.log(0, `[FOUND] ${allocator.name}(${this.size}) allocated protobuf data at ${retval}`);
                                                Utils.log(1, `Buffer preview:\n${Utils.hexdump(buffer)}`);
                                                Utils.saveBuffer(buffer, `proto_${allocator.name.replace(' ', '_')}`);
                                                
                                                // Log the backtrace at higher verbosity
                                                if (CONFIG.logLevel >= 3) {
                                                    Utils.log(3, `Allocation backtrace:\n${this.backtrace}`);
                                                }
                                            }
                                        } catch (e) {
                                            // Ignore errors checking the allocation
                                        }
                                    }, 50); // Short delay to let the buffer be filled
                                }
                            }
                        });
                        
                        STATE.hookCount.total++;
                    }
                } catch (e) {
                    Utils.log(2, `Failed to hook ${allocator.name}: ${e}`);
                }
            }
        }
    };

    // ================ Export Function Scanner ================
    const ExportScanner = {
        init: function() {
            if (!CONFIG.enableExportScanning) return;
            
            Utils.log(1, "Initializing export function scanning");
            
            setTimeout(() => {
                try {
                    this.scanExports();
                } catch (e) {
                    Utils.log(0, `Error scanning exports: ${e}`);
                }
            }, CONFIG.initialDelayMs + CONFIG.staggeredDelayMs * 3);
        },
        
        scanExports: function() {
            // Get all loaded modules
            const modules = Process.enumerateModules();
            let modulesToScan = [];
            
            if (CONFIG.scanMainModule) {
                modulesToScan.push(modules[0]); // Main module
            }
            
            // Add modules matching the patterns
            for (const modNamePattern of CONFIG.scanAdditionalModules) {
                const matchingModules = modules.filter(mod => 
                    mod.name.toLowerCase().includes(modNamePattern.toLowerCase()));
                
                for (const mod of matchingModules) {
                    if (!modulesToScan.some(m => m.name === mod.name)) {
                        modulesToScan.push(mod);
                    }
                }
            }
            
            Utils.log(1, `Scanning exports in ${modulesToScan.length} modules`);
            
            // Patterns that might indicate protobuf-related functions
            const protoExportPatterns = [
                "proto", "grpc", "message", "serialize", "parse", "descriptor",
                "encode", "decode", "pb_", "pb.", "_pb", ".pb", "msg_"
            ];
            
            for (const module of modulesToScan) {
                Utils.log(2, `Scanning exports in ${module.name}`);
                
                try {
                    const exports = module.enumerateExports();
                    
                    for (const exp of exports) {
                        // Check if the export name matches any of our patterns
                        const matchesPattern = protoExportPatterns.some(pattern => 
                            exp.name.toLowerCase().includes(pattern.toLowerCase()));
                        
                        if (matchesPattern) {
                            Utils.log(1, `Found potential protobuf export: ${exp.name} at ${exp.address}`);
                            HookManager.hookFunction(exp.address, "export", module);
                            
                            // Check if we've reached the hook limit for this module
                            if (STATE.hookCount.byModule[module.name] >= CONFIG.maxHooksPerModule) {
                                Utils.log(1, `Reached maximum hooks for module ${module.name}`);
                                break;
                            }
                        }
                    }
                } catch (e) {
                    Utils.log(1, `Error scanning exports in ${module.name}: ${e}`);
                }
            }
        }
    };

    // ================ Native Function Hook Manager ================
    const HookManager = {
        hookFunction: function(address, source, module) {
            const addrStr = address.toString();
            
            // Don't hook the same function multiple times
            if (STATE.hookedFunctions.has(addrStr)) {
                return false;
            }
            
            // Check if we've reached global hook limits
            if (STATE.hookCount.total >= CONFIG.maxTotalHooks) {
                Utils.log(1, `Skipping hook at ${address}: reached global limit of ${CONFIG.maxTotalHooks}`);
                return false;
            }
            
            // Check module-specific limits if a module was provided
            if (module) {
                const moduleName = module.name;
                STATE.hookCount.byModule[moduleName] = STATE.hookCount.byModule[moduleName] || 0;
                
                if (STATE.hookCount.byModule[moduleName] >= CONFIG.maxHooksPerModule) {
                    Utils.log(2, `Skipping hook at ${address}: reached module limit for ${moduleName}`);
                    return false;
                }
                
                STATE.hookCount.byModule[moduleName]++;
            }
            
            // Track this function as hooked
            STATE.hookedFunctions.add(addrStr);
            STATE.hookCount.total++;
            
            if (!CONFIG.enableNativeFunctionHooking) {
                return true; // Just count the hook but don't actually install it
            }
            
            Utils.log(2, `Installing hook at ${address} (source: ${source})`);
            
            try {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        this.args = args;
                        this.source = source;
                        this.address = address;
                        
                        // Check first 4 args for potential buffer pointers
                        for (let i = 0; i < 4; i++) {
                            const arg = this.args[i];
                            if (!arg.isNull()) {
                                Utils.checkMultipleBuffersForProtobuf(arg, source, i, this.context);
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            // Check if return value is a pointer to a buffer
                            Utils.checkMultipleBuffersForProtobuf(retval, `${source}_ret`, 0, this.context);
                        }
                    }
                });
                
                return true;
            } catch (e) {
                Utils.log(1, `Failed to hook function at ${address}: ${e}`);
                return false;
            }
        }
    };

    // ================ Main Initialization ================
    function initialize() {
        Utils.log(0, "Starting advanced protobuf exfiltration script");
        
        try {
            // Create the output directory
            try {
                const dirPath = CONFIG.outputDir;
                // Use a fallback if the directory doesn't exist and can't be created
                try {
                    const testFile = new File(dirPath + "test.txt", "a");
                    testFile.close();
                    // Remove the test file
                    try { new File(dirPath + "test.txt", "r").remove(); } catch (e) {}
                } catch (e) {
                    CONFIG.outputDir = "/data/local/tmp/";
                }
            } catch (e) {
                Utils.log(0, `Error creating output directory: ${e}`);
                CONFIG.outputDir = "/data/local/tmp/";
            }
            
            // Initialize all monitoring strategies in a staggered sequence
            
            // 1. Network monitoring (least invasive)
            NetworkMonitor.init();
            
            // 2. String searching
            StringSearcher.init();
            
            // 3. Memory allocation monitoring
            MemoryMonitor.init();
            
            // 4. Export scanning
            ExportScanner.init();
            
            Utils.log(0, "Initialization complete - waiting for protobuf messages");
        } catch (e) {
            Utils.log(0, `Critical error during initialization: ${e}`);
        }
    }
    
    // Start with a small delay to let the process initialize
    setTimeout(initialize, 1000);
})();
