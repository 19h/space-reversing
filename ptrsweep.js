// Multi-level recursive pointer scanner with tree visualization
// Optimized for high-precision identification of pointer reference chains

const pointerScannerModule = new CModule(`
#include <stdint.h>
#include <stdlib.h>

// Minimal result structure to avoid dependencies
typedef struct {
    void** pointers;
    uint32_t count;
    uint32_t capacity;
} ScanResults;

// Core scanning function with minimal dependencies
void scan_memory_range(void* start_address, uint64_t size, void* target_address, ScanResults* results) {
    // Use pointer-size alignment for scanning
    uintptr_t ptr_size = sizeof(void*);
    uintptr_t aligned_start = ((uintptr_t)start_address + ptr_size - 1) & ~(ptr_size - 1);
    void* end_address = (void*)((uintptr_t)start_address + size - ptr_size);

    // Skip if range is too small
    if ((void*)aligned_start > end_address) return;

    // Scan memory range pointer by pointer
    for (void* current = (void*)aligned_start; current <= end_address; current = (void*)((uintptr_t)current + ptr_size)) {
        // Read potential pointer value (exceptions handled by JS try/catch)
        void* value = *(void**)current;

        // Check if pointer equals target
        if (value == target_address) {
            // Add to results if capacity allows
            if (results->count < results->capacity) {
                results->pointers[results->count++] = current;
            } else {
                // Stop if result buffer is full
                break;
            }
        }
    }
}
`);

/**
 * Find direct pointers to a specific address with aggressive false positive filtering
 *
 * @param {string|number|NativePointer} targetAddress - Target address to find references to
 * @param {Object} options - Configuration options
 * @returns {Array} Array of validated pointers to the target address
 */
function findPointersToAddress(targetAddress, options = {}) {
    // Default options
    const opts = {
        // Core filtering options
        minValidAddress: options.minValidAddress || 0x10000,
        skipNullRegions: options.skipNullRegions !== false,
        filterPatternAddresses: options.filterPatternAddresses !== false,
        validatePointers: options.validatePointers !== false,
        requireModuleMembership: options.requireModuleMembership || false,

        // Pattern detection level
        patternDetectionLevel: options.patternDetectionLevel || 'aggressive',

        // Module filtering
        excludeModules: options.excludeModules || [],
        onlyIncludeModules: options.onlyIncludeModules || [],

        // Result limits
        maxResultsPerRange: options.maxResultsPerRange || 1000,
        maxTotalResults: options.maxTotalResults || 5000,

        // Output options
        includeModuleInfo: options.includeModuleInfo !== false,
        includeMemoryDump: options.includeMemoryDump || false,
        groupByModule: options.groupByModule !== false,

        // Performance options
        batchSize: options.batchSize || 10,
        progressInterval: options.progressInterval || 500,

        // Debug/logging options
        suppressErrors: options.suppressErrors !== false,
        verbose: options.verbose || false
    };

    // Convert target to NativePointer
    const targetPtr = ptr(targetAddress);
    if (opts.verbose) {
        console.log(`[+] Scanning for pointers to: ${targetPtr}`);
    }

    // Get target module information (if available)
    const targetModule = Process.findModuleByAddress(targetPtr);
    if (opts.verbose) {
        if (targetModule) {
            console.log(`[+] Target address belongs to module: ${targetModule.name}`);
        } else {
            console.log(`[+] Target address is not within any known module`);
        }
    }

    // Initialize module map for faster lookups
    const moduleMap = new ModuleMap();

    // Get the relevant modules based on inclusion/exclusion
    if (opts.verbose) {
        console.log(`[+] Collecting module information...`);
    }

    const validModules = Process.enumerateModules().filter(module => {
        // Skip if explicitly excluded
        if (opts.excludeModules.includes(module.name)) return false;

        // Only include if in the inclusion list (if specified)
        if (opts.onlyIncludeModules.length > 0) {
            return opts.onlyIncludeModules.includes(module.name);
        }

        return true;
    });

    // Get all readable memory ranges
    if (opts.verbose) {
        console.log(`[+] Enumerating memory ranges...`);
    }

    const ranges = Process.enumerateRanges({
        protection: 'r--', // Only need read permission to find pointers
        coalesce: true     // Combine adjacent ranges for efficiency
    });

    if (opts.verbose) {
        console.log(`[+] Found ${ranges.length} memory ranges to scan in ${validModules.length} modules`);
    }

    // Create the native scanner function
    const scanMemoryRange = new NativeFunction(
        pointerScannerModule.scan_memory_range,
        'void',
        ['pointer', 'uint64', 'pointer', 'pointer']
    );

    // Create a reusable result buffer
    const maxResultsPerBatch = opts.maxResultsPerRange;
    const resultBufferSize = 8 + (maxResultsPerBatch * Process.pointerSize); // Struct + pointer array
    const resultBuffer = Memory.alloc(resultBufferSize);
    const resultsArray = Memory.alloc(maxResultsPerBatch * Process.pointerSize);

    // Initialize the result struct fields
    resultBuffer.writePointer(resultsArray);                    // pointers array
    resultBuffer.add(Process.pointerSize).writeU32(0);          // count
    resultBuffer.add(Process.pointerSize + 4).writeU32(maxResultsPerBatch); // capacity

    // Track results and statistics
    const results = opts.groupByModule ? {} : [];
    let totalResults = 0;
    let totalBytesScanned = 0;
    let rangesProcessed = 0;
    let startTime = Date.now();
    let lastProgressTime = startTime;

    // Get the minimum module base address to filter out addresses below modules
    const minModuleAddress = Process.enumerateModulesSync().length > 0 ?
                            Process.enumerateModulesSync()[0].base : ptr(opts.minValidAddress);

    // Pattern detection: Check if an address matches known false positive patterns
    function isLikelyPatternAddress(addr) {
        if (!opts.filterPatternAddresses) return false;

        // Convert to string for pattern matching
        const addrStr = addr.toString();
        const addrHex = addrStr.replace('0x', '').toLowerCase();

        // Basic patterns (common in all levels)
        // ------------------------------

        // Null or very low addresses
        if (addr.compare(ptr(opts.minValidAddress)) < 0) return true;

        // Normal patterns (normal/aggressive levels)
        // ------------------------------
        if (opts.patternDetectionLevel !== 'basic') {
            // Repeated digits (e.g., 0x1111111)
            if (/0x(.)\1{5,}/.test(addrStr)) return true;

            // Addresses with long zero sequences
            if (/0x[0-9a-f]{1,4}0{6,}[0-9a-f]{1,4}$/i.test(addrStr)) return true;

            // Power-of-2 addresses or close to them
            const val = parseInt(addrHex, 16);
            const log2 = Math.log2(val);
            if (Math.abs(log2 - Math.round(log2)) < 0.001) return true;

            // Sequential digit patterns
            if (/0x[0-9a-f]{2,}(?:0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)/i.test(addrStr)) return true;
        }

        // Aggressive patterns
        // ------------------------------
        if (opts.patternDetectionLevel === 'aggressive') {
            // Repeated byte patterns
            if (/0x([0-9a-f]{2})\1{3,}/i.test(addrStr)) return true;

            // Sequential byte patterns
            if (/0x[0-9a-f]*?(?:0102030405|0504030201)[0-9a-f]*?$/i.test(addrStr)) return true;

            // Common alignment patterns (page/block boundaries)
            if (/0x[0-9a-f]+00{2,}$/i.test(addrStr)) return true;

            // Handle/special value patterns
            if (/0x[0-9a-f]{1,2}0{4,}[0-9a-f]{1,4}$/i.test(addrStr)) return true;

            // Very high memory regions (often kernel/hardware mappings)
            if (Process.pointerSize === 8 && addr.compare(ptr('0x7000000000000000')) > 0) return true;
        }

        return false;
    }

    // Validate if a pointer is likely legitimate
    function isValidPointer(pointerAddress) {
        // Skip invalid pointers
        if (pointerAddress.isNull()) return false;

        // Skip low addresses
        if (pointerAddress.compare(ptr(opts.minValidAddress)) < 0) return false;

        // Filter out addresses below module space
        if (pointerAddress.compare(minModuleAddress) < 0) return false;

        // Skip pattern addresses
        if (isLikelyPatternAddress(pointerAddress)) return false;

        // Validate pointer is readable if requested
        if (opts.validatePointers) {
            try {
                pointerAddress.readPointer();
            } catch (e) {
                return false;
            }
        }

        // Check if pointer belongs to a module if required
        if (opts.requireModuleMembership) {
            return Process.findModuleByAddress(pointerAddress) !== null;
        }

        return true;
    }

    // Add a result with all requested metadata
    function addResult(pointerAddress, module) {
        if (totalResults >= opts.maxTotalResults) {
            return false;  // Hit total limit
        }

        const result = {
            address: pointerAddress
        };

        // Add module information
        if (opts.includeModuleInfo && module) {
            const offset = pointerAddress.sub(module.base);
            result.moduleOffset = `${module.name}+0x${offset.toString(16)}`;
            result.module = module.name;
        } else if (opts.includeModuleInfo) {
            result.moduleOffset = `<unmapped>+0x${pointerAddress.toString(16)}`;
            result.module = "<unmapped>";
        }

        // Add memory dump if requested
        if (opts.includeMemoryDump) {
            try {
                result.hexDump = hexdump(pointerAddress.sub(16), { length: 48 });
            } catch (e) {
                result.hexDump = "<Memory access error>";
            }
        }

        // Store by module if requested
        if (opts.groupByModule) {
            const moduleName = result.module || "<unmapped>";
            if (!results[moduleName]) {
                results[moduleName] = [];
            }
            results[moduleName].push(result);
        } else {
            results.push(result);
        }

        totalResults++;
        return true;
    }

    // Process each range
    for (let i = 0; i < ranges.length; i++) {
        const range = ranges[i];

        // Skip small ranges
        if (range.size < Process.pointerSize) {
            continue;
        }

        // Skip null regions
        if (opts.skipNullRegions && range.base.isNull()) {
            continue;
        }

        // Skip if range contains our target (to avoid self-references)
        if (range.base.compare(targetPtr) <= 0 &&
            range.base.add(range.size).compare(targetPtr) > 0) {
            if (opts.verbose) {
                console.log(`[*] Skipping range containing target: ${range.base}-${range.base.add(range.size)}`);
            }
            continue;
        }

        // Get module for this range
        const rangeModule = Process.findModuleByAddress(range.base);

        // Skip if module is excluded
        if (rangeModule && opts.excludeModules.includes(rangeModule.name)) {
            continue;
        }

        // Skip if not in included modules
        if (opts.onlyIncludeModules.length > 0 && rangeModule &&
            !opts.onlyIncludeModules.includes(rangeModule.name)) {
            continue;
        }

        // Skip if we require module membership and this is unmapped
        if (opts.requireModuleMembership && !rangeModule) {
            continue;
        }

        // Reset the result buffer counter
        resultBuffer.add(Process.pointerSize).writeU32(0);

        try {
            // Scan this range
            scanMemoryRange(range.base, range.size, targetPtr, resultBuffer);

            // Process results
            const resultCount = resultBuffer.add(Process.pointerSize).readU32();

            if (resultCount > 0) {
                let addedCount = 0;

                // Process and filter each result
                for (let j = 0; j < resultCount; j++) {
                    const pointerAddr = resultsArray.add(j * Process.pointerSize).readPointer();

                    // Apply validation
                    if (isValidPointer(pointerAddr)) {
                        if (addResult(pointerAddr, rangeModule)) {
                            addedCount++;
                        } else {
                            // Hit total limit
                            break;
                        }
                    }
                }

                if (addedCount > 0 && opts.verbose) {
                    console.log(`[+] Found ${addedCount} valid pointers in ${rangeModule ? rangeModule.name : "unmapped"}`);
                }
            }

            totalBytesScanned += range.size;
        } catch (e) {
            if (opts.suppressErrors) {
                console.error(`[-] Error scanning range ${range.base}-${range.base.add(range.size)}: ${e}`);
            } else {
                throw e;
            }
        }

        rangesProcessed++;

        // Show progress periodically
        const now = Date.now();
        if (now - lastProgressTime > opts.progressInterval) {
            const elapsed = (now - startTime) / 1000;
            const scanRate = (totalBytesScanned / (1024 * 1024)) / Math.max(elapsed, 0.001);
            console.log(`[*] Progress: ${rangesProcessed}/${ranges.length} ranges (${Math.floor(rangesProcessed/ranges.length*100)}%), ${totalResults} pointers found, scanning at ${scanRate.toFixed(2)} MB/s`);
            lastProgressTime = now;

            // Yield to prevent UI freezing
            Thread.sleep(0);
        }

        // Yield periodically
        if (i % opts.batchSize === 0) {
            Thread.sleep(0);
        }

        // Stop if hit total limit
        if (totalResults >= opts.maxTotalResults) {
            console.log(`[!] Reached maximum result limit (${opts.maxTotalResults})`);
            break;
        }
    }

    // Calculate final statistics
    const totalElapsed = (Date.now() - startTime) / 1000;
    const finalScanRate = (totalBytesScanned / (1024 * 1024)) / Math.max(totalElapsed, 0.001);

    if (opts.verbose) {
        console.log(`[+] Scan complete: Found ${totalResults} pointers in ${rangesProcessed} ranges`);
        console.log(`[+] Scanned ${(totalBytesScanned / (1024 * 1024)).toFixed(2)} MB at ${finalScanRate.toFixed(2)} MB/s`);
    }

    return results;
}

/**
 * Scan for multi-level pointer references, building a complete reference chain
 *
 * @param {NativePointer|string|number} targetAddress - Initial target address to find references to
 * @param {number} maxDepth - Maximum depth to scan (1 = direct pointers, 2 = pointers to pointers, etc.)
 * @param {Object} options - Scanning and filtering options
 * @returns {Object} - Root node of the reference tree
 */
function scanPointerChain(targetAddress, maxDepth = 1, options = {}) {
    console.log(`[+] Starting recursive pointer scan to depth ${maxDepth}...`);

    // Default options
    const opts = {
        // Core options
        maxPointersPerLevel: options.maxPointersPerLevel || 25,
        maxTotalNodes: options.maxNodesTotal || 1000,
        requireModuleMembership: options.requireModuleMembership || false,
        patternDetectionLevel: options.patternDetectionLevel || 'aggressive',
        validatePointers: options.validatePointers !== false,

        // Tracking options
        verbose: options.verbose || false,
        showProgressInterval: options.showProgressInterval || 500,

        // Pass-through options for the findPointersToAddress function
        ...options
    };

    // Convert to pointer
    const targetPtr = ptr(targetAddress);

    // Get module info for root
    const targetModule = Process.findModuleByAddress(targetPtr);

    // Create root node
    const root = {
        address: targetPtr,
        pointsTo: null,  // Root doesn't point to anything
        children: [],
        depth: 0,
        module: targetModule ? targetModule.name : "<unmapped>",
        moduleOffset: targetModule ?
            `${targetModule.name}+0x${targetPtr.sub(targetModule.base).toString(16)}` :
            `<unmapped>+0x${targetPtr.toString(16)}`
    };

    // Track statistics
    let totalNodes = 1; // Count root
    const nodesAtDepth = new Array(maxDepth + 1).fill(0);
    nodesAtDepth[0] = 1; // Root at depth 0

    // Track already processed addresses to avoid cycles and duplicates
    const processedAddresses = new Set([targetPtr.toString()]);

    // Handle a single level of pointer scanning
    function scanLevel(parentNode, currentDepth) {
        if (currentDepth > maxDepth || totalNodes >= opts.maxTotalNodes) {
            return;
        }

        // Skip root node special case
        if (currentDepth === 0) {
            // Start with depth 1 - find pointers to target
            scanLevel(parentNode, 1);
            return;
        }

        if (opts.verbose) {
            console.log(`[*] Scanning for pointers to ${parentNode.address} at depth ${currentDepth}...`);
        }

        // Find pointers to this node's address
        const pointers = findPointersToAddress(parentNode.address, {
            maxTotalResults: opts.maxPointersPerLevel,
            requireModuleMembership: opts.requireModuleMembership,
            patternDetectionLevel: opts.patternDetectionLevel,
            validatePointers: opts.validatePointers,
            groupByModule: false, // Need flat array
            suppressErrors: true,
            verbose: false        // Reduce output noise
        });

        // No pointers found
        if (!pointers || pointers.length === 0) {
            return;
        }

        // Add each pointer as a child of the parent node
        for (const pointer of pointers) {
            // Skip if already processed (avoid cycles)
            if (processedAddresses.has(pointer.address.toString())) {
                continue;
            }

            // Track this address
            processedAddresses.add(pointer.address.toString());

            // Create child node
            const childNode = {
                address: pointer.address,
                pointsTo: parentNode.address,
                children: [],
                depth: currentDepth,
                module: pointer.module || "<unmapped>",
                moduleOffset: pointer.moduleOffset || `<unmapped>+0x${pointer.address.toString(16)}`
            };

            // Add to parent's children
            parentNode.children.push(childNode);

            // Update statistics
            totalNodes++;
            nodesAtDepth[currentDepth]++;

            if (opts.verbose) {
                console.log(`[+] Added node: ${childNode.address} → ${childNode.pointsTo} (depth ${currentDepth})`);
            }

            // Check node limit
            if (totalNodes >= opts.maxTotalNodes) {
                console.log(`[!] Reached maximum node limit (${opts.maxTotalNodes})`);
                return;
            }

            // Continue recursion if not at max depth
            if (currentDepth < maxDepth) {
                scanLevel(childNode, currentDepth + 1);
            }
        }
    }

    // Start recursive scan from root
    scanLevel(root, 0);

    // Summarize results
    console.log(`[+] Reference chain scan complete to depth ${maxDepth}`);
    console.log(`[+] Total nodes in tree: ${totalNodes}`);

    for (let i = 0; i <= maxDepth; i++) {
        console.log(`[+] Depth ${i}: ${nodesAtDepth[i]} nodes`);
    }

    return root;
}

/**
 * Format a pointer reference tree as an ASCII flowchart diagram
 *
 * @param {Object} root - Root node from scanPointerChain
 * @param {Object} options - Display options
 * @returns {string} Formatted tree representation
 */
function formatPointerTree(root, options = {}) {
    // Default options
    const opts = {
        maxDepth: options.maxDepth || 10,
        showModuleInfo: options.showModuleInfo !== false,
        indentSize: options.indentSize || 4,
        compactMode: options.compactMode || false,
        pointerFormat: options.pointerFormat || "full" // "full", "compact", "offset"
    };

    let output = "";

    // Helper to format address display
    function formatAddress(node) {
        switch (opts.pointerFormat) {
            case "compact":
                return `0x${node.address.toString(16).slice(-8)}`;
            case "offset":
                if (node.moduleOffset) {
                    return node.moduleOffset;
                }
                return node.address.toString();
            case "full":
            default:
                return node.address.toString();
        }
    }

    // Recursive function to print a node and its children
    function printNode(node, depth, prefix = "", isLast = true) {
        if (depth > opts.maxDepth) return;

        // Special handling for root node
        if (depth === 0) {
            output += `${formatAddress(node)} (Target Address)\n`;

            // Print children
            for (let i = 0; i < node.children.length; i++) {
                const child = node.children[i];
                const childIsLast = i === node.children.length - 1;
                printNode(child, depth + 1, "", childIsLast);
            }
            return;
        }

        // Create the line prefix with proper tree structure
        const connector = isLast ? "└── " : "├── ";
        const linePrefix = prefix + connector;

        // Format node information
        let nodeInfo = `${formatAddress(node)}`;
        if (node.pointsTo) {
            nodeInfo += ` → ${formatAddress({address: node.pointsTo})}`;
        }

        // Add module information if requested
        if (opts.showModuleInfo && node.moduleOffset) {
            nodeInfo += ` (${node.moduleOffset})`;
        }

        output += `${linePrefix}${nodeInfo}\n`;

        // Prepare indent for child nodes
        const childPrefix = prefix + (isLast ? " ".repeat(opts.indentSize) : "│" + " ".repeat(opts.indentSize - 1));

        // Print children recursively
        for (let i = 0; i < node.children.length; i++) {
            const child = node.children[i];
            const childIsLast = i === node.children.length - 1;
            printNode(child, depth + 1, childPrefix, childIsLast);
        }
    }

    // Start printing from root
    printNode(root, 0);

    return output;
}

/**
 * Primary interface for multi-level pointer scanning with tree visualization
 *
 * @param {NativePointer|string|number} targetAddress - Address to find pointers to
 * @param {number} depth - Maximum recursion depth
 * @param {Object} options - Scanning and display options
 * @returns {Object} Scan results - either direct pointers or reference tree
 */
function findPointers(targetAddress, depth = 1, options = {}) {
    // Default options
    const opts = {
        // Core scanning parameters
        depth: typeof depth === 'number' ? depth : 1,

        // Filtering options
        minValidAddress: options.minValidAddress || 0x10000,
        requireModuleMembership: options.requireModuleMembership || false,
        filterPatternAddresses: options.filterPatternAddresses !== false,
        patternDetectionLevel: options.patternDetectionLevel || 'aggressive',
        validatePointers: options.validatePointers !== false,

        // Tree-specific options (for multi-level scans)
        maxPointersPerLevel: options.maxPointersPerLevel || 25,
        maxNodesTotal: options.maxNodesTotal || 1000,

        // Display options
        printTree: options.printTree !== false,
        showModuleInfo: options.showModuleInfo !== false,
        pointerFormat: options.pointerFormat || "full",
        format: options.format !== false,

        // Verbose output
        verbose: options.verbose || false,

        // Pass-through all other options
        ...options
    };

    // Convert to pointer once
    const targetPtr = ptr(targetAddress);

    // For multi-level recursion, use pointer chain scanning
    if (opts.depth > 1) {
        console.log(`[+] Starting multi-level pointer scan for ${targetPtr} with depth ${opts.depth}`);

        // Build reference tree
        const referenceTree = scanPointerChain(targetPtr, opts.depth, {
            maxPointersPerLevel: opts.maxPointersPerLevel,
            maxNodesTotal: opts.maxNodesTotal,
            requireModuleMembership: opts.requireModuleMembership,
            patternDetectionLevel: opts.patternDetectionLevel,
            validatePointers: opts.validatePointers,
            minValidAddress: opts.minValidAddress,
            verbose: opts.verbose
        });

        // Display formatted tree if requested
        if (opts.printTree) {
            const treeOutput = formatPointerTree(referenceTree, {
                maxDepth: opts.depth,
                showModuleInfo: opts.showModuleInfo,
                pointerFormat: opts.pointerFormat,
                compactMode: opts.compactMode
            });

            console.log(`\n[+] Pointer Reference Tree for ${targetPtr}:`);
            console.log(treeOutput);
        }

        return referenceTree;
    }
    // For direct pointers only (depth=1), use single-level scan
    else {
        if (opts.verbose) {
            console.log(`[+] Starting single-level pointer scan for ${targetPtr}`);
        }

        // Use direct scanning
        const results = findPointersToAddress(targetPtr, {
            minValidAddress: opts.minValidAddress,
            filterPatternAddresses: opts.filterPatternAddresses,
            patternDetectionLevel: opts.patternDetectionLevel,
            validatePointers: opts.validatePointers,
            requireModuleMembership: opts.requireModuleMembership,
            maxResultsPerRange: opts.maxResultsPerRange || 1000,
            maxTotalResults: opts.maxTotalResults || 5000,
            includeModuleInfo: true,
            includeMemoryDump: opts.includeMemoryDump || false,
            groupByModule: true,
            suppressErrors: true,
            verbose: opts.verbose
        });

        // Format results for display if requested
        if (opts.format) {
            formatResults(results, {
                maxPerModule: opts.maxDisplay || 20,
                showMemoryDumps: opts.showMemoryDumps || false
            });
        }

        return results;
    }
}

/**
 * Format scan results for display
 */
function formatResults(results, options = {}) {
    const opts = {
        maxPerModule: options.maxPerModule || 10,
        showMemoryDumps: options.showMemoryDumps || false,
        sort: options.sort || 'address'
    };

    // Handle array output (flat results)
    if (Array.isArray(results)) {
        // Sort results as requested
        if (opts.sort === 'address') {
            results.sort((a, b) => a.address.compare(b.address));
        } else if (opts.sort === 'module') {
            results.sort((a, b) => (a.module || "").localeCompare(b.module || ""));
        }

        console.log(`\n[+] Results (${results.length} pointers found):`);

        const displayCount = Math.min(results.length, opts.maxPerModule);
        for (let i = 0; i < displayCount; i++) {
            const result = results[i];
            console.log(`  [${i}] ${result.address} ${result.moduleOffset || ''}`);

            if (opts.showMemoryDumps && result.hexDump) {
                console.log(result.hexDump);
            }
        }

        if (results.length > displayCount) {
            console.log(`  ... and ${results.length - displayCount} more`);
        }
    }
    // Handle object output (grouped by module)
    else if (typeof results === 'object' && !results.address) {
        const modules = Object.keys(results).sort();

        for (const module of modules) {
            const moduleResults = results[module];
            console.log(`\n[+] Module: ${module} (${moduleResults.length} pointers found)`);

            // Sort by address within module
            moduleResults.sort((a, b) => a.address.compare(b.address));

            const displayCount = Math.min(moduleResults.length, opts.maxPerModule);
            for (let i = 0; i < displayCount; i++) {
                const result = moduleResults[i];
                console.log(`  [${i}] ${result.address} ${result.moduleOffset || ''}`);

                if (opts.showMemoryDumps && result.hexDump) {
                    console.log(result.hexDump);
                }
            }

            if (moduleResults.length > displayCount) {
                console.log(`  ... and ${moduleResults.length - displayCount} more`);
            }
        }
    }
    // Handle tree-structured results (from recursive scanning)
    else if (typeof results === 'object' && results.address) {
        // Display tree visualization
        const treeOutput = formatPointerTree(results, {
            showModuleInfo: true
        });

        console.log(`\n[+] Pointer Reference Tree for ${results.address}:`);
        console.log(treeOutput);
    }

    return results;
}

// Example usage
function main() {
    // Example 1: Find direct pointers
    const targetFunction = Module.findExportByName(null, "malloc");
    if (!targetFunction) {
        console.error("[-] Could not find target function");
        return;
    }

    console.log(`[+] Example 1: Direct pointers to ${targetFunction}`);

    const results = findPointers(targetFunction, 1, {
        patternDetectionLevel: 'aggressive',
        requireModuleMembership: true,
        validatePointers: true,
        maxResultsPerRange: 500,
        verbose: false
    });

    // Example 2: Multi-level pointer scan with tree visualization
    console.log(`\n[+] Example 2: Multi-level pointer scan for ${targetFunction}`);

    const treeResults = findPointers(targetFunction, 2, {
        patternDetectionLevel: 'aggressive',
        requireModuleMembership: true,
        validatePointers: true,
        maxPointersPerLevel: 5,  // Limit for demonstration
        maxNodesTotal: 50,       // Limit for demonstration
        verbose: true,
        pointerFormat: "full"    // Show full addresses in tree
    });
}

// Export functions for module use
rpc.exports = {
    findPointers: findPointers,
    findPointersToAddress: findPointersToAddress,
    scanPointerChain: scanPointerChain,
    formatPointerTree: formatPointerTree,
    formatResults: formatResults
};

// Uncomment to run immediately
// main();
