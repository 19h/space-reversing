/**
 * SCigEventSystem::AddToEventQueue Hook - Event Logger
 * 
 * This script hooks the function responsible for adding events to the game's event queue,
 * capturing and analyzing all event data for debugging and reverse engineering purposes.
 * 
 * Based on decompiled function at 0x140391380, identified as SCigEventSystem::AddToEventQueue
 * Parameters:
 *   a1: Event queue system pointer
 *   a2: Pointer to event data (24 bytes/0x18 structure)
 */

// Configuration options
const CONFIG = {
    maxEvents: 0,                 // Maximum events to log (0 = unlimited)
    logLevel: 1,                  // 0=minimal, 1=normal, 2=verbose
    enableThrottling: true,       // Limit logging frequency for repetitive events
    throttleWindow: 1000,         // Milliseconds between logging same event type
    eventFilter: null,            // Array of event IDs to include, null = all
    pointerMemoryDumpSize: 16     // Bytes to dump when analyzing pointers
};

// Statistics tracking
const STATS = {
    eventsLogged: 0,
    eventsFiltered: 0,
    eventsThrottled: 0,
    eventTypes: new Map(),        // Map of event type to count
    startTime: Date.now()
};

// Throttling state
const THROTTLE_STATE = {
    lastLoggedTimestamp: new Map() // Map of event ID to timestamp
};

/**
 * Analyzes event data structure, interpreting it in multiple ways
 * @param {NativePointer} eventDataPtr - Pointer to the 24-byte event structure
 * @returns {Object} - Structured analysis of the event data
 */
function analyzeEventData(eventDataPtr) {
    if (eventDataPtr.isNull()) {
        return { error: "Null event data pointer" };
    }
    
    try {
        // Create basic structure for event analysis
        const eventAnalysis = {
            address: eventDataPtr,
            rawHex: hexdump(eventDataPtr, { length: 24, header: false, ansi: false }),
            
            // First 4 bytes are likely event type/ID
            possibleEventId: eventDataPtr.readU32(),
            
            // Different interpretations of the data
            asIntegers: {
                u32: [0, 4, 8, 12, 16, 20].map(offset => eventDataPtr.add(offset).readU32().toString(16)),
                i32: [0, 4, 8, 12, 16, 20].map(offset => eventDataPtr.add(offset).readS32().toString(16)),
                u64: [0, 8, 16].map(offset => eventDataPtr.add(offset).readU64().toString(16)),
                i64: [0, 8, 16].map(offset => eventDataPtr.add(offset).readS64().toString(16))
            },
            
            asPointers: {
                // Read as pointers at different offsets
                pointers: [0, 8, 16].map(offset => {
                    const ptrValue = eventDataPtr.add(offset).readPointer();
                    return {
                        value: ptrValue,
                        isNull: ptrValue.isNull(),
                        // If pointer is valid and we're in verbose mode, try to read memory
                        memory: CONFIG.logLevel >= 2 && !ptrValue.isNull() ? 
                                  tryReadMemory(ptrValue, CONFIG.pointerMemoryDumpSize) : null
                    };
                })
            }
        };
        
        return eventAnalysis;
    } catch (error) {
        return {
            address: eventDataPtr,
            error: `Failed to analyze event data: ${error.message}`
        };
    }
}

/**
 * Safely attempts to read memory from a pointer location
 * @param {NativePointer} ptr - Pointer to read from
 * @param {Number} size - Number of bytes to read
 * @returns {Object|null} - Memory data or null if failed
 */
function tryReadMemory(ptr, size) {
    try {
        // Check if pointer seems valid
        if (ptr.isNull() || ptr.toInt32() < 0x1000) {
            return null;
        }
        
        // Try to get memory range information
        let range = null;
        try {
            range = Process.findRangeByAddress(ptr);
        } catch (e) {
            return null; // Address not in accessible range
        }
        
        if (!range || !range.protection.includes('r')) {
            return null; // Not readable memory
        }
        
        // Try to detect if it might be a string
        let asString = null;
        try {
            const tempStr = ptr.readCString();
            if (tempStr && tempStr.length > 0 && tempStr.length < 100) {
                asString = tempStr;
            }
        } catch (e) {
            // Not a string
        }
        
        return {
            hex: hexdump(ptr, { length: size, header: false, ansi: false }),
            asString: asString
        };
    } catch (error) {
        return null;
    }
}

/**
 * Returns a formatted representation of a pointer, with module info if available
 * @param {NativePointer} ptr - The pointer to format
 * @returns {String} - Formatted pointer string
 */
function formatPointer(ptr) {
    if (ptr.isNull()) {
        return "NULL";
    }
    
    try {
        const moduleName = Process.findModuleByAddress(ptr)?.name;
        return moduleName ? 
            `${ptr} (${moduleName}+0x${ptr.sub(Module.findBaseAddress(moduleName)).toString(16)})` : 
            ptr.toString();
    } catch (e) {
        return ptr.toString();
    }
}

/**
 * Determines if an event should be throttled based on its ID
 * @param {Number} eventId - The event ID to check
 * @returns {Boolean} - True if event should be throttled, false otherwise
 */
function shouldThrottleEvent(eventId) {
    if (!CONFIG.enableThrottling) {
        return false;
    }
    
    const now = Date.now();
    const lastLogged = THROTTLE_STATE.lastLoggedTimestamp.get(eventId) || 0;
    
    if (now - lastLogged < CONFIG.throttleWindow) {
        STATS.eventsThrottled++;
        return true;
    }
    
    // Update last logged timestamp
    THROTTLE_STATE.lastLoggedTimestamp.set(eventId, now);
    return false;
}

/**
 * Logs event information based on current configuration
 * @param {Object} eventInfo - The event information to log
 * @param {NativePointer} eventSystemPtr - Pointer to the event system
 */
function logEvent(eventInfo, eventSystemPtr) {
    // Check if we've reached the maximum events limit
    if (CONFIG.maxEvents > 0 && STATS.eventsLogged >= CONFIG.maxEvents) {
        if (STATS.eventsLogged === CONFIG.maxEvents) {
            console.log(`[*] Maximum event limit (${CONFIG.maxEvents}) reached. Stopping logging.`);
            STATS.eventsLogged++; // Increment to prevent this message from showing again
        }
        return;
    }
    
    // Check event filter if configured
    if (CONFIG.eventFilter && 
        Array.isArray(CONFIG.eventFilter) && 
        !CONFIG.eventFilter.includes(eventInfo.possibleEventId)) {
        STATS.eventsFiltered++;
        return;
    }
    
    // Check throttling
    if (shouldThrottleEvent(eventInfo.possibleEventId)) {
        return;
    }
    
    // Increment stats
    STATS.eventsLogged++;
    
    // Update event type stats
    const currentCount = STATS.eventTypes.get(eventInfo.possibleEventId) || 0;
    STATS.eventTypes.set(eventInfo.possibleEventId, currentCount + 1);
    
    // Create log message
    let logMsg = `[Event #${STATS.eventsLogged}] ID: ${eventInfo.possibleEventId} (0x${eventInfo.possibleEventId.toString(16)})`;
    
    // Add more details based on log level
    if (CONFIG.logLevel >= 1) {
        logMsg += `\nData @ ${eventInfo.address}:\n${eventInfo.rawHex}`;
    }
    
    if (CONFIG.logLevel >= 2) {
        // Add detailed interpretations
        logMsg += "\n\nPossible Interpretations:";
        logMsg += "\n- As U32: " + eventInfo.asIntegers.u32.join(", ");
        logMsg += "\n- As S32: " + eventInfo.asIntegers.i32.join(", ");
        logMsg += "\n- As U64: " + eventInfo.asIntegers.u64.join(", ");
        logMsg += "\n- As S64: " + eventInfo.asIntegers.i64.join(", ");
        
        logMsg += "\n\nPointers:";
        for (let i = 0; i < eventInfo.asPointers.pointers.length; i++) {
            const ptrInfo = eventInfo.asPointers.pointers[i];
            logMsg += `\n- Offset ${i*8}: ${formatPointer(ptrInfo.value)}`;
            
            if (ptrInfo.memory && ptrInfo.memory.asString) {
                logMsg += `\n  String: "${ptrInfo.memory.asString}"`;
            }
            
            if (ptrInfo.memory && ptrInfo.memory.hex && !ptrInfo.isNull) {
                logMsg += `\n  Data: ${ptrInfo.memory.hex}`;
            }
        }
        
        logMsg += `\n\nEvent System: ${formatPointer(eventSystemPtr)}`;
    }
    
    //console.log(logMsg);
    
    // Send via IPC
    ///*send*/(r => console.log(JSON.stringify(r, null, 4)))({
    //    type: "event_log",
    //    eventNumber: STATS.eventsLogged,
    //    eventId: eventInfo.possibleEventId,
    //    data: CONFIG.logLevel >= 1 ? eventInfo : null
    //});

    const ptrs = eventInfo.asPointers.pointers.map(a => ptr(a.value));

    console.log(`${eventInfo.possibleEventId.toString(16)} ; ${ptrs.join(' - ')}`);
}

/**
 * Print script statistics
 */
function printStats() {
    const duration = (Date.now() - STATS.startTime) / 1000;
    
    // Convert event types map to sorted array
    const sortedEventTypes = Array.from(STATS.eventTypes.entries())
        .sort((a, b) => b[1] - a[1]) // Sort by count descending
        .map(([id, count]) => `  Event ID ${id} (0x${id.toString(16)}): ${count} occurrences`);
    
    console.log(`
===== Event Logger Statistics =====
Events logged: ${STATS.eventsLogged}
Events filtered: ${STATS.eventsFiltered}
Events throttled: ${STATS.eventsThrottled}
Running time: ${duration.toFixed(2)}s
Events per second: ${(STATS.eventsLogged / duration).toFixed(2)}

Top Event Types:
${sortedEventTypes.slice(0, 10).join('\n')}
`);
}

// ======= Main Hook Implementation =======

// The address of SCigEventSystem::AddToEventQueue
const targetFunctionAddress = ptr("0x140391380");

console.log(`[+] Event Logger script loaded`);
console.log(`[+] Hooking SCigEventSystem::AddToEventQueue at ${targetFunctionAddress}`);

// Create the hook
Interceptor.attach(targetFunctionAddress, {
    // This function is called when the target function is entered
    onEnter: function(args) {
        try {
            // Store arguments for later use
            this.eventQueuePtr = args[0];
            this.eventDataPtr = args[1];
            
            // Analyze the event data
            const eventInfo = analyzeEventData(this.eventDataPtr);
            
            // Log the event
            logEvent(eventInfo, this.eventQueuePtr);
        } catch (error) {
            console.error(`[-] Error in onEnter hook: ${error.message}`);
            if (CONFIG.logLevel >= 2) {
                console.error(error.stack);
            }
        }
    },
    
    // This function is called when the target function returns
    onLeave: function(retval) {
        // We could add additional logic here if needed
        // For example, tracking how many events failed to be added
    }
});

// Handle messages from the controlling application
recv("config", function(message) {
    if (message.type === "set_config") {
        console.log("[+] Updating configuration");
        
        // Update configuration
        for (const key in message.config) {
            if (CONFIG.hasOwnProperty(key)) {
                CONFIG[key] = message.config[key];
                console.log(`[+] Set ${key} = ${CONFIG[key]}`);
            }
        }
    } else if (message.type === "get_stats") {
        // Send back current statistics
        send({
            type: "stats",
            stats: STATS,
            config: CONFIG
        });
    } else if (message.type === "clear_stats") {
        // Reset statistics
        STATS.eventsLogged = 0;
        STATS.eventsFiltered = 0;
        STATS.eventsThrottled = 0;
        STATS.eventTypes = new Map();
        STATS.startTime = Date.now();
        console.log("[+] Statistics cleared");
    }
});

// Export RPC functions for controlling the script
rpc.exports = {
    // Update configuration
    setConfig: function(newConfig) {
        for (const key in newConfig) {
            if (CONFIG.hasOwnProperty(key)) {
                CONFIG[key] = newConfig[key];
            }
        }
        return true;
    },
    
    // Get current statistics
    getStats: function() {
        // Convert Map to object for serialization
        const eventTypesObj = {};
        STATS.eventTypes.forEach((count, id) => {
            eventTypesObj[id] = count;
        });
        
        return {
            stats: {
                ...STATS,
                eventTypes: eventTypesObj
            },
            config: CONFIG
        };
    },
    
    // Clear statistics
    clearStats: function() {
        STATS.eventsLogged = 0;
        STATS.eventsFiltered = 0;
        STATS.eventsThrottled = 0;
        STATS.eventTypes = new Map();
        STATS.startTime = Date.now();
        return true;
    },
    
    // Print statistics
    printStats: function() {
        printStats();
        return true;
    }
};

// Register script exit handler
Process.setExceptionHandler(function(exception) {
    printStats();
    console.log(`[+] Exception handler triggered: ${exception.type} at ${exception.address}`);
    return false;
});

// Register unload handler to print final stats
//Script.bindUnload(printStats);

// Print initial config
console.log(`[+] Event Logger configuration:`);
console.log(`[+] Max Events: ${CONFIG.maxEvents === 0 ? 'Unlimited' : CONFIG.maxEvents}`);
console.log(`[+] Log Level: ${CONFIG.logLevel}`);
console.log(`[+] Throttling: ${CONFIG.enableThrottling ? `Enabled (${CONFIG.throttleWindow}ms)` : 'Disabled'}`);
console.log(`[+] Event Filter: ${CONFIG.eventFilter ? CONFIG.eventFilter.join(', ') : 'None (logging all events)'}`);
console.log(`[+] Waiting for events...`);
