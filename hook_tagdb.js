/**
 * CEntity Tag Management Subsystem Instrumentation Framework
 *
 * Target Functions:
 * - 0x146B68FF0: CEntity::ReadTags() -> pointer
 * - 0x146B54980: CEntity::HasTag(pTagDefinition) -> bool
 * - 0x146B54AB0: CEntity::HasTags() -> bool
 *
 * Architecture:
 * - Dual-lock synchronization (global zone lock + entity-specific lock)
 * - Thread-local optimization for recursive acquisition
 * - Virtual dispatch through gEnv->pZoneSystem vtable
 * - Tag resolution via global CTagDatabase
 */

// Global state management
const g = {
    // Module base addresses
    modules: {
        main: Process.enumerateModules()[0].base,
        crySystem: Process.findModuleByName("CrySystem.dll")?.base || ptr(0)
    },

    // Critical global pointers
    pointers: {
        gEnv: ptr(0x149B4FBE8),
        // This is a pointer to the global pointer for the CTagDatabase instance.
        // To get the instance: g.pointers.pTagDatabase.readPointer()
        pTagDatabase: ptr(0x148c1fec0)
    },

    // Function addresses
    functions: {
        readTags: ptr(0x146B68FF0),
        hasTag: ptr(0x146B54980),
        hasTags: ptr(0x146B54AB0),
        getThreadContext: ptr(0x1470F2700),  // get_thread_context_ptr
        rwLockAcquireRead: ptr(0),           // rw_lock_acquire_read_lock_dispatch
        rwLockReleaseRead: ptr(0),           // rw_lock_release_read_lock

        // Tag Database functions from decompilation
        getTagFromString: ptr(0x146A54970), // CTagDatabase::GetTagFromGUID
        getStringFromTag: ptr(0x146A54EF0)  // CTagDatabase::GetTagGUID
    },

    // Statistics tracking
    stats: {
        readTags: { calls: 0, errors: 0, lockContention: 0 },
        hasTag: { calls: 0, errors: 0, lockContention: 0 },
        hasTags: { calls: 0, errors: 0, lockContention: 0 }
    },

    // Thread-local storage for context preservation
    threadContexts: new Map()
};

// Tag Database interaction subsystem
const tagResolver = {
    _dbInstance: null,
    _getStringFunc: null,
    _getTagFunc: null,

    /**
     * Lazily gets the CTagDatabase instance pointer.
     * @returns {NativePointer}
     */
    getDbInstance() {
        if (this._dbInstance === null) {
            try {
                this._dbInstance = g.pointers.pTagDatabase.readPointer();
            } catch (e) {
                console.error(`[-] Failed to read CTagDatabase instance pointer: ${e}`);
                this._dbInstance = NULL;
            }
        }
        return this._dbInstance;
    },

    /**
     * Resolves a tag definition pointer to its string representation.
     * @param {NativePointer} tagDefPtr - Pointer to the tag definition object.
     * @returns {string | null} The tag string or null on failure.
     */
    getString(tagDefPtr) {
        if (tagDefPtr.isNull()) {
            return "<null_tag_ptr>";
        }

        // *** FIX: The most robust approach. ***
        // 1. Do not attempt to read from tagDefPtr directly. Treat it as an opaque handle.
        // 2. Ensure the database is ready before attempting a call.
        // 3. Wrap the native call in a try/catch to handle crashes inside the game's own code.
        const db = this.getDbInstance();
        if (db.isNull()) {
            return "<db_not_ready>";
        }

        try {
            if (this._getStringFunc === null) {
                this._getStringFunc = new NativeFunction(
                    g.functions.getStringFromTag,
                    'pointer', // returns const char*
                    ['pointer', 'pointer'] // CTagDatabase*, _WORD* (tagDefPtr)
                );
            }

            const stringPtr = this._getStringFunc(db, tagDefPtr);
            return stringPtr.isNull() ? "<unresolved>" : stringPtr.readCString();
        } catch (e) {
            // This will catch the access violation if the native function fails.
            // console.error(`[-] Failed to resolve tag string for ${tagDefPtr}: ${e}`);
            return "<resolve_error>";
        }
    },

    /**
     * Resolves a string to its tag definition pointer.
     * @param {string} uuidString - The string to resolve.
     * @returns {NativePointer} The tag definition pointer or NULL on failure.
     */
    getTag(uuidString) {
        const db = this.getDbInstance();
        if (db.isNull()) return NULL;

        try {
            if (this._getTagFunc === null) {
                this._getTagFunc = new NativeFunction(
                    g.functions.getTagFromString,
                    'pointer', // returns pointer to the output buffer
                    ['pointer', 'pointer', 'pointer'] // CTagDatabase*, _QWORD* (out), char* (in)
                );
            }

            const outTagDefPtr = Memory.alloc(8); // Allocate space for the output QWORD*
            const uuidStrAlloc = Memory.allocUtf8String(uuidString);

            this._getTagFunc(db, outTagDefPtr, uuidStrAlloc);
            return outTagDefPtr.readPointer();
        } catch (e) {
            console.error(`[-] Failed to resolve tag for string "${uuidString}": ${e}`);
            return NULL;
        }
    }
};


// Utility functions for memory introspection
const utils = {
    /**
     * Read vtable pointer and resolve function address
     * @param {NativePointer} objPtr - Object pointer
     * @param {number} offset - Vtable offset
     * @returns {NativePointer} Function address
     */
    resolveVirtualFunction(objPtr, offset) {
        try {
            const vtable = objPtr.readPointer();
            return vtable.add(offset).readPointer();
        } catch (e) {
            console.error(`[-] Failed to resolve virtual function at offset 0x${offset.toString(16)}: ${e}`);
            return NULL;
        }
    },

    /**
     * Extract thread ID from thread context
     * @returns {number} Thread ID
     */
    getCurrentThreadId() {
        try {
            const contextPtr = new NativeFunction(
                g.functions.getThreadContext,
                'pointer',
                []
            )();
            return contextPtr.add(0x18).readU32();
        } catch (e) {
            console.error(`[-] Failed to get thread ID: ${e}`);
            return 0;
        }
    },

    /**
     * Analyze lock state from atomic value
     * @param {Int64} lockValue - Atomic lock value
     * @returns {Object} Lock state analysis
     */
    analyzeLockState(lockValue) {
        const value = lockValue.toNumber();
        return {
            raw: value,
            isContended: (value & 0x200000) !== 0,
            readerCount: value & 0x1FFFFF,
            hasWriter: (value & 0x80000000) !== 0
        };
    },

    /**
     * Format entity structure for logging
     * @param {NativePointer} entityPtr - Entity pointer
     * @returns {Object} Entity metadata
     */
    extractEntityMetadata(entityPtr) {
        try {
            return {
                address: entityPtr,
                lockState: entityPtr.add(0xC0).readU64(),
                ownerThread: entityPtr.add(0xD0).readU32(),
                recursiveCount: entityPtr.add(0xD4).readU32(),
                tagStorageOffset: entityPtr.add(0x2A8)
            };
        } catch (e) {
            return { address: entityPtr, error: e.message };
        }
    },

    /**
     * Hexdump with context annotations
     * @param {NativePointer} ptr - Memory pointer
     * @param {number} length - Bytes to dump
     * @param {string} context - Context description
     */
    annotatedHexdump(ptr, length, context) {
        console.log(`\n[*] Memory dump - ${context}:`);
        console.log(hexdump(ptr, {
            offset: 0,
            length: length,
            header: true,
            ansi: true
        }));
    }
};

// Lock tracking subsystem
const lockTracker = {
    activeLocks: new Map(),

    /**
     * Record lock acquisition
     * @param {string} lockType - Lock identifier
     * @param {NativePointer} lockPtr - Lock address
     * @param {Object} state - Lock state information
     */
    recordAcquisition(lockType, lockPtr, state) {
        const threadId = utils.getCurrentThreadId();
        const key = `${threadId}_${lockPtr}`;

        this.activeLocks.set(key, {
            type: lockType,
            address: lockPtr,
            threadId: threadId,
            timestamp: Date.now(),
            state: state,
            stackTrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
        });
    },

    /**
     * Record lock release
     * @param {NativePointer} lockPtr - Lock address
     */
    recordRelease(lockPtr) {
        const threadId = utils.getCurrentThreadId();
        const key = `${threadId}_${lockPtr}`;
        const lockInfo = this.activeLocks.get(key);

        if (lockInfo) {
            const duration = Date.now() - lockInfo.timestamp;
            if (duration > 100) {  // Log slow lock holds
                console.warn(`[!] Slow lock release: ${lockInfo.type} held for ${duration}ms`);
            }
            this.activeLocks.delete(key);
        }
    }
};

// Primary instrumentation implementations
const hooks = {
    /**
     * Instrument CEntity::ReadTags
     */
    installReadTagsHook() {
        Interceptor.attach(g.functions.readTags, {
            onEnter(args) {
                g.stats.readTags.calls++;

                const entityPtr = args[0];
                const threadContext = {
                    entityPtr: entityPtr,
                    entityMetadata: utils.extractEntityMetadata(entityPtr),
                    timestamp: Date.now(),
                    zoneSystemLoading: false,
                    globalLockPtr: NULL,
                    globalLockState: null,
                    entityLockState: null
                };

                // Store context for onLeave
                this.threadContext = threadContext;
                g.threadContexts.set(this.threadId, threadContext);

                console.log(`\n[+] CEntity::ReadTags called`);
                console.log(`    Entity: ${entityPtr}`);
                console.log(`    Metadata:`, JSON.stringify(threadContext.entityMetadata, null, 2));
            },

            onLeave(retval) {
                const threadContext = this.threadContext;
                if (!threadContext) {
                    console.error(`[-] Missing thread context in ReadTags onLeave`);
                    return;
                }

                const duration = Date.now() - threadContext.timestamp;
                const tagCollectionPtr = retval;

                console.log(`[+] CEntity::ReadTags completed in ${duration}ms`);
                console.log(`    Tag collection pointer: ${tagCollectionPtr}`);

                // Analyze tag collection structure if valid
                if (!tagCollectionPtr.isNull()) {
                    try {
                        const firstQword = tagCollectionPtr.readU64();
                        console.log(`    First qword: 0x${firstQword.toString(16)}`);

                        // Dump initial tag collection data
                        utils.annotatedHexdump(tagCollectionPtr, 64, "Tag collection header");
                    } catch (e) {
                        console.error(`    [-] Failed to analyze tag collection: ${e}`);
                    }
                }

                g.threadContexts.delete(this.threadId);
            }
        });
    },

    /**
     * Instrument CEntity::HasTag
     */
    installHasTagHook() {
        Interceptor.attach(g.functions.hasTag, {
            onEnter(args) {
                g.stats.hasTag.calls++;

                const entityPtr = args[0];
                const tagDefPtr = args[1]; // This is a pointer to the tag definition object

                const threadContext = {
                    entityPtr: entityPtr,
                    tagDefPtr: tagDefPtr,
                    tagString: tagResolver.getString(tagDefPtr), // Resolve the tag pointer to a string
                    entityMetadata: utils.extractEntityMetadata(entityPtr),
                    timestamp: Date.now()
                };

                this.threadContext = threadContext;

                console.log(`\n[+] CEntity::HasTag called`);
                console.log(`    Entity: ${entityPtr}`);
                console.log(`    Tag Def Ptr: ${tagDefPtr} -> "${threadContext.tagString}"`);
                console.log(`    Entity metadata:`, JSON.stringify(threadContext.entityMetadata, null, 2));
            },

            onLeave(retval) {
                const threadContext = this.threadContext;
                if (!threadContext) return;

                const duration = Date.now() - threadContext.timestamp;
                const hasTag = retval.toInt32() !== 0;

                console.log(`[+] CEntity::HasTag completed in ${duration}ms`);
                console.log(`    Result: ${hasTag} for tag "${threadContext.tagString}"`);
            }
        });
    },

    /**
     * Instrument CEntity::HasTags
     */
    installHasTagsHook() {
        Interceptor.attach(g.functions.hasTags, {
            onEnter(args) {
                g.stats.hasTags.calls++;

                const entityPtr = args[0];

                const threadContext = {
                    entityPtr: entityPtr,
                    entityMetadata: utils.extractEntityMetadata(entityPtr),
                    timestamp: Date.now()
                };

                this.threadContext = threadContext;

                console.log(`\n[+] CEntity::HasTags called`);
                console.log(`    Entity: ${entityPtr}`);
                console.log(`    Entity metadata:`, JSON.stringify(threadContext.entityMetadata, null, 2));
            },

            onLeave(retval) {
                const threadContext = this.threadContext;
                if (!threadContext) return;

                const duration = Date.now() - threadContext.timestamp;
                const hasTags = retval.toInt32() !== 0;

                console.log(`[+] CEntity::HasTags completed in ${duration}ms`);
                console.log(`    Result: ${hasTags} (${retval.toInt32()})`);
            }
        });
    },

    /**
     * Install supplementary hooks for lock operations
     */
    installLockHooks() {
        // Hook rw_lock_acquire_read_lock_dispatch if we can find it
        const acquireSymbol = DebugSymbol.fromName("rw_lock_acquire_read_lock_dispatch");
        if (acquireSymbol.address) {
            g.functions.rwLockAcquireRead = acquireSymbol.address;

            Interceptor.attach(g.functions.rwLockAcquireRead, {
                onEnter(args) {
                    const lockPtr = args[0];
                    const currentValue = args[1];
                    const callerName = args[2].readCString();
                    const lockName = args[3].readCString();

                    console.log(`[*] Lock contention detected:`);
                    console.log(`    Lock: ${lockPtr} (${lockName})`);
                    console.log(`    Caller: ${callerName}`);
                    console.log(`    State: ${utils.analyzeLockState(currentValue)}`);

                    // Update contention statistics
                    if (callerName.includes("ReadTags")) g.stats.readTags.lockContention++;
                    else if (callerName.includes("HasTag")) g.stats.hasTag.lockContention++;
                    else if (callerName.includes("HasTags")) g.stats.hasTags.lockContention++;
                }
            });
        }
    }
};

// Statistics reporting subsystem
const reporter = {
    /**
     * Generate comprehensive statistics report
     */
    generateReport() {
        console.log("\n" + "=".repeat(80));
        console.log("CEntity Tag Management Subsystem - Statistics Report");
        console.log("=".repeat(80));

        const reportTime = new Date().toISOString();
        console.log(`Report generated: ${reportTime}`);
        console.log(`\nFunction call statistics:`);

        for (const [funcName, stats] of Object.entries(g.stats)) {
            console.log(`\n${funcName}:`);
            console.log(`  Total calls: ${stats.calls}`);
            console.log(`  Errors: ${stats.errors}`);
            console.log(`  Lock contentions: ${stats.lockContention}`);

            if (stats.calls > 0) {
                const contentionRate = (stats.lockContention / stats.calls * 100).toFixed(2);
                console.log(`  Contention rate: ${contentionRate}%`);
            }
        }

        console.log(`\nActive locks: ${lockTracker.activeLocks.size}`);
        if (lockTracker.activeLocks.size > 0) {
            console.log("\nActive lock details:");
            for (const [key, lock] of lockTracker.activeLocks) {
                const age = Date.now() - lock.timestamp;
                console.log(`  ${lock.type} @ ${lock.address} (thread ${lock.threadId}, age: ${age}ms)`);
            }
        }

        console.log("\n" + "=".repeat(80));
    },

    /**
     * Start periodic reporting
     * @param {number} intervalMs - Reporting interval in milliseconds
     */
    startPeriodicReporting(intervalMs = 30000) {
        return setInterval(() => {
            this.generateReport();
        }, intervalMs);
    }
};

// RPC interface for external control
rpc.exports = {
    /**
     * Get current statistics
     * @returns {Object} Current statistics snapshot
     */
    getStats() {
        return {
            stats: g.stats,
            activeLocks: Array.from(lockTracker.activeLocks.values()),
            timestamp: Date.now()
        };
    },

    /**
     * Reset statistics
     */
    resetStats() {
        for (const stats of Object.values(g.stats)) {
            stats.calls = 0;
            stats.errors = 0;
            stats.lockContention = 0;
        }
        console.log("[*] Statistics reset");
    },

    /**
     * Analyze specific entity
     * @param {string} entityAddress - Entity address as hex string
     * @returns {Object} Entity analysis results
     */
    analyzeEntity(entityAddress) {
        try {
            const entityPtr = ptr(entityAddress);
            const metadata = utils.extractEntityMetadata(entityPtr);

            const readTagsFunc = new NativeFunction(
                g.functions.readTags,
                'pointer',
                ['pointer']
            );

            const tagCollectionPtr = readTagsFunc(entityPtr);

            return {
                metadata: metadata,
                tagCollection: tagCollectionPtr.toString(),
                success: true
            };
        } catch (e) {
            return {
                error: e.message,
                success: false
            };
        }
    },

    /**
     * Resolves a tag definition pointer to its string name.
     * @param {string} tagDefAddress - The tag definition pointer as a hex string.
     * @returns {string} The resolved tag name.
     */
    getStringFromTag(tagDefAddress) {
        try {
            const tagDefPtr = ptr(tagDefAddress);
            return tagResolver.getString(tagDefPtr);
        } catch (e) {
            return `Error: ${e.message}`;
        }
    },

    /**
     * Resolves a tag string/UUID to its definition pointer.
     * @param {string} tagName - The tag name/UUID to resolve.
     * @returns {string} The tag definition pointer as a hex string.
     */
    getTagFromString(tagName) {
        try {
            const tagDefPtr = tagResolver.getTag(tagName);
            return tagDefPtr.toString();
        } catch (e) {
            return `Error: ${e.message}`;
        }
    },

    /**
     * Enable or disable verbose logging
     * @param {boolean} enabled - Verbose mode state
     */
    setVerboseMode(enabled) {
        // Implementation would modify console.log behavior
        console.log(`[*] Verbose mode ${enabled ? 'enabled' : 'disabled'}`);
    }
};

// Initialization sequence
function initialize() {
    console.log("\n" + "=".repeat(80));
    console.log("CEntity Tag Management Subsystem Instrumentation Framework");
    console.log("Version: 1.3.0 (Crash-Resistant Tag Resolution)");
    console.log("=".repeat(80));

    console.log("\n[*] Initializing instrumentation framework...");

    // Verify critical pointers
    console.log("[*] Verifying global pointers:");
    try {
        const gEnvValue = g.pointers.gEnv.readPointer();
        console.log(`    gEnv @ ${g.pointers.gEnv} -> ${gEnvValue}`);

        const vtable = gEnvValue.readPointer();
        console.log(`    gEnv vtable -> ${vtable}`);

        const dbInstance = tagResolver.getDbInstance();
        console.log(`    pTagDatabase @ ${g.pointers.pTagDatabase} -> ${dbInstance}`);
        if (dbInstance.isNull()) {
            console.warn("    [!] CTagDatabase instance is NULL. Tag resolution will be skipped until it's initialized.");
        }

    } catch (e) {
        console.error(`[-] Failed to verify global pointers: ${e}`);
    }

    // Install primary hooks
    console.log("\n[*] Installing function hooks:");

    try {
        hooks.installReadTagsHook();
        console.log("    [+] ReadTags hook installed");
    } catch (e) {
        console.error(`    [-] Failed to hook ReadTags: ${e}`);
        g.stats.readTags.errors++;
    }

    try {
        hooks.installHasTagHook();
        console.log("    [+] HasTag hook installed");
    } catch (e) {
        console.error(`    [-] Failed to hook HasTag: ${e}`);
        g.stats.hasTag.errors++;
    }

    try {
        hooks.installHasTagsHook();
        console.log("    [+] HasTags hook installed");
    } catch (e) {
        console.error(`    [-] Failed to hook HasTags: ${e}`);
        g.stats.hasTags.errors++;
    }

    // Install supplementary hooks
    hooks.installLockHooks();

    // Start periodic reporting
    const reportInterval = reporter.startPeriodicReporting(60000);

    console.log("\n[+] Instrumentation framework initialized successfully");
    console.log("[*] Use rpc.exports functions for runtime control");
    console.log("[*] New RPC functions available: getStringFromTag(ptr), getTagFromString(name)");
    console.log("[*] Statistics will be reported every 60 seconds");

    // Cleanup handler
    Script.bindWeak(globalThis, () => {
        clearInterval(reportInterval);
        console.log("[*] Instrumentation framework cleanup completed");
    });
}

// Execute initialization
initialize();
