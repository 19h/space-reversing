// Frida script to instrument the sub_146675AD0 function with entity tracking
// Base address of the program is 0x140000000

const baseAddress = ptr('0x140000000');
const functionOffset = ptr('0x66E5AB0');
const functionAddress = baseAddress.add(functionOffset);

console.log('[+] Target function address: ' + functionAddress);

// Global entity tracker with Map data structure
// Key: Entity pointer as string, Value: {timestamp, data}
const entityTracker = new Map();

// Utility function to validate if a pointer is within valid memory regions
function isPointerValid(pointer) {
    if (pointer === null || pointer === undefined) return false;
    if (pointer.isNull()) return false;

    try {
        // Check if address is within a valid memory range
        const range = Process.findRangeByAddress(pointer);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (e) {
        return false;
    }
}

// Function to create ASCII table for entity statistics with safe access patterns
function printEntityStats() {
    try {
        // Make a copy of entries to avoid concurrent modification issues
        const entries = Array.from(entityTracker.entries());
        const entityCount = entries.length;

        console.log('\n╔═══════════════════════════════════════════════════════════════════════════════╗');
        console.log(`║ ENTITY STATISTICS                                     Total Entities: ${entityCount.toString().padStart(5)} ║`);
        console.log('╠═══════════════════╦═══════════════════╦═══════════════════╦═══════════════════╣');
        console.log('║ Entity Pointer    ║ Position X        ║ Position Y        ║ Position Z        ║');
        console.log('╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════╣');

        if (entityCount === 0) {
            console.log('║ No entities tracked                                                         ║');
        } else {
            // Process each entity safely
            for (const [ptrStr, entity] of entries) {
                try {
                    // Verify memory is still valid before access
                    const entityPtr = ptr(ptrStr);
                    if (!isPointerValid(entityPtr)) {
                        console.log(`[!] Entity at ${ptrStr} no longer valid, removing from tracker`);
                        entityTracker.delete(ptrStr);
                        continue;
                    }

                    const data = entity.data;
                    if (data && data.spatial && data.spatial.position) {
                        const pos = data.spatial.position;
                        console.log(`║ ${ptrStr.padEnd(17)} ║ ${pos.x.toFixed(6).padStart(17)} ║ ${pos.y.toFixed(6).padStart(17)} ║ ${pos.z.toFixed(6).padStart(17)} ║`);
                    } else {
                        console.log(`║ ${ptrStr.padEnd(17)} ║ ${'N/A'.padStart(17)} ║ ${'N/A'.padStart(17)} ║ ${'N/A'.padStart(17)} ║`);
                    }
                } catch (e) {
                    console.log(`[!] Error processing entity ${ptrStr}: ${e.message}`);
                    entityTracker.delete(ptrStr);
                }
            }
        }

        console.log('╚═══════════════════╩═══════════════════╩═══════════════════╩═══════════════════╝');
    } catch (e) {
        console.error(`[!] Error generating statistics table: ${e.message}`);
    }
}

// Function to clean up expired entities (older than 2 seconds)
function cleanupExpiredEntities() {
    try {
        const now = Date.now();
        let expiredCount = 0;

        // Use for...of with keys() to avoid concurrent modification issues
        for (const ptrStr of Array.from(entityTracker.keys())) {
            try {
                const entity = entityTracker.get(ptrStr);

                // Check timestamp expiration
                if (now - entity.timestamp > 2000) {
                    entityTracker.delete(ptrStr);
                    expiredCount++;
                    continue;
                }

                // Validate pointer still valid
                const entityPtr = ptr(ptrStr);
                if (!isPointerValid(entityPtr)) {
                    entityTracker.delete(ptrStr);
                    expiredCount++;
                }
            } catch (e) {
                console.error(`[!] Error during entity cleanup for ${ptrStr}: ${e.message}`);
                entityTracker.delete(ptrStr);
                expiredCount++;
            }
        }

        if (expiredCount > 0) {
            console.log(`[*] Removed ${expiredCount} expired or invalid entities`);
        }
    } catch (e) {
        console.error(`[!] Error in cleanup routine: ${e.message}`);
    }
}

// Safely set up interval for entity statistics and cleanup
let statInterval = null;
try {
    statInterval = setInterval(() => {
        try {
            cleanupExpiredEntities();
            printEntityStats();
        } catch (e) {
            console.error(`[!] Unhandled exception in stats interval: ${e.message}`);

            // If critical error, disable stats collection to prevent crashes
            if (e.message.includes("access violation") ||
                e.message.includes("segmentation fault") ||
                e.message.includes("cannot read")) {
                console.error("[!] Fatal error detected, disabling stats interval");
                clearInterval(statInterval);
                statInterval = null;
            }
        }
    }, 1000);
} catch (e) {
    console.error(`[!] Failed to set up stats interval: ${e.message}`);
}

function readEntityFields(actorEntityPtr) {
    // Handle null pointer protection with bitwise operations
    if (actorEntityPtr.isNull() || actorEntityPtr.compare(ptr(0)) === 0) {
        console.error("[!] Null actorEntity pointer detected");
        return null;
    }

    // Architecture-specific constants
    const PTR_SIZE = Process.pointerSize;
    const QWORD_SIZE = 8;
    const DWORD_SIZE = 4;
    const WORD_SIZE = 2;
    const BYTE_SIZE = 1;

    try {
        // Create result object with nested structure for organized data access
        const result = {
            // Core entity identification
            core: {},
            // Spatial and transform data
            spatial: {},
            // Physical properties and simulation parameters
            physical: {},
            // Entity state flags and runtime status
            state: {},
            // Velocity and kinematic data
            kinematic: {},
            // Collision and interaction data
            collision: {},
            // Entity relationships and references
            references: {},
            // Debug metadata for introspection
            _debug: {
                memAddresses: {}
            }
        };

        // Store base address for debug purposes
        result._debug.memAddresses.actorEntity = actorEntityPtr;

        // ---- Core Entity Identification ----
        result.core.vtable = actorEntityPtr.readPointer();
        result.core.entityId = actorEntityPtr.add(0x0008).readU64();

        // ---- Process Dynamic Entity List ----
        // Calculate effective address of pEntities field (offset 0x2848 from actorEntity base)
        //const pEntitiesPtr = actorEntityPtr.add(0x2848).readPointer();
        //result._debug.memAddresses.pEntities = pEntitiesPtr;
        //
        //if (!pEntitiesPtr.isNull() && Process.findRangeByAddress(pEntitiesPtr)) {
        //    // Read entity list containers
        //    result.references.entitiesEndPtr = actorEntityPtr.add(0x2856).readPointer();
        //    result.references.entitiesCapacityPtr = actorEntityPtr.add(0x2864).readPointer();
        //
        //    // Perform first-level indirection to resolve IPhysicalEntity* from array
        //    const physEntityPtr = pEntitiesPtr.readPointer();
        //    result._debug.memAddresses.physEntity = physEntityPtr;
        //
        //    if (!physEntityPtr.isNull() && Process.findRangeByAddress(physEntityPtr)) {
        //        // Extract critical physical entity fields
        //        result.references.physEntity = {
        //            vtable: physEntityPtr.readPointer(),
        //            entityId: physEntityPtr.add(0x08).readU64(),
        //            entityType: physEntityPtr.add(0x10).readU32(),
        //            entityFlags: physEntityPtr.add(0x14).readU32()
        //        };
        //    }
        //}

        // ---- Spatial Data ----
        // World bounds (AABB)
        result.spatial.worldBounds = {
            min: {
                x: actorEntityPtr.add(0x0010).readDouble(),
                y: actorEntityPtr.add(0x0018).readDouble(),
                z: actorEntityPtr.add(0x0020).readDouble()
            },
            max: {
                x: actorEntityPtr.add(0x0028).readDouble(),
                y: actorEntityPtr.add(0x0030).readDouble(),
                z: actorEntityPtr.add(0x0038).readDouble()
            }
        };

        // Position vector (as doubles for precision)
        result.spatial.position = {
            x: actorEntityPtr.add(0x01C0).readDouble(),
            y: actorEntityPtr.add(0x01C8).readDouble(),
            z: actorEntityPtr.add(0x01D0).readDouble()
        };

        // Orientation quaternion
        result.spatial.orientation = {
            x: actorEntityPtr.add(0x01D8).readFloat(),
            y: actorEntityPtr.add(0x01DC).readFloat(),
            z: actorEntityPtr.add(0x01E0).readFloat(),
            w: actorEntityPtr.add(0x01E4).readFloat()
        };

        // Scale factor (uniform scale)
        result.spatial.scale = actorEntityPtr.add(0x01E8).readFloat();

        // Grid cell coordinates (spatial partitioning)
        result.spatial.gridCell = {
            x: actorEntityPtr.add(0x0236).readS16(),
            y: actorEntityPtr.add(0x0238).readS16()
        };

        // ---- Kinematic State ----
        // Linear velocity vector
        result.kinematic.linearVelocity = {
            x: actorEntityPtr.add(0x03C0).readFloat(),
            y: actorEntityPtr.add(0x03C4).readFloat(),
            z: actorEntityPtr.add(0x03C8).readFloat()
        };

        // Previous/cached velocity
        result.kinematic.cachedVelocity = {
            x: actorEntityPtr.add(0x03CC).readFloat(),
            y: actorEntityPtr.add(0x03D0).readFloat(),
            z: actorEntityPtr.add(0x03D4).readFloat()
        };

        // Angular velocity vector
        result.kinematic.angularVelocity = {
            x: actorEntityPtr.add(0x03D8).readFloat(),
            y: actorEntityPtr.add(0x03DC).readFloat(),
            z: actorEntityPtr.add(0x03E0).readFloat()
        };

        // Angular speed (magnitude of angular velocity)
        result.kinematic.angularSpeed = actorEntityPtr.add(0x03E4).readFloat();

        // External acceleration (gravity, etc.)
        result.kinematic.externalAcceleration = {
            x: actorEntityPtr.add(0x03F0).readFloat(),
            y: actorEntityPtr.add(0x03F4).readFloat(),
            z: actorEntityPtr.add(0x03F8).readFloat()
        };

        // ---- Physical Properties ----
        // Inertia tensor (diagonal matrix)
        result.physical.inertiaTensor = {
            xx: actorEntityPtr.add(0x0478).readFloat(),
            yy: actorEntityPtr.add(0x047C).readFloat(),
            zz: actorEntityPtr.add(0x0480).readFloat()
        };

        // Mass properties
        result.physical.mass = actorEntityPtr.add(0x0488).readFloat();
        result.physical.invMass = actorEntityPtr.add(0x0484).readFloat();

        // Physics simulation parameters
        result.physical.sleepSpeedThreshold = actorEntityPtr.add(0x0490).readFloat();
        result.physical.maxTimeStep = actorEntityPtr.add(0x049C).readFloat();
        result.physical.dampingRatio = actorEntityPtr.add(0x04A0).readFloat();
        result.physical.frictionCoeff = actorEntityPtr.add(0x04B4).readFloat();
        result.physical.restitutionCoeff = actorEntityPtr.add(0x04B8).readFloat();

        // ---- State Flags and Runtime Status ----
        result.state.flags = actorEntityPtr.add(0x0520).readU32();
        result.state.stateFlags = actorEntityPtr.add(0x2416).readU16();
        result.state.simulationFlags = actorEntityPtr.add(0x2418).readU8();
        result.state.contactFlags = actorEntityPtr.add(0x2419).readU8();

        // Decompose state flags for easier analysis
        result.state.flagsAnalysis = {
            isDisabled: (result.state.flags & 0x20) !== 0,
            isConstrained: (result.state.flags & 0x40) !== 0,
            isAutoSleep: (result.state.flags & 0x80) !== 0,
            isSleeping: (result.state.flags & 0x100) !== 0
        };

        // Decompose simulation flags
        result.state.simulationFlagsAnalysis = {
            inCollision: (result.state.simulationFlags & 0x01) !== 0,
            forceApplied: (result.state.simulationFlags & 0x02) !== 0,
            requiresStep: (result.state.simulationFlags & 0x04) !== 0,
            timestepActive: (result.state.simulationFlags & 0x08) !== 0,
            velocityModified: (result.state.simulationFlags & 0x10) !== 0,
            positionModified: (result.state.simulationFlags & 0x40) !== 0
        };

        // ---- Collision Data ----
        result.collision.physicalEntityType = actorEntityPtr.add(0x0244).readU32();

        // Collision filter
        result.collision.collisionFilter = {
            physicalFlags: actorEntityPtr.add(0x0524).readU16(),
            physicalFlagsOR: actorEntityPtr.add(0x0526).readU16(),
            flagsGroupDst: actorEntityPtr.add(0x0530).readU8(),
            flagsGroupSrc: actorEntityPtr.add(0x0531).readU8()
        };

        // Latest contact point
        result.collision.contactPoint = {
            x: actorEntityPtr.add(0x0950).readFloat(),
            y: actorEntityPtr.add(0x0954).readFloat(),
            z: actorEntityPtr.add(0x0958).readFloat()
        };

        // ---- Entity References ----
        const pOwnerEntityPtr = actorEntityPtr.add(0x0184).readPointer();
        result.references.ownerEntityPtr = pOwnerEntityPtr;
        result.references.hasOwner = !pOwnerEntityPtr.isNull() && Process.findRangeByAddress(pOwnerEntityPtr);

        const pConstraintEntityPtr = actorEntityPtr.add(0x2552).readPointer();
        result.references.constraintEntityPtr = pConstraintEntityPtr;
        result.references.hasConstraint = !pConstraintEntityPtr.isNull() && Process.findRangeByAddress(pConstraintEntityPtr);

        const pPhysWorldPtr = actorEntityPtr.add(0x0704).readPointer();
        result.references.physWorldPtr = pPhysWorldPtr;

        // Read component subsystem pointers
        result.references.components = {
            hasFoliageInteraction: !actorEntityPtr.add(0x1624).readPointer().isNull(),
            hasWaterInteraction: !actorEntityPtr.add(0x1784).readPointer().isNull()
        };

        return result;
    } catch (e) {
        // Exception handler for access violations (EXCEPTION_ACCESS_VIOLATION)
        console.error("[!] Memory access violation during entity parsing: " + e.message);
        console.error("[!] Error occurred at: " + e.stack);
        return null;
    }
}

// Create a message queue for asynchronous processing
const pendingEntities = [];
const QUEUE_PROCESSING_INTERVAL = 16; // ~60fps timing
const MAX_QUEUE_SIZE = 128;
let processingActive = false;

// Modified interceptor to act as a lightweight producer
Interceptor.attach(functionAddress, {
    onEnter: function(args) {
        try {
            const entityPtr = args[0];

            // Fast validity check only - no memory reads
            if (entityPtr === null || entityPtr.isNull()) return;

            console.log(
                JSON.stringify(
                    readEntityFields(
                        entityPtr,
                    ),
                    null,
                    4,
                )
            );

            return;

            // Enqueue pointer for async processing, with overflow protection
            if (pendingEntities.length < MAX_QUEUE_SIZE) {
                pendingEntities.push({
                    ptr: entityPtr,
                    timestamp: Date.now()
                });
            }
        } catch (e) {
            // Minimized exception handler to reduce impact
            console.error(`[!] Queue error: ${e.message}`);
        }
    }
});

// Dedicated async consumer function that processes the queue
function processEntityQueue() {
    // Prevent concurrent processing
    if (processingActive || pendingEntities.length === 0) return;

    processingActive = true;

    try {
        // Dequeue a single entity to minimize processing time
        const entity = pendingEntities.shift();
        const ptrStr = entity.ptr.toString();

        console.log(-1);

        // Execute memory reads asynchronously and non-blocking
        setTimeout(function() {
            try {
                console.log(-2);
                // Only if pointer still valid after the async delay
                if (isPointerValid(entity.ptr)) {
                    console.log(-3);
                    const entityData = readEntityFields(entity.ptr);
                    console.log(-4);

                    if (entityData !== null) {
                        entityTracker.set(ptrStr, {
                            timestamp: entity.timestamp,
                            data: entityData,
                            updateCount: 1
                        });
                    }
                }
            } catch (e) {
                console.error(`[!] Async processing error: ${e.message}`);
            } finally {
                processingActive = false;
            }
        }, 0); // Zero timeout for next tick scheduling
    } catch (e) {
        console.error(`[!] Queue processor error: ${e.message}`);
        processingActive = false;
    }
}

// Setup timer for the consumer at higher frequency than display
const queueProcessorInterval = setInterval(processEntityQueue, QUEUE_PROCESSING_INTERVAL);

// // Attach the interceptor to the target function with proper exception handling
// try {
//     Interceptor.attach(functionAddress, {
//         onEnter: function(args) {
//             try {
//                 this.entityPtr = args[0];

//                 // Skip null pointers or invalid pointers
//                 if (!isPointerValid(this.entityPtr)) {
//                     return;
//                 }

//                 // Extract entity data with memory safety
//                 const entityData = readEntityFields(this.entityPtr);

//                 // Store entity in tracker with current timestamp if valid
//                 if (entityData !== null) {
//                     const ptrStr = this.entityPtr.toString();
//                     const existingEntry = entityTracker.get(ptrStr);

//                     if (existingEntry) {
//                         // Update existing entry with new data but keep same timestamp
//                         entityTracker.set(ptrStr, {
//                             timestamp: Date.now(), // Update timestamp on each interaction
//                             data: entityData,
//                             updateCount: (existingEntry.updateCount || 0) + 1
//                         });
//                     } else {
//                         // Add new entity
//                         entityTracker.set(ptrStr, {
//                             timestamp: Date.now(),
//                             data: entityData,
//                             updateCount: 1
//                         });
//                         console.log(`[+] New entity tracked: ${ptrStr}`);
//                     }
//                 }
//             } catch (e) {
//                 console.error(`[!] Exception in onEnter hook: ${e.message}`);
//             }
//         },

//         onLeave: function(retval) {
//             // Intentionally left minimal to avoid additional hooks
//             // that could cause instability
//         }
//     });
// } catch (e) {
//     console.error(`[!] Failed to attach interceptor: ${e.message}`);
// }

// Set up proper resource cleanup with exception handling
Process.setExceptionHandler(function(ex) {
    console.error(`[!] Exception caught: ${JSON.stringify(ex)}`);
    //if (statInterval !== null) {
    //    clearInterval(statInterval);
    //    statInterval = null;
    //    console.log("[*] Stats interval disabled due to exception");
    //}
    return false; // Allow default handler to run
});

// Handle script unload more robustly
//Script.bindExitHandler(function() {
//    console.log('[+] Script unloading, cleaning up resources');
//    if (statInterval !== null) {
//        clearInterval(statInterval);
//        statInterval = null;
//    }
//    // Clear global state
//    entityTracker.clear();
//});

console.log('[+] Entity tracking instrumentation active with enhanced memory safety');
console.log('[+] Statistics will be displayed every second');
console.log('[+] Entities will expire after 2 seconds of inactivity');
