/**
 * Rigid Entity Position Control Framework - Production Implementation
 *
 * This implementation synthesizes comprehensive reverse engineering analysis of the target
 * physics engine's entity management architecture. The framework provides deterministic
 * control over rigid body positions through strategic instrumentation of identified
 * update mechanisms.
 *
 * Architecture Overview:
 * - Primary position storage: entity_base + 0x628/0x630/0x638 (double precision X/Y/Z)
 * - Physics integration: sub_14687CFB0 (QuantumStep)
 * - Transform computation: sub_1468B88B0 (MainUpdate)
 * - State propagation: entity_base + 0x210 -> transform pipeline
 *
 * @version 2.0
 * @author Advanced Reverse Engineering Team
 */

'use strict';

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

const CONFIG = {
    // Target module identification
    MODULE_NAME: Process.platform === 'windows' ? 'StarCitizen.exe' : 'StarCitizen.exe',

    // Function RVAs from comprehensive static analysis
    FUNCTIONS: {
        QUANTUM_STEP: 0x687CFB0,     // CSpaceshipEntity::QuantumStep
        MAIN_UPDATE: 0x68B88B0,       // CRigidEntity::UpdatePosition
        UPDATE_BREAKABLE: 0x66DAB90,  // parts::container_t::update_breakable_clusters
        UPDATE_EXTENTS: 0x66DCD20,    // parts::container_t::update_extents
        SWAP_PARTS: 0x66D54E0         // Swap operation for part reordering
    },

    // Entity structure offsets (verified through multiple analysis passes)
    ENTITY_OFFSETS: {
        // Primary physics state (double precision coordinates)
        POSITION_X: 0x628,
        POSITION_Y: 0x630,
        POSITION_Z: 0x638,

        // Previous position backup (for interpolation/rollback)
        PREV_POS_X: 0x7C0,
        PREV_POS_Y: 0x7C8,
        PREV_POS_Z: 0x7D0,

        // Physics calculation intermediates
        PHYSICS_CALC_X: 0x650,
        PHYSICS_CALC_Y: 0x658,
        PHYSICS_CALC_Z: 0x660,

        // Velocity components (for physics integration)
        VELOCITY_X: 0x760,
        VELOCITY_Y: 0x768,
        VELOCITY_Z: 0x770,

        // Angular velocity components
        ANGULAR_VEL_BASE: 0x778,

        // Transform pipeline pointers
        TRANSFORM_SRC_PTR: 0x210,      // Points to source transform data
        WORKING_COPY_BASE: 0x1C0,       // Working transform copy
        EFFECTIVE_TRANSFORM: 0x418,     // Final transform matrix

        // Physics simulation parameters
        PHYSICS_ENABLED_FLAG: 0x6D50,   // Double - physics active when > 0.0
        DELTA_TIME_SCALE: 0x6B0,        // Physics timestep multiplier

        // Entity state flags
        UPDATE_FLAGS: 0x184,            // Bitfield controlling update behavior
        ENTITY_FLAGS: 0x208,            // General entity flags

        // Lock for thread-safe updates
        UPDATE_LOCK: 0xC8,

        // Part system references
        PARTS_PTR: 0x2A0,
        PARTS_UPDATE_FLAGS: 0x184       // Offset within parts structure
    },

    // IDA Pro assumed base address for RVA calculations
    IDA_BASE: ptr('0x140000000'),

    // Logging configuration
    LOGGING: {
        VERBOSE: false,
        POSITION_PRECISION: 6,
        HEX_DUMP_SIZE: 64,
        LOG_PHYSICS_CALCULATIONS: true,
        LOG_TRANSFORM_PIPELINE: true
    },

    // Performance tuning
    PERFORMANCE: {
        MAX_HOOKS_PER_FRAME: 100,      // Prevent hook flooding
        POSITION_UPDATE_THROTTLE_MS: 16, // ~60 FPS update rate
        MEMORY_CACHE_SIZE: 1024         // Cached memory reads
    }
};

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

const GlobalState = {
    // Module base address resolution
    moduleBase: NULL,

    // Resolved function addresses
    functions: {
        quantumStep: NULL,
        mainUpdate: NULL,
        updateBreakable: NULL,
        updateExtents: NULL,
        swapParts: NULL
    },

    // Active instrumentation
    activeHooks: new Map(),
    stalkerSessions: new Map(),

    // Position modification system
    positionModifications: new Map(), // entityPtr -> ModificationRequest

    // Entity tracking and analysis
    trackedEntities: new Map(), // entityPtr -> EntityMetadata
    entityUpdateHistory: new Map(), // entityPtr -> UpdateHistory[]

    // Performance metrics
    metrics: {
        hooksTriggered: 0,
        positionsModified: 0,
        physicsStepsTraced: 0,
        transformsComputed: 0,
        errors: 0,
        lastUpdateTime: Date.now()
    },

    // Memory access cache (for performance)
    memoryCache: new Map(),

    // Thread-local storage
    threadLocalData: new Map() // threadId -> ThreadLocalState
};

// ============================================================================
// TYPE DEFINITIONS AND INTERFACES
// ============================================================================

/**
 * @typedef {Object} ModificationRequest
 * @property {number} x - Target X coordinate
 * @property {number} y - Target Y coordinate
 * @property {number} z - Target Z coordinate
 * @property {string} mode - 'immediate' | 'post-physics' | 'pre-transform'
 * @property {number} priority - Modification priority (higher = more important)
 * @property {Function} [callback] - Optional completion callback
 */

/**
 * @typedef {Object} EntityMetadata
 * @property {NativePointer} base - Entity base address
 * @property {Object} lastKnownPosition - Last observed position
 * @property {Object} lastKnownVelocity - Last observed velocity
 * @property {number} lastUpdateTime - Timestamp of last update
 * @property {boolean} physicsEnabled - Whether physics is active
 * @property {Object} transformData - Cached transform information
 */

/**
 * @typedef {Object} UpdateHistory
 * @property {number} timestamp - Update timestamp
 * @property {Object} position - Position at update
 * @property {Object} velocity - Velocity at update
 * @property {string} updateType - 'physics' | 'transform' | 'manual'
 */

// ============================================================================
// INITIALIZATION AND SETUP
// ============================================================================

/**
 * Initialize the position control framework with comprehensive validation
 * @throws {Error} If target module cannot be located or critical functions cannot be resolved
 */
function initialize() {
    console.log('[INIT] Rigid Entity Position Control Framework v2.0');
    console.log(`[INIT] Target Platform: ${Process.platform} (${Process.arch})`);
    console.log(`[INIT] Process ID: ${Process.id}`);

    // Module base address resolution with fallback logic
    GlobalState.moduleBase = Module.findBaseAddress(CONFIG.MODULE_NAME);
    if (!GlobalState.moduleBase) {
        // Attempt fallback to main module
        const mainModule = Process.enumerateModules()[0];
        console.warn(`[INIT] Module '${CONFIG.MODULE_NAME}' not found, attempting main module: ${mainModule.name}`);
        if (mainModule.name.includes('target') || mainModule.name.includes('game')) {
            GlobalState.moduleBase = mainModule.base;
        } else {
            throw new Error(`Failed to locate target module. Expected: ${CONFIG.MODULE_NAME}`);
        }
    }

    console.log(`[INIT] Module base address: ${GlobalState.moduleBase}`);

    // Calculate runtime function addresses with offset adjustment
    const baseOffset = GlobalState.moduleBase.sub(CONFIG.IDA_BASE);

    for (const [funcName, rva] of Object.entries(CONFIG.FUNCTIONS)) {
        const funcPtr = CONFIG.IDA_BASE.add(rva).add(baseOffset);
        GlobalState.functions[funcName.toLowerCase().replace(/_/g, '')] = funcPtr;

        // Verify function accessibility
        try {
            funcPtr.readU8();
            console.log(`[INIT] ${funcName}: ${funcPtr} [OK]`);
        } catch (e) {
            console.error(`[INIT] ${funcName}: ${funcPtr} [INACCESSIBLE]`);
            throw new Error(`Critical function ${funcName} not accessible at ${funcPtr}`);
        }
    }

    // Initialize performance monitoring
    //initializePerformanceMonitoring();

    // Set up memory cache invalidation
    setInterval(() => {
        GlobalState.memoryCache.clear();
    }, 1000); // Clear cache every second

    console.log('[INIT] Framework initialization complete');
}

/**
 * Initialize performance monitoring subsystem
 */
function initializePerformanceMonitoring() {
    // Monitor hook performance
    Interceptor.addListener({
        onEnter: function(details) {
            const threadId = Process.getCurrentThreadId();
            if (!GlobalState.threadLocalData.has(threadId)) {
                GlobalState.threadLocalData.set(threadId, {
                    hookDepth: 0,
                    startTime: Date.now()
                });
            }
            GlobalState.threadLocalData.get(threadId).hookDepth++;
        },
        onLeave: function(details) {
            const threadId = Process.getCurrentThreadId();
            const threadData = GlobalState.threadLocalData.get(threadId);
            if (threadData) {
                threadData.hookDepth--;
                if (threadData.hookDepth === 0) {
                    GlobalState.threadLocalData.delete(threadId);
                }
            }
        }
    });
}

// ============================================================================
// MEMORY ACCESS UTILITIES
// ============================================================================

const MemoryUtils = {
    /**
     * Read double value with caching and validation
     * @param {NativePointer} ptr - Memory address
     * @param {string} label - Descriptive label for error reporting
     * @returns {number|null} Double value or null on error
     */
    readDoubleCached(ptr, label = 'memory') {
        const cacheKey = ptr.toString();

        // Check cache first
        if (GlobalState.memoryCache.has(cacheKey)) {
            const cached = GlobalState.memoryCache.get(cacheKey);
            if (Date.now() - cached.timestamp < 16) { // 16ms cache validity
                return cached.value;
            }
        }

        try {
            const value = ptr.readDouble();

            // Validate reasonable physics values
            if (!isFinite(value) || Math.abs(value) > 1e10) {
                console.warn(`[MemoryUtils] Suspicious value ${value} read from ${label} at ${ptr}`);
            }

            // Update cache
            GlobalState.memoryCache.set(cacheKey, {
                value: value,
                timestamp: Date.now()
            });

            return value;
        } catch (e) {
            console.error(`[MemoryUtils] Failed to read double from ${label} at ${ptr}: ${e.message}`);
            GlobalState.metrics.errors++;
            return null;
        }
    },

    /**
     * Read entity position with comprehensive validation
     * @param {NativePointer} entityPtr - Entity base address
     * @returns {Object|null} Position object {x, y, z} or null on error
     */
    readEntityPosition(entityPtr) {
        if (entityPtr.isNull()) {
            return null;
        }

        const x = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X), 'POS_X');
        const y = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Y), 'POS_Y');
        const z = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Z), 'POS_Z');

        if (x === null || y === null || z === null) {
            return null;
        }

        return { x, y, z };
    },

    /**
     * Write entity position with atomic updates
     * @param {NativePointer} entityPtr - Entity base address
     * @param {Object} position - Target position {x, y, z}
     * @returns {boolean} Success status
     */
    writeEntityPosition(entityPtr, position) {
        if (entityPtr.isNull()) {
            console.error('[MemoryUtils] Cannot write to NULL entity pointer');
            return false;
        }

        try {
            // Ensure atomic writes for consistency
            Memory.protect(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X), 24, 'rw-');

            entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X).writeDouble(position.x);
            entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Y).writeDouble(position.y);
            entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Z).writeDouble(position.z);

            // Invalidate cache
            GlobalState.memoryCache.delete(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X).toString());
            GlobalState.memoryCache.delete(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Y).toString());
            GlobalState.memoryCache.delete(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_Z).toString());

            return true;
        } catch (e) {
            console.error(`[MemoryUtils] Failed to write position to entity ${entityPtr}: ${e.message}`);
            GlobalState.metrics.errors++;
            return false;
        }
    },

    /**
     * Read entity velocity components
     * @param {NativePointer} entityPtr - Entity base address
     * @returns {Object|null} Velocity object {x, y, z} or null on error
     */
    readEntityVelocity(entityPtr) {
        if (entityPtr.isNull()) {
            return null;
        }

        const x = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_X), 'VEL_X');
        const y = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Y), 'VEL_Y');
        const z = this.readDoubleCached(entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Z), 'VEL_Z');

        if (x === null || y === null || z === null) {
            return null;
        }

        return { x, y, z };
    },

    /**
     * Check if physics is enabled for entity
     * @param {NativePointer} entityPtr - Entity base address
     * @returns {boolean} Physics enabled status
     */
    isPhysicsEnabled(entityPtr) {
        try {
            const physicsFlag = entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_ENABLED_FLAG).readDouble();
            return physicsFlag > 0.0;
        } catch (e) {
            return false;
        }
    },

    /**
     * Dump entity state for debugging
     * @param {NativePointer} entityPtr - Entity base address
     * @param {string} context - Context description
     */
    dumpEntityState(entityPtr, context) {
        if (!CONFIG.LOGGING.VERBOSE) return;

        console.log(`\n[EntityDump] ${context} - Entity: ${entityPtr}`);

        // Position
        const position = this.readEntityPosition(entityPtr);
        console.log(`  Position: ${position ? `(${position.x.toFixed(3)}, ${position.y.toFixed(3)}, ${position.z.toFixed(3)})` : 'UNREADABLE'}`);

        // Velocity
        const velocity = this.readEntityVelocity(entityPtr);
        console.log(`  Velocity: ${velocity ? `(${velocity.x.toFixed(3)}, ${velocity.y.toFixed(3)}, ${velocity.z.toFixed(3)})` : 'UNREADABLE'}`);

        // Physics state
        console.log(`  Physics Enabled: ${this.isPhysicsEnabled(entityPtr)}`);

        // Update flags
        try {
            const updateFlags = entityPtr.add(CONFIG.ENTITY_OFFSETS.UPDATE_FLAGS).readU32();
            console.log(`  Update Flags: 0x${updateFlags.toString(16)}`);
        } catch (e) {
            console.log(`  Update Flags: UNREADABLE`);
        }

        // Memory dump of position area
        if (CONFIG.LOGGING.VERBOSE) {
            console.log('  Position Memory Region:');
            console.log(hexdump(entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X), {
                length: 32,
                header: true,
                ansi: true
            }));
        }
    }
};

// ============================================================================
// ENTITY TRACKING AND METADATA MANAGEMENT
// ============================================================================

const EntityTracker = {
    /**
     * Register entity for tracking
     * @param {NativePointer} entityPtr - Entity base address
     */
    trackEntity(entityPtr) {
        if (GlobalState.trackedEntities.has(entityPtr.toString())) {
            return;
        }

        const metadata = {
            base: entityPtr,
            lastKnownPosition: MemoryUtils.readEntityPosition(entityPtr) || { x: 0, y: 0, z: 0 },
            lastKnownVelocity: MemoryUtils.readEntityVelocity(entityPtr) || { x: 0, y: 0, z: 0 },
            lastUpdateTime: Date.now(),
            physicsEnabled: MemoryUtils.isPhysicsEnabled(entityPtr),
            transformData: {}
        };

        GlobalState.trackedEntities.set(entityPtr.toString(), metadata);
        console.log(`[EntityTracker] Now tracking entity ${entityPtr}`);
    },

    /**
     * Update entity metadata
     * @param {NativePointer} entityPtr - Entity base address
     * @param {string} updateType - Type of update
     */
    updateEntityMetadata(entityPtr, updateType) {
        const key = entityPtr.toString();
        const metadata = GlobalState.trackedEntities.get(key);

        if (!metadata) {
            this.trackEntity(entityPtr);
            return;
        }

        const position = MemoryUtils.readEntityPosition(entityPtr);
        const velocity = MemoryUtils.readEntityVelocity(entityPtr);

        if (position) {
            metadata.lastKnownPosition = position;
        }
        if (velocity) {
            metadata.lastKnownVelocity = velocity;
        }

        metadata.lastUpdateTime = Date.now();
        metadata.physicsEnabled = MemoryUtils.isPhysicsEnabled(entityPtr);

        // Add to history
        if (!GlobalState.entityUpdateHistory.has(key)) {
            GlobalState.entityUpdateHistory.set(key, []);
        }

        const history = GlobalState.entityUpdateHistory.get(key);
        history.push({
            timestamp: Date.now(),
            position: position || metadata.lastKnownPosition,
            velocity: velocity || metadata.lastKnownVelocity,
            updateType: updateType
        });

        // Limit history size
        if (history.length > 100) {
            history.shift();
        }
    },

    /**
     * Get entity metadata
     * @param {NativePointer} entityPtr - Entity base address
     * @returns {EntityMetadata|null}
     */
    getEntityMetadata(entityPtr) {
        return GlobalState.trackedEntities.get(entityPtr.toString()) || null;
    }
};

// ============================================================================
// PHYSICS INSTRUMENTATION HOOKS
// ============================================================================

const PhysicsHooks = {
    /**
     * Install quantum step (physics update) hook
     */
    installQuantumStepHook() {
        const hook = Interceptor.attach(GlobalState.functions.quantumstep, {
            onEnter(args) {
                GlobalState.metrics.hooksTriggered++;
                GlobalState.metrics.physicsStepsTraced++;

                // Extract function arguments
                this.entity = args[0];
                this.deltaTime = args[1].readFloat();

                // Validate entity pointer
                if (this.entity.isNull()) {
                    console.warn('[QuantumStep] NULL entity pointer encountered');
                    return;
                }

                // Track entity
                EntityTracker.trackEntity(this.entity);

                // Store original state
                this.originalPosition = MemoryUtils.readEntityPosition(this.entity);
                this.originalVelocity = MemoryUtils.readEntityVelocity(this.entity);
                this.physicsEnabled = MemoryUtils.isPhysicsEnabled(this.entity);

                if (CONFIG.LOGGING.VERBOSE && CONFIG.LOGGING.LOG_PHYSICS_CALCULATIONS) {
                    console.log(`\n[QuantumStep::onEnter] ===== PHYSICS UPDATE START =====`);
                    console.log(`  Entity: ${this.entity}`);
                    console.log(`  Delta Time: ${this.deltaTime.toFixed(6)}`);
                    console.log(`  Physics Enabled: ${this.physicsEnabled}`);
                    MemoryUtils.dumpEntityState(this.entity, 'Pre-Physics State');
                }

                // Apply pending position modifications (immediate mode)
                const entityKey = this.entity.toString();
                if (GlobalState.positionModifications.has(entityKey)) {
                    const modification = GlobalState.positionModifications.get(entityKey);

                    if (modification.mode === 'immediate') {
                        console.log(`[QuantumStep::onEnter] Applying immediate position modification`);
                        console.log(`  From: (${this.originalPosition.x.toFixed(3)}, ${this.originalPosition.y.toFixed(3)}, ${this.originalPosition.z.toFixed(3)})`);
                        console.log(`  To: (${modification.x.toFixed(3)}, ${modification.y.toFixed(3)}, ${modification.z.toFixed(3)})`);

                        if (MemoryUtils.writeEntityPosition(this.entity, modification)) {
                            GlobalState.metrics.positionsModified++;

                            // Execute callback if provided
                            if (modification.callback) {
                                modification.callback(true, this.entity, modification);
                            }

                            GlobalState.positionModifications.delete(entityKey);
                        }
                    }
                }
            },

            onLeave(retval) {
                if (this.entity.isNull()) return;

                // Read updated state after physics calculations
                const newPosition = MemoryUtils.readEntityPosition(this.entity);
                const newVelocity = MemoryUtils.readEntityVelocity(this.entity);

                // Update entity metadata
                EntityTracker.updateEntityMetadata(this.entity, 'physics');

                if (CONFIG.LOGGING.VERBOSE && CONFIG.LOGGING.LOG_PHYSICS_CALCULATIONS) {
                    console.log(`[QuantumStep::onLeave] ===== PHYSICS UPDATE COMPLETE =====`);

                    if (this.originalPosition && newPosition) {
                        const delta = {
                            x: newPosition.x - this.originalPosition.x,
                            y: newPosition.y - this.originalPosition.y,
                            z: newPosition.z - this.originalPosition.z
                        };
                        console.log(`  Position Delta: (${delta.x.toFixed(6)}, ${delta.y.toFixed(6)}, ${delta.z.toFixed(6)})`);
                    }

                    MemoryUtils.dumpEntityState(this.entity, 'Post-Physics State');
                }

                // Apply pending position modifications (post-physics mode)
                const entityKey = this.entity.toString();
                if (GlobalState.positionModifications.has(entityKey)) {
                    const modification = GlobalState.positionModifications.get(entityKey);

                    if (modification.mode === 'post-physics') {
                        console.log(`[QuantumStep::onLeave] Overriding physics calculation result`);
                        console.log(`  Physics Result: ${newPosition ? `(${newPosition.x.toFixed(3)}, ${newPosition.y.toFixed(3)}, ${newPosition.z.toFixed(3)})` : 'NULL'}`);
                        console.log(`  Override To: (${modification.x.toFixed(3)}, ${modification.y.toFixed(3)}, ${modification.z.toFixed(3)})`);

                        if (MemoryUtils.writeEntityPosition(this.entity, modification)) {
                            GlobalState.metrics.positionsModified++;

                            // Zero out velocities to prevent further physics updates
                            try {
                                this.entity.add(CONFIG.ENTITY_OFFSETS.VELOCITY_X).writeDouble(0.0);
                                this.entity.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Y).writeDouble(0.0);
                                this.entity.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Z).writeDouble(0.0);
                            } catch (e) {
                                console.warn('[QuantumStep::onLeave] Failed to zero velocities');
                            }

                            // Execute callback
                            if (modification.callback) {
                                modification.callback(true, this.entity, modification);
                            }

                            GlobalState.positionModifications.delete(entityKey);
                        }
                    }
                }
            }
        });

        GlobalState.activeHooks.set('quantumStep', hook);
        console.log('[PhysicsHooks] Quantum step hook installed');
    },

    /**
     * Install main update (transform computation) hook
     */
    installMainUpdateHook() {
        const hook = Interceptor.attach(GlobalState.functions.mainupdate, {
            onEnter(args) {
                GlobalState.metrics.hooksTriggered++;
                GlobalState.metrics.transformsComputed++;

                // Extract arguments
                this.entity = args[0];
                this.a2 = args[1].toInt32();
                this.a3 = args[2].toInt32();
                this.a4 = args[3].toInt32();

                if (this.entity.isNull()) {
                    console.warn('[MainUpdate] NULL entity pointer encountered');
                    return;
                }

                // Store pre-transform state
                this.preTransformPosition = MemoryUtils.readEntityPosition(this.entity);

                if (CONFIG.LOGGING.VERBOSE && CONFIG.LOGGING.LOG_TRANSFORM_PIPELINE) {
                    console.log(`\n[MainUpdate::onEnter] ===== TRANSFORM UPDATE START =====`);
                    console.log(`  Entity: ${this.entity}`);
                    console.log(`  Flags: a2=${this.a2}, a3=${this.a3}, a4=${this.a4}`);

                    // Log transform source pointer
                    try {
                        const transformSrcPtr = this.entity.add(CONFIG.ENTITY_OFFSETS.TRANSFORM_SRC_PTR).readPointer();
                        console.log(`  Transform Source Pointer: ${transformSrcPtr}`);

                        if (!transformSrcPtr.isNull()) {
                            // Attempt to read position from transform source
                            const srcX = transformSrcPtr.readDouble();
                            const srcY = transformSrcPtr.add(8).readDouble();
                            const srcZ = transformSrcPtr.add(16).readDouble();
                            console.log(`  Transform Source Data: (${srcX.toFixed(3)}, ${srcY.toFixed(3)}, ${srcZ.toFixed(3)})`);
                        }
                    } catch (e) {
                        console.log(`  Transform Source: UNREADABLE`);
                    }
                }

                // Apply pre-transform modifications
                const entityKey = this.entity.toString();
                if (GlobalState.positionModifications.has(entityKey)) {
                    const modification = GlobalState.positionModifications.get(entityKey);

                    if (modification.mode === 'pre-transform') {
                        console.log(`[MainUpdate::onEnter] Applying pre-transform position modification`);

                        // Modify the transform source data
                        try {
                            const transformSrcPtr = this.entity.add(CONFIG.ENTITY_OFFSETS.TRANSFORM_SRC_PTR).readPointer();
                            if (!transformSrcPtr.isNull()) {
                                transformSrcPtr.writeDouble(modification.x);
                                transformSrcPtr.add(8).writeDouble(modification.y);
                                transformSrcPtr.add(16).writeDouble(modification.z);

                                GlobalState.metrics.positionsModified++;

                                if (modification.callback) {
                                    modification.callback(true, this.entity, modification);
                                }

                                GlobalState.positionModifications.delete(entityKey);
                            }
                        } catch (e) {
                            console.error(`[MainUpdate::onEnter] Failed to modify transform source: ${e.message}`);
                        }
                    }
                }
            },

            onLeave(retval) {
                if (this.entity.isNull()) return;

                // Update entity metadata
                EntityTracker.updateEntityMetadata(this.entity, 'transform');

                if (CONFIG.LOGGING.VERBOSE && CONFIG.LOGGING.LOG_TRANSFORM_PIPELINE) {
                    console.log(`[MainUpdate::onLeave] ===== TRANSFORM UPDATE COMPLETE =====`);

                    // Log effective transform matrix
                    try {
                        const transformPtr = this.entity.add(CONFIG.ENTITY_OFFSETS.EFFECTIVE_TRANSFORM);
                        console.log(`  Effective Transform Matrix at ${transformPtr}:`);
                        console.log(hexdump(transformPtr, {
                            length: 64,
                            header: true,
                            ansi: true
                        }));

                        // Attempt to extract translation from 4x4 matrix
                        // Assuming row-major layout with translation in elements [12], [13], [14]
                        const tx = transformPtr.add(12 * 4).readFloat();
                        const ty = transformPtr.add(13 * 4).readFloat();
                        const tz = transformPtr.add(14 * 4).readFloat();
                        console.log(`  Extracted Translation: (${tx.toFixed(3)}, ${ty.toFixed(3)}, ${tz.toFixed(3)})`);
                    } catch (e) {
                        console.log(`  Effective Transform: UNREADABLE`);
                    }
                }
            }
        });

        GlobalState.activeHooks.set('mainUpdate', hook);
        console.log('[PhysicsHooks] Main update hook installed');
    }
};

// ============================================================================
// POSITION MODIFICATION API
// ============================================================================

const PositionController = {
    /**
     * Schedule position modification with priority handling
     * @param {string|NativePointer} entityAddress - Entity address
     * @param {number} x - Target X coordinate
     * @param {number} y - Target Y coordinate
     * @param {number} z - Target Z coordinate
     * @param {Object} options - Modification options
     * @returns {Promise<Object>} Result promise
     */
    async schedulePositionUpdate(entityAddress, x, y, z, options = {}) {
        const defaults = {
            mode: 'immediate',
            priority: 5,
            callback: null,
            timeout: 5000
        };

        const config = Object.assign({}, defaults, options);

        return new Promise((resolve, reject) => {
            try {
                const entityPtr = entityAddress instanceof NativePointer ?
                    entityAddress : ptr(entityAddress);

                if (entityPtr.isNull()) {
                    throw new Error('Invalid entity address');
                }

                // Validate entity accessibility
                const currentPos = MemoryUtils.readEntityPosition(entityPtr);
                if (!currentPos) {
                    throw new Error('Entity position not accessible');
                }

                const modification = {
                    x: parseFloat(x),
                    y: parseFloat(y),
                    z: parseFloat(z),
                    mode: config.mode,
                    priority: config.priority,
                    timestamp: Date.now(),
                    callback: (success, entity, mod) => {
                        if (config.callback) {
                            config.callback(success, entity, mod);
                        }
                        resolve({
                            success: success,
                            entity: entity.toString(),
                            previousPosition: currentPos,
                            newPosition: { x: mod.x, y: mod.y, z: mod.z },
                            mode: mod.mode
                        });
                    }
                };

                // Handle priority queue
                const entityKey = entityPtr.toString();
                const existing = GlobalState.positionModifications.get(entityKey);
                if (!existing || modification.priority > existing.priority) {
                    GlobalState.positionModifications.set(entityKey, modification);

                    console.log(`[PositionController] Scheduled ${config.mode} update for entity ${entityPtr}`);
                    console.log(`  Current: (${currentPos.x.toFixed(3)}, ${currentPos.y.toFixed(3)}, ${currentPos.z.toFixed(3)})`);
                    console.log(`  Target: (${x.toFixed(3)}, ${y.toFixed(3)}, ${z.toFixed(3)})`);
                    console.log(`  Priority: ${config.priority}`);
                }

                // Set timeout for modification
                setTimeout(() => {
                    if (GlobalState.positionModifications.get(entityKey) === modification) {
                        GlobalState.positionModifications.delete(entityKey);
                        reject(new Error('Position modification timeout'));
                    }
                }, config.timeout);

            } catch (e) {
                console.error(`[PositionController] Error scheduling update: ${e.message}`);
                reject(e);
            }
        });
    },

    /**
     * Immediately force entity position with safety checks
     * @param {string|NativePointer} entityAddress - Entity address
     * @param {number} x - Target X coordinate
     * @param {number} y - Target Y coordinate
     * @param {number} z - Target Z coordinate
     * @returns {Object} Result object
     */
    forcePosition(entityAddress, x, y, z) {
        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            if (entityPtr.isNull()) {
                throw new Error('Invalid entity address');
            }

            const originalPos = MemoryUtils.readEntityPosition(entityPtr);
            if (!originalPos) {
                throw new Error('Cannot read current position');
            }

            const newPos = {
                x: parseFloat(x),
                y: parseFloat(y),
                z: parseFloat(z)
            };

            // Write position
            if (MemoryUtils.writeEntityPosition(entityPtr, newPos)) {
                GlobalState.metrics.positionsModified++;

                // Also update physics calculation positions to ensure consistency
                try {
                    entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_CALC_X).writeDouble(newPos.x);
                    entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_CALC_Y).writeDouble(newPos.y);
                    entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_CALC_Z).writeDouble(newPos.z);
                } catch (e) {
                    console.warn('[PositionController] Failed to update physics calc positions');
                }

                // Update entity tracking
                EntityTracker.updateEntityMetadata(entityPtr, 'manual');

                console.log(`[PositionController] Force-set position for entity ${entityPtr}`);
                console.log(`  From: (${originalPos.x.toFixed(3)}, ${originalPos.y.toFixed(3)}, ${originalPos.z.toFixed(3)})`);
                console.log(`  To: (${newPos.x.toFixed(3)}, ${newPos.y.toFixed(3)}, ${newPos.z.toFixed(3)})`);

                return {
                    success: true,
                    entity: entityPtr.toString(),
                    previousPosition: originalPos,
                    newPosition: newPos,
                    timestamp: Date.now()
                };
            } else {
                throw new Error('Failed to write position');
            }
        } catch (e) {
            console.error(`[PositionController] Error forcing position: ${e.message}`);
            return {
                success: false,
                error: e.message
            };
        }
    },

    /**
     * Get current entity position with metadata
     * @param {string|NativePointer} entityAddress - Entity address
     * @returns {Object} Position and metadata
     */
    getPosition(entityAddress) {
        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            if (entityPtr.isNull()) {
                throw new Error('Invalid entity address');
            }

            const position = MemoryUtils.readEntityPosition(entityPtr);
            const velocity = MemoryUtils.readEntityVelocity(entityPtr);
            const metadata = EntityTracker.getEntityMetadata(entityPtr);

            return {
                success: true,
                entity: entityPtr.toString(),
                position: position,
                velocity: velocity,
                physicsEnabled: MemoryUtils.isPhysicsEnabled(entityPtr),
                metadata: metadata,
                timestamp: Date.now()
            };
        } catch (e) {
            return {
                success: false,
                error: e.message
            };
        }
    },

    /**
     * Set entity velocity
     * @param {string|NativePointer} entityAddress - Entity address
     * @param {number} vx - X velocity
     * @param {number} vy - Y velocity
     * @param {number} vz - Z velocity
     * @returns {Object} Result object
     */
    setVelocity(entityAddress, vx, vy, vz) {
        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            if (entityPtr.isNull()) {
                throw new Error('Invalid entity address');
            }

            entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_X).writeDouble(parseFloat(vx));
            entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Y).writeDouble(parseFloat(vy));
            entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_Z).writeDouble(parseFloat(vz));

            console.log(`[PositionController] Set velocity for entity ${entityPtr}`);
            console.log(`  Velocity: (${vx.toFixed(3)}, ${vy.toFixed(3)}, ${vz.toFixed(3)})`);

            return {
                success: true,
                entity: entityPtr.toString(),
                velocity: { x: vx, y: vy, z: vz }
            };
        } catch (e) {
            console.error(`[PositionController] Error setting velocity: ${e.message}`);
            return {
                success: false,
                error: e.message
            };
        }
    },

    /**
     * Enable or disable physics for entity
     * @param {string|NativePointer} entityAddress - Entity address
     * @param {boolean} enabled - Physics enabled state
     * @returns {Object} Result object
     */
    setPhysicsEnabled(entityAddress, enabled) {
        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            if (entityPtr.isNull()) {
                throw new Error('Invalid entity address');
            }

            const value = enabled ? 1.0 : 0.0;
            entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_ENABLED_FLAG).writeDouble(value);

            console.log(`[PositionController] Set physics ${enabled ? 'ENABLED' : 'DISABLED'} for entity ${entityPtr}`);

            return {
                success: true,
                entity: entityPtr.toString(),
                physicsEnabled: enabled
            };
        } catch (e) {
            console.error(`[PositionController] Error setting physics state: ${e.message}`);
            return {
                success: false,
                error: e.message
            };
        }
    }
};

// ============================================================================
// ADVANCED TRACING WITH STALKER
// ============================================================================

const AdvancedTracing = {
    /**
     * Trace entity position updates with Stalker
     * @param {string|NativePointer} entityAddress - Entity to trace
     * @param {Object} options - Tracing options
     */
    traceEntityUpdates(entityAddress, options = {}) {
        const defaults = {
            duration: 5000,
            includeCallStack: true,
            logMemoryAccess: true
        };

        const config = Object.assign({}, defaults, options);

        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            const threadId = Process.getCurrentThreadId();
            const sessionId = `${entityPtr.toString()}_${Date.now()}`;

            console.log(`[AdvancedTracing] Starting Stalker trace for entity ${entityPtr}`);

            // Define position-related memory ranges
            const positionRanges = [
                { base: entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X), size: 24 },
                { base: entityPtr.add(CONFIG.ENTITY_OFFSETS.VELOCITY_X), size: 24 },
                { base: entityPtr.add(CONFIG.ENTITY_OFFSETS.PHYSICS_CALC_X), size: 24 }
            ];

            Stalker.follow(threadId, {
                events: {
                    call: config.includeCallStack,
                    exec: false,
                    block: true
                },

                transform: (iterator) => {
                    let instruction = iterator.next();
                    const startAddress = iterator.address;

                    while (instruction !== null) {
                        // Check if instruction accesses position-related memory
                        if (config.logMemoryAccess && instruction.mnemonic.includes('mov')) {
                            const shouldLog = instruction.operands.some(op => {
                                if (op.type === 'mem') {
                                    return positionRanges.some(range => {
                                        const memAddr = op.value.disp;
                                        return memAddr >= range.base &&
                                               memAddr < range.base.add(range.size);
                                    });
                                }
                                return false;
                            });

                            if (shouldLog) {
                                iterator.putCallout((context) => {
                                    console.log(`[Stalker] Position memory access at ${instruction.address}`);
                                    console.log(`  Instruction: ${instruction.mnemonic} ${instruction.opStr}`);
                                    console.log(`  RAX: ${context.rax}, RCX: ${context.rcx}`);
                                });
                            }
                        }

                        iterator.keep();
                        instruction = iterator.next();
                    }
                },

                onReceive: (events) => {
                    const parsed = Stalker.parse(events);
                    console.log(`[Stalker] Received ${parsed.length} events`);
                }
            });

            GlobalState.stalkerSessions.set(sessionId, {
                threadId: threadId,
                entity: entityPtr,
                startTime: Date.now()
            });

            // Auto-stop after duration
            setTimeout(() => {
                this.stopTracing(sessionId);
            }, config.duration);

            return {
                success: true,
                sessionId: sessionId,
                entity: entityPtr.toString()
            };

        } catch (e) {
            console.error(`[AdvancedTracing] Error starting trace: ${e.message}`);
            return {
                success: false,
                error: e.message
            };
        }
    },

    /**
     * Stop Stalker tracing session
     * @param {string} sessionId - Session ID to stop
     */
    stopTracing(sessionId) {
        const session = GlobalState.stalkerSessions.get(sessionId);
        if (!session) {
            console.warn(`[AdvancedTracing] Session ${sessionId} not found`);
            return;
        }

        Stalker.unfollow(session.threadId);
        Stalker.garbageCollect();

        GlobalState.stalkerSessions.delete(sessionId);

        const duration = Date.now() - session.startTime;
        console.log(`[AdvancedTracing] Stopped tracing session ${sessionId} after ${duration}ms`);
    }
};

// ============================================================================
// RPC INTERFACE
// ============================================================================

rpc.exports = {
    /**
     * Get framework status and statistics
     */
    getStatus() {
        return {
            initialized: !GlobalState.moduleBase.isNull(),
            moduleBase: GlobalState.moduleBase.toString(),
            functions: Object.fromEntries(
                Object.entries(GlobalState.functions).map(([name, ptr]) =>
                    [name, ptr ? ptr.toString() : 'NULL']
                )
            ),
            hooks: {
                active: GlobalState.activeHooks.size,
                list: Array.from(GlobalState.activeHooks.keys())
            },
            tracking: {
                entities: GlobalState.trackedEntities.size,
                modifications: GlobalState.positionModifications.size,
                stalkerSessions: GlobalState.stalkerSessions.size
            },
            metrics: GlobalState.metrics,
            uptime: Date.now() - GlobalState.metrics.lastUpdateTime
        };
    },

    /**
     * Schedule position update
     */
    async schedulePositionUpdate(entityAddress, x, y, z, options = {}) {
        return await PositionController.schedulePositionUpdate(
            entityAddress, x, y, z, options
        );
    },

    /**
     * Force immediate position change
     */
    forcePosition(entityAddress, x, y, z) {
        return PositionController.forcePosition(entityAddress, x, y, z);
    },

    /**
     * Get entity position and metadata
     */
    getPosition(entityAddress) {
        return PositionController.getPosition(entityAddress);
    },

    /**
     * Set entity velocity
     */
    setVelocity(entityAddress, vx, vy, vz) {
        return PositionController.setVelocity(entityAddress, vx, vy, vz);
    },

    /**
     * Enable/disable physics
     */
    setPhysicsEnabled(entityAddress, enabled) {
        return PositionController.setPhysicsEnabled(entityAddress, enabled);
    },

    /**
     * Get tracked entities
     */
    getTrackedEntities() {
        return Array.from(GlobalState.trackedEntities.entries()).map(([key, metadata]) => ({
            entity: key,
            position: metadata.lastKnownPosition,
            velocity: metadata.lastKnownVelocity,
            physicsEnabled: metadata.physicsEnabled,
            lastUpdate: metadata.lastUpdateTime
        }));
    },

    /**
     * Get entity update history
     */
    getEntityHistory(entityAddress) {
        const entityPtr = entityAddress instanceof NativePointer ?
            entityAddress : ptr(entityAddress);
        const history = GlobalState.entityUpdateHistory.get(entityPtr.toString());
        return history || [];
    },

    /**
     * Clear all modifications
     */
    clearModifications() {
        const count = GlobalState.positionModifications.size;
        GlobalState.positionModifications.clear();
        return {
            success: true,
            cleared: count
        };
    },

    /**
     * Set logging verbosity
     */
    setVerboseLogging(enabled) {
        CONFIG.LOGGING.VERBOSE = enabled;
        return {
            success: true,
            verboseLogging: CONFIG.LOGGING.VERBOSE
        };
    },

    /**
     * Start advanced tracing
     */
    traceEntityUpdates(entityAddress, options = {}) {
        return AdvancedTracing.traceEntityUpdates(entityAddress, options);
    },

    /**
     * Stop tracing session
     */
    stopTracing(sessionId) {
        AdvancedTracing.stopTracing(sessionId);
        return { success: true };
    },

    /**
     * Analyze entity structure (comprehensive debugging)
     */
    analyzeEntity(entityAddress) {
        try {
            const entityPtr = entityAddress instanceof NativePointer ?
                entityAddress : ptr(entityAddress);

            const analysis = {
                entity: entityAddress,
                base: entityPtr.toString(),
                position: MemoryUtils.readEntityPosition(entityPtr),
                velocity: MemoryUtils.readEntityVelocity(entityPtr),
                physicsEnabled: MemoryUtils.isPhysicsEnabled(entityPtr),
                offsets: {}
            };

            // Read all tracked offsets
            for (const [name, offset] of Object.entries(CONFIG.ENTITY_OFFSETS)) {
                try {
                    const addr = entityPtr.add(offset);
                    let value;

                    if (name.includes('PTR')) {
                        value = addr.readPointer().toString();
                    } else if (name.includes('FLAG')) {
                        value = addr.readDouble();
                    } else if (name.includes('POSITION') || name.includes('VELOCITY')) {
                        value = addr.readDouble();
                    } else {
                        // Read first 16 bytes as hex
                        const bytes = addr.readByteArray(16);
                        value = Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join(' ');
                    }

                    analysis.offsets[name] = {
                        offset: '0x' + offset.toString(16),
                        address: addr.toString(),
                        value: value
                    };
                } catch (e) {
                    analysis.offsets[name] = {
                        offset: '0x' + offset.toString(16),
                        error: e.message
                    };
                }
            }

            // Comprehensive memory dump
            console.log(`[Analysis] Entity structure dump for ${entityPtr}:`);
            console.log(hexdump(entityPtr.add(0x620), {
                length: 0x100,
                header: true,
                ansi: true
            }));

            return analysis;
        } catch (e) {
            return {
                success: false,
                error: e.message
            };
        }
    }
};

// ============================================================================
// MAIN EXECUTION
// ============================================================================

/**
 * Initialize and start the position control framework
 */
function main() {
    try {
        console.log('\n╔════════════════════════════════════════════════════════════════╗');
        console.log('║     Rigid Entity Position Control Framework - v2.0             ║');
        console.log('║     Production-Ready Implementation                            ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        // Initialize framework
        initialize();

        // Install hooks
        PhysicsHooks.installQuantumStepHook();
        PhysicsHooks.installMainUpdateHook();

        // Set up cleanup handler
        Script.bindWeak(global, () => {
            console.log('[Cleanup] Framework unloading, removing hooks...');
            for (const hook of GlobalState.activeHooks.values()) {
                hook.detach();
            }
            GlobalState.activeHooks.clear();

            // Stop all Stalker sessions
            for (const sessionId of GlobalState.stalkerSessions.keys()) {
                AdvancedTracing.stopTracing(sessionId);
            }
        });

        console.log('\n[Ready] Framework initialized and operational');
        console.log('Available RPC methods:');
        console.log('  - getStatus()');
        console.log('  - schedulePositionUpdate(entity, x, y, z, options)');
        console.log('  - forcePosition(entity, x, y, z)');
        console.log('  - getPosition(entity)');
        console.log('  - setVelocity(entity, vx, vy, vz)');
        console.log('  - setPhysicsEnabled(entity, enabled)');
        console.log('  - getTrackedEntities()');
        console.log('  - getEntityHistory(entity)');
        console.log('  - clearModifications()');
        console.log('  - traceEntityUpdates(entity, options)');
        console.log('  - analyzeEntity(entity)');
        console.log('\nExample usage:');
        console.log('  await rpc.exports.schedulePositionUpdate("0x1234567890", 100.0, 200.0, 50.0, {mode: "post-physics"})');
        console.log('  rpc.exports.forcePosition("0x1234567890", 100.0, 200.0, 50.0)');

    } catch (e) {
        console.error('[FATAL] Framework initialization failed:', e);
        console.error(e.stack);
        throw e;
    }
}

// Execute main initialization
main();
