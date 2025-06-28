/*
 *  Rigid Entity Position Control Framework - v2.7 (Definitive)
 *
 *  This script provides a comprehensive suite of tools for controlling entity positions.
 *  It combines direct, immediate control with event-driven instrumentation hooks.
 *
 *  Key Features:
 *  - Authoritative Position Reading: Exclusively uses the `getWorldPos` virtual function
 *    for all position lookups, ensuring maximum accuracy.
 *  - Resilient Position Writing: A robust `forcePosition` function handles multiple
 *    entity update pathways for broad compatibility.
 *  - Full Instrumentation Suite: Includes hooks for passive monitoring and for implementing
 *    time-based or event-driven modifications (e.g., 'pre-transform').
 *  - High-Level API: `moveEntityNearEntity` provides a simple, powerful interface for
 *    complex teleportation tasks.
 */

'use strict';

// --- Configuration ---
const CONFIG = {
    MODULE_NAME: Process.platform === 'windows' ? 'StarCitizen.exe' : 'StarCitizen.exe',

    FUNCTIONS: {
        MAIN_UPDATE: 0x68B88B0,
    },

    ENTITY_OFFSETS: {
        POSITION_X:          0x628, // double, used for direct physics state writing
        POSITION_Y:          0x630, // double
        POSITION_Z:          0x638, // double
        TRANSFORM_SRC_PTR:   0x210, // NativePointer -> points to source transform data
        UPDATE_FLAGS:        0x184, // u32 bitfield
    },

    IDA_BASE: ptr('0x140000000'),
};

// --- Global State ---
const GlobalState = {
    moduleBase: NULL,
    functions: {},
    activeHooks: new Map(),
    positionModifications: new Map(),
    metrics: {
        hooksTriggered: 0,
        positionsModified: 0,
        errors: 0,
        startTime: Date.now()
    },
};

// --- Shared Utilities & Entity Abstraction ---
const PTR_SIZE = Process.pointerSize;

function callVFunc(thisPtr, index, returnType, argTypes, args = []) {
    if (thisPtr.isNull()) {
        throw new Error("callVFunc received a null 'this' pointer.");
    }
    const vtable = thisPtr.readPointer();
    if (vtable.isNull()) {
        throw new Error("Vtable is null.");
    }
    const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
    if (fnPtr.isNull()) {
        throw new Error(`Function pointer at vtable index ${index} is null.`);
    }
    const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
    return fn(thisPtr, ...args);
}

class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
}

class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 89: Get world position. This is the authoritative source of truth.
    getWorldPos(flags = 0) {
        const outPos = Memory.alloc(24); // 3 * double
        callVFunc(this.ptr, 89, "void", ["pointer", "uint32"], [outPos, flags]);
        const x = outPos.readDouble();
        const y = outPos.add(8).readDouble();
        const z = outPos.add(16).readDouble();
        return new DVec3(x, y, z);
    }
}

// --- Core Utilities ---
const MemoryUtils = {
    // This utility is now only for WRITING to the physics state, not reading.
    writePhysicsStatePosition(entityPtr, position) {
        if (entityPtr.isNull()) return false;
        try {
            const baseAddr = entityPtr.add(CONFIG.ENTITY_OFFSETS.POSITION_X);
            Memory.protect(baseAddr, 24, 'rw-');
            baseAddr.writeDouble(position.x);
            baseAddr.add(8).writeDouble(position.y);
            baseAddr.add(16).writeDouble(position.z);
            return true;
        } catch (e) {
            console.error(`[Memory] Failed to write physics state position to entity ${entityPtr}: ${e.message}`);
            GlobalState.metrics.errors++;
            return false;
        }
    }
};

// --- Instrumentation Hooks ---
const PhysicsHooks = {
    installHooks() {
        this.installMainUpdateHook();
        console.log('[Hooks] All instrumentation hooks installed.');
    },

    installMainUpdateHook() {
        const targetAddress = GlobalState.functions.mainupdate;
        if (!targetAddress) {
            throw new Error("mainupdate function address is not resolved. Cannot install hook.");
        }

        const hook = Interceptor.attach(targetAddress, {
            onEnter(args) {
                GlobalState.metrics.hooksTriggered++;
                const entity = args[0];
                if (entity.isNull()) return;

                const entityKey = entity.toString();
                if (GlobalState.positionModifications.has(entityKey)) {
                    const mod = GlobalState.positionModifications.get(entityKey);
                    if (mod.mode === 'pre-transform') {
                        try {
                            const transformSrcPtr = entity.add(CONFIG.ENTITY_OFFSETS.TRANSFORM_SRC_PTR).readPointer();
                            if (!transformSrcPtr.isNull()) {
                                transformSrcPtr.writeDouble(mod.x);
                                transformSrcPtr.add(8).writeDouble(mod.y);
                                transformSrcPtr.add(16).writeDouble(mod.z);
                                GlobalState.metrics.positionsModified++;
                                if (mod.callback) mod.callback(true, entity, mod);
                                GlobalState.positionModifications.delete(entityKey);
                            }
                        } catch (e) {
                            console.error(`[Hook] Failed to apply pre-transform modification: ${e.message}`);
                        }
                    }
                }
            },
        });
        GlobalState.activeHooks.set('mainUpdate', hook);
    }
};

// --- Public API ---
const PositionController = {
    async schedulePositionUpdate(entityAddress, x, y, z, options = {}) {
        const config = { mode: 'pre-transform', priority: 5, timeout: 5000, ...options };
        return new Promise((resolve, reject) => {
            try {
                const entityPtr = ptr(entityAddress);
                if (entityPtr.isNull()) throw new Error('Invalid entity address');

                const modification = {
                    x: parseFloat(x), y: parseFloat(y), z: parseFloat(z),
                    mode: config.mode, priority: config.priority,
                    callback: (success, entity, mod) => {
                        if (config.callback) config.callback(success, entity, mod);
                        resolve({ success, entity: entity.toString(), newPosition: { x: mod.x, y: mod.y, z: mod.z } });
                    }
                };

                const entityKey = entityPtr.toString();
                const existing = GlobalState.positionModifications.get(entityKey);
                if (!existing || modification.priority >= existing.priority) {
                    GlobalState.positionModifications.set(entityKey, modification);
                }

                setTimeout(() => {
                    if (GlobalState.positionModifications.get(entityKey) === modification) {
                        GlobalState.positionModifications.delete(entityKey);
                        reject(new Error('Position modification request timed out.'));
                    }
                }, config.timeout);
            } catch (e) {
                console.error(`[Controller] Error scheduling update: ${e.message}`);
                reject(e);
            }
        });
    },

    forcePosition(entityAddress, x, y, z) {
        try {
            const entityPtr = ptr(entityAddress);
            if (entityPtr.isNull()) {
                throw new Error('Invalid entity address provided.');
            }

            const entity = new CEntity(entityPtr);
            const newPos = { x: parseFloat(x), y: parseFloat(y), z: parseFloat(z) };
            let transformSrcPtr = NULL;
            let pathUsed = 'unknown';

            const originalPos = entity.getWorldPos();

            try {
                transformSrcPtr = entityPtr.add(CONFIG.ENTITY_OFFSETS.TRANSFORM_SRC_PTR).readPointer();
            } catch (e) {
                transformSrcPtr = NULL;
                console.warn(`[Controller] Could not read transform source pointer for ${entityPtr}. Using fallback path.`);
            }

            if (!transformSrcPtr.isNull()) {
                pathUsed = 'primary (transform source)';
                transformSrcPtr.writeDouble(newPos.x);
                transformSrcPtr.add(8).writeDouble(newPos.y);
                transformSrcPtr.add(16).writeDouble(newPos.z);
            } else {
                pathUsed = 'fallback (direct physics state)';
                if (!MemoryUtils.writePhysicsStatePosition(entityPtr, newPos)) {
                    throw new Error("Failed to write to primary physics state in fallback path.");
                }
                try {
                    const updateFlagsAddr = entityPtr.add(CONFIG.ENTITY_OFFSETS.UPDATE_FLAGS);
                    const currentFlags = updateFlagsAddr.readU32();
                    Memory.writeInt(updateFlagsAddr, currentFlags | 0x1);
                } catch (e) {
                    console.warn(`[Controller] Failed to set update flag: ${e.message}. Position may not update visually until next physics tick.`);
                }
            }

            MemoryUtils.writePhysicsStatePosition(entityPtr, newPos);
            GlobalState.metrics.positionsModified++;

            console.log(`[Controller] Force-set position for entity ${entityPtr}`);
            console.log(`  From: (${originalPos.x.toFixed(3)}, ${originalPos.y.toFixed(3)}, ${originalPos.z.toFixed(3)})`);
            console.log(`  To:   (${newPos.x.toFixed(3)}, ${newPos.y.toFixed(3)}, ${newPos.z.toFixed(3)})`);

            return {
                success: true,
                entity: entityPtr.toString(),
                pathUsed: pathUsed,
                newPosition: newPos
            };
        } catch (e) {
            console.error(`[Controller] Error in forcePosition: ${e.message}`);
            GlobalState.metrics.errors++;
            return { success: false, error: e.message };
        }
    }
};

// --- RPC Interface ---
rpc.exports = {
    getStatus() {
        return {
            initialized: !GlobalState.moduleBase.isNull(),
            moduleBase: GlobalState.moduleBase.toString(),
            hooks: Array.from(GlobalState.activeHooks.keys()),
            metrics: { ...GlobalState.metrics, uptime: (Date.now() - GlobalState.metrics.startTime) / 1000 }
        };
    },

    schedulePositionUpdate(entityAddress, x, y, z, options = {}) {
        return PositionController.schedulePositionUpdate(entityAddress, x, y, z, options);
    },

    forcePosition(entityAddress, x, y, z) {
        return PositionController.forcePosition(entityAddress, x, y, z);
    },

    moveEntityNearEntity(sourceEntityAddress, targetEntityAddress) {
        try {
            const sourcePtr = ptr(sourceEntityAddress);
            const targetPtr = ptr(targetEntityAddress);

            if (sourcePtr.isNull() || targetPtr.isNull()) {
                throw new Error("One or both provided entity addresses are null.");
            }

            console.log(`[MoveEntity] Attempting to move ${sourcePtr} near ${targetPtr}`);

            const targetEntity = new CEntity(targetPtr);
            const targetPosition = targetEntity.getWorldPos();

            console.log(`[MoveEntity] Target position acquired via getWorldPos(): (${targetPosition.x.toFixed(2)}, ${targetPosition.y.toFixed(2)}, ${targetPosition.z.toFixed(2)})`);

            const moveResult = PositionController.forcePosition(
                sourcePtr,
                targetPosition.x,
                targetPosition.y,
                targetPosition.z
            );

            if (!moveResult.success) {
                throw new Error(`Failed to move source entity: ${moveResult.error}`);
            }

            return {
                success: true,
                sourceEntity: sourcePtr.toString(),
                targetEntity: targetPtr.toString(),
                movedToPosition: targetPosition,
                details: moveResult
            };
        } catch (e) {
            console.error(`[MoveEntity] Operation failed: ${e.message}`);
            return { success: false, error: e.message };
        }
    },

    analyzeEntity(entityAddress) {
        try {
            const entityPtr = ptr(entityAddress);
            const analysis = { entity: entityAddress, offsets: {} };
            for (const [name, offset] of Object.entries(CONFIG.ENTITY_OFFSETS)) {
                try {
                    const addr = entityPtr.add(offset);
                    let value;
                    if (name.includes('PTR')) value = addr.readPointer().toString();
                    else if (name.includes('FLAG')) value = addr.readDouble();
                    else if (name.includes('POSITION')) value = addr.readDouble();
                    else value = `0x${addr.readU32().toString(16)}`;
                    analysis.offsets[name] = { address: addr.toString(), value: value };
                } catch (e) {
                    analysis.offsets[name] = { error: e.message };
                }
            }
            try {
                const worldPos = new CEntity(entityPtr).getWorldPos();
                analysis.offsets['VFUNC_WORLD_POS'] = { value: worldPos };
            } catch (e) {
                analysis.offsets['VFUNC_WORLD_POS'] = { error: e.message };
            }
            return analysis;
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
};

// --- Main Execution ---
function main() {
    try {
        console.log('\n╔════════════════════════════════════════════════════════════════╗');
        console.log('║     Rigid Entity Position Control Framework - v2.7 (Definitive)  ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        GlobalState.moduleBase = Module.findBaseAddress(CONFIG.MODULE_NAME);
        if (!GlobalState.moduleBase) {
            throw new Error(`Failed to locate target module: ${CONFIG.MODULE_NAME}`);
        }
        console.log(`[Init] Module base address: ${GlobalState.moduleBase}`);

        const baseOffset = GlobalState.moduleBase.sub(CONFIG.IDA_BASE);

        for (const [funcName, rva] of Object.entries(CONFIG.FUNCTIONS)) {
            const key = funcName.toLowerCase().replace(/_/g, '');
            const address = CONFIG.IDA_BASE.add(rva).add(baseOffset);
            GlobalState.functions[key] = address;
            console.log(`[Init] Resolved ${key}: ${address}`);
        }

        PhysicsHooks.installHooks();

        Script.bindWeak(global, () => {
            console.log('[Cleanup] Detaching all hooks...');
            for (const hook of GlobalState.activeHooks.values()) {
                hook.detach();
            }
            GlobalState.activeHooks.clear();
        });

        console.log('\n[Ready] Framework initialized and operational. RPC methods are available.');
        console.log('Key function: rpc.exports.moveEntityNearEntity(sourceAddr, targetAddr)');

    } catch (e) {
        console.error(`[FATAL] Framework initialization failed: ${e.message}`);
        console.error(e.stack);
    }
}

main();
