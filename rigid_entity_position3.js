/*
 *  Rigid Entity Position Control Framework - v2.8 (Crash-Free Teleport)
 *
 *  This script provides a comprehensive suite of tools for controlling entity positions.
 *
 *  Correction:
 *  - Implemented a "clean teleport" mechanism using the engine's native `setLocalTransform`
 *    virtual function. This resolves use-after-free crashes when quitting to menu after
 *    a teleport by ensuring the entity's zone registration is correctly updated.
 */

'use strict';

// --- Configuration ---
const CONFIG = {
    MODULE_NAME: Process.platform === 'windows' ? 'StarCitizen.exe' : 'StarCitizen.exe',
    IDA_BASE: ptr('0x140000000'),
};

// --- Global State ---
const GlobalState = {
    moduleBase: NULL,
    metrics: {
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

class CZone {
    constructor(ptr) {
        this.ptr = ptr;
    }
}

class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 89: Get world position.
    getWorldPos(flags = 0) {
        const outPos = Memory.alloc(24); // 3 * double
        callVFunc(this.ptr, 89, "void", ["pointer", "uint32"], [outPos, flags]);
        return new DVec3(outPos.readDouble(), outPos.add(8).readDouble(), outPos.add(16).readDouble());
    }

    // vfunc 199: Get the zone this entity is currently in.
    getZone() {
        const ptr = callVFunc(this.ptr, 199, "pointer", [], 'getZone');
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 206: Set local transform relative to a target zone. This is the clean way to move entities.
    setLocalTransform(targetZonePtr, transformMatrixPtr, flags = 0) {
        callVFunc(this.ptr, 206, "void", ["pointer", "pointer", "uint32"], [targetZonePtr, transformMatrixPtr, flags]);
    }
}

// --- Public API ---
const PositionController = {
    // Creates a 4x4 transform matrix in memory for the setLocalTransform function.
    createTransformMatrix(position) {
        // A 4x4 matrix of floats is 16 * 4 = 64 bytes.
        const matrixPtr = Memory.alloc(64);

        // Write an identity matrix first.
        matrixPtr.writeByteArray([
            1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // Row 1 (1.0f, 0.0f, 0.0f, 0.0f)
            0, 0, 0, 0,  1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // Row 2 (0.0f, 1.0f, 0.0f, 0.0f)
            0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0,  0, 0, 0, 0, // Row 3 (0.0f, 0.0f, 1.0f, 0.0f)
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0  // Row 4 (translation + 1.0f)
        ]);

        // Overwrite the identity values with floats.
        matrixPtr.add(0 * 4).writeFloat(1.0);
        matrixPtr.add(5 * 4).writeFloat(1.0);
        matrixPtr.add(10 * 4).writeFloat(1.0);
        matrixPtr.add(15 * 4).writeFloat(1.0);

        // Write the translation part (position) into the last column.
        matrixPtr.add(12 * 4).writeFloat(position.x); // [3][0]
        matrixPtr.add(13 * 4).writeFloat(position.y); // [3][1]
        matrixPtr.add(14 * 4).writeFloat(position.z); // [3][2]

        return matrixPtr;
    }
};

// --- RPC Interface ---
rpc.exports = {
    getStatus() {
        return {
            initialized: !GlobalState.moduleBase.isNull(),
            moduleBase: GlobalState.moduleBase.toString(),
            metrics: { ...GlobalState.metrics, uptime: (Date.now() - GlobalState.metrics.startTime) / 1000 }
        };
    },

    moveEntityNearEntity(sourceEntityAddress, targetEntityAddress) {
        try {
            const sourcePtr = ptr(sourceEntityAddress);
            const targetPtr = ptr(targetEntityAddress);

            if (sourcePtr.isNull() || targetPtr.isNull()) {
                throw new Error("One or both provided entity addresses are null.");
            }

            console.log(`[MoveEntity] Initiating clean teleport for ${sourcePtr} to ${targetPtr}`);

            const sourceEntity = new CEntity(sourcePtr);
            const targetEntity = new CEntity(targetPtr);

            // Step 1: Get the authoritative world position of the target entity.
            const targetPosition = targetEntity.getWorldPos();
            console.log(`[MoveEntity] Target position acquired: (${targetPosition.x.toFixed(2)}, ${targetPosition.y.toFixed(2)}, ${targetPosition.z.toFixed(2)})`);

            // Step 2: Get the zone of the target entity. This is critical for a clean move.
            const targetZone = targetEntity.getZone();
            if (!targetZone || targetZone.ptr.isNull()) {
                throw new Error(`Could not retrieve a valid zone from the target entity ${targetPtr}.`);
            }
            console.log(`[MoveEntity] Target zone acquired: ${targetZone.ptr}`);

            // Step 3: Create a transform matrix representing the target position.
            const transformMatrixPtr = PositionController.createTransformMatrix(targetPosition);
            console.log(`[MoveEntity] Created transform matrix at ${transformMatrixPtr}`);

            // Step 4: Call the engine's native function to perform the move.
            // This function handles all internal state updates, preventing crashes.
            sourceEntity.setLocalTransform(targetZone.ptr, transformMatrixPtr);
            console.log(`[MoveEntity] 'setLocalTransform' called successfully.`);

            GlobalState.metrics.positionsModified++;

            return {
                success: true,
                sourceEntity: sourcePtr.toString(),
                targetEntity: targetPtr.toString(),
                movedToPosition: targetPosition,
                details: "Teleport executed via engine's native setLocalTransform function."
            };

        } catch (e) {
            console.error(`[MoveEntity] Operation failed: ${e.message}`);
            GlobalState.metrics.errors++;
            return { success: false, error: e.message };
        }
    },
};

// --- Main Execution ---
function main() {
    try {
        console.log('\n╔════════════════════════════════════════════════════════════════╗');
        console.log('║     Rigid Entity Position Control Framework - v2.8 (Crash-Free)  ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        GlobalState.moduleBase = Module.findBaseAddress(CONFIG.MODULE_NAME);
        if (!GlobalState.moduleBase) {
            throw new Error(`Failed to locate target module: ${CONFIG.MODULE_NAME}`);
        }
        console.log(`[Init] Module base address: ${GlobalState.moduleBase}`);

        console.log('\n[Ready] Framework initialized and operational. RPC methods are available.');
        console.log('Key function: rpc.exports.moveEntityNearEntity(sourceAddr, targetAddr)');

    } catch (e) {
        console.error(`[FATAL] Framework initialization failed: ${e.message}`);
        console.error(e.stack);
    }
}

main();
