/*
 * Frida Script to Teleport an Entity by Intercepting its Transform Update Function
 * Target: 64-bit game process using the analyzed code structure.
 *
 * This script hooks the dispatcher function `sub_140001BA0` which calls the
 * heavily optimized SIMD functions responsible for calculating entity transforms.
 * By modifying the *output* of this function, we can safely change the entity's
 * position without needing to understand the complex internal matrix math.
 */

// --- Configuration ---
// These addresses must be calculated relative to the game's base module address.
// Example: const DISPATCHER_FUNC_OFFSET = 0x1BA0;
const baseAddr = Module.findBaseAddress('StarCitizen.exe'); // Replace 'Game.exe' with the actual executable name
if (!baseAddr) {
    throw new Error("Could not find base address of the game module.");
}

// The target function is the dispatcher that chooses between the SIMD implementations.
const targetFuncPtr = baseAddr.add(0x1BA0); // Offset of sub_140001BA0

// --- Globals for RPC Control ---
let g_targetEntityPtr = NULL;
let g_newPosition = { x: 0, y: 0, z: 0 };
let isTeleportActive = false;

// --- Main Logic ---

console.log(`[+] Script loaded. Attaching to dispatcher function at: ${targetFuncPtr}`);

Interceptor.attach(targetFuncPtr, {
    /**
     * onEnter: Called when the dispatcher function is entered.
     * We capture the arguments here, especially the output pointers.
     */
    onEnter: function(args) {
        // The first argument to the underlying SIMD functions (sub_140006630/sub_14000C960)
        // is the entity-related data structure. This corresponds to `a1` of the dispatcher.
        const currentEntityDataPtr = args[0];

        // Store context for onLeave. We are interested in the output pointers.
        // Based on the x64 calling convention and the function signature, these are:
        // a1-a4 are in registers, a5-a10 are on the stack. Frida's `args` abstracts this.
        this.a5 = args[4]; // Output pointer 1
        this.a6 = args[5]; // Output pointer 2
        this.a7 = args[6]; // Output pointer 3

        // Check if the teleport is active and if this is our target entity.
        // The entity pointer itself might not be `a1`, but a structure pointed to by it.
        // For this example, we assume `a1` is a sufficient identifier. In a real scenario,
        // you might need to read an ID from `a1 + offset`.
        if (isTeleportActive && currentEntityDataPtr.equals(g_targetEntityPtr)) {
            this.isTarget = true;
            console.log(`[+] Target entity ${g_targetEntityPtr} found. Preparing to teleport.`);
        } else {
            this.isTarget = false;
        }
    },

    /**
     * onLeave: Called when the dispatcher function is about to return.
     * The original SIMD function has finished, and the output matrices are populated.
     * This is the perfect time to overwrite the position data.
     */
    onLeave: function(retval) {
        if (!this.isTarget) {
            return;
        }

        // Offsets within the 4x4 column-major transformation matrix for the position vector.
        const POS_X_OFFSET = 0x30; // 12 * sizeof(float)
        const POS_Y_OFFSET = 0x34; // 13 * sizeof(float)
        const POS_Z_OFFSET = 0x38; // 14 * sizeof(float)

        try {
            // To be safe, we modify all three potential transform outputs.
            // They might be used for rendering, physics, and other systems respectively.
            const outputPointers = [this.a5, this.a6, this.a7];

            console.log(`[*] Original position in matrix a5: { x: ${this.a5.add(POS_X_OFFSET).readFloat().toFixed(2)}, y: ${this.a5.add(POS_Y_OFFSET).readFloat().toFixed(2)}, z: ${this.a5.add(POS_Z_OFFSET).readFloat().toFixed(2)} }`);

            outputPointers.forEach((ptr, index) => {
                if (!ptr.isNull()) {
                    // Write the new coordinates directly into the output matrix.
                    ptr.add(POS_X_OFFSET).writeFloat(g_newPosition.x);
                    ptr.add(POS_Y_OFFSET).writeFloat(g_newPosition.y);
                    ptr.add(POS_Z_OFFSET).writeFloat(g_newPosition.z);
                }
            });

            console.log(`[+] Teleport successful! Entity moved to: { x: ${g_newPosition.x}, y: ${g_newPosition.y}, z: ${g_newPosition.z} }`);

        } catch (e) {
            console.error(`[!] Error during memory modification: ${e.message}`);
        }

        // Deactivate the flag so it only teleports once per command.
        isTeleportActive = false;
        g_targetEntityPtr = NULL;
    }
});

/**
 * Expose a function to be called from our external Python script.
 * This allows us to dynamically set the target and destination.
 */
rpc.exports = {
    teleportEntity: function(entityPtrStr, x, y, z) {
        console.log(`[RPC] Received teleport command.`);
        try {
            g_targetEntityPtr = ptr(entityPtrStr);
            g_newPosition = { x: parseFloat(x), y: parseFloat(y), z: parseFloat(z) };
            isTeleportActive = true;
            console.log(`[RPC] Teleport armed for entity ${g_targetEntityPtr} to (${x}, ${y}, ${z}).`);
            return `Teleport command received for entity ${g_targetEntityPtr}.`;
        } catch (e) {
            const errorMsg = `[RPC] Error processing teleport command: ${e.message}`;
            console.error(errorMsg);
            return errorMsg;
        }
    }
};
