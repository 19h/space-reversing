// --- CONFIGURATION ---
const GAME_MODULE_NAME = "StarCitizen.exe"; // Replace with your game's executable name
const ENTITY_ID_TO_TELEPORT = 201926434426; // Replace with the actual Entity ID (this is a placeholder)
const TARGET_X = 100.0;
const TARGET_Y = 200.0;
const TARGET_Z = 50.0;

// --- OFFSETS (relative to module base) ---
const OFFSET_SUB_1412A8110 = 0x1412A8110 - 0x140000000;
const OFFSET_SUB_145A8DC50 = 0x145A8DC50 - 0x140000000;
const OFFSET_ACTOR_ACTION_HANDLER_INSTANCE = 0x149B4FBE8 - 0x140000000;

function teleportEntity() {
    console.log("[DEBUG] === Starting teleportEntity function ===");
    console.log(`[DEBUG] Configuration - Game Module: ${GAME_MODULE_NAME}`);
    console.log(`[DEBUG] Configuration - Entity ID: ${ENTITY_ID_TO_TELEPORT}`);
    console.log(`[DEBUG] Configuration - Target Position: X=${TARGET_X}, Y=${TARGET_Y}, Z=${TARGET_Z}`);
    console.log(`[DEBUG] Configuration - Offset SUB_1412A8110: 0x${OFFSET_SUB_1412A8110.toString(16)}`);
    console.log(`[DEBUG] Configuration - Offset SUB_145A8DC50: 0x${OFFSET_SUB_145A8DC50.toString(16)}`);
    console.log(`[DEBUG] Configuration - Offset ACTOR_ACTION_HANDLER: 0x${OFFSET_ACTOR_ACTION_HANDLER_INSTANCE.toString(16)}`);

    const baseAddress = Module.findBaseAddress(GAME_MODULE_NAME);
    if (!baseAddress) {
        console.error(`[!] Module ${GAME_MODULE_NAME} not found.`);
        return;
    }
    console.log(`[+] Base address of ${GAME_MODULE_NAME}: ${baseAddress}`);
    console.log(`[DEBUG] fnPrepareTeleportParams address: ${baseAddress.add(OFFSET_SUB_1412A8110)}`);
    console.log(`[DEBUG] fnExecuteTeleport address: ${baseAddress.add(OFFSET_SUB_145A8DC50)}`);
    console.log(`[DEBUG] ActorActionHandler instance pointer address: ${baseAddress.add(OFFSET_ACTOR_ACTION_HANDLER_INSTANCE)}`);

    const fnSub1412A8110Address = baseAddress.add(OFFSET_SUB_1412A8110);

    console.log("[DEBUG] Intercepting sub_1412A8110 at " + fnSub1412A8110Address);
    Interceptor.attach(fnSub1412A8110Address, {
        onEnter: function(args) {
            this.a1_teleportParamsPtr = args[0];
            this.a2_entityId = args[1];
            this.a3_sourceTransformPtr = args[2];
            this.a4_a4FlagsPtr = args[3];
            this.a5_zoneIdPtr = args[4];
            this.a6_charFlag = args[5].toInt32(); // Convert NativePointer to int for logging
            this.a7_intFlag = args[6].toInt32();
            this.a8_intFlag = args[7].toInt32();
            this.a9_charFlag = args[8].toInt32();

            console.log("======================================================");
            console.log(`[HOOK sub_1412A8110 ON_ENTER]`);
            console.log(`  a1 (teleportParamsPtr): ${this.a1_teleportParamsPtr}`);
            console.log(`  a2 (entityId): ${this.a2_entityId}`);
            console.log(`  a3 (sourceTransformPtr): ${this.a3_sourceTransformPtr}`);
            console.log(`  a4 (a4FlagsPtr): ${this.a4_a4FlagsPtr}`);
            console.log(`  a5 (zoneIdPtr): ${this.a5_zoneIdPtr}`);
            console.log(`  a6: ${this.a6_charFlag}`);
            console.log(`  a7: ${this.a7_intFlag}`);
            console.log(`  a8: ${this.a8_intFlag}`);
            console.log(`  a9: ${this.a9_charFlag}`);

            // Log values pointed to by pointers if they are not null
            if (!this.a3_sourceTransformPtr.isNull()) {
                try {
                    console.log(`  *(a3 + 0x00): ${this.a3_sourceTransformPtr.readDouble()}`);
                    console.log(`  *(a3 + 0x08): ${this.a3_sourceTransformPtr.add(8).readDouble()}`);
                    console.log(`  *(a3 + 0x10): ${this.a3_sourceTransformPtr.add(16).readDouble()}`);
                } catch (e) { console.log(`  Error reading from a3: ${e.message}`); }
            }
            if (!this.a4_a4FlagsPtr.isNull()) {
                try {
                    console.log(`  *a4: ${this.a4_a4FlagsPtr.readU32()}`);
                    console.log(`  a4[1]: ${this.a4_a4FlagsPtr.add(4).readU32()}`);
                } catch (e) { console.log(`  Error reading from a4: ${e.message}`); }
            }
            if (!this.a5_zoneIdPtr.isNull()) {
                try {
                    console.log(`  *a5 (qword): ${this.a5_zoneIdPtr.readU64()}`);
                    console.log(`  *(a5 + 8) (dword): ${this.a5_zoneIdPtr.add(8).readU32()}`);
                } catch (e) { console.log(`  Error reading from a5: ${e.message}`); }
            }
            console.log("======================================================");

            this.loggEnv = true; // Flag to control logging of gEnv related calls

            this.gEnv = ptr(0x149B4FBE0);
            console.log(`  [HOOK] gEnv found at ${this.gEnv}`);
        },
        onLeave: function(retval) {
            console.log("======================================================");
            console.log(`[HOOK sub_1412A8110 ON_LEAVE] retval: ${retval}`);
            console.log("  Teleport Params after population (first few fields):");
            if (!this.a1_teleportParamsPtr.isNull()) {
                try {
                    console.log(`    EntityID: ${this.a1_teleportParamsPtr.readU64()}`);
                    console.log(`    Pos X: ${this.a1_teleportParamsPtr.add(0x08).readDouble()}`);
                    console.log(`    Pos Y: ${this.a1_teleportParamsPtr.add(0x10).readDouble()}`);
                    console.log(`    Pos Z: ${this.a1_teleportParamsPtr.add(0x18).readDouble()}`);
                    console.log(`    a1[0xE] (from *a5): ${this.a1_teleportParamsPtr.add(0x70).readU64()}`);
                    console.log(`    a1+0x78 (from *(a5+8)): ${this.a1_teleportParamsPtr.add(0x78).readU32()}`);
                } catch(e) { console.log(`    Error reading from a1_teleportParamsPtr onLeave: ${e.message}`); }
            }

            if (this.loggEnv && this.gEnv && !this.gEnv.isNull()) {
                try {
                    const v11_entityId = this.a1_teleportParamsPtr.readU64();
                    console.log(`  [HOOK ON_LEAVE] v11 (EntityID from params): ${v11_entityId}`);

                    if (!v11_entityId.equals(0)) { // Only proceed if entityId is not 0
                        const gEnv_vtable = this.gEnv;
                        const fn_gEnv_offset_118 = gEnv_vtable.add(0x118).readPointer();
                        const v12 = new NativeFunction(fn_gEnv_offset_118, 'pointer', ['pointer'])(this.gEnv);
                        console.log(`  [HOOK ON_LEAVE] v12 (from gEnv+0x118): ${v12}`);

                        if (!v12.isNull()) {
                            const v12_vtable = v12.readPointer();
                            const fn_v12_offset_668 = v12_vtable.add(0x668).readPointer();
                            const v13 = new NativeFunction(fn_v12_offset_668, 'pointer', ['pointer'])(v12);
                            console.log(`  [HOOK ON_LEAVE] v13 (from v12+0x668): ${v13}`);

                            if (!v13.isNull()) {
                                const v13_vtable = v13.readPointer();
                                const fn_v13_offset_170 = v13_vtable.add(0x170).readPointer();
                                // For the call to (v13 + 0x170), the third arg is a1 + 5 (teleportParamsPtr.add(0x28))
                                const arg_a1_plus_5 = this.a1_teleportParamsPtr.add(0x28); // 0x28 = 5 * sizeof(__int64)
                                const tempByteArgForV16 = Memory.alloc(1); // Dummy for _BYTE* v16

                                const v14 = new NativeFunction(fn_v13_offset_170, 'pointer', ['pointer', 'pointer', 'pointer'])(v13, tempByteArgForV16, arg_a1_plus_5);
                                console.log(`  [HOOK ON_LEAVE] v14 (from v13+0x170): ${v14}`);
                                if (v14.equals(ptr("-8"))) { // Check if v14 is -8
                                     console.error("  [HOOK ON_LEAVE] CRITICAL: v14 is -8 (0xfffffffffffffff8)!");
                                }
                                if (!v14.isNull()) {
                                     console.log(`  [HOOK ON_LEAVE] *(v14 + 0x10) would be read from: ${v14.add(0x10)}`);
                                }
                            }
                        }
                    }
                } catch (e) {
                    console.log(`  [HOOK ON_LEAVE] Error during gEnv chain: ${e.message}`);
                }
            }
            console.log("======================================================");
        }
    });
    console.log("[DEBUG] Interceptor for sub_1412A8110 attached.");

    console.log("[DEBUG] Creating NativeFunction for fnPrepareTeleportParams...");
    const fnPrepareTeleportParams = new NativeFunction(
        fnSub1412A8110Address, // Use the address directly
        'pointer',
        ['pointer', 'uint64', 'pointer', 'pointer', 'pointer', 'uint8', 'int32', 'int32', 'uint8'],
        'win64'
    );
    console.log("[DEBUG] fnPrepareTeleportParams NativeFunction created successfully");

    console.log("[DEBUG] Creating NativeFunction for fnExecuteTeleport...");
    const fnExecuteTeleport = new NativeFunction(
        baseAddress.add(OFFSET_SUB_145A8DC50),
        'uint64',
        ['pointer', 'pointer'],
        'win64'
    );
    console.log("[DEBUG] fnExecuteTeleport NativeFunction created successfully");

    const actorActionHandlerInstancePtr = baseAddress.add(OFFSET_ACTOR_ACTION_HANDLER_INSTANCE);
    console.log(`[DEBUG] Reading ActorActionHandler pointer from: ${actorActionHandlerInstancePtr}`);
    const actorActionHandler = actorActionHandlerInstancePtr.readPointer();
    console.log(`[+] ActorActionHandler instance at: ${actorActionHandler}`);
    console.log(`[DEBUG] ActorActionHandler is null: ${actorActionHandler.isNull()}`);

    console.log("[DEBUG] === Memory Allocation Phase ===");
    console.log("[DEBUG] Allocating 0x100 bytes for teleportParamsPtr...");
    const teleportParamsPtr = Memory.alloc(0x100);
    console.log(`[DEBUG] teleportParamsPtr allocated at: ${teleportParamsPtr}`);
    teleportParamsPtr.writeByteArray(new Array(0x100).fill(0));
    console.log("[DEBUG] teleportParamsPtr zeroed out");

    console.log("[DEBUG] Allocating 0x50 bytes for sourceTransformPtr...");
    const sourceTransformPtr = Memory.alloc(0x50);
    console.log(`[DEBUG] sourceTransformPtr allocated at: ${sourceTransformPtr}`);
    sourceTransformPtr.writeByteArray(new Array(0x50).fill(0));
    console.log("[DEBUG] sourceTransformPtr zeroed out");
    console.log("[DEBUG] Writing initial transform values...");
    sourceTransformPtr.add(0x00).writeDouble(0.0);
    sourceTransformPtr.add(0x08).writeDouble(0.0);
    sourceTransformPtr.add(0x10).writeDouble(0.0);
    console.log("[DEBUG] Initial position written: (0.0, 0.0, 0.0)");
    sourceTransformPtr.add(0x30).writeDouble(1.0);
    console.log("[DEBUG] Final sourceTransformPtr setup complete");

    console.log("[DEBUG] Allocating 16 bytes for a4FlagsPtr...");
    const a4FlagsPtr = Memory.alloc(16);
    console.log(`[DEBUG] a4FlagsPtr allocated at: ${a4FlagsPtr}`);
    a4FlagsPtr.writeInt(0);
    console.log("[DEBUG] a4FlagsPtr initialized with value 0");

    console.log("[DEBUG] Setting up remaining parameters...");
    const zoneIdPtr = Memory.alloc(16);
    // MODIFICATION HERE: Use new UInt64(0) for writing a 64-bit zero
    zoneIdPtr.writeU64(new UInt64(0)); // Write a 64-bit zero
    zoneIdPtr.add(8).writeU32(0);
    console.log(`[DEBUG] zoneIdPtr allocated at: ${zoneIdPtr} and initialized with dummy values (0, 0)`);

    const charFlagA6 = 0;
    const intFlagA7 = 0;
    const intFlagA8 = 0;
    const charFlagA9 = 0;
    console.log(`[DEBUG] zoneIdPtr (a5): ${zoneIdPtr}`);
    console.log(`[DEBUG] charFlagA6: ${charFlagA6}`);
    console.log(`[DEBUG] intFlagA7: ${intFlagA7}`);
    console.log(`[DEBUG] intFlagA8: ${intFlagA8}`);
    console.log(`[DEBUG] charFlagA9: ${charFlagA9}`);

    console.log("[DEBUG] === Function Call Phase ===");
    console.log(`[+] Calling fnPrepareTeleportParams(${teleportParamsPtr}, ${new UInt64(ENTITY_ID_TO_TELEPORT)}, ${sourceTransformPtr}, ...)`);
    console.log(`[DEBUG] Parameters breakdown:`);
    console.log(`[DEBUG]   a1 (teleportParamsPtr): ${teleportParamsPtr}`);
    console.log(`[DEBUG]   a2 (entityId): ${ENTITY_ID_TO_TELEPORT}`);
    console.log(`[DEBUG]   a3 (sourceTransformPtr): ${sourceTransformPtr}`);
    console.log(`[DEBUG]   a4 (a4FlagsPtr): ${a4FlagsPtr}`);
    console.log(`[DEBUG]   a5 (zoneIdPtr): ${zoneIdPtr}`);
    console.log(`[DEBUG]   a6-a9 (flags): ${charFlagA6}, ${intFlagA7}, ${intFlagA8}, ${charFlagA9}`);

    try {
        const prepResult = fnPrepareTeleportParams(
            teleportParamsPtr,
            new UInt64(ENTITY_ID_TO_TELEPORT),
            sourceTransformPtr,
            a4FlagsPtr,
            zoneIdPtr,
            charFlagA6,
            intFlagA7,
            intFlagA8,
            charFlagA9
        );
        console.log("[+] fnPrepareTeleportParams called successfully.");
        console.log(`[DEBUG] fnPrepareTeleportParams return value: ${prepResult}`);
    } catch (e) {
        console.error(`[ERROR] Exception during fnPrepareTeleportParams: ${e.message}`);
        console.error(`[ERROR] Stack: ${e.stack}`);
        return;
    }

    console.log("[DEBUG] Reading prepared parameters from teleportParamsPtr...");
    try {
        const preparedEntityId = teleportParamsPtr.readU64();
        const preparedPosX = teleportParamsPtr.add(0x08).readDouble();
        const preparedPosY = teleportParamsPtr.add(0x10).readDouble();
        const preparedPosZ = teleportParamsPtr.add(0x18).readDouble();
        console.log(`[DEBUG] Prepared EntityID: ${preparedEntityId}`);
        console.log(`[DEBUG] Prepared Pos X: ${preparedPosX}`);
        console.log(`[DEBUG] Prepared Pos Y: ${preparedPosY}`);
        console.log(`[DEBUG] Prepared Pos Z: ${preparedPosZ}`);
    } catch (e) {
        console.error(`[ERROR] Failed to read prepared parameters: ${e.message}`);
    }

    console.log("[DEBUG] === Position Override Phase ===");
    console.log(`[DEBUG] Overwriting position with target coordinates...`);
    try {
        teleportParamsPtr.add(0x08).writeDouble(TARGET_X);
        console.log(`[DEBUG] Wrote TARGET_X (${TARGET_X}) to offset 0x08`);
        teleportParamsPtr.add(0x10).writeDouble(TARGET_Y);
        console.log(`[DEBUG] Wrote TARGET_Y (${TARGET_Y}) to offset 0x10`);
        teleportParamsPtr.add(0x18).writeDouble(TARGET_Z);
        console.log(`[DEBUG] Wrote TARGET_Z (${TARGET_Z}) to offset 0x18`);
        console.log(`[+] Overwrote position in params to: X=${TARGET_X}, Y=${TARGET_Y}, Z=${TARGET_Z}`);

        const verifyX = teleportParamsPtr.add(0x08).readDouble();
        const verifyY = teleportParamsPtr.add(0x10).readDouble();
        const verifyZ = teleportParamsPtr.add(0x18).readDouble();
        console.log(`[DEBUG] Verification - Read back position: X=${verifyX}, Y=${verifyY}, Z=${verifyZ}`);
    } catch (e) {
        console.error(`[ERROR] Failed to overwrite position: ${e.message}`);
        return;
    }

    console.log("[DEBUG] === Teleport Execution Phase ===");
    console.log(`[+] Calling fnExecuteTeleport(${actorActionHandler}, ${teleportParamsPtr})`);
    console.log(`[DEBUG] fnExecuteTeleport parameters:`);
    console.log(`[DEBUG]   actorActionHandler: ${actorActionHandler}`);
    console.log(`[DEBUG]   teleportParamsPtr: ${teleportParamsPtr}`);

    try {
        const teleportResult = fnExecuteTeleport(actorActionHandler, teleportParamsPtr);
        console.log(`[+] fnExecuteTeleport called successfully, result: ${teleportResult}`);
        console.log(`[DEBUG] Result as hex: 0x${teleportResult.toString(16)}`);
        console.log(`[DEBUG] Result is zero: ${teleportResult == 0}`);
    } catch (e) {
        console.error(`[ERROR] Exception during fnExecuteTeleport: ${e.message}`);
        console.error(`[ERROR] Stack: ${e.stack}`);
        return;
    }

    console.log("[DEBUG] === Cleanup Phase ===");
    console.log("[DEBUG] Memory cleanup will be handled by Frida's garbage collector");
    console.log("[DEBUG] === teleportEntity function completed ===");
}

rpc.exports = {
    teleport: teleportEntity
};
