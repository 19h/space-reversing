/*
 * kill_entity.js (v3)
 *
 * Frida script to instantly kill a target entity in Star Citizen.
 *
 * This version corrects the HitInfo struct to use the entity's own ID as the
 * weapon ID, preventing a NULL pointer dereference inside the game's damage
 * processing logic.
 */

"use strict";

// =============================================================================
// SECTION 1: CORE ENTITY SYSTEM CLASSES (UNCHANGED)
// =============================================================================

const PTR_SIZE = Process.pointerSize;

function extractLower48(ptrVal) {
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
}

function callVFunc(thisPtr, index, returnType, argTypes, args = [], name = null) {
    try {
        if (thisPtr.isNull()) throw new Error("Null pointer passed to callVFunc");
        const vtable = thisPtr.readPointer();
        if (vtable.isNull()) throw new Error("Null vtable pointer");
        const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
        if (fnPtr.isNull()) throw new Error(`Null function pointer at vtable index ${index}`);
        const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
        return fn(thisPtr, ...args);
    } catch (e) {
        console.log(`callVFunc error at index ${index}${name ? ` (${name})` : ''}: ${e.message}`);
        throw e;
    }
}

class CEntityClass {
    constructor(ptr) { this.ptr = ptr; }
    get name() {
        const namePtr = this.ptr.add(0x10).readPointer();
        return readCString(namePtr);
    }
}

class CEngineComponentScheduler {
    constructor(ptr) { this.ptr = ptr; }
    getComponentIdByName(componentName) {
        try {
            const componentIdPtr = Memory.alloc(2);
            const componentNamePtr = Memory.allocUtf8String(componentName);
            const result = callVFunc(this.ptr, 2, "pointer", ["pointer", "pointer"], [componentIdPtr, componentNamePtr], 'getComponentIdByName');
            const componentId = componentIdPtr.readU16();
            return { success: !result.isNull(), componentId: componentId };
        } catch (e) {
            console.log(`[!] Error in getComponentIdByName: ${e.message}`);
            return { success: false, componentId: 0 };
        }
    }
}

class CEntity {
    constructor(ptr) { this.ptr = ptr; }
    get id() { return this.ptr.add(0x10).readU64(); }
    get entityClassPtr() {
        const raw = this.ptr.add(0x20).readPointer();
        return extractLower48(raw);
    }
    get entityClass() {
        const clsPtr = this.entityClassPtr;
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }
    getComponentAddrById(componentId) {
        try {
            const componentAddrPtr = Memory.alloc(PTR_SIZE);
            const componentIdPtr = Memory.alloc(2);
            componentIdPtr.writeU16(componentId);
            const result = callVFunc(this.ptr, 104, "pointer", ["pointer", "pointer"], [componentAddrPtr, componentIdPtr], 'getComponentAddrById');
            const componentAddr = componentAddrPtr.readPointer();
            return { success: !result.isNull(), componentPtr: componentAddr };
        } catch (e) {
            console.log(`[!] Error in getComponentAddrById: ${e.message}`);
            return { success: false, componentPtr: NULL };
        }
    }
    getComponentByName(componentName) {
        try {
            const scheduler = gEnv.engineComponentScheduler;
            if (!scheduler) {
                console.log("[!] Engine component scheduler not available");
                return null;
            }
            const idResult = scheduler.getComponentIdByName(componentName);
            if (!idResult.success || idResult.componentId === 0) {
                return null;
            }
            const componentResult = this.getComponentAddrById(idResult.componentId);
            if (!componentResult.success || componentResult.componentPtr.isNull()) {
                return null;
            }
            return componentResult.componentPtr;
        } catch (e) {
            console.log(`[!] Error in getComponentByName: ${e.message}`);
            return null;
        }
    }
}

class CEntityArray {
    constructor(ptr) { this.ptr = ptr; }
    get maxSize() { return this.ptr.readS64(); }
    get dataPtr() { return this.ptr.add(0x18).readPointer(); }
    at(i) {
        if (i < 0 || i >= this.maxSize) return null;
        const elementPtr = this.dataPtr.add(i * PTR_SIZE).readPointer();
        const realPtr = extractLower48(elementPtr);
        return realPtr.isNull() ? null : new CEntity(realPtr);
    }
    toArray() {
        const out = [];
        const size = this.maxSize;
        for (let i = 0; i < size; i++) {
            const e = this.at(i);
            if (e) out.push(e);
        }
        return out;
    }
}

class CEntitySystem {
    constructor(ptr) { this.ptr = ptr; }
    get entityArray() {
        const arrPtr = this.ptr.add(0x148);
        return new CEntityArray(arrPtr);
    }
}

class GEnv {
    constructor(ptr) { this.ptr = ptr; }
    get entitySystem() {
        const sysPtr = this.ptr.add(0x00a0).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }
    get engineComponentScheduler() {
        const ptr = this.ptr.add(0x00A8).readPointer();
        return ptr.isNull() ? null : new CEngineComponentScheduler(ptr);
    }
}

// =============================================================================
// SECTION 2: SCRIPT-SPECIFIC LOGIC
// =============================================================================

// Global environment pointer
const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x9B4FBE0");
const gEnv = new GEnv(GENV_ADDR);

// Address of the target function, CSCBodyHealthComponent::ProcessHit
const PROCESS_HIT_RVA = 0x6321C50;
const processHitFunc = new NativeFunction(
    Module.findBaseAddress('StarCitizen.exe').add(PROCESS_HIT_RVA),
    'void', // return type
    ['pointer', 'pointer'] // arg types: SCBodyHealthComponent* this, HitInfo* p_hit_info
);

console.log(`[*] Kill script initialized. CSCBodyHealthComponent::ProcessHit located at ${processHitFunc}`);

/**
 * Creates a fake HitInfo structure in memory with values designed to ensure a kill.
 * @param {UInt64} targetIdValue The 64-bit ID of the target entity.
 * @returns {NativePointer} A pointer to the allocated and populated HitInfo struct.
 */
 function createValidHitInfo(targetEntity, attackerEntity, weaponEntity) {
     const hitInfoPtr = Memory.alloc(0x110);

     // Complete zero initialization
     hitInfoPtr.writeByteArray(new Array(0x110).fill(0));

     // Primary entity IDs
     hitInfoPtr.add(0x00).writeU64(targetEntity.id);        // targetId
     hitInfoPtr.add(0x08).writeU64(attackerEntity.id);      // shooterId
     hitInfoPtr.add(0x10).writeU64(weaponEntity.id);        // weaponId

     // Damage parameters
     hitInfoPtr.add(0x18).writeFloat(999999.0);             // damage
     hitInfoPtr.add(0x1C).writeFloat(1.0);                  // damageMultiplier

     // Hit location parameters
     hitInfoPtr.add(0x44).writeFloat(0.0);                  // normalY
     hitInfoPtr.add(0x58).writeS32(0);                      // partId (0 = generic/torso)

     // Hit metadata
     hitInfoPtr.add(0x70).writeS32(0);                      // materialId
     hitInfoPtr.add(0x74).writeS32(10);                     // hitType: Bullet
     hitInfoPtr.add(0x78).writeS32(1);                      // damageType: Physical
     hitInfoPtr.add(0x7C).writeS32(0);                      // projectileClassId

     // Hit flags
     hitInfoPtr.add(0x80).writeU8(0);                       // isMelee: false
     hitInfoPtr.add(0xAA).writeU16(0x0001);                // hitFlags: valid hit

     // State flags
     hitInfoPtr.add(0xEA).writeU8(0);                       // flagEA
     hitInfoPtr.add(0xEB).writeU8(0);                       // flagEB
     hitInfoPtr.add(0xEC).writeU8(0);                       // flagEC: not recent driver
     hitInfoPtr.add(0xED).writeU8(0);                       // flagED: not split over parts

     // Killing blow indicator
     hitInfoPtr.add(0x108).writeU8(1);                      // isKillingBlow

     return hitInfoPtr;
}

function findValidWeaponEntity() {
    const entitySystem = gEnv.entitySystem;
    const entities = entitySystem.entityArray.toArray();

    for (const entity of entities) {
        const entityClass = entity.entityClass;
        if (!entityClass) continue;

        const className = entityClass.name;
        // Weapon class patterns based on Star Citizen conventions
        if (className.includes('Weapon') ||
            className.includes('Gun') ||
            className.includes('Rifle') ||
            className.includes('Pistol')) {
            return entity;
        }
    }

    return null;
}

function findPlayerEntity() {
    const entitySystem = gEnv.entitySystem;
    const entities = entitySystem.entityArray.toArray();

    for (const entity of entities) {
        const entityClass = entity.entityClass;
        if (!entityClass) continue;

        const className = entityClass.name;
        if (className.includes('Player') ||
            className.includes('LocalPlayer')) {
            return entity;
        }
    }

    return null;
}

/**
 * Kills an entity by its pointer.
 * @param {NativePointer | string} entityIdentifier The entity's memory pointer,
 * either as a NativePointer object (from REPL) or a string (from Python).
 */
function killEntity(entityIdentifier) {
    let entityPtr;

    if (typeof entityIdentifier === 'string') {
        console.log(`\n[+] Received request to kill entity with pointer string: ${entityIdentifier}`);
        entityPtr = ptr(entityIdentifier);
    } else if (typeof entityIdentifier === 'object' && entityIdentifier.add) {
        console.log(`\n[+] Received request to kill entity with pointer object: ${entityIdentifier}`);
        entityPtr = entityIdentifier;
    } else {
        const errorMsg = "Invalid argument. Please provide an entity pointer object or a pointer string.";
        console.error(`[ERROR] ${errorMsg}`);
        return { success: false, error: errorMsg };
    }

    try {
        const targetEntity = new CEntity(entityPtr);
        const targetId = targetEntity.id;
        console.log(`[*] Found entity ${targetEntity.ptr} (Class: ${targetEntity.entityClass.name}, ID: ${targetId.toString(16)})`);

        const healthComponentPtr = targetEntity.getComponentByName("SCBodyHealthComponent");
        if (!healthComponentPtr || healthComponentPtr.isNull()) {
            throw new Error("SCBodyHealthComponent not found on the entity. It may not be damageable.");
        }
        console.log(`[*] Found SCBodyHealthComponent at: ${healthComponentPtr}`);

        const fakeHitInfoPtr = createFakeHitInfo(targetId);
        console.log(`[*] Created fake HitInfo struct at: ${fakeHitInfoPtr}`);

        console.log(`[*] Calling ProcessHit(${healthComponentPtr}, ${fakeHitInfoPtr})...`);
        processHitFunc(healthComponentPtr, fakeHitInfoPtr);
        console.log(`[SUCCESS] ProcessHit called for entity ${entityPtr}. Target should be neutralized.`);

        return { success: true, message: `ProcessHit called for entity ${entityPtr}.` };

    } catch (e) {
        console.error(`[ERROR] Failed to kill entity ${entityPtr}: ${e.message}`);
        console.error(e.stack);
        return { success: false, error: e.message };
    }
}

// Export the main function for RPC
rpc.exports.killEntity = killEntity;

function killEntityDirect(targetEntityPtr) {
    const targetEntity = new CEntity(targetEntityPtr);
    const healthComponentPtr = targetEntity.getComponentByName("SCBodyHealthComponent");

    if (!healthComponentPtr || healthComponentPtr.isNull()) {
        throw new Error("No health component found");
    }

    // Based on decompiled analysis, health values likely stored at offsets:
    // Current health: component + 0x130 (float)
    // Max health: component + 0x134 (float)

    const currentHealthPtr = healthComponentPtr.add(0x130);
    const maxHealthPtr = healthComponentPtr.add(0x134);

    console.log(`[*] Current health: ${currentHealthPtr.readFloat()}`);
    console.log(`[*] Max health: ${maxHealthPtr.readFloat()}`);

    // Set health to zero
    currentHealthPtr.writeFloat(0.0);

    // Trigger death state update (may require additional flags)
    // This would need reverse engineering of the death state machine
}

rpc.exports.killEntityDirect = killEntityDirect;
