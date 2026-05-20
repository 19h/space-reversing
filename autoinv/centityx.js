//
// Frida script to mirror the game's C++ entity system in idiomatic JavaScript,
// providing rich, object-oriented wrappers around native memory structures.

"use strict";

const PTR_SIZE = Process.pointerSize;
const MODULE_BASE = Process.enumerateModules()[0].base;

function gameAddr(abs) {
    return MODULE_BASE.add(ptr(abs).sub(ptr('0x140000000')));
}

const GENV_ADDR = MODULE_BASE.add('0xA284E80');

function dumpSpawnParams(params) {
    if (!params || ptr(params).isNull()) {
        return null;
    }

    params = ptr(params);
    return {
        ptr: params.toString(),
        classPtr0x00: params.readPointer().toString(),
        parentId0x28: params.add(0x28).readU64().toString(),
        parentAttachId0x30: params.add(0x30).readU32(),
        entityId0x38: params.add(0x38).readU64().toString(),
        quatW0x58: params.add(0x58).readDouble(),
        posX0x60: params.add(0x60).readDouble(),
        posY0x68: params.add(0x68).readDouble(),
        posZ0x70: params.add(0x70).readDouble(),
        scale0x78: params.add(0x78).readDouble(),
        transformKind0x80: params.add(0x80).readU32(),
        context0x88: params.add(0x88).readPointer().toString(),
        flags0xB0: params.add(0xB0).readU32(),
        qword0x138: params.add(0x138).readPointer().toString(),
        qword0x148: params.add(0x148).readPointer().toString()
    };
}

function readHex(ptrValue, size) {
    const bytes = ptr(ptrValue).readByteArray(size);
    return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function cloneNativeContext(bytes) {
    if (!bytes || bytes.length === 0) {
        return NULL;
    }

    const copy = Memory.alloc(bytes.length);
    copy.writeByteArray(bytes);
    return copy;
}

function cloneNativeCallbackRecord(bytes) {
    if (!bytes || bytes.length === 0) {
        return NULL;
    }

    const copy = Memory.alloc(bytes.length);
    copy.writeByteArray(bytes);
    return copy;
}

function writeBytes(dst, bytes) {
    ptr(dst).writeByteArray(bytes);
}

function spawnBacktrace(context, limit = 12) {
    if (!globalThis.__spawnDebugBacktrace) {
        return undefined;
    }

    try {
        return Thread.backtrace(context, Backtracer.ACCURATE)
            .slice(0, limit)
            .map(addr => {
                const sym = DebugSymbol.fromAddress(addr);
                return `${addr} ${sym.moduleName || ''}!${sym.name || ''}`;
            });
    } catch (e) {
        return [`backtrace failed: ${e.message}`];
    }
}

function isLikelyPointerString(value) {
    try {
        return BigInt(value) > 0x10000n;
    } catch (_) {
        return false;
    }
}

// Helper to extract lower 48 bits of a pointer
function extractLower48(ptrVal) {
    // Mask with 0xFFFFFFFFFFFF
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

// Helper to read a C-style UTF-8 string pointer
function readCString(ptr) {
    try {
        return ptr.isNull() ? null : ptr.readUtf8String();
    } catch (e) {
        try {
            return ptr.readString();
        } catch (e) {}
    }

    return null;
}

function readCryString(objPtr) {
    try {
        const dataPtr = ptr(objPtr).readPointer();
        return readCString(extractLower48(dataPtr));
    } catch (_) {
        return null;
    }
}

// Helper to call a virtual method by vtable index
function callVFunc(thisPtr, index, returnType, argTypes, args = [], name = null) {
    try {
        if (thisPtr.isNull()) {
            throw new Error("Null pointer passed to callVFunc");
        }

        const vtable = thisPtr.readPointer();
        if (vtable.isNull()) {
            throw new Error("Null vtable pointer");
        }

        const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
        if (fnPtr.isNull()) {
            throw new Error(`Null function pointer at vtable index ${index}`);
        }

        // console.log(`Calling ${fnPtr} (${name}) at index ${index} with args ${args.join(', ')}`); // Verbose logging

        const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
        // console.log(fnPtr, name); // Uncomment for debugging vfunc calls
        return fn(thisPtr, ...args);
    } catch (e) {
        console.log(`callVFunc error at index ${index}${name ? ` (${name})` : ''}: ${e.message}`);
        console.log(e.stack);
        throw e;
    }
}

// Vector3 struct
class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
}

// Wrapper for IEntityClass (vtable size: 0x90)
class CEntityClass {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 6: GetFlags
    get flags() {
        return callVFunc(this.ptr, 6, "uint32", [], [], 'IEntityClass::GetFlags');
    }

    // vfunc 3: GetName
    get name() {
        const namePtr = callVFunc(this.ptr, 3, "pointer", [], [], 'IEntityClass::GetName');
        return readCString(namePtr);
    }

    release() {
        throw new Error('IEntityClass::Release is destructive and is intentionally not exposed');
    }
}

// Wrapper for CZone
class CZone {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vtable slot 0: Scalar deleting destructor
    destroy() {
        throw new Error('IZone destructor is intentionally not exposed');
    }

    // vtable slot 1: GetParent
    parent() {
        const nextPtr = callVFunc(this.ptr, 1, "pointer", []);
        return nextPtr.isNull() ? null : new CZone(extractLower48(nextPtr));
    }

    // vtable slot 33: ConvertWorldSpaceToZoneSpace(Vec3)
    getRelativePosition(camPosVec) {
        const outRel = Memory.alloc(24); // 3 doubles (24 bytes)

        // Create a native array from the camera position vector
        const nativeCamPos = Memory.alloc(24);
        nativeCamPos.writeDouble(camPosVec[0]);
        nativeCamPos.add(8).writeDouble(camPosVec[1]);
        nativeCamPos.add(16).writeDouble(camPosVec[2]);

        callVFunc(this.ptr, 33, "pointer", ["pointer", "pointer"], [outRel, nativeCamPos], 'ConvertWorldSpaceToZoneSpace(Vec3)');

        return {
            x: outRel.readDouble(),
            y: outRel.add(8).readDouble(),
            z: outRel.add(16).readDouble()
        };
    }

    // vtable slot 64: GetName
    getName() {
        const namePtr = callVFunc(this.ptr, 64, "pointer", [], [], 'IZone::GetName');
        return readCString(namePtr);
    }

    get name() {
        return this.getName();
    }
}

// Wrapper for CPhysicalWorld
class CPhysicalWorld {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 21: IPhysicalWorld::GetUniverseGrid
    getUniverseGrid() {
        return callVFunc(this.ptr, 21, "pointer", [], [], 'IPhysicalWorld::GetUniverseGrid');
    }

    // vfunc 136: IPhysicalWorld::GetRelativeTransform
    // Signature: QuatT<double>* GetRelativeTransform(result, fromGrid, toGrid, scale, lockFlag)
    getRelativeTransform(fromGrid = null, toGrid = null, scale = 0x3F800000, lockFlag = false) {
        try {
            // Allocate output buffer for 7 doubles (transform result)
            const resultPtr = Memory.alloc(7 * 8);

            // Use the interface-provided universe grid if a grid is not specified.
            const universeGrid = (!fromGrid || !toGrid) ? this.getUniverseGrid() : NULL;
            const fromGridPtr = fromGrid ? ptr(fromGrid) : universeGrid;
            const toGridPtr = toGrid ? ptr(toGrid) : universeGrid;

            // vfunc 136: IPhysicalWorld::GetRelativeTransform
            callVFunc(
                this.ptr,
                136,
                "pointer",
                ["pointer", "pointer", "pointer", "float", "bool"],
                [resultPtr, fromGridPtr, toGridPtr, scale, lockFlag ? 1 : 0],
                'IPhysicalWorld::GetRelativeTransform'
            );

            // Read the 7-element transform result
            return {
                quat: {
                    x: resultPtr.readDouble(),
                    y: resultPtr.add(8).readDouble(),
                    z: resultPtr.add(16).readDouble(),
                    w: resultPtr.add(24).readDouble()
                },
                translation: {
                    x: resultPtr.add(0x20).readDouble(),
                    y: resultPtr.add(0x28).readDouble(),
                    z: resultPtr.add(0x30).readDouble()
                }
            };
        } catch (e) {
            console.log(`[!] Error in getRelativeTransform: ${e.message}`);
            return {
                quat: { x: 0, y: 0, z: 0, w: 1 },
                translation: { x: 0, y: 0, z: 0 }
            };
        }
    }

    // vfunc 137: IPhysicalWorld::GetRelativeVelocityTransform.
    // The interface takes Vec3<double> values by value, so this wrapper is disabled until
    // its ABI shape is modeled explicitly.
    getRelativeVelocityTransform(fromGrid = null, fromVel = null, toGrid = null, toVel = null, lockFlag = false) {
        throw new Error('IPhysicalWorld::GetRelativeVelocityTransform has by-value Vec3 arguments and is not safely wrapped');
    }
}

// Wrapper for CPhysicalEntity (CPhysicalPlaceholder base size 0x140, CPhysicalEntity size 0x400)
class CPhysicalEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    get owningEntity() {
        const owningEntityPtr = extractLower48(this.ptr.add(0x0C0).readPointer());
        return owningEntityPtr.isNull() ? null : new CEntity(owningEntityPtr);
    }

    // m_lockUpdate at offset 0xC8
    get lockUpdate() {
        return this.ptr.add(0xC8).readS64();
    }

    // CPhysicalPlaceholder::m_debugName at 0xE8
    get name() {
        const namePtr = this.ptr.add(0x0E8).readPointer();
        return readCString(namePtr);
    }

    // CPhysicalPlaceholder::m_id at 0x108
    get physicalId() {
        return this.ptr.add(0x108).readS32();
    }

    // m_pWorld at offset 0x2C0
    get world() {
        const worldPtr = this.ptr.add(0x2C0).readPointer();
        return worldPtr.isNull() ? null : new CPhysicalWorld(worldPtr);
    }

    // CPhysicalEntity::m_pos/m_qrot/m_scale at 0x1C0/0x1D8/0x200.
    // This avoids a concrete-only vtable call that is not present on IPhysicalEntity.
    getWorldTransform() {
        try {
            return {
                quat: {
                    x: this.ptr.add(0x1D8).readFloat(),
                    y: this.ptr.add(0x1DC).readFloat(),
                    z: this.ptr.add(0x1E0).readFloat(),
                    w: this.ptr.add(0x1E4).readFloat()
                },
                translation: {
                    x: this.ptr.add(0x1C0).readDouble(),
                    y: this.ptr.add(0x1C8).readDouble(),
                    z: this.ptr.add(0x1D0).readDouble()
                },
                scale: this.ptr.add(0x200).readFloat()
            };
        } catch (e) {
            console.log(`[!] Error in getWorldTransform: ${e.message}`);
            return {
                quat: { x: 0, y: 0, z: 0, w: 1 },
                translation: { x: 0, y: 0, z: 0 }
            };
        }
    }

    // vfunc 45: IPhysicalEntity::ExportToObj_3(const char*, uint64)
    writeToObjFile(fileName) {
        try {
            const fileNamePtr = Memory.allocUtf8String(fileName);
            callVFunc(
                this.ptr,
                45,
                "void",
                ["pointer", "uint64"],
                [fileNamePtr, uint64(0)],
                'IPhysicalEntity::ExportToObj_3'
            );
            return 1;
        } catch (e) {
            console.log(`[!] Error in writeToObjFile: ${e.message}`);
            return 0;
        }
    }

    // Virtual slot 18: GetEntityId
    getEntityId() {
        try {
            // Allocate memory for output entity ID (8 bytes)
            const entityIdPtr = Memory.alloc(8);
            entityIdPtr.writeU64(0);

            // Call virtual function at vtable slot 18 (offset 144)
            const result = callVFunc(
                this.ptr,
                18,
                "pointer",
                ["pointer"],
                [entityIdPtr],
                'IPhysicalEntity::GetForeignEntityId'
            );

            // Read the entity ID from output parameter
            const entityId = entityIdPtr.readU64();

            return {
                success: !result.isNull(),
                entityId: entityId,
                resultPtr: result
            };
        } catch (e) {
            console.log(`[!] Error in getEntityId: ${e.message}`);
            return {
                success: false,
                entityId: 0,
                resultPtr: NULL
            };
        }
    }
}

// Wrapper for CRigidEntity (inherits from CPhysicalEntity)
class CRigidEntity extends CPhysicalEntity {
    constructor(ptr) {
        super(ptr);
    }

    // CRigidEntity::m_body.pos at 0x5F0 + 0x78
    get position() {
        const x = this.ptr.add(0x668).readDouble();
        const y = this.ptr.add(0x670).readDouble();
        const z = this.ptr.add(0x678).readDouble();
        return new DVec3(x, y, z);
    }

    get posX() {
        return this.ptr.add(0x668).readDouble();
    }

    get posY() {
        return this.ptr.add(0x670).readDouble();
    }

    get posZ() {
        return this.ptr.add(0x678).readDouble();
    }

    // CRigidEntity::m_posNew at 0x400
    get newPosition() {
        return new DVec3(
            this.ptr.add(0x400).readDouble(),
            this.ptr.add(0x408).readDouble(),
            this.ptr.add(0x410).readDouble()
        );
    }

    // CRigidEntity::m_body.M at 0x5F0 + 0x100
    get mass() {
        return this.ptr.add(0x6F0).readDouble();
    }

    // CRigidEntity::m_body.v at 0x5F0 + 0xDC
    get velocity() {
        const x = this.ptr.add(0x6CC).readFloat();
        const y = this.ptr.add(0x6D0).readFloat();
        const z = this.ptr.add(0x6D4).readFloat();
        return new DVec3(x, y, z);
    }

    get velX() {
        return this.ptr.add(0x6CC).readFloat();
    }

    get velY() {
        return this.ptr.add(0x6D0).readFloat();
    }

    get velZ() {
        return this.ptr.add(0x6D4).readFloat();
    }

    // Network state members from CRigidEntity.
    get netState() {
        const netStatePtr = this.ptr.add(0x970).readPointer();
        return netStatePtr.isNull() ? null : netStatePtr;
    }

    get netDesiredStateLock() {
        return this.ptr.add(0x978);
    }

    get shouldSnap() {
        return this.ptr.add(0x9EC).readU8() !== 0;
    }

    get hasNetworkAuthority() {
        return this.ptr.add(0x9ED).readU8() !== 0;
    }

    get isPhysicsSyncDisabled() {
        return this.ptr.add(0x9EE).readU8() !== 0;
    }

    // Setters for velocity components
    setVelX(value) {
        throw new Error('CRigidEntity velocity writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setVelY(value) {
        throw new Error('CRigidEntity velocity writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setVelZ(value) {
        throw new Error('CRigidEntity velocity writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setVelocity(x, y, z) {
        this.setVelX(x);
        this.setVelY(y);
        this.setVelZ(z);
    }

    // Setters for position components
    setPosX(value) {
        throw new Error('CRigidEntity position writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setPosY(value) {
        throw new Error('CRigidEntity position writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setPosZ(value) {
        throw new Error('CRigidEntity position writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setPosition(x, y, z) {
        this.setPosX(x);
        this.setPosY(y);
        this.setPosZ(z);
    }

    // Setter for mass
    setMass(value) {
        throw new Error('CRigidEntity mass writes are direct field mutation; use a verified IPhysicalEntity interface method before enabling');
    }

    setNetworkAuthority(value) {
        callVFunc(this.ptr, 23, "void", ["bool"], [value ? 1 : 0], 'IPhysicalEntity::SetNetworkAuthority');
    }

    detach() {
        throw new Error('CRigidEntity.detach used stale network offsets and is intentionally disabled');
    }

    registerForRecompute() {
        throw new Error('CRigidEntity::registerForRecompute uses a direct native address and is not verified through an interface vtable');
    }
}

// Wrapper for CZoneSystem (size: 0x108)
class CZoneSystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vtable slot 0: Scalar deleting destructor
    destroy() {
        throw new Error('IZoneSystem destructor is intentionally not exposed');
    }

    // vtable slot 1: DataCore_PostInitialize
    destructor() {
        throw new Error('IZoneSystem::DataCore_PostInitialize is not a destructor and is intentionally not exposed here');
    }

    // vfunc 2: GetUniverseRootZone
    getUniverseRootZone() {
        const ptr = callVFunc(this.ptr, 2, "pointer", [], [], 'IZoneSystem::GetUniverseRootZone');
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // vfunc 13: GetZone(const SZoneHandle*)
    getZone(handlePtr) {
        if (handlePtr === undefined || handlePtr === null) {
            return this.getUniverseRootZone();
        }

        if (typeof handlePtr === 'number') {
            return this.getZoneById(handlePtr);
        }

        const zonePtr = callVFunc(this.ptr, 13, "pointer", ["pointer"], [ptr(handlePtr)], 'IZoneSystem::GetZone');
        return zonePtr.isNull() ? null : new CZone(extractLower48(zonePtr));
    }

    // vfunc 14: GetZone_2(ZoneID)
    getZoneById(zoneId) {
        const zonePtr = callVFunc(this.ptr, 14, "pointer", ["uint32"], [zoneId], 'IZoneSystem::GetZone_2');
        return zonePtr.isNull() ? null : new CZone(extractLower48(zonePtr));
    }
}

class CEntityComponentSystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Virtual slot 0: Scalar deleting destructor
    destroy() {
        throw new Error('IEntityComponentSystem destructor is intentionally not exposed');
    }

    // Virtual slot 1: FinalizeComponentRegistration
    destructor() {
        throw new Error('IEntityComponentSystem::FinalizeComponentRegistration is intentionally not exposed here');
    }

    // Virtual slot 2: GetComponentId
    // Signature: CIGInplaceTrie<EComponentTypeIndex>::SEntry* GetComponentId(SEntry* result, const char* component_name)
    getComponentIdByName(componentName) {
        try {
            const componentIdPtr = Memory.alloc(2);
            const componentNamePtr = Memory.allocUtf8String(componentName);

            const result = callVFunc(
                this.ptr,
                2,
                "pointer",
                ["pointer", "pointer"],
                [componentIdPtr, componentNamePtr],
                'getComponentIdByName'
            );

            const componentId = componentIdPtr.readU16();

            return {
                success: !result.isNull(),
                componentId: componentId,
                resultPtr: result
            };
        } catch (e) {
            console.log(`[!] Error in getComponentIdByName: ${e.message}`);
            return {
                success: false,
                componentId: 0,
                resultPtr: NULL
            };
        }
    }
}

// Backwards-compatible name used by older helpers in this script.
const CEngineComponentScheduler = CEntityComponentSystem;

class EntityComponent {
    constructor(ptr, componentName) {
        this.ptr = ptr;
        this.componentName = componentName;
    }

    // Common component functionality
    get owningEntity() {
        const entityPtr = extractLower48(this.ptr.add(0x08).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }
}

globalThis.entcomp = (ptr, componentName = 'Unknown') => new EntityComponent(ptr(ptr), componentName);

class CPhysicalProxy extends EntityComponent {
    constructor(ptr) {
        super(ptr, 'CPhysicalProxy');
    }

    // CPhysicalProxy::m_pPhysicalEntity at 0x350 (IPhysicalEntityPtr).
    get physicalEntity() {
        const physicalEntityPtr = extractLower48(this.ptr.add(0x350).readPointer());
        return physicalEntityPtr.isNull() ? null : new CPhysicalEntity(physicalEntityPtr);
    }

    // CPhysicalProxy::m_pCachedPhysicalEntity at 0x358.
    get cachedPhysicalEntity() {
        const physicalEntityPtr = extractLower48(this.ptr.add(0x358).readPointer());
        return physicalEntityPtr.isNull() ? null : new CPhysicalEntity(physicalEntityPtr);
    }
}

class IComponentRender {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Method to call the native AddGlowForSlot function
    addGlow(glowParams, glowStyle = 0, slotIndex = -1) {
        throw new Error('CRenderProxy::AddGlowForSlot direct native call is not verified through an interface vtable');
    }
}

// Wrapper for CSCBodyHealthComponent
class CHealthComponent {
    constructor(ptr) {
        this.ptr = ptr;
    }

    get isDead() {
        throw new Error('CSCBodyHealthComponent::isDead offset is unverified in current types.h');
    }

    get isIncapacitated() {
        throw new Error('CSCBodyHealthComponent::isIncapacitated offset is unverified in current types.h');
    }

    // CSCBodyHealthComponent::m_pActor at 0x248
    get parentActor() {
        const actorPtr = extractLower48(this.ptr.add(0x0248).readPointer());
        return actorPtr.isNull() ? null : new CActor(actorPtr);
    }
}

class CRenderProxy {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // CRenderProxy::m_slots at 0xB8
    get slotsBegin() {
        return this.ptr.add(0xB8).readPointer();
    }

    get slotsEnd() {
        return this.ptr.add(0xC0).readPointer();
    }

    get slotsCapacity() {
        return this.ptr.add(0xC8).readPointer();
    }

    get slotCount() {
        const begin = this.slotsBegin;
        const end = this.slotsEnd;
        if (begin.isNull() || end.isNull()) {
            return 0;
        }
        return end.sub(begin).toInt32() / PTR_SIZE;
    }

    get lastEmptySlotId() {
        return this.ptr.add(0xD0).readS32();
    }

    get renderHandlePtr() {
        throw new Error('CRenderProxy::renderHandlePtr offset is unverified in current types.h');
    }

    get renderHandle() {
        throw new Error('CRenderProxy::renderHandle offset is unverified in current types.h');
    }

    get componentRender() {
        throw new Error('CRenderProxy::componentRender subobject offset is unverified in current types.h');
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLOT ARRAY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// Packed handle format: (index/flags << 48-56) | pointer
// Sentinel values: 0xffffffffffffffff or 0xffffffff00000000

globalThis.SENTINEL_64 = uint64("0xffffffffffffffff");
globalThis.SENTINEL_32_HIGH = uint64("0xffffffff00000000");

globalThis.isSlotSentinel = (value) => {
    if (typeof value === 'object' && value.equals) {
        return value.equals(SENTINEL_64) ||
               value.and(SENTINEL_32_HIGH).equals(SENTINEL_32_HIGH);
    }
    return value === 0xffffffffffffffff || (value & 0xffffffff00000000) === 0xffffffff00000000;
};

globalThis.parsePackedHandle = (addr) => {
    const v = ptr(addr).readU64();

    // Check sentinels
    if (v.equals(SENTINEL_64)) {
        return { valid: false, reason: 'sentinel_0xFFFFFFFFFFFFFFFF', raw: v };
    }
    if (v.and(SENTINEL_32_HIGH).equals(SENTINEL_32_HIGH)) {
        return { valid: false, reason: 'sentinel_high32_0xFFFFFFFF', raw: v };
    }

    // Check for null
    if (v.equals(uint64(0))) {
        return { valid: false, reason: 'null', raw: v };
    }

    const lower48 = v.and(uint64("0x0000FFFFFFFFFFFF"));
    const highWord = v.shr(48).and(0xFFFF).toNumber();

    // Heuristic: valid heap pointer range
    const isLikelyPointer = lower48.compare(uint64("0x700000000000")) > 0 &&
                            lower48.compare(uint64("0x800000000000")) < 0;

    if (!isLikelyPointer) {
        return {
            valid: false,
            reason: 'not_in_heap_range',
            raw: v,
            lower48: lower48.toString(16),
            highWord: highWord
        };
    }

    return {
        valid: true,
        reason: 'valid_packed_ptr',
        index: highWord,
        pointer: ptr(lower48),
        raw: v
    };
};

// Legacy discovery-only helper. This is not a verified CEntity substructure.
// Old observed pattern at 0x378+:
//   +0x00: sentinel or flags (0xffffffffffffffff or 0x2000000000000000)
//   +0x08: sentinel (-1) or null
//   +0x10: null or small value
//   +0x18: sentinel (0xffffffff)
//   +0x20: packed handle or null
//   +0x28: packed handle or null

class EntitySlot {
    constructor(ptr) {
        this.ptr = ptr;
    }

    get sentinel1() { return this.ptr.readU64(); }
    get field_08() { return this.ptr.add(0x08).readU64(); }
    get field_10() { return this.ptr.add(0x10).readU64(); }
    get flags() { return this.ptr.add(0x18).readU32(); }
    get handle1() { return parsePackedHandle(this.ptr.add(0x20)); }
    get handle2() { return parsePackedHandle(this.ptr.add(0x28)); }

    get isValid() {
        const h1 = this.handle1;
        const h2 = this.handle2;
        return h1.valid || h2.valid;
    }

    get entities() {
        const result = [];
        const h1 = this.handle1;
        const h2 = this.handle2;
        if (h1.valid && !h1.pointer.isNull()) result.push(h1);
        if (h2.valid && !h2.pointer.isNull()) result.push(h2);
        return result;
    }

    toString() {
        const h1 = this.handle1;
        const h2 = this.handle2;
        return `Slot[h1=${h1.valid ? h1.pointer : 'invalid'}, h2=${h2.valid ? h2.pointer : 'invalid'}]`;
    }
}

// Legacy discovery-only helper. This is not a verified CEntity substructure.
// Old smaller slot pattern seen at 0x770+ (0x30 bytes each).
class ResourceSlot {
    constructor(ptr) {
        this.ptr = ptr;
    }

    static SIZE = 0x38;

    get scale() { return this.ptr.readFloat(); }
    get field_04() { return this.ptr.add(0x04).readFloat(); }
    get resourcePtr() { return this.ptr.add(0x08).readPointer(); }

    // std::vector at 0x18
    get vectorBegin() { return this.ptr.add(0x18).readPointer(); }
    get vectorEnd() { return this.ptr.add(0x20).readPointer(); }
    get vectorCapacity() { return this.ptr.add(0x28).readPointer(); }

    get vectorSize() {
        const begin = this.vectorBegin;
        const end = this.vectorEnd;
        if (begin.isNull() || end.isNull()) return 0;
        return end.sub(begin).toInt32();
    }

    get count() { return this.ptr.add(0x30).readU32(); }
    get flags() { return this.ptr.add(0x34).readU32(); }

    get isValid() {
        return !this.resourcePtr.isNull() || this.vectorSize > 0;
    }

    toString() {
        return `ResourceSlot[res=${this.resourcePtr}, vecSize=${this.vectorSize}, count=${this.count}]`;
    }
}

// Legacy discovery-only helper. This is not a verified CEntity substructure.
class AssetTableEntry {
    constructor(ptr) {
        this.ptr = ptr;
    }

    static SIZE = 0x28;

    get typeInfo() { return this.ptr.readPointer(); }
    get flags() { return this.ptr.add(0x08).readU32(); }
    get stringTableBase() { return this.ptr.add(0x10).readPointer(); }
    get stringIndex() { return this.ptr.add(0x18).readU32(); }
    get dataPtr() { return this.ptr.add(0x20).readPointer(); }

    get isValid() {
        return !this.stringTableBase.isNull() && this.stringIndex !== 0;
    }

    toString() {
        return `Asset[idx=0x${this.stringIndex.toString(16)}, data=${this.dataPtr}]`;
    }
}

const bones = [
    ['root', 0],
    ['pelvis', 1],
    ['spine_01', 2],
    ['spine_02', 3],
    ['spine_03', 4],
    ['neck', 5],
    ['r_eye', 6],
    ['l_eye', 7],
    ['r_foot', 10],
    ['l_foot', 11],
    ['r_shoulder', 12],
    ['l_shoulder', 13],
    ['r_elbow', 14],
    ['left_elbow', 15],
    ['r_hand', 16],
    ['l_hand', 17],
    ['r_knee', 18],
    ['l_knee', 19],
    ['head', 20],
    ['r_hip', 21],
    ['l_hip', 22],
];

class CActor {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Get bone transform for a specific bone by ID
    getBoneTransform(boneId) {
        throw new Error('CActor::getBoneTransform uses a direct native address and is not verified through an interface vtable');
    }

    // Get all bone transforms
    getAllBoneTransforms() {
        const transforms = {};

        for (const [boneName, boneId] of bones) {
            transforms[boneName] = this.getBoneTransform(boneId);
        }

        return transforms;
    }

    // CActor::m_pHealthComponent at 0x550
    get healthComponent() {
        const compPtr = extractLower48(this.ptr.add(0x550).readPointer());
        return compPtr.isNull() ? null : new CHealthComponent(compPtr);
    }
}

// Wrapper for CEntity (size: 0x560)
class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // bitfield state flags at 0x08
    get flags() {
        return this.ptr.add(0x08).readU32();
    }

    // EEntityFlags at 0x128
    get entityFlags() {
        return this.ptr.add(0x0128).readU32();
    }

    // id_      at 0x10
    get id() {
        return this.ptr.add(0x10).readS64();
    }

    // entity_class_ at 0x20 (CEntityClass*)
    get entityClassPtr() {
        const raw = this.ptr.add(0x20).readPointer();
        return extractLower48(raw);
    }

    get entityClass() {
        const clsPtr = this.entityClassPtr;
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }

    // m_transformZoneSpace.t at 0x48
    get zonePos() {
        const x = this.ptr.add(0x0048).readDouble();
        const y = this.ptr.add(0x0050).readDouble();
        const z = this.ptr.add(0x0058).readDouble();
        return new DVec3(x, y, z);
    }

    // m_szName at 0x2A8 (CryStringT<char>)
    get name() {
        return readCryString(this.ptr.add(0x02A8));
    }

    // m_pZone at 0x2C0
    get zoneFromMemory() {
        const ptr = this.ptr.add(0x02C0).readPointer();
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // Preferred zone getter using virtual function
    get zone() {
        return this.getZone();
    }

    // Virtual slot 0 => Function0
    function0() {
        throw new Error('IEntity destructor is intentionally not exposed');
    }

    // vfunc 6: AddFlags(EEntityFlags, events*)
    addFlags(mask, events = NULL) {
        callVFunc(this.ptr, 6, "void", ["uint32", "pointer"], [mask, events], 'IEntity::AddFlags');
    }

    setFlagsOR(mask, events = NULL) {
        this.addFlags(mask, events);
    }

    // vfunc 7: ClearFlags(EEntityFlags, events*)
    clearFlags(mask, events = NULL) {
        callVFunc(this.ptr, 7, "void", ["uint32", "pointer"], [mask, events], 'IEntity::ClearFlags');
    }

    setFlagsORAlternative(mask, events = NULL) {
        this.clearFlags(mask, events);
    }

    // vfunc 108: IsHidden
    isHiddenOrDestroyed() {
        const hidden = callVFunc(this.ptr, 108, "bool", [], [], 'IEntity::IsHidden');
        const queuedForDestroy = (this.ptr.add(0x08).readU32() & (1 << 12)) !== 0;
        return hidden || queuedForDestroy;
    }

    // vfunc 46: GetChildCount
    getChildCount() {
        return callVFunc(this.ptr, 46, "int", [], [], 'IEntity::GetChildCount');
    }

    // vfunc 47: GetChild
    getChild(index) {
        const outChild = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 47, "pointer", ["pointer", "int"], [outChild, index], 'IEntity::GetChild');
        const childPtr = outChild.readPointer();
        const entityPtr = extractLower48(childPtr);
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    // vfunc 48: GetParent
    getParent() {
        const outParent = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 48, "pointer", ["pointer"], [outParent], 'IEntity::GetParent');
        const parentPtr = outParent.readPointer();
        const entityPtr = extractLower48(parentPtr);
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    // vfunc 86: GetZonePos(result, ECUSAccessType)
    getLocalPos(accessType = 0) {
        const outPos = Memory.alloc(24); // sizeof(Vec3)
        callVFunc(this.ptr, 86, "pointer", ["pointer", "uint32"], [outPos, accessType], 'IEntity::GetZonePos');
        const x = outPos.readDouble();
        const y = outPos.add(8).readDouble();
        const z = outPos.add(16).readDouble();
        return new DVec3(x, y, z);
    }

    get localPos() {
        return this.getLocalPos(0);
    }

    // vfunc 98: GetWorldPos_2(result, ECUSAccessType)
    getWorldPos(accessType = 0) {
        try {
            const outPos = Memory.alloc(24); // sizeof(Vec3)
            callVFunc(this.ptr, 98, "pointer", ["pointer", "uint32"], [outPos, accessType], 'IEntity::GetWorldPos_2');
            const x = outPos.readDouble();
            const y = outPos.add(8).readDouble();
            const z = outPos.add(16).readDouble();
            return new DVec3(x, y, z);
        } catch (e) {
            console.log(`getWorldPos failed: ${e.message}`);
            // Fallback to reading from memory offsets
            return this.zonePos;
        }
    }

    get worldPos() {
        return this.getWorldPos(0);
    }

    // Virtual slot 113: QueryComponent(TComponentPtr<IComponent>* result, component_id*)
    getComponentAddrById(componentId) {
        try {
            const componentAddrPtr = Memory.alloc(PTR_SIZE * 2);
            componentAddrPtr.writePointer(NULL);
            componentAddrPtr.add(PTR_SIZE).writePointer(NULL);

            const componentIdPtr = Memory.alloc(2);
            componentIdPtr.writeU16(componentId);

            const result = callVFunc(
                this.ptr,
                113,
                "pointer",
                ["pointer", "pointer"],
                [componentAddrPtr, componentIdPtr],
                'IEntity::QueryComponent'
            );

            const componentAddr = extractLower48(componentAddrPtr.readPointer());

            return {
                success: !result.isNull(),
                componentPtr: componentAddr,
                resultPtr: result
            };
        } catch (e) {
            console.log(`[!] Error in getComponentAddrById: ${e.message}`);
            return {
                success: false,
                componentPtr: NULL,
                resultPtr: NULL
            };
        }
    }

    // High-level convenience method for component retrieval by name
    getComponentByName(componentName) {
        try {
            // Access the engine component scheduler via GEnv
            const scheduler = gEnv.engineComponentScheduler;
            if (!scheduler) {
                console.log("[!] Engine component scheduler not available");
                return null;
            }

            // Resolve component name to ID
            const idResult = scheduler.getComponentIdByName(componentName);
            if (!idResult.success || idResult.componentId === 0xFFFF) {
                // console.log(`[!] Failed to resolve component name '${componentName}' to ID`);
                return null;
            }

            // console.log(`[*] Resolved component '${componentName}' to ID: 0x${idResult.componentId.toString(16)}`);

            // Retrieve component pointer using resolved ID
            const componentResult = this.getComponentAddrById(idResult.componentId);
            if (!componentResult.success || componentResult.componentPtr.isNull()) {
                // console.log(`[!] Failed to retrieve component with ID 0x${idResult.componentId.toString(16)}`);
                return null;
            }

            // console.log(`[*] Retrieved component '${componentName}' at address: ${componentResult.componentPtr}`);
            return extractLower48(componentResult.componentPtr);
        } catch (e) {
            console.log(`[!] Error in getComponentByName: ${e.message}`);
            return null;
        }
    }

    get renderProxy() {
        const ptr = this.getComponentByName("CRenderProxy");
        return !ptr || ptr.isNull() ? null : new CRenderProxy(ptr);
    }

    // CEntity::m_pPhysicalProxy at 0x500 (TComponentPtr<CPhysicalProxy>)
    get physicalProxy() {
        const ptr = extractLower48(this.ptr.add(0x500).readPointer());
        return ptr.isNull() ? null : new CPhysicalProxy(ptr);
    }

    // vfunc 215: GetZone
    getZone() {
        const ptr = callVFunc(this.ptr, 215, "pointer", [], [], 'IEntity::GetZone');
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // vfunc 219: GetHostedZone
    get hostedZone() {
        const ptr = callVFunc(this.ptr, 219, "pointer", [], [], 'IEntity::GetHostedZone');
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // vfunc 65: UpdateTransform(transform, ZoneSystem::ESpace, flags, ECUSAccessType, events*)
    updateTransform(transform, space = 2, flags = 0, accessType = 0, events = NULL) {
        return callVFunc(
            this.ptr,
            65,
            "int",
            ["pointer", "int", "int", "uint32", "pointer"],
            [transform, space, flags, accessType, events],
            'IEntity::UpdateTransform'
        );
    }

    setZoneTransform(transform, flags = 0, accessType = 0, events = NULL) {
        return this.updateTransform(transform, 2, flags, accessType, events);
    }

    setWorldTransform(transform, flags = 0, accessType = 0, events = NULL) {
        return this.updateTransform(transform, 0, flags, accessType, events);
    }

    setLocalTransform(targetZone, transform, flags = 0) {
        return this.moveToZone(targetZone, transform, true, NULL);
    }

    // vfunc 77: SetPos(Vec3*, flags, ZoneSystem::ESpace, ECUSAccessType)
    setPos(pos, space = 2, flags = 0, accessType = 0) {
        callVFunc(this.ptr, 77, "void", ["pointer", "int", "int", "uint32"], [pos, flags, space, accessType], 'IEntity::SetPos');
    }

    // vfunc 85: SetZonePos(Vec3*, flags, ECUSAccessType)
    setZonePos(pos, flags = 0, accessType = 0) {
        callVFunc(this.ptr, 85, "void", ["pointer", "int", "uint32"], [pos, flags, accessType], 'IEntity::SetZonePos');
    }

    // vfunc 96: SetWorldPos(Vec3*, flags, ECUSAccessType)
    setWorldPos(pos, flags = 0, accessType = 0) {
        callVFunc(this.ptr, 96, "void", ["pointer", "int", "uint32"], [pos, flags, accessType], 'IEntity::SetWorldPos');
    }

    // vfunc 222: MoveToZone(targetZone, QuatT*, updateAttached, events*)
    moveToZone(targetZone, transform, updateAttached = true, events = NULL) {
        callVFunc(this.ptr, 222, "void", ["pointer", "pointer", "bool", "pointer"], [targetZone, transform, updateAttached ? 1 : 0, events], 'IEntity::MoveToZone');
    }

    // Legacy discovery helpers below are intentionally disabled where they imply
    // named CEntity substructures not present in types.h.
    iterateEntitySlots(startOffset = 0x378, count = 20, slotSize = 0x38) {
        throw new Error('CEntity slot layout at 0x378 is not a verified structure in current types.h');
    }

    getValidEntitySlots(startOffset = 0x378, count = 20, slotSize = 0x38) {
        throw new Error('CEntity slot layout at 0x378 is not a verified structure in current types.h');
    }

    iterateResourceSlots(startOffset = 0x770, count = 10) {
        throw new Error('CEntity resource slot layout at 0x770 is not a verified structure in current types.h');
    }

    iterateAssetTable(startOffset = 0x918, count = 30) {
        throw new Error('CEntity asset table layout at 0x918 is not a verified structure in current types.h');
    }

    // Find all packed handles in a range
    findPackedHandles(startOffset = 0, endOffset = 0x1000, step = 8) {
        const handles = [];
        for (let off = startOffset; off < endOffset; off += step) {
            const handle = parsePackedHandle(this.ptr.add(off));
            if (handle.valid && handle.type === 'packed_ptr') {
                handles.push({
                    offset: off,
                    offsetHex: '0x' + off.toString(16),
                    handle: handle
                });
            }
        }
        return handles;
    }

    // Find all valid pointers in a range (useful for discovery)
    findPointers(startOffset = 0, endOffset = 0x1000, step = 8) {
        const pointers = [];
        const minHeap = uint64("0x700000000000");
        const maxHeap = uint64("0x800000000000");

        for (let off = startOffset; off < endOffset; off += step) {
            try {
                const val = this.ptr.add(off).readU64();
                // Check if looks like heap pointer
                if (val.compare(minHeap) > 0 && val.compare(maxHeap) < 0) {
                    pointers.push({
                        offset: off,
                        offsetHex: '0x' + off.toString(16),
                        pointer: ptr(val)
                    });
                }
            } catch (e) {}
        }
        return pointers;
    }

    // Find std::vector patterns (3 consecutive pointers in valid heap range)
    findVectors(startOffset = 0, endOffset = 0x1000) {
        const vectors = [];
        const minHeap = uint64("0x10000000");  // Lower bound for valid pointers

        for (let off = startOffset; off < endOffset - 24; off += 8) {
            try {
                const p1 = this.ptr.add(off).readPointer();
                const p2 = this.ptr.add(off + 8).readPointer();
                const p3 = this.ptr.add(off + 16).readPointer();

                // Check if looks like begin <= end <= capacity
                if (p1.isNull() && p2.isNull() && p3.isNull()) continue;

                // All three should be in similar memory region
                const v1 = p1.toString();
                const v2 = p2.toString();
                const v3 = p3.toString();

                // Heuristic: begin and end should be close, capacity >= end
                if (!p1.isNull() && !p2.isNull()) {
                    const size = p2.sub(p1).toInt32();
                    const cap = p3.sub(p1).toInt32();

                    // Reasonable vector: positive size, size <= capacity, not huge
                    if (size >= 0 && size <= cap && cap < 0x1000000 && cap > 0) {
                        vectors.push({
                            offset: off,
                            offsetHex: '0x' + off.toString(16),
                            begin: p1,
                            end: p2,
                            capacity: p3,
                            size: size,
                            capacityBytes: cap
                        });
                    }
                }
            } catch (e) {}
        }
        return vectors;
    }

    // Find 1.0f floats (often indicate scale or normalized values)
    findUnitFloats(startOffset = 0, endOffset = 0x1000) {
        const results = [];
        const ONE_F = 0x3f800000;
        const NEG_ONE_F = 0xbf800000;

        for (let off = startOffset; off < endOffset; off += 4) {
            try {
                const val = this.ptr.add(off).readU32();
                if (val === ONE_F || val === NEG_ONE_F) {
                    results.push({
                        offset: off,
                        offsetHex: '0x' + off.toString(16),
                        value: val === ONE_F ? 1.0 : -1.0
                    });
                }
            } catch (e) {}
        }
        return results;
    }

    // Scan for repeating structure patterns
    findRepeatingPattern(startOffset, patternSize, count, validator) {
        const matches = [];
        for (let i = 0; i < count; i++) {
            const offset = startOffset + i * patternSize;
            try {
                if (validator(this.ptr.add(offset))) {
                    matches.push({
                        index: i,
                        offset: offset,
                        offsetHex: '0x' + offset.toString(16)
                    });
                }
            } catch (e) {}
        }
        return matches;
    }

    // Improved slot dump
    dumpSlots() {
        throw new Error('CEntity::dumpSlots uses unverified legacy discovery offsets');
    }

    // Analyze the actual structure layout
    analyzeStructure() {
        throw new Error('CEntity::analyzeStructure uses unverified legacy discovery offsets');
    }

    getRealEntityReferences() {
        throw new Error('CEntity::getRealEntityReferences uses unverified legacy discovery offsets');
    }

    getLinkedEntities() {
        throw new Error('CEntity::getLinkedEntities uses unverified legacy discovery offsets');
    }

    get healthComponent() {
        let comp_ptr = ptr(0);
        try {
            comp_ptr = this.getComponentByName('SCBodyHealthComponent');
        } catch (e) {}
        return !comp_ptr || comp_ptr.isNull() ? null : new CHealthComponent(comp_ptr);
    }

    get containingEntity() {
        throw new Error('CEntity::containingEntity offset is unverified in current types.h');
    }

    get pilotingShip() {
        throw new Error('CEntity::pilotingShip offset is unverified in current types.h');
    }

    // CEntity::m_pECUSGroupParent at 0x4E8
    get ecusGroupParent() {
        const ptr = extractLower48(this.ptr.add(0x4E8).readPointer());
        return ptr.isNull() ? null : new CEntity(ptr);
    }

    // CEntity::m_pECUSGroupRoot at 0x4F0
    get ecusGroupRoot() {
        const ptr = extractLower48(this.ptr.add(0x4F0).readPointer());
        return ptr.isNull() ? null : new CEntity(ptr);
    }

    // CEntity::m_entityOwner[3] at 0x508
    get entityOwners() {
        const owners = [];
        for (let i = 0; i < 3; i++) {
            const ptr = extractLower48(this.ptr.add(0x508 + i * PTR_SIZE).readPointer());
            owners.push(ptr.isNull() ? null : new CEntity(ptr));
        }
        return owners;
    }

    get actor() {
        const actor = this.getComponentByName('Actor');
        return !actor || actor.isNull() ? null : new CActor(extractLower48(actor));
    }

    get actorEntity() {
        throw new Error('CEntity::actorEntity offset 0xFD8 is outside CEntity size 0x560 and is invalid');
    }

    get containingShip() {
        throw new Error('CEntity::containingShip offset is unverified; 0x4E8 is m_pECUSGroupParent');
    }
}

// Wrapper for CActorEntity (physical entity for player/NPC actors)
// VTable: 0x148338cc8
class CActorEntity extends CPhysicalEntity {
    constructor(ptr) {
        super(ptr);
    }

    // parentEntity at 0xc0 -> points back to the Player/NPC entity
    get parentEntity() {
        const ptr = extractLower48(this.ptr.add(0xc0).readPointer());
        return ptr.isNull() ? null : new CEntity(ptr);
    }

    // TODO: Find ship relationship pointers in CActorEntity
    // These may only be populated when player is in a ship
}

// Wrapper for CEntityLookup (CEntitySystem::m_entityLookup)
class CEntityArray {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // m_maxEntries at 0x00
    get maxSize() {
        return Number(this.ptr.readU64());
    }

    // m_numEntries at 0x08
    get currSize() {
        return Number(this.ptr.add(0x08).readU64());
    }

    // m_ppIEntities at 0x18
    get dataPtr() {
        return this.ptr.add(0x18).readPointer();
    }

    // Access element i as raw pointer (needs extractLower48)
    at(i) {
        if (i < 0 || i >= this.maxSize) return null;
        const elementPtr = this.dataPtr.add(i * PTR_SIZE).readPointer();
        const realPtr = extractLower48(elementPtr);
        return realPtr.isNull() ? null : new CEntity(realPtr);
    }

    // Iterate only the non-null entries
    toArray() {
        const out = [];
        for (let i = 0; i < this.maxSize; i++) {
            try {
                const e = this.at(i);
                if (e) out.push(e);
            } catch (_) {}
        }
        return out;
    }
}

// Wrapper for CEntityClassRegistry
class CEntityClassRegistry {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 4: IEntityClassRegistry::FindClass_3(const char*)
    findClass(name) {
        if (!name) {
            name = 'crlf_consumable_ea_medicateAll_01';
        }

        // allocate native CString
        const nameBuf = Memory.allocUtf8String(name);
        const clsPtr = callVFunc(
            this.ptr,
            4,
            "pointer",
            ["pointer"],
            [nameBuf],
            'IEntityClassRegistry::FindClass_3'
        );
        return clsPtr.isNull() ? null : new CEntityClass(extractLower48(clsPtr));
    }

    // vfunc 15: IEntityClassRegistry::GetClassCount
    getClassCount() {
        return callVFunc(this.ptr, 15, "int", [], [], 'IEntityClassRegistry::GetClassCount');
    }

    /**
     * Helper function to safely read a C-style string from a NativePointer.
     * Returns a placeholder string if the pointer is null or if reading fails.
     * @param {NativePointer} ptr Pointer to the C-string.
     * @returns {string} The read string or a placeholder.
     */
    readSafeCString(ptr) {
        if (!ptr || ptr.isNull()) {
            return "[Null String Pointer]";
        }
        try {
            const str = ptr.readCString();
            // readCString can return null if the string is empty or contains invalid sequences
            return str === null ? "[Null or Empty String Content]" : str;
        } catch (e) {
            return `[${ptr} - Read Error: ${e.message}]`;
        }
    }

    /**
     * Performs an in-order traversal of a Red-Black Tree (typically std::map's internal structure).
     * @param {NativePointer} nodePtr Current node being visited.
     * @param {NativePointer} headPtr Pointer to the map's head/sentinel node.
     * @param {function(string, NativePointer, NativePointer)} callback Called for each valid data-holding node with (className, classPtr, nodePtr).
     */
    traverseRBTree(nodePtr, headPtr, callback) {
        // Base case: current node is null, or it's the head/sentinel node itself.
        // The head node's _Isnil flag is true and it doesn't represent actual data.
        if (nodePtr.isNull() || nodePtr.equals(headPtr)) {
            return;
        }

        // Standard MSVC std::map node structure offsets (for PTR_SIZE=8, x64):
        // 0x00 (_Left):  Left child pointer
        // 0x08 (_Parent): Parent node pointer
        // 0x10 (_Right): Right child pointer
        // 0x18 (_Color): char/byte for RB tree color
        // 0x19 (_Isnil): bool/byte, true if head or NIL leaf
        // ---padding to align _Myval---
        // 0x20 (_Key): Key (e.g., const char*)
        // 0x28 (_Value): Value (e.g., CEntityClass* pointer)

        const isNilFlagOffset = (3 * PTR_SIZE) + 1; // Offset 0x19 for _Isnil flag
        const isNil = nodePtr.add(isNilFlagOffset).readU8();
        if (isNil !== 0) { // If _Isnil is true (typically 1), this node doesn't hold user data.
            return;
        }

        // Traverse left subtree
        const leftChildOffset = 0 * PTR_SIZE;
        const leftChild = nodePtr.add(leftChildOffset).readPointer();
        this.traverseRBTree(leftChild, headPtr, callback);

        // Process current node: extract key (class name) and value (class pointer)
        const keyFieldOffset = 4 * PTR_SIZE; // Offset 0x20 for _Key
        const classNameCharsPtr = nodePtr.add(keyFieldOffset).readPointer();
        const className = this.readSafeCString(classNameCharsPtr);

        const valueFieldOffset = 5 * PTR_SIZE; // Offset 0x28 for _Value
        const valueClassPtr = nodePtr.add(valueFieldOffset).readPointer();

        // Invoke the callback with the extracted information
        callback(className, valueClassPtr, nodePtr);

        // Traverse right subtree
        const rightChildOffset = 2 * PTR_SIZE;
        const rightChild = nodePtr.add(rightChildOffset).readPointer();
        this.traverseRBTree(rightChild, headPtr, callback);
    }

    // Function to get all registered classes from the registry
    getAllRegisteredClasses() {
        throw new Error('CEntityClassRegistry private class map offsets are not verified in current types.h');
    }

    // Function to print all registered classes
    dumpAllRegisteredClasses() {
        const classes = this.getAllRegisteredClasses();

        if (classes.length === 0) {
            console.log("No classes to dump.");
            return;
        }

        console.log("\nRegistered Entity Classes (Format: No. \"Name\": PointerToClass):");
        console.log("-----------------------------------------------------------------");

        classes.sort((a, b) => a.name.localeCompare(b.name)).forEach((classInfo, index) => {
            const classCount = index + 1;
            console.log(`${classCount.toString().padStart(3, ' ')}. "${classInfo.name}": ${classInfo.flags} @ ${classInfo.ptr}`);
        });

        console.log("-----------------------------------------------------------------");
        console.log(`Successfully dumped ${classes.length} classes.`);
    }
}

// Wrapper for CEntitySystem (size: 0x1410)
class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // m_entityLookup at offset 0x01A8
    get entityArray() {
        const arrPtr = this.ptr.add(0x01A8);
        return new CEntityArray(arrPtr);
    }

    // m_pClassRegistry at 0x0BE0
    get classRegistry() {
        const registry = this.getClassRegistryV();
        if (registry) {
            return registry;
        }

        const registryPtr = this.ptr.add(0x0BE0).readPointer();
        return registryPtr.isNull() ? null : new CEntityClassRegistry(registryPtr);
    }

    // Virtual slot 24 => GetClassRegistry(): CEntityClassRegistry*
    getClassRegistryV() {
        const ptr = callVFunc(this.ptr, 24, "pointer", []);
        return ptr.isNull() ? null : new CEntityClassRegistry(ptr);
    }

    // Convenience: find class by name via built-in registry
    getClassByName(name) {
        if (!name) {
            name = 'crlf_consumable_ea_medicateAll_01';
        }

        const registry = this.classRegistry;
        return registry ? registry.findClass(name) : null;
    }

    static get native() {
        throw new Error('CEntitySystem native spawn helpers use direct native addresses and are not verified through interface vtables');
    }

    buildSpawnTransform(position, rotation = null, scale = 1.0) {
        const transform = Memory.alloc(0x40);
        transform.writeByteArray(new Array(0x40).fill(0));

        // Quaternion x/y/z/w followed by double position x/y/z and double scale.
        transform.add(0x00).writeDouble(rotation?.x || 0.0);
        transform.add(0x08).writeDouble(rotation?.y || 0.0);
        transform.add(0x10).writeDouble(rotation?.z || 0.0);
        transform.add(0x18).writeDouble(rotation?.w === undefined ? 1.0 : rotation.w);
        transform.add(0x20).writeDouble(position.x);
        transform.add(0x28).writeDouble(position.y);
        transform.add(0x30).writeDouble(position.z);
        transform.add(0x38).writeDouble(scale);
        return transform;
    }

    createCreationBatch(callerName = 'centityx.js', batchKind = 0x14, flags = 0) {
        throw new Error('CEntitySystem::createCreationBatch is disabled pending interface-vtable verification');
    }

    createCreationCallback() {
        throw new Error('CEntitySystem::createCreationCallback is disabled pending interface-vtable verification');
    }

    createLocalSpawnBatch(callerName = 'centityx.js', callbackOrContext = NULL) {
        throw new Error('CEntitySystem::createLocalSpawnBatch is disabled pending interface-vtable verification');
    }

    spawnEntityBatch(className, options = {}) {
        throw new Error('CEntitySystem::spawnEntityBatch is disabled pending interface-vtable verification of all involved batch calls');
    }

    // Helper method to create and spawn an entity by class name
    createEntity(className, spawnParams = {}) {
        return { success: false, error: 'CEntitySystem::createEntity is disabled pending interface-vtable verification', className };
    }
}

class CRenderer {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vfunc 65: IRenderer::ProjectToScreen(x, y, z, outX, outY, outZ, camera)
    projectToScreen(pos, resolution = { x: 1920.0, y: 1080.0 }, camera = NULL) {
        // Allocate memory for output Vector3
        const outVec = Memory.alloc(4 * 3); // 3 floats (x, y, z)
        const outX = outVec;
        const outY = outVec.add(4);
        const outZ = outVec.add(8);

        const result = callVFunc(
            this.ptr,
            65,
            "bool",
            ["double", "double", "double", "pointer", "pointer", "pointer", "pointer"],
            [pos.x, pos.y, pos.z, outX, outY, outZ, camera],
            'IRenderer::ProjectToScreen'
        );

        if (result) {
            // Read output values
            const x = outX.readFloat() * (resolution.x);
            const y = outY.readFloat() * (resolution.y);
            const z = outZ.readFloat();

            // Return if z > 0 (in front of camera)
            if (z > 0.0) {
                return { x, y, z, success: true };
            }
        }

        return { x: 0, y: 0, z: 0, success: false };
    }
}

class CSystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Camera world position as Vector3
    get cameraWorldPos() {
        return new DVec3(
            this.ptr.add(0x40).readDouble(),
            this.ptr.add(0x60).readDouble(),
            this.ptr.add(0x80).readDouble()
        );
    }

    // Camera forward vector
    get cameraForward() {
        return new DVec3(
            this.ptr.add(0x30).readDouble(),
            this.ptr.add(0x50).readDouble(),
            this.ptr.add(0x70).readDouble()
        );
    }

    // Camera up vector
    get cameraUp() {
        return new DVec3(
            this.ptr.add(0x38).readDouble(),
            this.ptr.add(0x58).readDouble(),
            this.ptr.add(0x78).readDouble()
        );
    }

    // Internal FOV (X-axis)
    get internalXFOV() {
        return this.ptr.add(0x118).readFloat();
    }
}

// Wrapper for global environment GEnv / SSystemGlobalEnvironment (size: 0xA20)
class GEnv {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // pZoneSystem at 0x10
    get cZoneSystem() {
        const ptr = this.ptr.add(0x10).readPointer();
        return ptr.isNull() ? null : new CZoneSystem(ptr);
    }

    get zoneSystem() {
        return this.cZoneSystem;
    }

    // pPhysicalWorld at 0x28
    get physicalWorld() {
        const ptr = this.ptr.add(0x28).readPointer();
        return ptr.isNull() ? null : new CPhysicalWorld(ptr);
    }

    // pDataCore at 0x80
    get dataCore() {
        const ptr = this.ptr.add(0x80).readPointer();
        return ptr.isNull() ? null : ptr;
    }

    // pGame at 0xA0
    get game() {
        const ptr = this.ptr.add(0xa0).readPointer();
        return ptr.isNull() ? null : new CGame(ptr);
    }

    // pEntitySystem at 0xA8
    get entitySystem() {
        const sysPtr = this.ptr.add(0xa8).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }

    // pEntityComponentSystem at 0xB0
    get entityComponentSystem() {
        const ptr = this.ptr.add(0xb0).readPointer();
        return ptr.isNull() ? null : new CEntityComponentSystem(ptr);
    }

    // Compatibility alias for older code in this file.
    get engineComponentScheduler() {
        return this.entityComponentSystem;
    }

    // pConsole at 0xB8
    get console() {
        const ptr = this.ptr.add(0xb8).readPointer();
        return ptr.isNull() ? null : ptr;
    }

    // pSystem at 0xC8
    get cSystem() {
        const ptr = this.ptr.add(0xc8).readPointer();
        return ptr.isNull() ? null : new CSystem(ptr);
    }

    // pRenderer at 0xF8
    get cRenderer() {
        const ptr = this.ptr.add(0xf8).readPointer();
        return ptr.isNull() ? null : new CRenderer(ptr);
    }

    // pGen12Renderer at 0x100
    get gen12Renderer() {
        const ptr = this.ptr.add(0x100).readPointer();
        return ptr.isNull() ? null : ptr;
    }

    // pCIGServices at 0x188
    get cigServices() {
        const ptr = this.ptr.add(0x188).readPointer();
        return ptr.isNull() ? null : ptr;
    }
}

// Wrapper for CGame
class CGame {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // m_pClientPlayer at 0x0C18 (TComponentPtr<CSCPlayer>)
    get player() {
        const ptr = extractLower48(this.ptr.add(0x0C18).readPointer());
        return ptr.isNull() ? null : new CSCPlayer(ptr);
    }
}

// Wrapper for CSCPlayer
class CSCPlayer {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // IComponent owner entity pointer at 0x08 (TComponentPtr/IEntityPtr encoded pointer)
    get owningEntity() {
        const ptr = extractLower48(this.ptr.add(0x08).readPointer());
        return ptr.isNull() ? null : new CEntity(ptr);
    }

    // m_pCurrentActor at 0x3B8 (TComponentPtr<CActor>)
    get currentActor() {
        const actorPtr = extractLower48(this.ptr.add(0x3B8).readPointer());
        return actorPtr.isNull() ? null : new CActor(actorPtr);
    }

    // m_playerName at 0x398 (CSerializedVariable<CryStringT<char>>)
    get name() {
        return readCryString(this.ptr.add(0x3A0));
    }
}

const convenience_mapping = [
    ['zone', CZone],
    ['physent', CPhysicalEntity],
    ['rigent', CRigidEntity],
    ['healthcomp', CHealthComponent],
    ['ent', CEntity],
    ['entclass', CEntityClass],
];

convenience_mapping.forEach(([name, cls]) => {
    globalThis[name] = iptr => new cls(ptr(iptr));

    NativePointer.prototype[name] = function() {
        return new cls(this);
    };
});

// === Main polling loop ===
const gEnv = new GEnv(GENV_ADDR);

console.log("[*] Frida Entity System bridge initialized.");

const player = () => gEnv.game.player.owningEntity;

const run = () => {
    const es = gEnv.entitySystem;
    if (!es) {
        console.log("[!] entity_system not yet available");
        return;
    }

    console.log("[*] Enumerating all entities...");
    const allEntities = es.entityArray.toArray();
    console.log(`    → Found ${allEntities.length} entities`);

    const entityClasses = new Map();

    for (const ent of allEntities) {
        try {
            const cls = ent.entityClass;
            if (!cls) continue;
            const cls_name = cls.name;
            entityClasses.set(cls_name, cls);
        } catch {}
    }

    console.log(`    → Found ${entityClasses.size} entity classes`);

    const entityClassesSorted = Array.from(entityClasses.keys()).sort();

    for (const cls of entityClassesSorted) {
        console.log(`        [→ ${cls}]`);
    }
};

const listPlayers = () => {
    const cr = gEnv.cRenderer;

    if (!cr) {
        console.log("[!] cRenderer not yet available");
        return;
    }

    const es = gEnv.entitySystem;
    if (!es) {
        console.log("[!] entity_system not yet available");
        return;
    }

    console.log("[*] Enumerating all entities...");
    const allEntities = es.entityArray.toArray();
    console.log(`    → Found ${allEntities.length} entities`);

    const entityClasses = new Map();

    for (const ent of allEntities) {
        try {
            const cls = ent.entityClass;
            if (!cls) continue;
            const cls_name = cls.name;
            entityClasses.set(cls_name, cls);
        } catch {}
    }

    const actorClasses = [
        'Player',
        'PlayerCorpse'
    ];

    const actorClassPtrs = actorClasses.map(cls => entityClasses.get(cls)?.ptr).filter(ptr => ptr);

    console.log("[*] Filtering Player entities...");
    const players = allEntities.filter((ent) => {
        try {
            const cls = ent.entityClass;
            if (!cls) return false;

            for (const ptr of actorClassPtrs) {
                if (cls.ptr.equals(ptr)) {
                    return true;
                }
            }
        } catch (e) {}

        return false;
    });

    console.log(`    → Found ${players.length} Player entities`);
    for (const p of players) {
        const pos = p.worldPos;
        const proj = cr.projectToScreen(pos);
        const className = p.entityClass ? p.entityClass.name : "<unknown>";
        const isCorpse = className === 'PlayerCorpse';

        console.log(
            `        [${p.ptr}] [ID ${p.id}] ${isCorpse ? 'CORPSE' : 'ALIVE'} ${p.name || "<no-name>"} @ (${pos.x.toFixed(2)}, ${pos.y.toFixed(2)}, ${pos.z.toFixed(2)}) : Screen(${proj.x.toFixed(2)}, ${proj.y.toFixed(2)}, ${proj.z.toFixed(2)})`,
        );
   }
};

// // Global exception handler to prevent script crashes
// Process.setExceptionHandler((exception) => {
//     console.log("=== EXCEPTION CAUGHT ===");
//     console.log(`Type: ${exception.type}`);
//     console.log(`Address: ${exception.address}`);

//     // Log CPU context information
//     if (exception.context) {
//         console.log("CPU Context:");
//         try {
//             // Log common registers based on architecture
//             if (Process.arch === 'x64') {
//                 console.log(`  RAX: ${exception.context.rax}`);
//                 console.log(`  RBX: ${exception.context.rbx}`);
//                 console.log(`  RCX: ${exception.context.rcx}`);
//                 console.log(`  RDX: ${exception.context.rdx}`);
//                 console.log(`  RSP: ${exception.context.rsp}`);
//                 console.log(`  RBP: ${exception.context.rbp}`);
//                 console.log(`  RIP: ${exception.context.rip}`);
//             } else if (Process.arch === 'arm64') {
//                 console.log(`  X0: ${exception.context.x0}`);
//                 console.log(`  X1: ${exception.context.x1}`);
//                 console.log(`  SP: ${exception.context.sp}`);
//                 console.log(`  PC: ${exception.context.pc}`);
//             }
//         } catch (e) {
//             console.log(`  Context read error: ${e.message}`);
//         }
//     }

//     // Log memory access details for memory-related exceptions
//     if (exception.memory) {
//         console.log("Memory Access Details:");
//         console.log(`  Operation: ${exception.memory.operation}`);
//         console.log(`  Address: ${exception.memory.address}`);

//         // Try to provide more context about the memory region
//         try {
//             const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false });
//             const faultRange = ranges.find(range =>
//                 exception.memory.address.compare(range.base) >= 0 &&
//                 exception.memory.address.compare(range.base.add(range.size)) < 0
//             );

//             if (faultRange) {
//                 console.log(`  Memory region: ${faultRange.base}-${faultRange.base.add(faultRange.size)} (${faultRange.protection})`);
//                 if (faultRange.file) {
//                     console.log(`  File mapping: ${faultRange.file.path} (offset: ${faultRange.file.offset})`);
//                 }
//             } else {
//                 console.log(`  Memory region: Not found in mapped ranges`);
//             }
//         } catch (e) {
//             console.log(`  Memory region lookup failed: ${e.message}`);
//         }
//     }

//     // Log stack trace with more detail
//     console.log("Stack Trace:");
//     try {
//         const stackTrace = Thread.backtrace(exception.context, Backtracer.ACCURATE);
//         stackTrace.slice(0, 10).forEach((address, index) => {
//             const symbol = DebugSymbol.fromAddress(address);
//             const moduleName = Process.getModuleByAddress(address)?.name || "unknown";
//             console.log(`  ${index.toString().padStart(2, ' ')}: ${address} ${symbol.name || '<unknown>'} (${moduleName})`);
//         });
//     } catch (e) {
//         console.log(`  Stack trace generation failed: ${e.message}`);
//     }

//     // Log native context address for advanced debugging
//     console.log(`Native context: ${exception.nativeContext}`);

//     console.log("========================");

//     // Return true to indicate we've handled the exception
//     return true;
// });

rpc.exports.run = run;
rpc.exports.listPlayers = listPlayers;

// Helper to search for entities by regex pattern on class names
function findEntitiesByClassNamePattern(pattern) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return [];
    }

    const regex = new RegExp(pattern);
    const allEntities = entitySystem.entityArray.toArray();

    return allEntities.filter(entity => {
        try {
            const entityClass = entity.entityClass;
            if (!entityClass) return false;

            const className = entityClass.name;
            return regex.test(className);
        } catch (e) {
            return false;
        }
    });
}

// Utility to calculate distance between entity and camera
function calculateDistance(entity) {
    try {
        const pos = entity.worldPos;
        const cameraPos = gEnv.cSystem ? gEnv.cSystem.cameraWorldPos : null;

        if (!cameraPos) return Infinity;

        // Calculate Euclidean distance between entity and camera
        const dx = pos.x - cameraPos.x;
        const dy = pos.y - cameraPos.y;
        const dz = pos.z - cameraPos.z;
        return Math.sqrt(dx*dx + dy*dy + dz*dz);
    } catch (e) {
        return Infinity;
    }
}

// Utility to calculate angles between camera and entity
function calculateAngles(entity) {
    try {
        const pos = entity.worldPos;
        const cSystem = gEnv.cSystem;
        if (!cSystem) return { yaw: 0, pitch: 0 };

        const cameraPos = cSystem.cameraWorldPos;
        const cameraForward = cSystem.cameraForward;

        // Vector from camera to entity
        const toEntity = {
            x: pos.x - cameraPos.x,
            y: pos.y - cameraPos.y,
            z: pos.z - cameraPos.z
        };

        // Normalize vector
        const len = Math.sqrt(toEntity.x*toEntity.x + toEntity.y*toEntity.y + toEntity.z*toEntity.z);
        if (len === 0) return { yaw: 0, pitch: 0 };

        toEntity.x /= len;
        toEntity.y /= len;
        toEntity.z /= len;

        // Calculate yaw (horizontal angle)
        // Project both vectors onto XY plane
        const forward2D = Math.sqrt(cameraForward.x*cameraForward.x + cameraForward.y*cameraForward.y);
        const entity2D = Math.sqrt(toEntity.x*toEntity.x + toEntity.y*toEntity.y);

        let yaw = 0;
        if (forward2D > 0 && entity2D > 0) {
            // Calculate angle using atan2
            const camAngle = Math.atan2(cameraForward.y, cameraForward.x);
            const entityAngle = Math.atan2(toEntity.y, toEntity.x);
            yaw = (entityAngle - camAngle) * 180 / Math.PI;

            // Normalize to [-180, 180]
            while (yaw > 180) yaw -= 360;
            while (yaw < -180) yaw += 360;
        }

        // Calculate pitch (vertical angle)
        const pitch = Math.asin(toEntity.z) * 180 / Math.PI - Math.asin(cameraForward.z) * 180 / Math.PI;

        return { yaw, pitch };
    } catch (e) {
        return { yaw: 0, pitch: 0 };
    }
}

// Utility to format direction relative to player
function formatRelativeDirection(angles) {
    const { yaw, pitch } = angles;

    // Format horizontal direction
    let horizontalDirection = "";
    if (Math.abs(yaw) < 1) {
        horizontalDirection = "directly ahead";
    } else if (yaw > 0) {
        horizontalDirection = `${Math.abs(yaw).toFixed(1)}° right`;
    } else {
        horizontalDirection = `${Math.abs(yaw).toFixed(1)}° left`;
    }

    // Format vertical direction
    let verticalDirection = "";
    if (Math.abs(pitch) < 1) {
        verticalDirection = "level";
    } else if (pitch > 0) {
        verticalDirection = `${Math.abs(pitch).toFixed(1)}° up`;
    } else {
        verticalDirection = `${Math.abs(pitch).toFixed(1)}° down`;
    }

    return `${horizontalDirection}, ${verticalDirection}`;
}

// Search for entities by exact class name
function findEntitiesByClassName(className) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return [];
    }

    const allEntities = entitySystem.entityArray.toArray();

    return allEntities.filter(entity => {
        try {
            const entityClass = entity.entityClass;
            if (!entityClass) return false;
            return entityClass.name === className;
        } catch (e) {
            return false;
        }
    });
}

// Utility to print entity information with distance and angles
function printEntityInfoWithAngles(entity, distance, angles) {
    try {
        const worldPos = entity.worldPos;
        const className = entity.entityClass ? entity.entityClass.name : "<unknown-class>";
        const name = entity.name || "<no-name>";
        const direction = formatRelativeDirection(angles);

        console.log(
            `[${entity.ptr}] [ID ${entity.id}] Class: ${className} Name: ${name}\n` +
            `  World Position: (${worldPos.x.toFixed(2)}, ${worldPos.y.toFixed(2)}, ${worldPos.z.toFixed(2)})\n` +
            `  Distance: ${distance.toFixed(2)}m\n` +
            `  Direction: ${direction}\n` +
            `  Raw Angles: Yaw=${angles.yaw.toFixed(1)}° Pitch=${angles.pitch.toFixed(1)}°`
        );
    } catch (e) {
        console.log(`Error printing entity info: ${e}`);
        console.log(e.stack);
    }
}
// Export as RPC method
rpc.exports.findByClassName = function(pattern) {
    const entities = findEntitiesByClassNamePattern(pattern);
    console.log(`[*] Found ${entities.length} entities matching pattern: ${pattern}`);

    // Calculate distances and angles for each entity
    const entitiesWithMetrics = entities.map(entity => {
        const distance = calculateDistance(entity);
        const angles = calculateAngles(entity);
        return { entity, distance, angles };
    });

    // Sort by distance (closest first)
    entitiesWithMetrics.sort((a, b) => a.distance - b.distance);

    // Print sorted entities with full metrics
    entitiesWithMetrics.slice(0, 100).forEach(item => {
        printEntityInfoWithAngles(item.entity, item.distance, item.angles);
    });

    return {
        count: entities.length,
        entities: entitiesWithMetrics.slice(0, 100).map(item => {
            const worldPos = item.entity.worldPos;
            const zonePos = item.entity.zonePos;
            return {
                ptr: item.entity.ptr.toString(),
                id: item.entity.id,
                name: item.entity.name || "<no-name>",
                distance: item.distance,
                yaw: item.angles.yaw,
                pitch: item.angles.pitch,
                direction: formatRelativeDirection(item.angles),
                worldPos: {
                    x: worldPos.x,
                    y: worldPos.y,
                    z: worldPos.z
                },
                zonePos: {
                    x: zonePos.x,
                    y: zonePos.y,
                    z: zonePos.z
                }
            };
        })
    };
};

// New RPC method to search by exact class name with distance and angles
rpc.exports.findByExactClassName = function(className) {
    const entities = findEntitiesByClassName(className);
    console.log(`[*] Found ${entities.length} entities with class: ${className}`);

    // Calculate distances and angles for each entity
    const entitiesWithMetrics = entities.map(entity => {
        const distance = calculateDistance(entity);
        const angles = calculateAngles(entity);
        return { entity, distance, angles };
    });

    // Sort by distance (closest first)
    entitiesWithMetrics.sort((a, b) => a.distance - b.distance);

    // Print sorted entities with full metrics
    entitiesWithMetrics.forEach(item => {
        printEntityInfoWithAngles(item.entity, item.distance, item.angles);
    });

    return {
        count: entities.length,
        entities: entitiesWithMetrics.map(item => {
            const worldPos = item.entity.worldPos;
            const zonePos = item.entity.zonePos;
            return {
                ptr: item.entity.ptr.toString(),
                id: item.entity.id,
                name: item.entity.name || "<no-name>",
                distance: item.distance,
                yaw: item.angles.yaw,
                pitch: item.angles.pitch,
                direction: formatRelativeDirection(item.angles),
                worldPos: {
                    x: worldPos.x,
                    y: worldPos.y,
                    z: worldPos.z
                },
                zonePos: {
                    x: zonePos.x,
                    y: zonePos.y,
                    z: zonePos.z
                }
            };
        })
    };
};

// RPC method to get class pointer by name
rpc.exports.getClassPointer = function(className) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return null;
    }

    try {
        const entityClass = entitySystem.getClassByName(className);
        if (!entityClass) {
            console.log(`[!] Class '${className}' not found`);
            return null;
        }

        console.log(`[*] Found class '${className}' at pointer: ${entityClass.ptr}`);
        return entityClass.ptr.toString();
    } catch (e) {
        console.log(`[!] Error finding class '${className}': ${e.message}`);
        return null;
    }
};

// RPC method to replace entity class types
rpc.exports.replaceEntityClassType = function(fromClassName, toClassName) {
    return {
        success: false,
        error: "replaceEntityClassType directly writes CEntity::m_pClass and is disabled pending a verified interface path"
    };
};

// RPC method to replace entity class types using regex pattern
rpc.exports.replaceEntityClassTypeRegex = function(fromClassRegex, toClassName) {
    return {
        success: false,
        error: "replaceEntityClassTypeRegex directly writes CEntity::m_pClass and is disabled pending a verified interface path"
    };

    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        // Compile the regex pattern
        const regex = new RegExp(fromClassRegex);
        console.log(`[*] Compiled regex pattern: ${fromClassRegex}`);

        // Get the target class pointer
        const toClass = entitySystem.getClassByName(toClassName);
        if (!toClass) {
            console.log(`[!] Target class '${toClassName}' not found`);
            return { success: false, error: `Target class '${toClassName}' not found` };
        }

        console.log(`[*] Target class '${toClassName}' found at ${toClass.ptr}`);

        // Find all entities and filter by regex pattern
        const allEntities = entitySystem.entityArray.toArray();
        const matchingEntities = [];
        const matchedClassNames = new Set();

        for (const entity of allEntities) {
            try {
                const entityClass = entity.entityClass;
                if (!entityClass) continue;

                const className = entityClass.name;
                if (regex.test(className)) {
                    matchingEntities.push(entity);
                    matchedClassNames.add(className);
                }
            } catch (e) {
                // Skip entities that can't be processed
            }
        }

        console.log(`[*] Found ${matchingEntities.length} entities matching pattern '${fromClassRegex}'`);
        console.log(`[*] Matched class names: ${Array.from(matchedClassNames).join(', ')}`);

        let successCount = 0;
        let errorCount = 0;
        const processedClasses = {};

        // Replace the class pointer for each matching entity
        for (const entity of matchingEntities) {
            try {
                const originalClassName = entity.entityClass.name;

                // Write the new class pointer to the entity_class_ field at offset 0x20
                entity.ptr.add(0x20).writePointer(toClass.ptr);
                successCount++;

                // Track processed classes for reporting
                if (!processedClasses[originalClassName]) {
                    processedClasses[originalClassName] = 0;
                }
                processedClasses[originalClassName]++;

                console.log(`[+] Successfully changed class for entity ${entity.ptr} (ID: ${entity.id}) from '${originalClassName}' to '${toClassName}'`);
            } catch (e) {
                errorCount++;
                console.log(`[!] Failed to change class for entity ${entity.ptr}: ${e.message}`);
            }
        }

        const result = {
            success: true,
            fromClassRegex: fromClassRegex,
            toClass: toClassName,
            matchedClassNames: Array.from(matchedClassNames),
            processedClasses: processedClasses,
            totalFound: matchingEntities.length,
            successCount: successCount,
            errorCount: errorCount
        };

        console.log(`[*] Regex class replacement complete: ${successCount} successful, ${errorCount} failed`);
        console.log(`[*] Processed classes breakdown:`, processedClasses);
        return result;

    } catch (e) {
        console.log(`[!] Error during regex class replacement: ${e.message}`);
        return { success: false, error: e.message };
    }
};

// RPC method to spawn an entity by class name
rpc.exports.spawnEntityByClass = function(className, options = {}) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        if (!className) {
            className = 'crlf_consumable_ea_medicateAll_01';
        }

        // Default spawn parameters
        const spawnParams = {
            name: options.name || `Spawned_${className}_${Date.now()}`,
            zone: options.zone || null,
            parent: options.parent || null,
            ...options
        };
        if (options.flags === undefined) {
            delete spawnParams.flags;
        }

        console.log(`[*] Attempting to spawn entity of class '${className}' with params:`, spawnParams);

        const result = entitySystem.createEntity(className, spawnParams);

        if (result && result.success) {
            console.log(`[+] Successfully spawned entity of class '${className}'`);
            return result;
        }

        console.log(`[!] Failed to spawn entity of class '${className}'`);
        return result || {
            success: false,
            error: "Spawn function returned false",
            className: className
        };

    } catch (e) {
        console.log(`[!] Error spawning entity of class '${className}': ${e.message}`);
        return {
            success: false,
            error: e.message,
            className: className
        };
    }
};

rpc.exports.makeCorpsesLootable = () => ({
    success: false,
    error: "makeCorpsesLootable depends on disabled direct class-pointer mutation"
});

rpc.exports.installSpawnDebugHooks = function(options = {}) {
    return {
        success: false,
        error: "installSpawnDebugHooks uses direct native addresses and Interceptor hooks; verify each target against current symbols/interfaces before enabling"
    };
};

// RPC method to replace a single entity's class type by pointer
rpc.exports.replaceEntityClass = function(entityPtr, newClassName) {
    return {
        success: false,
        error: "replaceEntityClass directly writes CEntity::m_pClass and is disabled pending a verified interface path"
    };
};

// RPC method to list all entities within a specific distance, sorted by distance
rpc.exports.listEntitiesInRange = function(maxDistance = 100, options = {}) {
    if (typeof maxDistance === 'object') {
        options = maxDistance;
        maxDistance = options.maxDistance === undefined ? 100 : Number(options.maxDistance);
    }

    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    const cSystem = gEnv.cSystem;
    if (!cSystem) {
        console.log("[!] Camera system not available");
        return { success: false, error: "Camera system not available" };
    }

    try {
        console.log(`[*] Searching for entities within ${maxDistance}m range...`);

        const entitiesInRange = [];
        const maxScan = options.maxScan === undefined ? entitySystem.entityArray.maxSize : Math.min(Number(options.maxScan), entitySystem.entityArray.maxSize);
        const cameraPos = cSystem.cameraWorldPos;

        for (let i = 0; i < maxScan; i++) {
            try {
                const entity = entitySystem.entityArray.at(i);
                if (!entity) {
                    continue;
                }

                // Memory-only position read. Do not call CEntity::GetWorldPos across the full array.
                const worldPos = entity.zonePos;
                if (![worldPos.x, worldPos.y, worldPos.z].every(Number.isFinite)) {
                    continue;
                }

                const dx = worldPos.x - cameraPos.x;
                const dy = worldPos.y - cameraPos.y;
                const dz = worldPos.z - cameraPos.z;
                const distance = Math.sqrt(dx * dx + dy * dy + dz * dz);
                if (distance <= maxDistance && !(distance >= 1.7 && distance <= 7.9)) {
                    let className = "<unknown>";
                    let name = "<no-name>";
                    let id = null;
                    try { id = entity.id.toString(); } catch (_) {}
                    try {
                        const cls = entity.entityClass;
                        className = cls ? cls.name : "<unknown>";
                    } catch (_) {}
                    try { name = entity.name || "<no-name>"; } catch (_) {}
                    const angles = {
                        yaw: Math.atan2(dx, dy) * 180 / Math.PI,
                        pitch: Math.atan2(dz, Math.sqrt(dx * dx + dy * dy)) * 180 / Math.PI
                    };

                    entitiesInRange.push({
                        entity: entity,
                        id,
                        distance: distance,
                        angles: angles,
                        worldPos: worldPos,
                        className: className,
                        name: name
                    });
                }
            } catch (e) {
                // Skip entities that can't be processed
            }
        }

        // Sort by distance (closest first)
        entitiesInRange.sort((a, b) => a.distance - b.distance);

        console.log(`[*] Found ${entitiesInRange.length} entities within ${maxDistance}m range`);

        // Print detailed information for each entity
        entitiesInRange.forEach((item, index) => {
            const direction = formatRelativeDirection(item.angles);
            console.log(
                `${(index + 1).toString().padStart(3, ' ')}. [${item.entity.ptr}] [ID ${item.id || '<unknown>'}] Class: ${item.className}\n` +
                `     Name: ${item.name}\n` +
                `     Position: (${item.worldPos.x.toFixed(2)}, ${item.worldPos.y.toFixed(2)}, ${item.worldPos.z.toFixed(2)})\n` +
                `     Distance: ${item.distance.toFixed(2)}m | Direction: ${direction}`
            );
        });

        // Return structured data
        return {
            success: true,
            maxDistance: maxDistance,
            totalFound: entitiesInRange.length,
            entities: entitiesInRange.map(item => ({
                ptr: item.entity.ptr.toString(),
                id: item.id,
                className: item.className,
                name: item.name,
                distance: item.distance,
                yaw: item.angles.yaw,
                pitch: item.angles.pitch,
                direction: formatRelativeDirection(item.angles),
                worldPos: {
                    x: item.worldPos.x,
                    y: item.worldPos.y,
                    z: item.worldPos.z
                }
            }))
        };

    } catch (e) {
        console.log(`[!] Error listing entities in range: ${e.message}`);
        return { success: false, error: e.message };
    }
};

rpc.exports.findEntityById = function(entityId) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        return { success: false, error: "Entity system not available" };
    }

    const wanted = BigInt(entityId);
    try {
        const allEntities = entitySystem.entityArray.toArray();
        for (const entity of allEntities) {
            try {
                if (BigInt(entity.id.toString()) !== wanted) {
                    continue;
                }

                let worldPos = null;
                let distance = null;
                let className = "<unknown>";
                let name = "<no-name>";
                try {
                    const cls = entity.entityClass;
                    className = cls ? cls.name : "<unknown>";
                } catch (_) {}
                try {
                    name = entity.name || "<no-name>";
                } catch (_) {}
                try {
                    worldPos = entity.worldPos;
                    distance = calculateDistance(entity);
                } catch (_) {}
                return {
                    success: true,
                    ptr: entity.ptr.toString(),
                    id: entity.id.toString(),
                    className,
                    name,
                    worldPos: worldPos ? { x: worldPos.x, y: worldPos.y, z: worldPos.z } : null,
                    distance
                };
            } catch (_) {}
        }

        return { success: false, error: "Entity id not found", entityId: wanted.toString() };
    } catch (e) {
        return { success: false, error: e.message, entityId: wanted.toString() };
    }
};

rpc.exports.getEntityComponentData = function(entityPtr, componentName) {
    return {
        success: false,
        error: "getEntityComponentData depends on unverified component wrapper classes and is disabled pending component audit"
    };
};

// RPC method to resolve component name to ID
rpc.exports.resolveComponentNameToId = function(componentName) {
    try {
        const scheduler = gEnv.engineComponentScheduler;

        if (!scheduler) {
            return { success: false, error: "Engine component scheduler not available" };
        }

        const result = scheduler.getComponentIdByName(componentName);

        return {
            success: result.success,
            componentName: componentName,
            componentId: result.componentId,
            componentIdHex: `0x${result.componentId.toString(16)}`
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
};

// RPC method to add glow effect to entities matching regex pattern
rpc.exports.addGlowToEntitiesRegex = function(classNameRegex, glowParams = { r: 1.0, g: 1.0, b: 0.0 }, glowId = 3) {
    return {
        success: false,
        error: "addGlowToEntitiesRegex depends on an unverified render/glow path and is disabled pending interface-vtable verification"
    };
};

rpc.exports.hookRun = () => ({
    success: false,
    error: "hookRun uses a direct CActorEntity::Step address and stale actor field offsets; disabled pending verification"
});

// builds a dependency tree based on all entities of a class (entity -> containingEntity -> containingEntity -> etc.)
rpc.exports.buildClassEntitiesDepTree = (entityClassPattern, options = {}) => {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        const {
            useRegex = true,
            maxDepth = 100,
            outputPath = `/tmp/entity_dep_tree_${Date.now()}.dot`,
            includeZone = true,
            includePtr = true
        } = options;

        // Find all entities matching the class pattern
        const allEntities = entitySystem.entityArray.toArray();
        let matchingEntities;

        if (useRegex) {
            const regex = new RegExp(entityClassPattern);
            matchingEntities = allEntities.filter(entity => {
                try {
                    const entityClass = entity.entityClass;
                    if (!entityClass) return false;
                    return regex.test(entityClass.name);
                } catch (e) {
                    return false;
                }
            });
        } else {
            matchingEntities = allEntities.filter(entity => {
                try {
                    const entityClass = entity.entityClass;
                    if (!entityClass) return false;
                    return entityClass.name === entityClassPattern;
                } catch (e) {
                    return false;
                }
            });
        }

        console.log(`[*] Found ${matchingEntities.length} entities matching pattern '${entityClassPattern}'`);

        if (matchingEntities.length === 0) {
            return {
                success: true,
                pattern: entityClassPattern,
                matchingEntities: 0,
                totalNodes: 0,
                totalEdges: 0,
                filename: null,
                dotContent: null
            };
        }

        // Node storage: ptr string -> node data
        const nodes = new Map();
        // Edge storage: Set of "fromPtr->toPtr" strings
        const edgeSet = new Set();
        // Track which nodes are target class entities
        const targetNodes = new Set();

        const getPtrKey = (entity) => entity.ptr.toString();

        const getNodeLabel = (entity) => {
            const className = entity.entityClass ? entity.entityClass.name : "<unknown>";
            const name = entity.name || "<no-name>";
            const id = entity.id;

            let label = `${className}\\n${name}\\nID: ${id}`;

            if (includePtr) {
                label += `\\n${entity.ptr}`;
            }

            if (includeZone) {
                try {
                    const zone = entity.zone;
                    if (zone) {
                        const zoneName = zone.name || "<unnamed-zone>";
                        label += `\\nZone: ${zoneName}`;
                    }
                } catch (e) {}
            }

            return label;
        };

        const ensureNode = (entity) => {
            const key = getPtrKey(entity);
            if (!nodes.has(key)) {
                nodes.set(key, {
                    ptr: key,
                    label: getNodeLabel(entity),
                    className: entity.entityClass ? entity.entityClass.name : "<unknown>"
                });
            }
            return key;
        };

        // Traverse upward from each matching entity
        for (const entity of matchingEntities) {
            let current = entity;
            let depth = 0;

            const startKey = ensureNode(current);
            targetNodes.add(startKey);

            while (current && depth < maxDepth) {
                const currentKey = ensureNode(current);

                let containing = null;
                try {
                    containing = current.containingEntity;
                } catch (e) {
                    console.log(`[!] Error getting containingEntity for ${current.ptr}: ${e.message}`);
                }

                if (containing && !containing.ptr.isNull()) {
                    const containingKey = ensureNode(containing);
                    const edgeKey = `${currentKey}->${containingKey}`;

                    if (!edgeSet.has(edgeKey)) {
                        edgeSet.add(edgeKey);
                    }

                    current = containing;
                    depth++;
                } else {
                    break;
                }
            }

            if (depth >= maxDepth) {
                console.log(`[!] Max depth reached for entity ${entity.ptr}`);
            }
        }

        console.log(`[*] Built graph with ${nodes.size} nodes and ${edgeSet.size} edges`);

        // Generate DOT file content
        const dotLines = [
            'digraph EntityDependencyTree {',
            '    rankdir=BT;',
            '    node [shape=box, fontname="Consolas", fontsize=9];',
            '    edge [color=gray50];',
            ''
        ];

        // Escape DOT special characters in labels
        const escapeDotLabel = (label) => {
            return label.replace(/"/g, '\\"');
        };

        // Generate unique node IDs (DOT doesn't like hex addresses as IDs)
        const nodeIdMap = new Map();
        let nodeCounter = 0;
        for (const [ptrKey, _] of nodes) {
            nodeIdMap.set(ptrKey, `n${nodeCounter++}`);
        }

        // Add nodes
        for (const [ptrKey, nodeData] of nodes) {
            const nodeId = nodeIdMap.get(ptrKey);
            const isTarget = targetNodes.has(ptrKey);
            const style = isTarget
                ? ', style=filled, fillcolor=lightblue, penwidth=2'
                : '';
            dotLines.push(`    ${nodeId} [label="${escapeDotLabel(nodeData.label)}"${style}];`);
        }

        dotLines.push('');

        // Add edges
        for (const edgeKey of edgeSet) {
            const [fromPtr, toPtr] = edgeKey.split('->');
            const fromId = nodeIdMap.get(fromPtr);
            const toId = nodeIdMap.get(toPtr);
            if (fromId && toId) {
                dotLines.push(`    ${fromId} -> ${toId};`);
            }
        }

        dotLines.push('}');

        const dotContent = dotLines.join('\n');

        // Write to disk
        const file = new File(outputPath, 'w');
        file.write(dotContent);
        file.close();

        console.log(`[+] DOT file written to: ${outputPath}`);
        console.log(`[*] Render with: dot -Tpng ${outputPath} -o output.png`);

        return {
            success: true,
            pattern: entityClassPattern,
            matchingEntities: matchingEntities.length,
            totalNodes: nodes.size,
            totalEdges: edgeSet.size,
            filename: outputPath,
            dotContent: dotContent
        };

    } catch (e) {
        console.log(`[!] Error building dependency tree: ${e.message}`);
        console.log(e.stack);
        return { success: false, error: e.message };
    }
};
