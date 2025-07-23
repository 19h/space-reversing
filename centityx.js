//
// Frida script to mirror the game's C++ entity system in idiomatic JavaScript,
// providing rich, object-oriented wrappers around native memory structures.

"use strict";

const PTR_SIZE = Process.pointerSize;

// Helper to extract lower 48 bits of a pointer
function extractLower48(ptrVal) {
    // Mask with 0xFFFFFFFFFFFF
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

// Helper to read a C-style UTF-8 string pointer
function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
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

// Wrapper for CEntityClass (size: 0x90)
class CEntityClass {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // flags_ at offset 0x08 (int64)
    get flags() {
        return this.ptr.add(0x08).readS64();
    }

    // name_ at offset 0x10 (char*)
    get name() {
        const namePtr = this.ptr.add(0x10).readPointer();
        return readCString(namePtr);
    }

    // Virtual slot 0 => Function0 (no args, no return)
    function0() {
        callVFunc(this.ptr, 0, "void", []);
    }
}

// Wrapper for CZone
class CZone {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vtable slot 0: Scalar deleting destructor
    destroy() {
        callVFunc(this.ptr, 0, "void", []);
    }

    // vtable slot 1: Next - advances to the next zone in linked list
    next() {
        const nextPtr = callVFunc(this.ptr, 1, "pointer", []);
        return nextPtr.isNull() ? null : new CZone(extractLower48(nextPtr));
    }

    // vtable slot 31: Get relative position from camera
    getRelativePosition(camPosVec) {
        const outRel = Memory.alloc(24); // 3 doubles (24 bytes)

        // Create a native array from the camera position vector
        const nativeCamPos = Memory.alloc(24);
        nativeCamPos.writeDouble(camPosVec[0]);
        nativeCamPos.add(8).writeDouble(camPosVec[1]);
        nativeCamPos.add(16).writeDouble(camPosVec[2]);

        callVFunc(this.ptr, 31, "void", ["pointer", "pointer"], [outRel, nativeCamPos]);

        return {
            x: outRel.readDouble(),
            y: outRel.add(8).readDouble(),
            z: outRel.add(16).readDouble()
        };
    }

    // vtable slot 62: Get zone name
    getName() {
        const namePtr = callVFunc(this.ptr, 62, "pointer", []);
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

    // Virtual slot 130: GetRelativeTransform
    // Signature: double* GetRelativeTransform(double* result, __int64 a3, __int64 a4, int n0x3F800000, char a6)
    getRelativeTransform(fromGrid = null, toGrid = null, scale = 0x3F800000, lockFlag = false) {
        try {
            // Allocate output buffer for 7 doubles (transform result)
            const resultPtr = Memory.alloc(7 * 8);

            // Use default grid (this.ptr + 0xB40) if not specified
            const fromGridPtr = fromGrid ? fromGrid : this.ptr.add(0xB40);
            const toGridPtr = toGrid ? toGrid : this.ptr.add(0xB40);

            // Call virtual function at vtable slot 130
            callVFunc(
                this.ptr,
                130,
                "pointer",
                ["pointer", "pointer", "pointer", "int", "char"],
                [resultPtr, fromGridPtr, toGridPtr, scale, lockFlag ? 1 : 0],
                'getRelativeTransform'
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
                    x: resultPtr.add(32).readDouble(),
                    y: resultPtr.add(40).readDouble(),
                    z: resultPtr.add(48).readDouble()
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

    // Virtual slot 131: GetRelativeVelocityTransform
    // Signature: double* GetRelativeVelocityTransform(double* result, __int64* a3, double* a4, __int64* a5, double* a6, char a7)
    getRelativeVelocityTransform(fromGrid = null, fromVel = null, toGrid = null, toVel = null, lockFlag = false) {
        try {
            // Allocate output buffer for 7 doubles (velocity transform result)
            const resultPtr = Memory.alloc(7 * 8);

            // Use default grid (this.ptr + 0xB40) if not specified
            const fromGridPtr = fromGrid ? fromGrid : this.ptr.add(0xB40);
            const toGridPtr = toGrid ? toGrid : this.ptr.add(0xB40);

            // Allocate velocity vectors if provided
            let fromVelPtr = ptr(0);
            let toVelPtr = ptr(0);

            if (fromVel && Array.isArray(fromVel) && fromVel.length >= 3) {
                fromVelPtr = Memory.alloc(24);
                fromVelPtr.writeDouble(fromVel[0]);
                fromVelPtr.add(8).writeDouble(fromVel[1]);
                fromVelPtr.add(16).writeDouble(fromVel[2]);
            }

            if (toVel && Array.isArray(toVel) && toVel.length >= 3) {
                toVelPtr = Memory.alloc(24);
                toVelPtr.writeDouble(toVel[0]);
                toVelPtr.add(8).writeDouble(toVel[1]);
                toVelPtr.add(16).writeDouble(toVel[2]);
            }

            // Call virtual function at vtable slot 131
            callVFunc(
                this.ptr,
                131,
                "pointer",
                ["pointer", "pointer", "pointer", "pointer", "pointer", "char"],
                [resultPtr, fromGridPtr, fromVelPtr, toGridPtr, toVelPtr, lockFlag ? 1 : 0],
                'getRelativeVelocityTransform'
            );

            // Read the 7-element velocity transform result
            return {
                quat: {
                    x: resultPtr.readDouble(),
                    y: resultPtr.add(8).readDouble(),
                    z: resultPtr.add(16).readDouble(),
                    w: resultPtr.add(24).readDouble()
                },
                angularVelocity: {
                    x: resultPtr.add(32).readDouble(),
                    y: resultPtr.add(40).readDouble(),
                    z: resultPtr.add(48).readDouble()
                }
            };
        } catch (e) {
            console.log(`[!] Error in getRelativeVelocityTransform: ${e.message}`);
            return {
                quat: { x: 0, y: 0, z: 0, w: 1 },
                angularVelocity: { x: 0, y: 0, z: 0 }
            };
        }
    }
}

// Wrapper for CPhysicalEntity
class CPhysicalEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    get owningEntity() {
        const owningEntityPtr = this.ptr.add(0xc0).readPointer();
        return owningEntityPtr.isNull() ? null : new CEntity(owningEntityPtr);
    }

    // m_lockUpdate at offset 0xC8
    get lockUpdate() {
        return this.ptr.add(0xC8).readS64();
    }

    // m_pName at offset 0xD0
    get name() {
        const namePtr = this.ptr.add(0xD0).readPointer();
        return readCString(namePtr);
    }

    // m_nParts at offset 0x290
    get nParts() {
        return this.ptr.add(0x290).readS32();
    }

    // m_pWorld at offset 0x2C0
    get world() {
        const worldPtr = this.ptr.add(0x2C0).readPointer();
        return worldPtr.isNull() ? null : new CPhysicalWorld(worldPtr);
    }

    // Virtual slot 41: GetWorldTransform (at offset 328)
    getWorldTransform() {
        try {
            // Allocate memory for output transform (7 doubles for quaternion + translation)
            const resultPtr = Memory.alloc(7 * 8);

            // Read transform data from memory offsets as shown in decompiled code
            const v9 = Memory.alloc(4 * 8); // 4 doubles array

            // Read from offsets as per decompiled code
            v9.writeFloat(this.ptr.add(0x1D8).readFloat());          // v9[0]
            v9.add(4).writeFloat(this.ptr.add(0x1DC).readFloat());   // v9[1]
            v9.add(8).writeFloat(this.ptr.add(0x1E0).readFloat());   // v9[2]
            v9.add(12).writeFloat(this.ptr.add(0x1E4).readFloat());  // v9[3]

            // Read v10 (128-bit value from offset 0x1C0)
            const v10 = Memory.alloc(16);
            const v10_data = this.ptr.add(0x1C0).readByteArray(16);
            v10.writeByteArray(v10_data);

            // Read v11 and v12
            const v11 = this.ptr.add(0x1D0).readDouble();
            const v12 = this.ptr.add(0x200).readFloat();

            // Call virtual function at vtable slot 41 (offset 328)
            callVFunc(
                this.ptr,
                41,
                "pointer",
                ["pointer", "pointer", "pointer", "pointer"],
                [v9, resultPtr, ptr(0), ptr(0)],
                'getWorldTransform'
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
                    x: resultPtr.add(32).readDouble(),
                    y: resultPtr.add(40).readDouble(),
                    z: resultPtr.add(48).readDouble()
                }
            };
        } catch (e) {
            console.log(`[!] Error in getWorldTransform: ${e.message}`);
            return {
                quat: { x: 0, y: 0, z: 0, w: 1 },
                translation: { x: 0, y: 0, z: 0 }
            };
        }
    }

    // Virtual slot 43: WriteToObjFile (at offset 344)
    writeToObjFile(fileName) {
        try {
            // Allocate native string for filename
            const fileNamePtr = Memory.allocUtf8String(fileName);

            // Call virtual function at vtable slot 43 (offset 344)
            const result = callVFunc(
                this.ptr,
                43,
                "int",
                ["pointer", "pointer"],
                [fileNamePtr, ptr(1)],
                'writeToObjFile'
            );

            return result;
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
                'getEntityId'
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

    // Position components at offsets 0x628, 0x630, 0x638
    get position() {
        const x = this.ptr.add(0x628).readDouble();
        const y = this.ptr.add(0x630).readDouble();
        const z = this.ptr.add(0x638).readDouble();
        return new DVec3(x, y, z);
    }

    get posX() {
        return this.ptr.add(0x628).readDouble();
    }

    get posY() {
        return this.ptr.add(0x630).readDouble();
    }

    get posZ() {
        return this.ptr.add(0x638).readDouble();
    }

    // m_mass at offset 0x6B8
    get mass() {
        return this.ptr.add(0x6B8).readDouble();
    }

    // Velocity components at offsets 0x848, 0x84C, 0x850
    get velocity() {
        const x = this.ptr.add(0x848).readFloat();
        const y = this.ptr.add(0x84C).readFloat();
        const z = this.ptr.add(0x850).readFloat();
        return new DVec3(x, y, z);
    }

    get velX() {
        return this.ptr.add(0x848).readFloat();
    }

    get velY() {
        return this.ptr.add(0x84C).readFloat();
    }

    get velZ() {
        return this.ptr.add(0x850).readFloat();
    }

    // Network state members
    get netState() {
        const netStatePtr = this.ptr.add(0x8E8).readPointer();
        return netStatePtr.isNull() ? null : netStatePtr;
    }

    get netDesiredStateLock() {
        return this.ptr.add(0x8F0).readS64();
    }

    get isNetStateDirty() {
        return this.ptr.add(0x94C).readU8() !== 0;
    }

    get hasNetworkAuthority() {
        return this.ptr.add(0x94D).readU8() !== 0;
    }

    get isRemote() {
        return this.ptr.add(0x94E).readU8() !== 0;
    }

    // Setters for velocity components
    setVelX(value) {
        this.ptr.add(0x848).writeFloat(value);
    }

    setVelY(value) {
        this.ptr.add(0x84C).writeFloat(value);
    }

    setVelZ(value) {
        this.ptr.add(0x850).writeFloat(value);
    }

    setVelocity(x, y, z) {
        this.setVelX(x);
        this.setVelY(y);
        this.setVelZ(z);
    }

    // Setters for position components
    setPosX(value) {
        this.ptr.add(0x628).writeDouble(value);
    }

    setPosY(value) {
        this.ptr.add(0x630).writeDouble(value);
    }

    setPosZ(value) {
        this.ptr.add(0x638).writeDouble(value);
    }

    setPosition(x, y, z) {
        this.setPosX(x);
        this.setPosY(y);
        this.setPosZ(z);
    }

    // Setter for mass
    setMass(value) {
        this.ptr.add(0x6B8).writeDouble(value);
    }

    setNetworkAuthority(value) {
        console.log(this.ptr.add(0x94D));
        this.ptr.add(0x94D).writeU8(value);
    }

    detach() {
        // Set network state skip flag
        this.ptr.add(0x94D).writeU8(1);
        this.ptr.add(0x94E).writeU8(1);

        //// Set client authoritative flag (OR with 0x40000000)
        //const currentFlags = this.ptr.add(0x08).readU32();
        //this.ptr.add(0x08).writeU32(currentFlags | 0x40000000);

        // Set authority timer
        this.ptr.add(0x950).writeFloat(9999.0);
    }

    registerForRecompute() {
        return (new NativeFunction(ptr('0x146930530'), 'void', ['pointer', 'pointer']))(this.ptr.add(0x2c0).readPointer(), this.ptr);
    }
}

// Wrapper for CZoneSystem (size: 0x108)
class CZoneSystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vtable slot 0: Scalar deleting destructor
    destroy() {
        callVFunc(this.ptr, 0, "void", []);
    }

    // vtable slot 1: Scalar (non-deleting) destructor
    destructor() {
        callVFunc(this.ptr, 1, "void", []);
    }

    // vtable slot 13: GetFirstZone
    getZone(idx=0) {
        const ptr = callVFunc(this.ptr, 13, "pointer", ['int']);
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }
}

class CEngineComponentScheduler {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Virtual slot 0: Scalar deleting destructor
    destroy() {
        callVFunc(this.ptr, 0, "void", []);
    }

    // Virtual slot 1: Destructor
    destructor() {
        callVFunc(this.ptr, 1, "void", []);
    }

    // Virtual slot 2: GetComponentIdByName
    // Signature: void* GetComponentIdByName(uint16_t* component_id, const char* component_name)
    getComponentIdByName(componentName) {
        try {
            // Allocate memory for output component_id (uint16_t)
            const componentIdPtr = Memory.alloc(2);

            // Allocate native string for component name
            const componentNamePtr = Memory.allocUtf8String(componentName);

            // Call virtual function at index 2
            const result = callVFunc(
                this.ptr,
                2,
                "pointer",
                ["pointer", "pointer"],
                [componentIdPtr, componentNamePtr],
                'getComponentIdByName'
            );

            // Read the component ID from allocated memory
            const componentId = componentIdPtr.readU16();

            // Return both the result pointer and the component ID
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

class EntityComponent {
    constructor(ptr, componentName) {
        this.ptr = ptr;
        this.componentName = componentName;
    }

    // Common component functionality
    get owningEntity() {
        const entityPtr = this.ptr.add(0x08).readPointer();
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }
}

class IComponentRender {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Method to call the native AddGlowForSlot function
    addGlow(glowParams, glowStyle = 0, slotIndex = -1) {
        // RVA for CRenderProxy__AddGlowForSlot
        const addGlowFuncAddr = Module.findBaseAddress("StarCitizen.exe").add(0x69CB6D0);
        const addGlowFunc = new NativeFunction(addGlowFuncAddr, 'char', ['pointer', 'pointer', 'uint32', 'uint32']);

        // Allocate memory for the GlowParams struct
        const glowParamsPtr = Memory.alloc(16);
        glowParamsPtr.writeU8(glowParams.type || 1);
        glowParamsPtr.add(4).writeFloat(glowParams.r || 1.0);
        glowParamsPtr.add(8).writeFloat(glowParams.g || 1.0);
        glowParamsPtr.add(12).writeFloat(glowParams.b || 1.0);

        const nativeSlotIndex = (slotIndex === -1) ? 0xFFFFFFFF : slotIndex;

        return addGlowFunc(this.ptr, glowParamsPtr, glowStyle, nativeSlotIndex);
    }
}

// Wrapper for CSCBodyHealthComponent
class CHealthComponent {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // is_dead_ at offset 0x05C0
    get isDead() {
        return this.ptr.add(0x05C0).readU8() !== 0;
    }

    // is_incapacitated_ at offset 0x06E0
    get isIncapacitated() {
        return this.ptr.add(0x06E0).readU8() !== 0;
    }

    // parent_actor_ at offset 0x0270
    get parentActor() {
        const actorPtr = this.ptr.add(0x0270).readPointer();
        // The CActor class is complex and not fully defined; returning raw pointer for now.
        return actorPtr.isNull() ? null : actorPtr;
    }
}

class CRenderProxy {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // render_handle_ at offset 0x8
    get renderHandlePtr() {
        return this.ptr.add(0x8);
    }

    get renderHandle() {
        return this.renderHandlePtr.readPointer();
    }

    // component_render sub-object at offset 0x78
    get componentRender() {
        const subObjectPtr = this.ptr.add(0x78);
        return new IComponentRender(subObjectPtr);
    }
}

// Wrapper for CEntity (size: 0x0FD8)
class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // flags_   at 0x08
    get flags() {
        return this.ptr.add(0x08).readS64();
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

    // x_local_pos_, y_local_pos_, z_local_pos_
    get zonePos() {
        // Offsets from CEntity in StarCitizenClasses.hpp
        const x = this.ptr.add(0x00F0).readDouble();
        const y = this.ptr.add(0x00F8).readDouble();
        const z = this.ptr.add(0x0100).readDouble();
        return new DVec3(x, y, z);
    }

    // name_ at 0x290 (const char*)
    get name() {
        // Offset from CEntity in StarCitizenClasses.hpp
        const namePtr = this.ptr.add(0x0290).readPointer();
        return readCString(namePtr);
    }

    // zone_ at 0x2A8 (CZone*)
    get zoneFromMemory() {
        // Offset from CEntity in StarCitizenClasses.hpp
        const ptr = this.ptr.add(0x02A8).readPointer();
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // Preferred zone getter using virtual function
    get zone() {
        return this.getZone();
    }

    // Virtual slot 0 => Function0
    function0() {
        callVFunc(this.ptr, 0, "void", [], 'function0');
    }

    // vfunc 6: Set entity flags using OR operation
    setFlagsOR(mask, which) {
        callVFunc(this.ptr, 6, "void", ["uint32", "uint32"], [mask, which], 'setFlagsOR');
    }

    // vfunc 7: Alias of setFlagsOR or alternative flag bank
    setFlagsORAlternative(mask, which) {
        callVFunc(this.ptr, 7, "void", ["uint32", "uint32"], [mask, which], 'setFlagsORAlternative');
    }

    // vfunc 11: IsHiddenOrDestroyed
    isHiddenOrDestroyed() {
        return callVFunc(this.ptr, 11, "bool", [], 'isHiddenOrDestroyed');
    }

    // vfunc 40: Get count of child entities
    getChildCount() {
        return callVFunc(this.ptr, 40, "int", [], 'getChildCount');
    }

    // vfunc 41: Get child entity at index
    getChild(index) {
        const outChild = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 41, "void", ["uint32", "pointer"], [index, outChild], 'getChild');
        const childPtr = outChild.readPointer();
        return childPtr.isNull() ? null : new CEntity(childPtr);
    }

    // vfunc 42: Get parent entity
    getParent() {
        const outParent = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 42, "void", ["pointer"], [outParent], 'getParent');
        const parentPtr = outParent.readPointer();
        return parentPtr.isNull() ? null : new CEntity(parentPtr);
    }

    // vfunc 78: Get local position
    getLocalPos(flags = 0) {
        const outPos = Memory.alloc(24); // sizeof(Vec3)
        callVFunc(this.ptr, 78, "void", ["pointer", "uint32"], [outPos, flags], 'getLocalPos');
        const x = outPos.readDouble();
        const y = outPos.add(8).readDouble();
        const z = outPos.add(16).readDouble();
        return new DVec3(x, y, z);
    }

    get localPos() {
        return this.getLocalPos(0);
    }

    // vfunc 89: Get world position
    getWorldPos(flags = 0) {
        try {
            const outPos = Memory.alloc(24); // sizeof(Vec3)
            callVFunc(this.ptr, 89, "void", ["pointer", "uint32"], [outPos, flags], 'getWorldPos');
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

    // Virtual slot 104: GetComponentAddrById
    // Signature: uintptr_t* GetComponentAddrById(uintptr_t* component_addr, uint16_t* component_id)
    getComponentAddrById(componentId) {
        try {
            // Allocate memory for output component address (pointer size)
            const componentAddrPtr = Memory.alloc(PTR_SIZE);

            // Allocate memory for component ID parameter
            const componentIdPtr = Memory.alloc(2);
            componentIdPtr.writeU16(componentId);

            // Call virtual function at index 104
            const result = callVFunc(
                this.ptr,
                104,
                "pointer",
                ["pointer", "pointer"],
                [componentAddrPtr, componentIdPtr],
                'getComponentAddrById'
            );

            // Read the component address from output parameter
            const componentAddr = componentAddrPtr.readPointer();

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
        return ptr.isNull() ? null : new CRenderProxy(ptr);
    }

    // NEW: High-level method to add a glow effect
    addGlow(glowParams = { r: 1.0, g: 0.0, b: 0.0 }, slotIndex = -1, glowStyle = 0) {
        try {
            const pRenderProxy = this.renderProxy;
            if (!pRenderProxy) {
                // console.log(`[!] Entity ${this.ptr} has no RenderProxy component.`);
                return;
            }

            // Perform the game's safety checks
            const isHandleValidFunc = new NativeFunction(Module.findBaseAddress("StarCitizen.exe").add(0x30EC00), 'bool', ['pointer']);
            if (!isHandleValidFunc(pRenderProxy.renderHandlePtr)) {
                // console.log(`[!] Entity ${this.ptr} has an invalid render handle.`);
                return;
            }

            if (this.isHiddenOrDestroyed()) {
                // console.log(`[!] Entity ${this.ptr} is hidden or being destroyed.`);
                return;
            }

            // If checks pass, call the glow function on the sub-object
            pRenderProxy.componentRender.addGlow(glowParams, glowStyle, slotIndex);

        } catch (e) {
            console.log(`[!] Error in addGlow for entity ${this.ptr}: ${e.message}`);
        }
    }

    // vfunc 201: Get zone this entity is in
    getZone() {
        const ptr = callVFunc(this.ptr, 201, "pointer", [], [], 'getZone');
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // vfunc 203: Get zone hosted by this entity
    get hostedZone() {
        const ptr = callVFunc(this.ptr, 205, "pointer", [], [], 'hostedZone');
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 206: Set local transform
    setLocalTransform(targetZone, transform, flags) {
        callVFunc(this.ptr, 206, "void", ["pointer", "pointer", "uint32"], [targetZone, transform, flags], 'setLocalTransform');
    }

    get healthComponent() {
        let comp_ptr = ptr(0);
        try {
            comp_ptr = this.getComponentByName('CSCBodyHealthComponent');
        } catch (e) {}
        return comp_ptr.isNull() ? null : new CHealthComponent(comp_ptr);
    }

}

// Wrapper for CEntityArray<T> where T = CEntity*
class CEntityArray {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // max_size_ at 0x00
    get maxSize() {
        return this.ptr.readS64();
    }

    // curr_size_ at 0x08
    get currSize() {
        return this.ptr.add(0x08).readS64();
    }

    // data_ pointer at 0x18
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
            const e = this.at(i);
            if (e) out.push(e);
        }
        return out;
    }
}

// Wrapper for CEntityClassRegistry
class CEntityClassRegistry {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // vtable index 4 => FindClass(const char*): CEntityClass*
    findClass(name) {
        // allocate native CString
        const nameBuf = Memory.allocUtf8String(name);
        const clsPtr = callVFunc(
            this.ptr,
            4,
            "pointer",
            ["pointer"],
            [nameBuf],
        );
        return clsPtr.isNull() ? null : new CEntityClass(extractLower48(clsPtr));
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
        console.log("Retrieving all registered entity classes...");
        console.log(`Target: ${Process.arch}, Pointer Size: ${PTR_SIZE} bytes.`);

        try {
            console.log(`CEntityClassRegistry instance address: ${this.ptr}`);

            // Logic to find the map's head and size based on C++ code.
            // The pointer to the head node of the std::map's internal tree is at offset 0x28.
            const headNodePtrOffset = 0x28;
            const mapHeadNodePtrPtr = this.ptr.add(headNodePtrOffset); // Address of the pointer to the head node
            const mapHeadNodePtr = mapHeadNodePtrPtr.readPointer(); // The actual head node pointer
            if (mapHeadNodePtr.isNull()) {
                console.error("Error: Map's _Head node pointer (at registry_addr+0x28) is NULL.");
                return [];
            }
            console.log(`Map _Head node address: ${mapHeadNodePtr}`);

            // The size of the map is typically stored right after the head pointer in MSVC std::map's _Tree.
            const mapSizeOffset = headNodePtrOffset + PTR_SIZE; // 0x28 + 0x8 = 0x30
            const mapSize = this.ptr.add(mapSizeOffset).readULong();
            console.log(`Map size reported by std::map object: ${mapSize}`);

            if (mapSize.toUInt32() === 0) {
                console.log("Class registry map is empty (size is 0). No classes to retrieve.");
                return [];
            }

            // The actual root of the Red-Black tree is _Head->_Parent.
            // _Parent is at offset 0x08 (1 * PTR_SIZE) from any node pointer.
            const parentOffsetInNode = 1 * PTR_SIZE;
            const treeRootPtr = mapHeadNodePtr.add(parentOffsetInNode).readPointer();
            if (treeRootPtr.isNull()) {
                console.error("Error: Tree root pointer (_Head->_Parent) is NULL. Map might be malformed or empty in an unusual way.");
                return [];
            }
            console.log(`Tree root node address: ${treeRootPtr}`);

            const classes = [];
            this.traverseRBTree(treeRootPtr, mapHeadNodePtr, (className, classPtr) => {
                const classInst = new CEntityClass(classPtr);
                classes.push({
                    name: className,
                    ptr: classPtr,
                    flags: classInst.flags,
                    instance: classInst
                });
            });

            if (classes.length !== mapSize.toUInt32()) {
                console.warn(`Warning: Number of traversed classes (${classes.length}) does not match map's reported size (${mapSize}). Traversal might be incomplete or map structure assumptions might be slightly off.`);
            } else {
                console.log(`Successfully retrieved ${classes.length} classes.`);
            }

            return classes;

        } catch (e) {
            console.error(`Critical Error during class retrieval: ${e.message}`);
            if (e.stack) {
                console.error("Stack Trace:\n" + e.stack);
            }
            return [];
        }
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

// Wrapper for CEntitySystem (size: 0x06E0)
class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // entity_array_ at offset 0x0118
    get entityArray() {
        // Offset from CEntitySystem in StarCitizenClasses.hpp
        const arrPtr = this.ptr.add(0x0118);
        return new CEntityArray(arrPtr);
    }

    // entity_class_registry_ at 0x06D8
    get classRegistry() {
        // Offset from CEntitySystem in StarCitizenClasses.hpp
        const registryPtr = this.ptr.add(0x06D8).readPointer();
        return new CEntityClassRegistry(registryPtr);
    }

    // Virtual slot 24 => GetClassRegistry(): CEntityClassRegistry*
    getClassRegistryV() {
        const ptr = callVFunc(this.ptr, 24, "pointer", []);
        return ptr.isNull() ? null : new CEntityClassRegistry(ptr);
    }

    // Convenience: find class by name via built-in registry
    getClassByName(name) {
        return this.classRegistry.findClass(name);
    }

    // Direct call to spawn entity function (CreateEntityOfType)
    spawnEntity(entityParams) {
        // RVA for CreateEntityOfType
        const moduleBase = Process.enumerateModulesSync()[0].base;
        const spawnFuncAddr = moduleBase.add(0x65F5EC0);

        // Create native function directly
        const spawnFunc = new NativeFunction(spawnFuncAddr, "bool", ["pointer", "pointer"]);

        // Call with this pointer and entityParams
        return spawnFunc(this.ptr, entityParams);
    }

    // Helper method to create and spawn an entity by class name
    createEntity(className, spawnParams = {}) {
        try {
            // Get the entity class
            const entityClass = this.getClassByName(className);
            if (!entityClass) {
                console.log(`[!] Could not find entity class: ${className}`);
                return null;
            }

            // Allocate memory for spawn parameters structure
            const paramsPtr = Memory.alloc(0x200);
            paramsPtr.writeByteArray(new Array(0x200).fill(0));

            // Set entity class pointer at offset 0x00
            paramsPtr.writePointer(entityClass.ptr);

            // Set parent entity at offset 0x13 * 8 = 0x98 (based on the check in decompiled code)
            if (spawnParams.parent) {
                paramsPtr.add(0x98).writePointer(spawnParams.parent);
                // Also set at offset 0x8 * 8 = 0x40 (zone/context field)
                paramsPtr.add(0x40).writePointer(spawnParams.parent);
            }

            // Set entity name at offset 0x17 * 8 = 0xB8
            if (spawnParams.name) {
                const namePtr = Memory.allocUtf8String(spawnParams.name);
                paramsPtr.add(0xB8).writePointer(namePtr);
            }

            // Set flags at offset 0x18 * 8 = 0xC0
            if (spawnParams.flags !== undefined) {
                paramsPtr.add(0xC0).writeU64(spawnParams.flags);
            }

            // Call the spawn function
            const success = this.spawnEntity(paramsPtr);

            if (success) {
                console.log(`[+] Successfully spawned entity of class: ${className}`);
                return true;
            } else {
                console.log(`[!] Failed to spawn entity of class: ${className}`);
                return false;
            }

        } catch (e) {
            console.log(`[!] Error creating entity: ${e.message}`);
            return false;
        }
    }
}

class CRenderer {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // ProjectToScreen implementation - vtable slot 66
    projectToScreen(pos, resolution = { x: 1920.0, y: 1080.0 }, isPlayerViewportRelative = false) {
        // Allocate memory for output Vector3
        const outVec = Memory.alloc(4 * 3); // 3 floats (x, y, z)
        const outX = outVec;
        const outY = outVec.add(4);
        const outZ = outVec.add(8);

        // Call the native ProjectToScreen function (vtable slot 66)
        const result = callVFunc(
            this.ptr,
            66,
            "bool",
            ["double", "double", "double", "pointer", "pointer", "pointer", "bool", "int64"],
            [pos.x, pos.y, pos.z, outX, outY, outZ, isPlayerViewportRelative ? 1 : 0, 0]
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

// Wrapper for global environment GEnv (size: 0x440)
class GEnv {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // game_ at 0x98
    get game() {
        const ptr = this.ptr.add(0x98).readPointer();
        return ptr.isNull() ? null : new CGame(ptr);
    }

    // entity_system_ at 0x00A0
    get entitySystem() {
        const sysPtr = this.ptr.add(0x00a0).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }

    // engine_component_scheduler_ at 0x00A8
    get engineComponentScheduler() {
        const ptr = this.ptr.add(0x00A8).readPointer();
        return ptr.isNull() ? null : new CEngineComponentScheduler(ptr);
    }

    // system_ at 0xC0
    get cSystem() {
        const ptr = this.ptr.add(0xc0).readPointer();
        return ptr.isNull() ? null : new CSystem(ptr);
    }

    // renderer_ at 0xF8
    get cRenderer() {
        const ptr = this.ptr.add(0xf8).readPointer();
        return ptr.isNull() ? null : new CRenderer(ptr);
    }

    // zone_system_ at 0x8 (Note: Not present in provided C++ GEnv struct, may be outdated)
    get cZoneSystem() {
        const ptr = this.ptr.add(0x8).readPointer();
        return ptr.isNull() ? null : new CZoneSystem(ptr);
    }
}

// Wrapper for CGame
class CGame {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // player_ at 0x0C08
    get player() {
        // UPDATED: Offset from CGame in StarCitizenClasses.hpp
        const ptr = this.ptr.add(0x0C08).readPointer();
        return ptr.isNull() ? null : new CSCPlayer(ptr);
    }
}

// Wrapper for CSCPlayer
class CSCPlayer {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // owning_entity_ at 0x08
    get owningEntity() {
        const ptr = this.ptr.add(0x08).readPointer();
        return ptr.isNull() ? null : new CEntity(ptr);
    }

    // name_ at 0x3E8
    get name() {
        const namePtr = this.ptr.add(0x3E8).readPointer();
        return readCString(namePtr);
    }
}

// === Main polling loop ===

// UPDATED: RVA for GEnv from SCOffsets
const GENV_ADDR = Process.enumerateModules()[0].base.add("0x9AF6720");
const gEnv = new GEnv(GENV_ADDR);

console.log("[*] Frida Entity System bridge initialized.");

rpc.exports.getGEnv = () => gEnv;

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
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        // Get the source class pointer
        const fromClass = entitySystem.getClassByName(fromClassName);
        if (!fromClass) {
            console.log(`[!] Source class '${fromClassName}' not found`);
            return { success: false, error: `Source class '${fromClassName}' not found` };
        }

        // Get the target class pointer
        const toClass = entitySystem.getClassByName(toClassName);
        if (!toClass) {
            console.log(`[!] Target class '${toClassName}' not found`);
            return { success: false, error: `Target class '${toClassName}' not found` };
        }

        console.log(`[*] Replacing entities from class '${fromClassName}' (${fromClass.ptr}) to '${toClassName}' (${toClass.ptr})`);

        // Find all entities with the source class type
        const allEntities = entitySystem.entityArray.toArray();
        const matchingEntities = allEntities.filter(entity => {
            try {
                const entityClass = entity.entityClass;
                if (!entityClass) return false;
                return entityClass.ptr.equals(fromClass.ptr);
            } catch (e) {
                return false;
            }
        });

        console.log(`[*] Found ${matchingEntities.length} entities with class '${fromClassName}'`);

        let successCount = 0;
        let errorCount = 0;

        // Replace the class pointer for each matching entity
        for (const entity of matchingEntities) {
            try {
                // Get world position and calculate distance before making changes
                const worldPos = entity.worldPos;
                const distance = calculateDistance(entity);

                // Write the new class pointer to the entity_class_ field at offset 0x20
                entity.ptr.add(0x20).writePointer(toClass.ptr);
                successCount++;
                console.log(`[+] Successfully changed class for entity ${entity.ptr} (ID: ${entity.id}) at position (${worldPos.x.toFixed(2)}, ${worldPos.y.toFixed(2)}, ${worldPos.z.toFixed(2)}) distance: ${distance.toFixed(2)}m`);
            } catch (e) {
                errorCount++;
                console.log(`[!] Failed to change class for entity ${entity.ptr}: ${e.message}`);
            }
        }

        const result = {
            success: true,
            fromClass: fromClassName,
            toClass: toClassName,
            totalFound: matchingEntities.length,
            successCount: successCount,
            errorCount: errorCount
        };

        console.log(`[*] Class replacement complete: ${successCount} successful, ${errorCount} failed`);
        return result;

    } catch (e) {
        console.log(`[!] Error during class replacement: ${e.message}`);
        return { success: false, error: e.message };
    }
};

// RPC method to replace entity class types using regex pattern
rpc.exports.replaceEntityClassTypeRegex = function(fromClassRegex, toClassName) {
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
        // Default spawn parameters
        const spawnParams = {
            name: options.name || `Spawned_${className}_${Date.now()}`,
            flags: options.flags || 0,
            zone: options.zone || null,
            parent: options.parent || null,
            ...options
        };

        console.log(`[*] Attempting to spawn entity of class '${className}' with params:`, spawnParams);

        const result = entitySystem.createEntity(className, spawnParams);

        if (result) {
            console.log(`[+] Successfully spawned entity of class '${className}'`);
            return {
                success: true,
                className: className,
                spawnParams: spawnParams
            };
        } else {
            console.log(`[!] Failed to spawn entity of class '${className}'`);
            return {
                success: false,
                error: "Spawn function returned false",
                className: className
            };
        }

    } catch (e) {
        console.log(`[!] Error spawning entity of class '${className}': ${e.message}`);
        return {
            success: false,
            error: e.message,
            className: className
        };
    }
};

rpc.exports.makeCorpsesLootable = () => rpc.exports.replaceEntityClassType("PlayerCorpse", "PU_Pilots-Human-Criminal-Gunner_Light");

// RPC method to replace a single entity's class type by pointer
rpc.exports.replaceEntityClass = function(entityPtr, newClassName) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        // Parse the entity pointer
        const entityPointer = ptr(entityPtr);
        if (entityPointer.isNull()) {
            console.log("[!] Invalid entity pointer provided");
            return { success: false, error: "Invalid entity pointer" };
        }

        // Get the target class
        const newClass = entitySystem.getClassByName(newClassName);
        if (!newClass) {
            console.log(`[!] Target class '${newClassName}' not found`);
            return { success: false, error: `Target class '${newClassName}' not found` };
        }

        // Create entity wrapper to get current info
        const entity = new CEntity(entityPointer);
        const originalClass = entity.entityClass;
        const originalClassName = originalClass ? originalClass.name : "<unknown>";

        console.log(`[*] Replacing entity ${entityPtr} class from '${originalClassName}' to '${newClassName}'`);

        // Get position info for logging
        const worldPos = entity.worldPos;
        const distance = calculateDistance(entity);

        // Write the new class pointer to the entity_class_ field at offset 0x20
        entity.ptr.add(0x20).writePointer(newClass.ptr);

        console.log(`[+] Successfully changed class for entity ${entityPtr} (ID: ${entity.id}) from '${originalClassName}' to '${newClassName}'`);
        console.log(`    Position: (${worldPos.x.toFixed(2)}, ${worldPos.y.toFixed(2)}, ${worldPos.z.toFixed(2)}) Distance: ${distance.toFixed(2)}m`);

        return {
            success: true,
            entityPtr: entityPtr,
            originalClass: originalClassName,
            newClass: newClassName,
            entityId: entity.id,
            position: {
                x: worldPos.x,
                y: worldPos.y,
                z: worldPos.z
            },
            distance: distance
        };

    } catch (e) {
        console.log(`[!] Error replacing entity class: ${e.message}`);
        return { success: false, error: e.message };
    }
};

// RPC method to list all entities within a specific distance, sorted by distance
rpc.exports.listEntitiesInRange = function(maxDistance = 100) {
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

        const allEntities = entitySystem.entityArray.toArray();
        const entitiesInRange = [];

        // Filter entities by distance and collect metrics
        for (const entity of allEntities) {
            try {
                const distance = calculateDistance(entity);
                if (distance <= maxDistance && !(distance >= 1.7 && distance <= 7.9)) {
                    const angles = calculateAngles(entity);
                    const worldPos = entity.worldPos;
                    const className = entity.entityClass ? entity.entityClass.name : "<unknown>";
                    const name = entity.name || "<no-name>";

                    entitiesInRange.push({
                        entity: entity,
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
                `${(index + 1).toString().padStart(3, ' ')}. [${item.entity.ptr}] [ID ${item.entity.id}] Class: ${item.className}\n` +
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
                id: item.entity.id,
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

rpc.exports.getEntityComponentData = function(entityPtr, componentName) {
    try {
        const entity = new CEntity(ptr(entityPtr));
        const componentPtr = entity.getComponentByName(componentName);

        if (!componentPtr || componentPtr.isNull()) {
            return {
                success: false,
                error: `Component '${componentName}' not found on entity`
            };
        }

        const component = createComponentWrapper(componentPtr, componentName);

        // Extract component-specific data based on type
        const componentData = {
            name: componentName,
            ptr: componentPtr.toString(),
            owningEntity: component.owningEntity ? component.owningEntity.ptr.toString() : "null"
        };

        // Add type-specific data
        if (component instanceof CEntityComponentInventory) {
            componentData.maxMicroSCU = component.maxMicroSCU;
            componentData.currentMicroSCU = component.currentMicroSCU;
        }

        return {
            success: true,
            entityPtr: entityPtr,
            component: componentData
        };
    } catch (e) {
        return { success: false, error: e.message };
    }
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
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) {
        console.log("[!] Entity system not available");
        return { success: false, error: "Entity system not available" };
    }

    try {
        // Compile the regex pattern
        const regex = new RegExp(classNameRegex);
        console.log(`[*] Compiled regex pattern: ${classNameRegex}`);

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

        console.log(`[*] Found ${matchingEntities.length} entities matching pattern '${classNameRegex}'`);
        console.log(`[*] Matched class names: ${Array.from(matchedClassNames).join(', ')}`);

        let successCount = 0;
        let errorCount = 0;
        const processedClasses = {};

        // Add glow effect to each matching entity
        for (const entity of matchingEntities) {
            try {
                const className = entity.entityClass.name;
                const distance = calculateDistance(entity);

                // Add glow effect using the entity's addGlow method
                entity.addGlow(glowParams, -1, glowId);
                successCount++;

                // Track processed classes for reporting
                if (!processedClasses[className]) {
                    processedClasses[className] = 0;
                }
                processedClasses[className]++;

                console.log(`[+] Added glow to entity ${entity.ptr} (ID: ${entity.id}) class '${className}' at distance ${distance.toFixed(2)}m`);
            } catch (e) {
                errorCount++;
                console.log(`[!] Failed to add glow to entity ${entity.ptr}: ${e.message}`);
            }
        }

        const result = {
            success: true,
            classNameRegex: classNameRegex,
            glowParams: glowParams,
            glowId: glowId,
            matchedClassNames: Array.from(matchedClassNames),
            processedClasses: processedClasses,
            totalFound: matchingEntities.length,
            successCount: successCount,
            errorCount: errorCount
        };

        console.log(`[*] Glow effect application complete: ${successCount} successful, ${errorCount} failed`);
        console.log(`[*] Processed classes breakdown:`, processedClasses);
        return result;

    } catch (e) {
        console.log(`[!] Error adding glow to entities: ${e.message}`);
        return { success: false, error: e.message };
    }
};

// Frida hook for add_glow_effect function at 0x14038DCA0
const hookAddGlowEffect = () => {
    try {
        const moduleBase = Process.enumerateModulesSync()[0].base;
        const addGlowEffectAddr = moduleBase.add(0x38DCA0);

        console.log(`[*] Hooking add_glow_effect at: ${addGlowEffectAddr}`);

        Interceptor.attach(addGlowEffectAddr, {
            onEnter: function(args) {
                this.pGlowObject = args[0];
                this.pGlowConfig = args[1];
                this.glowId = args[2].toInt32();

                let output = `[HOOK] add_glow_effect called:\n`;
                output += `  p_glow_object: ${this.pGlowObject}\n`;
                output += `  p_glow_config: ${this.pGlowConfig}\n`;
                output += `  glow_id: ${this.glowId}\n`;

                // Read glow config data if pointer is valid
                if (this.pGlowConfig && !this.pGlowConfig.isNull()) {
                    try {
                        // Assuming glow config contains RGB values as first 3 bytes
                        const r = this.pGlowConfig.readU8();
                        const g = this.pGlowConfig.add(1).readU8();
                        const b = this.pGlowConfig.add(2).readU8();
                        output += `  glow_config RGB: (${r}, ${g}, ${b})\n`;
                    } catch (e) {
                        output += `  glow_config: [Unable to read: ${e.message}]\n`;
                    }
                }

                // Print stack trace
                output += `  Stack trace:\n`;
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .forEach((symbol, index) => {
                        output += `    ${index.toString().padStart(2, ' ')}: ${symbol.address} ${symbol.name || '<unknown>'}\n`;
                    });

                console.log(output);
            },

            onLeave: function(retval) {
                console.log(`[HOOK] add_glow_effect returned: ${retval}`);
            }
        });

        console.log("[*] add_glow_effect hook installed successfully");

    } catch (e) {
        console.log(`[!] Failed to hook add_glow_effect: ${e.message}`);
    }
};

// RPC export to enable/disable the hook
rpc.exports.hookAddGlowEffect = hookAddGlowEffect;

// Frida hook for function at 0x4C8900
const hookSub1404C8900 = () => {
    try {
        const moduleBase = Process.enumerateModulesSync()[0].base;
        const funcAddr = moduleBase.add(0x4C8900);

        console.log(`[*] Hooking sub_1404C8900 at: ${funcAddr}`);

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.a1 = args[0];
                this.a2 = args[1];
                this.a3 = args[2];

                let output = `[HOOK] sub_1404C8900 called:\n`;
                output += `  a1: ${this.a1}\n`;
                output += `  a2 (QWORD*): ${this.a2}\n`;
                output += `  a3 (char**): ${this.a3}\n`;

                // Try to read the QWORD value if a2 is valid
                if (this.a2 && !this.a2.isNull()) {
                    try {
                        const qwordValue = this.a2.readU64();
                        output += `  *a2 (QWORD value): 0x${qwordValue.toString(16)}\n`;
                    } catch (e) {
                        output += `  *a2: [Unable to read: ${e.message}]\n`;
                    }
                }

                // Try to read the char* pointer if a3 is valid
                if (this.a3 && !this.a3.isNull()) {
                    try {
                        const charPtr = this.a3.readPointer();
                        if (charPtr && !charPtr.isNull()) {
                            const stringValue = charPtr.readCString();
                            output += `  *a3 (char*): "${stringValue || '[empty/null string]'}"\n`;
                        } else {
                            output += `  *a3 (char*): [null pointer]\n`;
                        }
                    } catch (e) {
                        output += `  *a3: [Unable to read: ${e.message}]\n`;
                    }
                }

                // Print stack trace
                output += `  Stack trace:\n`;
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .slice(0, 10) // Limit to first 10 frames
                    .forEach((symbol, index) => {
                        output += `    ${index.toString().padStart(2, ' ')}: ${symbol.address} ${symbol.name || '<unknown>'}\n`;
                    });

                console.log(output);
            },

            onLeave: function(retval) {
                console.log(`[HOOK] sub_1404C8900 returned: ${retval.toInt32()} (char)`);
            }
        });

        console.log("[*] sub_1404C8900 hook installed successfully");

    } catch (e) {
        console.log(`[!] Failed to hook sub_1404C8900: ${e.message}`);
    }
};

// RPC export to enable the hook
rpc.exports.hookSub1404C8900 = hookSub1404C8900;

// Frida hook for CRigidEntity::ApplyStateFromNetwork function
const hookApplyStateFromNetwork = () => {
    try {
        const moduleBase = Process.enumerateModulesSync()[0].base;

        // You'll need to replace this with the actual RVA for CRigidEntity::ApplyStateFromNetwork
        // This is a placeholder - find the actual address from your analysis
        const funcAddr = moduleBase.add(0x6782C30);

        console.log(`[*] Hooking CRigidEntity::ApplyStateFromNetwork at: ${funcAddr}`);

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.a1 = args[0]; // _QWORD *a1 (CRigidEntity*)
                this.a2 = args[1]; // __int64 a2

                let output = `[HOOK] CRigidEntity::ApplyStateFromNetwork called:\n`;
                output += `  a1 (CRigidEntity*): ${this.a1}\n`;
                output += `  a2 (__int64): ${this.a2} (0x${this.a2.toString(16)})\n`;

                // Dump interesting fields from a1 (CRigidEntity)
                if (this.a1 && !this.a1.isNull()) {
                    try {
                        // a1[0x41] & 0x40000000 check
                        const flagsAt0x41 = this.a1.add(0x41 * 8).readU64();
                        output += `  a1[0x41] (flags): 0x${flagsAt0x41.toString(16)}\n`;
                        output += `  a1[0x41] & 0x40000000: ${(flagsAt0x41.toNumber() & 0x40000000) !== 0}\n`;

                        // *((_BYTE *)a1 + 0x94E) check
                        const byteAt0x94E = this.a1.add(0x94E).readU8();
                        output += `  *((_BYTE *)a1 + 0x94E): ${byteAt0x94E}\n`;

                        // *((float *)a1 + 0x252) check
                        const floatAt0x252 = this.a1.add(0x252 * 4).readFloat();
                        output += `  *((float *)a1 + 0x252): ${floatAt0x252}\n`;

                        // *((unsigned __int8 *)a1 + 0x94D) check
                        const byteAt0x94D = this.a1.add(0x94D).readU8();
                        output += `  *((unsigned __int8 *)a1 + 0x94D): ${byteAt0x94D}\n`;

                        // a1[0x11D] check
                        const qwordAt0x11D = this.a1.add(0x11D * 8).readU64();
                        output += `  a1[0x11D]: 0x${qwordAt0x11D.toString(16)}\n`;

                        // Lock field at a1 + 0x11E
                        const lockField = this.a1.add(0x11E * 8).readU64();
                        output += `  a1[0x11E] (m_netDesiredStateLock): 0x${lockField.toString(16)}\n`;

                    } catch (e) {
                        output += `  [Error reading a1 fields: ${e.message}]\n`;
                    }
                }

                // Print stack trace
                output += `  Stack trace:\n`;
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .slice(0, 8) // Limit to first 8 frames
                    .forEach((symbol, index) => {
                        output += `    ${index.toString().padStart(2, ' ')}: ${symbol.address} ${symbol.name || '<unknown>'}\n`;
                    });

                console.log(output);
            },

            onLeave: function(retval) {
                console.log(`[HOOK] CRigidEntity::ApplyStateFromNetwork returned: 0x${retval.toString(16)} (${retval})`);
            }
        });

        console.log("[*] CRigidEntity::ApplyStateFromNetwork hook installed successfully");

    } catch (e) {
        console.log(`[!] Failed to hook CRigidEntity::ApplyStateFromNetwork: ${e.message}`);
    }
};

// RPC export to enable the hook
rpc.exports.hookApplyStateFromNetwork = hookApplyStateFromNetwork;
