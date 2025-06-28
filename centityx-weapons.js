// frida-script.js
//
// Frida script to mirror the game's C++ entity system in idiomatic JavaScript,
// providing rich, object-oriented wrappers around native memory structures.

"use strict";

const PTR_SIZE = Process.pointerSize;

// Helper to extract lower 48 bits of a pointer
function extractLower48(ptrVal) {
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

// Helper to read a C-style UTF-8 string pointer
function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
}

// Helper to call a virtual method by vtable index
function callVFunc(thisPtr, index, returnType, argTypes, args = []) {
    const vtable = thisPtr.readPointer();
    const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
    const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
    return fn(thisPtr, ...args);
}

// Vector3 struct
class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    distanceTo(other) {
        const dx = this.x - other.x;
        const dy = this.y - other.y;
        const dz = this.z - other.z;
        return Math.sqrt(dx*dx + dy*dy + dz*dz);
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

// Wrapper for CZone (size: 0x513D0)
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
        return nextPtr.isNull() ? null : new CZone(nextPtr);
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
    getFirstZone() {
        const ptr = callVFunc(this.ptr, 13, "pointer", []);
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }
}

// Wrapper for CEntity (size: 0xA10)
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

    // c_entity_class_ at 0x20 (CEntityClass*)
    get entityClassPtr() {
        const raw = this.ptr.add(0x20).readPointer();
        return extractLower48(raw);
    }

    get entityClass() {
        const clsPtr = this.entityClassPtr;
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }

    // world-local position doubles at offsets 0xF0, 0xF8, 0x100
    get zonePos() {
        const x = this.ptr.add(0xf0).readDouble();
        const y = this.ptr.add(0xf8).readDouble();
        const z = this.ptr.add(0x100).readDouble();
        return new DVec3(x, y, z);
    }

    // name_ at 0x290 (const char*)
    get name() {
        const namePtr = this.ptr.add(0x290).readPointer();
        return readCString(namePtr);
    }

    // zone_ at 0x2A8 (CZone*)
    get zone() {
        const ptr = this.ptr.add(0x2a8).readPointer();
        return ptr.isNull() ? null : new CZone(extractLower48(ptr));
    }

    // Virtual slot 0 => Function0
    function0() {
        callVFunc(this.ptr, 0, "void", []);
    }

    // vfunc 6: Set entity flags using OR operation
    setFlagsOR(mask, which) {
        callVFunc(this.ptr, 6, "void", ["uint32", "uint32"], [mask, which]);
    }

    // vfunc 7: Alias of setFlagsOR or alternative flag bank
    setFlagsORAlternative(mask, which) {
        callVFunc(this.ptr, 7, "void", ["uint32", "uint32"], [mask, which]);
    }

    // vfunc 40: Get count of child entities
    getChildCount() {
        return callVFunc(this.ptr, 40, "int", []);
    }

    // vfunc 41: Get child entity at index
    getChild(index) {
        const outChild = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 41, "void", ["uint32", "pointer"], [index, outChild]);
        const childPtr = outChild.readPointer();
        return childPtr.isNull() ? null : new CEntity(childPtr);
    }

    // vfunc 42: Get parent entity
    getParent() {
        const outParent = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 42, "void", ["pointer"], [outParent]);
        const parentPtr = outParent.readPointer();
        return parentPtr.isNull() ? null : new CEntity(parentPtr);
    }

    // vfunc 78: Get local position
    getLocalPos(flags = 0) {
        const outPos = Memory.alloc(24); // sizeof(Vec3)
        callVFunc(this.ptr, 78, "void", ["pointer", "uint32"], [outPos, flags]);
        const x = outPos.readDouble();
        const y = outPos.add(8).readDouble();
        const z = outPos.add(16).readDouble();
        return new DVec3(x, y, z);
    }

    get localPos() {
        return this.getLocalPos(0);
    }

    // vfunc 88: Get world position
    getWorldPos(flags = 0) {
        const outPos = Memory.alloc(24); // sizeof(Vec3)
        callVFunc(this.ptr, 88, "void", ["pointer", "uint32"], [outPos, flags]);
        const x = outPos.readDouble();
        const y = outPos.add(8).readDouble();
        const z = outPos.add(16).readDouble();
        return new DVec3(x, y, z);
    }

    get worldPos() {
        return this.getWorldPos(0);
    }

    // vfunc 103: Get component by type ID
    getComponentByTypeID(typeId) {
        const outHandle = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 103, "void", ["int16", "pointer"], [typeId, outHandle]);
        const compPtr = outHandle.readPointer();
        return compPtr.isNull() ? null : compPtr; // Return raw pointer, would need component wrapper
    }

    // vfunc 199: Get zone this entity is in
    get zone() {
        const ptr = callVFunc(this.ptr, 199, "pointer", []);
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 203: Get zone hosted by this entity
    get hostedZone() {
        const ptr = callVFunc(this.ptr, 203, "pointer", []);
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 206: Set local transform
    setLocalTransform(targetZone, transform, flags) {
        callVFunc(this.ptr, 206, "void", ["pointer", "pointer", "uint32"], [targetZone, transform, flags]);
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
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }
}

// Wrapper for CEntitySystem (size: 0x6E0)
class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Direct memory for entity_array_ at offset 0x0118
    get entityArray() {
        const arrPtr = this.ptr.add(0x0118);
        return new CEntityArray(arrPtr);
    }

    // entity_class_registry_ at 0x06D8
    get classRegistry() {
        const registryPtr = this.ptr.add(0x06d8).readPointer();
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
}

class CRenderer {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // ProjectToScreen implementation - vtable slot 67
    projectToScreen(pos, resolution = { x: 1920.0, y: 1080.0 }, isPlayerViewportRelative = false) {
        // Allocate memory for output Vector3
        const outVec = Memory.alloc(4 * 3); // 3 floats (x, y, z)
        const outX = outVec;
        const outY = outVec.add(4);
        const outZ = outVec.add(8);

        // Call the native ProjectToScreen function (vtable slot 67)
        const result = callVFunc(
            this.ptr,
            66,
            "bool",
            ["double", "double", "double", "pointer", "pointer", "pointer", "bool", "int64"],
            [pos.x, pos.y, pos.z, outX, outY, outZ, isPlayerViewportRelative ? 1 : 0, 0]
        );

        if (result) {
            // Read output values
            const x = outX.readFloat() * (resolution.x * 0.01);
            const y = outY.readFloat() * (resolution.y * 0.01);
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

    // c_entity_system_ at 0x00A0
    get entitySystem() {
        const sysPtr = this.ptr.add(0x00a0).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }

    get cRenderer() {
        const ptr = this.ptr.add(0xf8).readPointer();
        return ptr.isNull() ? null : new CRenderer(ptr);
    }

    get cZoneSystem() {
        const ptr = this.ptr.add(0x8).readPointer();
        return ptr.isNull() ? null : new CZoneSystem(ptr);
    }

    get cSystem() {
        const ptr = this.ptr.add(0xc0).readPointer();
        return ptr.isNull() ? null : new CSystem(ptr);
    }
}

// === Main polling loop ===

// Replace with the actual static address of GEnv
const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x981D200");
const gEnv = new GEnv(GENV_ADDR);

console.log("[*] Frida Entity System bridge initialized.");

const run = () => {
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

    const cs = gEnv.cSystem;
    if (!cs) {
        console.log("[!] cSystem not yet available");
        return;
    }

    const playerClass = es.getClassByName("Player");
    if (!playerClass) {
        console.log("[!] Could not find Player class");
        return;
    }

    console.log("[*] Enumerating all entities...");
    const allEntities = es.entityArray.toArray();
    console.log(`    → Found ${allEntities.length} entities`);

    const entityClasses = new Map();
    for (const ent of allEntities) {
        const cls = ent.entityClass;
        if (!cls) continue;
        const cls_name = cls.name;
        entityClasses.set(cls_name, cls);
    }

    console.log(`    → Found ${entityClasses.size} entity classes`);

    const actorClasses = Array.from(entityClasses.values())
        .filter(cls => cls.name.includes("rifle"))
        .map(cls => cls.name);

    console.log(actorClasses);

    const actorClassPtrs = actorClasses
        .map(cls => entityClasses.get(cls)?.ptr)
        .filter(ptr => ptr);

    console.log("[*] Filtering entities...");
    const players = allEntities.filter((ent) => {
        try {
            const cls = ent.entityClass;
            for (const ptr of actorClassPtrs) {
                if (cls.ptr.equals(ptr)) {
                    return true;
                }
            }
        } catch (e) {}
        return false;
    });

    console.log(`    → Found ${players.length} entities`);

    // Get camera position for distance calculation
    const camPos = cs.cameraWorldPos;

    // Calculate distance and store with the player data
    const playersWithDistance = players.map(p => {
        const pos = p.worldPos;
        const proj = cr.projectToScreen(pos);
        const distance = pos.distanceTo(camPos);
        return { player: p, pos, proj, distance };
    });

    // Sort players by distance (closest first)
    playersWithDistance.sort((a, b) => a.distance - b.distance);

    // Log the sorted players
    for (const { player: p, pos, proj, distance } of playersWithDistance) {
        console.log(
            `        [${p.ptr}] [ID ${p.id}] ${p.name || "<no-name>"} @ (${pos.x.toFixed(1)}, ${pos.y.toFixed(1)}, ${pos.z.toFixed(1)}) | Distance: ${distance.toFixed(1)}m | Screen: (${proj.x.toFixed(1)}, ${proj.y.toFixed(1)})`,
        );
    }
};

// Global exception handler to prevent script crashes
Process.setExceptionHandler((exception) => {
    console.log("=== EXCEPTION CAUGHT ===");
    console.log(`Name: ${exception.name}`);
    console.log(`Message: ${exception.message}`);
    console.log(`Type: ${exception.type}`);
    console.log(`Address: ${exception.address}`);

    // Log stack trace if available
    if (exception.stack) {
        console.log("Stack trace:");
        console.log(exception.stack);
    }

    // Log memory access details for memory-related exceptions
    if (exception.memory) {
        console.log(`Memory operation: ${exception.memory.operation}`);
        console.log(`Memory address: ${exception.memory.address}`);
    }

    console.log("========================");

    // Return true to indicate we've handled the exception
    return true;
});

rpc.exports.run = run;
