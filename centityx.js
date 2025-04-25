// frida-script.js
//
// Frida script to mirror the game’s C++ entity system in idiomatic JavaScript,
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
    get worldPos() {
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
    get zonePtr() {
        return this.ptr.add(0x2a8).readPointer();
    }

    // Virtual slot 0 => Function0
    function0() {
        callVFunc(this.ptr, 0, "void", []);
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
}

// === Main polling loop ===

// Replace with the actual static address of GEnv
const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x981D200");
const gEnv = new GEnv(GENV_ADDR);

console.log("[*] Frida Entity System bridge initialized.");

const run = () => {
    const es = gEnv.entitySystem;
    if (!es) {
        console.log("[!] entity_system not yet available");
        return;
    }

    console.log("[*] Enumerating all entities...");
    const allEntities = es.entityArray.toArray();
    //console.log(allEntities);
    console.log(`    → Found ${allEntities.length} entities`);

    console.log("[*] Looking up Player class...");
    const playerClass = es.getClassByName("Player");
    if (!playerClass) {
        console.log("    [!] Could not find Player class");
        return;
    }
    console.log(`    → Player class at ${playerClass.ptr}`);

    console.log("[*] Filtering Player entities...");
    const players = allEntities.filter((ent) => {
        try {
            const cls = ent.entityClass;
            return cls && cls.ptr.equals(playerClass.ptr);
        } catch (e) {
            return false;
        }
    });

    console.log(`    → Found ${players.length} Player entities`);
    for (const p of players) {
        const pos = p.worldPos;
        console.log(
            `        [${p.ptr}] [ID ${p.id}] ${p.name || "<no-name>"} @ (${pos.x.toFixed(2)}, ${pos.y.toFixed(2)}, ${pos.z.toFixed(2)})`,
        );
    }
};

const dump = () => {
    const es = gEnv.entitySystem;
    if (!es) {
        console.log("[!] entity_system not yet available");
        return;
    }

    console.log("[*] Enumerating all entities...");
    const allEntities = es.entityArray.toArray();
    //console.log(allEntities);
    console.log(`    → Found ${allEntities.length} entities`);

    const x = [];

    const filterRgx = /.*?(ObjectContainer|Audio|Light|NavPoint|Rotation|AreaBox).*?/;

    for (const e of allEntities) {
        try {
            const pos = e.worldPos;
            const className = e.entityClass.name;

            if (!pos) continue;
            if ((pos.x + pos.y + pos.z) > 2000) continue;
            if (filterRgx.test(className)) continue;

            x.push([e.entityClass.name, e.id, e.name, e.flags, pos]);
        } catch (e) {
        }
    }

    // dump to filtered entities
    const file = new File("entities.json", "w");
    file.write(JSON.stringify(x, null, 4));
    file.close();

    console.log(`[*] Wrote ${x.length} entities`);
};

rpc.exports.run = run;
rpc.exports.dump = dump;

// Keep the script running
