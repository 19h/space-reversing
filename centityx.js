// vtable slot 31: Get relative position from camera
// frida-script.js
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

        const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
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

// Wrapper for CEntity (size: 0x02B8)
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

    // x_local_pos_, y_local_pos_, z_local_pos_ at offsets 0xF8, 0x100, 0x108
    get zonePos() {
        const x = this.ptr.add(0xF8).readDouble();
        const y = this.ptr.add(0x100).readDouble();
        const z = this.ptr.add(0x108).readDouble();
        return new DVec3(x, y, z);
    }

    // name_ at 0x298 (const char*)
    get name() {
        const namePtr = this.ptr.add(0x298).readPointer();
        return readCString(namePtr);
    }

    // zone_ at 0x2B0 (CZone*)
    get zoneFromMemory() {
        const ptr = this.ptr.add(0x2B0).readPointer();
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

    // vfunc 89: Get world position (based on C++ offset 0x2C8)
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

    // vfunc 103: Get component by type ID
    getComponentByTypeID(typeId) {
        const outHandle = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 103, "void", ["int16", "pointer"], [typeId, outHandle], 'getComponentByTypeID');
        const compPtr = outHandle.readPointer();
        return compPtr.isNull() ? null : compPtr; // Return raw pointer, would need component wrapper
    }

    // vfunc 199: Get zone this entity is in
    getZone() {
        const ptr = callVFunc(this.ptr, 199, "pointer", [], 'getZone');
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 203: Get zone hosted by this entity
    get hostedZone() {
        const ptr = callVFunc(this.ptr, 203, "pointer", [], 'hostedZone');
        return ptr.isNull() ? null : new CZone(ptr);
    }

    // vfunc 206: Set local transform
    setLocalTransform(targetZone, transform, flags) {
        callVFunc(this.ptr, 206, "void", ["pointer", "pointer", "uint32"], [targetZone, transform, flags], 'setLocalTransform');
    }
}

// Wrapper for CEntityArray<T> where T = CEntity*
class CEntityArray {
    constructor(ptr) {
        this.ptr = ptr;
        console.log(this.ptr);
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
        console.log('findClass');
        const clsPtr = callVFunc(
            this.ptr,
            4,
            "pointer",
            ["pointer"],
            [nameBuf],
        );
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
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
        // 0x20 (_Myval): std::pair<const Key, Value>
        //      0x20 (_Myval.first): Key (e.g., pointer to a string object for class name)
        //      0x28 (_Myval.second): Value (e.g., CEntityClass* pointer)

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
        const keyFieldOffset = 4 * PTR_SIZE; // Offset 0x20 for _Myval.first
        const stringObjectPtr = nodePtr.add(keyFieldOffset).readPointer();

        let className = "[Invalid Key StringObj Ptr]";
        if (stringObjectPtr && !stringObjectPtr.isNull()) {
            // Assuming the string object (KeyType) contains the char* at its own offset 0.
            // This is common for simple string wrappers or std::string's _Ptr.
            const classNameCharsPtr = stringObjectPtr;
            className = this.readSafeCString(classNameCharsPtr);
        } else {
            className = "[Null Key StringObj Ptr]";
        }

        const valueFieldOffset = 5 * PTR_SIZE; // Offset 0x28 for _Myval.second
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

            // The std::map for classes (e.g., m_classesByName) is at offset 0x30 in CEntityClassRegistry.
            // This offset points to the std::map object itself.
            const mapObjectInRegistryOffset = 0x30;
            const mapObjectPtr = this.ptr.add(mapObjectInRegistryOffset); // Address of the std::map object

            // In std::map, the first member is typically the _Tree object.
            // In _Tree, the first member is _Myhead (pointer to head/sentinel node).
            const mapHeadNodePtr = mapObjectPtr.readPointer(); // mapObjectPtr + 0 -> _Mytree._Myhead
            if (mapHeadNodePtr.isNull()) {
                console.error("Error: Map's _Head node pointer (at map_obj_addr+0) is NULL.");
                return [];
            }
            console.log(`Map _Head node address: ${mapHeadNodePtr}`);

            // The second member of _Tree is _Mysize (size_t).
            const mapSize = mapObjectPtr.add(PTR_SIZE).readULong(); // mapObjectPtr + PTR_SIZE -> _Mytree._Mysize
            console.log(`Map size reported by std::map object: ${mapSize}`);

            if (mapSize === 0) {
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

            // Sanity check: if root is head, map is empty. (Should be covered by mapSize check)
            if (treeRootPtr.equals(mapHeadNodePtr)) {
                console.log("Informational: Tree root points to head node, indicating an empty map.");
                if (mapSize.toUInt32() !== 0) {
                     console.warn(`Warning: Root is head, but map size is ${mapSize}. This is inconsistent.`);
                }
                return []; // Already handled by mapSize check, but good for robustness.
            }

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

            if (classes.length !== mapSize) {
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

        classes.forEach((classInfo, index) => {
            const classCount = index + 1;
            console.log(`${classCount.toString().padStart(3, ' ')}. "${classInfo.name}": ${classInfo.flags} @ ${classInfo.ptr}`);
        });

        console.log("-----------------------------------------------------------------");
        console.log(`Successfully dumped ${classes.length} classes.`);
    }
}

// Wrapper for CEntitySystem (size: 0x8A0)
class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }

    // Direct memory for entity_array_ at offset 0x148
    get entityArray() {
        const arrPtr = this.ptr.add(0x148);
        return new CEntityArray(arrPtr);
    }

    // entity_class_registry_ at 0x898
    get classRegistry() {
        const registryPtr = this.ptr.add(0x898).readPointer();
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

    // Direct call to spawn entity function at RVA 0x6B65BC0
    spawnEntity(entityParams) {
        // Calculate the absolute address from the module base + RVA
        const moduleBase = Process.enumerateModulesSync()[0].base;
        const spawnFuncAddr = moduleBase.add(0x6B65BC0);

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
        console.log(ptr);
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

    // player_ at 0xC08
    get player() {
        const ptr = this.ptr.add(0xC08).readPointer();
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

// Replace with the actual static address of GEnv
const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x9B4FBE0");
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

    console.log(cr);

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

    console.log(actorClasses);

    const actorClassPtrs = actorClasses.map(cls => entityClasses.get(cls)?.ptr).filter(ptr => ptr);

    console.log("[*] Filtering Player entities...");
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

    console.log(`    → Found ${players.length} Player entities`);
    for (const p of players) {
        const pos = p.worldPos;
        const proj = cr.projectToScreen(pos);
        const className = p.entityClass ? p.entityClass.name : "<unknown>";
        const isCorpse = className === 'PlayerCorpse';

        console.log(
            `        [${p.ptr}] [ID ${p.id}] ${isCorpse ? 'CORPSE' : 'ALIVE'} ${p.name || "<no-name>"} @ (${pos.x.toFixed(2)}, ${pos.y.toFixed(2)}, ${pos.z.toFixed(2)}) : ${proj.x.toFixed(2)}, ${proj.y.toFixed(2)}, ${proj.z.toFixed(2)})`,
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
        const zone = entity.zone;
        const zoneName = zone ? zone.name : "<no-zone>";
        const direction = formatRelativeDirection(angles);

        console.log(
            `[${entity.ptr}] [ID ${entity.id}] Class: ${className} Name: ${name}\n` +
            `  Zone: ${zoneName}\n` +
            `  World Position: (${worldPos.x.toFixed(2)}, ${worldPos.y.toFixed(2)}, ${worldPos.z.toFixed(2)})\n` +
            `  Distance: ${distance.toFixed(2)}m\n` +
            `  Direction: ${direction}\n` +
            `  Raw Angles: Yaw=${angles.yaw.toFixed(1)}° Pitch=${angles.pitch.toFixed(1)}°`
        );
    } catch (e) {
        console.log(`Error printing entity info: ${e}`);
    }
}

// Export as RPC method
rpc.exports.findByClassName = function(pattern) {
    const entities = findEntitiesByClassNamePattern(pattern);
    console.log(`[*] Found ${entities.length} entities matching pattern: ${pattern}`);

    // Calculate distances and sort entities by distance
    const entitiesWithDistance = entities.map(entity => {
        const distance = calculateDistance(entity);
        return { entity, distance };
    });

    // Sort by distance (closest first)
    entitiesWithDistance.sort((a, b) => a.distance - b.distance);

    // Print sorted entities
    entitiesWithDistance.slice(0, 100).forEach(item => {
        printEntityInfo(item.entity, item.distance);
    });

    return entities.length;
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
