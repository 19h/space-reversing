// Frida Script to Dump All Classes from CEntityClassRegistry

// Global constants
const PTR_SIZE = Process.pointerSize; // Automatically detects 4 or 8 based on target process

/**
 * Helper function to safely read a C-style string from a NativePointer.
 * Returns a placeholder string if the pointer is null or if reading fails.
 * @param {NativePointer} ptr Pointer to the C-string.
 * @returns {string} The read string or a placeholder.
 */
function readSafeCString(ptr) {
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
function traverseRBTree(nodePtr, headPtr, callback) {
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
    traverseRBTree(leftChild, headPtr, callback);

    // Process current node: extract key (class name) and value (class pointer)
    const keyFieldOffset = 4 * PTR_SIZE; // Offset 0x20 for _Myval.first
    const stringObjectPtr = nodePtr.add(keyFieldOffset).readPointer();

    let className = "[Invalid Key StringObj Ptr]";
    if (stringObjectPtr && !stringObjectPtr.isNull()) {
        // Assuming the string object (KeyType) contains the char* at its own offset 0.
        // This is common for simple string wrappers or std::string's _Ptr.
        const classNameCharsPtr = stringObjectPtr;
        className = readSafeCString(classNameCharsPtr);
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
    traverseRBTree(rightChild, headPtr, callback);
}

// Main function to orchestrate the class dumping process.
function dumpAllRegisteredClasses() {
    console.log("Initiating dump of all registered entity classes...");
    console.log(`Target: ${Process.arch}, Pointer Size: ${PTR_SIZE} bytes.`);

    try {
        const mainModule = Process.enumerateModulesSync()[0];
        if (!mainModule || !mainModule.base) {
            console.error("Fatal: Could not retrieve main module information.");
            return;
        }
        const baseAddress = mainModule.base;
        console.log(`Main module: ${mainModule.name} (Base: ${baseAddress})`);

        // Address of gEnv global (static offset from module base, from user's script)
        const GENV_OFFSET_FROM_BASE = ptr("0x9B4FBE0");
        const gEnvPtr = baseAddress.add(GENV_OFFSET_FROM_BASE);
        console.log(`gEnv global address: ${gEnvPtr}`);

        // Navigate: gEnv->pEntitySystem (offset 0x00A0)
        const entitySystemMemberOffset = 0x00A0;
        const entitySystemPtr = gEnvPtr.add(entitySystemMemberOffset).readPointer();
        if (entitySystemPtr.isNull()) {
            console.error(`Error: CEntitySystem pointer at gEnv+0x${entitySystemMemberOffset.toString(16)} is NULL.`);
            return;
        }
        console.log(`CEntitySystem instance address: ${entitySystemPtr}`);

        // Navigate: CEntitySystem->pClassRegistry (offset 0x898)
        const classRegistryMemberOffset = 0x898;
        const classRegistryPtr = entitySystemPtr.add(classRegistryMemberOffset).readPointer();
        if (classRegistryPtr.isNull()) {
            console.error(`Error: CEntityClassRegistry pointer at CEntitySystem+0x${classRegistryMemberOffset.toString(16)} is NULL.`);
            return;
        }
        console.log(`CEntityClassRegistry instance address: ${classRegistryPtr}`);

        // The std::map for classes (e.g., m_classesByName) is at offset 0x30 in CEntityClassRegistry.
        // This offset points to the std::map object itself.
        const mapObjectInRegistryOffset = 0x30;
        const mapObjectPtr = classRegistryPtr.add(mapObjectInRegistryOffset); // Address of the std::map object

        // In std::map, the first member is typically the _Tree object.
        // In _Tree, the first member is _Myhead (pointer to head/sentinel node).
        const mapHeadNodePtr = mapObjectPtr.readPointer(); // mapObjectPtr + 0 -> _Mytree._Myhead
        if (mapHeadNodePtr.isNull()) {
            console.error("Error: Map's _Head node pointer (at map_obj_addr+0) is NULL.");
            return;
        }
        console.log(`Map _Head node address: ${mapHeadNodePtr}`);

        // The second member of _Tree is _Mysize (size_t).
        const mapSize = mapObjectPtr.add(PTR_SIZE).readULong(); // mapObjectPtr + PTR_SIZE -> _Mytree._Mysize
        console.log(`Map size reported by std::map object: ${mapSize}`);

        if (mapSize === 0) {
            console.log("Class registry map is empty (size is 0). No classes to dump.");
            return;
        }

        // The actual root of the Red-Black tree is _Head->_Parent.
        // _Parent is at offset 0x08 (1 * PTR_SIZE) from any node pointer.
        const parentOffsetInNode = 1 * PTR_SIZE;
        const treeRootPtr = mapHeadNodePtr.add(parentOffsetInNode).readPointer();
        if (treeRootPtr.isNull()) {
            console.error("Error: Tree root pointer (_Head->_Parent) is NULL. Map might be malformed or empty in an unusual way.");
            return;
        }
        console.log(`Tree root node address: ${treeRootPtr}`);

        // Sanity check: if root is head, map is empty. (Should be covered by mapSize check)
        if (treeRootPtr.equals(mapHeadNodePtr)) {
            console.log("Informational: Tree root points to head node, indicating an empty map.");
            if (mapSize.toUInt32() !== 0) {
                 console.warn(`Warning: Root is head, but map size is ${mapSize}. This is inconsistent.`);
            }
            return; // Already handled by mapSize check, but good for robustness.
        }

        console.log("\nRegistered Entity Classes (Format: No. \"Name\": PointerToClass):");
        console.log("-----------------------------------------------------------------");
        let classCount = 0;
        traverseRBTree(treeRootPtr, mapHeadNodePtr, (className, classPtr, nodePtr) => {
            classCount++;
            // Log with padding for alignment
            console.log(`${classCount.toString().padStart(3, ' ')}. "${className}": ${classPtr}`);
        });
        console.log("-----------------------------------------------------------------");

        if (classCount !== mapSize) {
            console.warn(`Warning: Number of traversed classes (${classCount}) does not match map's reported size (${mapSize}). Traversal might be incomplete or map structure assumptions might be slightly off.`);
        } else {
            console.log(`Successfully dumped ${classCount} classes.`);
        }

    } catch (e) {
        console.error(`Critical Error during class dumping: ${e.message}`);
        if (e.stack) {
            console.error("Stack Trace:\n" + e.stack);
        }
    }
}

// Schedule the main function to run once the script is injected.
setImmediate(dumpAllRegisteredClasses);
