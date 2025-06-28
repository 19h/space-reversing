const base = Process.enumerateModulesSync()[0].base;

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
        console.log(fnPtr, name);
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

    // render_handle_ at 0x1E0
    get renderHandlePtr() {
        return this.ptr.add(0x1E0);
    }

    get renderHandle() {
        return this.renderHandlePtr.readPointer();
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
}

Interceptor.attach(base.add(ptr("0x3C161F0")), {
    onLeave: function(retval) {
        try {
            console.log("sub_143C161F0 returned:", retval.readFloat());
        } catch (e) {
            console.log("sub_143C161F0 returned:", retval);
        }

        retval.replace(2.5);
    }
});

Interceptor.attach(base.add(ptr("0x67F8350")), {
    onEnter: function(args) {
        return;

        // a1: pointer to _DWORD
        // a2: float
        var a1 = args[0];
        var a2 = args[1];
        console.log("CRigidEntity::StartStep called");
        console.log("a1:", a1.and(ptr(0xFFFFFFFFFFFF)));

        try {
            console.log("+ a2:", a2.readFloat());
        } catch (e) {
            console.log("! a2:", a2);
        }

        try {
            console.log(a1.and(ptr(0xFFFFFFFFFFFF)).readPointer());
        } catch (e) {
        }
    }
});

Interceptor.attach(base.add(ptr("0x67C2090")), {
    onEnter: function(args) {
        // CRigidEntity::GetMaxTimeStep(__int64 *rigidEntity, double a2)
        // x64 __fastcall: RCX = rigidEntity, XMM1 = a2 (double)

        this.rigidEntity = args[0];

        console.log("\n=== CRigidEntity::GetMaxTimeStep called ===");
        console.log("rigidEntity:", this.rigidEntity);

        // Note: a2 is passed in XMM1 register as a double value
        // Standard Frida doesn't provide direct XMM register access
        // We'll focus on the rigidEntity structure instead

        try {
            var basePtr = this.rigidEntity;

            // Validate pointer
            if (basePtr.isNull()) {
                console.log("rigidEntity is NULL");
                return;
            }

            // Try to validate memory is readable
            try {
                basePtr.readU8();
            } catch (e) {
                console.log("rigidEntity pointer is not readable");
                return;
            }

            console.log("\nReading rigidEntity structure:");

            // Helper function to safely read memory
            function safeRead(ptr, type, offset, name) {
                try {
                    var addr = ptr.add(offset);
                    var value;
                    switch(type) {
                        case 'float':
                            value = addr.readFloat();
                            break;
                        case 'double':
                            value = addr.readDouble();
                            break;
                        case 'u32':
                            value = addr.readU32();
                            break;
                        case 'pointer':
                            value = addr.readPointer();
                            break;
                    }
                    console.log("  [0x" + offset.toString(16) + "] " + name + ":", value);
                    return value;
                } catch (e) {
                    console.log("  [0x" + offset.toString(16) + "] " + name + ": <read error>");
                    return null;
                }
            }

            // Key fields from the decompiled code
            // Note: rigidEntity[N] in decompiled code means *(rigidEntity + N*8)
            // (float*)rigidEntity + N means basePtr + N*4

            // Read pointer fields (8-byte aligned, array indexing)
            console.log("\nPointer fields (array indexing):");
            safeRead(basePtr, 'pointer', 0x28 * 8, "rigidEntity[0x28]");
            safeRead(basePtr, 'pointer', 0x48 * 8, "rigidEntity[0x48]");
            safeRead(basePtr, 'pointer', 0x49 * 8, "rigidEntity[0x49]");
            safeRead(basePtr, 'pointer', 0x4C * 8, "rigidEntity[0x4C]");
            safeRead(basePtr, 'pointer', 0x58 * 8, "rigidEntity[0x58]");
            safeRead(basePtr, 'pointer', 0x98 * 8, "rigidEntity[0x98]");

            // Read float fields (4-byte aligned, cast to float*)
            console.log("\nFloat fields (float* cast):");
            safeRead(basePtr, 'float', 0x76 * 4, "rotation quaternion w");
            safeRead(basePtr, 'float', 0x77 * 4, "rotation quaternion x");
            safeRead(basePtr, 'float', 0x78 * 4, "rotation quaternion y");
            safeRead(basePtr, 'float', 0x79 * 4, "rotation quaternion z");
            safeRead(basePtr, 'float', 0x80 * 4, "scale factor");
            safeRead(basePtr, 'float', 0x146 * 4, "field_0x146");
            safeRead(basePtr, 'float', 0x147 * 4, "field_0x147");
            safeRead(basePtr, 'float', 0x148 * 4, "current time");
            safeRead(basePtr, 'float', 0x149 * 4, "time threshold");
            safeRead(basePtr, 'float', 0x155 * 4, "field_0x155");
            safeRead(basePtr, 'float', 0x1A5 * 4, "field_0x1A5");
            safeRead(basePtr, 'float', 0x220 * 4, "velocity x");
            safeRead(basePtr, 'float', 0x221 * 4, "velocity y");
            safeRead(basePtr, 'float', 0x222 * 4, "velocity z");

            // Read integer fields
            console.log("\nInteger fields:");
            safeRead(basePtr, 'u32', 0x52 * 4, "field_0x52");
            safeRead(basePtr, 'u32', 0xA5 * 4, "n4");
            safeRead(basePtr, 'u32', 0x129 * 4, "flags");

            // Read double fields (8-byte aligned, cast to double*)
            console.log("\nDouble fields:");
            safeRead(basePtr, 'double', 0xD6 * 8, "field_0xD6");

            // Special offset 0x68C (appears to be a 12-byte structure)
            console.log("\nSpecial field at 0x68C:");
            safeRead(basePtr, 'float', 0x68C, "field_0x68C[0]");
            safeRead(basePtr, 'float', 0x68C + 4, "field_0x68C[1]");
            safeRead(basePtr, 'float', 0x68C + 8, "field_0x68C[2]");

            // Try to read the first condition check
            var ptr_0x58 = safeRead(basePtr, 'pointer', 0x58 * 8, "ptr at 0x58*8");
            if (ptr_0x58 && !ptr_0x58.isNull()) {
                console.log("\nReading from ptr_0x58:");
                safeRead(ptr_0x58, 'float', 0x114, "ptr_0x58->field_0x114");
            }

        } catch (e) {
            console.log("Error in onEnter:", e);
            console.log("Stack:", e.stack);
        }
    },

    onLeave: function(retval) {
        console.log("\n=== CRigidEntity::GetMaxTimeStep returns ===");

        // The return value is __m128 (128-bit SSE register)
        // In x64 calling convention, this is returned in XMM0
        // Frida's retval for floating point might not work as expected

        console.log("retval:", retval);

        // Try different interpretations
        try {
            // The function seems to return a time step value
            // Try to read as pointer to see what we get
            if (!retval.isNull()) {
                console.log("retval as pointer is not null, value:", retval.toInt32());
            }
        } catch (e) {
            console.log("Cannot read retval:", e.message);
        }

        // Based on the decompiled code, the function returns either:
        // 1. The input a2 parameter unchanged
        // 2. A calculated time step value
        // The actual value is in XMM0 register which standard Frida can't directly access
    }
});
