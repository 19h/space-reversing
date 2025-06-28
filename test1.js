// Helper function to read Vector3 (3 floats)
function readVector3(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        return {
            x: ptr.readFloat(),
            y: ptr.add(4).readFloat(),
            z: ptr.add(8).readFloat()
        };
    } catch (e) {
        // console.error(`Error reading Vector3 at ${ptr}: ${e}`);
        return null;
    }
}

// Helper function to read DoubleVector3 (3 doubles)
function readDoubleVector3(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        // Ensure we read doubles, not floats
        return {
            x: ptr.readDouble(),
            y: ptr.add(8).readDouble(),
            z: ptr.add(16).readDouble()
        };
    } catch (e) {
        // console.error(`Error reading DoubleVector3 at ${ptr}: ${e}`);
        return null;
    }
}

// Function: GetObjectMetadata (0x1403B0AA0)
// Attempts to retrieve some metadata/type info via an indirect vtable call.
function GetObjectMetadata(objectPtr) {
    try {
        const objPtr = ptr(objectPtr); // Ensure NativePointer

        if (objPtr.isNull()) {
            // console.warn("[!] GetObjectMetadata called with NULL objectPtr.");
            return "NULL_PTR"; // Return a string indicator
        }

        // Read the pointer stored at the global address 0x14981A1C0
        const globalObjPtr = ptr("0x14981A1C0").readPointer();

        if (globalObjPtr.isNull()) {
             // console.warn("[!] Global object pointer at 0x14981A1C0 is NULL.");
             return "NO_GLOBAL";
        }

        // Read the vtable pointer from the object pointed to by the global
        const vtablePtr = globalObjPtr.readPointer();

        if (vtablePtr.isNull()) {
             // console.warn("[!] Global object's vtable is NULL.");
             return "NO_VTABLE";
        }

        // Read the function pointer from the vtable at offset 296 (0x128)
        const funcPtr = vtablePtr.add(296).readPointer(); // 296 = 0x128

        if (funcPtr.isNull()) {
             // console.warn("[!] GetObjectMetadata indirect function pointer (vtable+296) is NULL.");
             return "NO_FUNC_PTR";
        }

        // Define the native function signature
        // Assuming 'pointer' return and args: ('pointer' this, 'pointer' obj, 'uint64' flags)
        // ABI is 'win64' based on typical Windows x64 conventions
        const getMetadataFunc = new NativeFunction(funcPtr, 'pointer', ['pointer', 'pointer', 'uint64'], 'win64');

        // Call the function. Pass the global object as 'this', the target object, and flags=0.
        const result = getMetadataFunc(globalObjPtr, objPtr, uint64(0));

        // Attempt to read a string from the result pointer (common for names/types)
        // Add checks for NULL before reading
        if (!result.isNull()) {
             try {
                 // Try reading as CString first
                 const name = result.readCString();
                 if (name && name.length > 0 && name.length < 200) { // Basic sanity check
                     return name;
                 }
                 // If not a valid string, return the pointer address
                 return result.toString();
             } catch(readError) {
                 // If reading fails, just return the pointer address
                 return result.toString();
             }
        } else {
            return "NULL_RESULT";
        }

    } catch (e) {
        console.error(`[!] Error in GetObjectMetadata for ${objectPtr}:`);
        console.error(e.message); // Log only the message for brevity
        // console.error(e.stack); // Uncomment for full stack trace if needed
        return "ERROR";
    }
}


// --- Calculation Helpers ---

function calculateDistance(x, y, z) {
    // Distance from origin (0,0,0)
    return Math.sqrt(Math.pow(x, 2) + Math.pow(y, 2) + Math.pow(z, 2));
}

function calculateAngles(x, y, z) {
    // Calculates angles relative to origin (0,0,0) looking forward along +Y axis.
    // X is right, Y is forward, Z is up.

    // Horizontal angle (Azimuth) in XY plane. Angle from +Y towards +X.
    const horizontalAngleRad = Math.atan2(x, y); // atan2(opposite, adjacent) -> atan2(x, y)
    const horizontalAngleDeg = horizontalAngleRad * (180 / Math.PI);

    // Vertical angle (Elevation/Pitch). Angle from XY plane towards +Z.
    const xyDistance = Math.sqrt(Math.pow(x, 2) + Math.pow(y, 2));
    // Handle case where entity is exactly at origin or directly above/below
    const verticalAngleRad = (xyDistance < 0.0001) ? (z >= 0 ? Math.PI / 2 : -Math.PI / 2) : Math.atan2(z, xyDistance); // atan2(opposite, adjacent) -> atan2(z, xy_dist)
    const verticalAngleDeg = verticalAngleRad * (180 / Math.PI);

    return {
        horizontal: horizontalAngleDeg,
        vertical: verticalAngleDeg
    };
}

// --- Hooking Script ---

// Focus only on the function confirmed to provide position data
const func_146601700_ptr = ptr('0x146601700');
console.log(`[*] Target function address: ${func_146601700_ptr}`);

try {
    Interceptor.attach(func_146601700_ptr, {
        onEnter: function(args) {
            const objPtr = this.context.rcx; // a1 (this pointer)

            // Attempt to get metadata first for context
            const metadataInfo = GetObjectMetadata(objPtr);

            // Read the confirmed position offset (DoubleVector3 at 0x1C0)
            const pos = readDoubleVector3(objPtr.add(0x1C0));

            // Log only if position data is successfully read
            if (pos) {
                console.log(`-----------------------------------------------------`);
                console.log(`[+] Hooked sub_146601700`);
                console.log(`    Object Ptr: ${objPtr}`);
                console.log(`    Metadata:   ${metadataInfo}`); // Display metadata/name/type if available
                console.log(`    Position:   X=${pos.x.toFixed(3)}, Y=${pos.y.toFixed(3)}, Z=${pos.z.toFixed(3)}`);

                // Calculate and log distance
                const distance = calculateDistance(pos.x, pos.y, pos.z);
                console.log(`    Distance:   ${distance.toFixed(3)}`);

                // Calculate and log angles (assuming player looks along +Y)
                // Note: Ensure this assumption matches your game's coordinate system
                const angles = calculateAngles(pos.x, pos.y, pos.z);
                console.log(`    Angles:     H=${angles.horizontal.toFixed(1)}°, V=${angles.vertical.toFixed(1)}° (Relative to +Y Forward)`);
            }
            // Optional: Log even if position read fails, for debugging
            // else {
            //     console.log(`[+] Hooked sub_146601700`);
            //     console.log(`    Object Ptr: ${objPtr}`);
            //     console.log(`    Metadata:   ${metadataInfo}`);
            //     console.log(`    Position (Offset 0x1C0): Could not read or NULL.`);
            //     console.log(`---`);
            // }
        }
    });

    console.log("[*] Entity Position Hook Attached (sub_146601700). Waiting for calls...");

} catch (e) {
    console.error(`[!] Failed to attach hook: ${e.message}`);
}