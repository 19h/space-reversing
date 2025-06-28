// Star Citizen Structure Analysis Tool
// Target: GetStructDataFields (sub_14723EB40)

// --- CONFIGURATION ---
const gEnvBase = ptr("0x14981d200");
const pDataCore = gEnvBase.add(0x78).readPointer();
const DATA_CORE_INSTANCE_ADDRESS = pDataCore;

// Placeholder for the 'a4' boolean flag.
// true (1): Traverse inheritance/composition hierarchy.
// false (0): Get fields for the specific struct only.
const GET_INHERITED_FIELDS = 1; // Use 1 for true, 0 for false

// Size of the DataField structure determined from decompilation analysis
const DATAFIELD_SIZE = 40;
// ---------------------

// Field type constants from EDataFieldType enum (add more as needed)
const FIELDTYPE = {
    BOOL: 0x1,
    INT8: 0x2,
    UINT8: 0x6,
    INT16: 0x3,
    UINT16: 0x7,
    INT32: 0x4,
    UINT32: 0x8,
    INT64: 0x5,
    UINT64: 0x9,
    FLOAT: 0xB,
    DOUBLE: 0xC,
    CONSTCHAR_PTR: 0xD, // String (char*)
    GUID: 0xE,          // Likely a 16-byte structure
    ENUM: 0xF,
    STRUCT_INSTANCE: 0x10, // Embedded Struct
    STRUCTPTR_AND_TAG: 0x110, // Pointer to Struct + Tag (Polymorphic)
    ARRAY: 0x11,        // Array (requires sub-type info)
    // Add other types based on Star Citizen's EDataFieldType
};

// Find the StarCitizen.exe module
const starCitizenModule = Process.findModuleByName("StarCitizen.exe");
if (!starCitizenModule) {
    console.error("Could not find StarCitizen.exe module!");
    throw new Error("Target module not found");
}

// Define the GetStructDataFields function using the CORRECT address and signature
// __int64 __fastcall sub_14723EB40(__int64 a1, __int64 a2, __int64 *a3, char a4)
const GetStructDataFields = new NativeFunction(
    starCitizenModule.base.add(0x723EB40), // Corrected address
    'int64', // Return type: count (__int64)
    ['pointer', 'pointer', 'pointer', 'uint8'], // Args: a1 (pointer), a2 (const char*), a3 (vector*), a4 (char/uint8)
    'win64' // ABI: MSVC x64 __fastcall
);

console.log("[+] GetStructDataFields function (sub_14723EB40) targeted at address:", GetStructDataFields.address);
console.log("[+] Using Data Core Instance Address:", DATA_CORE_INSTANCE_ADDRESS);

/**
 * Wrapper function that calls the corrected GetStructDataFields
 *
 * @param {string} structName - The name of the struct to get data fields for
 * @returns {object} Object containing the DataField array pointer, count, and parsed fields
 */
function getStructFields(structName) {
    // Allocate memory for the struct name (passed as const char*)
    const structNamePtr = Memory.allocUtf8String(structName);

    // Allocate memory for the std::vector-like structure expected by a3.
    // The native function expects a pointer to { void* begin; void* end; void* capacity; }
    // We initialize it to an empty state. The native function will manage its internal buffer.
    const vectorStructSize = Process.pointerSize * 3; // begin, end, capacity
    const vectorStructPtr = Memory.alloc(vectorStructSize);
    Memory.writePointer(vectorStructPtr.add(0 * Process.pointerSize), NULL); // begin = null
    Memory.writePointer(vectorStructPtr.add(1 * Process.pointerSize), NULL); // end = null
    Memory.writePointer(vectorStructPtr.add(2 * Process.pointerSize), NULL); // capacity = null

    // Call the native function with the correct arguments
    try {
        console.log(
            'Calling GetStructDataFields with:',
            DATA_CORE_INSTANCE_ADDRESS,
            structNamePtr,
            vectorStructPtr,
            GET_INHERITED_FIELDS
        );

        const count = GetStructDataFields(
            DATA_CORE_INSTANCE_ADDRESS, // a1: Context/Instance Pointer
            structNamePtr,              // a2: Struct Name (const char*)
            vectorStructPtr,            // a3: Pointer to our vector structure
            GET_INHERITED_FIELDS        // a4: Boolean flag (char/uint8)
        );

        // After the call, read the 'begin' and 'end' pointers from the vector structure
        // These pointers now point to the native function's internal buffer containing DataField pointers.
        const dataFieldPtrArrayBegin = Memory.readPointer(vectorStructPtr.add(0 * Process.pointerSize));
        const dataFieldPtrArrayEnd = Memory.readPointer(vectorStructPtr.add(1 * Process.pointerSize));

        // Calculate the actual count based on the pointers (optional, as the function returns count)
        let calculatedCount = 0;
        if (!dataFieldPtrArrayBegin.isNull() && !dataFieldPtrArrayEnd.isNull()) {
            // The vector stores POINTERS to DataField structs
            calculatedCount = dataFieldPtrArrayEnd.sub(dataFieldPtrArrayBegin).toInt32() / Process.pointerSize;
        }
        // It's generally safer to trust the function's return value if available
        const finalCount = count.toNumber(); // Use the returned count

        if (finalCount !== calculatedCount && calculatedCount > 0) {
            console.warn(`[!] Count mismatch for ${structName}: Returned=${finalCount}, Calculated=${calculatedCount}. Using returned count.`);
        }

        // Convert the native array of DataField POINTERS to JavaScript objects
        const fields = [];
        if (finalCount > 0 && !dataFieldPtrArrayBegin.isNull()) {
            for (let i = 0; i < finalCount; i++) {
                // Read the POINTER to the DataField structure from the vector's buffer
                const dataFieldDescPtr = Memory.readPointer(dataFieldPtrArrayBegin.add(i * Process.pointerSize));
                if (dataFieldDescPtr.isNull()) {
                    console.warn(`[!] Found NULL DataField pointer at index ${i} for struct ${structName}`);
                    continue;
                }
                // Read the actual DataField structure using the pointer we just read
                fields.push(readDataField(dataFieldDescPtr));
            }
        }

        // Note: We do NOT free the memory pointed to by dataFieldPtrArrayBegin,
        // as it's likely managed by the native CDataCore instance.
        // We only allocated vectorStructPtr, which goes out of scope or can be freed if needed later.

        return {
            count: finalCount,
            fields: fields
        };
    } catch (error) {
        console.error(`Error getting struct fields for ${structName}: ${error.message}`);
        console.error(error.stack); // Log stack trace for debugging
        return { count: 0, fields: [], error: error.message };
    } finally {
        // Clean up the allocated vector structure pointer if necessary,
        // though usually letting it be garbage collected by JS is fine for simple scripts.
        // If this function were called repeatedly in a loop, explicit freeing might be considered.
    }
}

/**
 * Helper function to read a DataField structure from a given pointer.
 * @param {NativePointer} fieldDescPtr - Pointer to the actual DataField structure (40 bytes).
 */
function readDataField(fieldDescPtr) {
    // Read each field according to the CORRECTED DataField structure (40 bytes)
    const fieldNamePtr = Memory.readPointer(fieldDescPtr.add(0)); // Offset +0
    const fieldName = fieldNamePtr.isNull() ? "<NULL_NAME>" : Memory.readUtf8String(fieldNamePtr);
    const fieldOffset = Memory.readU64(fieldDescPtr.add(8));   // Offset +8
    const fieldSize = Memory.readU64(fieldDescPtr.add(16));  // Offset +16
    const fieldType = Memory.readU8(fieldDescPtr.add(24));     // Offset +24 (Type is uint8_t)
    // Read potential sub-type/flags if needed for more detailed analysis later
    // const fieldSubType = Memory.readU8(fieldDescPtr.add(25)); // Offset +25
    // const isArrayFlag = Memory.readU8(fieldDescPtr.add(26));  // Offset +26
    // const enumOrStructSize = Memory.readUInt64(fieldDescPtr.add(32)); // Offset +32

    return {
        name: fieldName,
        offset: fieldOffset,
        size: fieldSize,
        type: fieldType, // Store the raw type value
        typeName: getFieldTypeName(fieldType) // Get the descriptive name
        // Add subType, isArrayFlag, enumOrStructSize here if needed
    };
}

/**
 * Convert field type value to a readable string based on EDataFieldType enum
 */
function getFieldTypeName(typeValue) {
    // Find the enum name corresponding to the value
    for (const name in FIELDTYPE) {
        if (FIELDTYPE[name] === typeValue) {
            return name;
        }
    }
    // Handle combined types like STRUCTPTR_AND_TAG if necessary
    if (typeValue === FIELDTYPE.STRUCTPTR_AND_TAG) return "STRUCTPTR_AND_TAG";

    return `UNKNOWN_TYPE(0x${typeValue.toString(16)})`;
}

/**
 * Function to dump all struct fields to string with proper type information
 */
function dumpStructLayout(structName) {
    console.log(`[.] Analyzing struct: ${structName} (Inherited: ${GET_INHERITED_FIELDS ? 'Yes' : 'No'})`);
    const result = getStructFields(structName);

    if (result.error) {
        return `Error analyzing ${structName}: ${result.error}\n`;
    }
    if (result.count === 0 && result.fields.length === 0) {
        // Distinguish between truly empty structs and lookup failures
        // A more robust check might involve trying with GET_INHERITED_FIELDS = 0
        return `Struct ${structName} not found or has no fields.\n`;
    }

    let output = `Struct ${structName} Layout (${result.count} fields):\n`;
    output += "-".repeat(80) + "\n";

    // Calculate padding
    const maxNameLength = result.fields.length > 0
        ? Math.max(...result.fields.map(f => f.name.length), 10)
        : 10;
    const maxTypeNameLength = result.fields.length > 0
        ? Math.max(...result.fields.map(f => f.typeName.length), 16)
        : 16;


    // Header
    output += `${"Offset".padEnd(8)} | ${"Name".padEnd(maxNameLength)} | ${"Type".padEnd(maxTypeNameLength)} | ${"Size".padEnd(6)}\n`;
    output += "-".repeat(80) + "\n";

    // Fields
    result.fields.forEach(field => {
        output += `0x${field.offset.toString(16).padStart(6, '0')} | `;
        output += `${field.name.padEnd(maxNameLength)} | `;
        output += `${field.typeName.padEnd(maxTypeNameLength)} | `;
        output += `${field.size.toString().padEnd(6)} bytes\n`;
    });

    return output;
}

/**
 * Function to find a field by name in a struct
 */
function findField(structName, fieldName) {
    const result = getStructFields(structName);
    if (result.error) {
        console.error(`Error finding field in ${structName}: ${result.error}`);
        return null;
    }
    return result.fields.find(field => field.name === fieldName) || null;
}

/**
 * Read value from a structure at runtime based on field information
 * (Expand this based on FIELDTYPE enum and actual needs)
 */
function readFieldValue(structPtr, fieldInfo) {
    if (!fieldInfo || structPtr.isNull()) {
        return "<Invalid Args>";
    }
    const valuePtr = structPtr.add(fieldInfo.offset);

    try {
        switch (fieldInfo.type) {
            case FIELDTYPE.BOOL:
                return Memory.readU8(valuePtr) !== 0;
            case FIELDTYPE.INT8:
                return Memory.readS8(valuePtr);
            case FIELDTYPE.UINT8:
                return Memory.readU8(valuePtr);
            case FIELDTYPE.INT16:
                return Memory.readS16(valuePtr);
            case FIELDTYPE.UINT16:
                return Memory.readU16(valuePtr);
            case FIELDTYPE.INT32:
                return Memory.readS32(valuePtr);
            case FIELDTYPE.UINT32:
                return Memory.readU32(valuePtr);
            case FIELDTYPE.INT64:
                return Memory.readS64(valuePtr);
            case FIELDTYPE.UINT64:
                return Memory.readU64(valuePtr);
            case FIELDTYPE.FLOAT:
                return Memory.readFloat(valuePtr);
            case FIELDTYPE.DOUBLE:
                return Memory.readDouble(valuePtr);
            case FIELDTYPE.CONSTCHAR_PTR:
                const strPtr = Memory.readPointer(valuePtr);
                return strPtr.isNull() ? null : Memory.readUtf8String(strPtr);
            case FIELDTYPE.GUID: // Assuming 16 bytes
                return valuePtr.readByteArray(16); // Return as ArrayBuffer
            case FIELDTYPE.ENUM: // Size depends on definition, often int32
                // Read based on fieldInfo.size if available, default to S32
                if (fieldInfo.size === 1) return Memory.readS8(valuePtr);
                if (fieldInfo.size === 2) return Memory.readS16(valuePtr);
                if (fieldInfo.size === 8) return Memory.readS64(valuePtr);
                return Memory.readS32(valuePtr); // Default
            case FIELDTYPE.STRUCT_INSTANCE:
                return `<Struct Instance @ ${valuePtr}>`; // Cannot read directly
            case FIELDTYPE.STRUCTPTR_AND_TAG:
                return Memory.readPointer(valuePtr); // Return the pointer part
            case FIELDTYPE.ARRAY:
                return `<Array @ ${valuePtr}>`; // Need more info to read

            default:
                return `<Cannot read type 0x${fieldInfo.type.toString(16)}>`;
        }
    } catch (e) {
        return `<Read Error: ${e.message}>`;
    }
}

/**
 * Save structure information to a JSON file (requires file system access)
 */
function saveStructInfo(structName, filePath) {
    const result = getStructFields(structName);
    if (result.error) {
        console.error(`Error saving struct info for ${structName}: ${result.error}`);
        return null;
    }
    if (result.count === 0) {
        console.log(`No fields found for struct: ${structName}`);
        return null;
    }

    // Create a simplified object for export
    const exportData = {
        name: structName,
        fieldCount: result.count,
        retrievedWithInheritance: GET_INHERITED_FIELDS ? true : false,
        fields: result.fields.map(f => ({
            name: f.name,
            offset: '0x' + f.offset.toString(16), // Store offset as hex string
            size: f.size.toString(), // Store size as string
            type: f.type,
            typeName: f.typeName
        }))
    };

    const jsonString = JSON.stringify(exportData, null, 2);

    // To write to file, you'd typically use Frida's RPC or frida-fs:
    // Example using RPC (requires setup in your Python/Node controller):
    // rpc.exports.writeFile(filePath, jsonString);
    // console.log(`Struct info for ${structName} ready to be saved.`);

    // For now, just return the JSON string
    return jsonString;
}

// ===================== USAGE EXAMPLES =====================

// Example 1: Analyze a single structure
console.log("\n[*] STRUCTURE ANALYSIS EXAMPLE:");
// !!! Replace "Vec3" with a known, valid struct name from Star Citizen !!!
// Common examples might include "Vec3", "Quat", "EntityId", "Player", "SShipInfo"
// You may need to find these through other reversing efforts (strings, RTTI, etc.)
console.log(dumpStructLayout("RestrictedAreaHandlerParams"));

// Example 2: Find a specific field in a structure
console.log("\n[*] FIND FIELD EXAMPLE:");
// !!! Replace "Player" and "health" with valid struct/field names !!!
const fieldInfo = findField("DataForge", "__type"); // Example using a potentially known field
if (fieldInfo) {
    console.log(`Found field: ${fieldInfo.name}`);
    console.log(`  - Offset: 0x${fieldInfo.offset.toString(16)}`);
    console.log(`  - Type: ${fieldInfo.typeName} (0x${fieldInfo.type.toString(16)})`);
    console.log(`  - Size: ${fieldInfo.size} bytes`);
} else {
    console.log("Field not found (or struct lookup failed).");
}

// Example 3: Batch process multiple structures
console.log("\n[*] BATCH ANALYSIS EXAMPLE:");
// !!! Replace with actual Star Citizen struct names !!!
[
    "Vec3",
    "Quat",
    "EntityId",
    //"DataForge", // Often a base class
    //"CDataCore", // The main instance type?
    //"SShipInfo",
    //"CEntityComponent",
    //"SPlayerData"
].forEach(structName => {
    console.log(dumpStructLayout(structName));
});

// ===================== INTERACTIVE COMMANDS =====================
// Add these exports to access the functions from the Frida REPL

// Export key functions to make them available in the Frida REPL
global.analyze = dumpStructLayout;
global.findField = findField;
global.saveStruct = saveStructInfo;
// Add readFieldValue if you have a pointer to a struct instance
// global.readField = function(structPtrHex, structName, fieldName) {
//     const field = findField(structName, fieldName);
//     if (!field) return `Field ${fieldName} not found in ${structName}`;
//     try {
//         const structPtr = ptr(structPtrHex);
//         return readFieldValue(structPtr, field);
//     } catch (e) {
//         return `Error reading field: ${e.message}`;
//     }
// };


console.log("\n[+] Star Citizen Structure Analysis Tool loaded!");
console.log("[+] Available commands in REPL:");
console.log("    analyze('StructName') - Dump structure layout");
console.log("    findField('StructName', 'fieldName') - Find specific field info");
console.log("    saveStruct('StructName') - Get structure JSON data (returned as string)");
// console.log("    readField('0xSTRUCT_PTR', 'StructName', 'fieldName') - Read field value at runtime");
console.log(`[+] Using GET_INHERITED_FIELDS = ${GET_INHERITED_FIELDS}`);
console.log("[+] Replace 'StructName' with actual Star Citizen structure names found via reversing.");
