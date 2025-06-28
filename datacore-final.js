"use strict";

/***************************************************************************
 *  starcitizen_datacore_header_generator.js
 *  ------------------------------------------------------------------------
 *  Unified Frida agent that **directly** emits a complete C header
 *  describing every enum, every enum-variant, every struct and every field
 *  present in Star Citizen’s DataCore *at runtime*.
 *
 *  It is a consolidation of:
 *      • dump_enums_sc_revised.js
 *      • struct_dumper_frida_json_v6.js
 *
 *  All RPC plumbing has been removed.  Inject, let the script run once, and
 *  capture its stdout.  The sole output is a syntactically-correct C header
 *  (UTF-8) with three sections:
 *
 *      1. Required preamble (exactly as requested).
 *      2. Enum definitions – variants sorted by ascending value.
 *      3. Struct definitions – topologically sorted where possible,
 *         with cyclic dependencies noted and placed at the end.
 *         Nested structs and arrays are represented as pointers.
 *
 *  Compile-time constants marked ***VERIFY*** must be checked whenever the
 *  game build changes.
 *
 *      $ frida -U -f StarCitizen.exe -l starcitizen_datacore_header_generator.js \
 *              --runtime=v8 > StarCitizen_DataCore.hpp
 *
 **************************************************************************/


/*─────────────────────────────────────────────────────────────────────────*\
|*  0.  GLOBAL CONFIGURATION                                              *|
\*─────────────────────────────────────────────────────────────────────────*/

const CONFIG = {
  REL_GENV_RVA:
    typeof REL_GENV_RVA !== "undefined" ? ptr(REL_GENV_RVA) : ptr("0x9B4FBE0"),
  REL_GET_STRUCT_FPTRS_RVA:
    typeof REL_GET_STRUCT_FPTRS_RVA !== "undefined"
      ? ptr(REL_GET_STRUCT_FPTRS_RVA)
      : ptr("0x74A5370"), // Example RVA, adjust as needed
  REL_GET_STRUCTDESC_BY_NAME_RVA:
    typeof REL_GET_STRUCTDESC_BY_NAME_RVA !== "undefined"
      ? ptr(REL_GET_STRUCTDESC_BY_NAME_RVA)
      : ptr("0x74A5750"),

  OFFSET_DATACORE_IN_GENV: ptr("0x78"), // ***VERIFY*** Offset of DataCore pointer within gEnv
  OFFSET_ENUM_REGISTRY_IN_DC: ptr("0x120"), // ***VERIFY*** Offset of EnumRegistry map within DataCore
  OFFSET_STRUCT_MAP_IN_DC: ptr("0x130"), // ***VERIFY*** Offset of Struct map within DataCore

  // Red-Black Tree Node Offsets (relative to node pointer)
  TREE: { L: 0x00, P: 0x08, R: 0x10, V: 0x20 }, // Left, Parent, Right, Value/Data

  // Enum Registry Map Node Value Offsets (relative to node pointer + TREE.V)
  ENUM_MAP: { KEY_PTR: 0x20, VAL_PTR: 0x30 }, // Pointer to enum name string, Pointer to EnumDescriptor

  // Enum Variant Map Node Value Offsets (relative to node pointer + TREE.V)
  VARIANT_MAP: { KEY_PTR: 0x20, VAL_S32: 0x28 }, // Pointer to variant name string, SInt32 value of variant

  // Enum Descriptor Offsets (relative to EnumDescriptor pointer)
  ENUM_DESCRIPTOR: { VARIANT_MAP_PTR: 0x00 }, // Pointer to the root of the variant map tree

  // FieldInfo Structure Offsets (relative to FieldInfo pointer)
  FIELDINFO: {
    name: 0x00,             // Pointer to field name string
    offset: 0x08,           // uint64_t offset within the struct
    size: 0x10,             // uint64_t size of the field's type
    type: 0x18,             // uint8_t enum representing the field type (see fieldTypeName)
    flags: 0x19,            // uint8_t field flags
    isArrayOrPointer: 0x1a, // uint8_t: 1 if it's a DynArray (or potentially other pointer types?)
    typeSpecificIndex: 0x1c,// uint32_t: Index for enum types, potentially other uses
    defaultValue: 0x20,     // Pointer: Usage depends on type (e.g., points to struct name for type 16)
  },

  // Robin Hood Hash Map (Control Structure) Offsets (relative to map control struct pointer)
  RH_HASH: {
    SLOT_SIZE: 72,          // Size of each data slot in bytes
    CONTROL_EMPTY: 0x80,    // Control byte value indicating an empty slot
    CTRL_PTR: 0x0,          // Pointer to the array of control bytes
    DATA_PTR: 0x8,          // Pointer to the array of data slots
    MASK: 0x18,             // uint64_t hash mask (capacity - 1)
    SLOT_KEY_PTR: 0x0,      // Offset within a data slot to the pointer to the key (struct name string)
  },

  PTR_VALIDITY_THRESHOLD: ptr("0x10000"), // Minimum valid pointer address threshold
  MAX_ENUMS: 20000,         // Safety limit for enum map traversal
  MAX_VARIANTS: 10000,      // Safety limit for variant map traversal
  MAX_STRUCTS: 25000,       // Safety limit for struct map traversal (increased for DynArrays)
  MAX_FIELDS: 4096,         // Safety limit for fields per struct (increased)
};

/*─────────────────────────────────────────────────────────────────────────*\
|*  1.  MINIMAL LOGGING INFRA – QUIET BY DEFAULT                          *|
\*─────────────────────────────────────────────────────────────────────────*/

// Set to true to enable diagnostic prints during script execution
const ENABLE_DPRINT = true;
function dprint(...args) {
    if (ENABLE_DPRINT) {
        // Use console.error for diagnostics so they don't mix with header output on stdout
        console.error("[D]", ...args);
    }
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  2.  POINTER SAFETY HELPERS                                            *|
\*─────────────────────────────────────────────────────────────────────────*/

/** Checks if a NativePointer is likely valid (not null and above a threshold). */
function isLikelyValidPtr(p) {
  return (
    p instanceof NativePointer &&
    !p.isNull() &&
    p.compare(CONFIG.PTR_VALIDITY_THRESHOLD) >= 0
  );
}

/** Safely reads a pointer from memory, returning 0x0 if the address is invalid. */
const rp = (addr) => (isLikelyValidPtr(addr) ? addr.readPointer() : ptr("0"));

/** Safely reads a signed 32-bit integer, returning 0 if the address is invalid. */
const r32 = (addr) => (isLikelyValidPtr(addr) ? addr.readS32() : 0);

/** Safely reads a C string, returning "<BAD_PTR>" or "<NULL>" on error. */
const rstr = (addr) => {
    if (!isLikelyValidPtr(addr)) return "<BAD_PTR>";
    try {
        const s = addr.readCString();
        return s ?? "<NULL>";
    } catch (e) {
        // Catch potential errors reading from invalid memory even if pointer seemed valid
        dprint(`Error reading string at ${hex(addr)}: ${e}`);
        return "<READ_ERR>";
    }
};

/** Converts a number or NativePointer to a hexadecimal string. */
const hex = (p) =>
  p instanceof NativePointer ? p.toString() : "0x" + Number(p).toString(16);

/*─────────────────────────────────────────────────────────────────────────*\
|*  3.  PROCESS-WIDE BASE ADDRESSES                                       *|
\*─────────────────────────────────────────────────────────────────────────*/

const base = Module.findBaseAddress("StarCitizen.exe");
if (!base) throw new Error("Module StarCitizen.exe not found.");
dprint(`StarCitizen.exe base address: ${hex(base)}`);

const gEnvPtr = base.add(CONFIG.REL_GENV_RVA);
dprint(`gEnv pointer address: ${hex(gEnvPtr)}`);


const dataCorePtrAddr = gEnvPtr.add(CONFIG.OFFSET_DATACORE_IN_GENV);
dprint(`DataCore pointer address: ${hex(dataCorePtrAddr)}`);
const dataCorePtr = rp(dataCorePtrAddr); // Read the actual DataCore pointer
if (!isLikelyValidPtr(dataCorePtr))
  throw new Error(`DataCore pointer invalid at ${hex(dataCorePtrAddr)}.`);
dprint(`DataCore pointer value: ${hex(dataCorePtr)}`);

const kGetStructFieldPtrsAddr = base.add(CONFIG.REL_GET_STRUCT_FPTRS_RVA);
const kGetStructDescByNameAddr = base.add(CONFIG.REL_GET_STRUCTDESC_BY_NAME_RVA);
dprint(`kGetStructFieldPtrs function address: ${hex(kGetStructFieldPtrsAddr)}`);
dprint(`kGetStructDescByName function address: ${hex(kGetStructDescByNameAddr)}`);

/*─────────────────────────────────────────────────────────────────────────*\
|*  4.  ENUM & VARIANT WALKER                                             *|
\*─────────────────────────────────────────────────────────────────────────*/

// Set of C/C++ keywords and other potentially problematic identifiers
const RESERVED_KEYWORDS = new Set([
  "alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel", "atomic_commit",
  "atomic_noexcept", "auto", "bitand", "bitor", "bool", "break", "case", "catch",
  "char", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "const",
  "consteval", "constexpr", "constinit", "const_cast", "continue", "co_await",
  "co_return", "co_yield", "decltype", "default", "delete", "do", "double",
  "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float",
  "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace",
  "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq",
  "private", "protected", "public", "reflexpr", "register", "reinterpret_cast",
  "requires", "return", "short", "signed", "sizeof", "static", "static_assert",
  "static_cast", "struct", "switch", "synchronized", "template", "this",
  "thread_local", "throw", "true", "try", "typedef", "typeid", "typename", "union",
  "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while", "xor",
  "xor_eq", "near", "far", "fallback", "abstract", "type", "uint8_t", "uint16_t",
  "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
]);

/** Appends an underscore to a string if it's a reserved C/C++ keyword. */
function unreserve_keyword(s) {
  if (RESERVED_KEYWORDS.has(s)) {
    s += "_";
  }
  return s;
}

/** Sanitizes a string to be a valid C identifier. */
function sanitizeName(s) {
  if (typeof s !== "string") {
    console.error(`!!! SANITIZE_NAME_ERROR: Received non-string input! Type=${typeof s}, Value=`, s);
    return "sanitizeName_received_non_string";
  }
  let result = "";
  try {
    result = s
      .replace(/[^A-Za-z0-9_]+/g, "_") // Replace non-alphanumeric/underscore with _
      .replace(/^_+|_+$/g, "")       // Trim leading/trailing underscores
      .replace(/^[0-9]/, "_$&")      // Prepend _ if starts with digit
      || "unnamed";                  // Fallback if empty after replacements
  } catch (e) {
    console.error(`!!! SANITIZE_NAME_ERROR: Exception during replace/fallback for input "${s}": ${e}`);
    result = "sanitizeName_exception";
  }
  result = unreserve_keyword(result); // Check against reserved keywords
  if (typeof result !== "string" || result === "") {
    console.error(`!!! SANITIZE_NAME_ERROR: Producing invalid result! Type=${typeof result}, Value="${result}" for Input="${s}"`);
    result = result || "unnamed"; // Final fallback check
    if (result === "") result = "sanitizeName_became_empty";
  }
  return result;
}

/** Generates the C struct name for a DynArray of a given base type. */
function getDynArrayName(baseTypeName) {
    // Always sanitize the base name part *before* adding prefix
    const sanitizedBase = sanitizeName(baseTypeName);
    // Sanitize the final generated name to catch potential keyword conflicts
    return sanitizeName(`DynArray_${sanitizedBase}`);
}

/** Generates the C type name for the m_data field within a DynArray struct. */
function getDynArrayFieldType(baseTypeName) {
    // The data field is a pointer to the base type.
    // If baseTypeName was "MyStruct", field type is "MyStruct*".
    // If baseTypeName was "MyStruct*", field type is "MyStruct**".
    return `${baseTypeName}*`;
}


const EnumWalker = (() => {
  const { L, P, R } = CONFIG.TREE; // Node offsets

  /** Finds the next inorder node in a Red-Black tree. */
  function nextNode(n, head) {
    if (n.isNull() || n.equals(head)) return head; // Stop if null or back at head

    const right = rp(n.add(R)); // Check right child
    if (!right.isNull() && !right.equals(head)) {
      // Go right once, then left as far as possible
      let cur = right;
      while (true) {
        const left = rp(cur.add(L));
        if (left.isNull() || left.equals(head)) return cur; // Found leftmost node in right subtree
        cur = left;
      }
    } else {
      // Go up until we come from a left child
      let cur = n;
      let parent = rp(cur.add(P));
      while (!parent.isNull() && !parent.equals(head) && cur.equals(rp(parent.add(R)))) {
        cur = parent;
        parent = rp(cur.add(P));
      }
      return parent; // This parent is the next node (or head if done)
    }
  }

  /** Dumps all variants (name, value) for a given enum descriptor. */
  function dumpVariants(enumDescPtr) {
    if (!isLikelyValidPtr(enumDescPtr)) return [];
    const head = rp(enumDescPtr.add(CONFIG.ENUM_DESCRIPTOR.VARIANT_MAP_PTR)); // Get variant map root
    if (!isLikelyValidPtr(head)) return [];

    const variants = [];
    let n = rp(head.add(L)); // Start with the leftmost node (minimum value)
    let count = 0;
    while (isLikelyValidPtr(n) && !n.equals(head) && count < CONFIG.MAX_VARIANTS) {
      count++;
      const keyPtr = rp(n.add(CONFIG.VARIANT_MAP.KEY_PTR));
      const name = rstr(keyPtr);
      const value = r32(n.add(CONFIG.VARIANT_MAP.VAL_S32));
      if (name !== "<BAD_PTR>" && name !== "<NULL>" && name !== "<READ_ERR>") {
          variants.push([name, value]);
      } else {
          dprint(`Skipping invalid variant name at node ${hex(n)} (keyPtr: ${hex(keyPtr)})`);
      }
      n = nextNode(n, head); // Move to the next inorder node
    }
    if (count >= CONFIG.MAX_VARIANTS) {
        dprint(`Warning: Reached MAX_VARIANTS limit for enum described by ${hex(enumDescPtr)}`);
    }
    return variants;
  }

  /** Dumps all enums and their variants from the DataCore registry. */
  function dumpAllEnums() {
    const head = rp(dataCorePtr.add(CONFIG.OFFSET_ENUM_REGISTRY_IN_DC)); // Get enum map root
    if (!isLikelyValidPtr(head)) {
        console.error("!!! ERROR: Enum registry pointer is invalid.");
        return { enums: {}, indexMap: [] };
    }

    const enums = {}; // { enumName: { variants: [[name, value], ...] } }
    const indexMap = []; // [enumName0, enumName1, ...] for resolving typeSpecificIndex
    let n = rp(head.add(L)); // Start with leftmost node
    let processed = 0;

    while (isLikelyValidPtr(n) && !n.equals(head) && processed < CONFIG.MAX_ENUMS) {
      const namePtr = rp(n.add(CONFIG.ENUM_MAP.KEY_PTR));
      const name = rstr(namePtr);
      const valPtr = rp(n.add(CONFIG.ENUM_MAP.VAL_PTR)); // Pointer to EnumDescriptor

      if (name !== "<BAD_PTR>" && name !== "<NULL>" && name !== "<READ_ERR>" && isLikelyValidPtr(valPtr)) {
          enums[name] = {
            variants: dumpVariants(valPtr),
          };
          indexMap.push(name); // Store original name for index mapping
          processed++;
      } else {
          dprint(`Skipping potentially invalid enum entry at node ${hex(n)} (namePtr: ${hex(namePtr)}, valPtr: ${hex(valPtr)})`);
      }
      n = nextNode(n, head); // Move to next inorder node
    }
     if (processed >= CONFIG.MAX_ENUMS) {
        dprint(`Warning: Reached MAX_ENUMS limit.`);
    }
    return { enums, indexMap };
  }

  return { dumpAllEnums };
})();

/*─────────────────────────────────────────────────────────────────────────*\
|*  5.  STRUCT & FIELD WALKER                                             *|
\*─────────────────────────────────────────────────────────────────────────*/

const StructWalker = (() => {
  const ptrSize = Process.pointerSize;
  const { SLOT_SIZE, CONTROL_EMPTY, CTRL_PTR, DATA_PTR, MASK, SLOT_KEY_PTR } = CONFIG.RH_HASH;

  // Native function pointers for DataCore interaction
  const kGetStructFieldPtrs = new NativeFunction(
    kGetStructFieldPtrsAddr, "pointer", ["pointer", "pointer", "pointer", "int8"], "win64"
  );
  const kGetStructDescByName = new NativeFunction(
    kGetStructDescByNameAddr, "pointer", ['pointer', 'pointer'], "win64"
  );

  /** Retrieves all struct names from the DataCore hash map. */
  function getStructNames() {
    const ctrlStruct = dataCorePtr.add(CONFIG.OFFSET_STRUCT_MAP_IN_DC); // Address of the map control struct
    const pCtrl = rp(ctrlStruct.add(CTRL_PTR)); // Pointer to control bytes array
    const pData = rp(ctrlStruct.add(DATA_PTR)); // Pointer to data slots array
    const mask = ctrlStruct.add(MASK).readU64(); // Hash mask
    const capacity = mask.add(1).toNumber(); // Capacity = mask + 1

    const names = [];
    if (!isLikelyValidPtr(pCtrl) || !isLikelyValidPtr(pData)) {
        console.error("!!! ERROR: Invalid control or data pointer in struct hash map.");
        return [];
    }
    dprint(`Struct map capacity: ${capacity}`);

    let count = 0;
    for (let i = 0; i < capacity && count < CONFIG.MAX_STRUCTS; i++) {
      try {
        const ctrlByte = pCtrl.add(i).readU8();
        if (ctrlByte !== CONTROL_EMPTY) { // Check if slot is occupied
          const slotAddr = pData.add(i * SLOT_SIZE);
          const keyPtr = rp(slotAddr.add(SLOT_KEY_PTR)); // Pointer to struct name string
          const nm = rstr(keyPtr);
          if (nm !== "<BAD_PTR>" && nm !== "<NULL>" && nm !== "<READ_ERR>" && nm !== "") {
              names.push(nm);
              count++;
          } else {
              dprint(`Skipping potentially invalid struct name at slot ${i}, keyPtr: ${hex(keyPtr)}`);
          }
        }
      } catch (e) {
          console.error(`!!! ERROR reading struct map at index ${i}: ${e}`);
          // Attempt to continue to the next slot
      }
    }
     if (count >= CONFIG.MAX_STRUCTS) {
        dprint(`Warning: Reached MAX_STRUCTS limit during name discovery.`);
    }
    return names;
  }

  /** Determines the C base type name for a field based on DataCore metadata. */
  function fieldBaseTypeName(t, enumNameResolver, typeIdx, defPtr) {
    let baseType;
    switch (t) {
      case 1: baseType = "bool"; break;
      case 2: baseType = "int8_t"; break;
      case 3: baseType = "int16_t"; break;
      case 4: baseType = "int32_t"; break;
      case 5: baseType = "int64_t"; break;
      case 6: baseType = "uint8_t"; break;
      case 7: baseType = "uint16_t"; break;
      case 8: baseType = "uint32_t"; break;
      case 9: baseType = "uint64_t"; break;
      case 10: baseType = "CryStringT"; break;
      case 11: baseType = "float"; break;
      case 12: baseType = "double"; break;
      case 13: baseType = "CLocIdentifier"; break;
      case 14: baseType = "CryGUID"; break;
      case 15: {
        const originalEnumName = enumNameResolver(typeIdx);
        baseType = originalEnumName ? sanitizeName(originalEnumName) : `UnknownEnum_${typeIdx}`;
        break;
      }
      case 16: {
              const rawStructName = rstr(defPtr);
              if (rawStructName !== "<BAD_PTR>" && rawStructName !== "<NULL>" && rawStructName !== "<READ_ERR>" && rawStructName !== "") {
                  baseType = sanitizeName(rawStructName);
              } else {
                  baseType = "UnknownStruct";
                  dprint(`Info: defPtr (${hex(defPtr)}) for type 16 field was invalid/null/empty. Using "UnknownStruct".`);
              }
              break;
            }
      default: baseType = `uint8_t/*unk_type_${t}*/`; break;
    }
    return baseType;
  }


  /** Processes a single struct, extracting its fields, size, and dependencies. */
  function processStruct(structName, enumNameResolver) {
    const buf = Memory.alloc(CONFIG.MAX_FIELDS * ptrSize);
    const vec = Memory.alloc(ptrSize * 3);
    vec.writePointer(buf);
    vec.add(ptrSize).writePointer(buf);
    vec.add(ptrSize * 2).writePointer(buf.add(CONFIG.MAX_FIELDS * ptrSize));

    const structNamePtr = Memory.allocUtf8String(structName);
    let pStructDesc = ptr(0);
    let vtablePtr = ptr(0);
    let structSize = 0;
    const sanitizedStructName = sanitizeName(structName);

    try {
        kGetStructFieldPtrs(dataCorePtr, structNamePtr, vec, 1);
        pStructDesc = kGetStructDescByName(dataCorePtr, structNamePtr);
        if (isLikelyValidPtr(pStructDesc)) {
            try { vtablePtr = rp(pStructDesc.add(0x10)); } catch(e) { dprint(`Error reading vtable for ${structName}: ${e}`); vtablePtr = ptr(0); }
            try { structSize = pStructDesc.add(0x28).readU32(); } catch(e) { dprint(`Error reading size for ${structName}: ${e}`); structSize = 0; }
        } else {
            dprint(`Warning: kGetStructDescByName returned invalid pointer for ${structName}`);
        }
    } catch (e) {
        console.error(`!!! ERROR during initial processing for struct ${structName}: ${e}`);
        return {
            name: structName, sanitizedName: sanitizedStructName, fields: [],
            vtablePtr: ptr(0), structSize: 0, dependencies: [],
            arrayElementTypes: new Set(), isGeneratedDynArray: false,
        };
    }

    const begin = vec.readPointer();
    const end = vec.add(ptrSize).readPointer();
    const count = isLikelyValidPtr(begin) && isLikelyValidPtr(end) && end.compare(begin) >= 0
                  ? Math.min(end.sub(begin).toUInt32() / ptrSize, CONFIG.MAX_FIELDS)
                  : 0;

    const rawFields = []; // Store raw field data first
    for (let i = 0; i < count; i++) {
        const fPtr = rp(begin.add(i * ptrSize));
        if (!isLikelyValidPtr(fPtr)) {
            dprint(`Skipping invalid field pointer at index ${i} for struct ${structName}`);
            continue;
        }
        try {
            const fi = CONFIG.FIELDINFO;
            const namePtr = rp(fPtr.add(fi.name));
            const rawName = rstr(namePtr);
            if (rawName === "<BAD_PTR>" || rawName === "<NULL>" || rawName === "<READ_ERR>" || rawName === "") {
                dprint(`Skipping field index ${i} in ${structName} due to invalid name (namePtr: ${hex(namePtr)})`);
                continue;
            }
            rawFields.push({
                rawName: rawName,
                offset: fPtr.add(fi.offset).readU64().toNumber(),
                originalSize: fPtr.add(fi.size).readU64().toNumber(),
                type: fPtr.add(fi.type).readU8(),
                flags: fPtr.add(fi.flags).readU8(),
                isArray: fPtr.add(fi.isArrayOrPointer).readU8() === 1,
                typeIdx: fPtr.add(fi.typeSpecificIndex).readU32(),
                defPtr: rp(fPtr.add(fi.defaultValue)),
            });
        } catch (e) {
            console.error(`!!! ERROR reading raw field data at index ${i} for struct ${structName}: ${e}`);
        }
    }
    rawFields.sort((a, b) => a.offset - b.offset); // Sort by offset

    const fields = [];
    const usedFieldNames = new Set();
    const dependencies = new Set();
    const arrayElementTypes = new Set();

    for (let i = 0; i < rawFields.length; i++) {
        const rf = rawFields[i];
        let sanFieldName = sanitizeName(rf.rawName);
        let n = 1;
        while (usedFieldNames.has(sanFieldName)) {
            sanFieldName = `${sanitizeName(rf.rawName)}_${n++}`;
        }
        usedFieldNames.add(sanFieldName);

        const baseTypeNameForField = fieldBaseTypeName(rf.type, enumNameResolver, rf.typeIdx, rf.defPtr);
        let final_dtype;
        let final_layout_size;
        let isOpaque = (rf.type === 16 && baseTypeNameForField === "UnknownStruct");
        let isPointerForced = false;

        if (isOpaque) {
            if (rf.isArray) {
                final_dtype = "uint8_t*";
                final_layout_size = ptrSize;
            } else {
                final_dtype = "uint8_t";
                final_layout_size = rf.originalSize > 0 ? rf.originalSize : 1;
            }
        } else {
            if (rf.isArray) {
                final_dtype = getDynArrayName(baseTypeNameForField) + '*';
                final_layout_size = ptrSize;
                if (baseTypeNameForField && baseTypeNameForField !== "UnknownStruct") {
                    dependencies.add(getDynArrayName(baseTypeNameForField));
                    arrayElementTypes.add(baseTypeNameForField);
                }
            } else if (rf.type === 16) { // Nested struct, not array, not opaque
                isPointerForced = false;
                // 1. Self-Referential Check
                if (baseTypeNameForField === sanitizedStructName) {
                    final_dtype = baseTypeNameForField + '*';
                    final_layout_size = ptrSize;
                    isPointerForced = true;
                    dprint(`  Self-ref field ${sanitizedStructName}.${sanFieldName} forced to pointer.`);
                } else {
                    // 2. Offset vs. Size Heuristic
                    const nextField = (i + 1 < rawFields.length) ? rawFields[i+1] : null;
                    if (nextField && (rf.offset + rf.originalSize > nextField.offset)) {
                        final_dtype = baseTypeNameForField + '*';
                        final_layout_size = ptrSize;
                        isPointerForced = true;
                        dprint(`  Overlap heuristic: ${sanitizedStructName}.${sanFieldName} (size 0x${rf.originalSize.toString(16)}) forced to pointer due to next field at 0x${nextField.offset.toString(16)} (current offset 0x${rf.offset.toString(16)}).`);
                    } else if (rf.originalSize === ptrSize) { // Ambiguous case, default to pointer for safety/cycles
                        final_dtype = baseTypeNameForField + '*';
                        final_layout_size = ptrSize;
                        isPointerForced = true; // Technically, size matched, but we prefer pointer here.
                         dprint(`  Size-match heuristic: ${sanitizedStructName}.${sanFieldName} (size 0x${rf.originalSize.toString(16)}) treated as pointer.`);
                    } else { // Default to inline if no other rule applies
                        final_dtype = baseTypeNameForField;
                        final_layout_size = rf.originalSize;
                    }
                }
                if (baseTypeNameForField && baseTypeNameForField !== sanitizedStructName && baseTypeNameForField !== "UnknownStruct") {
                    dependencies.add(baseTypeNameForField);
                }
            } else if ([10, 13, 14].includes(rf.type)) {
                final_dtype = baseTypeNameForField + '*';
                final_layout_size = ptrSize;
            } else { // Primitives, Enums
                final_dtype = baseTypeNameForField;
                final_layout_size = rf.originalSize;
            }
        }

        fields.push({
            name: sanFieldName, rawName: rf.rawName, offset: rf.offset,
            size: final_layout_size, originalSize: rf.originalSize,
            type: rf.type, isArray: rf.isArray, flags: rf.flags,
            dtype: final_dtype, baseDtype: baseTypeNameForField,
            enumRef: rf.type === 15 ? (enumNameResolver(rf.typeIdx) ?? null) : null,
            isOpaque: isOpaque,
            isPointerOverride: isPointerForced // Store if we forced it to be a pointer
        });
    }
    // Fields are already sorted by offset from rawFields

    return {
      name: structName, sanitizedName: sanitizedStructName, fields: fields,
      vtablePtr: vtablePtr, structSize: structSize,
      dependencies: Array.from(dependencies),
      arrayElementTypes: arrayElementTypes, isGeneratedDynArray: false,
    };
  }

  /** Dumps all structs found in the DataCore registry. */
  function dumpAllStructs(enumNameResolver) {
    const names = getStructNames();
    dprint(`Found ${names.length} raw struct names.`);
    const results = names.map(n => processStruct(n, enumNameResolver));
    const validResults = results.filter(s => s && (s.fields.length > 0 || s.structSize > 0 || s.isGeneratedDynArray));
    dprint(`Successfully processed ${validResults.length} structs.`);
    return validResults;
  }

  return { dumpAllStructs };
})();


/*─────────────────────────────────────────────────────────────────────────*\
|*  6.  DynArray STRUCT GENERATION                                        *|
\*─────────────────────────────────────────────────────────────────────────*/

/**
 * Generates DynArray_<T> struct definitions (as JS objects) for each unique
 * element type T found in array fields across all structs.
 */
function generateDynArrayStructs(allStructsData) {
    const uniqueArrayElementTypes = new Set(); // Stores unique baseType strings
    const dynArrayStructs = new Map(); // Map<DynArray_T_Name, DynArrayStructObject>
    const ptrSize = Process.pointerSize;

    // 1. Collect all unique base element types (T) used in arrays (T[])
    for (const s of allStructsData) {
        // s.arrayElementTypes should be a Set populated by processStruct
        if (s.arrayElementTypes instanceof Set) {
            s.arrayElementTypes.forEach(baseType => {
                // Filter out problematic base types before adding
                if (baseType &&
                    !baseType.startsWith("UnknownStruct") &&
                    !baseType.startsWith("sanitizeName_") &&
                    baseType !== "unnamed")
                {
                   uniqueArrayElementTypes.add(baseType);
                } else {
                    dprint(`Skipping DynArray generation for problematic base type: ${baseType}`);
                }
            });
        }
    }
    dprint(`Found ${uniqueArrayElementTypes.size} unique base types used in arrays.`);

    // 2. Create DynArray struct objects for each unique base type
    for (const baseType of uniqueArrayElementTypes) {
        const dynArrayName = getDynArrayName(baseType); // e.g., "DynArray_MyStruct"
        const fieldType = getDynArrayFieldType(baseType); // e.g., "MyStruct*" or "MyStruct**"

        // Avoid generating if a struct with this name already exists (either original or another generated)
        if (!dynArrayStructs.has(dynArrayName) && !allStructsData.some(s => s.sanitizedName === dynArrayName)) {
            dprint(`Generating DynArray struct: ${dynArrayName} for base type ${baseType}`);

            // Determine the dependency: DynArray_T depends on T (use sanitized name of T)
            const dependency = sanitizeName(baseType);

            dynArrayStructs.set(dynArrayName, {
                name: dynArrayName, // Use the generated name as the "original" name for consistency
                sanitizedName: dynArrayName, // Already sanitized during generation
                fields: [
                    {
                        name: "m_data",           // Standard name for the pointer field
                        rawName: "m_data",
                        offset: 0,
                        size: ptrSize,            // The field itself is a pointer
                        originalSize: ptrSize,    // Underlying size is also pointer size
                        type: -1,                 // Custom type marker (not from DataCore enums)
                        isArray: false,           // The m_data field itself is not an array
                        flags: 0,
                        dtype: fieldType,         // C type, e.g., "MyStruct*"
                        baseDtype: baseType,      // Original base type T
                        enumRef: null,
                        isOpaque: false,          // DynArray m_data field is not opaque itself
                        isPointerOverride: true,  // m_data is always a pointer
                    }
                ],
                vtablePtr: ptr(0),              // No vtable for simple DynArray struct
                structSize: ptrSize,            // Size of the DynArray struct is just the pointer
                dependencies: dependency !== "UnknownStruct" ? [dependency] : [], // DynArray_T depends on T
                arrayElementTypes: new Set(),   // DynArray struct itself doesn't contain array fields
                isGeneratedDynArray: true,      // Mark as generated
            });
        } else {
             dprint(`Skipping generation for ${dynArrayName}, name collision or already exists.`);
        }
    }

    return dynArrayStructs; // Return the map of generated structs
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  7.  TOPOLOGICAL SORT FOR STRUCTS                                      *|
\*─────────────────────────────────────────────────────────────────────────*/

/**
 * Performs a topological sort on structs based on dependencies.
 * Returns { sorted: Array<Struct>, unprocessed: Array<Struct> }
 */
function sortStructsTopologically(structsData, iteration = 1, forcePointerHeuristicForDependencies = false) {
  dprint(`Topological Sort: Starting iteration ${iteration}... ForcePointerHeuristic: ${forcePointerHeuristicForDependencies}`);
  const adj = new Map();
  const inDegree = new Map();
  const structMap = new Map();

  // --- Initialization Phase ---
  dprint(`Topological Sort (Iter ${iteration}): Initializing maps...`);
  let initializedCount = 0;
  for (const s of structsData) {
    const sanName = s.sanitizedName;
    if (!sanName || sanName === "unnamed" || sanName.startsWith("sanitizeName_")) {
        console.warn(`Warning (Iter ${iteration}): Skipping struct with invalid sanitized name during sort init: ${s.name} -> ${sanName}`);
        continue;
    }
    if (structMap.has(sanName) && iteration === 1) {
      console.warn(`Warning (Iter ${iteration}): Duplicate sanitized struct name detected during sort init: ${sanName} (from original: ${s.name}). Overwriting previous entry in map.`);
    }
    adj.set(sanName, new Set());
    inDegree.set(sanName, 0);
    structMap.set(sanName, s);
    initializedCount++;
  }
  dprint(`Topological Sort (Iter ${iteration}): Initialized ${initializedCount} structs in the map.`);
  if (initializedCount !== structsData.length && iteration === 1) {
    console.warn(`Warning (Iter ${iteration}): ${structsData.length - initializedCount} structs were skipped during sort initialization due to invalid/duplicate sanitized names.`);
  }

  // --- Graph Building Phase ---
  dprint(`Topological Sort (Iter ${iteration}): Building dependency graph...`);
  let edgeCount = 0;
  for (const s of structsData) {
    const dependentName = s.sanitizedName;
    if (!structMap.has(dependentName)) continue;

    // Recalculate dependencies based on current field interpretations, especially if forcePointerHeuristicForDependencies is true
    const currentDependencies = new Set();
    s.fields.forEach(f => {
        let isConsideredPointer = f.isArray || // DynArrays are pointers to their management struct
                                  f.dtype.endsWith('*') || // Already determined to be a pointer
                                  ([10,13,14].includes(f.type) && !f.isArray); // Special Cry types are pointers

        if (forcePointerHeuristicForDependencies && f.type === 16 && !f.isArray && !f.isOpaque) {
            isConsideredPointer = true; // For this sort iteration, assume type 16 non-array is a pointer
        }

        if (f.baseDtype && f.baseDtype !== "UnknownStruct" && f.baseDtype !== dependentName) {
            if (f.isArray) {
                currentDependencies.add(getDynArrayName(f.baseDtype));
            } else if (isConsideredPointer) { // Only add dependency if it's a pointer type or forced to be
                currentDependencies.add(f.baseDtype);
            } else { // Inline struct, dependency is on its fields' types, not the struct itself directly for ordering
                // This part is tricky. If it's inline, the dependency is "stronger".
                // For now, the original `s.dependencies` (which considers inline structs as direct deps) is used
                // if `forcePointerHeuristicForDependencies` is false.
                // If true, we are trying to break cycles by making them pointers.
                if (!forcePointerHeuristicForDependencies) { // If not forcing, use original logic
                     if (f.type === 16) currentDependencies.add(f.baseDtype);
                }
            }
        }
    });
    // If forcePointerHeuristicForDependencies is false, use the originally calculated dependencies.
    // Otherwise, use the newly calculated ones that assume pointers for type 16.
    const dependenciesToUse = forcePointerHeuristicForDependencies ? Array.from(currentDependencies) : s.dependencies;


    if (!Array.isArray(dependenciesToUse)) {
      console.error(`Error (Iter ${iteration}): Dependencies for struct ${s.name} (${dependentName}) is not an array. Skipping dependency processing.`);
      continue;
    }

    for (const dependencyName of dependenciesToUse) {
      if (typeof dependencyName !== "string" || dependencyName === "" || dependencyName.startsWith("UnknownStruct")) {
        continue;
      }

      if (structMap.has(dependencyName)) {
        const dependentsSet = adj.get(dependencyName);
        if (!(dependentsSet instanceof Set)) {
          console.error(`FATAL Error (Iter ${iteration}): Adjacency map corruption! Key ${dependencyName} does not map to a Set.`);
          continue;
        }

        if (!dependentsSet.has(dependentName)) {
          dependentsSet.add(dependentName);
          edgeCount++;
          if (inDegree.has(dependentName)) {
            inDegree.set(dependentName, inDegree.get(dependentName) + 1);
          } else {
            console.error(`Error (Iter ${iteration}): Dependent struct ${dependentName} not found in inDegree map during graph build.`);
          }
        }
      } else {
         dprint(`Info (Iter ${iteration}): Struct ${dependentName} depends on '${dependencyName}', which is not in the current struct map for sorting. Ignoring this dependency.`);
      }
    }
  }
  dprint(`Topological Sort (Iter ${iteration}): Graph built with ${edgeCount} dependency edges.`);

  // --- Queue Initialization Phase (Kahn's Algorithm) ---
  dprint(`Topological Sort (Iter ${iteration}): Initializing queue with nodes of in-degree 0...`);
  const queue = [];
  for (const [name, degree] of inDegree.entries()) {
    if (degree === 0) {
      if (structMap.has(name)) {
          queue.push(name);
      } else {
          console.error(`Error (Iter ${iteration}): Struct ${name} has in-degree 0 but is not in structMap. Discarding from initial queue.`);
      }
    }
  }
  dprint(`Topological Sort (Iter ${iteration}): Initial queue size: ${queue.length}`);

  // --- Sorting Phase (Kahn's Algorithm) ---
  dprint(`Topological Sort (Iter ${iteration}): Processing queue...`);
  const currentSortedStructs = [];
  const processedNamesInThisIteration = new Set();

  while (queue.length > 0) {
    const currentName = queue.shift();

    if (typeof currentName !== "string" || !structMap.has(currentName)) {
      console.error(`Error (Iter ${iteration}): Dequeued invalid or unknown name "${currentName}". Skipping.`);
      continue;
    }
    if (processedNamesInThisIteration.has(currentName)) {
        console.warn(`Warning (Iter ${iteration}): Attempting to process node ${currentName} again. Skipping.`);
        continue;
    }

    const currentStruct = structMap.get(currentName);
    currentSortedStructs.push(currentStruct);
    processedNamesInThisIteration.add(currentName);

    if (adj.has(currentName)) {
      const neighbors = adj.get(currentName);
       if (!(neighbors instanceof Set)) {
           console.error(`FATAL ERROR (Iter ${iteration}): adj.get('${currentName}') returned non-Set value! Type: ${typeof neighbors}`);
           continue;
       }

      for (const neighborName of neighbors) {
        if (typeof neighborName !== "string" || !inDegree.has(neighborName)) {
          console.error(`Error (Iter ${iteration}): Invalid neighbor name "${neighborName}" (dependent of ${currentName}). Skipping degree update.`);
          continue;
        }

        const currentDegree = inDegree.get(neighborName);
        if (typeof currentDegree !== "number" || isNaN(currentDegree) || currentDegree <= 0) {
          console.error(`Error (Iter ${iteration}): Invalid or non-positive in-degree (${currentDegree}) for neighbor ${neighborName} before decrementing. Skipping degree update.`);
          continue;
        }

        inDegree.set(neighborName, currentDegree - 1);

        if (inDegree.get(neighborName) === 0) {
          if (structMap.has(neighborName)) {
              queue.push(neighborName);
          } else {
              console.error(`Error (Iter ${iteration}): Neighbor ${neighborName} reached in-degree 0 but is not in structMap. Discarding.`);
          }
        }
      }
    }
  }
  dprint(`Topological Sort (Iter ${iteration}): Finished processing queue. Added ${currentSortedStructs.length} structs to sorted list for this iteration.`);

  const remainingStructs = [];
  for (const s of structsData) {
      if (!processedNamesInThisIteration.has(s.sanitizedName)) {
          remainingStructs.push(s);
      }
  }
  dprint(`Topological Sort (Iter ${iteration}): ${remainingStructs.length} structs remaining.`);

  return {
    sortedThisIteration: currentSortedStructs,
    remainingForNextIteration: remainingStructs,
  };
}

/**
 * Iteratively sorts structs, applying pointer override heuristics for cycles.
 */
function iterativeTopologicalSort(allStructsData) {
    let currentStructsToProcess = [...allStructsData];
    let finalSortedList = [];
    let iteration = 1;
    const MAX_ITERATIONS = 5; // Safety break for too many iterations

    while (currentStructsToProcess.length > 0 && iteration <= MAX_ITERATIONS) {
        dprint(`--- Starting Iterative Sort - Iteration ${iteration} ---`);
        // For iterations > 1, we force pointer heuristic for dependency calculation
        // to try and break cycles.
        const forcePointerHeuristic = iteration > 1;
        const { sortedThisIteration, remainingForNextIteration } = sortStructsTopologically(currentStructsToProcess, iteration, forcePointerHeuristic);

        finalSortedList.push(...sortedThisIteration);

        if (remainingForNextIteration.length === 0) {
            dprint("All structs sorted successfully after iteration " + iteration);
            currentStructsToProcess = []; // Empty the list to exit loop
            break;
        }

        if (remainingForNextIteration.length === currentStructsToProcess.length && iteration > 1) {
            // No progress made even with pointer heuristic, indicates a hard cycle or unresolvable dependencies
            dprint(`No progress in iteration ${iteration} despite pointer heuristic. Remaining ${remainingForNextIteration.length} structs are likely in hard cycles or have missing external dependencies.`);
            finalSortedList.push(...remainingForNextIteration); // Add them to the end
            currentStructsToProcess = []; // Empty the list to exit loop
            break;
        }
        currentStructsToProcess = remainingForNextIteration; // Prepare for next iteration
        iteration++;
    }

    if (iteration > MAX_ITERATIONS && currentStructsToProcess.length > 0) {
        dprint(`Reached MAX_ITERATIONS for topological sort. Appending ${currentStructsToProcess.length} remaining structs.`);
        finalSortedList.push(...currentStructsToProcess);
    }

    // The 'unprocessed' part for generateHeader will be any structs that are *still* in
    // currentStructsToProcess after the loop (if MAX_ITERATIONS was hit and no progress was made in the last attempt).
    // If all were sorted, unprocessed will be empty.
    const finalUnprocessed = currentStructsToProcess.length > 0 && iteration > MAX_ITERATIONS ? currentStructsToProcess :
                             (iteration > 1 && remainingForNextIteration.length === currentStructsToProcess.length) ? currentStructsToProcess : [];


    return {
        sorted: finalSortedList.filter(s => !finalUnprocessed.includes(s)),
        unprocessed: finalUnprocessed
    };
}


/*─────────────────────────────────────────────────────────────────────────*\
|*  8.  HEADER GENERATOR                                                   *|
\*─────────────────────────────────────────────────────────────────────────*/

/** Generates the final C header string. */
function generateHeader(pre, enumsData, { sorted: sortedStructs, unprocessed: unprocessedStructs }) {
  const out = []; // Array to build the header lines

  /* 0. Preamble */
  out.push(pre.trimEnd(), ""); // Add preamble verbatim

  /* 1. ENUMS (Prefixed C-Style) */
  out.push("/*=========================================================================*/");
  out.push("/*   ENUM DEFINITIONS (C-Style with Prefixed Variants)                     */");
  out.push("/*=========================================================================*/\n");
  const sortedEnumNames = Object.keys(enumsData.enums).sort();
  for (const enumName of sortedEnumNames) {
      const { variants } = enumsData.enums[enumName];
      const enumId = sanitizeName(enumName); // Sanitized name for the enum type itself
      out.push(`// Original name: ${enumName}`);
      // Use standard C enum
      out.push(`enum ${enumId} {`);

      const processedVariants = variants
          .map(([n, v]) => ({
              originalName: n,
              sanitizedVariantName: sanitizeName(n), // Sanitize variant part first
              value: v
           }))
          .sort((a, b) => a.value - b.value);

      // Determine padding based on the longest *prefixed* variant name
      const prefixedNames = processedVariants.map(v => `${enumId}_${v.sanitizedVariantName}`);
      const maxNameLength = prefixedNames.reduce((max, name) => Math.max(max, name.length), 0);
      const uniquePrefixedNames = new Set(); // Track final prefixed names within this enum

      processedVariants.forEach(({ originalName, sanitizedVariantName, value }) => {
          // Create the prefixed name
          let basePrefixedName = `${enumId}_${sanitizedVariantName}`;

          // Sanitize the *combined* name again, just in case prefixing created issues
          // (e.g., double underscores if enumId ended with _ and variant started with _)
          // Also handles potential keyword clashes if the combined name becomes one.
          let finalPrefixedName = sanitizeName(basePrefixedName);

          // Ensure uniqueness *within* the enum (e.g., if sanitization caused a clash AFTER prefixing)
          if (uniquePrefixedNames.has(finalPrefixedName)) {
              let suffix = 1;
              const tempBase = finalPrefixedName; // Base for adding suffix
              while(uniquePrefixedNames.has(`${tempBase}_${suffix}`)) {
                  suffix++;
              }
              finalPrefixedName = `${tempBase}_${suffix}`;
              dprint(`Warning: Renaming duplicate prefixed variant name "${basePrefixedName}" to "${finalPrefixedName}" in enum ${enumId}`);
          }
          uniquePrefixedNames.add(finalPrefixedName);

          const padding = " ".repeat(maxNameLength > finalPrefixedName.length ? maxNameLength - finalPrefixedName.length : 0);
          let valueStr = value < 0 ? `-0x${Math.abs(value).toString(16)}` : `0x${value.toString(16)}`;
          // Add original variant name in comment for reference
          out.push(`    ${finalPrefixedName}${padding} = ${valueStr}, /* ${originalName} */`);
      });
      out.push(`};\n`);
  }

  /* 2. FORWARD DECLARATIONS */
  out.push("/*=========================================================================*/");
  out.push("/*   STRUCT FORWARD DECLARATIONS                                           */");
  out.push("/*=========================================================================*/");
  out.push("/* Forward declarations allow pointers to structs defined later.           */\n");
  const allStructsForForwardDecl = [...sortedStructs, ...unprocessedStructs]; // Use the final lists
  const declaredStructs = new Set();
  allStructsForForwardDecl.forEach(s => {
      if (s.sanitizedName && !s.sanitizedName.startsWith("UnknownStruct") && !s.sanitizedName.startsWith("sanitizeName_") && !declaredStructs.has(s.sanitizedName)) {
          out.push(`struct ${s.sanitizedName};`);
          declaredStructs.add(s.sanitizedName);
      }
  });
  // Also forward declare the DynArray types generated (if any were part of the sorted/unprocessed lists)
  allStructsForForwardDecl.forEach(s => {
      if (s.isGeneratedDynArray && s.sanitizedName && !declaredStructs.has(s.sanitizedName)) {
           out.push(`struct ${s.sanitizedName};`);
           declaredStructs.add(s.sanitizedName);
      }
  });
  out.push("\n");


  /* Helper function to generate the C definition string for a single struct */
  const generateStructDefinition = (s, isUnprocessedBlock = false) => {
    const structLines = [];
    const sn = s.sanitizedName;

    structLines.push(`// Original name: ${s.name}`);
    if (s.isGeneratedDynArray) {
        const baseT = s.fields[0]?.baseDtype ?? 'unknown';
        structLines.push(`// Generated DynArray for base type: ${baseT}`);
    }
    structLines.push(`// Size: 0x${s.structSize.toString(16)}`);
    if (isLikelyValidPtr(s.vtablePtr)) {
        structLines.push(`// VTable: ${hex(s.vtablePtr)}`);
    } else {
      consoile.log(`// not isLikelyValidPtr? VTable: ${hex(s.vtablePtr)}`);
    }
    if (isUnprocessedBlock) {
        structLines.push(`// WARNING: This struct was part of a cycle or had missing dependencies.`);
        structLines.push(`// Pointer heuristic may have been applied to its type 16 fields for ordering.`);
    }


    structLines.push(`struct ${sn} {`);
    let currentOffset = 0;
    let padIndex = 0;

    const emitPadding = (gapSize, offsetBeforePadding) => {
      if (gapSize > 0) {
        structLines.push(`    uint8_t _pad_${padIndex++}[0x${gapSize.toString(16)}]; // Offset: 0x${offsetBeforePadding.toString(16)}`);
      } else if (gapSize < 0) {
          structLines.push(`    /* !!! FIELD OVERLAP DETECTED at offset 0x${offsetBeforePadding.toString(16)} (gap: ${gapSize}) !!! */`);
      }
    };

    s.fields.forEach((f) => {
      const gap = f.offset - currentOffset;
      emitPadding(gap, currentOffset);

      const nameComment = (f.name !== f.rawName && f.rawName) ? ` /* ${f.rawName} */` : "";
      const offsetComment = ` // Offset: 0x${f.offset.toString(16)}`;
      let fieldDefinition;
      let fieldLayoutSize = f.size; // Use the size calculated in processStruct
      let sizeAndTypeComment = "";
      let finalDtypeForField = f.dtype;

      // If this struct is in the "unprocessed" block, and the field is type 16 (struct) and not an array,
      // AND it wasn't already determined to be a pointer by the refined heuristics in processStruct,
      // aggressively assume it's a pointer to help with IDA.
      if (isUnprocessedBlock && f.type === 16 && !f.isArray && !f.isOpaque && !f.dtype.endsWith('*') && !f.isPointerOverride) {
          finalDtypeForField = f.baseDtype + '*'; // Force to pointer
          fieldLayoutSize = Process.pointerSize; // Layout size becomes pointer size
          sizeAndTypeComment = ` /* CYCLIC_HEURISTIC: Forced to pointer. Original size: 0x${f.originalSize.toString(16)} */`;
          dprint(`Applying cyclic heuristic to ${sn}.${f.name}, changing type to ${finalDtypeForField}`);
      }


      if (f.isOpaque && !f.isArray) { // Opaque struct field (not array of opaque)
          fieldDefinition = `    uint8_t ${f.name}[0x${fieldLayoutSize.toString(16)}];${nameComment} // Opaque struct field (type resolution failed)${offsetComment}`;
      } else {
          const arrayMarker = (f.isArray && !f.isOpaque) ? " // Pointer to DynArray struct" :
                              (f.isOpaque && f.isArray) ? " // Pointer to array of opaque structs" : "";

          if (f.type === 16 && !f.isArray && !f.isOpaque) { // Special comment for type 16 non-array
              if (finalDtypeForField.endsWith('*')) { // It was determined/forced to be a pointer
                  sizeAndTypeComment += ` /* Target struct size: 0x${f.originalSize.toString(16)} */`;
              } else { // It was determined to be inline
                  if (f.originalSize === Process.pointerSize && fieldLayoutSize === Process.pointerSize) {
                     sizeAndTypeComment += ` /* Inline struct, size matches ptrSize */`;
                  }
              }
          } else if (fieldLayoutSize !== f.originalSize && !f.isArray && ![10,13,14].includes(f.type)) {
              sizeAndTypeComment += ` (Original size: 0x${f.originalSize.toString(16)})`;
          }
          fieldDefinition = `    ${finalDtypeForField} ${f.name};${nameComment}${offsetComment}${sizeAndTypeComment}${arrayMarker}`;
      }
      // Ensure fieldDefinition is set if not by opaque block
      if (!fieldDefinition) {
           const arrayMarker = (f.isArray && !f.isOpaque) ? " // Pointer to DynArray struct" :
                              (f.isOpaque && f.isArray) ? " // Pointer to array of opaque structs" : "";
           fieldDefinition = `    ${finalDtypeForField} ${f.name};${nameComment}${offsetComment}${sizeAndTypeComment}${arrayMarker}`;
      }


      structLines.push(fieldDefinition);
      currentOffset = f.offset + fieldLayoutSize;

    });

    const trailingGap = s.structSize - currentOffset;
    emitPadding(trailingGap, currentOffset);

    structLines.push(`};\n`);
    return structLines.join("\n");
  };


  /* 3. CYCLIC/UNPROCESSED STRUCTS (DEFINED AFTER FORWARD DECLS) */
  if (unprocessedStructs && unprocessedStructs.length > 0) {
    out.push("/*=========================================================================*/");
    out.push("/*   CYCLIC / UNPROCESSED STRUCT DEFINITIONS                             */");
    out.push("/*=========================================================================*/");
    out.push("/* These structs have cyclic dependencies or could not be sorted.        */");
    out.push("/* Forward declarations above should resolve pointer usage issues.       */\n");

    unprocessedStructs.sort((a, b) => a.sanitizedName.localeCompare(b.sanitizedName));
    for (const s of unprocessedStructs) {
       if (s.sanitizedName && !s.sanitizedName.startsWith("UnknownStruct") && !s.sanitizedName.startsWith("sanitizeName_")) {
           out.push(generateStructDefinition(s, true)); // Pass true for unprocessed block
       } else {
           dprint(`Skipping definition for unprocessed struct with invalid name: ${s.name} -> ${s.sanitizedName}`);
       }
    }
  }

  /* 4. TOPOLOGICALLY SORTED STRUCTS (DEFINED LAST) */
  out.push("/*=========================================================================*/");
  out.push("/*   NON-CYCLIC STRUCT DEFINITIONS (Sorted)                              */");
  out.push("/*=========================================================================*/");
  out.push("/* These structs were topologically sorted based on their dependencies.    */\n");
  for (const s of sortedStructs) {
     if (s.sanitizedName && !s.sanitizedName.startsWith("UnknownStruct") && !s.sanitizedName.startsWith("sanitizeName_")) {
         out.push(generateStructDefinition(s, false)); // Pass false for sorted block
     } else {
         dprint(`Skipping definition for sorted struct with invalid name: ${s.name} -> ${s.sanitizedName}`);
     }
  }

  return out.join("\n");
}


/*─────────────────────────────────────────────────────────────────────────*\
|*  9.  MAIN – RUN ONCE, EMIT HEADER, EXIT                                *|
\*─────────────────────────────────────────────────────────────────────────*/

(function main() {
  // Define the C header preamble
  const PREAMBLE = String.raw`#ifndef STARCITIZEN_DATACORE_HPP
#define STARCITIZEN_DATACORE_HPP

#include <stdint.h> // For sized types like uint64_t, int32_t, etc.

/* Define bool if not using <stdbool.h> */
/* typedef uint8_t bool; */
/* #define true 1 */
/* #define false 0 */

/*=========================================================================*/
/*   CORE TYPE DEFINITIONS                                                 */
/*=========================================================================*/

/* Unique runtime entity handle (seems to be 64-bit in Star Citizen) */
typedef uint64_t EntityId;

/* 32-bit FNV-1a hash, commonly used in CryEngine */
typedef uint32_t Fnv1a32;

/*-------------------------------------------------------------------------*
 * CryString
 *-------------------------------------------------------------------------*/

/* The user-facing string type (holds pointer to heap data) */
/* Note: This is often a template (CryStringT<char>) */
struct CryStringT {
    char *m_str;               /* -> UTF-8 data, NUL-terminated on heap */
};

/* The hidden metadata header preceding the string data on the heap */
struct CryString_StrHeader {
    int32_t nRefCount;         /* Reference counter */
    int32_t nLength;           /* Number of characters (excluding NUL) */
    int32_t nAllocSize;        /* Allocated size (excluding NUL and this header) */
    /* char data[nAllocSize+1] follows */
};

/* Macro to retrieve the heap header from a CryStringT object's pointer */
/* Usage: CryString_StrHeader* header = CRYSTRING_HEADER(myCryString); */
#define CRYSTRING_HEADER(obj)  ((struct CryString_StrHeader*)((obj).m_str) - 1)

/*-------------------------------------------------------------------------*
 * CryGUID
 *-------------------------------------------------------------------------*/

/* 128-bit Globally Unique Identifier */
struct CryGUID {
    uint64_t lo; /* Lower 64 bits */
    uint64_t hi; /* Upper 64 bits */
};

/*-------------------------------------------------------------------------*
 * Localization Helpers
 *-------------------------------------------------------------------------*/

/* Canonical localisation key (pointer to identifier string) */
struct CLocIdentifier {
    char *m_sIdentifier; /* Null-terminated, heap-allocated string */
};

/* Pre-hashed localisation key (FNV-1a 32-bit hash of the identifier) */
typedef Fnv1a32 CLocIdentifierHash;

/* Localised string resolved for the current language (pointer to text) */
struct CLocString {
    char *m_wString;  /* Pointer to language-specific UTF-8 text */
};

/* Generic 32-bit string hash wrapper (often FNV-1a) */
typedef Fnv1a32 CStringHash;

/*-------------------------------------------------------------------------*
 * DynArray Placeholders
 *-------------------------------------------------------------------------*/
/* The generated DynArray_T structs below represent the stack-allocated part */
/* of a dynamic array (CryEngine's LegacyDynArray / SmallDynStorage).      */
/* This typically just holds a pointer ('m_data') to the heap-allocated    */
/* element buffer. The actual elements on the heap are preceded by a       */
/* header containing size and capacity information, similar in concept to  */
/* CryString_StrHeader but with different fields.                          */

#endif // STARCITIZEN_DATACORE_HPP PREAMBLE GUARD

/*=========================================================================*/
/*   BEGINNING OF AUTO-GENERATED DEFINITIONS                               */
/*=========================================================================*/
`; // End of PREAMBLE

  try {
      /* 1. Enumerations */
      dprint("Step 1: Dumping enums...");
      const enumsData = EnumWalker.dumpAllEnums();
      dprint(`Found ${Object.keys(enumsData.enums).length} enums.`);

      /* Helper function for StructWalker to resolve enum names from type index */
      const enumNameResolver = (idx) =>
        idx >= 0 && idx < enumsData.indexMap.length
          ? enumsData.indexMap[idx] // Return original name; sanitization happens later if needed
          : null;

      /* 2. Structs (Initial Dump) */
      dprint("Step 2: Dumping initial structs and fields...");
      const initialStructsData = StructWalker.dumpAllStructs(enumNameResolver);
      dprint(`Found ${initialStructsData.length} initial structs.`);

      /* 3. Generate DynArray Struct Definitions */
      dprint("Step 3: Generating DynArray struct objects...");
      const dynArrayStructsMap = generateDynArrayStructs(initialStructsData);
      dprint(`Generated ${dynArrayStructsMap.size} DynArray struct objects.`);

      /* 4. Combine Original Structs and Generated DynArrays */
      const allStructsData = [...initialStructsData, ...dynArrayStructsMap.values()];
      dprint(`Total structs including DynArrays: ${allStructsData.length}`);

      /* 5. Sort Structs Topologically (Iteratively) */
      dprint("Step 5: Sorting all structs topologically (iteratively)...");
      const sortResult = iterativeTopologicalSort(allStructsData); // Use the new iterative sort
      dprint(`Sorting complete. Sorted: ${sortResult.sorted.length}, Unprocessed: ${sortResult.unprocessed.length}`);


      /* 6. DEBUG: Write intermediate data to dump.json */
      if (ENABLE_DPRINT) { // Only write dump if diagnostics are enabled
          try {
            dprint("Step 6a: Writing combined data to dump.json...");
            // Combine sorted and unprocessed for the dump file
            const dumpStructs = [...sortResult.sorted, ...sortResult.unprocessed];
            // Sort enums alphabetically and their variants by value for the dump file
            const dumpEnums = Object.entries(enumsData.enums)
                                    .sort(([nameA], [nameB]) => nameA.localeCompare(nameB))
                                    .map(([name, data]) => [name, data.variants.sort(([,vA],[,vB]) => vA - vB)]);

            const dumpData = { structs: dumpStructs, enums: dumpEnums };

            const jsonString = JSON.stringify(dumpData, (key, value) => {
                // Custom replacer for JSON stringify
                if (value instanceof NativePointer) {
                    return value.toString(); // Convert pointers to strings
                }
                if (value instanceof Set) {
                    return Array.from(value); // Convert Sets to Arrays
                }
                // Handle potential BigInts from U64 reads if they occur (though offset/size are converted to Number)
                if (typeof value === 'bigint') {
                    return value.toString() + 'n'; // Mark BigInts
                }
                return value; // Default handling
            }, 2); // Pretty print JSON with 2 spaces indentation

            const file = new File("dump.json", "w");
            file.write(jsonString);
            file.close();
            dprint("Successfully wrote data to dump.json");
          } catch (e) {
            console.error(`Error writing dump.json: ${e}`);
            dprint(`Error writing dump.json: ${e.stack}`);
          }
      }

      /* 7. Assemble final header */
      dprint("Step 7: Generating final header content...");
      const header = generateHeader(PREAMBLE, enumsData, sortResult);

      /* 8. Emit Header to File */
        try {
            dprint("Step 8: Writing structs.h...");
            // const header = generateHeader(PREAMBLE, enumsData, sortResult); // Already generated
            const file = new File("structs.h", "w");
            file.write(header);
            file.close();
            dprint("Successfully wrote headers to structs.h");
        } catch (e) {
            console.error(`Error writing structs.h: ${e}`);
            dprint(`Error writing structs.h: ${e}`);
        }

      /* 9. Graceful exit */
      dprint("Step 9: Scheduling script detachment...");
      setTimeout(() => {
        dprint("Detaching script now.");
        // Attempt to unload the script cleanly
        if (typeof Script !== "undefined" && typeof Script.unload === "function") {
             try { Script.unload(); } catch (e) { console.error("Error during Script.unload():", e); }
        }
      }, 200); // Delay slightly to ensure stdout buffer is flushed

  } catch (error) {
      // Catch any top-level errors during main execution
      console.error("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
      console.error("!!! CRITICAL ERROR IN SCRIPT EXECUTION !!!");
      console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
      console.error("Error message:", error.message);
      console.error("Error stack:", error.stack);
      console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
      // Still try to detach if possible
      setTimeout(() => {
        dprint("Detaching script after critical error.");
        if (typeof Script !== "undefined" && typeof Script.unload === "function") {
             try { Script.unload(); } catch (e) { console.error("Error during Script.unload() after error:", e); }
        }
      }, 100);
  }

})(); // Immediately invoke main function
