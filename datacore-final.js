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
 *  Compile-time constants marked ***VERIFY*** or ***ASSUMED UNCHANGED***
 *  must be checked whenever the game build changes.
 *
 *      $ frida -U -f StarCitizen.exe -l starcitizen_datacore_header_generator.js \
 *              --runtime=v8 > StarCitizen_DataCore.hpp
 *
 **************************************************************************/

/*─────────────────────────────────────────────────────────────────────────*\
|*  0.  GLOBAL CONFIGURATION                                              *|
\*─────────────────────────────────────────────────────────────────────────*/

const CONFIG = {
    // --- RVAs for Star Citizen 4.3 ---
    REL_GENV_RVA:
        typeof REL_GENV_RVA !== "undefined"
            ? ptr(REL_GENV_RVA)
            : ptr("0xa0377e0"),
    REL_GET_STRUCT_FPTRS_RVA:
        typeof REL_GET_STRUCT_FPTRS_RVA !== "undefined"
            ? ptr(REL_GET_STRUCT_FPTRS_RVA)
            : ptr("0x7867EB0"),
    REL_GET_STRUCTDESC_BY_NAME_RVA:
        typeof REL_GET_STRUCTDESC_BY_NAME_RVA !== "undefined"
            ? ptr(REL_GET_STRUCTDESC_BY_NAME_RVA)
            : ptr("0x78682A0"),

    // --- OFFSETS for Star Citizen 3.23 ---
    OFFSET_DATACORE_IN_GENV: ptr("0x78"), // ***VERIFIED*** Offset of DataCore pointer within gEnv
    OFFSET_ENUM_REGISTRY_IN_DC: ptr("0x120"), // ***VERIFIED*** Offset of EnumRegistry map within DataCore
    OFFSET_STRUCT_MAP_IN_DC: ptr("0x130"), // ***VERIFIED*** Offset of Struct map within DataCore

    // --- STRUCTURE LAYOUTS ---
    // Red-Black Tree Node Offsets (relative to node pointer)
    TREE: { L: 0x00, P: 0x08, R: 0x10, V: 0x20 }, // ***ASSUMED UNCHANGED*** Left, Parent, Right, Value/Data

    // Enum Registry Map Node Value Offsets (relative to node pointer + TREE.V)
    ENUM_MAP: { KEY_PTR: 0x20, VAL_PTR: 0x30 }, // ***ASSUMED UNCHANGED*** Pointer to enum name string, Pointer to EnumDescriptor

    // Enum Variant Map Node Value Offsets (relative to node pointer + TREE.V)
    VARIANT_MAP: { KEY_PTR: 0x20, VAL_S32: 0x28 }, // ***ASSUMED UNCHANGED*** Pointer to variant name string, SInt32 value of variant

    // Enum Descriptor Offsets (relative to EnumDescriptor pointer)
    ENUM_DESCRIPTOR: { VARIANT_MAP_PTR: 0x0 }, // ***ASSUMED UNCHANGED*** Pointer to the root of the variant map tree

    // FieldInfo Structure Offsets (relative to FieldInfo pointer)
    FIELDINFO: {
        // ***ASSUMED UNCHANGED*** Based on data reading functions.
        name: 0x00, // Pointer to field name string
        offset: 0x08, // uint64_t offset within the struct
        size: 0x10, // uint64_t size of the field's type
        type: 0x18, // uint8_t enum representing the field type (see fieldTypeName)
        flags: 0x19, // uint8_t field flags
        isArrayOrPointer: 0x1a, // uint8_t: 1 if it's a DynArray (or potentially other pointer types?)
        typeSpecificIndex: 0x1c, // uint32_t: Index for enum types, potentially other uses
        defaultValue: 0x20, // Pointer: Usage depends on type (e.g., points to struct name for type 16)
    },

    // Robin Hood Hash Map (Control Structure) Offsets (relative to map control struct pointer)
    RH_HASH: {
        // ***VERIFIED***
        SLOT_SIZE: 72, // Size of each data slot in bytes
        CONTROL_EMPTY: 0x80, // Control byte value indicating an empty slot
        CTRL_PTR: 0x0, // Pointer to the array of control bytes
        DATA_PTR: 0x8, // Pointer to the array of data slots
        MASK: 0x18, // uint64_t hash mask (capacity - 1)
        SLOT_KEY_PTR: 0x0, // Offset within a data slot to the pointer to the key (struct name string)
    },

    // --- SCRIPT PARAMETERS ---
    PTR_VALIDITY_THRESHOLD: ptr("0x10000"),
    MAX_ENUMS: 20000,
    MAX_VARIANTS: 10000,
    MAX_STRUCTS: 25000,
    MAX_FIELDS: 4096,
};

/*─────────────────────────────────────────────────────────────────────────*\
|*  1.  MINIMAL LOGGING INFRA – QUIET BY DEFAULT                          *|
\*─────────────────────────────────────────────────────────────────────────*/

const ENABLE_DPRINT = true;
function dprint(...args) {
    if (ENABLE_DPRINT) {
        console.error("[D]", ...args);
    }
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  2.  POINTER SAFETY HELPERS                                            *|
\*─────────────────────────────────────────────────────────────────────────*/

function isLikelyValidPtr(p) {
    return (
        p instanceof NativePointer &&
        !p.isNull() &&
        p.compare(CONFIG.PTR_VALIDITY_THRESHOLD) >= 0
    );
}

const rp = (addr) => (isLikelyValidPtr(addr) ? addr.readPointer() : ptr("0"));
const r32 = (addr) => (isLikelyValidPtr(addr) ? addr.readS32() : 0);

const rstr = (addr) => {
    if (!isLikelyValidPtr(addr)) return "<BAD_PTR>";
    try {
        const s = addr.readCString();
        return s ?? "<NULL>";
    } catch (e) {
        dprint(`Error reading string at ${hex(addr)}: ${e}`);
        return "<READ_ERR>";
    }
};

const hex = (p) =>
    p instanceof NativePointer ? p.toString() : "0x" + Number(p).toString(16);

/*─────────────────────────────────────────────────────────────────────────*\
|*  3.  PROCESS-WIDE BASE ADDRESSES                                       *|
\*─────────────────────────────────────────────────────────────────────────*/

const base = Process.findModuleByName("StarCitizen.exe").base;
if (!base) throw new Error("Module StarCitizen.exe not found.");
dprint(`StarCitizen.exe base address: ${hex(base)}`);

const gEnvPtr = base.add(CONFIG.REL_GENV_RVA);
dprint(`gEnv pointer address: ${hex(gEnvPtr)}`);

const dataCorePtrAddr = gEnvPtr.add(CONFIG.OFFSET_DATACORE_IN_GENV);
dprint(`DataCore pointer address: ${hex(dataCorePtrAddr)}`);
const dataCorePtr = rp(dataCorePtrAddr);
if (!isLikelyValidPtr(dataCorePtr))
    throw new Error(`DataCore pointer invalid at ${hex(dataCorePtrAddr)}.`);
dprint(`DataCore pointer value: ${hex(dataCorePtr)}`);

const kGetStructFieldPtrsAddr = base.add(CONFIG.REL_GET_STRUCT_FPTRS_RVA);
const kGetStructDescByNameAddr = base.add(
    CONFIG.REL_GET_STRUCTDESC_BY_NAME_RVA,
);
dprint(`kGetStructFieldPtrs function address: ${hex(kGetStructFieldPtrsAddr)}`);
dprint(
    `kGetStructDescByName function address: ${hex(kGetStructDescByNameAddr)}`,
);

/*─────────────────────────────────────────────────────────────────────────*\
|*  4.  ENUM & VARIANT WALKER                                             *|
\*─────────────────────────────────────────────────────────────────────────*/

const RESERVED_KEYWORDS = new Set([
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "atomic_cancel",
    "atomic_commit",
    "atomic_noexcept",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char8_t",
    "char16_t",
    "char32_t",
    "class",
    "compl",
    "concept",
    "const",
    "consteval",
    "constexpr",
    "constinit",
    "const_cast",
    "continue",
    "co_await",
    "co_return",
    "co_yield",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "reflexpr",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "synchronized",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
    "near",
    "far",
    "fallback",
    "abstract",
    "type",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
]);

function unreserve_keyword(s) {
    if (RESERVED_KEYWORDS.has(s)) {
        s += "_";
    }
    return s;
}

function sanitizeName(s) {
    if (typeof s !== "string") {
        console.error(
            `!!! SANITIZE_NAME_ERROR: Received non-string input! Type=${typeof s}, Value=`,
            s,
        );
        return "sanitizeName_received_non_string";
    }
    let result = "";
    try {
        result =
            s
                .replace(/[^A-Za-z0-9_]+/g, "_")
                .replace(/^_+|_+$/g, "")
                .replace(/^[0-9]/, "_$&") || "unnamed";
    } catch (e) {
        console.error(
            `!!! SANITIZE_NAME_ERROR: Exception during replace/fallback for input "${s}": ${e}`,
        );
        result = "sanitizeName_exception";
    }
    result = unreserve_keyword(result);
    if (typeof result !== "string" || result === "") {
        console.error(
            `!!! SANITIZE_NAME_ERROR: Producing invalid result! Type=${typeof result}, Value="${result}" for Input="${s}"`,
        );
        result = result || "unnamed";
        if (result === "") result = "sanitizeName_became_empty";
    }
    return result;
}

function getDynArrayName(baseTypeName) {
    const sanitizedBase = sanitizeName(baseTypeName);
    return sanitizeName(`DynArray_${sanitizedBase}`);
}

function getDynArrayFieldType(baseTypeName) {
    return `${baseTypeName}*`;
}

const EnumWalker = (() => {
    const { L, P, R } = CONFIG.TREE;

    function nextNode(n, head) {
        if (n.isNull() || n.equals(head)) return head;

        const right = rp(n.add(R));
        if (!right.isNull() && !right.equals(head)) {
            let cur = right;
            while (true) {
                const left = rp(cur.add(L));
                if (left.isNull() || left.equals(head)) return cur;
                cur = left;
            }
        } else {
            let cur = n;
            let parent = rp(cur.add(P));
            while (
                !parent.isNull() &&
                !parent.equals(head) &&
                cur.equals(rp(parent.add(R)))
            ) {
                cur = parent;
                parent = rp(cur.add(P));
            }
            return parent;
        }
    }

    function dumpVariants(enumDescPtr) {
        if (!isLikelyValidPtr(enumDescPtr)) return [];
        const head = rp(
            enumDescPtr.add(CONFIG.ENUM_DESCRIPTOR.VARIANT_MAP_PTR),
        );
        if (!isLikelyValidPtr(head)) {
            dprint(
                `Warning: Invalid variant map head for EnumDescriptor at ${hex(enumDescPtr)}. This enum will appear empty.`,
            );
            return [];
        }

        const variants = [];
        let n = rp(head.add(L));
        let count = 0;
        while (
            isLikelyValidPtr(n) &&
            !n.equals(head) &&
            count < CONFIG.MAX_VARIANTS
        ) {
            count++;
            const keyPtr = rp(n.add(CONFIG.VARIANT_MAP.KEY_PTR));
            const name = rstr(keyPtr);
            const value = r32(n.add(CONFIG.VARIANT_MAP.VAL_S32));
            if (
                name !== "<BAD_PTR>" &&
                name !== "<NULL>" &&
                name !== "<READ_ERR>"
            ) {
                variants.push([name, value]);
            } else {
                dprint(
                    `Skipping invalid variant name at node ${hex(n)} (keyPtr: ${hex(keyPtr)})`,
                );
            }
            n = nextNode(n, head);
        }
        if (count >= CONFIG.MAX_VARIANTS) {
            dprint(
                `Warning: Reached MAX_VARIANTS limit for enum described by ${hex(enumDescPtr)}`,
            );
        }
        return variants;
    }

    function dumpAllEnums() {
        const head = rp(dataCorePtr.add(CONFIG.OFFSET_ENUM_REGISTRY_IN_DC));
        if (!isLikelyValidPtr(head)) {
            console.error("!!! ERROR: Enum registry pointer is invalid.");
            return { enums: {}, indexMap: [] };
        }

        const enums = {};
        const indexMap = [];
        let n = rp(head.add(L)); // Start with the leftmost node (minimum value)
        let processed = 0;

        while (
            isLikelyValidPtr(n) &&
            !n.equals(head) &&
            processed < CONFIG.MAX_ENUMS
        ) {
            const namePtr = rp(n.add(CONFIG.ENUM_MAP.KEY_PTR));
            const name = rstr(namePtr);
            const valPtr = rp(n.add(CONFIG.ENUM_MAP.VAL_PTR));

            if (
                name !== "<BAD_PTR>" &&
                name !== "<NULL>" &&
                name !== "<READ_ERR>" &&
                isLikelyValidPtr(valPtr)
            ) {
                enums[name] = {
                    variants: dumpVariants(valPtr),
                };
                indexMap.push(name);
                processed++;
            } else {
                dprint(
                    `Skipping potentially invalid enum entry at node ${hex(n)} (namePtr: ${hex(namePtr)}, valPtr: ${hex(valPtr)})`,
                );
            }
            n = nextNode(n, head);
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
    const { SLOT_SIZE, CONTROL_EMPTY, CTRL_PTR, DATA_PTR, MASK, SLOT_KEY_PTR } =
        CONFIG.RH_HASH;

    const kGetStructFieldPtrs = new NativeFunction(
        kGetStructFieldPtrsAddr,
        "pointer",
        ["pointer", "pointer", "pointer", "int8"],
        "win64",
    );
    const kGetStructDescByName = new NativeFunction(
        kGetStructDescByNameAddr,
        "pointer",
        ["pointer", "pointer"],
        "win64",
    );

    function getStructNames() {
        const ctrlStruct = dataCorePtr.add(CONFIG.OFFSET_STRUCT_MAP_IN_DC);
        const pCtrl = rp(ctrlStruct.add(CTRL_PTR));
        const pData = rp(ctrlStruct.add(DATA_PTR));
        const mask = ctrlStruct.add(MASK).readU64();
        const capacity = mask.add(1).toNumber();

        const names = [];
        if (!isLikelyValidPtr(pCtrl) || !isLikelyValidPtr(pData)) {
            console.error(
                "!!! ERROR: Invalid control or data pointer in struct hash map.",
            );
            return [];
        }
        dprint(`Struct map capacity: ${capacity}`);

        let count = 0;
        for (let i = 0; i < capacity && count < CONFIG.MAX_STRUCTS; i++) {
            try {
                const ctrlByte = pCtrl.add(i).readU8();
                if (ctrlByte !== CONTROL_EMPTY) {
                    const slotAddr = pData.add(i * SLOT_SIZE);
                    const keyPtr = rp(slotAddr.add(SLOT_KEY_PTR));
                    const nm = rstr(keyPtr);
                    if (
                        nm !== "<BAD_PTR>" &&
                        nm !== "<NULL>" &&
                        nm !== "<READ_ERR>" &&
                        nm !== ""
                    ) {
                        names.push(nm);
                        count++;
                    } else {
                        dprint(
                            `Skipping potentially invalid struct name at slot ${i}, keyPtr: ${hex(keyPtr)}`,
                        );
                    }
                }
            } catch (e) {
                console.error(
                    `!!! ERROR reading struct map at index ${i}: ${e}`,
                );
            }
        }
        if (count >= CONFIG.MAX_STRUCTS) {
            dprint(`Warning: Reached MAX_STRUCTS limit during name discovery.`);
        }
        return names;
    }

    function fieldBaseTypeName(t, enumNameResolver, typeIdx, defPtr) {
        let baseType;
        switch (t) {
            case 1:
                baseType = "bool";
                break;
            case 2:
                baseType = "int8_t";
                break;
            case 3:
                baseType = "int16_t";
                break;
            case 4:
                baseType = "int32_t";
                break;
            case 5:
                baseType = "int64_t";
                break;
            case 6:
                baseType = "uint8_t";
                break;
            case 7:
                baseType = "uint16_t";
                break;
            case 8:
                baseType = "uint32_t";
                break;
            case 9:
                baseType = "uint64_t";
                break;
            case 10:
                baseType = "CryStringT";
                break;
            case 11:
                baseType = "float";
                break;
            case 12:
                baseType = "double";
                break;
            case 13:
                baseType = "CLocIdentifier";
                break;
            case 14:
                baseType = "CryGUID";
                break;
            case 15: {
                const originalEnumName = enumNameResolver(typeIdx);
                baseType = originalEnumName
                    ? sanitizeName(originalEnumName)
                    : `UnknownEnum_${typeIdx}`;
                break;
            }
            case 16: {
                const rawStructName = rstr(defPtr);
                if (
                    rawStructName !== "<BAD_PTR>" &&
                    rawStructName !== "<NULL>" &&
                    rawStructName !== "<READ_ERR>" &&
                    rawStructName !== ""
                ) {
                    baseType = sanitizeName(rawStructName);
                } else {
                    baseType = "UnknownStruct";
                    dprint(
                        `Info: defPtr (${hex(defPtr)}) for type 16 field was invalid/null/empty. Using "UnknownStruct".`,
                    );
                }
                break;
            }
            default:
                baseType = `uint8_t/*unk_type_${t}*/`;
                break;
        }
        return baseType;
    }

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
                // ***ASSUMED UNCHANGED***: The location of structSize at +0x28 is unverified in the new build.
                // Analysis suggests size is now calculated recursively. This read may fail or return incorrect data.
                try {
                    vtablePtr = rp(pStructDesc.add(0x10));
                } catch (e) {
                    dprint(`Error reading vtable for ${structName}: ${e}`);
                    vtablePtr = ptr(0);
                }
                try {
                    structSize = pStructDesc.add(0x28).readU32();
                } catch (e) {
                    dprint(`Error reading size for ${structName}: ${e}`);
                    structSize = 0;
                }
            } else {
                dprint(
                    `Warning: kGetStructDescByName returned invalid pointer for ${structName}`,
                );
            }
        } catch (e) {
            console.error(
                `!!! ERROR during initial processing for struct ${structName}: ${e}`,
            );
            return {
                name: structName,
                sanitizedName: sanitizedStructName,
                fields: [],
                vtablePtr: ptr(0),
                structSize: 0,
                dependencies: [],
                arrayElementTypes: new Set(),
                isGeneratedDynArray: false,
            };
        }

        const begin = vec.readPointer();
        const end = vec.add(ptrSize).readPointer();
        const count =
            isLikelyValidPtr(begin) &&
            isLikelyValidPtr(end) &&
            end.compare(begin) >= 0
                ? Math.min(
                      end.sub(begin).toUInt32() / ptrSize,
                      CONFIG.MAX_FIELDS,
                  )
                : 0;

        const rawFields = [];
        for (let i = 0; i < count; i++) {
            const fPtr = rp(begin.add(i * ptrSize));
            if (!isLikelyValidPtr(fPtr)) {
                dprint(
                    `Skipping invalid field pointer at index ${i} for struct ${structName}`,
                );
                continue;
            }
            try {
                const fi = CONFIG.FIELDINFO;
                const namePtr = rp(fPtr.add(fi.name));
                const rawName = rstr(namePtr);
                if (
                    rawName === "<BAD_PTR>" ||
                    rawName === "<NULL>" ||
                    rawName === "<READ_ERR>" ||
                    rawName === ""
                ) {
                    dprint(
                        `Skipping field index ${i} in ${structName} due to invalid name (namePtr: ${hex(namePtr)})`,
                    );
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
                console.error(
                    `!!! ERROR reading raw field data at index ${i} for struct ${structName}: ${e}`,
                );
            }
        }
        rawFields.sort((a, b) => a.offset - b.offset);

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

            const baseTypeNameForField = fieldBaseTypeName(
                rf.type,
                enumNameResolver,
                rf.typeIdx,
                rf.defPtr,
            );
            let final_dtype;
            let final_layout_size;
            let isOpaque =
                rf.type === 16 && baseTypeNameForField === "UnknownStruct";
            let isPointerForced = false;

            if (isOpaque) {
                if (rf.isArray) {
                    final_dtype = "uint8_t*";
                    final_layout_size = ptrSize;
                } else {
                    final_dtype = "uint8_t";
                    final_layout_size =
                        rf.originalSize > 0 ? rf.originalSize : 1;
                }
            } else {
                if (rf.isArray) {
                    final_dtype = getDynArrayName(baseTypeNameForField) + "*";
                    final_layout_size = ptrSize;
                    if (
                        baseTypeNameForField &&
                        baseTypeNameForField !== "UnknownStruct"
                    ) {
                        dependencies.add(getDynArrayName(baseTypeNameForField));
                        arrayElementTypes.add(baseTypeNameForField);
                    }
                } else if (rf.type === 16) {
                    isPointerForced = false;
                    if (baseTypeNameForField === sanitizedStructName) {
                        final_dtype = baseTypeNameForField + "*";
                        final_layout_size = ptrSize;
                        isPointerForced = true;
                        dprint(
                            `  Self-ref field ${sanitizedStructName}.${sanFieldName} forced to pointer.`,
                        );
                    } else {
                        const nextField =
                            i + 1 < rawFields.length ? rawFields[i + 1] : null;
                        if (
                            nextField &&
                            rf.offset + rf.originalSize > nextField.offset
                        ) {
                            final_dtype = baseTypeNameForField + "*";
                            final_layout_size = ptrSize;
                            isPointerForced = true;
                            dprint(
                                `  Overlap heuristic: ${sanitizedStructName}.${sanFieldName} (size 0x${rf.originalSize.toString(16)}) forced to pointer due to next field at 0x${nextField.offset.toString(16)} (current offset 0x${rf.offset.toString(16)}).`,
                            );
                        } else if (rf.originalSize === ptrSize) {
                            final_dtype = baseTypeNameForField + "*";
                            final_layout_size = ptrSize;
                            isPointerForced = true;
                            dprint(
                                `  Size-match heuristic: ${sanitizedStructName}.${sanFieldName} (size 0x${rf.originalSize.toString(16)}) treated as pointer.`,
                            );
                        } else {
                            final_dtype = baseTypeNameForField;
                            final_layout_size = rf.originalSize;
                        }
                    }
                    if (
                        baseTypeNameForField &&
                        baseTypeNameForField !== sanitizedStructName &&
                        baseTypeNameForField !== "UnknownStruct"
                    ) {
                        dependencies.add(baseTypeNameForField);
                    }
                } else if ([10, 13, 14].includes(rf.type)) {
                    final_dtype = baseTypeNameForField + "*";
                    final_layout_size = ptrSize;
                } else {
                    final_dtype = baseTypeNameForField;
                    final_layout_size = rf.originalSize;
                }
            }

            fields.push({
                name: sanFieldName,
                rawName: rf.rawName,
                offset: rf.offset,
                size: final_layout_size,
                originalSize: rf.originalSize,
                type: rf.type,
                isArray: rf.isArray,
                flags: rf.flags,
                dtype: final_dtype,
                baseDtype: baseTypeNameForField,
                enumRef:
                    rf.type === 15
                        ? (enumNameResolver(rf.typeIdx) ?? null)
                        : null,
                isOpaque: isOpaque,
                isPointerOverride: isPointerForced,
            });
        }

        return {
            name: structName,
            sanitizedName: sanitizedStructName,
            fields: fields,
            vtablePtr: vtablePtr,
            structSize: structSize,
            dependencies: Array.from(dependencies),
            arrayElementTypes: arrayElementTypes,
            isGeneratedDynArray: false,
        };
    }

    function dumpAllStructs(enumNameResolver) {
        const names = getStructNames();
        dprint(`Found ${names.length} raw struct names.`);
        const results = names.map((n) => processStruct(n, enumNameResolver));
        const validResults = results.filter(
            (s) =>
                s &&
                (s.fields.length > 0 ||
                    s.structSize > 0 ||
                    s.isGeneratedDynArray),
        );
        dprint(`Successfully processed ${validResults.length} structs.`);
        return validResults;
    }

    return { dumpAllStructs };
})();

/*─────────────────────────────────────────────────────────────────────────*\
|*  6.  DynArray STRUCT GENERATION                                        *|
\*─────────────────────────────────────────────────────────────────────────*/

function generateDynArrayStructs(allStructsData) {
    const uniqueArrayElementTypes = new Set();
    const dynArrayStructs = new Map();
    const ptrSize = Process.pointerSize;

    for (const s of allStructsData) {
        if (s.arrayElementTypes instanceof Set) {
            s.arrayElementTypes.forEach((baseType) => {
                if (
                    baseType &&
                    !baseType.startsWith("UnknownStruct") &&
                    !baseType.startsWith("sanitizeName_") &&
                    baseType !== "unnamed"
                ) {
                    uniqueArrayElementTypes.add(baseType);
                } else {
                    dprint(
                        `Skipping DynArray generation for problematic base type: ${baseType}`,
                    );
                }
            });
        }
    }
    dprint(
        `Found ${uniqueArrayElementTypes.size} unique base types used in arrays.`,
    );

    for (const baseType of uniqueArrayElementTypes) {
        const dynArrayName = getDynArrayName(baseType);
        const fieldType = getDynArrayFieldType(baseType);

        if (
            !dynArrayStructs.has(dynArrayName) &&
            !allStructsData.some((s) => s.sanitizedName === dynArrayName)
        ) {
            dprint(
                `Generating DynArray struct: ${dynArrayName} for base type ${baseType}`,
            );
            const dependency = sanitizeName(baseType);
            dynArrayStructs.set(dynArrayName, {
                name: dynArrayName,
                sanitizedName: dynArrayName,
                fields: [
                    {
                        name: "m_data",
                        rawName: "m_data",
                        offset: 0,
                        size: ptrSize,
                        originalSize: ptrSize,
                        type: -1,
                        isArray: false,
                        flags: 0,
                        dtype: fieldType,
                        baseDtype: baseType,
                        enumRef: null,
                        isOpaque: false,
                        isPointerOverride: true,
                    },
                ],
                vtablePtr: ptr(0),
                structSize: ptrSize,
                dependencies:
                    dependency !== "UnknownStruct" ? [dependency] : [],
                arrayElementTypes: new Set(),
                isGeneratedDynArray: true,
            });
        } else {
            dprint(
                `Skipping generation for ${dynArrayName}, name collision or already exists.`,
            );
        }
    }
    return dynArrayStructs;
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  7.  TOPOLOGICAL SORT FOR STRUCTS                                      *|
\*─────────────────────────────────────────────────────────────────────────*/

function sortStructsTopologically(
    structsData,
    iteration = 1,
    forcePointerHeuristicForDependencies = false,
) {
    dprint(
        `Topological Sort: Starting iteration ${iteration}... ForcePointerHeuristic: ${forcePointerHeuristicForDependencies}`,
    );
    const adj = new Map();
    const inDegree = new Map();
    const structMap = new Map();

    dprint(`Topological Sort (Iter ${iteration}): Initializing maps...`);
    let initializedCount = 0;
    for (const s of structsData) {
        const sanName = s.sanitizedName;
        if (
            !sanName ||
            sanName === "unnamed" ||
            sanName.startsWith("sanitizeName_")
        ) {
            console.warn(
                `Warning (Iter ${iteration}): Skipping struct with invalid sanitized name during sort init: ${s.name} -> ${sanName}`,
            );
            continue;
        }
        if (structMap.has(sanName) && iteration === 1) {
            console.warn(
                `Warning (Iter ${iteration}): Duplicate sanitized struct name detected during sort init: ${sanName} (from original: ${s.name}). Overwriting previous entry in map.`,
            );
        }
        adj.set(sanName, new Set());
        inDegree.set(sanName, 0);
        structMap.set(sanName, s);
        initializedCount++;
    }
    dprint(
        `Topological Sort (Iter ${iteration}): Initialized ${initializedCount} structs in the map.`,
    );
    if (initializedCount !== structsData.length && iteration === 1) {
        console.warn(
            `Warning (Iter ${iteration}): ${structsData.length - initializedCount} structs were skipped during sort initialization due to invalid/duplicate sanitized names.`,
        );
    }

    dprint(
        `Topological Sort (Iter ${iteration}): Building dependency graph...`,
    );
    let edgeCount = 0;
    for (const s of structsData) {
        const dependentName = s.sanitizedName;
        if (!structMap.has(dependentName)) continue;

        const currentDependencies = new Set();
        s.fields.forEach((f) => {
            let isConsideredPointer =
                f.isArray ||
                f.dtype.endsWith("*") ||
                ([10, 13, 14].includes(f.type) && !f.isArray);
            if (
                forcePointerHeuristicForDependencies &&
                f.type === 16 &&
                !f.isArray &&
                !f.isOpaque
            ) {
                isConsideredPointer = true;
            }
            if (
                f.baseDtype &&
                f.baseDtype !== "UnknownStruct" &&
                f.baseDtype !== dependentName
            ) {
                if (f.isArray) {
                    currentDependencies.add(getDynArrayName(f.baseDtype));
                } else if (isConsideredPointer) {
                    currentDependencies.add(f.baseDtype);
                } else {
                    if (!forcePointerHeuristicForDependencies) {
                        if (f.type === 16) currentDependencies.add(f.baseDtype);
                    }
                }
            }
        });
        const dependenciesToUse = forcePointerHeuristicForDependencies
            ? Array.from(currentDependencies)
            : s.dependencies;

        if (!Array.isArray(dependenciesToUse)) {
            console.error(
                `Error (Iter ${iteration}): Dependencies for struct ${s.name} (${dependentName}) is not an array. Skipping dependency processing.`,
            );
            continue;
        }

        for (const dependencyName of dependenciesToUse) {
            if (
                typeof dependencyName !== "string" ||
                dependencyName === "" ||
                dependencyName.startsWith("UnknownStruct")
            ) {
                continue;
            }
            if (structMap.has(dependencyName)) {
                const dependentsSet = adj.get(dependencyName);
                if (!(dependentsSet instanceof Set)) {
                    console.error(
                        `FATAL Error (Iter ${iteration}): Adjacency map corruption! Key ${dependencyName} does not map to a Set.`,
                    );
                    continue;
                }
                if (!dependentsSet.has(dependentName)) {
                    dependentsSet.add(dependentName);
                    edgeCount++;
                    if (inDegree.has(dependentName)) {
                        inDegree.set(
                            dependentName,
                            inDegree.get(dependentName) + 1,
                        );
                    } else {
                        console.error(
                            `Error (Iter ${iteration}): Dependent struct ${dependentName} not found in inDegree map during graph build.`,
                        );
                    }
                }
            } else {
                dprint(
                    `Info (Iter ${iteration}): Struct ${dependentName} depends on '${dependencyName}', which is not in the current struct map for sorting. Ignoring this dependency.`,
                );
            }
        }
    }
    dprint(
        `Topological Sort (Iter ${iteration}): Graph built with ${edgeCount} dependency edges.`,
    );

    dprint(
        `Topological Sort (Iter ${iteration}): Initializing queue with nodes of in-degree 0...`,
    );
    const queue = [];
    for (const [name, degree] of inDegree.entries()) {
        if (degree === 0) {
            if (structMap.has(name)) {
                queue.push(name);
            } else {
                console.error(
                    `Error (Iter ${iteration}): Struct ${name} has in-degree 0 but is not in structMap. Discarding from initial queue.`,
                );
            }
        }
    }
    dprint(
        `Topological Sort (Iter ${iteration}): Initial queue size: ${queue.length}`,
    );

    dprint(`Topological Sort (Iter ${iteration}): Processing queue...`);
    const currentSortedStructs = [];
    const processedNamesInThisIteration = new Set();

    while (queue.length > 0) {
        const currentName = queue.shift();
        if (typeof currentName !== "string" || !structMap.has(currentName)) {
            console.error(
                `Error (Iter ${iteration}): Dequeued invalid or unknown name "${currentName}". Skipping.`,
            );
            continue;
        }
        if (processedNamesInThisIteration.has(currentName)) {
            console.warn(
                `Warning (Iter ${iteration}): Attempting to process node ${currentName} again. Skipping.`,
            );
            continue;
        }
        const currentStruct = structMap.get(currentName);
        currentSortedStructs.push(currentStruct);
        processedNamesInThisIteration.add(currentName);

        if (adj.has(currentName)) {
            const neighbors = adj.get(currentName);
            if (!(neighbors instanceof Set)) {
                console.error(
                    `FATAL ERROR (Iter ${iteration}): adj.get('${currentName}') returned non-Set value! Type: ${typeof neighbors}`,
                );
                continue;
            }
            for (const neighborName of neighbors) {
                if (
                    typeof neighborName !== "string" ||
                    !inDegree.has(neighborName)
                ) {
                    console.error(
                        `Error (Iter ${iteration}): Invalid neighbor name "${neighborName}" (dependent of ${currentName}). Skipping degree update.`,
                    );
                    continue;
                }
                const currentDegree = inDegree.get(neighborName);
                if (
                    typeof currentDegree !== "number" ||
                    isNaN(currentDegree) ||
                    currentDegree <= 0
                ) {
                    console.error(
                        `Error (Iter ${iteration}): Invalid or non-positive in-degree (${currentDegree}) for neighbor ${neighborName} before decrementing. Skipping degree update.`,
                    );
                    continue;
                }
                inDegree.set(neighborName, currentDegree - 1);
                if (inDegree.get(neighborName) === 0) {
                    if (structMap.has(neighborName)) {
                        queue.push(neighborName);
                    } else {
                        console.error(
                            `Error (Iter ${iteration}): Neighbor ${neighborName} reached in-degree 0 but is not in structMap. Discarding.`,
                        );
                    }
                }
            }
        }
    }
    dprint(
        `Topological Sort (Iter ${iteration}): Finished processing queue. Added ${currentSortedStructs.length} structs to sorted list for this iteration.`,
    );

    const remainingStructs = [];
    for (const s of structsData) {
        if (!processedNamesInThisIteration.has(s.sanitizedName)) {
            remainingStructs.push(s);
        }
    }
    dprint(
        `Topological Sort (Iter ${iteration}): ${remainingStructs.length} structs remaining.`,
    );

    return {
        sortedThisIteration: currentSortedStructs,
        remainingForNextIteration: remainingStructs,
    };
}

function iterativeTopologicalSort(allStructsData) {
    let currentStructsToProcess = [...allStructsData];
    let finalSortedList = [];
    let iteration = 1;
    const MAX_ITERATIONS = 5;
    let remainingForNextIteration = [];  // Declare outside for post-loop access
    while (currentStructsToProcess.length > 0 && iteration <= MAX_ITERATIONS) {
        dprint(`--- Starting Iterative Sort - Iteration ${iteration} ---`);
        const forcePointerHeuristic = iteration > 1;
        const { sortedThisIteration, remainingForNextIteration: nextRemaining } =
            sortStructsTopologically(
                currentStructsToProcess,
                iteration,
                forcePointerHeuristic,
            );
        remainingForNextIteration = nextRemaining;  // Update the outer variable
        finalSortedList.push(...sortedThisIteration);
        if (remainingForNextIteration.length === 0) {
            dprint("All structs sorted successfully after iteration " + iteration);
            currentStructsToProcess = [];
            break;
        }
        if (
            remainingForNextIteration.length === currentStructsToProcess.length &&
            iteration > 1
        ) {
            dprint(`No progress in iteration ${iteration} despite pointer heuristic. Remaining ${remainingForNextIteration.length} structs are likely in hard cycles or have missing external dependencies.`);
            finalSortedList.push(...remainingForNextIteration);
            currentStructsToProcess = [];
            break;
        }
        currentStructsToProcess = remainingForNextIteration;
        iteration++;
    }
    if (iteration > MAX_ITERATIONS && currentStructsToProcess.length > 0) {
        dprint(`Reached MAX_ITERATIONS for topological sort. Appending ${currentStructsToProcess.length} remaining structs.`);
        finalSortedList.push(...currentStructsToProcess);
    }
    const finalUnprocessed =
        currentStructsToProcess.length > 0 && iteration > MAX_ITERATIONS
            ? currentStructsToProcess
            : iteration > 1 &&
              remainingForNextIteration.length === currentStructsToProcess.length
              ? currentStructsToProcess
              : [];
    return {
        sorted: finalSortedList.filter((s) => !finalUnprocessed.includes(s)),
        unprocessed: finalUnprocessed,
    };
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  8.  HEADER GENERATOR                                                   *|
\*─────────────────────────────────────────────────────────────────────────*/

function generateHeader(
    pre,
    enumsData,
    { sorted: sortedStructs, unprocessed: unprocessedStructs },
) {
    const out = [];

    out.push(pre.trimEnd(), "");

    out.push(
        "/*=========================================================================*/",
    );
    out.push(
        "/*   ENUM DEFINITIONS (C-Style with Prefixed Variants)                     */",
    );
    out.push(
        "/*=========================================================================*/\n",
    );
    const sortedEnumNames = Object.keys(enumsData.enums).sort();
    for (const enumName of sortedEnumNames) {
        const { variants } = enumsData.enums[enumName];
        const enumId = sanitizeName(enumName);
        out.push(`// Original name: ${enumName}`);
        out.push(`enum ${enumId} {`);

        const processedVariants = variants
            .map(([n, v]) => ({
                originalName: n,
                sanitizedVariantName: sanitizeName(n),
                value: v,
            }))
            .sort((a, b) => a.value - b.value);

        const prefixedNames = processedVariants.map(
            (v) => `${enumId}_${v.sanitizedVariantName}`,
        );
        const maxNameLength = prefixedNames.reduce(
            (max, name) => Math.max(max, name.length),
            0,
        );
        const uniquePrefixedNames = new Set();

        processedVariants.forEach(
            ({ originalName, sanitizedVariantName, value }) => {
                let basePrefixedName = `${enumId}_${sanitizedVariantName}`;
                let finalPrefixedName = sanitizeName(basePrefixedName);

                if (uniquePrefixedNames.has(finalPrefixedName)) {
                    let suffix = 1;
                    const tempBase = finalPrefixedName;
                    while (uniquePrefixedNames.has(`${tempBase}_${suffix}`)) {
                        suffix++;
                    }
                    finalPrefixedName = `${tempBase}_${suffix}`;
                    dprint(
                        `Warning: Renaming duplicate prefixed variant name "${basePrefixedName}" to "${finalPrefixedName}" in enum ${enumId}`,
                    );
                }
                uniquePrefixedNames.add(finalPrefixedName);

                const padding = " ".repeat(
                    maxNameLength > finalPrefixedName.length
                        ? maxNameLength - finalPrefixedName.length
                        : 0,
                );
                let valueStr =
                    value < 0
                        ? `-0x${Math.abs(value).toString(16)}`
                        : `0x${value.toString(16)}`;
                out.push(
                    `    ${finalPrefixedName}${padding} = ${valueStr}, /* ${originalName} */`,
                );
            },
        );
        out.push(`};\n`);
    }

    out.push(
        "/*=========================================================================*/",
    );
    out.push(
        "/*   STRUCT FORWARD DECLARATIONS                                           */",
    );
    out.push(
        "/*=========================================================================*/",
    );
    out.push(
        "/* Forward declarations allow pointers to structs defined later.           */\n",
    );
    const allStructsForForwardDecl = [...sortedStructs, ...unprocessedStructs];
    const declaredStructs = new Set();
    allStructsForForwardDecl.forEach((s) => {
        if (
            s.sanitizedName &&
            !s.sanitizedName.startsWith("UnknownStruct") &&
            !s.sanitizedName.startsWith("sanitizeName_") &&
            !declaredStructs.has(s.sanitizedName)
        ) {
            out.push(`struct ${s.sanitizedName};`);
            declaredStructs.add(s.sanitizedName);
        }
    });
    allStructsForForwardDecl.forEach((s) => {
        if (
            s.isGeneratedDynArray &&
            s.sanitizedName &&
            !declaredStructs.has(s.sanitizedName)
        ) {
            out.push(`struct ${s.sanitizedName};`);
            declaredStructs.add(s.sanitizedName);
        }
    });
    out.push("\n");

    const generateStructDefinition = (s, isUnprocessedBlock = false) => {
        const structLines = [];
        const sn = s.sanitizedName;

        structLines.push(`// Original name: ${s.name}`);
        if (s.isGeneratedDynArray) {
            const baseT = s.fields[0]?.baseDtype ?? "unknown";
            structLines.push(`// Generated DynArray for base type: ${baseT}`);
        }
        structLines.push(`// Size: 0x${s.structSize.toString(16)}`);
        if (isLikelyValidPtr(s.vtablePtr)) {
            structLines.push(`// VTable: ${hex(s.vtablePtr)}`);
        }
        if (isUnprocessedBlock) {
            structLines.push(
                `// WARNING: This struct was part of a cycle or had missing dependencies.`,
            );
            structLines.push(
                `// Pointer heuristic may have been applied to its type 16 fields for ordering.`,
            );
        }

        structLines.push(`struct ${sn} {`);
        let currentOffset = 0;
        let padIndex = 0;

        const emitPadding = (gapSize, offsetBeforePadding) => {
            if (gapSize > 0) {
                structLines.push(
                    `    uint8_t _pad_${padIndex++}[0x${gapSize.toString(16)}]; // Offset: 0x${offsetBeforePadding.toString(16)}`,
                );
            } else if (gapSize < 0) {
                structLines.push(
                    `    /* !!! FIELD OVERLAP DETECTED at offset 0x${offsetBeforePadding.toString(16)} (gap: ${gapSize}) !!! */`,
                );
            }
        };

        s.fields.forEach((f) => {
            const gap = f.offset - currentOffset;
            emitPadding(gap, currentOffset);

            const nameComment =
                f.name !== f.rawName && f.rawName ? ` /* ${f.rawName} */` : "";
            const offsetComment = ` // Offset: 0x${f.offset.toString(16)}`;
            let fieldDefinition;
            let fieldLayoutSize = f.size;
            let sizeAndTypeComment = "";
            let finalDtypeForField = f.dtype;

            if (
                isUnprocessedBlock &&
                f.type === 16 &&
                !f.isArray &&
                !f.isOpaque &&
                !f.dtype.endsWith("*") &&
                !f.isPointerOverride
            ) {
                finalDtypeForField = f.baseDtype + "*";
                fieldLayoutSize = Process.pointerSize;
                sizeAndTypeComment = ` /* CYCLIC_HEURISTIC: Forced to pointer. Original size: 0x${f.originalSize.toString(16)} */`;
                dprint(
                    `Applying cyclic heuristic to ${sn}.${f.name}, changing type to ${finalDtypeForField}`,
                );
            }

            if (f.isOpaque && !f.isArray) {
                fieldDefinition = `    uint8_t ${f.name}[0x${fieldLayoutSize.toString(16)}];${nameComment} // Opaque struct field (type resolution failed)${offsetComment}`;
            } else {
                const arrayMarker =
                    f.isArray && !f.isOpaque
                        ? " // Pointer to DynArray struct"
                        : f.isOpaque && f.isArray
                          ? " // Pointer to array of opaque structs"
                          : "";
                if (f.type === 16 && !f.isArray && !f.isOpaque) {
                    if (finalDtypeForField.endsWith("*")) {
                        sizeAndTypeComment += ` /* Target struct size: 0x${f.originalSize.toString(16)} */`;
                    } else {
                        if (
                            f.originalSize === Process.pointerSize &&
                            fieldLayoutSize === Process.pointerSize
                        ) {
                            sizeAndTypeComment += ` /* Inline struct, size matches ptrSize */`;
                        }
                    }
                } else if (
                    fieldLayoutSize !== f.originalSize &&
                    !f.isArray &&
                    ![10, 13, 14].includes(f.type)
                ) {
                    sizeAndTypeComment += ` (Original size: 0x${f.originalSize.toString(16)})`;
                }
                fieldDefinition = `    ${finalDtypeForField} ${f.name};${nameComment}${offsetComment}${sizeAndTypeComment}${arrayMarker}`;
            }
            if (!fieldDefinition) {
                const arrayMarker =
                    f.isArray && !f.isOpaque
                        ? " // Pointer to DynArray struct"
                        : f.isOpaque && f.isArray
                          ? " // Pointer to array of opaque structs"
                          : "";
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

    if (unprocessedStructs && unprocessedStructs.length > 0) {
        out.push(
            "/*=========================================================================*/",
        );
        out.push(
            "/*   CYCLIC / UNPROCESSED STRUCT DEFINITIONS                             */",
        );
        out.push(
            "/*=========================================================================*/",
        );
        out.push(
            "/* These structs have cyclic dependencies or could not be sorted.        */",
        );
        out.push(
            "/* Forward declarations above should resolve pointer usage issues.       */\n",
        );

        unprocessedStructs.sort((a, b) =>
            a.sanitizedName.localeCompare(b.sanitizedName),
        );
        for (const s of unprocessedStructs) {
            if (
                s.sanitizedName &&
                !s.sanitizedName.startsWith("UnknownStruct") &&
                !s.sanitizedName.startsWith("sanitizeName_")
            ) {
                out.push(generateStructDefinition(s, true));
            } else {
                dprint(
                    `Skipping definition for unprocessed struct with invalid name: ${s.name} -> ${s.sanitizedName}`,
                );
            }
        }
    }

    out.push(
        "/*=========================================================================*/",
    );
    out.push(
        "/*   NON-CYCLIC STRUCT DEFINITIONS (Sorted)                              */",
    );
    out.push(
        "/*=========================================================================*/",
    );
    out.push(
        "/* These structs were topologically sorted based on their dependencies.    */\n",
    );
    for (const s of sortedStructs) {
        if (
            s.sanitizedName &&
            !s.sanitizedName.startsWith("UnknownStruct") &&
            !s.sanitizedName.startsWith("sanitizeName_")
        ) {
            out.push(generateStructDefinition(s, false));
        } else {
            dprint(
                `Skipping definition for sorted struct with invalid name: ${s.name} -> ${s.sanitizedName}`,
            );
        }
    }

    return out.join("\n");
}

/*─────────────────────────────────────────────────────────────────────────*\
|*  9.  MAIN – RUN ONCE, EMIT HEADER, EXIT                                *|
\*─────────────────────────────────────────────────────────────────────────*/

(function main() {
    const PREAMBLE = String.raw`#ifndef STARCITIZEN_DATACORE_HPP
#define STARCITIZEN_DATACORE_HPP

#include <stdint.h>

/*=========================================================================*/
/*   CORE TYPE DEFINITIONS                                                 */
/*=========================================================================*/

typedef uint64_t EntityId;
typedef uint32_t Fnv1a32;

struct CryStringT {
    char *m_str;
};

struct CryString_StrHeader {
    int32_t nRefCount;
    int32_t nLength;
    int32_t nAllocSize;
};

#define CRYSTRING_HEADER(obj)  ((struct CryString_StrHeader*)((obj).m_str) - 1)

struct CryGUID {
    uint64_t lo;
    uint64_t hi;
};

struct CLocIdentifier {
    char *m_sIdentifier;
};

typedef Fnv1a32 CLocIdentifierHash;

struct CLocString {
    char *m_wString;
};

typedef Fnv1a32 CStringHash;

#endif // STARCITIZEN_DATACORE_HPP PREAMBLE GUARD

/*=========================================================================*/
/*   BEGINNING OF AUTO-GENERATED DEFINITIONS                               */
/*=========================================================================*/
`;

    try {
        dprint("Step 1: Dumping enums...");
        const enumsData = EnumWalker.dumpAllEnums();
        dprint(`Found ${Object.keys(enumsData.enums).length} enums.`);

        const enumNameResolver = (idx) =>
            idx >= 0 && idx < enumsData.indexMap.length
                ? enumsData.indexMap[idx]
                : null;

        dprint("Step 2: Dumping initial structs and fields...");
        const initialStructsData =
            StructWalker.dumpAllStructs(enumNameResolver);
        dprint(`Found ${initialStructsData.length} initial structs.`);

        dprint("Step 3: Generating DynArray struct objects...");
        const dynArrayStructsMap = generateDynArrayStructs(initialStructsData);
        dprint(`Generated ${dynArrayStructsMap.size} DynArray struct objects.`);

        const allStructsData = [
            ...initialStructsData,
            ...dynArrayStructsMap.values(),
        ];
        dprint(`Total structs including DynArrays: ${allStructsData.length}`);

        dprint("Step 5: Sorting all structs topologically (iteratively)...");
        const sortResult = iterativeTopologicalSort(allStructsData);
        dprint(
            `Sorting complete. Sorted: ${sortResult.sorted.length}, Unprocessed: ${sortResult.unprocessed.length}`,
        );

        if (ENABLE_DPRINT) {
            try {
                dprint("Step 6a: Writing combined data to dump.json...");
                const dumpStructs = [
                    ...sortResult.sorted,
                    ...sortResult.unprocessed,
                ];
                const dumpEnums = Object.entries(enumsData.enums)
                    .sort(([nameA], [nameB]) => nameA.localeCompare(nameB))
                    .map(([name, data]) => [
                        name,
                        data.variants.sort(([, vA], [, vB]) => vA - vB),
                    ]);
                const dumpData = { structs: dumpStructs, enums: dumpEnums };
                const jsonString = JSON.stringify(
                    dumpData,
                    (key, value) => {
                        if (value instanceof NativePointer)
                            return value.toString();
                        if (value instanceof Set) return Array.from(value);
                        if (typeof value === "bigint")
                            return value.toString() + "n";
                        return value;
                    },
                    2,
                );
                const file = new File("dump.json", "w");
                file.write(jsonString);
                file.close();
                dprint("Successfully wrote data to dump.json");
            } catch (e) {
                console.error(`Error writing dump.json: ${e}`);
                dprint(`Error writing dump.json: ${e.stack}`);
            }
        }

        dprint("Step 7: Generating final header content...");
        const header = generateHeader(PREAMBLE, enumsData, sortResult);

        dprint("Step 8: Writing final header to stdout...");
        console.log(header);

        dprint("Step 9: Scheduling script detachment...");
        setTimeout(() => {
            dprint("Detaching script now.");
            if (
                typeof Script !== "undefined" &&
                typeof Script.unload === "function"
            ) {
                try {
                    Script.unload();
                } catch (e) {
                    console.error("Error during Script.unload():", e);
                }
            }
        }, 200);
    } catch (error) {
        console.error("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        console.error("!!! CRITICAL ERROR IN SCRIPT EXECUTION !!!");
        console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        console.error("Error message:", error.message);
        console.error("Error stack:", error.stack);
        console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        setTimeout(() => {
            dprint("Detaching script after critical error.");
            if (
                typeof Script !== "undefined" &&
                typeof Script.unload === "function"
            ) {
                try {
                    Script.unload();
                } catch (e) {
                    console.error(
                        "Error during Script.unload() after error:",
                        e,
                    );
                }
            }
        }, 100);
    }
})();
