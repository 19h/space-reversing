"use strict"; // CIG CONFIDENTIAL, INTERNAL USE ONLY

const PTR_SIZE = Process.pointerSize;
const MODULE_BASE = Process.enumerateModules()[0].base;
const GENV_ADDR = MODULE_BASE.add("0xa294ef0");
const CActor__GetBoneTransform_ADDR = MODULE_BASE.add("0x2f5c630");

function lower48(value) {
    return ptr(value).and(ptr("0xFFFFFFFFFFFF"));
}

function readCString(value) {
    const p = ptr(value);
    if (p.isNull()) return null;

    try {
        return p.readUtf8String();
    } catch (_) {
        try {
            return p.readCString();
        } catch (_) {
            return null;
        }
    }
}

function readWideCString(value) {
    const p = ptr(value);
    if (p.isNull()) return null;

    try {
        return p.readUtf16String();
    } catch (_) {
        return null;
    }
}

function readCryString(value) {
    try {
        return readCString(lower48(ptr(value).readPointer()));
    } catch (_) {
        return null;
    }
}

function readCryGuid(value) {
    const p = ptr(value);
    const a = p.readU32().toString(16).padStart(8, "0");
    const b = p.add(0x04).readU16().toString(16).padStart(4, "0");
    const c = p.add(0x06).readU16().toString(16).padStart(4, "0");
    const d = [];

    for (let i = 0x08; i < 0x10; i++) {
        d.push(p.add(i).readU8().toString(16).padStart(2, "0"));
    }

    return `${a}-${b}-${c}-${d.slice(0, 2).join("")}-${d.slice(2).join("")}`;
}

function writeCryGuid(destination, guid) {
    const out = ptr(destination);
    const text = String(guid || "").trim();
    const match = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i.exec(text);
    if (!match) {
        throw new Error(`invalid CryGUID: ${text}`);
    }

    out.writeU32(parseInt(match[1], 16));
    out.add(0x04).writeU16(parseInt(match[2], 16));
    out.add(0x06).writeU16(parseInt(match[3], 16));

    const tail = match[4] + match[5];
    for (let i = 0; i < 8; i++) {
        out.add(0x08 + i).writeU8(parseInt(tail.slice(i * 2, i * 2 + 2), 16));
    }
}

function zeroMemory(destination, size) {
    ptr(destination).writeByteArray(new Uint8Array(size));
}

function bytesToHex(value, length) {
    const bytes = ptr(value).readByteArray(length);
    return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function readCryStringHandle(value) {
    return readCryString(value);
}

function readCLocString(value) {
    try {
        return readWideCString(lower48(ptr(value).readPointer()));
    } catch (_) {
        return null;
    }
}

function readEntityId(value) {
    return ptr(value).readU64().toString();
}

function parseU16(value, name = "value") {
    const n = typeof value === "string" && /^0x/i.test(value) ? parseInt(value, 16) : Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 0xFFFF) {
        throw new Error(`${name} must be a uint16`);
    }
    return n & 0xFFFF;
}

function readVec3f(value) {
    const p = ptr(value);
    return {
        x: p.readFloat(),
        y: p.add(0x04).readFloat(),
        z: p.add(0x08).readFloat()
    };
}

function writeVec3f(value, vec) {
    const p = ptr(value);
    if (Object.prototype.hasOwnProperty.call(vec, "x")) p.writeFloat(parseFiniteFloat(vec.x, "x"));
    if (Object.prototype.hasOwnProperty.call(vec, "y")) p.add(0x04).writeFloat(parseFiniteFloat(vec.y, "y"));
    if (Object.prototype.hasOwnProperty.call(vec, "z")) p.add(0x08).writeFloat(parseFiniteFloat(vec.z, "z"));
}

function readVec3d(value) {
    const p = ptr(value);
    return {
        x: p.readDouble(),
        y: p.add(0x08).readDouble(),
        z: p.add(0x10).readDouble()
    };
}

function readVec3u64(value) {
    const p = ptr(value);
    return {
        x: p.readU64().toString(),
        y: p.add(0x08).readU64().toString(),
        z: p.add(0x10).readU64().toString()
    };
}

function sequentialSlots(prefix, count, startSlot) {
    const slots = {};
    for (let i = 0; i < count; i++) {
        slots[`${prefix}${i}`] = startSlot + i;
    }
    return slots;
}

function enumName(enumObject, value) {
    for (const [name, enumValue] of Object.entries(enumObject)) {
        if (enumValue === value) return name;
    }
    return `unknown_${value}`;
}

function stdMapInfo(value) {
    const p = ptr(value);
    return {
        head: p.readPointer().toString(),
        size: p.add(0x08).readU64().toString()
    };
}

function traverseStdTreeMap(mapPtrValue, readNodeValue, limit = 16384) {
    const mapPtr = ptr(mapPtrValue);
    const head = mapPtr.readPointer();
    if (head.isNull()) return { map: null, entries: [] };

    const size = Number(mapPtr.add(0x08).readU64());
    const root = head.add(0x08).readPointer();
    const map = {
        ptr: mapPtr.toString(),
        head: head.toString(),
        root: root.toString(),
        size
    };

    if (root.isNull() || root.equals(head) || root.add(0x19).readU8() !== 0) {
        return { map, entries: [] };
    }

    const entries = [];
    const stack = [root];
    const seen = new Set();
    const max = Math.max(0, Number(limit) || 0);
    while (stack.length > 0 && entries.length < max) {
        const node = stack.pop();
        const nodeKey = node.toString();
        if (seen.has(nodeKey) || node.isNull() || node.equals(head)) continue;
        seen.add(nodeKey);
        if (node.add(0x19).readU8() !== 0) continue;

        const left = node.readPointer();
        const right = node.add(0x10).readPointer();
        if (!right.isNull() && !right.equals(head)) stack.push(right);
        if (!left.isNull() && !left.equals(head)) stack.push(left);

        entries.push(readNodeValue(node));
    }

    return { map, entries };
}

function stdVectorRawInfo(value) {
    const p = ptr(value);
    return {
        begin: p.readPointer().toString(),
        end: p.add(0x08).readPointer().toString(),
        capacityEnd: p.add(0x10).readPointer().toString()
    };
}

function eastlMapInfo(value) {
    const p = ptr(value);
    return {
        anchor: p.toString(),
        size: p.add(0x20).readU64().toString()
    };
}

function dataCoreArrayInfo(value) {
    const p = ptr(value);
    const high = p.add(0x04).readU32();
    return {
        data: lower48(p.readPointer()).toString(),
        ownsMemory: ((high >>> 16) & 1) !== 0,
        elementSize: (high >>> 17) & 0x7fff,
        count: p.add(0x08).readU32(),
        capacity: p.add(0x0C).readU32()
    };
}

function dataCoreOptionalInfo(value, typeName) {
    const p = ptr(value);
    return {
        ptr: p.toString(),
        type: `DataCoreOptional<${typeName}>`,
        valuePtr: p.readPointer().toString()
    };
}

function dataCoreStructPtrInfo(value, typeName) {
    const p = ptr(value);
    return {
        ptr: p.toString(),
        type: `DataCoreStructPtr<${typeName}>`,
        valuePtr: p.readPointer().toString()
    };
}

function vtableAddressMap(owner, slots) {
    const addresses = {};
    for (const [name, slot] of Object.entries(slots)) {
        addresses[`${name}Address`] = owner.vfuncAddress(slot).toString();
    }
    return addresses;
}

function eastlDequeInfo(value) {
    const p = ptr(value);
    return {
        ptrArray: p.readPointer().toString(),
        ptrArraySize: p.add(0x08).readU64().toString(),
        beginCurrent: p.add(0x10).readPointer().toString(),
        endCurrent: p.add(0x30).readPointer().toString()
    };
}

function componentPtrInfo(value) {
    const raw = ptr(value).readU64();
    return {
        raw: raw.toString(),
        ptr: lower48(raw).toString()
    };
}

function typedMemberInfo(value, type, size = null) {
    const info = {
        ptr: ptr(value).toString(),
        type
    };
    if (size !== null) info.size = size;
    return info;
}

function callVFunc(thisPtr, index, returnType, argTypes = [], args = [], name = null) {
    const objectPtr = ptr(thisPtr);
    if (objectPtr.isNull()) {
        throw new Error(`${name || "vfunc"} called on null object`);
    }

    const vtable = objectPtr.readPointer();
    if (vtable.isNull()) {
        throw new Error(`${name || "vfunc"} has null vtable`);
    }

    const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
    if (fnPtr.isNull()) {
        throw new Error(`${name || "vfunc"} has null function pointer at slot ${index}`);
    }

    return new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes])(objectPtr, ...args);
}

function tryCallVFunc(thisPtr, index, returnType, argTypes = [], args = [], name = null) {
    try {
        return callVFunc(thisPtr, index, returnType, argTypes, args, name);
    } catch (_) {
        return null;
    }
}


class QuatTFloat {
    constructor(address) {
        this.ptr = ptr(address);
        this.q = {
            x: this.ptr.add(0x00).readFloat(),
            y: this.ptr.add(0x04).readFloat(),
            z: this.ptr.add(0x08).readFloat(),
            w: this.ptr.add(0x0c).readFloat(),
        };
        this.t = {
            x: this.ptr.add(0x10).readFloat(),
            y: this.ptr.add(0x14).readFloat(),
            z: this.ptr.add(0x18).readFloat(),
        };
    }

    get finite() {
        return Number.isFinite(this.q.x) && Number.isFinite(this.q.y) && Number.isFinite(this.q.z) && Number.isFinite(this.q.w) &&
            Number.isFinite(this.t.x) && Number.isFinite(this.t.y) && Number.isFinite(this.t.z);
    }

    get identityFallback() {
        return Math.abs(this.q.x) < 0.0001 && Math.abs(this.q.y) < 0.0001 && Math.abs(this.q.z) < 0.0001 &&
            Math.abs(this.q.w - 1.0) < 0.0001 && Math.abs(this.t.x) < 0.0001 && Math.abs(this.t.y) < 0.0001 && Math.abs(this.t.z) < 0.0001;
    }

    toObject() {
        return { q: this.q, t: this.t, finite: this.finite, identityFallback: this.identityFallback };
    }
}

const BoneId = Object.freeze({
    ROOT: 0,
    PELVIS: 1,
    SPINE01: 2,
    SPINE02: 3,
    SPINE03: 4,
    NECK: 5,
    R_EYE: 6,
    L_EYE: 7,
    R_FOOT: 10,
    L_FOOT: 11,
    R_SHOULDER: 12,
    L_SHOULDER: 13,
    R_ELBOW: 14,
    L_ELBOW: 15,
    R_HAND: 16,
    L_HAND: 17,
    R_KNEE: 18,
    L_KNEE: 19,
    HEAD: 20,
    R_HIP: 21,
    L_HIP: 22,
});

const BoneList = Object.freeze([
    [0, "root"],
    [1, "pelvis"],
    [2, "spine01"],
    [3, "spine02"],
    [4, "spine03"],
    [5, "neck"],
    [6, "r_eye"],
    [7, "l_eye"],
    [10, "r_foot"],
    [11, "l_foot"],
    [12, "r_shoulder"],
    [13, "l_shoulder"],
    [14, "r_elbow"],
    [15, "l_elbow"],
    [16, "r_hand"],
    [17, "l_hand"],
    [18, "r_knee"],
    [19, "l_knee"],
    [20, "head"],
    [21, "r_hip"],
    [22, "l_hip"],
]);

const BoneConnections = Object.freeze([
    [BoneId.HEAD, BoneId.NECK],
    [BoneId.NECK, BoneId.SPINE03],
    [BoneId.SPINE03, BoneId.SPINE02],
    [BoneId.SPINE02, BoneId.SPINE01],
    [BoneId.SPINE01, BoneId.PELVIS],
    [BoneId.SPINE03, BoneId.R_SHOULDER],
    [BoneId.R_SHOULDER, BoneId.R_ELBOW],
    [BoneId.R_ELBOW, BoneId.R_HAND],
    [BoneId.SPINE03, BoneId.L_SHOULDER],
    [BoneId.L_SHOULDER, BoneId.L_ELBOW],
    [BoneId.L_ELBOW, BoneId.L_HAND],
    [BoneId.PELVIS, BoneId.R_HIP],
    [BoneId.R_HIP, BoneId.R_KNEE],
    [BoneId.R_KNEE, BoneId.R_FOOT],
    [BoneId.PELVIS, BoneId.L_HIP],
    [BoneId.L_HIP, BoneId.L_KNEE],
    [BoneId.L_KNEE, BoneId.L_FOOT],
]);

function boneName(id) {
    const entry = BoneList.find(([boneId]) => boneId === id);
    return entry ? entry[1] : `bone_${id}`;
}

let CActorGetBoneTransformNative = null;
function cActorGetBoneTransformNative() {
    if (!CActorGetBoneTransformNative) {
        CActorGetBoneTransformNative = new NativeFunction(CActor__GetBoneTransform_ADDR, "pointer", ["pointer", "pointer", "uint"]);
    }
    return CActorGetBoneTransformNative;
}

class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
}

class StdVector {
    constructor(ptrValue, elementSize, elementClass = null) {
        this.ptr = ptr(ptrValue);
        this.elementSize = elementSize;
        this.elementClass = elementClass;
    }

    get begin() {
        return this.ptr.readPointer();
    }

    get end() {
        return this.ptr.add(0x08).readPointer();
    }

    get capacityEnd() {
        return this.ptr.add(0x10).readPointer();
    }

    get count() {
        const begin = this.begin;
        const end = this.end;
        if (begin.isNull() || end.isNull()) return 0;
        return end.sub(begin).toInt32() / this.elementSize;
    }

    at(index) {
        if (index < 0 || index >= this.count) return null;
        const itemPtr = this.begin.add(index * this.elementSize);
        return this.elementClass ? new this.elementClass(itemPtr) : itemPtr;
    }

    toArray(limit = this.count) {
        const out = [];
        const n = Math.min(this.count, limit);
        for (let i = 0; i < n; i++) out.push(this.at(i));
        return out;
    }

    toSummary() {
        return {
            begin: this.begin.toString(),
            end: this.end.toString(),
            capacityEnd: this.capacityEnd.toString(),
            count: this.count
        };
    }
}

class QuatT {
    constructor(ptrValue) {
        const p = ptr(ptrValue);
        this.x = p.readDouble();
        this.y = p.add(0x08).readDouble();
        this.z = p.add(0x10).readDouble();
        this.w = p.add(0x18).readDouble();
        this.t = new DVec3(
            p.add(0x20).readDouble(),
            p.add(0x28).readDouble(),
            p.add(0x30).readDouble()
        );
    }
}

class QuatTS extends QuatT {
    constructor(ptrValue) {
        super(ptrValue);
        this.s = ptr(ptrValue).add(0x38).readDouble();
    }
}

class CEntityClass {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get classGuid() {
        return readCryGuid(this.ptr.add(0x88));
    }

    get name() {
        return readCryString(this.ptr.add(0x10));
    }

    get group() {
        return readCryString(this.ptr.add(0x18));
    }

    get classCrc() {
        return this.ptr.add(0x20).readU32();
    }

    get flags() {
        return this.ptr.add(0x08).readU32();
    }

    get propertyHandlerPtr() {
        return this.ptr.add(0x40).readPointer();
    }

    get editorClassInfoPtr() {
        return this.ptr.add(0x48);
    }

    get classComponentParamsPtr() {
        return this.ptr.add(0x28);
    }

    get isUniqueEntityClass() {
        return this.ptr.add(0x9C).readU8() !== 0;
    }

    containsComponent(componentId) {
        return callVFunc(
            this.ptr,
            11,
            "bool",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityClass::ContainsComponent"
        );
    }

    componentIds(limit = 256) {
        const vectorPtr = this.classComponentParamsPtr;
        if (vectorPtr.isNull()) return [];

        const begin = vectorPtr.readPointer();
        const end = vectorPtr.add(0x08).readPointer();
        if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return [];

        const count = Math.min(Math.floor(end.sub(begin).toUInt32() / 0x20), Number(limit));
        const ids = [];
        for (let i = 0; i < count; i++) {
            ids.push(begin.add(i * 0x20).readU16());
        }
        return ids;
    }

    components(limit = 256) {
        const componentSystem = gEnv.entityComponentSystem;
        return this.componentIds(limit).map(componentId => {
            const info = componentSystem?.componentInfoById(componentId) ?? { componentId };
            return info;
        });
    }

    toObject(includeComponents = false) {
        const out = {
            ptr: this.ptr.toString(),
            name: this.name,
            group: this.group,
            classCrc: this.classCrc,
            flags: this.flags,
            classGuid: this.classGuid,
            propertyHandler: this.propertyHandlerPtr.toString(),
            editorClassInfo: this.editorClassInfoPtr.toString(),
            classComponentParams: this.classComponentParamsPtr.toString(),
            isUniqueEntityClass: this.isUniqueEntityClass
        };

        if (includeComponents) out.components = this.components();
        return out;
    }
}

class CZone {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get parent() {
        const zonePtr = callVFunc(this.ptr, 1, "pointer", [], [], "IZone::GetParent");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    get name() {
        return readCString(callVFunc(this.ptr, 64, "pointer", [], [], "IZone::GetName"));
    }

    worldToZonePosition(pos) {
        const input = Memory.alloc(0x18);
        input.writeDouble(pos.x ?? pos[0]);
        input.add(0x08).writeDouble(pos.y ?? pos[1]);
        input.add(0x10).writeDouble(pos.z ?? pos[2]);

        const output = Memory.alloc(0x18);
        callVFunc(
            this.ptr,
            33,
            "pointer",
            ["pointer", "pointer"],
            [output, input],
            "IZone::ConvertWorldSpaceToZoneSpace_10"
        );

        return new DVec3(output.readDouble(), output.add(0x08).readDouble(), output.add(0x10).readDouble());
    }
}

class CPhysicalWorld {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get universeGrid() {
        return callVFunc(this.ptr, 21, "pointer", [], [], "IPhysicalWorld::GetUniverseGrid");
    }

    getRelativeTransform(fromGrid = null, toGrid = null, scale = 1.0, lockFlag = false) {
        const output = Memory.alloc(0x38);
        const fallbackGrid = (!fromGrid || !toGrid) ? this.universeGrid : NULL;

        callVFunc(
            this.ptr,
            136,
            "pointer",
            ["pointer", "pointer", "pointer", "float", "bool"],
            [output, fromGrid ? ptr(fromGrid) : fallbackGrid, toGrid ? ptr(toGrid) : fallbackGrid, scale, lockFlag ? 1 : 0],
            "IPhysicalWorld::GetRelativeTransform"
        );

        return new QuatT(output);
    }
}

class CPhysicalEntity {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get owningEntity() {
        const entityPtr = lower48(this.ptr.add(0x0C0).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get lockUpdate() {
        return this.ptr.add(0x0C8).readS64();
    }

    get name() {
        return readCString(this.ptr.add(0x0E8).readPointer());
    }

    get physicalId() {
        return this.ptr.add(0x108).readS32();
    }

    get world() {
        const worldPtr = this.ptr.add(0x2C0).readPointer();
        return worldPtr.isNull() ? null : new CPhysicalWorld(worldPtr);
    }

    get worldTransform() {
        return {
            quat: {
                x: this.ptr.add(0x1D8).readFloat(),
                y: this.ptr.add(0x1DC).readFloat(),
                z: this.ptr.add(0x1E0).readFloat(),
                w: this.ptr.add(0x1E4).readFloat()
            },
            translation: new DVec3(
                this.ptr.add(0x1C0).readDouble(),
                this.ptr.add(0x1C8).readDouble(),
                this.ptr.add(0x1D0).readDouble()
            ),
            scale: this.ptr.add(0x200).readFloat()
        };
    }

    get foreignEntityId() {
        const output = Memory.alloc(0x08);
        output.writeU64(uint64(0));
        callVFunc(this.ptr, 18, "pointer", ["pointer"], [output], "IPhysicalEntity::GetForeignEntityId");
        return output.readU64();
    }
}

class CRigidEntity extends CPhysicalEntity {
    get newPosition() {
        return new DVec3(
            this.ptr.add(0x400).readDouble(),
            this.ptr.add(0x408).readDouble(),
            this.ptr.add(0x410).readDouble()
        );
    }

    get position() {
        return new DVec3(
            this.ptr.add(0x668).readDouble(),
            this.ptr.add(0x670).readDouble(),
            this.ptr.add(0x678).readDouble()
        );
    }

    get velocity() {
        return new DVec3(
            this.ptr.add(0x6CC).readFloat(),
            this.ptr.add(0x6D0).readFloat(),
            this.ptr.add(0x6D4).readFloat()
        );
    }

    get mass() {
        return this.ptr.add(0x6F0).readDouble();
    }

    get netState() {
        const statePtr = this.ptr.add(0x970).readPointer();
        return statePtr.isNull() ? null : statePtr;
    }

    get netDesiredStateLock() {
        return this.ptr.add(0x978);
    }

    get shouldSnap() {
        return this.ptr.add(0x9EC).readU8() !== 0;
    }

    get hasNetworkAuthority() {
        return this.ptr.add(0x9ED).readU8() !== 0;
    }

    get isPhysicsSyncDisabled() {
        return this.ptr.add(0x9EE).readU8() !== 0;
    }
}

class CZoneSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get universeRootZone() {
        const zonePtr = callVFunc(this.ptr, 2, "pointer", [], [], "IZoneSystem::GetUniverseRootZone");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    getZone(handlePtr) {
        if (handlePtr === undefined || handlePtr === null) {
            return this.universeRootZone;
        }

        if (typeof handlePtr === "number") {
            return this.getZoneById(handlePtr);
        }

        const zonePtr = callVFunc(this.ptr, 13, "pointer", ["pointer"], [ptr(handlePtr)], "IZoneSystem::GetZone");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    getZoneById(zoneId) {
        const zonePtr = callVFunc(this.ptr, 14, "pointer", ["uint32"], [zoneId], "IZoneSystem::GetZone_2");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }
}

class CEntityComponentSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    getComponentIdByName(componentName) {
        const output = Memory.alloc(0x02);
        const name = Memory.allocUtf8String(componentName);
        const result = callVFunc(
            this.ptr,
            2,
            "pointer",
            ["pointer", "pointer"],
            [output, name],
            "IEntityComponentSystem::GetComponentId"
        );

        return {
            success: !result.isNull(),
            componentId: output.readU16(),
            resultPtr: result
        };
    }

    get registryHash() {
        return callVFunc(this.ptr, 30, "uint32", [], [], "IEntityComponentSystem::GetComponentRegistryHash");
    }

    get allComponentsMapPtr() {
        return callVFunc(this.ptr, 16, "pointer", [], [], "IEntityComponentSystem::GetAllComponents");
    }

    getComponentNameById(componentId) {
        const namePtr = callVFunc(
            this.ptr,
            4,
            "pointer",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentName"
        );
        return readCString(namePtr);
    }

    getComponentSubSystemById(componentId) {
        return callVFunc(
            this.ptr,
            5,
            "int",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentSubSystem"
        );
    }

    getComponentNameAliasById(componentId) {
        const aliasPtr = callVFunc(
            this.ptr,
            6,
            "pointer",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentNameAlias"
        );
        return readCString(aliasPtr);
    }

    isComponentImplementation(componentId) {
        return callVFunc(
            this.ptr,
            7,
            "bool",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::IsComponentImplementation"
        );
    }

    getComponentSizeById(componentId) {
        return callVFunc(
            this.ptr,
            8,
            "uint32",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentSize"
        );
    }

    getComponentAlignmentById(componentId) {
        return callVFunc(
            this.ptr,
            9,
            "uint32",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentAlignment"
        );
    }

    getStringHashFromComponentId(componentId) {
        return callVFunc(
            this.ptr,
            11,
            "uint32",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetStringHashFromComponentId"
        );
    }

    getComponentCreationFlags(componentId) {
        return callVFunc(
            this.ptr,
            12,
            "uint32",
            ["uint16"],
            [parseU16(componentId, "componentId")],
            "IEntityComponentSystem::GetComponentCreationFlags"
        );
    }

    componentInfoById(componentId) {
        const id = parseU16(componentId, "componentId");
        const name = this.getComponentNameById(id);
        return {
            componentId: id,
            componentIdHex: `0x${id.toString(16).padStart(4, "0")}`,
            name,
            alias: name ? this.getComponentNameAliasById(id) : null,
            subsystem: name ? this.getComponentSubSystemById(id) : null,
            size: name ? this.getComponentSizeById(id) : null,
            alignment: name ? this.getComponentAlignmentById(id) : null,
            stringHash: name ? this.getStringHashFromComponentId(id) : null,
            creationFlags: name ? this.getComponentCreationFlags(id) : null,
            isImplementation: name ? this.isComponentImplementation(id) : null
        };
    }

    allComponentEntries(limit = 16384) {
        const mapPtr = this.allComponentsMapPtr;
        if (mapPtr.isNull()) return { map: null, entries: [] };
        return traverseStdTreeMap(mapPtr, node => ({
            stringHashKey: node.add(0x1C).readU32(),
            componentId: node.add(0x20).readU16()
        }), limit);
    }

    registeredComponentIds(maxId = null, allowRangeFallback = false) {
        const max = maxId === null || maxId === undefined ? 0xFFFF : Math.min(parseU16(maxId, "maxId"), 0xFFFF);
        let entries = [];
        try {
            entries = this.allComponentEntries().entries;
        } catch (_) {
            entries = [];
        }

        if (entries.length === 0) {
            if (!allowRangeFallback) return [];
            const ids = [];
            const fallbackMax = maxId === null || maxId === undefined ? 4096 : max;
            for (let componentId = 0; componentId <= fallbackMax; componentId++) ids.push(componentId);
            return ids;
        }

        const seen = new Set();
        const ids = [];
        for (const entry of entries) {
            const componentId = parseU16(entry.componentId, "componentId");
            if (componentId > max || seen.has(componentId)) continue;
            seen.add(componentId);
            ids.push(componentId);
        }
        return ids;
    }

    registeredComponents(maxId = null, includeInvalid = false, allowRangeFallback = false) {
        const out = [];
        let entriesById = new Map();
        try {
            entriesById = new Map(this.allComponentEntries().entries.map(entry => [
                parseU16(entry.componentId, "componentId"),
                entry
            ]));
        } catch (_) {
            entriesById = new Map();
        }

        for (const componentId of this.registeredComponentIds(maxId, allowRangeFallback)) {
            const entry = entriesById.get(componentId) ?? { componentId, stringHashKey: null };
            let info;
            try {
                info = this.componentInfoById(componentId);
                info.stringHashKey = entry.stringHashKey;
            } catch (_) {
                if (!includeInvalid) continue;
                info = { componentId, stringHashKey: entry.stringHashKey, name: null, error: _.message };
            }
            if (info.name || includeInvalid) out.push(info);
        }
        return out;
    }

    findComponentsByName(pattern, maxId = null, allowRangeFallback = false) {
        const re = pattern instanceof RegExp ? pattern : new RegExp(String(pattern), "i");
        return this.registeredComponents(maxId, false, allowRangeFallback).filter(component => re.test(component.name ?? "") || re.test(component.alias ?? ""));
    }

    toObject(includeAllComponentsMap = false) {
        const out = {
            ptr: this.ptr.toString(),
            registryHash: this.registryHash
        };

        if (includeAllComponentsMap) {
            out.allComponentsMap = (() => {
                try {
                    return this.allComponentEntries(0).map;
                } catch (e) {
                    return { error: e.message };
                }
            })();
        }

        return out;
    }
}

class EntityComponent {
    constructor(ptrValue, componentName = "Unknown") {
        this.ptr = ptr(ptrValue);
        this.componentName = componentName;
    }

    get owningEntity() {
        const entityPtr = lower48(this.ptr.add(0x08).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get componentId() {
        return this.ptr.add(0x3A).readU16();
    }

    get debugUpdateIndex() {
        return this.ptr.add(0x40).readU32();
    }

    get isDebugUpdateEnabled() {
        return this.ptr.add(0x45).readU8() !== 0;
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            componentName: this.componentName,
            componentId: this.componentId,
            componentIdHex: `0x${this.componentId.toString(16).padStart(4, "0")}`,
            owningEntity: this.owningEntity?.ptr.toString() ?? null,
            debugUpdateIndex: this.debugUpdateIndex,
            isDebugUpdateEnabled: this.isDebugUpdateEnabled
        };
    }
}

class IMissionSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get missionService() {
        const servicePtr = callVFunc(this.ptr, 9, "pointer", [], [], "IMissionSystem::GetIMissionService");
        return servicePtr.isNull() ? null : new IMissionService(servicePtr);
    }

    get environmentalMissionManager() {
        return callVFunc(this.ptr, 7, "pointer", [], [], "IMissionSystem::GetIEnvironmentalMissionManager");
    }

    get lawSystem() {
        return callVFunc(this.ptr, 8, "pointer", [], [], "IMissionSystem::GetILawSystem");
    }

    get contractGenerator() {
        return callVFunc(this.ptr, 10, "pointer", [], [], "IMissionSystem::GetIContractGenerator");
    }

    get contractBroker() {
        return callVFunc(this.ptr, 11, "pointer", [], [], "IMissionSystem::GetIContractBroker");
    }

    get missionFactory() {
        return callVFunc(this.ptr, 12, "pointer", [], [], "IMissionSystem::GetIMissionFactory");
    }

    get missionSystemDebug() {
        return callVFunc(this.ptr, 13, "pointer", [], [], "IMissionSystem::GetIMissionSystemDebug");
    }

    get commsNotificationManager() {
        return callVFunc(this.ptr, 14, "pointer", [], [], "IMissionSystem::GetICommsNotificationManager");
    }

    get cvars() {
        return callVFunc(this.ptr, 15, "pointer", [], [], "IMissionSystem::GetCVars");
    }

    get useNewMissionSystem() {
        return callVFunc(this.ptr, 33, "bool", [], [], "IMissionSystem::UseNewMissionSystem");
    }

    get reviveBeaconsEnabled() {
        return callVFunc(this.ptr, 34, "bool", [], [], "IMissionSystem::IsReviveBeaconsEnabled");
    }

    get beaconScreenEnabled() {
        return callVFunc(this.ptr, 35, "bool", [], [], "IMissionSystem::IsBeaconScreenEnabled");
    }

    get missionDataSet() {
        return callVFunc(this.ptr, 44, "pointer", [], [], "IMissionSystem::GetMissionDataSet");
    }

    get missionDataSetConst() {
        return callVFunc(this.ptr, 45, "pointer", [], [], "IMissionSystem::GetMissionDataSet_2");
    }

    getContractDebugName(contractDefinitionIdPtr) {
        return readCString(callVFunc(
            this.ptr,
            47,
            "pointer",
            ["pointer"],
            [ptr(contractDefinitionIdPtr)],
            "IMissionSystem::GetContractDebugName"
        ));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            environmentalMissionManager: this.environmentalMissionManager.toString(),
            lawSystem: this.lawSystem.toString(),
            missionService: this.missionService?.ptr.toString() ?? null,
            contractGenerator: this.contractGenerator.toString(),
            contractBroker: this.contractBroker.toString(),
            missionFactory: this.missionFactory.toString(),
            missionSystemDebug: this.missionSystemDebug.toString(),
            commsNotificationManager: this.commsNotificationManager.toString(),
            cvars: this.cvars.toString(),
            useNewMissionSystem: this.useNewMissionSystem,
            reviveBeaconsEnabled: this.reviveBeaconsEnabled,
            beaconScreenEnabled: this.beaconScreenEnabled,
            missionDataSet: this.missionDataSet.toString(),
            missionDataSetConst: this.missionDataSetConst.toString()
        };
    }
}

class IMissionService {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get hasDebugCompleteAllObjectivesSlot() {
        try {
            return !this.ptr.readPointer().add(29 * PTR_SIZE).readPointer().isNull();
        } catch (_) {
            return false;
        }
    }
}

class ICIGServices {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get external() {
        const servicesPtr = tryCallVFunc(this.ptr, 2, "pointer", [], [], "ICIGServices::GetExternal");
        if (!servicesPtr) return null;
        return servicesPtr.isNull() ? null : new ICIGServicesExternal(servicesPtr);
    }

    get internal() {
        const servicesPtr = tryCallVFunc(this.ptr, 3, "pointer", [], [], "ICIGServices::GetInternal");
        if (!servicesPtr) return null;
        return servicesPtr.isNull() ? null : new ICIGServicesInternal(servicesPtr);
    }
}

class ICIGServicesExternal {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryApi() {
        const servicePtr = tryCallVFunc(this.ptr, 12, "pointer", [], [], "ICIGServicesExternal::GetInventoryApi");
        if (!servicePtr) return null;
        return servicePtr.isNull() ? null : new IInventoryApi(servicePtr);
    }
}

class ICIGServicesInternal {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get missionServiceInternal() {
        const servicePtr = tryCallVFunc(this.ptr, 31, "pointer", [], [], "ICIGServicesInternal::GetMissionServiceInternal");
        if (!servicePtr || servicePtr.equals(this.ptr)) return null;
        return servicePtr.isNull() ? null : new IMissionServiceInternal(servicePtr);
    }
}

class StdDeque {
    constructor(ptrValue, elemSize, ElemClass = null) {
        this.ptr = ptr(ptrValue);
        this.elemSize = elemSize;
        this.ElemClass = ElemClass;
    }

    static blockSizeFor(elemSize) {
        if (elemSize <= 1) return 16;
        if (elemSize <= 2) return 8;
        if (elemSize <= 4) return 4;
        if (elemSize <= 8) return 2;
        return 1;
    }

    get map() {
        return this.ptr.add(0x08).readPointer();
    }

    get mapSize() {
        return this.ptr.add(0x10).readU64();
    }

    get offset() {
        return this.ptr.add(0x18).readU64();
    }

    get size() {
        return this.ptr.add(0x20).readU64();
    }

    get blockSize() {
        return StdDeque.blockSizeFor(this.elemSize);
    }

    elementAddress(index) {
        const size = Number(this.size);
        if (index < 0 || index >= size) throw new Error(`deque index out of range: ${index}`);
        const map = this.map;
        const mapSize = Number(this.mapSize);
        if (map.isNull() || mapSize === 0) throw new Error("deque map is null");
        const logical = Number(this.offset) + index;
        const blockSize = this.blockSize;
        const mapIndex = Math.floor(logical / blockSize) & (mapSize - 1);
        const blockIndex = logical % blockSize;
        const block = map.add(mapIndex * PTR_SIZE).readPointer();
        if (block.isNull()) throw new Error(`deque block ${mapIndex} is null`);
        return block.add(blockIndex * this.elemSize);
    }

    at(index) {
        const p = this.elementAddress(index);
        return this.ElemClass ? new this.ElemClass(p) : p;
    }

    toArray(limit = 64) {
        const n = Math.min(Number(this.size), limit);
        const out = [];
        for (let i = 0; i < n; i++) {
            out.push(this.at(i));
        }
        return out;
    }

    toSummary() {
        let map, mapSize, offset, size;
        try {
            map = this.map.toString();
            mapSize = this.mapSize.toString();
            offset = this.offset.toString();
            size = this.size.toString();
        } catch (e) {
            map = null;
            mapSize = null;
            offset = null;
            size = null;
            return {
                map,
                mapSize,
                offset,
                size,
                elemSize: this.elemSize,
                blockSize: this.blockSize,
                error: e.message
            };
        }
        return {
            map,
            mapSize,
            offset,
            size,
            elemSize: this.elemSize,
            blockSize: this.blockSize
        };
    }
}

class CigFunctionBase {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get dispatcherOrDirectCall() {
        return this.ptr.readPointer();
    }

    get modify() {
        return this.ptr.add(0x08).readU64().toString();
    }

    get storage() {
        return this.ptr.add(0x10).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            dispatcherOrDirectCall: this.dispatcherOrDirectCall.toString(),
            modify: this.modify,
            storage: this.storage.toString()
        };
    }
}

class SharedPtr {
    constructor(ptrValue, typeName = null) {
        this.ptr = ptr(ptrValue);
        this.typeName = typeName;
    }

    get object() {
        return this.ptr.readPointer();
    }

    get controlBlock() {
        return this.ptr.add(0x08).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            typeName: this.typeName,
            object: this.object.toString(),
            controlBlock: this.controlBlock.toString()
        };
    }
}

class StdFunction {
    constructor(ptrValue, signature = null) {
        this.ptr = ptr(ptrValue);
        this.signature = signature;
    }

    get words() {
        const out = [];
        for (let i = 0; i < 8; i++) {
            out.push(this.ptr.add(i * PTR_SIZE).readPointer().toString());
        }
        return out;
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            signature: this.signature,
            words: this.words
        };
    }
}

class DataCoreRecordRef {
    constructor(ptrValue, typeName = null) {
        this.ptr = ptr(ptrValue);
        this.typeName = typeName;
    }

    get recordPtr() {
        return this.ptr.readPointer();
    }

    get id() {
        return this.ptr.add(0x08).readU64().toString();
    }

    get dbPtr() {
        return this.ptr.add(0x10).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            typeName: this.typeName,
            recordPtr: this.recordPtr.toString(),
            id: this.id,
            dbPtr: this.dbPtr.toString()
        };
    }
}

class CIGRWLock {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get lockPtr() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            lockPtr: this.lockPtr.toString(),
            size: InventoryManagementSurface.sizes.CIGRWLock_StlAdapter
        };
    }
}

class CIGCriticalSection {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get value() {
        return this.ptr.readU32();
    }

    get header() {
        return this.ptr.add(0x04).readU32();
    }

    get threadOwner() {
        return this.ptr.add(0x08).readPointer();
    }

    get functionOwnerValue() {
        return this.ptr.add(0x10).readU64().toString();
    }

    get lockOwner() {
        return this.ptr.add(0x18).readU32();
    }

    get recursionCount() {
        return this.ptr.add(0x1C).readU8();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            value: this.value,
            header: this.header,
            threadOwner: this.threadOwner.toString(),
            functionOwnerValue: this.functionOwnerValue,
            lockOwner: this.lockOwner,
            recursionCount: this.recursionCount
        };
    }
}

class LockedDeque {
    constructor(ptrValue, elementSize, elementClass = null, typeName = null) {
        this.ptr = ptr(ptrValue);
        this.elementSize = elementSize;
        this.elementClass = elementClass;
        this.typeName = typeName;
    }

    get deque() {
        return new StdDeque(this.ptr, this.elementSize, this.elementClass);
    }

    get lock() {
        return new CIGRWLock(this.ptr.add(0x28));
    }

    toObject(includeEntries = false, limit = 32) {
        return {
            ptr: this.ptr.toString(),
            type: this.typeName,
            deque: includeEntries ? this.deque.toArray(limit).map(entry => entry.toObject()) : this.deque.toSummary(),
            lock: this.lock.toObject()
        };
    }
}

class CSerializedRemoteMethod {
    constructor(ptrValue, signature = null) {
        this.ptr = ptr(ptrValue);
        this.signature = signature;
    }

    get hook() {
        return this.ptr.readU64().toString();
    }

    get handler() {
        return new CigFunctionBase(this.ptr.add(0x08));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            signature: this.signature,
            hook: this.hook,
            handler: this.handler.toObject()
        };
    }
}

class CSerializedVariable {
    constructor(ptrValue, valueReader = null, typeName = null, valueSize = null) {
        this.ptr = ptr(ptrValue);
        this.valueReader = valueReader;
        this.typeName = typeName;
        this.valueSize = valueSize;
    }

    get hook() {
        return this.ptr.readU64().toString();
    }

    get valuePtr() {
        return this.ptr.add(0x08);
    }

    get value() {
        return this.valueReader ? this.valueReader(this.valuePtr) : this.valuePtr;
    }

    toObject() {
        const value = this.value;
        const serializedValue = value && typeof value.toObject === "function"
            ? value.toObject()
            : (value && typeof value.toSummary === "function"
                ? value.toSummary()
                : (value instanceof NativePointer ? value.toString() : value));
        return {
            ptr: this.ptr.toString(),
            type: this.typeName,
            hook: this.hook,
            value: serializedValue,
            valuePtr: this.valuePtr.toString(),
            valueSize: this.valueSize
        };
    }
}

class LockedMap {
    constructor(ptrValue, typeName = null) {
        this.ptr = ptr(ptrValue);
        this.typeName = typeName;
    }

    get map() {
        return stdMapInfo(this.ptr);
    }

    get lock() {
        return this.ptr.add(0x10);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            type: this.typeName,
            map: this.map,
            lock: this.lock.toString()
        };
    }
}

class ReadWriteLockableValue {
    constructor(ptrValue, valueReader = null, typeName = null) {
        this.ptr = ptr(ptrValue);
        this.valueReader = valueReader;
        this.typeName = typeName;
    }

    get valuePtr() {
        return this.ptr;
    }

    get lock() {
        return this.ptr.add(0x10);
    }

    get value() {
        return this.valueReader ? this.valueReader(this.valuePtr) : this.valuePtr;
    }

    toObject() {
        const value = this.value;
        return {
            ptr: this.ptr.toString(),
            type: this.typeName,
            value: value && typeof value.toObject === "function" ? value.toObject() : value,
            valuePtr: this.valuePtr.toString(),
            lock: this.lock.toString()
        };
    }
}

class CDeferredCallbackQueueU64 {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get lock() {
        return this.ptr;
    }

    get callbacks() {
        return new StdVector(this.ptr.add(0x20), 0xD0);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            lock: this.lock.toString(),
            callbacks: this.callbacks.toSummary()
        };
    }
}

class SCigEventSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get callbackLock() {
        return this.ptr.add(0x08);
    }

    get callbacks() {
        return new StdVector(this.ptr.add(0x30), 0x20);
    }

    get component() {
        return this.ptr.add(0x48).readPointer();
    }

    get eventQueueLock() {
        return this.ptr.add(0x50);
    }

    get eventQueue() {
        return new StdVector(this.ptr.add(0x70), InventoryManagementSurface.sizes.CigFunctionBase, CigFunctionBase);
    }

    get activeObjectIterators() {
        return this.ptr.add(0x88).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            callbackLock: this.callbackLock.toString(),
            callbacks: this.callbacks.toSummary(),
            component: this.component.toString(),
            eventQueueLock: this.eventQueueLock.toString(),
            eventQueue: this.eventQueue.toSummary(),
            activeObjectIterators: this.activeObjectIterators.toString()
        };
    }
}

class SCigEventSystemWithLinks extends SCigEventSystem {
    get links() {
        return new StdVector(this.ptr.add(0x90), PTR_SIZE);
    }

    get linksToThis() {
        return new StdVector(this.ptr.add(0xA8), PTR_SIZE);
    }

    get dispatchers() {
        return new StdVector(this.ptr.add(0xC0), 0x10);
    }

    toObject() {
        return {
            ...super.toObject(),
            links: this.links.toSummary(),
            linksToThis: this.linksToThis.toSummary(),
            dispatchers: this.dispatchers.toSummary()
        };
    }
}

class SCigEventDispatcher {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get eventSystems() {
        return new StdVector(this.ptr, PTR_SIZE);
    }

    get links() {
        return new StdVector(this.ptr.add(0x20), PTR_SIZE);
    }

    get linksToThis() {
        return new StdVector(this.ptr.add(0x40), PTR_SIZE);
    }

    get eventMapping() {
        return stdMapInfo(this.ptr.add(0x60));
    }

    get eventMappingValid() {
        return this.ptr.add(0x70).readS32();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            eventSystems: this.eventSystems.toSummary(),
            links: this.links.toSummary(),
            linksToThis: this.linksToThis.toSummary(),
            eventMapping: this.eventMapping,
            eventMappingValid: this.eventMappingValid
        };
    }
}

class ILegacyEventSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get eventSystem() {
        return new SCigEventSystemWithLinks(this.ptr.add(0x08));
    }

    get eventDispatcher() {
        return new SCigEventDispatcher(this.ptr.add(0xE8));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            eventSystem: this.eventSystem.toObject(),
            eventDispatcher: this.eventDispatcher.toObject()
        };
    }
}

const EInventoryContext = Object.freeze({
    Container: 0x00,
    Debug: 0x01,
    Entitlement: 0x02,
    Location: 0x03,
    PlayerInventory: 0x04,
    Prison: 0x05,
    PersonalEntityInventory: 0x06,
    Hangar: 0x07,
    Mission: 0x08,
    ClientOnly: 0x09
});

const EInventoryContainerType = Object.freeze({
    OpenAlways: 0x02
});

const EInventoryContainerGridCellSizeUnit = Object.freeze({
    Meters: 0x00,
    Centimeters: 0x01
});

const EItemOwnershipStatus = Object.freeze({
    Imprinted: 0x02,
    Rented: 0x03,
    Bricked: 0x04
});

const EInventoryQueryOrderBy = Object.freeze({
    EntityId: 0x01,
    Rank: 0x02
});

const EPersonalInventoryOperationType = Object.freeze({
    Sort: 0x03,
    Split: 0x04,
    Stack: 0x05,
    StoreAndHide: 0x08,
    OpenNestedInventory: 0x09,
    QueryInventory: 0x0A,
    QueryOrCreate: 0x0B,
    SwapOutfit: 0x0C,
    StackAll: 0x0E
});

const EPlayerInventoryType = Object.freeze({
    LootEntity: 0x01,
    StoredItem: 0x04,
    SnapshotEntity: 0x05
});

const EInventoryDataRequestType = Object.freeze({
    WithExistingInventory: 0x00
});

const EInventoryRequestResult = Object.freeze({
    Fail_EntityNotFound: 0x02,
    Fail_LockFailed: 0x03,
    Fail_InvalidResponse: 0x04
});

const SInventoryManagementRequestFlags = Object.freeze({
    eRF_None: 0x00,
    eRF_LockQueueAck: 0x01
});

const InventoryManagementSurface = Object.freeze({
    source: "types.h verified",
    sizes: {
        CryGUID: 0x10,
        CTimeValue: 0x08,
        CryStringT_char: 0x08,
        StdVector: 0x18,
        EastlVector: 0x18,
        EntityId: 0x08,
        Vec3f: 0x0C,
        SVec3Def: 0x18,
        CSCURN_SSCURNMetaData: 0x02,
        CigVariant_i64_double_CryGUID_EntityId_CryString: 0x18,
        CSCURN_SCURNValue: 0x20,
        CSCURN: 0x28,
        Serialized_Detail_SRemoteMethodBase: 0x08,
        Serialized_Detail_SVariableBase: 0x08,
        SharedPtr: 0x10,
        StdFunction: 0x40,
        CIGRWLock: 0x20,
        CIGRWLock_StlAdapter: 0x28,
        CIGCriticalSection: 0x20,
        LockedDeque_CSCLocalPlayerPersonalThoughtComponent_SInventoryMove: 0x50,
        CTagList: 0x04,
        SEntityLocationInfo: 0x10,
        STraceId: 0xB0,
        OBB_tpl_double: 0x78,
        CigFunctionBase: 0x18,
        CSerializedRemoteMethod: 0x20,
        CSerializedVariable_bool: 0x10,
        CSerializedVariable_EntityId: 0x10,
        CSerializedVariable_SInventoryId: 0x20,
        CSerializedVariable_SCargoAmount: 0x18,
        CSerializedVariable_StdVector: 0x20,
        EastlOptional_SInventoryConfiguration: 0x38,
        LockedMap_uint_EntityId: 0x38,
        SReadWriteLockableValue_std_set_u64: 0x38,
        CDeferredCallbackQueue_u64: 0x38,
        CDeferredCallbackQueue_u64_SQueuedCallbackData: 0xD0,
        SCigEventSystem: 0x90,
        SCigEventSystemWithLinks: 0xE0,
        SCigEventDispatcher: 0x78,
        ILegacyEventSystem: 0x160,
        DataCoreArrayBase: 0x10,
        DCString: 0x08,
        CLocIdentifier: 0x08,
        STypeSubtypeParams: 0x10,
        SItemCategory: 0x28,
        SInventoryInteractionBlockingAttachedEntities: 0x40,
        SPlayerInventoryDef: 0x20,
        SInventoryConfig: 0x210,
        SOpenInventory: 0x1C,
        SLootGeneration: 0x04,
        SInventoryContainerCVars: 0x30,
        SInventoryContainerTypeBaseDef: 0x08,
        SInventoryOpenContainerTypeDef: 0x80,
        SInventoryOpenAlwaysContainerTypeDef: 0x80,
        SInventoryClosedContainerTypeDef: 0x10,
        SInventoryContainerItemTypeFilter: 0x20,
        SInventoryParams: 0x20,
        SInventoryGamePersistentData: 0xE8,
        SInventoryItemMapEntry: 0x30,
        SInventoryContainerUIParams: 0x48,
        SInventorySortMode: 0x10,
        SInventoryDropDetachRules: 0x40,
        SInventoryStateModifier: 0x18,
        SStowPolicyCache: 0x38,
        SCargoGridOccupantFace: 0x10,
        SCargoGridOccupantProperties: 0x68,
        SOpenInventoryOccupantItemTypeProperties: 0x78,
        SInventoryContainerManagerDef: 0xF8,
        SInventoryContainerGridCellSizeBase: 0x08,
        SInventoryContainerGridCellSizeCentimeters: 0x10,
        SInventoryContainerGridCellSizeMeters: 0x10,
        SInventoryId: 0x18,
        SInventoryEntity: 0x20,
        SInventoryConfiguration: 0x30,
        SInventoryContainerDef: 0x40,
        SInventoryItemTypes: 0x30,
        SInventoryUpdateItem: 0x68,
        SStowContext: 0x68,
        SStowItemRequestParams: 0x10,
        SCargoAmount: 0x10,
        SPaginationArguments: 0x20,
        SPaginationInfo: 0x18,
        SInventoryEntry: 0x10,
        SItemPortId: 0x10,
        SInventoryManagementRequestClassItemRank: 0x10,
        SInventoryContainerEntry: 0x48,
        SPlayerInventoryQuery: 0x98,
        SMoveStackRequest: 0x30,
        SMoveItemRequest: 0x28,
        SUnstackEntityRequestParams: 0x58,
        SUnstackEntityRequest: 0x48,
        SMoveEntityStackParam: 0x20,
        SInventoryManagementRequest: 0x1D0,
        SInventoryDataRequest: 0x20,
        SInventoryContainerManagerEntriesCache: 0x30,
        SInventoryContainerManagerDataCache: 0x90,
        SPersonalInventoryReceivedData: 0xE0,
        SPersonalInventoryData: 0x48,
        SInventoryContainerFilterCacheKey: 0x20,
        SInventoryContainerFilterCachePair: 0x50,
        SInventoryContainerManagerDataCachePair: 0xA8,
        CLocString: 0x08,
        CStringHash: 0x18,
        InteractionPointId: 0x18,
        DataCoreRecordRef_SCEntityClass: 0x18,
        EntityGraph_SEntityGraphFilterParams: 0x68,
        EntityGraph_SEntityGraphQueryFilterParams: 0x70,
        InventoryGridCommons_SPersonalThoughtInventoryLocalPageInfo: 0x10,
        InventoryUI_SInventoryUIData: 0x28,
        InventoryUI_SInventoryItemWeakenedData: 0x08,
        InventoryUI_SInventoryItemDataDesc: 0x20,
        InventoryUI_SInventoryItemData: 0x168,
        InventoryUI_SInventoryNavigationData: 0x20,
        InventoryUI_SInventoryMenuOptionData: 0x28,
        InventoryUI_SInventoryFilterData: 0x18,
        InventoryUI_SInventoryCategoryFilterData: 0x40,
        InventoryUI_SInventoryItemPort: 0x1D0,
        SInventoryContent: 0x30,
        SInventoryItemKey: 0x08,
        CBindingsShopInventoryItem: 0x370,
        SBindingsInventoryItem: 0x1490,
        SBindingsInventoryItemResourceContents: 0x178,
        InventoryGridCommons_SBindingsInventoryItemCraftedStat: 0x220,
        SBindingsInventoryItemMenuOptions: 0x1A8,
        SBindingsInventoryItemHologram: 0x298,
        SBindingsInventoryItemPersistence: 0x4D0,
        SBindingsInventoryItemDesc: 0x2F8,
        SBindingsInventoryCustomSubFilter: 0xE8,
        SBindingsInventoryCustomFilter: 0x160,
        SBindingsInventoryItemFilter: 0x210,
        SBindingsInventoryInvalidMoveData: 0x178,
        SBindingsInventoryContainer: 0x14A0,
        SBindingsInventoryContainerTab: 0xF8,
        SBindingsInventoryPopBox: 0x1E0,
        SBindingsInventoryContainerTabMenu: 0x1F8,
        SBindingsInventorySection: 0x540,
        InventoryGridCommons_SBindingsTooltipData: 0x3B8,
        SBindingsInventoryGridData: 0x12B8,
        InventoryGridCommons_CSCBaseInventoryGrid: 0x1D0,
        SCFreightKioskInventoryGrid: 0x1D0,
        SBindings_FreightElevatorUI: 0xCC0,
        CBindingsMap_SInventoryItemKey_SBindingsInventoryItem: 0x60,
        CSCInventoryDisplay_SPotentialQuickMove: 0x28,
        CSCInventoryDisplay: 0x1968,
        InventoryGridCommons_SSelectedInventoryThoughtOption: 0xB8,
        InventoryGridCommons_SInventoryGridThoughtOption: 0x180,
        CSCLocalPlayerPersonalThoughtComponent_SInventorySectionTab: 0x30,
        CSCLocalPlayerPersonalThoughtComponent_SLootingTabInventory: 0x30,
        CSCLocalPlayerPersonalThoughtComponent_SLootingInventoryData: 0x20,
        CSCLocalPlayerPersonalThoughtComponent_SInventorySection: 0x40,
        CSCLocalPlayerPersonalThoughtComponent_SectionState: 0x20,
        CSCLocalPlayerPersonalThoughtComponent_SInventorySectionsAndContainers: 0x78,
        CSCLocalPlayerPersonalThoughtComponent_SSelectedThoughtOption: 0xA8,
        CSCLocalPlayerPersonalThoughtComponent_SThoughtOption: 0xA0,
        CSCLocalPlayerPersonalThoughtComponent_SPITFavorite: 0xB8,
        CSCLocalPlayerPersonalThoughtComponent_SPITQuickAccessMenu: 0x48,
        CSCLocalPlayerPersonalThoughtComponent_SInventoryMove_SLocalAttachData: 0x18,
        CSCLocalPlayerPersonalThoughtComponent_SInventoryMove: 0x98,
        CSCLocalPlayerPersonalThoughtComponent_SDragItem: 0x1C0,
        CSCLocalPlayerPersonalThoughtComponent_SSoftAttachItemInfo: 0x20,
        CSCLocalPlayerPersonalThoughtComponent_SSwapPortDraggedItem: 0x38,
        CSCLocalPlayerPersonalThoughtComponent_SPendingSwapItem: 0x28,
        CSCLocalPlayerPersonalThoughtComponent_SLootingEquipment: 0x20,
        CSCLocalPlayerPersonalThoughtComponent_SPersonalThoughtInventoryContainer: 0x128,
        InventoryGridCommons_SPersonalThoughtInventoryContainer: 0x138,
        CSCLocalPlayerPersonalThoughtComponent: 0xA10,
        CSCPlayerInventory: 0x368,
        CInventoryContainerManager: 0x148,
        SInventoryContainerGridItem: 0x50,
        SGridItemRequest: 0x18,
        SInventoryContainerManagerEntry: 0x90,
        SInventoryContainerManagerData: 0x78,
        SInventoryEntityQuery: 0xB0,
        SInventoryQueryResult_Inventory: 0x20,
        SInventoryQueryResult: 0x38,
        SInventoryQueryResponse: 0x50,
        SInventoryQueryResultInfo: 0x70,
        CInventoryContainerManager_CInventoryQueryPendingRequest: 0x48,
        CInventoryContainerManager_CInventoryOpenPendingRequest: 0x88,
        CInventoryContainerManager_LockedOpenPendingRequests: 0x40,
        SLootRequest: 0x30,
        SInventoryContainerItemGenerationRequest: 0x18,
        ContainerPacking_SFreeSpace: 0x38,
        ContainerPacking_SItem: 0xF0,
        ContainerPacking_SContainer: 0xB0,
        ContainerPacking_SPackingPlan: 0x20,
        SGridBox: 0x30,
        SSerializeableFreeSpace: 0x40,
        CInventoryContainerComponent_SCargoGridLockData: 0x10,
        CInventoryContainerComponent_SSerializedAndLockedCargoGridsLocks: 0x58,
        SInventoryEventListener: 0x10,
        CInventoryContainerComponent_LockedEventListeners: 0x40,
        CInventoryContainerComponent_SOpenAttachmentOcclusionDebug: 0x90,
        SPersonalInventoryReceivedData: 0xE0,
        SStowRequest: 0x148,
        SEntityUnstowParams: 0x78,
        SUnstowInfo: 0xD0,
        SStowInfo: 0x30,
        SUnstowItemRequestParams: 0x70,
        SUnstowRequest: 0x30,
        SSPlitStackRequestParams: 0x48,
        SSplitStackRequest: 0x48,
        SDeleteItemRequestParams: 0x28,
        SDeleteItemRequest: 0x30,
        SInventoryUpdateContext: 0x28,
        SEntityStackChangeParam: 0x10,
        SStowEntityRequest: 0x10,
        IInventoryApi_SMoveResult: 0x18,
        IInventoryApi_SMoveRequest: 0x50,
        SIncreaseEntityStackRequest: 0x30,
        SDecreaseEntityStackRequest: 0x30,
        SMoveEntityStackRequest: 0x48,
        SSetEntityStackRequest: 0x30,
        STransferEntityAggregateRequest: 0x50,
        SCreateEntityToInventoryRequest: 0x90,
        IInventoryApi_SCreateEntityToInventoryRequest: 0x78,
        SDestroyEntityPreconditions: 0x08,
        SDestroyEntityParam: 0x18,
        SDestroyEntityRequest: 0x30,
        SOptionalArguments: 0x18,
        EntityGraph_SChangeRankParam: 0x30,
        EntityGraph_SMoveParam: 0x88,
        EntityGraph_SMoveAllParam: 0x68,
        EntityGraph_SAttachEntry: 0x28,
        EntityGraph_SAttachParam: 0x48,
        EntityGraph_SDetachEntry: 0x10,
        EntityGraph_SDetachParam: 0x48,
        EntityGraph_SChangeSnapshotParam: 0x18,
        EntityGraph_SEraseParam: 0x30,
        IItemPortModificationApi_SAttachRequest: 0x48,
        IItemPortModificationApi_SDetachRequest: 0x28,
        IItemPortModificationApi_SModifyItemPortRequest: 0x60,
        IInventoryManagementApi_SQueryFiltersContext: 0x18,
        IInventoryManagementApi_SQueryFilters: 0x48,
        IInventoryManagementApi_SUpdateInventoryRequest: 0x28,
        CInventoryContainerManager_SLootableBox: 0x28,
        CInventoryContainerManager_AsyncQueryInventoryData_SQueryEntry: 0xD0,
        CInventoryContainerManager_AsyncStowEntity_SAsyncStowSharedData: 0x30,
        CInventoryContainerManager_ProcessPendingInventoryContainerOpens_SUnstowRequestInfo: 0x48,
        SFreightElevatorRequest: 0x90,
        CEntityComponentFreightElevatorUIProvider_SClientData: 0xC8,
        CEntityComponentFreightElevatorUIProvider_STransferRequestIndex: 0x10,
        CEntityComponentFreightElevatorUIProvider_BadStateRecoveryData: 0x40,
        CEntityComponentFreightElevatorUIProvider: 0x1240,
        CPlayerAssetManagerProvider_SBindingsInventory_Locations: 0xA0,
        CPlayerAssetManagerProvider_SBindingsInventory_FilterType: 0xA0,
        CPlayerAssetManagerProvider_SBindingsInventory_AssetStat: 0x110,
        CPlayerAssetManagerProvider_SBindingsInventory_AssetList: 0x308,
        CPlayerAssetManagerProvider_SAssetDirectory: 0x658,
        CPlayerAssetManagerProvider: 0x11B0,
        SBindingsLootItemSlotState: 0x5E0,
        SBindingsEquipGroupItemPorts: 0x380,
        SBindingsEquipItemPortInfo: 0x15E0,
        SBindingsPITInventoryDragEquipment: 0xEB0,
        SBindingsPITInventoryHoveredCharacterItemInfo: 0x398,
        SBindingsPITLootingFocusItem: 0x908,
        SBindingsPITLootPortContainerGroup: 0x1A20,
        SBindingsPITLootingArmour: 0x5810,
        SBindingsPITLootingClothing: 0x99B0,
        SBindingsPITLootingStorage: 0x1670,
        SBindingsPITLootingSection: 0x1E108,
        SBindingsPITInventoryLooting: 0x3D378,
        SBindingsPITInventoryItem: 0x670,
        SBindingsPITInventoryGrid: 0x1338,
        CSCPersonalThoughtDisplay: 0x3F000,
        CInventoryContainerComponent: 0x490,
        IPlatformInventoryManager: 0x08,
        IPlayerInventoryManager: 0x08,
        ISCActorInventory: 0x08,
        CSCActorInventory: 0xC8,
        CFuture_CigOptionalErrorResult_CigError: 0x20
    },
    sInventoryIdOffsets: {
        holderId: 0x00,
        context: 0x08,
        subject: 0x10
    },
    sInventoryContainerDefOffsets: {
        itemDimensions: 0x08,
        inventoryType: 0x20,
        excludedItemSubTypes: 0x28,
        capacity: 0x38
    },
    sInventoryOpenContainerTypeDefOffsets: {
        gridCellSize: 0x08,
        minPermittedItemSize: 0x10,
        maxPermittedItemSize: 0x28,
        isExternalContainer: 0x40,
        gridPosOffset: 0x48,
        maxPercentageErasedOnParentDestruction: 0x60,
        randomDestructionDistributionExponent: 0x64,
        appliedForceOnParentDestruction: 0x68,
        overrideStorableItemTypes: 0x70
    },
    sInventoryContainerItemTypeFilterOffsets: {
        itemType: 0x08,
        itemSubTypes: 0x10
    },
    sInventoryClosedContainerTypeDefOffsets: {
        capacity: 0x08
    },
    sInventoryParamsOffsets: {
        capacity: 0x18
    },
    sInventoryGamePersistentDataOffsets: {
        json: 0x00,
        writer: 0xC0,
        reader: 0xD0,
        counts: 0xE0
    },
    sInventoryItemMapEntryOffsets: {
        entityId: 0x00,
        stackCount: 0x08,
        missionId: 0x10,
        classGUID: 0x20
    },
    sInventoryContainerUIParamsOffsets: {
        nameIdentifier: 0x08,
        tags: 0x10,
        itemCategory: 0x18,
        nameLoc: 0x40
    },
    sInventorySortModeOffsets: {
        name: 0x08
    },
    sInventoryDropDetachRulesOffsets: {
        category: 0x08,
        dropDetachTypes: 0x30
    },
    sInventoryStateModifierOffsets: {
        openedState: 0x08,
        closedState: 0x10
    },
    sStowPolicyCacheOffsets: {
        policy: 0x00,
        index: 0x28,
        deferredWrite: 0x2A,
        crc: 0x2C,
        lastExpiryTime: 0x30
    },
    sCargoGridOccupantFaceOffsets: {
        faceUpwardAllowed: 0x08,
        stackingSupport: 0x0C
    },
    sCargoGridOccupantPropertiesOffsets: {
        top: 0x08,
        bottom: 0x18,
        front: 0x28,
        back: 0x38,
        right: 0x48,
        left: 0x58
    },
    sOpenInventoryOccupantItemTypePropertiesOffsets: {
        itemType: 0x08,
        defaultProperties: 0x10
    },
    sInventoryContainerManagerDefOffsets: {
        lootBoxes: 0x08,
        spawnLootGridDimensions: 0x18,
        closedInventoryNonStorableItemTypes: 0x30,
        closedInventoryNonStorableOutfitItemTypes: 0x40,
        openInventoryNonStorableItemTypes: 0x50,
        itemTypeOpenInventoryOccupantProperties: 0x60,
        defaultOpenInventoryOccupantProperties: 0x70,
        smallItemDropDist: 0xD8,
        bigItemDropDist: 0xDC,
        bigItemVolumeThresholdSCU: 0xE0,
        dropItemMaxHeight: 0xE4,
        dropItemSurfaceOffset: 0xE8,
        dropItemRetryOffset: 0xEC,
        numberOfRetries: 0xF0
    },
    sInventoryContainerGridCellSizeCentimetersOffsets: {
        centimeters: 0x08
    },
    sInventoryContainerGridCellSizeMetersOffsets: {
        meters: 0x08
    },
    sInventoryUpdateItemOffsets: {
        itemGEID: 0x00,
        classGUID: 0x08,
        amount: 0x18,
        legalOwnerGEID: 0x20,
        singleItemOccupancy: 0x28,
        rank: 0x38,
        context: 0x40
    },
    sStowContextOffsets: {
        entityId: 0x00,
        entitlementUrn: 0x08,
        classPtr: 0x30,
        ownerId: 0x38,
        isStowed: 0x40,
        inventoryId: 0x48,
        shardId: 0x60
    },
    sStowItemRequestParamsOffsets: {
        entityId: 0x00,
        rank: 0x08
    },
    sInventoryDataRequestOffsets: {
        withInventoryId: 0x00,
        withOwnerId: 0x18
    },
    sInventoryContainerEntryOffsets: {
        itemGEID: 0x00,
        classGUID: 0x08,
        itemClassName: 0x18,
        gridAmount: 0x20,
        ammoCount: 0x24,
        rank: 0x28,
        occupancy: 0x30,
        hasChildren: 0x40
    },
    inventoryUINavigationDataOffsets: {
        name: 0x00,
        tabIndex: 0x08,
        iconPath: 0x10,
        highlightEntityId: 0x18
    },
    inventoryUIMenuOptionDataOffsets: {
        name: 0x00,
        infoDisplayText: 0x08,
        isEnabled: 0x10,
        param: 0x14,
        userInput: 0x18,
        amount: 0x1C,
        minAmount: 0x20,
        maxAmount: 0x24
    },
    inventoryUICategoryFilterDataOffsets: {
        locId: 0x00,
        filterLabel: 0x08,
        iconPath: 0x10,
        disableForFPS: 0x18,
        filterType: 0x1C,
        active: 0x20,
        filters: 0x28
    },
    inventoryUIItemPortOffsets: {
        itemPortContainer: 0x00,
        itemPortId: 0x08,
        itemPortType: 0x18,
        itemPortSizeUIClass: 0x1C,
        iconClass: 0x20,
        localOffset: 0x28,
        capacityUsagePercentage: 0x34,
        weakData: 0x38,
        weaponType: 0x40,
        isVisible: 0x41,
        isFree: 0x42,
        isInteractive: 0x43,
        allowStorageInteractions: 0x44,
        itemHasCapacity: 0x45,
        isCorpseLocked: 0x46,
        itemData: 0x48,
        itemChildren: 0x1B0,
        flags: 0x1C8
    },
    sInventoryContentOffsets: {
        inventoryId: 0x00,
        classCRC: 0x18,
        rank: 0x20,
        gridAmount: 0x28,
        occupancy: 0x2C
    },
    sInventoryItemKeyOffsets: {
        value: 0x00
    },
    cBindingsShopInventoryItemOffsets: {
        rawBuyPrice: 0x50,
        rawSellToPrice: 0x98,
        stock: 0xE0,
        maxStock: 0x130,
        displayBuyPrice: 0x180,
        displaySellToPrice: 0x1C8,
        displayNameLoc: 0x210,
        amountInPersonalInventory: 0x260,
        itemGuid: 0x2B0,
        itemGEID: 0x2C0,
        itemName: 0x2C8,
        organizationPriceMods: 0x2D0,
        rentalOptions: 0x2E8,
        preSpawnedQuickBuyItems: 0x300,
        goldLicensesRequired: 0x318,
        platinumLicensesRequired: 0x320,
        hiddenPerkItem: 0x328,
        licencePerkItem: 0x329,
        shopLoadouts: 0x330,
        quantity: 0x348,
        quantitySellPrice: 0x350,
        previousBuyPrice: 0x358,
        previousSellPrice: 0x360,
        boxSizesAvailable: 0x368
    },
    sBindingsInventoryItemResourceContentsOffsets: {
        resourceName: 0x48,
        resourceQuality: 0x98,
        resourceAmountSCU: 0xE8,
        isVolatile: 0x130
    },
    inventoryGridCommonsCraftedStatOffsets: {
        statName: 0x48,
        baseValue: 0x98,
        newValue: 0xE8,
        deltaValue: 0x138,
        comparisonState: 0x188,
        isHighlighted: 0x1D8
    },
    sBindingsInventoryItemMenuOptionsOffsets: {
        active: 0x48,
        hoverItemMenuIndex: 0x90,
        name: 0xE0,
        options: 0x130
    },
    sBindingsInventoryItemHologramOffsets: {
        itemEntityClass: 0x48,
        lightGroupEntityClass: 0x98,
        dimensionX: 0xE8,
        dimensionY: 0x130,
        dimensionZ: 0x178,
        orientationX: 0x1C0,
        orientationY: 0x208,
        orientationZ: 0x250
    },
    sBindingsInventoryItemPersistenceOffsets: {
        isConsumable: 0x48,
        consumableRemainingVolume: 0x90,
        isAmmoContainer: 0xD8,
        ammoCount: 0x120,
        ammoMaxCount: 0x170,
        missionItem: 0x1C0,
        itemBrickingStatus: 0x208,
        itemTimerState: 0x258,
        itemTimerEnd: 0x2A8,
        craftedStats: 0x2F8,
        resourceCapacityUsage: 0x370,
        resourceCapacity: 0x3B8,
        resourceContents: 0x408,
        resourceDisplayMode: 0x480
    },
    sBindingsInventoryItemDescOffsets: {
        isTiered: 0x48,
        isSized: 0x90,
        isVehicleComponent: 0xD8,
        isMaterial: 0x120,
        tier: 0x168,
        materialQuality: 0x1B8,
        size: 0x208,
        componentClass: 0x258,
        componentGrade: 0x2A8
    },
    sBindingsInventoryCustomSubFilterOffsets: {
        name: 0x48,
        state: 0x98,
        filterLabel: 0xE0
    },
    sBindingsInventoryCustomFilterOffsets: {
        name: 0x48,
        state: 0x98,
        subfilters: 0xE0,
        filterLabel: 0x158
    },
    sBindingsInventoryItemFilterOffsets: {
        customFilters: 0x48,
        categoryFilters: 0xC0,
        itemFiltersExpanded: 0x138,
        customFilterExpanded: 0x180,
        clearFilter: 0x1C8
    },
    sBindingsInventoryInvalidMoveDataOffsets: {
        isInvalidMovement: 0x48,
        dropItemValid: 0x90,
        invalidMessagePersistentCondition: 0xD8,
        invalidMessageTemporaryCondition: 0x128
    },
    sBindingsInventoryItemOffsets: {
        descData: 0x60,
        dragItemTarget: 0x358,
        name: 0x3A8,
        tooltipDescription: 0x3F8,
        displayName: 0x448,
        itemDisplayThumbnail: 0x490,
        itemCount: 0x4E0,
        itemsCount: 0x530,
        order: 0x580,
        hologram: 0x5D0,
        isAttachment: 0x868,
        isInventoryContainer: 0x8B0,
        itemPersistence: 0x8F8,
        optionsMenu: 0xDC8,
        disabled: 0xF70,
        highlightMoveAll: 0xFB8,
        highlightQuickMoveInvalid: 0x1000,
        capacityUsage: 0x1048,
        isDragging: 0x1090,
        isCorpseLocked: 0x10D8,
        weakenedType: 0x1120,
        weakenedRatio: 0x1170,
        weaponType: 0x11B8,
        useOnEquipmentSlot: 0x1208,
        optionsTrigger: 0x1258,
        startDraggingTrigger: 0x12A0,
        stopDraggingTrigger: 0x12D0,
        singleClickCheckTrigger: 0x1300,
        onClickOpenContainer: 0x1348,
        quickMoveRollOnTrigger: 0x1390,
        quickMoveRollOffTrigger: 0x13D8,
        capacity: 0x1420,
        itemOccupancyAbs: 0x1428,
        occupancyFormatted: 0x1430,
        detailedDescription: 0x1438,
        isItemExpiryItem: 0x1440,
        itemExpiryEndTime: 0x1448,
        classCRC: 0x1450,
        missionGuid: 0x1458,
        inventoryId: 0x1468,
        rank: 0x1480,
        belongsToPlayer: 0x1488
    },
    sFreightElevatorRequestOffsets: {
        state: 0x00,
        requestId: 0x08,
        requestType: 0x10,
        requesterId: 0x18,
        locationId: 0x20,
        transferEntities: 0x28,
        warehouseEntities: 0x40,
        missionEntities: 0x58,
        groupWarehouseOrder: 0x70,
        containNonMissionCargo: 0x88
    },
    sBindingsInventoryContainerOffsets: {
        listOfItems: 0x48,
        dragContainerId: 0xC0,
        display: 0x110,
        loading: 0x158,
        name: 0x1A0,
        maxCapacity: 0x1F0,
        capacityUsage: 0x240,
        atFullCapacity: 0x288,
        itemCapacityUsage: 0x2D0,
        armorMaxCapacity: 0x318,
        containerHeight: 0x368,
        selectedItemIndex: 0x3B0,
        hoverItemIndex: 0x400,
        order: 0x450,
        nestedInventory: 0x4A0,
        hasNextPage: 0x4E8,
        hasPreviousPage: 0x530,
        currentPage: 0x578,
        totalPages: 0x5C8,
        pageSelection: 0x618,
        containerExpanded: 0x690,
        hasNoMoveableItems: 0x6D8,
        itemFilters: 0x720,
        filterView: 0x930,
        sortView: 0xAD8,
        itemHoverTooltip: 0xCC0,
        itemHoverIsCorpseLocked: 0xD10,
        hoverItemBrickingStatus: 0xD58,
        hoverItemTimerState: 0xDA8,
        hoverItemTimerEnd: 0xDF8,
        itemHoverCraftedStats: 0xE48,
        itemHoverResourceCapacity: 0xEC0,
        itemHoverResourceCapacityUsage: 0xF10,
        itemHoverResourceContents: 0xF58,
        comparableItemTooltip: 0xFD0,
        invalidMoveData: 0x1020,
        closeContainerTrigger: 0x1198,
        enterContainerTrigger: 0x11D8,
        leaveContainerTrigger: 0x1220,
        requestNextPageTrigger: 0x1268,
        requestPreviousPageTrigger: 0x12B0,
        requestFullSort: 0x12F8,
        moveAllTrigger: 0x1338,
        stackAllTrigger: 0x1380,
        moveAllRollOnTrigger: 0x13C0,
        moveAllRollOffTrigger: 0x1408,
        inventoryId: 0x1450,
        parentInventoryId: 0x1468,
        dimensions: 0x1480,
        gridCellPixelSize: 0x148C,
        usedCapacityAbs: 0x1490,
        typeOrderPriority: 0x1498,
        type: 0x149C
    },
    sBindingsInventoryContainerTabOffsets: {
        title: 0x48,
        iconPath: 0x98,
        tabIndex: 0xE8,
        highlightEntityId: 0xF0
    },
    sBindingsInventoryPopBoxOffsets: {
        display: 0x48,
        message: 0x90,
        acceptButtonText: 0xE0,
        cancelButtonText: 0x130,
        acceptActionTrigger: 0x180,
        cancelActionTrigger: 0x1B0
    },
    sBindingsInventoryContainerTabMenuOffsets: {
        display: 0x48,
        tabs: 0x90,
        selectedIndex: 0x108,
        hoverIndex: 0x158,
        previousTabTrigger: 0x1A8,
        nextTabTrigger: 0x1D0
    },
    sBindingsInventorySectionOffsets: {
        containers: 0x48,
        inventoryTabsMenu: 0xC0,
        tabsMenu: 0x2B8,
        searchBarTextInput: 0x4B0,
        applySearchTrigger: 0x500,
        lastSearchText: 0x530,
        isLeftSection: 0x538
    },
    inventoryGridCommonsTooltipDataOffsets: {
        tooltipEnabled: 0x48,
        currentTooltip: 0x90,
        currentComparableTooltip: 0xE0,
        tooltipCraftedStats: 0x130,
        currentResourceCapacity: 0x1A8,
        currentResourceContents: 0x1F8,
        itemBrickingStatus: 0x270,
        itemTimerState: 0x2C0,
        itemTimerEnd: 0x310,
        tooltipAlignment: 0x360,
        tooltipSrc: 0x3B0
    },
    sBindingsInventoryGridDataOffsets: {
        display: 0x60,
        playerSection: 0xA8,
        externalSection: 0x5E8,
        capacityBarTitle: 0xB28,
        currentDragContainerId: 0xB78,
        currentOrderIndex: 0xBC8,
        dragMovementResult: 0xC18,
        inventoryGeoTag: 0xC68,
        tooltipEnabled: 0xCB8,
        dragDropTarget: 0xD00,
        dropTooltip: 0xD50,
        isDragging: 0xDA0,
        cameraFocus: 0xDE8,
        weightRatio: 0xE30,
        settingsSelected: 0xE78,
        tooltipData: 0xEC0,
        backTrigger: 0x1278,
        armorCapacityUnits: 0x12A8,
        gridCellPixelSize: 0x12B0,
        dropBlocked: 0x12B4
    },
    inventoryGridCommonsBaseInventoryGridOffsets: {
        eventsTargetEntityPtr: 0x08,
        lastRequestTimeStamp: 0x10,
        lastRequestCompleteTimeStamp: 0x18,
        requestInventoryDataTimeStamp: 0x20,
        recentRequestElapsedTimes: 0x30,
        excludedItemTypes: 0x88,
        personalInventoryContainers: 0xB8,
        inventoryManagementLock: 0xF0,
        inventoryMoves: 0x110,
        actor: 0x160,
        player: 0x168,
        playerEntityId: 0x170,
        missionLog: 0x178,
        configDef: 0x180,
        inventorySectionLock: 0x188,
        eventsTargetComponentPtr: 0x1A8,
        pendingLocationInventoryQuery: 0x1B0,
        pendingVehicleInventoryQuery: 0x1B1,
        locationInventoryQueryRetries: 0x1B4,
        vehicleInventoryQueryRetries: 0x1B8,
        entityInventoryQueryRetries: 0x1C0
    },
    inventoryGridCommonsBaseInventoryGridVtable: {
        requestInventoryData: 0,
        requestInventoryData2: 1,
        requestInventoryDataNextPage: 2,
        closeInventoryGrid: 3,
        clearPlayerInventoryCache: 4,
        getGridCellPixelSize: 5,
        onInventoryRequestPopulateInventoryGrid: 6,
        onInventoryPopulateInventoryGridFail: 7,
        handlePITInventoryRequestCompleted: 8,
        revertInventoryMoves: 9,
        evaluateInventoryStateOnFailedMove: 10,
        getInventoryContainerItemsPerPage: 11,
        removeInventoryContainerFromUI: 12,
        terminateAccessToInventoryContainer: 13,
        reset: 14
    },
    sBindingsFreightElevatorUIOffsets: {
        leftViewIndex: 0x48,
        rightViewIndex: 0x98,
        viewList: 0xE8,
        exitKiosk: 0x160,
        hangarServiceOpen: 0x190,
        hangarServiceView: 0x1D8,
        loadingMessage: 0x710,
        loadingMessageState: 0x758,
        showItemBankView: 0x7A8,
        useTooltipFullDescription: 0x7F0,
        inventoryGeoTag: 0x838,
        currentDragContainerId: 0x888,
        currentDragXPos: 0x8D8,
        currentDragYPos: 0x920,
        generalPopup: 0x968,
        popupType: 0x9B0,
        closePopupTrigger: 0xA00,
        buttonPopupTrigger: 0xA30,
        capacityOverload: 0xA60,
        popupItemList: 0xAB0,
        popupMessage: 0xB28,
        searchBarTextInput: 0xB78,
        applySearchTrigger: 0xBC8,
        kioskName: 0xBF8,
        itemKeyAccumulator: 0xC48,
        popUpOnCloseWithButtonContext: 0xC50,
        defaultBindingTarget: 0xC58,
        defaultBindingsVendor: 0xC60,
        initialDropTargetId: 0xC68,
        missionItemData: 0xC70,
        dropIdCounter: 0xC88,
        rightViewHistoric: 0xC90,
        leftViewHistoric: 0xCA8
    },
    cscInventoryDisplayOffsets: {
        controllerEntity: 0x08,
        actor: 0x10,
        inventoryGridData: 0x18,
        displayV4: 0x12D0,
        enableV4: 0x1318,
        exitButtonAction: 0x1360,
        inventoryDisplayState: 0x1510,
        popUpBox: 0x1560,
        settingsButtonAction: 0x1740,
        inventoryDragTargetId: 0x18F0,
        inventoryItemMenu: 0x18F8,
        inventoryEnabled: 0x1910,
        defaultItemThumbnail: 0x1918,
        selectedItem: 0x1920,
        potentialQuickMove: 0x1928,
        leftShiftPressed: 0x1950,
        rightAltPressed: 0x1951,
        bindingTarget: 0x1958,
        bindingsVendor: 0x1960
    },
    cscInventoryDisplayVtable: {
        resizeDynamicBBList: 0,
        resetUI: 1,
        resetInventoryItem: 2,
        resetInventoryGrid: 3,
        resetUIButtons: 4,
        populateInventoryGrid: 5,
        updateInventoryGridContainer: 6,
        updateInventoryBindings: 7,
        checkContainerCanStoreEntites: 8,
        willItemQuickMove: 9,
        canFitInContainer: 10,
        canFitInContainer2: 11,
        updateInventoryContainersOrder: 12,
        updateInventoryContainersSize: 13
    },
    freightElevatorUIProviderClientDataOffsets: {
        interactorId: 0x00,
        state: 0x08,
        localRequest: 0x10,
        externalInventoryId: 0xA0,
        bindingTarget: 0xB8,
        bindingsVendor: 0xC0
    },
    freightElevatorUIProviderOffsets: {
        freightElevatorUI: 0x48,
        freightKioskInventoryGrid: 0xD08,
        clientData: 0xED8,
        kioskWarehouseLocationId: 0xFA0,
        latestUserId: 0xFB0,
        kioskOwnerId: 0xFC0,
        platform: 0xFC8,
        platformEntityId: 0xFD0,
        clientRequest: 0xFD8,
        authorityState: 0x1070,
        authorityRequestResponse: 0x1088,
        token: 0x10A0,
        authoritySplitItemStack: 0x10B0,
        tokenSplitItemStackResult: 0x10D0,
        authorityMoveItemStack: 0x10F0,
        tokenMoveItemStackResult: 0x1110,
        authorityRequestRetrieveItems: 0x1130,
        warehouseMissionOrderQueryBatch: 0x1150,
        fillMissionItemsFutureHandle: 0x1188,
        deletionRequestFutureHandle: 0x1198,
        missionOrderRequestFutureHandle: 0x11A8,
        currentRequestFutureHandle: 0x11B8,
        pendingDeletionRequests: 0x11C8,
        pendingMissionOrderRequests: 0x11E0,
        isRecoveringFromBadState: 0x11F0,
        badStateRecoveryData: 0x1200
    },
    playerAssetManagerProviderOffsets: {
        requestInventoryLocationCollection: 0x48,
        requestInventoryId: 0x68,
        handleRequestInventoryLocationCallback: 0x88,
        handleRequestInventoryIdCallback: 0xA8,
        listOfInventoryLocations: 0xC8,
        directoryTreeSelectedIndex: 0x140,
        assetListSelectedIndex: 0x190,
        listOfInventoryLocationsExpanded: 0x1E0,
        assetFilterCategoryDropdownList: 0x228,
        assetFilterTypeDropdownList: 0x2A0,
        assetFilterCategorySelectedIndex: 0x318,
        assetFilterTypeSelectedIndex: 0x368,
        assetFilterCategoryExpanded: 0x3B8,
        assetFilterTypeExpanded: 0x400,
        assetFilterCategoryClearTrigger: 0x448,
        assetFilterTypeClearTrigger: 0x470,
        assetList: 0x498,
        selectedAsset: 0x7A0,
        assetListLoading: 0xD80,
        searchInput: 0xDC8,
        locationsLoading: 0xE18,
        showFilters: 0xE60,
        prevPage: 0xEA8,
        showPrevPage: 0xED0,
        nextPage: 0xF18,
        showNextPage: 0xF40,
        directoryTree: 0xF88,
        activeFilter: 0xF98,
        legallyOwnedVehiclesRequest: 0xFB0,
        inventoryAsyncRequest: 0xFC0,
        shipLocationsRequest: 0xFD0,
        awaitingLocationsQueryResponse: 0xFE0,
        awaitingInventoryIdQueryResponse: 0xFE1,
        awaitingShipQueryResponse: 0xFE2,
        awaitingPersonalInventoryQueryResponse: 0xFE3,
        userEntity: 0xFE8,
        pageInfo: 0xFF0,
        nextAvailableDirectoryID: 0x1008,
        currentOpenDirectory: 0x100C,
        savedInventoryIdPageRequest: 0x1010,
        assetManagerSessionId: 0x1030,
        itemTypeDef: 0x1038,
        legacyEventSystem: 0x1050
    },
    personalThoughtDisplayOffsets: {
        inventoryDisplayBase: 0x00,
        lootingData: 0x19C0,
        focusedLootItem: 0x3ED38,
        dragTargetIds: 0x3ED90,
        pendingPrimaryActionSelection: 0x3EDA8,
        lastAmmoRepoolOperation: 0x3EDB0,
        oldRepoolSourceBindings: 0x3EE48,
        oldRepoolTargetBindings: 0x3EE50,
        lootingPortsMap: 0x3EE58,
        usedCapacityAbs: 0x3EE68,
        secondarySelectionIndex: 0x3EE6C,
        listOfItems: 0x3EE70,
        displayAllItemPorts: 0x3EE88,
        displayingAllItemPorts: 0x3EE89,
        configDef: 0x3EE90,
        cameraConfig: 0x3EE98,
        legacyEventSystem: 0x3EEA0
    },
    sBindingsLootItemSlotStateOffsets: {
        isDisabled: 0x48,
        isInteractive: 0x90,
        isSelected: 0xD8,
        isInFocus: 0x120,
        isDragging: 0x168,
        isCompatibleItem: 0x1B0,
        isCorpseLocked: 0x1F8,
        compatibleState: 0x240,
        weakenedType: 0x290,
        weakenedRatio: 0x2E0,
        repoolingInfo: 0x328,
        lootItemRollOnTrigger: 0x4F0,
        lootItemRollOffTrigger: 0x520,
        lootPrimaryActionTrigger: 0x550,
        lootSecondaryActionTrigger: 0x580,
        lootDoubleClickActionTrigger: 0x5B0
    },
    sBindingsEquipItemPortInfoOffsets: {
        portAnchorX: 0x48,
        portAnchorY: 0xC8,
        id: 0x148,
        hologram: 0x198,
        type: 0x430,
        sizeClass: 0x480,
        iconPath: 0x4D0,
        isFree: 0x520,
        itemCapacityUsage: 0x568,
        hasCapacity: 0x5B0,
        number: 0x5F8,
        isVisible: 0x648,
        itemPersistence: 0x690,
        lootSlotState: 0xB60,
        descData: 0x1140,
        itemPortRollOnTrigger: 0x1438,
        itemPortRollOffTrigger: 0x1488,
        startDraggingLoot: 0x14D8,
        stopDraggingLoot: 0x1508,
        tooltipItemRollOnTrigger: 0x1538,
        tooltipItemRollOffTrigger: 0x1578,
        itemPortId: 0x15B8,
        itemPortContainer: 0x15C8,
        looseEntityId: 0x15D0,
        belongsToPlayer: 0x15D8,
        allowStorageInteractions: 0x15D9,
        groupType: 0x15DC
    },
    sBindingsEquipGroupItemPortsOffsets: {
        portAnchorX: 0x48,
        portAnchorY: 0xC8,
        groupItemPorts: 0x148,
        display: 0x1C0,
        isEmpty: 0x208,
        hoverGroupTooltip: 0x250,
        hoverGroupTooltipEnabled: 0x2A0,
        hoverGroupComparableTooltip: 0x2E8,
        hoverGroupComparableTooltipEnabled: 0x338
    },
    sBindingsPITInventoryDragEquipmentOffsets: {
        hologram: 0x48,
        id: 0x2E0,
        itemPorts: 0x330,
        consumablePorts: 0x3A8,
        attachmentsPorts: 0x728,
        throwablePorts: 0xAA8,
        startDraggingTrigger: 0xE28,
        stopDraggingTrigger: 0xE58,
        entity: 0xE88,
        groundFocusEntity: 0xE90,
        dragTargetIds: 0xE98
    },
    sBindingsPITInventoryHoveredCharacterItemInfoOffsets: {
        portAnchorX: 0x48,
        portAnchorY: 0xC8,
        tooltipInfo: 0x148,
        portKeyBindingInfo: 0x198,
        craftedStats: 0x1E8,
        enabled: 0x260,
        itemBrickingStatus: 0x2A8,
        itemTimerState: 0x2F8,
        itemTimerEnd: 0x348
    },
    sBindingsPITLootingFocusItemOffsets: {
        displayPort: 0x48,
        portAnchorX: 0x90,
        portAnchorY: 0x110,
        itemName: 0x190,
        hologram: 0x1E0,
        primaryActions: 0x478,
        item: 0x900
    },
    sBindingsPITLootPortContainerGroupOffsets: {
        itemContainer: 0x48,
        itemAttachments: 0x1628,
        showItemPreview: 0x19A8,
        attachmentsToggle: 0x19F0
    },
    sBindingsPITLootingArmourOffsets: {
        display: 0x48,
        helmet: 0x90,
        core: 0x1670,
        arms: 0x2C50,
        legs: 0x4230
    },
    sBindingsPITLootingClothingOffsets: {
        display: 0x48,
        head: 0x90,
        eyes: 0x1670,
        torso: 0x2C50,
        legs: 0x4230,
        feet: 0x5810,
        hands: 0x6DF0,
        backpack: 0x83D0
    },
    sBindingsPITLootingStorageOffsets: {
        display: 0x48,
        backpack: 0x90
    },
    sBindingsPITLootingSectionOffsets: {
        lootConsumablePorts: 0x48,
        lootAttachmentsPorts: 0x3C8,
        lootThrowablePorts: 0x748,
        handHeld: 0xAC8,
        primaryWeapon: 0x24E8,
        secondaryWeapon: 0x3F08,
        sidearmWeapon: 0x5928,
        gadget: 0x7348,
        meleeWeapon: 0x8D68,
        miningGadget: 0xA788,
        undersuit: 0xC1A8,
        armourGroup: 0xD788,
        clothingGroup: 0x12F98,
        storageGroup: 0x1C948,
        showLootingConsumablePreview: 0x1DFB8,
        showLootingAttachmentPreview: 0x1E000,
        showLootingThrowablePreview: 0x1E048,
        portContainerItems: 0x1E090
    },
    sBindingsPITInventoryLootingOffsets: {
        display: 0x48,
        currentDisplayView: 0x90,
        lootedHostilityReaction: 0xE0,
        gameMode: 0x130,
        playerEquipment: 0x180,
        lootedEntityEquipment: 0x1E288,
        focusItem: 0x3C390,
        lootingItemPreview: 0x3CC98,
        repoolingTimestamp: 0x3CF30,
        repoolingDuration: 0x3CF80,
        isRepooling: 0x3CFC8,
        repoolingStage: 0x3D010,
        dragDropTarget: 0x3D060,
        currentRollOverTarget: 0x3D0B0,
        cursorScreenRelPos: 0x3D100,
        takeAllMagazineAttachments: 0x3D1D8,
        magazineAttachmentsCanTakeAll: 0x3D208,
        takeAllUtilityAttachments: 0x3D250,
        utilityAttachmentsCanTakeAll: 0x3D280,
        holsterUnavailable: 0x3D2C8,
        toggleView: 0x3D310,
        requestInventoryView: 0x3D340,
        showAttachments: 0x3D370,
        enable: 0x3D371,
        userSelectedView: 0x3D374
    },
    sBindingsPITInventoryItemOffsets: {
        lootSlotState: 0x48,
        quickEquipTrigger: 0x628
    },
    sBindingsPITInventoryGridOffsets: {
        dragEquipment: 0x48,
        hoveredCharacterItem: 0xEF8,
        portsToolTipEnabled: 0x1290,
        requestLootingView: 0x12D8,
        requestChangeVersion: 0x1308
    },
    sUnstowInfoOffsets: {
        entityUnstowRequest: 0x00,
        inventoryId: 0x78,
        actorId: 0x90,
        atcId: 0x98,
        locationId: 0xA0,
        vehicleId: 0xA8,
        vehicleEntityClass: 0xB0,
        snapshotVariableRequests: 0xB8
    },
    sStowInfoOffsets: {
        vehicleId: 0x00,
        playerId: 0x08,
        locationId: 0x10,
        locationInventoryId: 0x18
    },
    sInventoryConfigOffsets: {
        selectTimer: 0x08,
        silhouettesAmount: 0x0C,
        silhouettesFillStr: 0x10,
        silhouetteEdgeWidth: 0x14,
        silhouetteBlurRadius: 0x18,
        hoverParams: 0x20,
        hoverAttachmentsParams: 0x60,
        focusParams: 0xA0,
        focusAttachmentsParams: 0xE0,
        unavailableParams: 0x120,
        unavailableAttachmentsParams: 0x160,
        blockedHoverParams: 0x1A0,
        extInvOutlineParams: 0x1E0,
        blockedInvOutlineParams: 0x1E8,
        skinParentTypes: 0x1F0,
        blockingRules: 0x200
    },
    sInventoryContainerCVarsOffsets: {
        log: 0x00,
        debugDuration: 0x04,
        maxUnstowsPerRequest: 0x08,
        maxUnstowRequests: 0x0C,
        openInventory: 0x10,
        lootGeneration: 0x2C
    },
    sPlayerInventoryQueryOffsets: {
        page: 0x00,
        orderBy: 0x20,
        inventoryId: 0x28,
        parentInventoryId: 0x40,
        type: 0x58,
        itemTypes: 0x60,
        excludeItemTypes: 0x70,
        localizedNamePattern: 0x80,
        localeLanguage: 0x88,
        localizedNamePatternIsRegex: 0x90
    },
    sInventoryManagementRequestOffsets: {
        requestMoveId: 0x00,
        type: 0x04,
        userId: 0x08,
        sourceInventoryId: 0x10,
        targetInventoryId: 0x28,
        affectedInventoriesDeprecated: 0x40,
        sourceClassId: 0x58,
        sourceAmount: 0x5C,
        sourceRank: 0x60,
        classItemRankList: 0x68,
        targetClassId: 0x80,
        targetAmount: 0x84,
        targetRank: 0x88,
        targetRankList: 0x90,
        itemEntityId: 0xA8,
        postActionTargetPortId: 0xB0,
        dependentMoveId: 0xC0,
        stack: 0xC4,
        postAction: 0xC8,
        dataEntries: 0xD0,
        inventoryQuery: 0xE8,
        offsetDirZs: 0x180,
        moveStackList: 0x190,
        unstowAggregateRootId: 0x1A8,
        itemPortPath: 0x1B0,
        itemPortId: 0x1B8,
        flags: 0x1C8
    },
    sMoveStackRequestOffsets: {
        sourceClassId: 0x00,
        sourceEntityId: 0x08,
        sourceRank: 0x10,
        sourceStackChange: 0x18,
        targetClassId: 0x1C,
        targetEntityId: 0x20,
        targetRank: 0x28
    },
    sMoveItemRequestOffsets: {
        itemGEID: 0x00,
        itemClassGUID: 0x08,
        legalOwnerGEID: 0x18,
        rank: 0x20
    },
    sUnstackEntityRequestParamsOffsets: {
        entityId: 0x00,
        quantity: 0x08,
        ranks: 0x10,
        classGuid: 0x28,
        ownerId: 0x38,
        snapshotSharedPtr: 0x40,
        tags: 0x50
    },
    sUnstackEntityRequestOffsets: {
        sourceInventoryId: 0x00,
        destinationInventoryId: 0x18,
        unstackParams: 0x30
    },
    sMoveEntityStackParamOffsets: {
        fromEntityId: 0x00,
        toEntityId: 0x08,
        rank: 0x10,
        stackSize: 0x18
    },
    iInventoryApiMoveResultOffsets: {
        from: 0x00,
        to: 0x08,
        fromStackSize: 0x10,
        toStackSize: 0x14
    },
    iInventoryApiMoveRequestOffsets: {
        from: 0x00,
        to: 0x20,
        rank: 0x40,
        stackSize: 0x48
    },
    sEntityStackChangeParamOffsets: {
        entityId: 0x00,
        classGuidCrc: 0x08,
        quantity: 0x0C
    },
    sEntityStackChangeRequestOffsets: {
        inventoryId: 0x00,
        stackChangeParams: 0x18
    },
    sMoveEntityStackRequestOffsets: {
        fromInventoryId: 0x00,
        toInventoryId: 0x18,
        moveParams: 0x30
    },
    sTransferEntityAggregateRequestOffsets: {
        fromInventoryId: 0x00,
        toInventoryId: 0x18,
        inventoryEntries: 0x30,
        legalOwnerId: 0x48
    },
    sCreateEntityToInventoryRequestOffsets: {
        entityClassGUID: 0x00,
        quantity: 0x10,
        updateContext: 0x18,
        targetRank: 0x40,
        tags: 0x48,
        createParamsCB: 0x50,
        ownerId: 0x68,
        snapshotSharedPtr: 0x70,
        ownershipTimeStamp: 0x80,
        ownershipStatus: 0x88
    },
    iInventoryApiCreateEntityToInventoryRequestOffsets: {
        entityClassGUID: 0x00,
        quantity: 0x10,
        rank: 0x18,
        snapshotSharedPtr: 0x20,
        updateContext: 0x30,
        tags: 0x58,
        createParamsCB: 0x60
    },
    sUnstowItemRequestParamsOffsets: {
        gridItem: 0x00,
        itemPortId: 0x50,
        action: 0x60,
        offsetDirZs: 0x64
    },
    sEntityUnstowParamsOffsets: {
        parentPortName: 0x00,
        entityId: 0x08,
        parentRelativeTransform: 0x10,
        parentId: 0x50,
        parentAttachId: 0x58,
        snapshotSharedPtr: 0x60,
        flags: 0x70,
        flagsEngaged: 0x74
    },
    sUnstowRequestOffsets: {
        inventoryId: 0x00,
        unstowParams: 0x18
    },
    sSplitStackRequestParamsOffsets: {
        entityId: 0x00,
        newStackQuantity: 0x08,
        newStackRank: 0x10,
        classGuid: 0x18,
        ownerId: 0x28,
        snapshotSharedPtr: 0x30,
        tags: 0x40
    },
    sSplitStackRequestOffsets: {
        sourceInventoryId: 0x00,
        destinationInventoryId: 0x18,
        splitParams: 0x30
    },
    sDeleteItemRequestParamsOffsets: {
        itemGEID: 0x00,
        classGUID: 0x08,
        amount: 0x18,
        legalOwnerId: 0x20
    },
    sDeleteItemRequestOffsets: {
        inventoryId: 0x00,
        deleteParams: 0x18
    },
    sStowEntityRequestOffsets: {
        entityAggregatePtr: 0x00,
        rank: 0x08
    },
    sStowRequestOffsets: {
        entityId: 0x00,
        inventoryId: 0x08,
        rank: 0x20,
        occupancy: 0x28,
        location: 0x30,
        purpose: 0x40,
        traceId: 0x44,
        inventoryConfig: 0xF8,
        topic: 0x128,
        serviceId: 0x130,
        shardId: 0x138,
        commandId: 0x140
    },
    sDestroyEntityPreconditionsOffsets: {
        stackSize: 0x00,
        stackSizeEngaged: 0x04
    },
    sDestroyEntityParamOffsets: {
        entityId: 0x00,
        preconditions: 0x08,
        preconditionsEngaged: 0x10
    },
    sDestroyEntityRequestOffsets: {
        inventoryId: 0x00,
        entities: 0x18
    },
    sOptionalArgumentsOffsets: {
        commandArgumentsPtr: 0x00,
        maxDuration: 0x08,
        maxDurationEngaged: 0x10
    },
    iItemPortModificationApiAttachRequestOffsets: {
        entity: 0x00,
        newParentEntity: 0x20,
        newItemPort: 0x40,
        disassembleCurrentAttachment: 0x44
    },
    iItemPortModificationApiDetachRequestOffsets: {
        entityId: 0x00,
        newInventoryId: 0x08,
        disassembleCurrentAttachment: 0x20,
        ownershipBehavior: 0x24
    },
    iItemPortModificationApiModifyItemPortRequestOffsets: {
        attachCommands: 0x00,
        detachCommands: 0x18,
        changeSnapshotCommands: 0x30,
        eraseCommands: 0x48
    },
    inventoryItemDataOffsets: {
        entityId: 0x00,
        ownerId: 0x08,
        inventoryId: 0x10,
        groupOriginInventoryId: 0x28,
        itemClassId: 0x40,
        rank: 0x48,
        gridAmount: 0x50,
        occupancy: 0x58,
        occupancyDimensions: 0x60,
        uiItemClassId: 0x6C,
        uiDimensions: 0x70,
        uiOrientation: 0x7C,
        lightGroupEntityClass: 0x88,
        gamePersistentData: 0xA0,
        consumableRemainingVolumePercentage: 0xA8,
        ammoCount: 0xAC,
        ammoMaxCount: 0xB0,
        weaponType: 0xB4,
        containerOccupancy: 0xB8,
        containerMaxOccupancy: 0xC0,
        itemMissionId: 0xC8,
        itemName: 0xD8,
        occupancyFormatted: 0xE0,
        detailedDescription: 0xE8,
        tooltipDescription: 0xF0,
        itemExpiryEndTime: 0xF8,
        isItemExpiryItem: 0x100,
        corpseLockedItem: 0x101,
        ownershipTimeStamp: 0x108,
        ownershipStatus: 0x110,
        weakData: 0x114,
        descData: 0x120,
        craftedProperties: 0x140,
        resources: 0x158
    },
    selectedInventoryThoughtOptionOffsets: {
        text: 0x00,
        description: 0x08,
        enabled: 0x10,
        name: 0x18,
        arg: 0x20,
        callback: 0x28,
        itemPtr: 0x68,
        postSelectAction: 0x70,
        interactionPointId: 0x78,
        interactionNameHash: 0x90,
        userInput: 0xA8,
        minAmount: 0xAC,
        maxAmount: 0xB0
    },
    personalThoughtInventoryContainerOffsets: {
        inventoryId: 0x00,
        ownerInventoryId: 0x18,
        classCRC: 0x30,
        parentInventoryId: 0x38,
        dimensions: 0x50,
        type: 0x5C,
        maxCapacity: 0x60,
        usedCapacity: 0x68,
        items: 0x70,
        nestedInventories: 0x88,
        groupedInventories: 0xA0,
        servicePageInfo: 0xB8,
        localPageInfo: 0xD0,
        activeFilter: 0xE0,
        filterString: 0x110,
        wideFilterString: 0x118,
        categoryFilters: 0x120,
        filtersExpanded: 0x121,
        waitingOnServer: 0x122,
        pendingDataRequests: 0x123,
        visible: 0x124,
        failedMoves: 0x125
    },
    personalThoughtInventoryMoveLocalAttachDataOffsets: {
        attachedEntity: 0x00,
        portPath: 0x08,
        aggregatePortParent: 0x10
    },
    personalThoughtInventoryMoveOffsets: {
        id: 0x00,
        type: 0x04,
        sourceInventoryId: 0x08,
        targetInventoryId: 0x20,
        sourceItems: 0x38,
        targetItems: 0x50,
        storedEntity: 0x68,
        localDetach: 0x70,
        inventoryQueryType: 0x74,
        timeStamp: 0x78,
        localAttachData: 0x80
    },
    cscLocalPlayerPersonalThoughtComponentOffsets: {
        dragItemPorts: 0xD0,
        inventorySectionLock: 0xE8,
        playerSection: 0x108,
        externalSection: 0x148,
        sectionsData: 0x188,
        lootAnimation: 0x200,
        configDef: 0x208,
        playerChoice: 0x210,
        actor: 0x218,
        player: 0x220,
        currentState: 0x228,
        currentInternalState: 0x22C,
        currentVersion: 0x230,
        currentMenuIndex: 0x234,
        selectedChoiceIndex: 0x238,
        hoverFavoriteIndex: 0x23C,
        previousFavoriteIndex: 0x240,
        lastFavoriteUpdated: 0x244,
        cursorType: 0x248,
        thoughtMenus: 0x250,
        categoriesActions: 0x268,
        favorites: 0x278,
        quickAccessMenus: 0x290,
        quickAccessActions: 0x2A8,
        quickAccessEventHashes: 0x2B8,
        rebuildMenu: 0x2C8,
        rebuildMenuTimer: 0x2D0,
        inventoryView: 0x2D8,
        inventoryCameraInteractionEnabled: 0x2E8,
        lastLocationId: 0x2EC,
        lastLandingZoneLocationId: 0x2F0,
        pendingLocationInventoryQuery: 0x2F4,
        pendingVehicleInventoryQuery: 0x2F5,
        locationInventoryQueryRetries: 0x2F8,
        vehicleInventoryQueryRetries: 0x2FC,
        entityInventoryQueryRetries: 0x300,
        personalInventoryContainers: 0x310,
        entitiesBlockingInteraction: 0x348,
        hadInteractionBlockingEntities: 0x360,
        closeInventoryForBlockingItemsCleared: 0x361,
        lastRequestTimeStamp: 0x368,
        lastRequestCompleteTimeStamp: 0x370,
        requestInventoryDataTimeStamp: 0x378,
        recentRequestElapsedTimes: 0x388,
        inventoryManagementLock: 0x3E0,
        inventoryMoves: 0x400,
        confirmedLocalAttachments: 0x450,
        externalInventoryEntityPtr: 0x460,
        extInventoryEntities: 0x468,
        extInventoryEntitiesDebug: 0x480,
        externalEntityHostilityReaction: 0x498,
        previousStance: 0x49C,
        isLooting: 0x49D,
        selectedInventoryId: 0x4A0,
        focusOnEntityPtr: 0x4B8,
        currentRequesterKioskEntityPtr: 0x4C0,
        requestedCamera: 0x4C8,
        focusBothEntities: 0x4D8,
        dragItem: 0x4E0,
        softAttachedItemInfo: 0x6A0,
        swapPortDraggedItem: 0x6C0,
        pendingSwapItem: 0x6F8,
        hiddenItemPorts: 0x720,
        thoughtMenusLock: 0x738,
        attachment: 0x758,
        legacyEventSystem: 0x760,
        chatAlreadyDisabled: 0x8C0,
        showDisabledActions: 0x8C1,
        showTriedToEquipClothingWithUndersuitHint: 0x8C2,
        chatEnabledOnOpen: 0x8C3,
        processingOnAction: 0x8C4,
        ammoRepooling: 0x8C5
    },
    cscPlayerInventoryOffsets: {
        pendingDataRequests: 0x00,
        pendingDataRequestsLock: 0x10,
        lastPendingRequestId: 0x30,
        inventoryManagementQueueLock: 0x38,
        inventoryManagementQueue: 0x58,
        unspawnedEntities: 0x80,
        pendingMoveTimer: 0xB8,
        lockedMoveRequestId: 0xC0,
        rmTokenTerminateAccessToInventory: 0xC8,
        rmAuthorityProcessInventoryManagementOperation: 0xE8,
        rmTokenRequestInventoryManagementOperation: 0x108,
        rmAuthorityRequestDropEquippedItem: 0x128,
        rmAuthorityNotifyLootEntityAccessed: 0x148,
        rmAuthorityNotifyReserveCarryable: 0x168,
        rmAuthorityRequestChangePortOnEquippedItem: 0x188,
        rmAuthorityRequestSwapPortOnEquippedItem: 0x1A8,
        rmTokenReceivePersonalInventoryData: 0x1C8,
        rmTokenMoveRequestCompleted: 0x1E8,
        rmTokenRefreshLocationInventory: 0x208,
        rmOnTokenSetHideEntity: 0x228,
        rmTokenRequestInventoryData: 0x248,
        rmAuthorityRequestOpenInventory: 0x268,
        rmAuthorityRequestCloseInventory: 0x288,
        rmAuthorityProcessDataRequest: 0x2A8,
        rmTokenDataResponse: 0x2C8,
        entityChangeRequestInProgress: 0x2E8,
        currentProcessingRequest: 0x2F0,
        itemTypeFilteredInventoryCache: 0x2F8,
        resetInventoryCache: 0x310,
        authNotifyCloseInventories: 0x330,
        player: 0x348,
        storedSwappedPortId: 0x350,
        responseEntityPtr: 0x360
    },
    cscPlayerInventoryFunctions: {
        requestInventoryManagementOperation: "0x1445DFE70",
        processRequest: "0x1445B56A0",
        queryInventoryInternal: "0x1445BA6C0",
        processRequestStoredItemInventory: "0x1445B5FF0",
        processMoveItems: "0x1445B3040",
        processStoreItem: "0x1445B7C50",
        asyncRequestAccessToInventory: "0x1444A99F0"
    },
    personalThoughtFunctions: {
        handleInventoryClickOpenContainer: "0x1462ED6F0",
        doOpenNestedInventory: "0x1462C3F60",
        onInventoryMoveItemOntoUnoccupiedPosition: "0x1463153E0",
        handleInventoryQuickMoveItem: "0x1462F3810",
        handleInventoryStoreItem: "0x1462F6FB0",
        storeItem: "0x14635B9D0",
        tryStoreItemInContainer: "0x14635F6D0"
    },
    cInventoryContainerManagerFunctions: {
        queueOpenInventoryContainer: "0x1445BB060",
        asyncOpenInventoryContainer: "0x1444A5240",
        asyncQueryInventory: "0x1444A5E50",
        processPendingInventoryContainerOpens: "0x1445B3C50"
    },
    headerFunctionCatalogs: {
        CSCPlayerInventory: [
            "AsyncRequestAccessToInventory",
            "AsyncRequestCurrentLocationInventory",
            "AsyncWithExistingInventory",
            "CacheItemTypeFilteredInventory",
            "ChangePortOnEquippedItem",
            "ClearInventoryCache",
            "DumpInventory",
            "GetInventoryTypeFromQuery",
            "HandleHelmetAttachRequestState",
            "MoveItemComplete",
            "PopulateRecievedPersonalInventoryData",
            "PostInitialize",
            "PostInitialize_",
            "ProcessAmmoRepool",
            "ProcessItemInteraction",
            "ProcessMoveItems",
            "ProcessQueryOrCreateInventory",
            "ProcessRequestQueryInventory",
            "ProcessRequestStoredItemInventory",
            "ProcessSortItems",
            "ProcessSplitItems",
            "ProcessStackAllItems",
            "ProcessStackItems",
            "ProcessStoreItem",
            "ProcessSwapItems",
            "ProcessSwapOutfit",
            "QueryInventoryInternal",
            "ReceivePersonalInventoryData",
            "RequestOrCreatePersonalInventoryData",
            "RequestOrCreatePersonalInventoryData_",
            "RequestPersonalInventoryData",
            "RequestTerminateAccessToInventory",
            "RmAuthorityProcessDataRequest",
            "RmAuthorityRequestCloseInventory",
            "RmAuthorityRequestOpenInventory",
            "RmTokenDataResponse",
            "SendDataRequest",
            "SwapPortOnEquippedItem",
            "Update"
        ],
        CInventoryContainerManager: [
            "AsyncAmmoRepoolInventory",
            "AsyncAmmoRepoolInventory_",
            "AsyncCanStoreEntities",
            "AsyncCanStoreEntities_",
            "AsyncCreateItem",
            "AsyncCreateItems",
            "AsyncCreateItemsToInventoryContainer",
            "AsyncDecreaseStackAmount",
            "AsyncDeleteItems",
            "AsyncDeleteItemsIf",
            "AsyncDeleteItemsIf_",
            "AsyncDeleteItems_",
            "AsyncGenerateLootBoxes",
            "AsyncGenerateLootBoxes_",
            "AsyncGetInventoryGridItem",
            "AsyncGetInventoryGridItem_",
            "AsyncIncreaseStackAmount",
            "AsyncMoveEntityStacks",
            "AsyncMoveEntityStacks_",
            "AsyncMoveItemStacks",
            "AsyncOpenInventoryContainer",
            "AsyncQueryInventory",
            "AsyncQueryInventoryData",
            "AsyncQueryInventory_",
            "AsyncQueryOcclusionDataForOpenInventoryContainer",
            "AsyncSetOpenInventoryOcclusion",
            "AsyncSortGridItems",
            "AsyncSortGridItems_",
            "AsyncSplitItemStack",
            "AsyncSplitItemStack_",
            "AsyncStowEntity",
            "AsyncStowEntity_",
            "AsyncTransferEntityAggregates",
            "AsyncTransferEntityAggregates_",
            "AsyncUnstackEntities",
            "AsyncUnstackEntities_",
            "AsyncUnstowItems",
            "AsyncUnstowItems_",
            "CloseOpenInventory",
            "FillBestLootBox",
            "FindGridEntity",
            "IsItemTypePermissibleInInventory",
            "IterateThroughItemPortAndCloseOpenInventory",
            "MoveItemStacksForSnapshotInventory",
            "NotifyInventoryContainerUpdated",
            "PopulateUnstowParamsForRequest",
            "ProcessPendingInventoryContainerOpens",
            "ProcessPendingInventoryContainerOpens_",
            "ProcessPopulateEntriesHelper",
            "QueueMainThreadCallback",
            "QueueOpenInventoryContainer",
            "QueueOpenInventoryContainer_",
            "SpawnLootBox",
            "StowVehicleEntityAndCloseInventoryContainers",
            "TransferItemsForSnapshotInventory",
            "UnQueuePendingDependentRequest",
            "Update",
            "WithExistingInventories"
        ],
        CSCLocalPlayerPersonalThoughtComponent: [
            "AddInventoryManagementMove",
            "AddOrFindContainerInSection",
            "AddToFavorite",
            "AttachItem",
            "BuildChoicesForInventoryItem",
            "BuildChoicesForInventoryItem_",
            "BuildChoicesForItem",
            "CanPerformInputAction",
            "CheckForMoveAllButton",
            "CheckTryingToEquipClothingOnUndersuit",
            "CheckTryingToEquipSecondHelmet",
            "CloseCurrentQuickAccessSelectionContextualMenu",
            "CreateAddToFavoriteMenuCB",
            "CreateInventoryGridItemData",
            "CreateMenus",
            "CreateThought",
            "DebugDrawCurrentMenu",
            "DebugDrawOptionOnFocus",
            "DisplayInventory",
            "DisplayPlaceholderInventory",
            "DoSwapOutfitCB",
            "DropItemFromContainerImpl",
            "EnableInventoryCamera",
            "FixOrderItems",
            "ForceSelectDifferentContainerTab",
            "GetCapacitySortedCachedContainers",
            "GetChildDepth",
            "GetDataForCurrentMenu",
            "GetDataForFavoriteMenu",
            "GetDataForInventoryContainer",
            "GetDataForItemMenu",
            "GetEntityLootData",
            "GetFilteredCapacitySortedCachedContainers",
            "GetFilteredCapacitySortedCachedContainers_",
            "GetInventoryContents",
            "GetParentEntityForStoredItem",
            "GetQuickAccessMenuElements",
            "GetQuickSelectionWheelDefaultSelection",
            "GetQuickSelectionWheelDefaultSelectionEntity",
            "GetSelectedContainersTabIds",
            "HandleComponentEvent",
            "HandleComponentEvent_",
            "InitializePersonalInventory",
            "InsertTabGroupInventoryIfNeeded",
            "InternalGetDataForInventoryContainer",
            "IsBlockedByRule",
            "IsCategoryAvailable",
            "LoadSavedFavorites",
            "LootEntity",
            "ModifyNestedContainerUI",
            "ModifyNestedOccupancyOnParentItem",
            "OnActionInt",
            "OnChangeSectionTab",
            "OnChangeSectionTab_",
            "OnComponentUpdate_PreUpdate",
            "OnDragInventoryItemModifyTarget",
            "OnInventoryMoveOntoOccupiedGridPosition",
            "OnQuickAccessWheelAction",
            "OpenExternalInventory",
            "OpenFullInventoryScreen",
            "PopulateDataForGroupTabContainer",
            "PopulateDataForLootEntity",
            "PopulateInventoryGrid",
            "PopulateInventoryTabs",
            "PopulateProximityInventoryTabs",
            "PopulateTabsUIDataForInventorySection",
            "PopulateTestInventory",
            "PostRemoveInventorySelectionUpdate",
            "ProcessEvent",
            "ProcessProximityContainerRaycastResult",
            "ProcessProximityContainerRaycastResult__CSCLocalPlayerPersonalThoughtComponent",
            "QueueProximityRaycastCheck",
            "QuickAccessWheelData",
            "RefreshAvailablePorts",
            "RemoveFavorite",
            "RemoveInventoryContainerFromUI",
            "RemoveInventoryContainerFromUI_",
            "RemoveInventoryFromNavigation",
            "RemoveInventoryFromNavigation_",
            "RequestEquipItem",
            "RequestInternalState",
            "RequestInventoryData",
            "RequestUpdateInventoryGridGroupTabUI",
            "RevertInventoryMoves",
            "SetupBackOption",
            "SetupCategoryOptions",
            "SetupContextActionsMenu",
            "ShouldShowLocationInventory",
            "ShouldShowVehicleInventory",
            "SortGridItems",
            "SpawnLocalEntity",
            "SpawnSoftAttachItem",
            "StartCameraEffects",
            "StoreItem",
            "UpdateAccessToExternalInventories",
            "UpdateContainerItemsAddNewItem",
            "UpdateGroupTabs",
            "UpdateInventory",
            "UpdateInventoryDisplay",
            "UpdateInventoryGridUI",
            "UpdateInventoryNavigationUI",
            "UpdateInventorySections",
            "UpdateInventoryWeightUI"
        ]
    },
    inventoryRequestPath: {
        uiClickOpenContainer: {
            owner: "CSCLocalPlayerPersonalThoughtComponent",
            entry: "HandleComponentEvent(SCEvtControl_OnInventoryClickOpenContainer)",
            address: "0x1462ED6F0",
            next: "DoOpenNestedInventory"
        },
        buildOpenNestedRequest: {
            owner: "CSCLocalPlayerPersonalThoughtComponent",
            entry: "DoOpenNestedInventory",
            address: "0x1462C3F60",
            requestType: "OpenNestedInventory",
            requestTypeValue: 0x09,
            requestFields: [
                "sourceInventoryId",
                "sourceRank",
                "itemEntityId",
                "sourceClassId",
                "inventoryQuery"
            ]
        },
        backendQueue: {
            owner: "CSCPlayerInventory",
            entry: "RequestInventoryManagementOperation",
            address: "0x1445DFE70",
            queueField: "inventoryManagementQueue @ +0x58"
        },
        dispatch: {
            owner: "CSCPlayerInventory",
            entry: "ProcessRequest",
            address: "0x1445B56A0",
            queryEntry: "QueryInventoryInternal @ 0x1445BA6C0",
            storedItemEntry: "ProcessRequestStoredItemInventory @ 0x1445B5FF0"
        },
        containerManager: {
            owner: "CInventoryContainerManager",
            gridItemResolverSlot: 12,
            queueOpenInventoryContainerSlot: 26,
            entries: {
                queueOpenInventoryContainer: "0x1445BB060",
                asyncOpenInventoryContainer: "0x1444A5240",
                asyncQueryInventory: "0x1444A5E50",
                processPendingInventoryContainerOpens: "0x1445B3C50"
            }
        }
    },
    cInventoryContainerManagerOffsets: {
        callbackQueue: 0x08,
        lockedRequests: 0x40,
        currentRequestId: 0x78,
        config: 0x80,
        inventoryConfig: 0x88,
        pendingDataRequests: 0x90,
        lastPendingRequestId: 0xA0,
        pendingDataRequestsLock: 0xA8,
        pendingInventoryOpenRequests: 0xC8,
        currentOpenRequest: 0x108,
        openRequestPending: 0x110,
        closedInventoryNonStorableItemTypes: 0x118
    },
    sInventoryContainerGridItemOffsets: {
        itemGEID: 0x00,
        legalOwnerGEID: 0x08,
        classGUID: 0x10,
        rank: 0x20,
        amount: 0x28,
        occupancy: 0x30,
        ownershipTimeStamp: 0x40,
        ownershipStatus: 0x48
    },
    sGridItemRequestOffsets: {
        classGUID: 0x00,
        rank: 0x10
    },
    sInventoryContainerManagerEntryOffsets: {
        itemGEID: 0x00,
        ownerGEID: 0x08,
        classGUID: 0x10,
        ownershipTimeStamp: 0x20,
        ownershipStatus: 0x28,
        gridAmount: 0x2C,
        rank: 0x30,
        itemDimensions: 0x38,
        occupancy: 0x48,
        hasChildren: 0x58,
        gamePersistentData: 0x60,
        children: 0x68,
        resources: 0x80
    },
    sInventoryContainerManagerDataOffsets: {
        classGUID: 0x00,
        occupancy: 0x10,
        capacity: 0x20,
        dimensions: 0x30,
        entries: 0x40,
        pageInfo: 0x58,
        valid: 0x70
    },
    sInventoryContainerFilterCacheKeyOffsets: {
        filteredTypes: 0x00,
        excludedTypes: 0x10
    },
    sInventoryContainerManagerEntriesCacheOffsets: {
        entries: 0x00,
        pageInfo: 0x18
    },
    sInventoryContainerManagerDataCacheOffsets: {
        managerData: 0x00,
        filteredEntries: 0x78
    },
    sInventoryContainerManagerDataCachePairOffsets: {
        inventoryId: 0x00,
        dataCache: 0x18
    },
    cInventoryQueryPendingRequestOffsets: {
        pendingRequests: 0x00,
        results: 0x18,
        callback: 0x30
    },
    cInventoryOpenPendingRequestOffsets: {
        inventoryId: 0x00,
        requestId: 0x18,
        unstowParams: 0x20,
        gridItems: 0x38,
        callback: 0x50,
        timestamp: 0x68,
        currentUnstowRange: 0x70,
        numRetries: 0x80
    },
    cInventoryContainerManagerAsyncQueryInventoryDataSQueryEntryOffsets: {
        inventoryId: 0x00,
        query: 0x18,
        dependentRequestId: 0xC8
    },
    cInventoryContainerManagerAsyncStowEntitySAsyncStowSharedDataOffsets: {
        lockSessionSharedPtr: 0x00,
        addedEntitiesVec: 0x10,
        startTimeStamp: 0x28
    },
    cInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfoOffsets: {
        request: 0x00,
        requestIds: 0x30
    },
    sPersonalInventoryReceivedDataOffsets: {
        inventoryId: 0x00,
        inventoryRequestId: 0x18,
        parentInventoryId: 0x20,
        type: 0x38,
        data: 0x40,
        itemTypes: 0xB8,
        excludedItemTypes: 0xC8,
        recordResultToCache: 0xD8,
        success: 0xD9
    },
    sPersonalInventoryDataOffsets: {
        occupancy: 0x00,
        capacity: 0x10,
        dimensions: 0x20,
        entries: 0x30
    },
    cInventoryContainerComponentOffsets: {
        userToken: 0x48,
        inventoryUser: 0x58,
        previousInventoryUser: 0x68,
        userRequestLock: 0x70,
        userRequestId: 0x90,
        userRequestCallback: 0x98,
        containerOccupancy: 0xB0,
        spawnedPopulateLoot: 0xC8,
        snapshotInventoryLock: 0xE8,
        snapshotInventoryGridItems: 0x110,
        lootGenerationRequest: 0x130,
        packingPlan: 0x150,
        containerFreeSpaces: 0x170,
        hasInitialized: 0x190,
        inventoryCreated: 0x1A0,
        interactionLock: 0x1B0,
        containerOpen: 0x1C0,
        cargoGridLocks: 0x1D0,
        eventListeners: 0x228,
        firstAuthorityChangeHasQueueOpening: 0x268,
        openInteractionName: 0x270,
        openLootingInteractionName: 0x288,
        openAttachmentOcclusionDebug: 0x2A0,
        legacyEventSystem: 0x330
    },
    cInventoryContainerComponentVtable: {
        dtorIComponent: 0,
        isCompatible: 1,
        moveToZone: 2,
        export: 3,
        getSubSystem: 4,
        processEvent: 5,
        getEventSubscriptions: 6,
        getStreamingAndUpdateRadius: 7,
        getLegacyEventSystem: 8,
        ...sequentialSlots("registerUpdate", 64, 9),
        ...sequentialSlots("registerEventHandler", 128, 73),
        registerDebugUpdate: 201,
        getDefaultEventUpdatePass: 202,
        needLegacyEventHandler: 203,
        unregisterFromExternalSystems: 204,
        done: 205,
        setOnPropertyChangedCallbacks: 206,
        listenToAggregateRootChange: 207,
        onAggregateRootChanged: 208,
        getProfileMarkerRWES: 209,
        getProfileMarkerUFES: 210,
        getProfileMarkerDONE: 211,
        getProfileMarkerUnregister: 212,
        getProfileMarkerInitialize: 213,
        getProfileMarkerPostInitialize: 214,
        getProfileMarkerSpawnBatchComplete: 215,
        initialize: 216,
        postInitialize: 217,
        spawnBatchComplete: 218,
        registerWithExternalSystems: 219,
        shutdown: 220,
        registerEventListener: 221,
        unregisterEventListener: 222,
        setInventoryContents: 223,
        getInventoryParamsRecordGuid: 224,
        getCapacity: 225,
        getOccupancy: 226,
        getDimensions: 227,
        getExcludedItemTypes: 228,
        isItemTypeAllowed: 229,
        isOpen: 230,
        isOpenInventoryType: 231,
        addTractorBeamInteractionLock: 232,
        removeTractorBeamInteractionLock: 233,
        tbInteractionAllowed: 234,
        tryComputePackingPlanForOpenCargo: 235,
        getCurrentPackingPlan: 236,
        deleteItemsFromSnapshotInventory: 237,
        getContainerManagerDataForSnapshotInventory: 238,
        withExistingInventories: 239,
        detachAndRepackFromOpenInventory: 240
    },
    icigServicesExternalVtable: {
        getInventoryApi: 12
    },
    iInventoryApiVtable: {
        dtorIInventoryApi: 0,
        asyncQueryInventory: 1,
        asyncQueryInventoryAutoPagination: 2,
        asyncQueryEntities: 3,
        asyncQueryEntitiesDeprecated: 4,
        asyncGetSnapshots: 5,
        asyncGetSnapshotVariables: 6,
        asyncSetSnapshotVariables: 7,
        stowEntityAggregate: 8,
        stowEntityAggregate2: 9,
        unstowEntityAggregateDeprecated: 10,
        unstowEntityAggregate: 11,
        unstowEntityFromStack: 12,
        setEntityAggregateRank: 13,
        asyncMoveEntities: 14,
        asyncMoveAll: 15,
        asyncMoveEntityStacks: 16,
        asyncIncreaseEntityStacks: 17,
        asyncDecreaseEntityStacks: 18,
        asyncSetEntityStacks: 19,
        asyncTransferEntityAggregate: 20,
        asyncCreateEntitiesToInventory: 21,
        asyncDestroyEntities: 22,
        asyncMelt: 23,
        asyncBatchMoveAll: 24,
        getInventoryManagementApi: 25,
        getItemPortModificationApi: 26,
        forceStowEntityAggregate: 27
    },
    iInventoryManagementApiVtable: {
        dtorIInventoryManagementApi: 0,
        queryInventoryListDeprecated: 1,
        queryInventoryConfiguration: 2,
        updateInventoryConfiguration: 3,
        createInventory: 4,
        destroyInventory: 5,
        withExistingInventory: 6
    },
    iItemPortModificationApiVtable: {
        attachToStowedEntities: 0,
        detachStowedEntities: 1,
        modifyItemPorts: 2
    },
    cGameVtable: {
        getInventoryContainerManager: 57
    },
    iPlatformInventoryManagerVtable: {
        dtorIPlatformInventoryManager: 0,
        isLongTermPersistenceWhiteListedItemForAddDeprecated: 1,
        isLongTermPersistenceWhiteListedItemForUpdate: 2
    },
    iPlayerInventoryManagerVtable: {
        dtorIPlayerInventoryManager: 0,
        asyncGetPersonalLocationInventoryId: 1,
        asyncGetOrCreatePersonalEntityInventoryId: 2,
        asyncGetPersonalEntityInventoryId: 3,
        getPersonalLocationInventoryDataFromCache: 4,
        getLocationIdFromPersonalInventoryId: 5
    },
    iscActorInventoryVtable: {
        getAvailableThrowables: 0
    },
    iInventoryContainerManagerVtable: {
        dtorIInventoryContainerManager: 0,
        asyncStowEntity: 1,
        asyncStowEntity2: 2,
        asyncStowEntity3: 3,
        asyncQueryInventory: 4,
        asyncQueryInventoryData: 5,
        asyncMoveEntityStacks: 6,
        asyncMoveEntityStacks2: 7,
        asyncMoveItemStacks: 8,
        asyncMoveItemStacks2: 9,
        asyncTransferEntityAggregates: 10,
        asyncTransferItems: 11,
        asyncGetInventoryGridItem: 12,
        asyncSortGridItems: 13,
        asyncUnstackEntities: 14,
        asyncSplitItemStack: 15,
        asyncUnstowItems: 16,
        asyncCanStoreEntities: 17,
        asyncIncreaseStackAmount: 18,
        asyncDecreaseStackAmount: 19,
        asyncCreateItem: 20,
        asyncCreateItems: 21,
        asyncCreateItems2: 22,
        asyncGenerateLootBoxes: 23,
        asyncDeleteItemsIf: 24,
        asyncDeleteItems: 25,
        queueOpenInventoryContainer: 26,
        stowVehicleEntityAndCloseInventoryContainers: 27,
        iterateThroughItemPortAndCloseOpenInventory: 28,
        closeOpenInventory: 29,
        asyncQueryOcclusionDataForOpenInventoryContainer: 30,
        asyncSetOpenInventoryOcclusion: 31,
        attachEntityToOpenInventoryContainer: 32,
        detachEntityFromOpenInventoryContainer: 33,
        asyncAmmoRepoolInventory: 34,
        withExistingInventories: 35,
        cancelCallback: 36,
        getEntireInventoryQuery: 37,
        isUserStowValid: 38,
        isItemTypePermissibleInInventory: 39,
        getBlockedClosedInventoryItems: 40,
        getItemTypeOpenInventoryOccupantProperties: 41,
        getDefaultOpenInventoryOccupantProperties: 42,
        notifyInventoryContainerUpdated: 43
    },
    notes: [
        "Inventory service methods are recorded as vtable slots only. This script does not call move/stow/delete/open inventory methods.",
        "Container UI requests flow through SInventoryManagementRequest and CSCPlayerInventory before reaching CInventoryContainerManager."
    ]
});

class SInventoryId {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get holderId() {
        return readEntityId(this.ptr);
    }

    get context() {
        return this.ptr.add(0x08).readS32();
    }

    get subject() {
        return this.ptr.add(0x10).readU64().toString();
    }

    toObject() {
        return {
            holderId: this.holderId,
            context: this.context,
            subject: this.subject
        };
    }
}

class SInventoryEntity {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get entityId() {
        return readEntityId(this.ptr.add(0x18));
    }

    toObject() {
        return {
            inventoryId: this.inventoryId.toObject(),
            entityId: this.entityId
        };
    }
}

class SInventoryConfiguration {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get id() {
        return new SInventoryId(this.ptr);
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x18));
    }

    get typeRaw() {
        return {
            ptr: this.ptr.add(0x20),
            rawSize: "0xc",
            which: this.ptr.add(0x28).readU8()
        };
    }

    toObject() {
        return {
            id: this.id.toObject(),
            ownerId: this.ownerId,
            typeRaw: {
                ptr: this.typeRaw.ptr.toString(),
                rawSize: this.typeRaw.rawSize,
                which: this.typeRaw.which
            }
        };
    }
}

class SVec3Def {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get value() {
        return readVec3f(this.ptr.add(0x08));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            value: this.value
        };
    }
}

class CigVariantI64DoubleCryGuidEntityIdCryString {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get which() {
        return this.ptr.add(0x10).readU8();
    }

    get storageHex() {
        return bytesToHex(this.ptr, 0x10);
    }

    toObject() {
        return {
            which: this.which,
            storageHex: this.storageHex
        };
    }
}

class CSCURN {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get metaData() {
        return {
            domain: this.ptr.readU8(),
            entityTag: this.ptr.add(0x01).readU8()
        };
    }

    get valueType() {
        return this.ptr.add(0x08).readU8();
    }

    get value() {
        return new CigVariantI64DoubleCryGuidEntityIdCryString(this.ptr.add(0x10));
    }

    toObject() {
        return {
            metaData: this.metaData,
            valueType: this.valueType,
            value: this.value.toObject()
        };
    }
}

class SInventoryContainerDef {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get itemDimensions() {
        return new SVec3Def(this.ptr.add(0x08));
    }

    get inventoryTypePtr() {
        return this.ptr.add(0x20).readPointer();
    }

    get excludedItemSubTypes() {
        return {
            ptr: this.ptr.add(0x28),
            type: "DataCoreArray<SInventoryContainerItemTypeFilter>",
            size: "0x10"
        };
    }

    get capacity() {
        return this.ptr.add(0x38).readS64().toString();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            itemDimensions: this.itemDimensions.toObject(),
            inventoryTypePtr: this.inventoryTypePtr.toString(),
            excludedItemSubTypes: {
                ptr: this.excludedItemSubTypes.ptr.toString(),
                type: this.excludedItemSubTypes.type,
                size: this.excludedItemSubTypes.size
            },
            capacity: this.capacity
        };
    }
}

class SInventoryContainerTypeBaseDef {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString()
        };
    }
}

class SInventoryContainerGridCellSizeBase extends SInventoryContainerTypeBaseDef {
    constructor(ptrValue) {
        super(ptrValue);
    }
}

class SInventoryContainerGridCellSizeCentimeters extends SInventoryContainerGridCellSizeBase {
    get centimeters() {
        return this.ptr.add(0x08).readS32();
    }

    toObject() {
        return {
            ...super.toObject(),
            centimeters: this.centimeters
        };
    }
}

class SInventoryContainerGridCellSizeMeters extends SInventoryContainerGridCellSizeBase {
    get meters() {
        return this.ptr.add(0x08).readS32();
    }

    toObject() {
        return {
            ...super.toObject(),
            meters: this.meters
        };
    }
}

class SInventoryContainerItemTypeFilter {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get itemType() {
        return this.ptr.add(0x08).readS32();
    }

    get itemSubTypes() {
        return new DataCoreArrayBase(this.ptr.add(0x10), "EItemSubType");
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            itemType: this.itemType,
            itemSubTypes: this.itemSubTypes.toObject()
        };
    }
}

class SInventoryOpenContainerTypeDef extends SInventoryContainerTypeBaseDef {
    get gridCellSize() {
        return dataCoreOptionalInfo(this.ptr.add(0x08), "SInventoryContainerGridCellSizeBase");
    }

    get minPermittedItemSize() {
        return new SVec3Def(this.ptr.add(0x10));
    }

    get maxPermittedItemSize() {
        return new SVec3Def(this.ptr.add(0x28));
    }

    get isExternalContainer() {
        return this.ptr.add(0x40).readU8() !== 0;
    }

    get gridPosOffset() {
        return new SVec3Def(this.ptr.add(0x48));
    }

    get maxPercentageErasedOnParentDestruction() {
        return this.ptr.add(0x60).readS32();
    }

    get randomDestructionDistributionExponent() {
        return this.ptr.add(0x64).readFloat();
    }

    get appliedForceOnParentDestruction() {
        return this.ptr.add(0x68).readFloat();
    }

    get overrideStorableItemTypes() {
        return new DataCoreArrayBase(this.ptr.add(0x70), "SInventoryContainerItemTypeFilter");
    }

    toObject() {
        return {
            ...super.toObject(),
            gridCellSize: this.gridCellSize,
            minPermittedItemSize: this.minPermittedItemSize.toObject(),
            maxPermittedItemSize: this.maxPermittedItemSize.toObject(),
            isExternalContainer: this.isExternalContainer,
            gridPosOffset: this.gridPosOffset.toObject(),
            maxPercentageErasedOnParentDestruction: this.maxPercentageErasedOnParentDestruction,
            randomDestructionDistributionExponent: this.randomDestructionDistributionExponent,
            appliedForceOnParentDestruction: this.appliedForceOnParentDestruction,
            overrideStorableItemTypes: this.overrideStorableItemTypes.toObject()
        };
    }
}

class SInventoryOpenAlwaysContainerTypeDef extends SInventoryOpenContainerTypeDef {
    constructor(ptrValue) {
        super(ptrValue);
    }
}

class SInventoryClosedContainerTypeDef extends SInventoryContainerTypeBaseDef {
    get capacity() {
        return dataCoreOptionalInfo(this.ptr.add(0x08), "SBaseCargoUnit");
    }

    toObject() {
        return {
            ...super.toObject(),
            capacity: this.capacity
        };
    }
}

class SInventoryParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get capacity() {
        return dataCoreOptionalInfo(this.ptr.add(0x18), "SBaseCargoUnit");
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            capacity: this.capacity
        };
    }
}

class SInventoryGamePersistentData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            json: typedMemberInfo(this.ptr, "CSerializedJson", 0xC0),
            writer: typedMemberInfo(this.ptr.add(0xC0), "CSerializedJsonWriter", 0x10),
            reader: typedMemberInfo(this.ptr.add(0xD0), "CSerializedJsonReader", 0x10),
            counts: this.ptr.add(0xE0).readU64().toString()
        };
    }
}

class SInventoryItemMapEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            entityId: readEntityId(this.ptr),
            stackCount: this.ptr.add(0x08).readS32(),
            missionId: readCryGuid(this.ptr.add(0x10)),
            classGUID: readCryGuid(this.ptr.add(0x20))
        };
    }
}

class SInventoryContainerUIParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get nameIdentifier() {
        return new CLocIdentifier(this.ptr.add(0x08));
    }

    get tags() {
        return new DCString(this.ptr.add(0x10));
    }

    get itemCategory() {
        return new SItemCategory(this.ptr.add(0x18));
    }

    get nameLoc() {
        return readCLocString(this.ptr.add(0x40));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            nameIdentifier: this.nameIdentifier.toObject(),
            tags: this.tags.toObject(),
            itemCategory: this.itemCategory.toObject(),
            nameLoc: this.nameLoc
        };
    }
}

class SInventorySortMode {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get name() {
        return new CLocIdentifier(this.ptr.add(0x08));
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            name: this.name.toObject()
        };
    }
}

class SInventoryDropDetachRules {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get category() {
        return new SItemCategory(this.ptr.add(0x08));
    }

    get dropDetachTypes() {
        return new DataCoreArrayBase(this.ptr.add(0x30), "SItemCategory");
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            category: this.category.toObject(),
            dropDetachTypes: this.dropDetachTypes.toObject()
        };
    }
}

class SInventoryStateModifier {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            openedState: dataCoreStructPtrInfo(this.ptr.add(0x08), "SInteractionState"),
            closedState: dataCoreStructPtrInfo(this.ptr.add(0x10), "SInteractionState")
        };
    }
}

class SStowPolicyCache {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            policy: typedMemberInfo(this.ptr, "SAutoStowPolicy", 0x28),
            index: this.ptr.add(0x28).readU16(),
            deferredWrite: this.ptr.add(0x2A).readU8() !== 0,
            crc: this.ptr.add(0x2C).readU32(),
            lastExpiryTime: this.ptr.add(0x30).readS64().toString()
        };
    }
}

class SCargoGridOccupantFace {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    get faceUpwardAllowed() {
        return this.ptr.add(0x08).readU8() !== 0;
    }

    get stackingSupport() {
        return this.ptr.add(0x0C).readS32();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            faceUpwardAllowed: this.faceUpwardAllowed,
            stackingSupport: this.stackingSupport
        };
    }
}

class SCargoGridOccupantProperties {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            top: new SCargoGridOccupantFace(this.ptr.add(0x08)).toObject(),
            bottom: new SCargoGridOccupantFace(this.ptr.add(0x18)).toObject(),
            front: new SCargoGridOccupantFace(this.ptr.add(0x28)).toObject(),
            back: new SCargoGridOccupantFace(this.ptr.add(0x38)).toObject(),
            right: new SCargoGridOccupantFace(this.ptr.add(0x48)).toObject(),
            left: new SCargoGridOccupantFace(this.ptr.add(0x58)).toObject()
        };
    }
}

class SOpenInventoryOccupantItemTypeProperties {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            itemType: this.ptr.add(0x08).readS32(),
            defaultProperties: new SCargoGridOccupantProperties(this.ptr.add(0x10)).toObject()
        };
    }
}

class SInventoryContainerManagerDef {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            lootBoxes: new DataCoreArrayBase(this.ptr.add(0x08), "DataCoreRecordRef<SCEntityClass>").toObject(),
            spawnLootGridDimensions: new SVec3Def(this.ptr.add(0x18)).toObject(),
            closedInventoryNonStorableItemTypes: new DataCoreArrayBase(this.ptr.add(0x30), "SInventoryContainerItemTypeFilter").toObject(),
            closedInventoryNonStorableOutfitItemTypes: new DataCoreArrayBase(this.ptr.add(0x40), "EItemType").toObject(),
            openInventoryNonStorableItemTypes: new DataCoreArrayBase(this.ptr.add(0x50), "SInventoryContainerItemTypeFilter").toObject(),
            itemTypeOpenInventoryOccupantProperties: new DataCoreArrayBase(this.ptr.add(0x60), "SOpenInventoryOccupantItemTypeProperties").toObject(),
            defaultOpenInventoryOccupantProperties: new SCargoGridOccupantProperties(this.ptr.add(0x70)).toObject(),
            smallItemDropDist: this.ptr.add(0xD8).readFloat(),
            bigItemDropDist: this.ptr.add(0xDC).readFloat(),
            bigItemVolumeThresholdSCU: this.ptr.add(0xE0).readFloat(),
            dropItemMaxHeight: this.ptr.add(0xE4).readFloat(),
            dropItemSurfaceOffset: this.ptr.add(0xE8).readFloat(),
            dropItemRetryOffset: this.ptr.add(0xEC).readFloat(),
            numberOfRetries: this.ptr.add(0xF0).readS32()
        };
    }
}

class SInventoryItemTypes {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get blockedItemTypesMap() {
        return {
            ptr: this.ptr,
            type: "eastl::map<EItemType,std::vector<EItemSubType>>",
            size: "0x30"
        };
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            blockedItemTypesMap: {
                ptr: this.blockedItemTypesMap.ptr.toString(),
                type: this.blockedItemTypesMap.type,
                size: this.blockedItemTypesMap.size
            }
        };
    }
}

class EastlOptionalInventoryConfiguration {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get value() {
        return new SInventoryConfiguration(this.ptr);
    }

    get engaged() {
        return this.ptr.add(0x30).readU8() !== 0;
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            engaged: this.engaged,
            value: this.engaged ? this.value.toObject() : null
        };
    }
}

class CTagList {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get handle() {
        return this.ptr.readU32();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            handle: this.handle
        };
    }
}

class SEntityLocationInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get locationId() {
        return this.ptr.add(0x08).readU32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            locationId: this.locationId
        };
    }
}

class STraceId {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    readHex(offset, length) {
        const bytes = this.ptr.add(offset).readByteArray(length);
        return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, "0")).join("");
    }

    get traceId() {
        return this.readHex(0x00, 16);
    }

    get traceParentId() {
        return this.readHex(0x10, 16);
    }

    get spanId() {
        return this.readHex(0x20, 8);
    }

    get parentSpanId() {
        return this.readHex(0x28, 8);
    }

    get prevTracestate() {
        return readCString(this.ptr.add(0x30));
    }

    toObject() {
        return {
            traceId: this.traceId,
            traceParentId: this.traceParentId,
            spanId: this.spanId,
            parentSpanId: this.parentSpanId,
            prevTracestate: this.prevTracestate
        };
    }
}

class SCargoAmount {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get microCargoUnits() {
        return this.ptr.add(0x08).readS64().toString();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            microCargoUnits: this.microCargoUnits
        };
    }
}

class SPaginationArguments {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get first() {
        return this.ptr.readS32();
    }

    get after() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    get last() {
        return this.ptr.add(0x10).readS32();
    }

    get before() {
        return readCryStringHandle(this.ptr.add(0x18));
    }

    toObject() {
        return {
            first: this.first,
            after: this.after,
            last: this.last,
            before: this.before
        };
    }
}

class SPaginationInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get hasNextPage() {
        return this.ptr.readU8() !== 0;
    }

    get hasPreviousPage() {
        return this.ptr.add(0x01).readU8() !== 0;
    }

    get startCursor() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    get endCursor() {
        return readCryStringHandle(this.ptr.add(0x10));
    }

    toObject() {
        return {
            hasNextPage: this.hasNextPage,
            hasPreviousPage: this.hasPreviousPage,
            startCursor: this.startCursor,
            endCursor: this.endCursor
        };
    }
}

class SInventoryEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            entityId: readEntityId(this.ptr),
            rank: readCryStringHandle(this.ptr.add(0x08))
        };
    }
}

class SGridBox {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get min() {
        return readVec3u64(this.ptr);
    }

    get max() {
        return readVec3u64(this.ptr.add(0x18));
    }

    toObject() {
        return {
            min: this.min,
            max: this.max
        };
    }
}

class SLootRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get gridItems() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SInventoryContainerGridItem, SInventoryContainerGridItem);
    }

    toObject(includeGridItems = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            gridItems: includeGridItems ? this.gridItems.toArray(64).map(item => item.toObject()) : this.gridItems.toSummary()
        };
    }
}

class SInventoryContainerItemGenerationRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get items() {
        return new StdVector(this.ptr, 0x10);
    }

    toObject() {
        return {
            items: this.items.toSummary()
        };
    }
}

class ContainerPackingSFreeSpace {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get gridBox() {
        return new SGridBox(this.ptr);
    }

    get selfStackClass() {
        return this.ptr.add(0x30).readPointer();
    }

    toObject() {
        return {
            gridBox: this.gridBox.toObject(),
            selfStackClass: this.selfStackClass.toString()
        };
    }
}

class OBBd {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get matrix33() {
        const values = [];
        for (let i = 0; i < 9; i++) {
            values.push(this.ptr.add(i * 0x08).readDouble());
        }
        return values;
    }

    get halfExtents() {
        return readVec3d(this.ptr.add(0x48));
    }

    get center() {
        return readVec3d(this.ptr.add(0x60));
    }

    toObject() {
        return {
            matrix33: this.matrix33,
            halfExtents: this.halfExtents,
            center: this.center
        };
    }
}

class ContainerPackingSItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get creationRequest() {
        return new SCreateEntityToInventoryRequest(this.ptr);
    }

    get entityClassPtr() {
        return this.ptr.add(0x90).readPointer();
    }

    get entityId() {
        return readEntityId(this.ptr.add(0x98));
    }

    get gridBox() {
        return new SGridBox(this.ptr.add(0xA0));
    }

    get orientation() {
        return this.ptr.add(0xD0).readU8();
    }

    get upwardFace() {
        return this.ptr.add(0xD1).readU8();
    }

    get supportedFaceUpFlags() {
        return this.ptr.add(0xD2).readU8();
    }

    get stackingSupportFlagsPerFace() {
        return this.ptr.add(0xD4).readU32();
    }

    get resourceValueMap() {
        return eastlMapInfo(this.ptr.add(0xD8));
    }

    toObject(includeCreationRequest = false) {
        return {
            creationRequest: includeCreationRequest ? this.creationRequest.toObject() : { ptr: this.creationRequest.ptr.toString() },
            entityClassPtr: this.entityClassPtr.toString(),
            entityId: this.entityId,
            gridBox: this.gridBox.toObject(),
            orientation: this.orientation,
            upwardFace: this.upwardFace,
            supportedFaceUpFlags: this.supportedFaceUpFlags,
            stackingSupportFlagsPerFace: this.stackingSupportFlagsPerFace,
            resourceValueMap: this.resourceValueMap
        };
    }
}

class ContainerPackingSContainer {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get availableFreeSpaces() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.ContainerPacking_SFreeSpace, ContainerPackingSFreeSpace);
    }

    get erasedFreeSpace() {
        return this.ptr.add(0x18).readU64().toString();
    }

    get items() {
        return new StdVector(this.ptr.add(0x20), InventoryManagementSurface.sizes.ContainerPacking_SItem, ContainerPackingSItem);
    }

    get occlusions() {
        return new StdVector(this.ptr.add(0x38), InventoryManagementSurface.sizes.SGridBox, SGridBox);
    }

    get size() {
        return readVec3u64(this.ptr.add(0x50));
    }

    get currentOccupancyVolumeQCU() {
        return this.ptr.add(0x68).readU64().toString();
    }

    get capacityVolumeQCU() {
        return this.ptr.add(0x70).readU64().toString();
    }

    get containerClass() {
        return this.ptr.add(0x78).readPointer();
    }

    get containerId() {
        return readEntityId(this.ptr.add(0x80));
    }

    get numEntriesBeforePacking() {
        return this.ptr.add(0x88).readU64().toString();
    }

    get cellSizeCm() {
        return this.ptr.add(0x90).readU16();
    }

    get largestBoxDimensionFit() {
        return readVec3u64(this.ptr.add(0x98));
    }

    toObject(includeNested = false) {
        return {
            availableFreeSpaces: includeNested ? this.availableFreeSpaces.toArray(64).map(space => space.toObject()) : this.availableFreeSpaces.toSummary(),
            erasedFreeSpace: this.erasedFreeSpace,
            items: includeNested ? this.items.toArray(64).map(item => item.toObject(false)) : this.items.toSummary(),
            occlusions: includeNested ? this.occlusions.toArray(64).map(box => box.toObject()) : this.occlusions.toSummary(),
            size: this.size,
            currentOccupancyVolumeQCU: this.currentOccupancyVolumeQCU,
            capacityVolumeQCU: this.capacityVolumeQCU,
            containerClass: this.containerClass.toString(),
            containerId: this.containerId,
            numEntriesBeforePacking: this.numEntriesBeforePacking,
            cellSizeCm: this.cellSizeCm,
            largestBoxDimensionFit: this.largestBoxDimensionFit
        };
    }
}

class ContainerPackingSPackingPlan {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get containers() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.ContainerPacking_SContainer, ContainerPackingSContainer);
    }

    get initState() {
        return this.ptr.add(0x18).readU8();
    }

    toObject(includeNested = false) {
        return {
            containers: includeNested ? this.containers.toArray(64).map(container => container.toObject(includeNested)) : this.containers.toSummary(),
            initState: this.initState
        };
    }
}

class SSerializeableFreeSpace {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get gridBox() {
        return new SGridBox(this.ptr);
    }

    get selfStackClassGUID() {
        return readCryGuid(this.ptr.add(0x30));
    }

    toObject() {
        return {
            gridBox: this.gridBox.toObject(),
            selfStackClassGUID: this.selfStackClassGUID
        };
    }
}

class SInventoryContainerGridItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get legalOwnerGEID() {
        return readEntityId(this.ptr.add(0x08));
    }

    get classGUID() {
        return readCryGuid(this.ptr.add(0x10));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x20));
    }

    get amount() {
        return this.ptr.add(0x28).readS32();
    }

    get occupancy() {
        return new SCargoAmount(this.ptr.add(0x30));
    }

    get ownershipTimeStamp() {
        return this.ptr.add(0x40).readS64().toString();
    }

    get ownershipStatus() {
        return this.ptr.add(0x48).readS8();
    }

    toObject() {
        return {
            itemGEID: this.itemGEID,
            legalOwnerGEID: this.legalOwnerGEID,
            classGUID: this.classGUID,
            rank: this.rank,
            amount: this.amount,
            occupancy: this.occupancy.toObject(),
            ownershipTimeStamp: this.ownershipTimeStamp,
            ownershipStatus: this.ownershipStatus
        };
    }
}

class SGridItemRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get classGUID() {
        return readCryGuid(this.ptr);
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x10));
    }

    toObject() {
        return {
            classGUID: this.classGUID,
            rank: this.rank
        };
    }
}

class SInventoryContainerManagerEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get children() {
        return new StdVector(this.ptr.add(0x68), InventoryManagementSurface.sizes.SInventoryContainerManagerEntry, SInventoryContainerManagerEntry);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get ownerGEID() {
        return readEntityId(this.ptr.add(0x08));
    }

    get classGUID() {
        return readCryGuid(this.ptr.add(0x10));
    }

    get ownershipTimeStamp() {
        return this.ptr.add(0x20).readS64().toString();
    }

    get ownershipStatus() {
        return this.ptr.add(0x28).readS8();
    }

    get gridAmount() {
        return this.ptr.add(0x2C).readS32();
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x30));
    }

    get itemDimensions() {
        return readVec3f(this.ptr.add(0x38));
    }

    get occupancy() {
        return new SCargoAmount(this.ptr.add(0x48));
    }

    get hasChildren() {
        return this.ptr.add(0x58).readU8() !== 0;
    }

    get gamePersistentData() {
        return readCryStringHandle(this.ptr.add(0x60));
    }

    get resourcesSharedPtr() {
        return {
            ptr: this.ptr.add(0x80).readPointer(),
            rep: this.ptr.add(0x88).readPointer()
        };
    }

    toObject(includeChildren = false) {
        const resources = this.resourcesSharedPtr;
        return {
            itemGEID: this.itemGEID,
            ownerGEID: this.ownerGEID,
            classGUID: this.classGUID,
            ownershipTimeStamp: this.ownershipTimeStamp,
            ownershipStatus: this.ownershipStatus,
            gridAmount: this.gridAmount,
            rank: this.rank,
            itemDimensions: this.itemDimensions,
            occupancy: this.occupancy.toObject(),
            hasChildren: this.hasChildren,
            gamePersistentData: this.gamePersistentData,
            children: includeChildren ? this.children.toArray(16).map(child => child.toObject(false)) : this.children.toSummary(),
            resourcesSharedPtr: {
                ptr: resources.ptr.toString(),
                rep: resources.rep.toString()
            }
        };
    }
}

class SInventoryContainerManagerData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entries() {
        return new StdVector(this.ptr.add(0x40), InventoryManagementSurface.sizes.SInventoryContainerManagerEntry, SInventoryContainerManagerEntry);
    }

    get classGUID() {
        return readCryGuid(this.ptr);
    }

    get occupancy() {
        return new SCargoAmount(this.ptr.add(0x10));
    }

    get capacity() {
        return new SCargoAmount(this.ptr.add(0x20));
    }

    get dimensions() {
        return readVec3f(this.ptr.add(0x30));
    }

    get pageInfo() {
        return new SPaginationInfo(this.ptr.add(0x58));
    }

    get valid() {
        return this.ptr.add(0x70).readU8() !== 0;
    }

    toObject(includeEntries = false) {
        return {
            classGUID: this.classGUID,
            occupancy: this.occupancy.toObject(),
            capacity: this.capacity.toObject(),
            dimensions: this.dimensions,
            entries: includeEntries ? this.entries.toArray(32).map(entry => entry.toObject(false)) : this.entries.toSummary(),
            pageInfo: this.pageInfo.toObject(),
            valid: this.valid
        };
    }
}

class SInventoryUpdateContext {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get associatedEntityType() {
        return this.ptr.readS8();
    }

    get associatedEntityId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get associatedInventoryId() {
        return new SInventoryId(this.ptr.add(0x10));
    }

    toObject() {
        return {
            associatedEntityType: this.associatedEntityType,
            associatedEntityId: this.associatedEntityId,
            associatedInventoryId: this.associatedInventoryId.toObject()
        };
    }
}

class SInventoryUpdateItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get classGUID() {
        return readCryGuid(this.ptr.add(0x08));
    }

    get amount() {
        return this.ptr.add(0x18).readS32();
    }

    get legalOwnerGEID() {
        return readEntityId(this.ptr.add(0x20));
    }

    get singleItemOccupancy() {
        return new SCargoAmount(this.ptr.add(0x28));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x38));
    }

    get context() {
        return new SInventoryUpdateContext(this.ptr.add(0x40));
    }

    toObject() {
        return {
            itemGEID: this.itemGEID,
            classGUID: this.classGUID,
            amount: this.amount,
            legalOwnerGEID: this.legalOwnerGEID,
            singleItemOccupancy: this.singleItemOccupancy.toObject(),
            rank: this.rank,
            context: this.context.toObject()
        };
    }
}

class SStowContext {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get entitlementUrn() {
        return new CSCURN(this.ptr.add(0x08));
    }

    get classPtr() {
        return this.ptr.add(0x30).readPointer();
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x38));
    }

    get isStowed() {
        return this.ptr.add(0x40).readU8() !== 0;
    }

    get inventoryId() {
        return new SInventoryId(this.ptr.add(0x48));
    }

    get shardId() {
        return readCryStringHandle(this.ptr.add(0x60));
    }

    toObject() {
        return {
            entityId: this.entityId,
            entitlementUrn: this.entitlementUrn.toObject(),
            classPtr: this.classPtr.toString(),
            ownerId: this.ownerId,
            isStowed: this.isStowed,
            inventoryId: this.inventoryId.toObject(),
            shardId: this.shardId
        };
    }
}

class SItemPortId {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get owner() {
        return readEntityId(this.ptr);
    }

    get id() {
        return this.ptr.add(0x08).readU16();
    }

    toObject() {
        return {
            owner: this.owner,
            id: this.id
        };
    }
}

class SInventoryManagementRequestClassItemRank {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get sourceClassId() {
        return this.ptr.readU32();
    }

    get sourceRank() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    toObject() {
        return {
            sourceClassId: this.sourceClassId,
            sourceRank: this.sourceRank
        };
    }
}

class SInventoryContainerEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get classGUID() {
        return readCryGuid(this.ptr.add(0x08));
    }

    get itemClassName() {
        return readCryStringHandle(this.ptr.add(0x18));
    }

    get gridAmount() {
        return this.ptr.add(0x20).readS32();
    }

    get ammoCount() {
        return this.ptr.add(0x24).readS32();
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x28));
    }

    get occupancy() {
        return new SCargoAmount(this.ptr.add(0x30));
    }

    get hasChildren() {
        return this.ptr.add(0x40).readU8() !== 0;
    }

    toObject() {
        return {
            itemGEID: this.itemGEID,
            classGUID: this.classGUID,
            itemClassName: this.itemClassName,
            gridAmount: this.gridAmount,
            ammoCount: this.ammoCount,
            rank: this.rank,
            occupancy: this.occupancy.toObject(),
            hasChildren: this.hasChildren
        };
    }
}

class CStringHash {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get hash() {
        return this.ptr.readU32();
    }

    get strPtr() {
        return this.ptr.add(0x08).readPointer();
    }

    get strLen() {
        return this.ptr.add(0x10).readU64().toString();
    }

    get str() {
        const p = this.strPtr;
        if (p.isNull()) return null;
        return readCString(p);
    }

    toObject() {
        return {
            hash: this.hash,
            strPtr: this.strPtr.toString(),
            strLen: this.strLen,
            str: this.str
        };
    }
}

class InteractionPointId {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get entityPtr() {
        return lower48(this.ptr.add(0x08).readPointer());
    }

    get pointId() {
        return this.ptr.add(0x10).readU32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            entityPtr: this.entityPtr.toString(),
            pointId: this.pointId
        };
    }
}

class SPlayerInventoryQuery {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get page() {
        return new SPaginationArguments(this.ptr);
    }

    get orderBy() {
        return this.ptr.add(0x20).readS32();
    }

    get inventoryId() {
        return new SInventoryId(this.ptr.add(0x28));
    }

    get parentInventoryId() {
        return new SInventoryId(this.ptr.add(0x40));
    }

    get type() {
        return this.ptr.add(0x58).readS32();
    }

    get itemTypes() {
        return stdMapInfo(this.ptr.add(0x60));
    }

    get excludeItemTypes() {
        return stdMapInfo(this.ptr.add(0x70));
    }

    get localizedNamePattern() {
        return readCryStringHandle(this.ptr.add(0x80));
    }

    get localeLanguage() {
        return readCryStringHandle(this.ptr.add(0x88));
    }

    get localizedNamePatternIsRegex() {
        return this.ptr.add(0x90).readU8() !== 0;
    }

    toObject() {
        return {
            page: this.page.toObject(),
            orderBy: this.orderBy,
            inventoryId: this.inventoryId.toObject(),
            parentInventoryId: this.parentInventoryId.toObject(),
            type: this.type,
            itemTypes: this.itemTypes,
            excludeItemTypes: this.excludeItemTypes,
            localizedNamePattern: this.localizedNamePattern,
            localeLanguage: this.localeLanguage,
            localizedNamePatternIsRegex: this.localizedNamePatternIsRegex
        };
    }
}

class SMoveStackRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            sourceClassId: this.ptr.readU32(),
            sourceEntityId: readEntityId(this.ptr.add(0x08)),
            sourceRank: readCryStringHandle(this.ptr.add(0x10)),
            sourceStackChange: this.ptr.add(0x18).readS32(),
            targetClassId: this.ptr.add(0x1C).readU32(),
            targetEntityId: readEntityId(this.ptr.add(0x20)),
            targetRank: readCryStringHandle(this.ptr.add(0x28))
        };
    }
}

class SMoveItemRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get itemClassGUID() {
        return readCryGuid(this.ptr.add(0x08));
    }

    get legalOwnerGEID() {
        return readEntityId(this.ptr.add(0x18));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x20));
    }

    toObject() {
        return {
            itemGEID: this.itemGEID,
            itemClassGUID: this.itemClassGUID,
            legalOwnerGEID: this.legalOwnerGEID,
            rank: this.rank
        };
    }
}

class SUnstackEntityRequestParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get quantity() {
        return this.ptr.add(0x08).readS32();
    }

    get ranks() {
        return new StdVector(this.ptr.add(0x10), InventoryManagementSurface.sizes.CryStringT_char);
    }

    get classGuid() {
        return readCryGuid(this.ptr.add(0x28));
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x38));
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x40), "IEntitySnapshot");
    }

    get tagsRaw() {
        return new CTagList(this.ptr.add(0x50));
    }

    toObject() {
        return {
            entityId: this.entityId,
            quantity: this.quantity,
            ranks: this.ranks.toSummary(),
            classGuid: this.classGuid,
            ownerId: this.ownerId,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject(),
            tags: this.tagsRaw.toObject()
        };
    }
}

class SUnstackEntityRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get sourceInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get destinationInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get unstackParams() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SUnstackEntityRequestParams, SUnstackEntityRequestParams);
    }

    toObject(includeParams = false) {
        return {
            sourceInventoryId: this.sourceInventoryId.toObject(),
            destinationInventoryId: this.destinationInventoryId.toObject(),
            unstackParams: includeParams ? this.unstackParams.toArray(32).map(param => param.toObject()) : this.unstackParams.toSummary()
        };
    }
}

class SMoveEntityStackParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromEntityId() {
        return readEntityId(this.ptr);
    }

    get toEntityId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x10));
    }

    get stackSize() {
        return this.ptr.add(0x18).readS32();
    }

    toObject() {
        return {
            fromEntityId: this.fromEntityId,
            toEntityId: this.toEntityId,
            rank: this.rank,
            stackSize: this.stackSize
        };
    }
}

class IInventoryApiSMoveResult {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get from() {
        return readEntityId(this.ptr);
    }

    get to() {
        return readEntityId(this.ptr.add(0x08));
    }

    get fromStackSize() {
        return this.ptr.add(0x10).readS32();
    }

    get toStackSize() {
        return this.ptr.add(0x14).readS32();
    }

    toObject() {
        return {
            from: this.from,
            to: this.to,
            fromStackSize: this.fromStackSize,
            toStackSize: this.toStackSize
        };
    }
}

class IInventoryApiSMoveRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get from() {
        return new SInventoryEntity(this.ptr);
    }

    get to() {
        return new SInventoryEntity(this.ptr.add(0x20));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x40));
    }

    get stackSize() {
        return this.ptr.add(0x48).readS32();
    }

    toObject() {
        return {
            from: this.from.toObject(),
            to: this.to.toObject(),
            rank: this.rank,
            stackSize: this.stackSize
        };
    }
}

class EntityGraphSChangeRankParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get inventoryEntries() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SInventoryEntry, SInventoryEntry);
    }

    toObject(includeEntries = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            inventoryEntries: includeEntries ? this.inventoryEntries.toArray(64).map(entry => entry.toObject()) : this.inventoryEntries.toSummary()
        };
    }
}

class EntityGraphSMoveParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get inventoryEntries() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SInventoryEntry, SInventoryEntry);
    }

    get legalOwnerId() {
        return readEntityId(this.ptr.add(0x48));
    }

    get inventoryConfig() {
        return new EastlOptionalInventoryConfiguration(this.ptr.add(0x50));
    }

    toObject(includeEntries = false) {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            inventoryEntries: includeEntries ? this.inventoryEntries.toArray(64).map(entry => entry.toObject()) : this.inventoryEntries.toSummary(),
            legalOwnerId: this.legalOwnerId,
            inventoryConfig: this.inventoryConfig.toObject()
        };
    }
}

class EntityGraphSMoveAllParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get inventoryConfig() {
        return new EastlOptionalInventoryConfiguration(this.ptr.add(0x30));
    }

    toObject() {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            inventoryConfig: this.inventoryConfig.toObject()
        };
    }
}

class EntityGraphSAttachEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get parentId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get attachmentType() {
        return this.ptr.add(0x10).readS32();
    }

    get portCrc() {
        return this.ptr.add(0x14).readU32();
    }

    get attachmentId() {
        return readEntityId(this.ptr.add(0x18));
    }

    get ownershipChangeBehavior() {
        return this.ptr.add(0x20).readS32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            parentId: this.parentId,
            attachmentType: this.attachmentType,
            portCrc: this.portCrc,
            attachmentId: this.attachmentId,
            ownershipChangeBehavior: this.ownershipChangeBehavior
        };
    }
}

class EntityGraphSAttachParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get attachEntries() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.EntityGraph_SAttachEntry, EntityGraphSAttachEntry);
    }

    toObject(includeEntries = false) {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            attachEntries: includeEntries ? this.attachEntries.toArray(64).map(entry => entry.toObject()) : this.attachEntries.toSummary()
        };
    }
}

class EntityGraphSDetachEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get ownershipChangeBehavior() {
        return this.ptr.add(0x08).readS32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            ownershipChangeBehavior: this.ownershipChangeBehavior
        };
    }
}

class EntityGraphSDetachParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get detachEntries() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.EntityGraph_SDetachEntry, EntityGraphSDetachEntry);
    }

    toObject(includeEntries = false) {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            detachEntries: includeEntries ? this.detachEntries.toArray(64).map(entry => entry.toObject()) : this.detachEntries.toSummary()
        };
    }
}

class EntityGraphSChangeSnapshotParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x08), "IEntitySnapshot");
    }

    toObject() {
        return {
            entityId: this.entityId,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject()
        };
    }
}

class EntityGraphSEraseParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get entityIds() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.EntityId);
    }

    toObject() {
        return {
            inventoryId: this.inventoryId.toObject(),
            entityIds: this.entityIds.toSummary()
        };
    }
}

class SInventoryManagementRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get classItemRankList() {
        return new StdVector(this.ptr.add(0x68), InventoryManagementSurface.sizes.SInventoryManagementRequestClassItemRank, SInventoryManagementRequestClassItemRank);
    }

    get requestMoveId() {
        return this.ptr.readU32();
    }

    get type() {
        return this.ptr.add(0x04).readS32();
    }

    get typeName() {
        return enumName(EPersonalInventoryOperationType, this.type);
    }

    get userId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get sourceInventoryId() {
        return new SInventoryId(this.ptr.add(0x10));
    }

    get targetInventoryId() {
        return new SInventoryId(this.ptr.add(0x28));
    }

    get affectedInventoriesDeprecated() {
        return new StdVector(this.ptr.add(0x40), InventoryManagementSurface.sizes.SInventoryId, SInventoryId);
    }

    get sourceClassId() {
        return this.ptr.add(0x58).readU32();
    }

    get sourceAmount() {
        return this.ptr.add(0x5C).readS32();
    }

    get sourceRank() {
        return readCryStringHandle(this.ptr.add(0x60));
    }

    get targetClassId() {
        return this.ptr.add(0x80).readU32();
    }

    get targetAmount() {
        return this.ptr.add(0x84).readS32();
    }

    get targetRank() {
        return readCryStringHandle(this.ptr.add(0x88));
    }

    get targetRankList() {
        return new StdVector(this.ptr.add(0x90), InventoryManagementSurface.sizes.CryStringT_char);
    }

    get itemEntityId() {
        return readEntityId(this.ptr.add(0xA8));
    }

    get postActionTargetPortId() {
        return new SItemPortId(this.ptr.add(0xB0));
    }

    get dependentMoveId() {
        return this.ptr.add(0xC0).readU32();
    }

    get stack() {
        return this.ptr.add(0xC4).readU8() !== 0;
    }

    get postAction() {
        return this.ptr.add(0xC8).readS32();
    }

    get dataEntries() {
        return new StdVector(this.ptr.add(0xD0), InventoryManagementSurface.sizes.SInventoryContainerEntry, SInventoryContainerEntry);
    }

    get inventoryQuery() {
        return new SPlayerInventoryQuery(this.ptr.add(0xE8));
    }

    get offsetDirZs() {
        return readVec3f(this.ptr.add(0x180));
    }

    get moveStackList() {
        return new StdVector(this.ptr.add(0x190), InventoryManagementSurface.sizes.SMoveStackRequest, SMoveStackRequest);
    }

    get unstowAggregateRootId() {
        return readEntityId(this.ptr.add(0x1A8));
    }

    get itemPortPath() {
        return readCryStringHandle(this.ptr.add(0x1B0));
    }

    get itemPortId() {
        return new SItemPortId(this.ptr.add(0x1B8));
    }

    get flags() {
        return this.ptr.add(0x1C8).readS8();
    }

    toSummary(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            requestMoveId: this.requestMoveId,
            type: this.type,
            typeName: this.typeName,
            userId: this.userId,
            sourceInventoryId: this.sourceInventoryId.toObject(),
            targetInventoryId: this.targetInventoryId.toObject(),
            sourceClassId: this.sourceClassId,
            sourceAmount: this.sourceAmount,
            sourceRank: this.sourceRank,
            targetClassId: this.targetClassId,
            targetAmount: this.targetAmount,
            targetRank: this.targetRank,
            itemEntityId: this.itemEntityId,
            inventoryQuery: this.inventoryQuery.toObject(),
            dataEntries: includeNested ? this.dataEntries.toArray(16).map(item => item.toObject()) : this.dataEntries.toSummary(),
            classItemRankList: includeNested ? this.classItemRankList.toArray(16).map(item => item.toObject()) : this.classItemRankList.toSummary(),
            moveStackList: includeNested ? this.moveStackList.toArray(16).map(item => item.toObject()) : this.moveStackList.toSummary(),
            flags: this.flags
        };
    }

    toObject(includeNested = false) {
        return {
            requestMoveId: this.requestMoveId,
            type: this.type,
            typeName: this.typeName,
            userId: this.userId,
            sourceInventoryId: this.sourceInventoryId.toObject(),
            targetInventoryId: this.targetInventoryId.toObject(),
            affectedInventoriesDeprecated: this.affectedInventoriesDeprecated.toSummary(),
            sourceClassId: this.sourceClassId,
            sourceAmount: this.sourceAmount,
            sourceRank: this.sourceRank,
            classItemRankList: includeNested ? this.classItemRankList.toArray(32).map(item => item.toObject()) : this.classItemRankList.toSummary(),
            targetClassId: this.targetClassId,
            targetAmount: this.targetAmount,
            targetRank: this.targetRank,
            targetRankList: this.targetRankList.toSummary(),
            itemEntityId: this.itemEntityId,
            postActionTargetPortId: this.postActionTargetPortId.toObject(),
            dependentMoveId: this.dependentMoveId,
            stack: this.stack,
            postAction: this.postAction,
            dataEntries: includeNested ? this.dataEntries.toArray(32).map(item => item.toObject()) : this.dataEntries.toSummary(),
            inventoryQuery: this.inventoryQuery.toObject(),
            offsetDirZs: this.offsetDirZs,
            moveStackList: includeNested ? this.moveStackList.toArray(32).map(item => item.toObject()) : this.moveStackList.toSummary(),
            unstowAggregateRootId: this.unstowAggregateRootId,
            itemPortPath: this.itemPortPath,
            itemPortId: this.itemPortId.toObject(),
            flags: this.flags
        };
    }
}

class SInventoryDataRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get withInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get withOwnerId() {
        return readEntityId(this.ptr.add(0x18));
    }

    toObject() {
        return {
            withInventoryId: this.withInventoryId.toObject(),
            withOwnerId: this.withOwnerId
        };
    }
}

class SInventoryContainerManagerEntriesCache {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entries() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.SInventoryContainerManagerEntry, SInventoryContainerManagerEntry);
    }

    get pageInfo() {
        return new SPaginationInfo(this.ptr.add(0x18));
    }

    toObject(includeEntries = false) {
        return {
            entries: includeEntries ? this.entries.toArray(32).map(entry => entry.toObject(false)) : this.entries.toSummary(),
            pageInfo: this.pageInfo.toObject()
        };
    }
}

class SInventoryContainerFilterCacheKey {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get filteredTypes() {
        return stdMapInfo(this.ptr);
    }

    get excludedTypes() {
        return stdMapInfo(this.ptr.add(0x10));
    }

    toObject() {
        return {
            filteredTypes: this.filteredTypes,
            excludedTypes: this.excludedTypes
        };
    }
}

class SInventoryContainerManagerDataCache {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get managerData() {
        return new SInventoryContainerManagerData(this.ptr);
    }

    get filteredEntries() {
        return new StdVector(this.ptr.add(0x78), InventoryManagementSurface.sizes.SInventoryContainerFilterCachePair);
    }

    toObject(includeEntries = false) {
        return {
            managerData: this.managerData.toObject(includeEntries),
            filteredEntries: this.filteredEntries.toSummary()
        };
    }
}

class SInventoryContainerManagerDataCachePair {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get dataCache() {
        return new SInventoryContainerManagerDataCache(this.ptr.add(0x18));
    }

    toObject(includeEntries = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            dataCache: this.dataCache.toObject(includeEntries)
        };
    }
}

class EntityGraphQueryFilterParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemTypes() {
        return stdMapInfo(this.ptr);
    }

    get excludeItemTypes() {
        return stdMapInfo(this.ptr.add(0x10));
    }

    get classCRCs() {
        return new StdVector(this.ptr.add(0x20), 0x04);
    }

    get includedGameFlags() {
        return this.ptr.add(0x38).readU64().toString();
    }

    get excludedGameFlags() {
        return this.ptr.add(0x40).readU64().toString();
    }

    get includeSnapshot() {
        return this.ptr.add(0x48).readU8() !== 0;
    }

    get snapshotFlags() {
        return this.ptr.add(0x4A).readU16();
    }

    get pathMode() {
        return this.ptr.add(0x4C).readU8() !== 0;
    }

    get localizedNamePattern() {
        return readCryStringHandle(this.ptr.add(0x50));
    }

    get localeLanguage() {
        return readCryStringHandle(this.ptr.add(0x58));
    }

    get localizedNamePatternIsRegex() {
        return this.ptr.add(0x60).readU8() !== 0;
    }

    get entityQueryOptionMask() {
        return this.ptr.add(0x68).readU32();
    }

    toObject() {
        return {
            itemTypes: this.itemTypes,
            excludeItemTypes: this.excludeItemTypes,
            classCRCs: this.classCRCs.toSummary(),
            includedGameFlags: this.includedGameFlags,
            excludedGameFlags: this.excludedGameFlags,
            includeSnapshot: this.includeSnapshot,
            snapshotFlags: this.snapshotFlags,
            pathMode: this.pathMode,
            localizedNamePattern: this.localizedNamePattern,
            localeLanguage: this.localeLanguage,
            localizedNamePatternIsRegex: this.localizedNamePatternIsRegex,
            entityQueryOptionMask: this.entityQueryOptionMask
        };
    }
}

class SInventoryEntityQuery {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityGraphFilterParams() {
        return new EntityGraphQueryFilterParams(this.ptr);
    }

    get page() {
        return new SPaginationArguments(this.ptr.add(0x70));
    }

    get orderBy() {
        return this.ptr.add(0x90).readS32();
    }

    get queryType() {
        return this.ptr.add(0x94).readS32();
    }

    get inventoryId() {
        return new SInventoryId(this.ptr.add(0x98));
    }

    toObject() {
        const filter = this.entityGraphFilterParams;
        return {
            entityGraphFilterParams: filter.toObject(),
            page: this.page.toObject(),
            orderBy: this.orderBy,
            queryType: this.queryType,
            inventoryId: this.inventoryId.toObject()
        };
    }
}

class SInventoryQueryResultInventory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryStowedAggregateRoots() {
        return new StdVector(this.ptr, PTR_SIZE);
    }

    get totalOccupancy() {
        return this.ptr.add(0x18).readS64().toString();
    }

    toObject(includeRoots = false) {
        return {
            inventoryStowedAggregateRoots: includeRoots
                ? this.inventoryStowedAggregateRoots.toArray(128).map(p => p.readPointer().toString())
                : this.inventoryStowedAggregateRoots.toSummary(),
            totalOccupancy: this.totalOccupancy
        };
    }
}

class SInventoryQueryResult {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityGraphResultEntities() {
        return {
            ...stdVectorRawInfo(this.ptr),
            note: "std::vector<EntityGraph::SEntityNode>; element layout not decoded here"
        };
    }

    get inventory() {
        return new SInventoryQueryResultInventory(this.ptr.add(0x18));
    }

    toObject(includeRoots = false) {
        return {
            entityGraphResultEntities: this.entityGraphResultEntities,
            inventory: this.inventory.toObject(includeRoots)
        };
    }
}

class SInventoryQueryResponse {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get pageInfo() {
        return new SPaginationInfo(this.ptr);
    }

    get queryResult() {
        return new SInventoryQueryResult(this.ptr.add(0x18));
    }

    toObject(includeRoots = false) {
        return {
            pageInfo: this.pageInfo.toObject(),
            queryResult: this.queryResult.toObject(includeRoots)
        };
    }
}

class SInventoryQueryResultInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get pageInfo() {
        return new SPaginationInfo(this.ptr.add(0x18));
    }

    get result() {
        return new SInventoryQueryResult(this.ptr.add(0x30));
    }

    get valid() {
        return this.ptr.add(0x68).readU8() !== 0;
    }

    toObject(includeInventory = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            pageInfo: this.pageInfo.toObject(),
            result: this.result.toObject(includeInventory),
            valid: this.valid
        };
    }
}

class CInventoryQueryPendingRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get pendingRequests() {
        return new StdVector(this.ptr, 0x08);
    }

    get results() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SInventoryQueryResultInfo, SInventoryQueryResultInfo);
    }

    get callback() {
        return new CigFunctionBase(this.ptr.add(0x30));
    }

    toObject(includeResults = false) {
        const callback = this.callback;
        return {
            pendingRequests: this.pendingRequests.toSummary(),
            results: includeResults ? this.results.toArray(32).map(result => result.toObject(false)) : this.results.toSummary(),
            callback: callback.toObject()
        };
    }
}

class CInventoryOpenPendingRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get requestId() {
        return this.ptr.add(0x18).readU64().toString();
    }

    get unstowParams() {
        return new StdVector(this.ptr.add(0x20), InventoryManagementSurface.sizes.SEntityUnstowParams, SEntityUnstowParams);
    }

    get gridItems() {
        return new StdVector(this.ptr.add(0x38), InventoryManagementSurface.sizes.SInventoryContainerGridItem, SInventoryContainerGridItem);
    }

    get callback() {
        return new CigFunctionBase(this.ptr.add(0x50));
    }

    get timestamp() {
        return this.ptr.add(0x68).readS64().toString();
    }

    get currentUnstowRange() {
        return {
            begin: this.ptr.add(0x70).readU64().toString(),
            end: this.ptr.add(0x78).readU64().toString()
        };
    }

    get numRetries() {
        return this.ptr.add(0x80).readS32();
    }

    toObject(includeNested = false) {
        const callback = this.callback;
        return {
            inventoryId: this.inventoryId.toObject(),
            requestId: this.requestId,
            unstowParams: includeNested ? this.unstowParams.toArray(32).map(param => param.toObject()) : this.unstowParams.toSummary(),
            gridItems: includeNested ? this.gridItems.toArray(64).map(item => item.toObject()) : this.gridItems.toSummary(),
            callback: callback.toObject(),
            timestamp: this.timestamp,
            currentUnstowRange: this.currentUnstowRange,
            numRetries: this.numRetries
        };
    }
}

class CInventoryContainerManagerSLootableBox {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityClass() { return this.ptr.readPointer(); }
    get inventoryDef() { return this.ptr.add(0x08).readPointer(); }
    get usedCapacity() { return this.ptr.add(0x10).readS32(); }
    get contents() { return { ...stdMapInfo(this.ptr.add(0x18)), type: "std::map<SInventoryId,std::vector<EntityGraph::SEntityNode*>>" }; }

    toObject() {
        return {
            entityClass: this.entityClass.toString(),
            inventoryDef: this.inventoryDef.toString(),
            usedCapacity: this.usedCapacity,
            contents: this.contents
        };
    }
}

class CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() { return new SInventoryId(this.ptr); }
    get query() { return new SInventoryEntityQuery(this.ptr.add(0x18)); }
    get dependentRequestId() { return this.ptr.add(0xC8).readU64().toString(); }

    toObject() {
        return {
            inventoryId: this.inventoryId.toObject(),
            query: this.query.toObject(),
            dependentRequestId: this.dependentRequestId
        };
    }
}

class CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get lockSessionSharedPtr() { return new SharedPtr(this.ptr, "IDistributedLockManager::CLockSession"); }
    get addedEntitiesVec() {
        return new StdVector(this.ptr.add(0x10), InventoryManagementSurface.sizes.SInventoryUpdateItem, SInventoryUpdateItem);
    }
    get startTimeStamp() { return this.ptr.add(0x28).readS64().toString(); }

    toObject(includeItems = false) {
        return {
            lockSessionSharedPtr: this.lockSessionSharedPtr.toObject(),
            addedEntitiesVec: includeItems ? this.addedEntitiesVec.toArray(128).map(item => item.toObject()) : this.addedEntitiesVec.toSummary(),
            startTimeStamp: this.startTimeStamp
        };
    }
}

class CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get request() { return new SUnstowRequest(this.ptr); }
    get requestIds() { return new StdVector(this.ptr.add(0x30), 0x08); }

    toObject(includeParams = false) {
        return {
            request: this.request.toObject(includeParams),
            requestIds: this.requestIds.toSummary()
        };
    }
}

class LockedOpenPendingRequests {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get requests() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.CInventoryContainerManager_CInventoryOpenPendingRequest, CInventoryOpenPendingRequest);
    }

    get lock() {
        return new CIGRWLock(this.ptr.add(0x18));
    }

    toObject(includeRequests = false) {
        const lock = this.lock;
        return {
            requests: includeRequests ? this.requests.toArray(32).map(request => request.toObject(false)) : this.requests.toSummary(),
            lock: lock.toObject()
        };
    }
}

class SPersonalInventoryReceivedData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get inventoryRequestId() {
        return this.ptr.add(0x18).readU32();
    }

    get parentInventoryId() {
        return new SInventoryId(this.ptr.add(0x20));
    }

    get type() {
        return this.ptr.add(0x38).readS32();
    }

    get data() {
        return new SInventoryContainerManagerData(this.ptr.add(0x40));
    }

    get itemTypes() {
        return stdMapInfo(this.ptr.add(0xB8));
    }

    get excludedItemTypes() {
        return stdMapInfo(this.ptr.add(0xC8));
    }

    get recordResultToCache() {
        return this.ptr.add(0xD8).readU8() !== 0;
    }

    get success() {
        return this.ptr.add(0xD9).readU8() !== 0;
    }

    toObject(includeEntries = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            inventoryRequestId: this.inventoryRequestId,
            parentInventoryId: this.parentInventoryId.toObject(),
            type: this.type,
            data: this.data.toObject(includeEntries),
            itemTypes: this.itemTypes,
            excludedItemTypes: this.excludedItemTypes,
            recordResultToCache: this.recordResultToCache,
            success: this.success
        };
    }
}

class SPersonalInventoryData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get occupancy() {
        return new SCargoAmount(this.ptr);
    }

    get capacity() {
        return new SCargoAmount(this.ptr.add(0x10));
    }

    get dimensions() {
        return readVec3f(this.ptr.add(0x20));
    }

    get entries() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SInventoryContainerEntry, SInventoryContainerEntry);
    }

    toObject(includeEntries = false) {
        return {
            occupancy: this.occupancy.toObject(),
            capacity: this.capacity.toObject(),
            dimensions: this.dimensions,
            entries: includeEntries ? this.entries.toArray(64).map(entry => entry.toObject()) : this.entries.toSummary()
        };
    }
}

class DataCoreArrayBase {
    constructor(ptrValue, elementType = null) {
        this.ptr = ptr(ptrValue);
        this.elementType = elementType;
    }

    toObject() {
        return {
            ...dataCoreArrayInfo(this.ptr),
            elementType: this.elementType
        };
    }
}

class DCString {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toString() {
        return readCryStringHandle(this.ptr);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            value: this.toString()
        };
    }
}

class CLocIdentifier {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toString() {
        return readCryStringHandle(this.ptr);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            identifier: this.toString()
        };
    }
}

class STypeSubtypeParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemType() {
        return this.ptr.add(0x08).readS32();
    }

    get itemSubType() {
        return this.ptr.add(0x0C).readS32();
    }

    toObject() {
        return {
            itemType: this.itemType,
            itemSubType: this.itemSubType
        };
    }
}

class SItemCategory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemType() {
        return this.ptr.add(0x08).readS32();
    }

    get itemSubType() {
        return this.ptr.add(0x0C).readS32();
    }

    get requiredTag() {
        return new DataCoreRecordRef(this.ptr.add(0x10), "SDCTag");
    }

    toObject() {
        return {
            itemType: this.itemType,
            itemSubType: this.itemSubType,
            requiredTag: this.requiredTag.toObject()
        };
    }
}

class SInventoryInteractionBlockingAttachedEntities {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get category() { return new SItemCategory(this.ptr.add(0x08)); }
    get blockingAttachedTypes() { return new DataCoreArrayBase(this.ptr.add(0x30), "SItemCategory"); }

    toObject() {
        return {
            category: this.category.toObject(),
            blockingAttachedTypes: this.blockingAttachedTypes.toObject()
        };
    }
}

class SPlayerInventoryDef {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get landingZoneInventory() {
        return new DataCoreRecordRef(this.ptr.add(0x08), "SLandingZoneInventoryDef");
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            landingZoneInventory: this.landingZoneInventory.toObject()
        };
    }
}

class SInventoryConfig {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get selectTimer() { return this.ptr.add(0x08).readFloat(); }
    get silhouettesAmount() { return this.ptr.add(0x0C).readFloat(); }
    get silhouettesFillStr() { return this.ptr.add(0x10).readFloat(); }
    get silhouetteEdgeWidth() { return this.ptr.add(0x14).readFloat(); }
    get silhouetteBlurRadius() { return this.ptr.add(0x18).readFloat(); }
    get skinParentTypes() { return new DataCoreArrayBase(this.ptr.add(0x1F0), "SItemCategory"); }
    get blockingRules() { return new DataCoreArrayBase(this.ptr.add(0x200), "SInventoryInteractionBlockingAttachedEntities"); }

    silhouetteBlock(offset) {
        return {
            ptr: this.ptr.add(offset).toString(),
            type: "SHUDSilhouetteParams",
            size: "0x40"
        };
    }

    optionalSilhouetteBlock(offset) {
        return {
            ptr: this.ptr.add(offset).readPointer().toString(),
            type: "DataCoreOptional<SHUDSilhouetteParams>",
            size: "0x08"
        };
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            selectTimer: this.selectTimer,
            silhouettesAmount: this.silhouettesAmount,
            silhouettesFillStr: this.silhouettesFillStr,
            silhouetteEdgeWidth: this.silhouetteEdgeWidth,
            silhouetteBlurRadius: this.silhouetteBlurRadius,
            hoverParams: this.silhouetteBlock(0x20),
            hoverAttachmentsParams: this.silhouetteBlock(0x60),
            focusParams: this.silhouetteBlock(0xA0),
            focusAttachmentsParams: this.silhouetteBlock(0xE0),
            unavailableParams: this.silhouetteBlock(0x120),
            unavailableAttachmentsParams: this.silhouetteBlock(0x160),
            blockedHoverParams: this.silhouetteBlock(0x1A0),
            extInvOutlineParams: this.optionalSilhouetteBlock(0x1E0),
            blockedInvOutlineParams: this.optionalSilhouetteBlock(0x1E8),
            skinParentTypes: this.skinParentTypes.toObject(),
            blockingRules: this.blockingRules.toObject()
        };
    }
}

class SOpenInventory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            reconciliation: this.ptr.readS32(),
            reconciliationOnAuthorityChange: this.ptr.add(0x04).readS32(),
            reconciliationOnContentUpdate: this.ptr.add(0x08).readS32(),
            gridAlignment: this.ptr.add(0x0C).readS32(),
            useImmediateCreationFlow: this.ptr.add(0x10).readS32(),
            maxOpenRetries: this.ptr.add(0x14).readS32(),
            alwaysOpenOpenInventory: this.ptr.add(0x18).readS32()
        };
    }
}

class SLootGeneration {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            disabled: this.ptr.readS32()
        };
    }
}

class SInventoryContainerCVars {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get openInventory() { return new SOpenInventory(this.ptr.add(0x10)); }
    get lootGeneration() { return new SLootGeneration(this.ptr.add(0x2C)); }

    toObject() {
        return {
            log: this.ptr.readS32(),
            debugDuration: this.ptr.add(0x04).readFloat(),
            maxUnstowsPerRequest: this.ptr.add(0x08).readS32(),
            maxUnstowRequests: this.ptr.add(0x0C).readS32(),
            openInventory: this.openInventory.toObject(),
            lootGeneration: this.lootGeneration.toObject()
        };
    }
}

class InventoryUIData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get name() {
        return readCLocString(this.ptr);
    }

    get displayName() {
        return this.ptr.add(0x08).readU8() !== 0;
    }

    get isEnabled() {
        return this.ptr.add(0x09).readU8() !== 0;
    }

    get itemDisplayThumbnail() {
        return readCryStringHandle(this.ptr.add(0x10));
    }

    get itemClass() {
        return readCryStringHandle(this.ptr.add(0x18));
    }

    get param() {
        return this.ptr.add(0x20).readS32();
    }

    get flags() {
        return this.ptr.add(0x24).readU8();
    }

    toObject() {
        return {
            name: this.name,
            displayName: this.displayName,
            isEnabled: this.isEnabled,
            itemDisplayThumbnail: this.itemDisplayThumbnail,
            itemClass: this.itemClass,
            param: this.param,
            flags: this.flags
        };
    }
}

class InventoryItemWeakenedData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get weakenedType() {
        return this.ptr.readS32();
    }

    get weakenedRatio() {
        return this.ptr.add(0x04).readFloat();
    }

    toObject() {
        return {
            weakenedType: this.weakenedType,
            weakenedRatio: this.weakenedRatio
        };
    }
}

class InventoryItemDataDesc {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get isTiered() {
        return this.ptr.readU8() !== 0;
    }

    get isSized() {
        return this.ptr.add(0x01).readU8() !== 0;
    }

    get isVehicleComponent() {
        return this.ptr.add(0x02).readU8() !== 0;
    }

    get isMaterial() {
        return this.ptr.add(0x03).readU8() !== 0;
    }

    get materialQuality() {
        return this.ptr.add(0x04).readS32();
    }

    get tier() {
        return this.ptr.add(0x08).readS32();
    }

    get size() {
        return this.ptr.add(0x0C).readS32();
    }

    get componentClass() {
        return readCLocString(this.ptr.add(0x10));
    }

    get componentGrade() {
        return readCLocString(this.ptr.add(0x18));
    }

    toObject() {
        return {
            isTiered: this.isTiered,
            isSized: this.isSized,
            isVehicleComponent: this.isVehicleComponent,
            isMaterial: this.isMaterial,
            materialQuality: this.materialQuality,
            tier: this.tier,
            size: this.size,
            componentClass: this.componentClass,
            componentGrade: this.componentGrade
        };
    }
}

class InventoryItemData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get inventoryId() {
        return new SInventoryId(this.ptr.add(0x10));
    }

    get groupOriginInventoryId() {
        return new SInventoryId(this.ptr.add(0x28));
    }

    get itemClassId() {
        return this.ptr.add(0x40).readU32();
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x48));
    }

    get gridAmount() {
        return this.ptr.add(0x50).readS32();
    }

    get occupancy() {
        return this.ptr.add(0x58).readS64().toString();
    }

    get occupancyDimensions() {
        return readVec3f(this.ptr.add(0x60));
    }

    get uiItemClassId() {
        return this.ptr.add(0x6C).readU32();
    }

    get uiDimensions() {
        return readVec3f(this.ptr.add(0x70));
    }

    get uiOrientation() {
        return readVec3f(this.ptr.add(0x7C));
    }

    get lightGroupEntityClass() {
        return new DataCoreRecordRef(this.ptr.add(0x88), "SCEntityClass");
    }

    get gamePersistentData() {
        return readCryStringHandle(this.ptr.add(0xA0));
    }

    get consumableRemainingVolumePercentage() {
        return this.ptr.add(0xA8).readFloat();
    }

    get ammoCount() {
        return this.ptr.add(0xAC).readS32();
    }

    get ammoMaxCount() {
        return this.ptr.add(0xB0).readS32();
    }

    get weaponType() {
        return this.ptr.add(0xB4).readS8();
    }

    get containerOccupancy() {
        return this.ptr.add(0xB8).readS64().toString();
    }

    get containerMaxOccupancy() {
        return this.ptr.add(0xC0).readS64().toString();
    }

    get itemMissionId() {
        return readCryGuid(this.ptr.add(0xC8));
    }

    get itemName() {
        return readCLocString(this.ptr.add(0xD8));
    }

    get occupancyFormatted() {
        return readCLocString(this.ptr.add(0xE0));
    }

    get detailedDescription() {
        return readCLocString(this.ptr.add(0xE8));
    }

    get tooltipDescription() {
        return readCLocString(this.ptr.add(0xF0));
    }

    get itemExpiryEndTime() {
        return this.ptr.add(0xF8).readS64().toString();
    }

    get isItemExpiryItem() {
        return this.ptr.add(0x100).readU8() !== 0;
    }

    get isCorpseLockedItem() {
        return this.ptr.add(0x101).readU8() !== 0;
    }

    get ownershipTimeStamp() {
        return this.ptr.add(0x108).readS64().toString();
    }

    get ownershipStatus() {
        return this.ptr.add(0x110).readS8();
    }

    get weakData() {
        return new InventoryItemWeakenedData(this.ptr.add(0x114));
    }

    get descData() {
        return new InventoryItemDataDesc(this.ptr.add(0x120));
    }

    get craftedProperties() {
        return new StdVector(this.ptr.add(0x140), 0x01);
    }

    get resourcesSharedPtr() {
        return new SharedPtr(this.ptr.add(0x158), "InventoryUI::SItemResources");
    }

    toObject() {
        return {
            entityId: this.entityId,
            ownerId: this.ownerId,
            inventoryId: this.inventoryId.toObject(),
            groupOriginInventoryId: this.groupOriginInventoryId.toObject(),
            itemClassId: this.itemClassId,
            rank: this.rank,
            gridAmount: this.gridAmount,
            occupancy: this.occupancy,
            occupancyDimensions: this.occupancyDimensions,
            uiItemClassId: this.uiItemClassId,
            uiDimensions: this.uiDimensions,
            uiOrientation: this.uiOrientation,
            lightGroupEntityClass: this.lightGroupEntityClass.toObject(),
            gamePersistentData: this.gamePersistentData,
            consumableRemainingVolumePercentage: this.consumableRemainingVolumePercentage,
            ammoCount: this.ammoCount,
            ammoMaxCount: this.ammoMaxCount,
            weaponType: this.weaponType,
            containerOccupancy: this.containerOccupancy,
            containerMaxOccupancy: this.containerMaxOccupancy,
            itemMissionId: this.itemMissionId,
            itemName: this.itemName,
            occupancyFormatted: this.occupancyFormatted,
            detailedDescription: this.detailedDescription,
            tooltipDescription: this.tooltipDescription,
            itemExpiryEndTime: this.itemExpiryEndTime,
            isItemExpiryItem: this.isItemExpiryItem,
            isCorpseLockedItem: this.isCorpseLockedItem,
            ownershipTimeStamp: this.ownershipTimeStamp,
            ownershipStatus: this.ownershipStatus,
            weakData: this.weakData.toObject(),
            descData: this.descData.toObject(),
            craftedProperties: this.craftedProperties.toSummary(),
            resourcesSharedPtr: this.resourcesSharedPtr.toObject()
        };
    }
}

class InventoryUINavigationData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get name() { return readCLocString(this.ptr); }
    get tabIndex() { return this.ptr.add(0x08).readS32(); }
    get iconPath() { return readCryStringHandle(this.ptr.add(0x10)); }
    get highlightEntityId() { return readEntityId(this.ptr.add(0x18)); }

    toObject() {
        return {
            name: this.name,
            tabIndex: this.tabIndex,
            iconPath: this.iconPath,
            highlightEntityId: this.highlightEntityId
        };
    }
}

class InventoryUIMenuOptionData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get name() { return readCLocString(this.ptr); }
    get infoDisplayText() { return readCLocString(this.ptr.add(0x08)); }
    get isEnabled() { return this.ptr.add(0x10).readU8() !== 0; }
    get param() { return this.ptr.add(0x14).readS32(); }
    get userInput() { return this.ptr.add(0x18).readU8() !== 0; }
    get amount() { return this.ptr.add(0x1C).readS32(); }
    get minAmount() { return this.ptr.add(0x20).readS32(); }
    get maxAmount() { return this.ptr.add(0x24).readS32(); }

    toObject() {
        return {
            name: this.name,
            infoDisplayText: this.infoDisplayText,
            isEnabled: this.isEnabled,
            param: this.param,
            userInput: this.userInput,
            amount: this.amount,
            minAmount: this.minAmount,
            maxAmount: this.maxAmount
        };
    }
}

class InventoryUIFilterData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get locId() { return this.ptr.readU32(); }
    get filterLabel() { return readCryStringHandle(this.ptr.add(0x08)); }
    get active() { return this.ptr.add(0x10).readU8() !== 0; }

    toObject() {
        return {
            locId: this.locId,
            filterLabel: this.filterLabel,
            active: this.active
        };
    }
}

class InventoryUICategoryFilterData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get locId() { return this.ptr.readU32(); }
    get filterLabel() { return readCryStringHandle(this.ptr.add(0x08)); }
    get iconPath() { return readCryStringHandle(this.ptr.add(0x10)); }
    get disableForFPS() { return this.ptr.add(0x18).readU8() !== 0; }
    get filterType() { return this.ptr.add(0x1C).readS32(); }
    get active() { return this.ptr.add(0x20).readU8() !== 0; }
    get filters() {
        return new StdVector(this.ptr.add(0x28), InventoryManagementSurface.sizes.InventoryUI_SInventoryFilterData, InventoryUIFilterData);
    }

    toObject(includeFilters = false) {
        return {
            locId: this.locId,
            filterLabel: this.filterLabel,
            iconPath: this.iconPath,
            disableForFPS: this.disableForFPS,
            filterType: this.filterType,
            active: this.active,
            filters: includeFilters ? this.filters.toArray(64).map(filter => filter.toObject()) : this.filters.toSummary()
        };
    }
}

class InventoryUIItemPort {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemPortContainer() { return componentPtrInfo(this.ptr); }
    get itemPortId() { return new SItemPortId(this.ptr.add(0x08)); }
    get itemPortType() { return this.ptr.add(0x18).readS32(); }
    get itemPortSizeUIClass() { return this.ptr.add(0x1C).readS32(); }
    get iconClass() { return readCryStringHandle(this.ptr.add(0x20)); }
    get localOffset() { return readVec3f(this.ptr.add(0x28)); }
    get capacityUsagePercentage() { return this.ptr.add(0x34).readFloat(); }
    get weakData() { return new InventoryItemWeakenedData(this.ptr.add(0x38)); }
    get weaponType() { return this.ptr.add(0x40).readS8(); }
    get isVisible() { return this.ptr.add(0x41).readU8() !== 0; }
    get isFree() { return this.ptr.add(0x42).readU8() !== 0; }
    get isInteractive() { return this.ptr.add(0x43).readU8() !== 0; }
    get allowStorageInteractions() { return this.ptr.add(0x44).readU8() !== 0; }
    get itemHasCapacity() { return this.ptr.add(0x45).readU8() !== 0; }
    get isCorpseLocked() { return this.ptr.add(0x46).readU8() !== 0; }
    get itemData() { return new InventoryItemData(this.ptr.add(0x48)); }
    get itemChildren() {
        return new StdVector(this.ptr.add(0x1B0), InventoryManagementSurface.sizes.InventoryUI_SInventoryItemPort, InventoryUIItemPort);
    }
    get flags() { return this.ptr.add(0x1C8).readU8(); }

    toObject(includeNested = false) {
        return {
            itemPortContainer: this.itemPortContainer,
            itemPortId: this.itemPortId.toObject(),
            itemPortType: this.itemPortType,
            itemPortSizeUIClass: this.itemPortSizeUIClass,
            iconClass: this.iconClass,
            localOffset: this.localOffset,
            capacityUsagePercentage: this.capacityUsagePercentage,
            weakData: this.weakData.toObject(),
            weaponType: this.weaponType,
            isVisible: this.isVisible,
            isFree: this.isFree,
            isInteractive: this.isInteractive,
            allowStorageInteractions: this.allowStorageInteractions,
            itemHasCapacity: this.itemHasCapacity,
            isCorpseLocked: this.isCorpseLocked,
            itemData: this.itemData.toObject(),
            itemChildren: includeNested ? this.itemChildren.toArray(64).map(child => child.toObject(false)) : this.itemChildren.toSummary(),
            flags: this.flags
        };
    }
}

class SInventoryContent {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() { return new SInventoryId(this.ptr); }
    get classCRC() { return this.ptr.add(0x18).readU32(); }
    get rank() { return readCryStringHandle(this.ptr.add(0x20)); }
    get gridAmount() { return this.ptr.add(0x28).readS32(); }
    get occupancy() { return this.ptr.add(0x2C).readS32(); }

    toObject() {
        return {
            inventoryId: this.inventoryId.toObject(),
            classCRC: this.classCRC,
            rank: this.rank,
            gridAmount: this.gridAmount,
            occupancy: this.occupancy
        };
    }
}

class SInventoryItemKey {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get value() { return this.ptr.readU64().toString(); }

    toObject() {
        return {
            value: this.value
        };
    }
}

class SFreightElevatorRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get transferEntities() {
        return new StdVector(this.ptr.add(0x28), 0x01);
    }

    get warehouseEntities() {
        return new StdVector(this.ptr.add(0x40), 0x01);
    }

    get missionEntities() {
        return new StdVector(this.ptr.add(0x58), 0x01);
    }

    get groupWarehouseOrder() {
        return new StdVector(this.ptr.add(0x70), 0x01);
    }

    toObject() {
        return {
            state: this.ptr.readS32(),
            requestId: this.ptr.add(0x08).readS64().toString(),
            requestType: this.ptr.add(0x10).readS32(),
            requesterId: readEntityId(this.ptr.add(0x18)),
            locationId: this.ptr.add(0x20).readU32(),
            transferEntities: stdVectorRawInfo(this.ptr.add(0x28)),
            warehouseEntities: stdVectorRawInfo(this.ptr.add(0x40)),
            missionEntities: stdVectorRawInfo(this.ptr.add(0x58)),
            groupWarehouseOrder: stdVectorRawInfo(this.ptr.add(0x70)),
            containNonMissionCargo: this.ptr.add(0x88).readU8() !== 0
        };
    }
}

class CBindingsShopInventoryItem {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            rawBuyPrice: typedMemberInfo(this.ptr.add(0x50), "CBindingsVariableFloat", 0x48),
            rawSellToPrice: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableFloat", 0x48),
            stock: typedMemberInfo(this.ptr.add(0xE0), "CBindingsVariableInt", 0x50),
            maxStock: typedMemberInfo(this.ptr.add(0x130), "CBindingsVariableInt", 0x50),
            displayBuyPrice: typedMemberInfo(this.ptr.add(0x180), "CBindingsVariableFloat", 0x48),
            displaySellToPrice: typedMemberInfo(this.ptr.add(0x1C8), "CBindingsVariableFloat", 0x48),
            displayNameLoc: typedMemberInfo(this.ptr.add(0x210), "CBindingsVariableLocalization", 0x50),
            amountInPersonalInventory: typedMemberInfo(this.ptr.add(0x260), "CBindingsVariableInt", 0x50),
            itemGuid: readCryGuid(this.ptr.add(0x2B0)),
            itemGEID: readEntityId(this.ptr.add(0x2C0)),
            itemName: readCryStringHandle(this.ptr.add(0x2C8)),
            organizationPriceMods: stdVectorRawInfo(this.ptr.add(0x2D0)),
            rentalOptions: stdVectorRawInfo(this.ptr.add(0x2E8)),
            preSpawnedQuickBuyItems: stdVectorRawInfo(this.ptr.add(0x300)),
            goldLicensesRequired: this.ptr.add(0x318).readU64().toString(),
            platinumLicensesRequired: this.ptr.add(0x320).readU64().toString(),
            hiddenPerkItem: this.ptr.add(0x328).readU8() !== 0,
            licencePerkItem: this.ptr.add(0x329).readU8() !== 0,
            shopLoadouts: stdVectorRawInfo(this.ptr.add(0x330)),
            quantity: this.ptr.add(0x348).readU64().toString(),
            quantitySellPrice: this.ptr.add(0x350).readDouble(),
            previousBuyPrice: this.ptr.add(0x358).readDouble(),
            previousSellPrice: this.ptr.add(0x360).readDouble(),
            boxSizesAvailable: this.ptr.add(0x368).readU64().toString()
        };
    }
}

class SBindingsInventoryItemResourceContents {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            resourceName: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableLocalization", 0x50),
            resourceQuality: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableInt", 0x50),
            resourceAmountSCU: typedMemberInfo(this.ptr.add(0xE8), "CBindingsVariableFloat", 0x48),
            isVolatile: typedMemberInfo(this.ptr.add(0x130), "CBindingsVariableBool", 0x48)
        };
    }
}

class InventoryGridCommonsSBindingsInventoryItemCraftedStat {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            statName: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableLocalization", 0x50),
            baseValue: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableLocalization", 0x50),
            newValue: typedMemberInfo(this.ptr.add(0xE8), "CBindingsVariableLocalization", 0x50),
            deltaValue: typedMemberInfo(this.ptr.add(0x138), "CBindingsVariableLocalization", 0x50),
            comparisonState: typedMemberInfo(this.ptr.add(0x188), "CBindingsVariableInt", 0x50),
            isHighlighted: typedMemberInfo(this.ptr.add(0x1D8), "CBindingsVariableBool", 0x48)
        };
    }
}

class SBindingsInventoryItemMenuOptions {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            active: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            hoverItemMenuIndex: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableInt", 0x50),
            name: typedMemberInfo(this.ptr.add(0xE0), "CBindingsVariableLocalization", 0x50),
            options: typedMemberInfo(this.ptr.add(0x130), "CBindingsArray<SBindingsInventoryItemOption>", 0x78)
        };
    }
}

class SBindingsInventoryItemHologram {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            itemEntityClass: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableString", 0x50),
            lightGroupEntityClass: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableString", 0x50),
            dimensionX: typedMemberInfo(this.ptr.add(0xE8), "CBindingsVariableFloat", 0x48),
            dimensionY: typedMemberInfo(this.ptr.add(0x130), "CBindingsVariableFloat", 0x48),
            dimensionZ: typedMemberInfo(this.ptr.add(0x178), "CBindingsVariableFloat", 0x48),
            orientationX: typedMemberInfo(this.ptr.add(0x1C0), "CBindingsVariableFloat", 0x48),
            orientationY: typedMemberInfo(this.ptr.add(0x208), "CBindingsVariableFloat", 0x48),
            orientationZ: typedMemberInfo(this.ptr.add(0x250), "CBindingsVariableFloat", 0x48)
        };
    }
}

class SBindingsInventoryItemPersistence {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            isConsumable: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            consumableRemainingVolume: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableFloat", 0x48),
            isAmmoContainer: typedMemberInfo(this.ptr.add(0xD8), "CBindingsVariableBool", 0x48),
            ammoCount: typedMemberInfo(this.ptr.add(0x120), "CBindingsVariableInt", 0x50),
            ammoMaxCount: typedMemberInfo(this.ptr.add(0x170), "CBindingsVariableInt", 0x50),
            missionItem: typedMemberInfo(this.ptr.add(0x1C0), "CBindingsVariableBool", 0x48),
            itemBrickingStatus: typedMemberInfo(this.ptr.add(0x208), "CBindingsVariableInt", 0x50),
            itemTimerState: typedMemberInfo(this.ptr.add(0x258), "CBindingsVariableInt", 0x50),
            itemTimerEnd: typedMemberInfo(this.ptr.add(0x2A8), "CBindingsVariableInt", 0x50),
            craftedStats: typedMemberInfo(this.ptr.add(0x2F8), "CBindingsArray<InventoryGridCommons::SBindingsInventoryItemCraftedStat>", 0x78),
            resourceCapacityUsage: typedMemberInfo(this.ptr.add(0x370), "CBindingsVariableFloat", 0x48),
            resourceCapacity: typedMemberInfo(this.ptr.add(0x3B8), "CBindingsVariableInt", 0x50),
            resourceContents: typedMemberInfo(this.ptr.add(0x408), "CBindingsArray<SBindingsInventoryItemResourceContents>", 0x78),
            resourceDisplayMode: typedMemberInfo(this.ptr.add(0x480), "CBindingsVariableInt", 0x50)
        };
    }
}

class SBindingsInventoryItemDesc {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            isTiered: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            isSized: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableBool", 0x48),
            isVehicleComponent: typedMemberInfo(this.ptr.add(0xD8), "CBindingsVariableBool", 0x48),
            isMaterial: typedMemberInfo(this.ptr.add(0x120), "CBindingsVariableBool", 0x48),
            tier: typedMemberInfo(this.ptr.add(0x168), "CBindingsVariableInt", 0x50),
            materialQuality: typedMemberInfo(this.ptr.add(0x1B8), "CBindingsVariableInt", 0x50),
            size: typedMemberInfo(this.ptr.add(0x208), "CBindingsVariableInt", 0x50),
            componentClass: typedMemberInfo(this.ptr.add(0x258), "CBindingsVariableLocalization", 0x50),
            componentGrade: typedMemberInfo(this.ptr.add(0x2A8), "CBindingsVariableLocalization", 0x50)
        };
    }
}

class SBindingsInventoryCustomSubFilter {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            name: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableLocalization", 0x50),
            state: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableBool", 0x48),
            filterLabel: readCryStringHandle(this.ptr.add(0xE0))
        };
    }
}

class SBindingsInventoryCustomFilter {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            name: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableLocalization", 0x50),
            state: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableBool", 0x48),
            subfilters: typedMemberInfo(this.ptr.add(0xE0), "CBindingsArray<SBindingsInventoryCustomSubFilter>", 0x78),
            filterLabel: readCryStringHandle(this.ptr.add(0x158))
        };
    }
}

class SBindingsInventoryItemFilter {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            customFilters: typedMemberInfo(this.ptr.add(0x48), "CBindingsArray<SBindingsInventoryCustomFilter>", 0x78),
            categoryFilters: typedMemberInfo(this.ptr.add(0xC0), "CBindingsArray<SBindingsCategoryFilter>", 0x78),
            itemFiltersExpanded: typedMemberInfo(this.ptr.add(0x138), "CBindingsVariableBool", 0x48),
            customFilterExpanded: typedMemberInfo(this.ptr.add(0x180), "CBindingsVariableBool", 0x48),
            clearFilter: typedMemberInfo(this.ptr.add(0x1C8), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryApplyFilter>", 0x48)
        };
    }
}

class SBindingsInventoryInvalidMoveData {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            isInvalidMovement: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            dropItemValid: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableBool", 0x48),
            invalidMessagePersistentCondition: typedMemberInfo(this.ptr.add(0xD8), "CBindingsVariableLocalization", 0x50),
            invalidMessageTemporaryCondition: typedMemberInfo(this.ptr.add(0x128), "CBindingsVariableLocalization", 0x50)
        };
    }
}

class SBindingsLootItemSlotState {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            isDisabled: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            isInteractive: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableBool", 0x48),
            isSelected: typedMemberInfo(this.ptr.add(0xD8), "CBindingsVariableBool", 0x48),
            isInFocus: typedMemberInfo(this.ptr.add(0x120), "CBindingsVariableBool", 0x48),
            isDragging: typedMemberInfo(this.ptr.add(0x168), "CBindingsVariableBool", 0x48),
            isCompatibleItem: typedMemberInfo(this.ptr.add(0x1B0), "CBindingsVariableBool", 0x48),
            isCorpseLocked: typedMemberInfo(this.ptr.add(0x1F8), "CBindingsVariableBool", 0x48),
            compatibleState: typedMemberInfo(this.ptr.add(0x240), "CBindingsVariableInt", 0x50),
            weakenedType: typedMemberInfo(this.ptr.add(0x290), "CBindingsVariableInt", 0x50),
            weakenedRatio: typedMemberInfo(this.ptr.add(0x2E0), "CBindingsVariableFloat", 0x48),
            repoolingInfo: typedMemberInfo(this.ptr.add(0x328), "SBindingsRepoolingInfo", 0x1C8),
            triggers: {
                rollOn: typedMemberInfo(this.ptr.add(0x4F0), "CBindingsCustomTrigger<SCEvtNotify_OnLootItemRollOn>", 0x30),
                rollOff: typedMemberInfo(this.ptr.add(0x520), "CBindingsCustomTrigger<SCEvtNotify_OnLootItemRollOff>", 0x30),
                primaryAction: typedMemberInfo(this.ptr.add(0x550), "CBindingsCustomTrigger<SCEvtNotify_OnLootPrimaryAction>", 0x30),
                secondaryAction: typedMemberInfo(this.ptr.add(0x580), "CBindingsCustomTrigger<SCEvtNotify_OnLootSecondaryAction>", 0x30),
                doubleClickAction: typedMemberInfo(this.ptr.add(0x5B0), "CBindingsCustomTrigger<SCEvtNotify_OnLootDoubleClickAction>", 0x30)
            }
        };
    }
}

class SBindingsEquipItemPortInfo {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            portAnchorX: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableFloat", 0x80),
            portAnchorY: typedMemberInfo(this.ptr.add(0xC8), "CBindingsVariableFloat", 0x80),
            id: typedMemberInfo(this.ptr.add(0x148), "CBindingsVariableInt", 0x50),
            hologram: new SBindingsInventoryItemHologram(this.ptr.add(0x198)).toObject(),
            type: typedMemberInfo(this.ptr.add(0x430), "CBindingsVariableInt", 0x50),
            sizeClass: typedMemberInfo(this.ptr.add(0x480), "CBindingsVariableInt", 0x50),
            iconPath: typedMemberInfo(this.ptr.add(0x4D0), "CBindingsVariableString", 0x50),
            isFree: typedMemberInfo(this.ptr.add(0x520), "CBindingsVariableBool", 0x48),
            itemCapacityUsage: typedMemberInfo(this.ptr.add(0x568), "CBindingsVariableFloat", 0x48),
            hasCapacity: typedMemberInfo(this.ptr.add(0x5B0), "CBindingsVariableBool", 0x48),
            number: typedMemberInfo(this.ptr.add(0x5F8), "CBindingsVariableInt", 0x50),
            isVisible: typedMemberInfo(this.ptr.add(0x648), "CBindingsVariableBool", 0x48),
            itemPersistence: includeNested ? new SBindingsInventoryItemPersistence(this.ptr.add(0x690)).toObject() : typedMemberInfo(this.ptr.add(0x690), "SBindingsInventoryItemPersistence", InventoryManagementSurface.sizes.SBindingsInventoryItemPersistence),
            lootSlotState: includeNested ? new SBindingsLootItemSlotState(this.ptr.add(0xB60)).toObject() : typedMemberInfo(this.ptr.add(0xB60), "SBindingsLootItemSlotState", InventoryManagementSurface.sizes.SBindingsLootItemSlotState),
            descData: includeNested ? new SBindingsInventoryItemDesc(this.ptr.add(0x1140)).toObject() : typedMemberInfo(this.ptr.add(0x1140), "SBindingsInventoryItemDesc", InventoryManagementSurface.sizes.SBindingsInventoryItemDesc),
            triggers: {
                itemPortRollOn: typedMemberInfo(this.ptr.add(0x1438), "CBindingsCustomTrigger<SCEvtNotify_OnItemPortRollOn>", 0x50),
                itemPortRollOff: typedMemberInfo(this.ptr.add(0x1488), "CBindingsCustomTrigger<SCEvtNotify_OnItemPortRollOff>", 0x50),
                startDraggingLoot: typedMemberInfo(this.ptr.add(0x14D8), "CBindingsCustomTrigger<SCEvtNotify_OnStartDraggingLoot>", 0x30),
                stopDraggingLoot: typedMemberInfo(this.ptr.add(0x1508), "CBindingsCustomTrigger<SCEvtNotify_OnStopDraggingLoot>", 0x30),
                tooltipItemRollOn: typedMemberInfo(this.ptr.add(0x1538), "CBindingsCustomTrigger<SCEvtNotify_OnTooltipItemRollOn>", 0x40),
                tooltipItemRollOff: typedMemberInfo(this.ptr.add(0x1578), "CBindingsCustomTrigger<SCEvtNotify_OnTooltipItemRollOff>", 0x40)
            },
            itemPortId: new SItemPortId(this.ptr.add(0x15B8)).toObject(),
            itemPortContainer: componentPtrInfo(this.ptr.add(0x15C8)),
            looseEntityId: readEntityId(this.ptr.add(0x15D0)),
            belongsToPlayer: this.ptr.add(0x15D8).readU8() !== 0,
            allowStorageInteractions: this.ptr.add(0x15D9).readU8() !== 0,
            groupType: this.ptr.add(0x15DC).readS32()
        };
    }
}

class SBindingsEquipGroupItemPorts {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            portAnchorX: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableFloat", 0x80),
            portAnchorY: typedMemberInfo(this.ptr.add(0xC8), "CBindingsVariableFloat", 0x80),
            groupItemPorts: typedMemberInfo(this.ptr.add(0x148), "CBindingsArray<SBindingsEquipItemPortInfo>", 0x78),
            display: typedMemberInfo(this.ptr.add(0x1C0), "CBindingsVariableBool", 0x48),
            isEmpty: typedMemberInfo(this.ptr.add(0x208), "CBindingsVariableBool", 0x48),
            hoverGroupTooltip: typedMemberInfo(this.ptr.add(0x250), "CBindingsVariableLocalization", 0x50),
            hoverGroupTooltipEnabled: typedMemberInfo(this.ptr.add(0x2A0), "CBindingsVariableBool", 0x48),
            hoverGroupComparableTooltip: typedMemberInfo(this.ptr.add(0x2E8), "CBindingsVariableLocalization", 0x50),
            hoverGroupComparableTooltipEnabled: typedMemberInfo(this.ptr.add(0x338), "CBindingsVariableBool", 0x48)
        };
    }
}

class SBindingsPITInventoryDragEquipment {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            hologram: new SBindingsInventoryItemHologram(this.ptr.add(0x48)).toObject(),
            id: typedMemberInfo(this.ptr.add(0x2E0), "CBindingsVariableInt", 0x50),
            itemPorts: typedMemberInfo(this.ptr.add(0x330), "CBindingsArray<SBindingsEquipItemPortInfo>", 0x78),
            consumablePorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x3A8)).toObject() : typedMemberInfo(this.ptr.add(0x3A8), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            attachmentsPorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x728)).toObject() : typedMemberInfo(this.ptr.add(0x728), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            throwablePorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0xAA8)).toObject() : typedMemberInfo(this.ptr.add(0xAA8), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            startDraggingTrigger: typedMemberInfo(this.ptr.add(0xE28), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemStartDragging>", 0x30),
            stopDraggingTrigger: typedMemberInfo(this.ptr.add(0xE58), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemStopDragging>", 0x30),
            entity: componentPtrInfo(this.ptr.add(0xE88)),
            groundFocusEntity: componentPtrInfo(this.ptr.add(0xE90)),
            dragTargetIds: stdVectorRawInfo(this.ptr.add(0xE98))
        };
    }
}

class SBindingsPITInventoryHoveredCharacterItemInfo {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            portAnchorX: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableFloat", 0x80),
            portAnchorY: typedMemberInfo(this.ptr.add(0xC8), "CBindingsVariableFloat", 0x80),
            tooltipInfo: typedMemberInfo(this.ptr.add(0x148), "CBindingsVariableLocalization", 0x50),
            portKeyBindingInfo: typedMemberInfo(this.ptr.add(0x198), "CBindingsVariableLocalization", 0x50),
            craftedStats: typedMemberInfo(this.ptr.add(0x1E8), "CBindingsArray<InventoryGridCommons::SBindingsInventoryItemCraftedStat>", 0x78),
            enabled: typedMemberInfo(this.ptr.add(0x260), "CBindingsVariableBool", 0x48),
            itemBrickingStatus: typedMemberInfo(this.ptr.add(0x2A8), "CBindingsVariableInt", 0x50),
            itemTimerState: typedMemberInfo(this.ptr.add(0x2F8), "CBindingsVariableInt", 0x50),
            itemTimerEnd: typedMemberInfo(this.ptr.add(0x348), "CBindingsVariableInt", 0x50)
        };
    }
}

class SBindingsPITLootingFocusItem {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject() {
        return {
            ptr: this.ptr.toString(),
            displayPort: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            portAnchorX: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableFloat", 0x80),
            portAnchorY: typedMemberInfo(this.ptr.add(0x110), "CBindingsVariableFloat", 0x80),
            itemName: typedMemberInfo(this.ptr.add(0x190), "CBindingsVariableLocalization", 0x50),
            hologram: new SBindingsInventoryItemHologram(this.ptr.add(0x1E0)).toObject(),
            primaryActions: typedMemberInfo(this.ptr.add(0x478), "PIT looting action bindings", 0x488),
            item: componentPtrInfo(this.ptr.add(0x900))
        };
    }
}

class SBindingsPITLootPortContainerGroup {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            itemContainer: includeNested ? new SBindingsEquipItemPortInfo(this.ptr.add(0x48)).toObject(false) : typedMemberInfo(this.ptr.add(0x48), "SBindingsEquipItemPortInfo", InventoryManagementSurface.sizes.SBindingsEquipItemPortInfo),
            itemAttachments: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x1628)).toObject() : typedMemberInfo(this.ptr.add(0x1628), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            showItemPreview: typedMemberInfo(this.ptr.add(0x19A8), "CBindingsVariableBool", 0x48),
            attachmentsToggle: typedMemberInfo(this.ptr.add(0x19F0), "CBindingsTriggerBase", 0x30)
        };
    }
}

class SBindingsPITLootingArmour {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        const member = (offset, name) => includeNested ? new SBindingsPITLootPortContainerGroup(this.ptr.add(offset)).toObject(false) : typedMemberInfo(this.ptr.add(offset), name, InventoryManagementSurface.sizes.SBindingsPITLootPortContainerGroup);
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            helmet: member(0x90, "helmet"),
            core: member(0x1670, "core"),
            arms: member(0x2C50, "arms"),
            legs: member(0x4230, "legs")
        };
    }
}

class SBindingsPITLootingClothing {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        const member = (offset, name) => includeNested ? new SBindingsPITLootPortContainerGroup(this.ptr.add(offset)).toObject(false) : typedMemberInfo(this.ptr.add(offset), name, InventoryManagementSurface.sizes.SBindingsPITLootPortContainerGroup);
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            head: member(0x90, "head"),
            eyes: member(0x1670, "eyes"),
            torso: member(0x2C50, "torso"),
            legs: member(0x4230, "legs"),
            feet: member(0x5810, "feet"),
            hands: member(0x6DF0, "hands"),
            backpack: member(0x83D0, "backpack")
        };
    }
}

class SBindingsPITLootingStorage {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            backpack: includeNested ? new SBindingsPITLootPortContainerGroup(this.ptr.add(0x90)).toObject(false) : typedMemberInfo(this.ptr.add(0x90), "backpack", InventoryManagementSurface.sizes.SBindingsPITLootPortContainerGroup)
        };
    }
}

class SBindingsPITLootingSection {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        const port = (offset, name) => includeNested ? new SBindingsPITLootPortContainerGroup(this.ptr.add(offset)).toObject(false) : typedMemberInfo(this.ptr.add(offset), name, InventoryManagementSurface.sizes.SBindingsPITLootPortContainerGroup);
        return {
            ptr: this.ptr.toString(),
            lootConsumablePorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x48)).toObject() : typedMemberInfo(this.ptr.add(0x48), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            lootAttachmentsPorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x3C8)).toObject() : typedMemberInfo(this.ptr.add(0x3C8), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            lootThrowablePorts: includeNested ? new SBindingsEquipGroupItemPorts(this.ptr.add(0x748)).toObject() : typedMemberInfo(this.ptr.add(0x748), "SBindingsEquipGroupItemPorts", InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts),
            handHeld: port(0xAC8, "handHeld"),
            primaryWeapon: port(0x24E8, "primaryWeapon"),
            secondaryWeapon: port(0x3F08, "secondaryWeapon"),
            sidearmWeapon: port(0x5928, "sidearmWeapon"),
            gadget: port(0x7348, "gadget"),
            meleeWeapon: port(0x8D68, "meleeWeapon"),
            miningGadget: port(0xA788, "miningGadget"),
            undersuit: port(0xC1A8, "undersuit"),
            armourGroup: includeNested ? new SBindingsPITLootingArmour(this.ptr.add(0xD788)).toObject(false) : typedMemberInfo(this.ptr.add(0xD788), "SBindingsPITLootingArmour", InventoryManagementSurface.sizes.SBindingsPITLootingArmour),
            clothingGroup: includeNested ? new SBindingsPITLootingClothing(this.ptr.add(0x12F98)).toObject(false) : typedMemberInfo(this.ptr.add(0x12F98), "SBindingsPITLootingClothing", InventoryManagementSurface.sizes.SBindingsPITLootingClothing),
            storageGroup: includeNested ? new SBindingsPITLootingStorage(this.ptr.add(0x1C948)).toObject(false) : typedMemberInfo(this.ptr.add(0x1C948), "SBindingsPITLootingStorage", InventoryManagementSurface.sizes.SBindingsPITLootingStorage),
            showLootingConsumablePreview: typedMemberInfo(this.ptr.add(0x1DFB8), "CBindingsVariableBool", 0x48),
            showLootingAttachmentPreview: typedMemberInfo(this.ptr.add(0x1E000), "CBindingsVariableBool", 0x48),
            showLootingThrowablePreview: typedMemberInfo(this.ptr.add(0x1E048), "CBindingsVariableBool", 0x48),
            portContainerItems: typedMemberInfo(this.ptr.add(0x1E090), "CBindingsArray<SBindingsPITInventoryItem>", 0x78)
        };
    }
}

class SBindingsPITInventoryLooting {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            currentDisplayView: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableInt", 0x50),
            lootedHostilityReaction: typedMemberInfo(this.ptr.add(0xE0), "CBindingsVariableInt", 0x50),
            gameMode: typedMemberInfo(this.ptr.add(0x130), "CBindingsVariableInt", 0x50),
            playerEquipment: includeNested ? new SBindingsPITLootingSection(this.ptr.add(0x180)).toObject(false) : typedMemberInfo(this.ptr.add(0x180), "SBindingsPITLootingSection", InventoryManagementSurface.sizes.SBindingsPITLootingSection),
            lootedEntityEquipment: includeNested ? new SBindingsPITLootingSection(this.ptr.add(0x1E288)).toObject(false) : typedMemberInfo(this.ptr.add(0x1E288), "SBindingsPITLootingSection", InventoryManagementSurface.sizes.SBindingsPITLootingSection),
            focusItem: new SBindingsPITLootingFocusItem(this.ptr.add(0x3C390)).toObject(),
            lootingItemPreview: new SBindingsInventoryItemHologram(this.ptr.add(0x3CC98)).toObject(),
            repoolingTimestamp: typedMemberInfo(this.ptr.add(0x3CF30), "CBindingsVariableFloat", 0x50),
            repoolingDuration: typedMemberInfo(this.ptr.add(0x3CF80), "CBindingsVariableFloat", 0x48),
            isRepooling: typedMemberInfo(this.ptr.add(0x3CFC8), "CBindingsVariableBool", 0x48),
            repoolingStage: typedMemberInfo(this.ptr.add(0x3D010), "CBindingsVariableInt", 0x50),
            dragDropTarget: typedMemberInfo(this.ptr.add(0x3D060), "CBindingsVariableInt", 0x50),
            currentRollOverTarget: typedMemberInfo(this.ptr.add(0x3D0B0), "CBindingsVariableInt", 0x50),
            cursorScreenRelPos: typedMemberInfo(this.ptr.add(0x3D100), "CBindingsVariable<Vec2>", 0xD8),
            takeAllMagazineAttachments: typedMemberInfo(this.ptr.add(0x3D1D8), "CBindingsCustomTrigger<SCEvtNotify_OnTakeAllMagazineAttachments>", 0x30),
            magazineAttachmentsCanTakeAll: typedMemberInfo(this.ptr.add(0x3D208), "CBindingsVariableBool", 0x48),
            takeAllUtilityAttachments: typedMemberInfo(this.ptr.add(0x3D250), "CBindingsCustomTrigger<SCEvtNotify_OnTakeAllUtilityAttachments>", 0x30),
            utilityAttachmentsCanTakeAll: typedMemberInfo(this.ptr.add(0x3D280), "CBindingsVariableBool", 0x48),
            holsterUnavailable: typedMemberInfo(this.ptr.add(0x3D2C8), "CBindingsVariableBool", 0x48),
            toggleView: typedMemberInfo(this.ptr.add(0x3D310), "CBindingsTriggerBase", 0x30),
            requestInventoryView: typedMemberInfo(this.ptr.add(0x3D340), "CBindingsTriggerBase", 0x30),
            showAttachments: this.ptr.add(0x3D370).readU8() !== 0,
            enable: this.ptr.add(0x3D371).readU8() !== 0,
            userSelectedView: this.ptr.add(0x3D374).readS32()
        };
    }
}

class SBindingsPITInventoryItem {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            lootSlotState: includeNested ? new SBindingsLootItemSlotState(this.ptr.add(0x48)).toObject() : typedMemberInfo(this.ptr.add(0x48), "SBindingsLootItemSlotState", InventoryManagementSurface.sizes.SBindingsLootItemSlotState),
            quickEquipTrigger: typedMemberInfo(this.ptr.add(0x628), "CBindingsCustomTrigger<SCEvtNotify_OnQuickEquipLootItem>", 0x48)
        };
    }
}

class SBindingsPITInventoryGrid {
    constructor(ptrValue) { this.ptr = ptr(ptrValue); }
    toObject(includeNested = false) {
        return {
            ptr: this.ptr.toString(),
            dragEquipment: includeNested ? new SBindingsPITInventoryDragEquipment(this.ptr.add(0x48)).toObject(false) : typedMemberInfo(this.ptr.add(0x48), "SBindingsPITInventoryDragEquipment", InventoryManagementSurface.sizes.SBindingsPITInventoryDragEquipment),
            hoveredCharacterItem: new SBindingsPITInventoryHoveredCharacterItemInfo(this.ptr.add(0xEF8)).toObject(),
            portsToolTipEnabled: typedMemberInfo(this.ptr.add(0x1290), "CBindingsVariableBool", 0x48),
            requestLootingView: typedMemberInfo(this.ptr.add(0x12D8), "CBindingsTriggerBase", 0x30),
            requestChangeVersion: typedMemberInfo(this.ptr.add(0x1308), "CBindingsTriggerBase", 0x30)
        };
    }
}

class SBindingsInventoryContainerTab {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            title: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableLocalization", 0x50),
            iconPath: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableString", 0x50),
            tabIndex: this.ptr.add(0xE8).readS32(),
            highlightEntityId: readEntityId(this.ptr.add(0xF0))
        };
    }
}

class SBindingsInventoryItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            descData: new SBindingsInventoryItemDesc(this.ptr.add(0x60)).toObject(),
            dragItemTarget: typedMemberInfo(this.ptr.add(0x358), "CBindingsVariableInt", 0x50),
            name: typedMemberInfo(this.ptr.add(0x3A8), "CBindingsVariableLocalization", 0x50),
            tooltipDescription: typedMemberInfo(this.ptr.add(0x3F8), "CBindingsVariableLocalization", 0x50),
            displayName: typedMemberInfo(this.ptr.add(0x448), "CBindingsVariableBool", 0x48),
            itemDisplayThumbnail: typedMemberInfo(this.ptr.add(0x490), "CBindingsVariableString", 0x50),
            itemCount: typedMemberInfo(this.ptr.add(0x4E0), "CBindingsVariableLocalization", 0x50),
            itemsCount: typedMemberInfo(this.ptr.add(0x530), "CBindingsVariableInt", 0x50),
            order: typedMemberInfo(this.ptr.add(0x580), "CBindingsVariableInt", 0x50),
            hologram: new SBindingsInventoryItemHologram(this.ptr.add(0x5D0)).toObject(),
            isAttachment: typedMemberInfo(this.ptr.add(0x868), "CBindingsVariableBool", 0x48),
            isInventoryContainer: typedMemberInfo(this.ptr.add(0x8B0), "CBindingsVariableBool", 0x48),
            itemPersistence: new SBindingsInventoryItemPersistence(this.ptr.add(0x8F8)).toObject(),
            optionsMenu: new SBindingsInventoryItemMenuOptions(this.ptr.add(0xDC8)).toObject(),
            disabled: typedMemberInfo(this.ptr.add(0xF70), "CBindingsVariableBool", 0x48),
            highlightMoveAll: typedMemberInfo(this.ptr.add(0xFB8), "CBindingsVariableBool", 0x48),
            highlightQuickMoveInvalid: typedMemberInfo(this.ptr.add(0x1000), "CBindingsVariableBool", 0x48),
            capacityUsage: typedMemberInfo(this.ptr.add(0x1048), "CBindingsVariableFloat", 0x48),
            isDragging: typedMemberInfo(this.ptr.add(0x1090), "CBindingsVariableBool", 0x48),
            isCorpseLocked: typedMemberInfo(this.ptr.add(0x10D8), "CBindingsVariableBool", 0x48),
            weakenedType: typedMemberInfo(this.ptr.add(0x1120), "CBindingsVariableInt", 0x50),
            weakenedRatio: typedMemberInfo(this.ptr.add(0x1170), "CBindingsVariableFloat", 0x48),
            weaponType: typedMemberInfo(this.ptr.add(0x11B8), "CBindingsVariableInt", 0x50),
            useOnEquipmentSlot: typedMemberInfo(this.ptr.add(0x1208), "CBindingsVariableInt", 0x50),
            triggers: {
                options: typedMemberInfo(this.ptr.add(0x1258), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemShowOptions>", 0x48),
                startDragging: typedMemberInfo(this.ptr.add(0x12A0), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemStartDragging>", 0x30),
                stopDragging: typedMemberInfo(this.ptr.add(0x12D0), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemStopDragging>", 0x30),
                singleClickCheck: typedMemberInfo(this.ptr.add(0x1300), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryItemSingleClickCheck>", 0x48),
                clickOpenContainer: typedMemberInfo(this.ptr.add(0x1348), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryClickOpenContainer>", 0x48),
                quickMoveRollOn: typedMemberInfo(this.ptr.add(0x1390), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryQuickMoveRollOver>", 0x48),
                quickMoveRollOff: typedMemberInfo(this.ptr.add(0x13D8), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryQuickMoveRollOver>", 0x48)
            },
            capacity: this.ptr.add(0x1420).readS64().toString(),
            itemOccupancyAbs: this.ptr.add(0x1428).readS64().toString(),
            occupancyFormatted: readCLocString(this.ptr.add(0x1430)),
            detailedDescription: readCLocString(this.ptr.add(0x1438)),
            isItemExpiryItem: this.ptr.add(0x1440).readU8() !== 0,
            itemExpiryEndTime: this.ptr.add(0x1448).readS64().toString(),
            classCRC: this.ptr.add(0x1450).readU32(),
            missionGuid: readCryGuid(this.ptr.add(0x1458)),
            inventoryId: new SInventoryId(this.ptr.add(0x1468)).toObject(),
            rank: readCryStringHandle(this.ptr.add(0x1480)),
            belongsToPlayer: this.ptr.add(0x1488).readU8() !== 0
        };
    }
}

class SBindingsInventoryPopBox {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            message: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableLocalization", 0x50),
            acceptButtonText: typedMemberInfo(this.ptr.add(0xE0), "CBindingsVariableLocalization", 0x50),
            cancelButtonText: typedMemberInfo(this.ptr.add(0x130), "CBindingsVariableLocalization", 0x50),
            acceptActionTrigger: typedMemberInfo(this.ptr.add(0x180), "CBindingsCustomTrigger<SCEvtControl_OnInventoryPopUpAction>", 0x30),
            cancelActionTrigger: typedMemberInfo(this.ptr.add(0x1B0), "CBindingsCustomTrigger<SCEvtControl_OnInventoryPopUpAction>", 0x30)
        };
    }
}

class SBindingsInventoryContainerTabMenu {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            tabs: typedMemberInfo(this.ptr.add(0x90), "CBindingsArray<SBindingsInventoryContainerTab>", 0x78),
            selectedIndex: typedMemberInfo(this.ptr.add(0x108), "CBindingsVariableInt", 0x50),
            hoverIndex: typedMemberInfo(this.ptr.add(0x158), "CBindingsVariableInt", 0x50),
            previousTabTrigger: typedMemberInfo(this.ptr.add(0x1A8), "CBindingsTriggerBase", 0x28),
            nextTabTrigger: typedMemberInfo(this.ptr.add(0x1D0), "CBindingsTriggerBase", 0x28)
        };
    }
}

class SBindingsInventorySection {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            containers: typedMemberInfo(this.ptr.add(0x48), "CBindingsArray<SBindingsInventoryContainer>", 0x78),
            inventoryTabsMenu: new SBindingsInventoryContainerTabMenu(this.ptr.add(0xC0)).toObject(),
            tabsMenu: new SBindingsInventoryContainerTabMenu(this.ptr.add(0x2B8)).toObject(),
            searchBarTextInput: typedMemberInfo(this.ptr.add(0x4B0), "CBindingsVariableString", 0x50),
            applySearchTrigger: typedMemberInfo(this.ptr.add(0x500), "CBindingsTriggerWithIndex", 0x30),
            lastSearchText: readCryStringHandle(this.ptr.add(0x530)),
            isLeftSection: this.ptr.add(0x538).readU8() !== 0
        };
    }
}

class InventoryGridCommonsSBindingsTooltipData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            tooltipEnabled: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableBool", 0x48),
            currentTooltip: typedMemberInfo(this.ptr.add(0x90), "CBindingsVariableLocalization", 0x50),
            currentComparableTooltip: typedMemberInfo(this.ptr.add(0xE0), "CBindingsVariableLocalization", 0x50),
            tooltipCraftedStats: typedMemberInfo(this.ptr.add(0x130), "CBindingsArray<InventoryGridCommons::SBindingsInventoryItemCraftedStat>", 0x78),
            currentResourceCapacity: typedMemberInfo(this.ptr.add(0x1A8), "CBindingsVariableInt", 0x50),
            currentResourceContents: typedMemberInfo(this.ptr.add(0x1F8), "CBindingsArray<SBindingsInventoryItemResourceContents>", 0x78),
            itemBrickingStatus: typedMemberInfo(this.ptr.add(0x270), "CBindingsVariableInt", 0x50),
            itemTimerState: typedMemberInfo(this.ptr.add(0x2C0), "CBindingsVariableInt", 0x50),
            itemTimerEnd: typedMemberInfo(this.ptr.add(0x310), "CBindingsVariableInt", 0x50),
            tooltipAlignment: typedMemberInfo(this.ptr.add(0x360), "CBindingsVariableInt", 0x50),
            tooltipSrc: this.ptr.add(0x3B0).readPointer().toString()
        };
    }
}

class SBindingsInventoryGridData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject(includeSections = false) {
        return {
            ptr: this.ptr.toString(),
            display: typedMemberInfo(this.ptr.add(0x60), "CBindingsVariableBool", 0x48),
            playerSection: includeSections ? new SBindingsInventorySection(this.ptr.add(0xA8)).toObject() : typedMemberInfo(this.ptr.add(0xA8), "SBindingsInventorySection", InventoryManagementSurface.sizes.SBindingsInventorySection),
            externalSection: includeSections ? new SBindingsInventorySection(this.ptr.add(0x5E8)).toObject() : typedMemberInfo(this.ptr.add(0x5E8), "SBindingsInventorySection", InventoryManagementSurface.sizes.SBindingsInventorySection),
            capacityBarTitle: typedMemberInfo(this.ptr.add(0xB28), "CBindingsVariableLocalization", 0x50),
            currentDragContainerId: typedMemberInfo(this.ptr.add(0xB78), "CBindingsVariableInt", 0x50),
            currentOrderIndex: typedMemberInfo(this.ptr.add(0xBC8), "CBindingsVariableInt", 0x50),
            dragMovementResult: typedMemberInfo(this.ptr.add(0xC18), "CBindingsVariableInt", 0x50),
            inventoryGeoTag: typedMemberInfo(this.ptr.add(0xC68), "CBindingsVariableString", 0x50),
            tooltipEnabled: typedMemberInfo(this.ptr.add(0xCB8), "CBindingsVariableBool", 0x48),
            dragDropTarget: typedMemberInfo(this.ptr.add(0xD00), "CBindingsVariableInt", 0x50),
            dropTooltip: typedMemberInfo(this.ptr.add(0xD50), "CBindingsVariableLocalization", 0x50),
            isDragging: typedMemberInfo(this.ptr.add(0xDA0), "CBindingsVariableBool", 0x48),
            cameraFocus: typedMemberInfo(this.ptr.add(0xDE8), "CBindingsVariableFloat", 0x48),
            weightRatio: typedMemberInfo(this.ptr.add(0xE30), "CBindingsVariableFloat", 0x48),
            settingsSelected: typedMemberInfo(this.ptr.add(0xE78), "CBindingsVariableBool", 0x48),
            tooltipData: new InventoryGridCommonsSBindingsTooltipData(this.ptr.add(0xEC0)).toObject(),
            backTrigger: typedMemberInfo(this.ptr.add(0x1278), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryBackAction>", 0x30),
            armorCapacityUnits: readCLocString(this.ptr.add(0x12A8)),
            gridCellPixelSize: this.ptr.add(0x12B0).readFloat(),
            dropBlocked: this.ptr.add(0x12B4).readU8() !== 0
        };
    }
}

class SBindingsInventoryContainer {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() { return new SInventoryId(this.ptr.add(0x1450)); }
    get parentInventoryId() { return new SInventoryId(this.ptr.add(0x1468)); }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            inventoryId: this.inventoryId.toObject(),
            parentInventoryId: this.parentInventoryId.toObject(),
            dimensions: readVec3f(this.ptr.add(0x1480)),
            gridCellPixelSize: this.ptr.add(0x148C).readFloat(),
            usedCapacityAbs: this.ptr.add(0x1490).readS64().toString(),
            typeOrderPriority: this.ptr.add(0x1498).readS32(),
            type: this.ptr.add(0x149C).readS32(),
            listOfItems: typedMemberInfo(this.ptr.add(0x48), "CBindingsArray<SBindingsInventoryItem>", 0x78),
            pageSelection: typedMemberInfo(this.ptr.add(0x618), "CBindingsArray<CBindingsVariableBool>", 0x78),
            itemFilters: new SBindingsInventoryItemFilter(this.ptr.add(0x720)).toObject(),
            filterView: typedMemberInfo(this.ptr.add(0x930), "InventoryGridCommons::SBindings_FilterView"),
            sortView: typedMemberInfo(this.ptr.add(0xAD8), "InventoryGridCommons::SBindings_SortView"),
            itemHoverCraftedStats: typedMemberInfo(this.ptr.add(0xE48), "CBindingsArray<InventoryGridCommons::SBindingsInventoryItemCraftedStat>", 0x78),
            itemHoverResourceContents: typedMemberInfo(this.ptr.add(0xF58), "CBindingsArray<SBindingsInventoryItemResourceContents>", 0x78),
            invalidMoveData: new SBindingsInventoryInvalidMoveData(this.ptr.add(0x1020)).toObject(),
            triggers: {
                closeContainer: typedMemberInfo(this.ptr.add(0x1198), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryCloseInventory>", 0x40),
                enterContainer: typedMemberInfo(this.ptr.add(0x11D8), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryCursorEnterContainer>", 0x48),
                leaveContainer: typedMemberInfo(this.ptr.add(0x1220), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryCursorEnterContainer>", 0x48),
                requestNextPage: typedMemberInfo(this.ptr.add(0x1268), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryRequestPageChange>", 0x48),
                requestPreviousPage: typedMemberInfo(this.ptr.add(0x12B0), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryRequestPageChange>", 0x48),
                requestFullSort: typedMemberInfo(this.ptr.add(0x12F8), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryRequestFullSort>", 0x40),
                moveAll: typedMemberInfo(this.ptr.add(0x1338), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryMoveAll>", 0x48),
                stackAll: typedMemberInfo(this.ptr.add(0x1380), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryStackAll>", 0x40),
                moveAllRollOn: typedMemberInfo(this.ptr.add(0x13C0), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryMoveAllRollOver>", 0x48),
                moveAllRollOff: typedMemberInfo(this.ptr.add(0x1408), "CBindingsCustomTrigger<SCEvtNotify_OnInventoryMoveAllRollOver>", 0x48)
            },
            bindings: {
                dragContainerId: typedMemberInfo(this.ptr.add(0xC0), "CBindingsVariableInt", 0x50),
                display: typedMemberInfo(this.ptr.add(0x110), "CBindingsVariableBool", 0x48),
                loading: typedMemberInfo(this.ptr.add(0x158), "CBindingsVariableBool", 0x48),
                name: typedMemberInfo(this.ptr.add(0x1A0), "CBindingsVariableLocalization", 0x50),
                maxCapacity: typedMemberInfo(this.ptr.add(0x1F0), "CBindingsVariableInt", 0x50),
                capacityUsage: typedMemberInfo(this.ptr.add(0x240), "CBindingsVariableFloat", 0x48),
                atFullCapacity: typedMemberInfo(this.ptr.add(0x288), "CBindingsVariableBool", 0x48),
                selectedItemIndex: typedMemberInfo(this.ptr.add(0x3B0), "CBindingsVariableInt", 0x50),
                hoverItemIndex: typedMemberInfo(this.ptr.add(0x400), "CBindingsVariableInt", 0x50),
                hasNextPage: typedMemberInfo(this.ptr.add(0x4E8), "CBindingsVariableBool", 0x48),
                hasPreviousPage: typedMemberInfo(this.ptr.add(0x530), "CBindingsVariableBool", 0x48),
                currentPage: typedMemberInfo(this.ptr.add(0x578), "CBindingsVariableInt", 0x50),
                totalPages: typedMemberInfo(this.ptr.add(0x5C8), "CBindingsVariableInt", 0x50),
                itemHoverTooltip: typedMemberInfo(this.ptr.add(0xCC0), "CBindingsVariableLocalization", 0x50),
                comparableItemTooltip: typedMemberInfo(this.ptr.add(0xFD0), "CBindingsVariableLocalization", 0x50)
            }
        };
    }
}

class CSCInventoryDisplay {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() { return this.ptr.readPointer(); }
    get inventoryItemMenu() { return new SInventoryId(this.ptr.add(0x18F8)); }

    vfuncAddress(slot) {
        return this.vtable.add(slot * Process.pointerSize).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            controllerEntity: this.ptr.add(0x08).readPointer().toString(),
            actor: componentPtrInfo(this.ptr.add(0x10)),
            inventoryGridData: new SBindingsInventoryGridData(this.ptr.add(0x18)).toObject(false),
            displayV4: typedMemberInfo(this.ptr.add(0x12D0), "CBindingsVariableBool", 0x48),
            enableV4: typedMemberInfo(this.ptr.add(0x1318), "CBindingsVariableBool", 0x48),
            exitButtonAction: typedMemberInfo(this.ptr.add(0x1360), "SBindingsInventoryAction<SCEvtNotify_OnInventoryExitAction>", 0x1B0),
            inventoryDisplayState: typedMemberInfo(this.ptr.add(0x1510), "CBindingsVariableInt", 0x50),
            popUpBox: new SBindingsInventoryPopBox(this.ptr.add(0x1560)).toObject(),
            settingsButtonAction: typedMemberInfo(this.ptr.add(0x1740), "SBindingsInventoryAction<SCEvtNotify_OnInventorySettingsAction>", 0x1B0),
            inventoryDragTargetId: this.ptr.add(0x18F0).readS32(),
            inventoryItemMenu: this.inventoryItemMenu.toObject(),
            inventoryEnabled: this.ptr.add(0x1910).readU8() !== 0,
            defaultItemThumbnail: readCryStringHandle(this.ptr.add(0x1918)),
            selectedItem: this.ptr.add(0x1920).readS32(),
            potentialQuickMove: {
                inventoryItem: this.ptr.add(0x1928).readS32(),
                inventoryId: new SInventoryId(this.ptr.add(0x1930)).toObject(),
                isPlayerInventory: this.ptr.add(0x1948).readU8() !== 0
            },
            leftShiftPressed: this.ptr.add(0x1950).readU8() !== 0,
            rightAltPressed: this.ptr.add(0x1951).readU8() !== 0,
            bindingTarget: componentPtrInfo(this.ptr.add(0x1958)),
            bindingsVendor: componentPtrInfo(this.ptr.add(0x1960))
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CSCInventoryDisplay,
            offsets: InventoryManagementSurface.cscInventoryDisplayOffsets,
            vtableSlots: InventoryManagementSurface.cscInventoryDisplayVtable,
            addresses: vtableAddressMap(this, InventoryManagementSurface.cscInventoryDisplayVtable)
        };
    }
}

class InventoryGridCommonsCSCBaseInventoryGrid {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() { return this.ptr.readPointer(); }

    vfuncAddress(slot) {
        return this.vtable.add(slot * Process.pointerSize).readPointer();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            eventsTargetEntityPtr: this.ptr.add(0x08).readPointer().toString(),
            lastRequestTimeStamp: this.ptr.add(0x10).readS64().toString(),
            lastRequestCompleteTimeStamp: this.ptr.add(0x18).readS64().toString(),
            requestInventoryDataTimeStamp: stdMapInfo(this.ptr.add(0x20)),
            recentRequestElapsedTimes: eastlDequeInfo(this.ptr.add(0x30)),
            excludedItemTypes: eastlMapInfo(this.ptr.add(0x88)),
            personalInventoryContainers: typedMemberInfo(this.ptr.add(0xB8), "LockedMap<SInventoryId,InventoryGridCommons::SPersonalThoughtInventoryContainer>", 0x38),
            inventoryManagementLock: typedMemberInfo(this.ptr.add(0xF0), "CIGCriticalSection", InventoryManagementSurface.sizes.CIGCriticalSection),
            inventoryMoves: typedMemberInfo(this.ptr.add(0x110), "LockedDeque<InventoryGridCommons::SInventoryMove>", 0x50),
            actor: componentPtrInfo(this.ptr.add(0x160)),
            player: componentPtrInfo(this.ptr.add(0x168)),
            playerEntityId: readEntityId(this.ptr.add(0x170)),
            missionLog: this.ptr.add(0x178).readPointer().toString(),
            configDef: this.ptr.add(0x180).readPointer().toString(),
            inventorySectionLock: typedMemberInfo(this.ptr.add(0x188), "CIGCriticalSection", InventoryManagementSurface.sizes.CIGCriticalSection),
            eventsTargetComponentPtr: componentPtrInfo(this.ptr.add(0x1A8)),
            pendingLocationInventoryQuery: this.ptr.add(0x1B0).readU8() !== 0,
            pendingVehicleInventoryQuery: this.ptr.add(0x1B1).readU8() !== 0,
            locationInventoryQueryRetries: this.ptr.add(0x1B4).readS32(),
            vehicleInventoryQueryRetries: this.ptr.add(0x1B8).readS32(),
            entityInventoryQueryRetries: stdMapInfo(this.ptr.add(0x1C0))
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.InventoryGridCommons_CSCBaseInventoryGrid,
            offsets: InventoryManagementSurface.inventoryGridCommonsBaseInventoryGridOffsets,
            vtableSlots: InventoryManagementSurface.inventoryGridCommonsBaseInventoryGridVtable,
            addresses: vtableAddressMap(this, InventoryManagementSurface.inventoryGridCommonsBaseInventoryGridVtable)
        };
    }
}

class SCFreightKioskInventoryGrid extends InventoryGridCommonsCSCBaseInventoryGrid {
    surface() {
        const base = super.surface();
        return {
            ...base,
            size: InventoryManagementSurface.sizes.SCFreightKioskInventoryGrid,
            className: "SCFreightKioskInventoryGrid"
        };
    }
}

class SBindingsFreightElevatorUI {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            leftViewIndex: typedMemberInfo(this.ptr.add(0x48), "CBindingsVariableInt", 0x50),
            rightViewIndex: typedMemberInfo(this.ptr.add(0x98), "CBindingsVariableInt", 0x50),
            viewList: typedMemberInfo(this.ptr.add(0xE8), "CBindingsArray<SBindings_InventoryView>", 0x78),
            exitKiosk: typedMemberInfo(this.ptr.add(0x160), "CBindingsTriggerWithIndex", 0x30),
            hangarServiceOpen: typedMemberInfo(this.ptr.add(0x190), "CBindingsVariableBool", 0x48),
            hangarServiceView: typedMemberInfo(this.ptr.add(0x1D8), "SBindings_HangarServiceModalView", 0x538),
            loadingMessage: typedMemberInfo(this.ptr.add(0x710), "CBindingsVariableBool", 0x48),
            loadingMessageState: typedMemberInfo(this.ptr.add(0x758), "CBindingsVariableInt", 0x50),
            showItemBankView: typedMemberInfo(this.ptr.add(0x7A8), "CBindingsVariableBool", 0x48),
            useTooltipFullDescription: typedMemberInfo(this.ptr.add(0x7F0), "CBindingsVariableBool", 0x48),
            inventoryGeoTag: typedMemberInfo(this.ptr.add(0x838), "CBindingsVariableString", 0x50),
            currentDragContainerId: typedMemberInfo(this.ptr.add(0x888), "CBindingsVariableInt", 0x50),
            currentDragXPos: typedMemberInfo(this.ptr.add(0x8D8), "CBindingsVariableFloat", 0x48),
            currentDragYPos: typedMemberInfo(this.ptr.add(0x920), "CBindingsVariableFloat", 0x48),
            generalPopup: typedMemberInfo(this.ptr.add(0x968), "CBindingsVariableBool", 0x48),
            popupType: typedMemberInfo(this.ptr.add(0x9B0), "CBindingsVariableInt", 0x50),
            closePopupTrigger: typedMemberInfo(this.ptr.add(0xA00), "CBindingsTriggerWithIndex", 0x30),
            buttonPopupTrigger: typedMemberInfo(this.ptr.add(0xA30), "CBindingsTriggerWithIndex", 0x30),
            capacityOverload: typedMemberInfo(this.ptr.add(0xA60), "CBindingsVariableInt", 0x50),
            popupItemList: typedMemberInfo(this.ptr.add(0xAB0), "CBindingsArray<SBindings_GeneralPopUpItem>", 0x78),
            popupMessage: typedMemberInfo(this.ptr.add(0xB28), "CBindingsVariableLocalization", 0x50),
            searchBarTextInput: typedMemberInfo(this.ptr.add(0xB78), "CBindingsVariableString", 0x50),
            applySearchTrigger: typedMemberInfo(this.ptr.add(0xBC8), "CBindingsTriggerWithIndex", 0x30),
            kioskName: typedMemberInfo(this.ptr.add(0xBF8), "CBindingsVariableLocalization", 0x50),
            itemKeyAccumulator: typedMemberInfo(this.ptr.add(0xC48), "SKeyAccumulator", 0x08),
            popUpOnCloseWithButtonContext: this.ptr.add(0xC50).readS32(),
            defaultBindingTarget: componentPtrInfo(this.ptr.add(0xC58)),
            defaultBindingsVendor: componentPtrInfo(this.ptr.add(0xC60)),
            initialDropTargetId: this.ptr.add(0xC68).readU16(),
            missionItemData: stdVectorRawInfo(this.ptr.add(0xC70)),
            dropIdCounter: this.ptr.add(0xC88).readU64().toString(),
            rightViewHistoric: stdVectorRawInfo(this.ptr.add(0xC90)),
            leftViewHistoric: stdVectorRawInfo(this.ptr.add(0xCA8))
        };
    }
}

class CEntityComponentFreightElevatorUIProviderSClientData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            interactorId: readEntityId(this.ptr),
            state: this.ptr.add(0x08).readS32(),
            localRequest: new SFreightElevatorRequest(this.ptr.add(0x10)).toObject(),
            externalInventoryId: new SInventoryId(this.ptr.add(0xA0)).toObject(),
            bindingTarget: componentPtrInfo(this.ptr.add(0xB8)),
            bindingsVendor: componentPtrInfo(this.ptr.add(0xC0))
        };
    }
}

class CEntityComponentFreightElevatorUIProvider {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            freightElevatorUI: new SBindingsFreightElevatorUI(this.ptr.add(0x48)).toObject(),
            freightKioskInventoryGrid: new SCFreightKioskInventoryGrid(this.ptr.add(0xD08)).toObject(),
            clientData: new CEntityComponentFreightElevatorUIProviderSClientData(this.ptr.add(0xED8)).toObject(),
            kioskWarehouseLocationId: typedMemberInfo(this.ptr.add(0xFA0), "CSerializedVariable<unsigned int>", 0x10),
            latestUserId: typedMemberInfo(this.ptr.add(0xFB0), "CSerializedVariable<EntityId>", 0x10),
            kioskOwnerId: readEntityId(this.ptr.add(0xFC0)),
            platform: componentPtrInfo(this.ptr.add(0xFC8)),
            platformEntityId: readEntityId(this.ptr.add(0xFD0)),
            clientRequest: typedMemberInfo(this.ptr.add(0xFD8), "CSerializedVariable<SFreightElevatorRequest>", 0x98),
            authorityState: typedMemberInfo(this.ptr.add(0x1070), "CSerializedVariable<SEFreightElevatorKioskServerStateHelper>", 0x18),
            authorityRequestResponse: typedMemberInfo(this.ptr.add(0x1088), "CSerializedVariable<SRequestResponse>", 0x18),
            token: typedMemberInfo(this.ptr.add(0x10A0), "CSerializedToken", 0x10),
            remoteMethods: {
                authoritySplitItemStack: typedMemberInfo(this.ptr.add(0x10B0), "CSerializedRemoteMethod<AuthoritySplitItemStack>", 0x20),
                tokenSplitItemStackResult: typedMemberInfo(this.ptr.add(0x10D0), "CSerializedRemoteMethod<TokenSplitItemStackResult>", 0x20),
                authorityMoveItemStack: typedMemberInfo(this.ptr.add(0x10F0), "CSerializedRemoteMethod<AuthorityMoveItemStack>", 0x20),
                tokenMoveItemStackResult: typedMemberInfo(this.ptr.add(0x1110), "CSerializedRemoteMethod<TokenMoveItemStackResult>", 0x20),
                authorityRequestRetrieveItems: typedMemberInfo(this.ptr.add(0x1130), "CSerializedRemoteMethod<AuthorityRequestRetrieveItems>", 0x20)
            },
            futureHandles: {
                fillMissionItems: this.ptr.add(0x1188).readU64().toString(),
                deletionRequest: this.ptr.add(0x1198).readU64().toString(),
                missionOrderRequest: this.ptr.add(0x11A8).readU64().toString(),
                currentRequest: this.ptr.add(0x11B8).readU64().toString()
            },
            pendingDeletionRequests: eastlMapInfo(this.ptr.add(0x11C8)),
            pendingMissionOrderRequests: stdMapInfo(this.ptr.add(0x11E0)),
            isRecoveringFromBadState: typedMemberInfo(this.ptr.add(0x11F0), "CSerializedVariable<bool>", 0x10),
            badStateRecoveryData: typedMemberInfo(this.ptr.add(0x1200), "BadStateRecoveryData", InventoryManagementSurface.sizes.CEntityComponentFreightElevatorUIProvider_BadStateRecoveryData)
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CEntityComponentFreightElevatorUIProvider,
            offsets: InventoryManagementSurface.freightElevatorUIProviderOffsets
        };
    }
}

class CPlayerAssetManagerProvider {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            remoteMethods: {
                requestInventoryLocationCollection: typedMemberInfo(this.ptr.add(0x48), "CSerializedRemoteMethod<RequestInventoryLocationCollection>", 0x20),
                requestInventoryId: typedMemberInfo(this.ptr.add(0x68), "CSerializedRemoteMethod<RequestInventoryId>", 0x20),
                handleRequestInventoryLocationCallback: typedMemberInfo(this.ptr.add(0x88), "CSerializedRemoteMethod<HandleRequestInventoryLocationCallback>", 0x20),
                handleRequestInventoryIdCallback: typedMemberInfo(this.ptr.add(0xA8), "CSerializedRemoteMethod<HandleRequestInventoryIdCallback>", 0x20)
            },
            listOfInventoryLocations: typedMemberInfo(this.ptr.add(0xC8), "CBindingsArray<SBindingsInventory_Locations>", 0x78),
            directoryTreeSelectedIndex: typedMemberInfo(this.ptr.add(0x140), "CBindingsVariableInt", 0x50),
            assetListSelectedIndex: typedMemberInfo(this.ptr.add(0x190), "CBindingsVariableInt", 0x50),
            listOfInventoryLocationsExpanded: typedMemberInfo(this.ptr.add(0x1E0), "CBindingsVariableBool", 0x48),
            assetFilterCategoryDropdownList: typedMemberInfo(this.ptr.add(0x228), "CBindingsArray<SBindingsInventory_FilterCategories>", 0x78),
            assetFilterTypeDropdownList: typedMemberInfo(this.ptr.add(0x2A0), "CBindingsArray<SBindingsInventory_FilterType>", 0x78),
            assetFilterCategorySelectedIndex: typedMemberInfo(this.ptr.add(0x318), "CBindingsVariableInt", 0x50),
            assetFilterTypeSelectedIndex: typedMemberInfo(this.ptr.add(0x368), "CBindingsVariableInt", 0x50),
            assetFilterCategoryExpanded: typedMemberInfo(this.ptr.add(0x3B8), "CBindingsVariableBool", 0x48),
            assetFilterTypeExpanded: typedMemberInfo(this.ptr.add(0x400), "CBindingsVariableBool", 0x48),
            assetFilterCategoryClearTrigger: typedMemberInfo(this.ptr.add(0x448), "CBindingsTriggerBase", 0x28),
            assetFilterTypeClearTrigger: typedMemberInfo(this.ptr.add(0x470), "CBindingsTriggerBase", 0x28),
            assetList: typedMemberInfo(this.ptr.add(0x498), "SBindingsInventory_AssetList", InventoryManagementSurface.sizes.CPlayerAssetManagerProvider_SBindingsInventory_AssetList),
            selectedAsset: typedMemberInfo(this.ptr.add(0x7A0), "SBindingsInventory_AssetItem", 0x5E0),
            assetListLoading: typedMemberInfo(this.ptr.add(0xD80), "CBindingsVariableBool", 0x48),
            searchInput: typedMemberInfo(this.ptr.add(0xDC8), "CBindingsVariableString", 0x50),
            locationsLoading: typedMemberInfo(this.ptr.add(0xE18), "CBindingsVariableBool", 0x48),
            showFilters: typedMemberInfo(this.ptr.add(0xE60), "CBindingsVariableBool", 0x48),
            prevPage: typedMemberInfo(this.ptr.add(0xEA8), "CBindingsTriggerBase", 0x28),
            showPrevPage: typedMemberInfo(this.ptr.add(0xED0), "CBindingsVariableBool", 0x48),
            nextPage: typedMemberInfo(this.ptr.add(0xF18), "CBindingsTriggerBase", 0x28),
            showNextPage: typedMemberInfo(this.ptr.add(0xF40), "CBindingsVariableBool", 0x48),
            directoryTree: stdMapInfo(this.ptr.add(0xF88)),
            activeFilter: stdVectorRawInfo(this.ptr.add(0xF98)),
            futureHandles: {
                legallyOwnedVehiclesRequest: this.ptr.add(0xFB0).readU64().toString(),
                inventoryAsyncRequest: this.ptr.add(0xFC0).readU64().toString(),
                shipLocationsRequest: this.ptr.add(0xFD0).readU64().toString()
            },
            awaitingLocationsQueryResponse: this.ptr.add(0xFE0).readU8() !== 0,
            awaitingInventoryIdQueryResponse: this.ptr.add(0xFE1).readU8() !== 0,
            awaitingShipQueryResponse: this.ptr.add(0xFE2).readU8() !== 0,
            awaitingPersonalInventoryQueryResponse: this.ptr.add(0xFE3).readU8() !== 0,
            userEntity: this.ptr.add(0xFE8).readPointer().toString(),
            pageInfo: stdVectorRawInfo(this.ptr.add(0xFF0)),
            nextAvailableDirectoryID: this.ptr.add(0x1008).readS32(),
            currentOpenDirectory: this.ptr.add(0x100C).readS32(),
            savedInventoryIdPageRequest: new SPaginationArguments(this.ptr.add(0x1010)).toObject(),
            assetManagerSessionId: this.ptr.add(0x1030).readU32(),
            itemTypeDef: new DataCoreRecordRef(this.ptr.add(0x1038), "SItemTypeDefinition").toObject(),
            legacyEventSystem: typedMemberInfo(this.ptr.add(0x1050), "ILegacyEventSystem", InventoryManagementSurface.sizes.ILegacyEventSystem)
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CPlayerAssetManagerProvider,
            offsets: InventoryManagementSurface.playerAssetManagerProviderOffsets
        };
    }
}

class CSCPersonalThoughtDisplay extends CSCInventoryDisplay {
    toObject(includeNested = false) {
        return {
            ...super.toObject(),
            lootingData: new SBindingsPITInventoryLooting(this.ptr.add(0x19C0)).toObject(includeNested),
            focusedLootItem: typedMemberInfo(this.ptr.add(0x3ED38), "CSCPersonalThoughtDisplay::SLootItemFocus", 0x58),
            dragTargetIds: stdVectorRawInfo(this.ptr.add(0x3ED90)),
            pendingPrimaryActionSelection: this.ptr.add(0x3EDA8).readS32(),
            lastAmmoRepoolOperation: typedMemberInfo(this.ptr.add(0x3EDB0), "eastl::optional<CigVariant<AmmoRepoolOperation>>", 0x98),
            oldRepoolSourceBindings: this.ptr.add(0x3EE48).readPointer().toString(),
            oldRepoolTargetBindings: this.ptr.add(0x3EE50).readPointer().toString(),
            lootingPortsMap: stdMapInfo(this.ptr.add(0x3EE58)),
            usedCapacityAbs: this.ptr.add(0x3EE68).readS32(),
            secondarySelectionIndex: this.ptr.add(0x3EE6C).readS32(),
            listOfItems: stdVectorRawInfo(this.ptr.add(0x3EE70)),
            displayAllItemPorts: this.ptr.add(0x3EE88).readU8() !== 0,
            displayingAllItemPorts: this.ptr.add(0x3EE89).readU8() !== 0,
            configDef: this.ptr.add(0x3EE90).readPointer().toString(),
            cameraConfig: this.ptr.add(0x3EE98).readPointer().toString(),
            legacyEventSystem: typedMemberInfo(this.ptr.add(0x3EEA0), "ILegacyEventSystem", InventoryManagementSurface.sizes.ILegacyEventSystem)
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CSCPersonalThoughtDisplay,
            offsets: InventoryManagementSurface.personalThoughtDisplayOffsets,
            inventoryDisplay: super.surface()
        };
    }
}

class SelectedInventoryThoughtOption {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get text() {
        return this.ptr.readU32();
    }

    get description() {
        return readCLocString(this.ptr.add(0x08));
    }

    get enabled() {
        return this.ptr.add(0x10).readU8() !== 0;
    }

    get name() {
        return readCryStringHandle(this.ptr.add(0x18));
    }

    get arg() {
        return this.ptr.add(0x20).readS32();
    }

    get callback() {
        return new StdFunction(
            this.ptr.add(0x28),
            "void(InventoryGridCommons::SInventoryGridThoughtOption&, InventoryGridCommons::SSelectedInventoryThoughtOption&)"
        );
    }

    get itemPtr() {
        return lower48(this.ptr.add(0x68).readPointer());
    }

    get postSelectAction() {
        return this.ptr.add(0x70).readS32();
    }

    get interactionPointId() {
        return new InteractionPointId(this.ptr.add(0x78));
    }

    get interactionNameHash() {
        return new CStringHash(this.ptr.add(0x90));
    }

    get userInput() {
        return this.ptr.add(0xA8).readU8() !== 0;
    }

    get minAmount() {
        return this.ptr.add(0xAC).readS32();
    }

    get maxAmount() {
        return this.ptr.add(0xB0).readS32();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            text: this.text,
            description: this.description,
            enabled: this.enabled,
            name: this.name,
            arg: this.arg,
            callback: this.callback.toObject(),
            itemPtr: this.itemPtr.toString(),
            postSelectAction: this.postSelectAction,
            interactionPointId: this.interactionPointId.toObject(),
            interactionNameHash: this.interactionNameHash.toObject(),
            userInput: this.userInput,
            minAmount: this.minAmount,
            maxAmount: this.maxAmount
        };
    }
}

class InventoryGridThoughtOption {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemData() {
        return new InventoryItemData(this.ptr);
    }

    get itemSecondaryActions() {
        return new StdVector(
            this.ptr.add(0x168),
            InventoryManagementSurface.sizes.InventoryGridCommons_SSelectedInventoryThoughtOption,
            SelectedInventoryThoughtOption
        );
    }

    toObject(includeActions = false) {
        return {
            itemData: this.itemData.toObject(),
            itemSecondaryActions: includeActions
                ? this.itemSecondaryActions.toArray(32).map(action => action.toObject())
                : this.itemSecondaryActions.toSummary()
        };
    }
}

class PersonalThoughtInventoryLocalPageInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get startIndex() {
        return this.ptr.readS32();
    }

    get hasNextPage() {
        return this.ptr.add(0x04).readU8() !== 0;
    }

    get hasPreviousPage() {
        return this.ptr.add(0x05).readU8() !== 0;
    }

    get currentPage() {
        return this.ptr.add(0x08).readS32();
    }

    get totalPages() {
        return this.ptr.add(0x0C).readS32();
    }

    toObject() {
        return {
            startIndex: this.startIndex,
            hasNextPage: this.hasNextPage,
            hasPreviousPage: this.hasPreviousPage,
            currentPage: this.currentPage,
            totalPages: this.totalPages
        };
    }
}

class PersonalThoughtInventoryContainer {
    constructor(ptrValue, variant = "CSCLocalPlayerPersonalThoughtComponent") {
        this.ptr = ptr(ptrValue);
        this.variant = variant;
    }

    get items() {
        return new StdVector(this.ptr.add(0x70), InventoryManagementSurface.sizes.InventoryGridCommons_SInventoryGridThoughtOption, InventoryGridThoughtOption);
    }

    get nestedInventories() {
        return new StdVector(this.ptr.add(0x88), InventoryManagementSurface.sizes.SInventoryId, SInventoryId);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get ownerInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get classCRC() {
        return this.ptr.add(0x30).readU32();
    }

    get parentInventoryId() {
        return new SInventoryId(this.ptr.add(0x38));
    }

    get dimensions() {
        return readVec3f(this.ptr.add(0x50));
    }

    get type() {
        return this.ptr.add(0x5C).readS32();
    }

    get maxCapacity() {
        return this.ptr.add(0x60).readS64().toString();
    }

    get usedCapacity() {
        return this.ptr.add(0x68).readS64().toString();
    }

    get groupedInventories() {
        if (this.variant !== "CSCLocalPlayerPersonalThoughtComponent") {
            return null;
        }
        return new StdVector(this.ptr.add(0xA0), InventoryManagementSurface.sizes.SInventoryId, SInventoryId);
    }

    get servicePageInfo() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0xB8 : 0xA0;
        return new SPaginationInfo(this.ptr.add(offset));
    }

    get localPageInfo() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0xD0 : 0xB8;
        return new PersonalThoughtInventoryLocalPageInfo(this.ptr.add(offset));
    }

    get filteredItemTypePageInfo() {
        if (this.variant === "CSCLocalPlayerPersonalThoughtComponent") {
            return null;
        }
        return stdMapInfo(this.ptr.add(0xC8));
    }

    get pendingQueries() {
        if (this.variant === "CSCLocalPlayerPersonalThoughtComponent") {
            return null;
        }
        return new StdVector(this.ptr.add(0xD8), 0x04);
    }

    get activeFilter() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0xE0 : 0xF0;
        return eastlMapInfo(this.ptr.add(offset));
    }

    get filterStringOffset() {
        return this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0x110 : 0x120;
    }

    get filterString() {
        return readCryStringHandle(this.ptr.add(this.filterStringOffset));
    }

    get wideFilterString() {
        if (this.variant !== "CSCLocalPlayerPersonalThoughtComponent") {
            return null;
        }
        return readCLocString(this.ptr.add(0x118));
    }

    get categoryFiltersOffset() {
        return this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0x120 : 0x128;
    }

    get categoryFilters() {
        return this.ptr.add(this.categoryFiltersOffset).readU8() !== 0;
    }

    get filtersExpanded() {
        return this.ptr.add(this.categoryFiltersOffset + 0x01).readU8() !== 0;
    }

    get waitingOnServer() {
        return this.ptr.add(this.categoryFiltersOffset + 0x02).readU8() !== 0;
    }

    get pendingDataRequests() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0x123 : 0x12C;
        return this.variant === "CSCLocalPlayerPersonalThoughtComponent"
            ? this.ptr.add(offset).readU8() !== 0
            : this.ptr.add(offset).readS32();
    }

    get visible() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0x124 : 0x130;
        return this.ptr.add(offset).readU8() !== 0;
    }

    get failedMoves() {
        const offset = this.variant === "CSCLocalPlayerPersonalThoughtComponent" ? 0x125 : 0x131;
        return this.ptr.add(offset).readU8();
    }

    toObject(includeItems = false) {
        const servicePageInfo = this.servicePageInfo;
        const localPageInfo = this.localPageInfo;
        return {
            ptr: this.ptr.toString(),
            variant: this.variant,
            inventoryId: this.inventoryId.toObject(),
            ownerInventoryId: this.ownerInventoryId.toObject(),
            classCRC: this.classCRC,
            parentInventoryId: this.parentInventoryId.toObject(),
            dimensions: this.dimensions,
            type: this.type,
            maxCapacity: this.maxCapacity,
            usedCapacity: this.usedCapacity,
            items: includeItems ? this.items.toArray(64).map(item => item.toObject(false)) : this.items.toSummary(),
            nestedInventories: includeItems ? this.nestedInventories.toArray(32).map(item => item.toObject()) : this.nestedInventories.toSummary(),
            groupedInventories: this.groupedInventories === null ? null : this.groupedInventories.toSummary(),
            servicePageInfo: servicePageInfo.toObject(),
            localPageInfo: localPageInfo.toObject(),
            filteredItemTypePageInfo: this.filteredItemTypePageInfo,
            pendingQueries: this.pendingQueries === null ? null : this.pendingQueries.toSummary(),
            activeFilter: this.activeFilter,
            filterString: this.filterString,
            wideFilterString: this.wideFilterString,
            categoryFilters: this.categoryFilters,
            filtersExpanded: this.filtersExpanded,
            waitingOnServer: this.waitingOnServer,
            pendingDataRequests: this.pendingDataRequests,
            visible: this.visible,
            failedMoves: this.failedMoves
        };
    }
}

class PersonalThoughtInventorySectionTab {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get type() { return this.ptr.readS32(); }
    get ownerId() { return readEntityId(this.ptr.add(0x08)); }
    get name() { return readCLocString(this.ptr.add(0x10)); }
    get inventoryContainers() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SInventoryId, SInventoryId);
    }

    toObject(includeContainers = false) {
        return {
            type: this.type,
            ownerId: this.ownerId,
            name: this.name,
            inventoryContainers: includeContainers
                ? this.inventoryContainers.toArray(64).map(id => id.toObject())
                : this.inventoryContainers.toSummary()
        };
    }
}

class PersonalThoughtLootingTabInventory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get order() { return this.ptr.readS32(); }
    get iconPath() { return readCryStringHandle(this.ptr.add(0x08)); }
    get tabTitle() { return readCLocString(this.ptr.add(0x10)); }
    get inventoryId() { return new SInventoryId(this.ptr.add(0x18)); }

    toObject() {
        return {
            order: this.order,
            iconPath: this.iconPath,
            tabTitle: this.tabTitle,
            inventoryId: this.inventoryId.toObject()
        };
    }
}

class PersonalThoughtLootingInventoryData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get selectedInventory() { return this.ptr.readS32(); }
    get inventoryContainers() {
        return new StdVector(
            this.ptr.add(0x08),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SLootingTabInventory,
            PersonalThoughtLootingTabInventory
        );
    }

    toObject(includeContainers = false) {
        return {
            selectedInventory: this.selectedInventory,
            inventoryContainers: includeContainers
                ? this.inventoryContainers.toArray(64).map(container => container.toObject())
                : this.inventoryContainers.toSummary()
        };
    }
}

class PersonalThoughtInventorySection {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get selectedTab() { return this.ptr.readS32(); }
    get belongsToPlayer() { return this.ptr.add(0x04).readU8() !== 0; }
    get tabs() {
        return new StdVector(
            this.ptr.add(0x08),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventorySectionTab,
            PersonalThoughtInventorySectionTab
        );
    }
    get lootingData() { return new PersonalThoughtLootingInventoryData(this.ptr.add(0x20)); }

    toObject(includeNested = false) {
        return {
            selectedTab: this.selectedTab,
            belongsToPlayer: this.belongsToPlayer,
            tabs: includeNested ? this.tabs.toArray(32).map(tab => tab.toObject(true)) : this.tabs.toSummary(),
            lootingData: this.lootingData.toObject(includeNested)
        };
    }
}

class PersonalThoughtSectionState {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get selectedSectionIndex() { return this.ptr.readS32(); }
    get selectedContainerIndex() { return this.ptr.add(0x04).readS32(); }
    get selectedInventoryId() { return new SInventoryId(this.ptr.add(0x08)); }

    toObject() {
        return {
            selectedSectionIndex: this.selectedSectionIndex,
            selectedContainerIndex: this.selectedContainerIndex,
            selectedInventoryId: this.selectedInventoryId.toObject()
        };
    }
}

class PersonalThoughtInventorySectionsAndContainers {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get sections() {
        return new StdVector(
            this.ptr,
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventorySection,
            PersonalThoughtInventorySection
        );
    }
    get sectionTabs() {
        return new StdVector(
            this.ptr.add(0x18),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventorySectionTab,
            PersonalThoughtInventorySectionTab
        );
    }
    get leftState() { return new PersonalThoughtSectionState(this.ptr.add(0x30)); }
    get rightState() { return new PersonalThoughtSectionState(this.ptr.add(0x50)); }
    get lockPtr() { return this.ptr.add(0x70).readPointer(); }

    toObject(includeNested = false) {
        return {
            sections: includeNested ? this.sections.toArray(16).map(section => section.toObject(false)) : this.sections.toSummary(),
            sectionTabs: includeNested ? this.sectionTabs.toArray(32).map(tab => tab.toObject(false)) : this.sectionTabs.toSummary(),
            leftState: this.leftState.toObject(),
            rightState: this.rightState.toObject(),
            lockPtr: this.lockPtr.toString()
        };
    }
}

class PersonalThoughtSelectedThoughtOption {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get text() { return this.ptr.readU32(); }
    get description() { return readCLocString(this.ptr.add(0x08)); }
    get enabled() { return this.ptr.add(0x10).readU8() !== 0; }
    get name() { return readCryStringHandle(this.ptr.add(0x18)); }
    get arg() { return this.ptr.add(0x20).readS32(); }
    get callback() { return new StdFunction(this.ptr.add(0x28), "void(int)"); }
    get itemPtr() { return lower48(this.ptr.add(0x68).readPointer()); }
    get postSelectAction() { return this.ptr.add(0x70).readS32(); }
    get interactionPointId() { return new InteractionPointId(this.ptr.add(0x78)); }
    get interactionNameHash() { return new CStringHash(this.ptr.add(0x90)); }

    toObject() {
        return {
            text: this.text,
            description: this.description,
            enabled: this.enabled,
            name: this.name,
            arg: this.arg,
            callback: this.callback.toObject(),
            itemPtr: this.itemPtr.toString(),
            postSelectAction: this.postSelectAction,
            interactionPointId: this.interactionPointId.toObject(),
            interactionNameHash: this.interactionNameHash.toObject()
        };
    }
}

class PersonalThoughtOption {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get text() { return this.ptr.readU32(); }
    get description() { return readCLocString(this.ptr.add(0x08)); }
    get name() { return readCryStringHandle(this.ptr.add(0x10)); }
    get bindingAction() { return this.ptr.add(0x18).readS32(); }
    get menuToLoad() { return this.ptr.add(0x1C).readS32(); }
    get parent() { return this.ptr.add(0x20).readU8() !== 0; }
    get backOption() { return this.ptr.add(0x21).readU8() !== 0; }
    get isFavorite() { return this.ptr.add(0x22).readU8() !== 0; }
    get favoriteType() { return this.ptr.add(0x24).readS32(); }
    get arg() { return this.ptr.add(0x28).readS32(); }
    get callback() { return new StdFunction(this.ptr.add(0x30), "void(int)"); }
    get isCategory() { return this.ptr.add(0x70).readU8() !== 0; }
    get showEmptyCategory() { return this.ptr.add(0x71).readU8() !== 0; }
    get active() { return this.ptr.add(0x72).readU8() !== 0; }
    get enabled() { return this.ptr.add(0x73).readU8() !== 0; }
    get blocked() { return this.ptr.add(0x74).readU8() !== 0; }
    get actionMap() { return readCryStringHandle(this.ptr.add(0x78)); }
    get itemSecondaryActions() {
        return new StdVector(
            this.ptr.add(0x80),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SSelectedThoughtOption,
            PersonalThoughtSelectedThoughtOption
        );
    }
    get itemEntityPtr() { return lower48(this.ptr.add(0x98).readPointer()); }

    toObject(includeActions = false) {
        return {
            text: this.text,
            description: this.description,
            name: this.name,
            bindingAction: this.bindingAction,
            menuToLoad: this.menuToLoad,
            parent: this.parent,
            backOption: this.backOption,
            isFavorite: this.isFavorite,
            favoriteType: this.favoriteType,
            arg: this.arg,
            callback: this.callback.toObject(),
            isCategory: this.isCategory,
            showEmptyCategory: this.showEmptyCategory,
            active: this.active,
            enabled: this.enabled,
            blocked: this.blocked,
            actionMap: this.actionMap,
            itemSecondaryActions: includeActions ? this.itemSecondaryActions.toArray(32).map(action => action.toObject()) : this.itemSecondaryActions.toSummary(),
            itemEntityPtr: this.itemEntityPtr.toString()
        };
    }
}

class PersonalThoughtPITFavorite {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get coords() { return { x: this.ptr.readS32(), y: this.ptr.add(0x04).readS32() }; }
    get isActive() { return this.ptr.add(0x08).readU8() !== 0; }
    get isLocked() { return this.ptr.add(0x09).readU8() !== 0; }
    get defaultText() { return this.ptr.add(0x0C).readU32(); }
    get type() { return this.ptr.add(0x10).readS32(); }
    get favoriteThought() { return new PersonalThoughtOption(this.ptr.add(0x18)); }

    toObject(includeThought = false) {
        return {
            coords: this.coords,
            isActive: this.isActive,
            isLocked: this.isLocked,
            defaultText: this.defaultText,
            type: this.type,
            favoriteThought: includeThought ? this.favoriteThought.toObject(false) : { ptr: this.favoriteThought.ptr.toString() }
        };
    }
}

class PersonalThoughtQuickAccessMenu {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get elements() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.SharedPtr, SharedPtr);
    }
    get currentSelection() { return new SharedPtr(this.ptr.add(0x18), "SPITQuickAccessSelectableElement"); }
    get quickAccessSelectedMenuIndex() { return this.ptr.add(0x28).readS32(); }
    get saveSelection() { return this.ptr.add(0x2C).readU8() !== 0; }
    get wheelItemCategories() { return new StdVector(this.ptr.add(0x30), 0x04); }

    toObject() {
        return {
            elements: this.elements.toSummary(),
            currentSelection: this.currentSelection.toObject(),
            quickAccessSelectedMenuIndex: this.quickAccessSelectedMenuIndex,
            saveSelection: this.saveSelection,
            wheelItemCategories: this.wheelItemCategories.toSummary()
        };
    }
}

class PersonalThoughtInventoryMoveLocalAttachData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get attachedEntityPtr() { return lower48(this.ptr.readPointer()); }
    get portPath() { return readCryStringHandle(this.ptr.add(0x08)); }
    get aggregatePortParentPtr() { return lower48(this.ptr.add(0x10).readPointer()); }

    toObject() {
        return {
            attachedEntityPtr: this.attachedEntityPtr.toString(),
            portPath: this.portPath,
            aggregatePortParentPtr: this.aggregatePortParentPtr.toString()
        };
    }
}

class PersonalThoughtInventoryMove {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get id() { return this.ptr.readU32(); }
    get type() { return this.ptr.add(0x04).readS32(); }
    get sourceInventoryId() { return new SInventoryId(this.ptr.add(0x08)); }
    get targetInventoryId() { return new SInventoryId(this.ptr.add(0x20)); }
    get sourceItems() {
        return new StdVector(this.ptr.add(0x38), InventoryManagementSurface.sizes.InventoryGridCommons_SInventoryGridThoughtOption, InventoryGridThoughtOption);
    }
    get targetItems() {
        return new StdVector(this.ptr.add(0x50), InventoryManagementSurface.sizes.InventoryGridCommons_SInventoryGridThoughtOption, InventoryGridThoughtOption);
    }
    get storedEntityPtr() { return lower48(this.ptr.add(0x68).readPointer()); }
    get localDetach() { return this.ptr.add(0x70).readU8() !== 0; }
    get inventoryQueryType() { return this.ptr.add(0x74).readS32(); }
    get timeStamp() { return this.ptr.add(0x78).readS64().toString(); }
    get localAttachData() { return new PersonalThoughtInventoryMoveLocalAttachData(this.ptr.add(0x80)); }

    toObject(includeItems = false) {
        return {
            id: this.id,
            type: this.type,
            sourceInventoryId: this.sourceInventoryId.toObject(),
            targetInventoryId: this.targetInventoryId.toObject(),
            sourceItems: includeItems ? this.sourceItems.toArray(16).map(item => item.toObject(false)) : this.sourceItems.toSummary(),
            targetItems: includeItems ? this.targetItems.toArray(16).map(item => item.toObject(false)) : this.targetItems.toSummary(),
            storedEntityPtr: this.storedEntityPtr.toString(),
            localDetach: this.localDetach,
            inventoryQueryType: this.inventoryQueryType,
            timeStamp: this.timeStamp,
            localAttachData: this.localAttachData.toObject()
        };
    }
}

class PersonalThoughtDragItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() { return new SInventoryId(this.ptr); }
    get item() { return new InventoryGridThoughtOption(this.ptr.add(0x18)); }
    get itemIndex() { return this.ptr.add(0x198).readS32(); }
    get previousTargetInventoryId() { return new SInventoryId(this.ptr.add(0x1A0)); }
    get equippedItem() { return readEntityId(this.ptr.add(0x1B8)); }

    toObject(includeItem = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            item: includeItem ? this.item.toObject(false) : { ptr: this.item.ptr.toString() },
            itemIndex: this.itemIndex,
            previousTargetInventoryId: this.previousTargetInventoryId.toObject(),
            equippedItem: this.equippedItem
        };
    }
}

class PersonalThoughtSoftAttachItemInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemPortID() { return new SItemPortId(this.ptr); }
    get itemPortContainerPtr() { return componentPtrInfo(this.ptr.add(0x10)); }
    get spawnedSoftAttachItemPtr() { return lower48(this.ptr.add(0x18).readPointer()); }

    toObject() {
        return {
            itemPortID: this.itemPortID.toObject(),
            itemPortContainerPtr: this.itemPortContainerPtr,
            spawnedSoftAttachItemPtr: this.spawnedSoftAttachItemPtr.toString()
        };
    }
}

class PersonalThoughtSwapPortDraggedItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get draggedItemPortId() { return new SItemPortId(this.ptr); }
    get draggedEntityPtr() { return lower48(this.ptr.add(0x10).readPointer()); }
    get swappedItemPortId() { return new SItemPortId(this.ptr.add(0x18)); }
    get swappedEntityPtr() { return lower48(this.ptr.add(0x28).readPointer()); }
    get itemPortContainerPtr() { return componentPtrInfo(this.ptr.add(0x30)); }

    toObject() {
        return {
            draggedItemPortId: this.draggedItemPortId.toObject(),
            draggedEntityPtr: this.draggedEntityPtr.toString(),
            swappedItemPortId: this.swappedItemPortId.toObject(),
            swappedEntityPtr: this.swappedEntityPtr.toString(),
            itemPortContainerPtr: this.itemPortContainerPtr
        };
    }
}

class PersonalThoughtPendingSwapItem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get targetItemPortId() { return new SItemPortId(this.ptr); }
    get swapPortId() { return new SItemPortId(this.ptr.add(0x10)); }
    get swapItemPtr() { return lower48(this.ptr.add(0x20).readPointer()); }

    toObject() {
        return {
            targetItemPortId: this.targetItemPortId.toObject(),
            swapPortId: this.swapPortId.toObject(),
            swapItemPtr: this.swapItemPtr.toString()
        };
    }
}

class PersonalThoughtLootingEquipment {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get flags() { return this.ptr.readU8(); }
    get enabled() { return this.ptr.add(0x01).readU8() !== 0; }
    get itemPortId() { return new SItemPortId(this.ptr.add(0x08)); }
    get looseAttachmentPtr() { return componentPtrInfo(this.ptr.add(0x18)); }

    toObject() {
        return {
            flags: this.flags,
            enabled: this.enabled,
            itemPortId: this.itemPortId.toObject(),
            looseAttachmentPtr: this.looseAttachmentPtr
        };
    }
}

class SEntityStackChangeParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get classGuidCrc() {
        return this.ptr.add(0x08).readU32();
    }

    get quantity() {
        return this.ptr.add(0x0C).readS32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            classGuidCrc: this.classGuidCrc,
            quantity: this.quantity
        };
    }
}

class SEntityStackChangeRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get stackChangeParams() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SEntityStackChangeParam, SEntityStackChangeParam);
    }

    toObject(includeParams = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            stackChangeParams: includeParams
                ? this.stackChangeParams.toArray(64).map(param => param.toObject())
                : this.stackChangeParams.toSummary()
        };
    }
}

const SIncreaseEntityStackRequest = SEntityStackChangeRequest;
const SDecreaseEntityStackRequest = SEntityStackChangeRequest;
const SSetEntityStackRequest = SEntityStackChangeRequest;

class SMoveEntityStackRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get moveParams() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SMoveEntityStackParam, SMoveEntityStackParam);
    }

    toObject(includeParams = false) {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            moveParams: includeParams ? this.moveParams.toArray(64).map(param => param.toObject()) : this.moveParams.toSummary()
        };
    }
}

class STransferEntityAggregateRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get fromInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get toInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get inventoryEntries() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SInventoryEntry, SInventoryEntry);
    }

    get legalOwnerId() {
        return readEntityId(this.ptr.add(0x48));
    }

    toObject(includeEntries = false) {
        return {
            fromInventoryId: this.fromInventoryId.toObject(),
            toInventoryId: this.toInventoryId.toObject(),
            inventoryEntries: includeEntries ? this.inventoryEntries.toArray(64).map(entry => entry.toObject()) : this.inventoryEntries.toSummary(),
            legalOwnerId: this.legalOwnerId
        };
    }
}

class SCreateEntityToInventoryRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityClassGUID() {
        return readCryGuid(this.ptr);
    }

    get quantity() {
        return this.ptr.add(0x10).readS32();
    }

    get updateContext() {
        return new SInventoryUpdateContext(this.ptr.add(0x18));
    }

    get targetRank() {
        return readCryStringHandle(this.ptr.add(0x40));
    }

    get tagsRaw() {
        return new CTagList(this.ptr.add(0x48));
    }

    get createParamsCB() {
        return new CigFunctionBase(this.ptr.add(0x50));
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x68));
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x70), "IEntitySnapshot");
    }

    get ownershipTimeStamp() {
        return this.ptr.add(0x80).readS64().toString();
    }

    get ownershipStatus() {
        return this.ptr.add(0x88).readS8();
    }

    toObject() {
        const tags = this.tagsRaw;
        const cb = this.createParamsCB;
        return {
            entityClassGUID: this.entityClassGUID,
            quantity: this.quantity,
            updateContext: this.updateContext.toObject(),
            targetRank: this.targetRank,
            tags: tags.toObject(),
            createParamsCB: cb.toObject(),
            ownerId: this.ownerId,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject(),
            ownershipTimeStamp: this.ownershipTimeStamp,
            ownershipStatus: this.ownershipStatus
        };
    }
}

class IInventoryApiSCreateEntityToInventoryRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityClassGUID() {
        return readCryGuid(this.ptr);
    }

    get quantity() {
        return this.ptr.add(0x10).readS32();
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x18));
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x20), "IEntitySnapshot");
    }

    get updateContext() {
        return new SInventoryUpdateContext(this.ptr.add(0x30));
    }

    get tagsRaw() {
        return new CTagList(this.ptr.add(0x58));
    }

    get createParamsCB() {
        return new CigFunctionBase(this.ptr.add(0x60));
    }

    toObject() {
        const tags = this.tagsRaw;
        const cb = this.createParamsCB;
        return {
            entityClassGUID: this.entityClassGUID,
            quantity: this.quantity,
            rank: this.rank,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject(),
            updateContext: this.updateContext.toObject(),
            tags: tags.toObject(),
            createParamsCB: cb.toObject()
        };
    }
}

class SUnstowItemRequestParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get gridItem() {
        return new SInventoryContainerGridItem(this.ptr);
    }

    get itemPortId() {
        return new SItemPortId(this.ptr.add(0x50));
    }

    get action() {
        return this.ptr.add(0x60).readS32();
    }

    get offsetDirZs() {
        return readVec3f(this.ptr.add(0x64));
    }

    toObject() {
        return {
            gridItem: this.gridItem.toObject(),
            itemPortId: this.itemPortId.toObject(),
            action: this.action,
            offsetDirZs: this.offsetDirZs
        };
    }
}

class SEntityUnstowParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get parentPortName() {
        return readCryStringHandle(this.ptr);
    }

    get entityId() {
        return readEntityId(this.ptr.add(0x08));
    }

    get parentRelativeTransform() {
        return new QuatTS(this.ptr.add(0x10));
    }

    get parentId() {
        return readEntityId(this.ptr.add(0x50));
    }

    get parentAttachId() {
        return this.ptr.add(0x58).readU32();
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x60), "CEntitySnapshotBinary");
    }

    get flagsEngaged() {
        return this.ptr.add(0x74).readU8() !== 0;
    }

    get flags() {
        return this.flagsEngaged ? this.ptr.add(0x70).readU32() : null;
    }

    toObject() {
        return {
            parentPortName: this.parentPortName,
            entityId: this.entityId,
            parentRelativeTransform: this.parentRelativeTransform,
            parentId: this.parentId,
            parentAttachId: this.parentAttachId,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject(),
            flags: this.flags,
            flagsEngaged: this.flagsEngaged
        };
    }
}

class SUnstowInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityUnstowRequest() { return new SEntityUnstowParams(this.ptr); }
    get inventoryId() { return new SInventoryId(this.ptr.add(0x78)); }
    get actorId() { return readEntityId(this.ptr.add(0x90)); }
    get atcId() { return readEntityId(this.ptr.add(0x98)); }
    get locationId() { return this.ptr.add(0xA0).readU32(); }
    get vehicleId() { return readEntityId(this.ptr.add(0xA8)); }
    get vehicleEntityClass() { return this.ptr.add(0xB0).readPointer(); }
    get snapshotVariableRequests() { return new StdVector(this.ptr.add(0xB8), 0x30); }

    toObject(includeRequests = false) {
        return {
            entityUnstowRequest: this.entityUnstowRequest.toObject(),
            inventoryId: this.inventoryId.toObject(),
            actorId: this.actorId,
            atcId: this.atcId,
            locationId: this.locationId,
            vehicleId: this.vehicleId,
            vehicleEntityClass: this.vehicleEntityClass.toString(),
            snapshotVariableRequests: includeRequests
                ? this.snapshotVariableRequests.toArray(64).map(value => ({ ptr: value.toString(), rawSize: "0x30" }))
                : this.snapshotVariableRequests.toSummary()
        };
    }
}

class SStowInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vehicleId() { return readEntityId(this.ptr); }
    get playerId() { return readEntityId(this.ptr.add(0x08)); }
    get locationId() { return this.ptr.add(0x10).readU32(); }
    get locationInventoryId() { return new SInventoryId(this.ptr.add(0x18)); }

    toObject() {
        return {
            vehicleId: this.vehicleId,
            playerId: this.playerId,
            locationId: this.locationId,
            locationInventoryId: this.locationInventoryId.toObject()
        };
    }
}

class SUnstowRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get unstowParams() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SEntityUnstowParams, SEntityUnstowParams);
    }

    toObject(includeParams = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            unstowParams: includeParams ? this.unstowParams.toArray(64).map(param => param.toObject()) : this.unstowParams.toSummary()
        };
    }
}

class SSPlitStackRequestParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get newStackQuantity() {
        return this.ptr.add(0x08).readS32();
    }

    get newStackRank() {
        return readCryStringHandle(this.ptr.add(0x10));
    }

    get classGuid() {
        return readCryGuid(this.ptr.add(0x18));
    }

    get ownerId() {
        return readEntityId(this.ptr.add(0x28));
    }

    get snapshotSharedPtr() {
        return new SharedPtr(this.ptr.add(0x30), "IEntitySnapshot");
    }

    get tagsRaw() {
        return new CTagList(this.ptr.add(0x40));
    }

    toObject() {
        return {
            entityId: this.entityId,
            newStackQuantity: this.newStackQuantity,
            newStackRank: this.newStackRank,
            classGuid: this.classGuid,
            ownerId: this.ownerId,
            snapshotSharedPtr: this.snapshotSharedPtr.toObject(),
            tags: this.tagsRaw.toObject()
        };
    }
}

const SSplitStackRequestParams = SSPlitStackRequestParams;

class SSplitStackRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get sourceInventoryId() {
        return new SInventoryId(this.ptr);
    }

    get destinationInventoryId() {
        return new SInventoryId(this.ptr.add(0x18));
    }

    get splitParams() {
        return new StdVector(this.ptr.add(0x30), InventoryManagementSurface.sizes.SSPlitStackRequestParams, SSPlitStackRequestParams);
    }

    toObject(includeParams = false) {
        return {
            sourceInventoryId: this.sourceInventoryId.toObject(),
            destinationInventoryId: this.destinationInventoryId.toObject(),
            splitParams: includeParams ? this.splitParams.toArray(64).map(param => param.toObject()) : this.splitParams.toSummary()
        };
    }
}

class SDeleteItemRequestParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get itemGEID() {
        return readEntityId(this.ptr);
    }

    get classGUID() {
        return readCryGuid(this.ptr.add(0x08));
    }

    get amount() {
        return this.ptr.add(0x18).readS32();
    }

    get legalOwnerId() {
        return readEntityId(this.ptr.add(0x20));
    }

    toObject() {
        return {
            itemGEID: this.itemGEID,
            classGUID: this.classGUID,
            amount: this.amount,
            legalOwnerId: this.legalOwnerId
        };
    }
}

class SDeleteItemRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get deleteParams() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SDeleteItemRequestParams, SDeleteItemRequestParams);
    }

    toObject(includeParams = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            deleteParams: includeParams ? this.deleteParams.toArray(64).map(param => param.toObject()) : this.deleteParams.toSummary()
        };
    }
}

class SStowEntityRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityAggregatePtr() {
        return lower48(this.ptr.readPointer());
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    toObject() {
        return {
            entityAggregatePtr: this.entityAggregatePtr.toString(),
            rank: this.rank
        };
    }
}

class SStowItemRequestParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    toObject() {
        return {
            entityId: this.entityId,
            rank: this.rank
        };
    }
}

class SStowRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr.add(0x08));
    }

    get rank() {
        return readCryStringHandle(this.ptr.add(0x20));
    }

    get occupancy() {
        return this.ptr.add(0x28).readU32();
    }

    get location() {
        return new SEntityLocationInfo(this.ptr.add(0x30));
    }

    get purpose() {
        return this.ptr.add(0x40).readS32();
    }

    get traceId() {
        return new STraceId(this.ptr.add(0x44));
    }

    get inventoryConfig() {
        return new SInventoryConfiguration(this.ptr.add(0xF8));
    }

    get topic() {
        return readCryStringHandle(this.ptr.add(0x128));
    }

    get serviceId() {
        return readCryStringHandle(this.ptr.add(0x130));
    }

    get shardId() {
        return readCryStringHandle(this.ptr.add(0x138));
    }

    get commandId() {
        return readCryStringHandle(this.ptr.add(0x140));
    }

    toObject() {
        return {
            entityId: this.entityId,
            inventoryId: this.inventoryId.toObject(),
            rank: this.rank,
            occupancy: this.occupancy,
            location: this.location.toObject(),
            purpose: this.purpose,
            traceId: this.traceId.toObject(),
            inventoryConfig: this.inventoryConfig.toObject(),
            topic: this.topic,
            serviceId: this.serviceId,
            shardId: this.shardId,
            commandId: this.commandId
        };
    }
}

class SDestroyEntityPreconditions {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get stackSizeEngaged() {
        return this.ptr.add(0x04).readU8() !== 0;
    }

    get stackSize() {
        return this.stackSizeEngaged ? this.ptr.readU32() : null;
    }

    toObject() {
        return {
            stackSize: this.stackSize,
            stackSizeEngaged: this.stackSizeEngaged
        };
    }
}

class SDestroyEntityParam {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get preconditionsEngaged() {
        return this.ptr.add(0x10).readU8() !== 0;
    }

    get preconditions() {
        return this.preconditionsEngaged ? new SDestroyEntityPreconditions(this.ptr.add(0x08)) : null;
    }

    toObject() {
        return {
            entityId: this.entityId,
            preconditionsEngaged: this.preconditionsEngaged,
            preconditions: this.preconditions?.toObject() ?? null
        };
    }
}

class SDestroyEntityRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get inventoryId() {
        return new SInventoryId(this.ptr);
    }

    get entities() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.SDestroyEntityParam, SDestroyEntityParam);
    }

    toObject(includeEntities = false) {
        return {
            inventoryId: this.inventoryId.toObject(),
            entities: includeEntities ? this.entities.toArray(64).map(entity => entity.toObject()) : this.entities.toSummary()
        };
    }
}

class SOptionalArguments {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get commandArgumentsPtr() {
        return this.ptr.readPointer();
    }

    get maxDuration() {
        const engaged = this.ptr.add(0x10).readU8() !== 0;
        return {
            engaged,
            value: engaged ? this.ptr.add(0x08).readU64().toString() : null
        };
    }

    toObject() {
        return {
            commandArgumentsPtr: this.commandArgumentsPtr.toString(),
            maxDuration: this.maxDuration
        };
    }
}

class CInventoryContainerComponentSCargoGridLockData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get sourceEntityId() {
        return readEntityId(this.ptr);
    }

    get sourceType() {
        return this.ptr.add(0x08).readS32();
    }

    toObject() {
        return {
            sourceEntityId: this.sourceEntityId,
            sourceType: this.sourceType
        };
    }
}

class CInventoryContainerComponentSSerializedAndLockedCargoGridsLocks {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get readWriteLock() {
        return new CIGRWLock(this.ptr);
    }

    get locks() {
        return new StdVector(
            this.ptr.add(0x28 + 0x08),
            InventoryManagementSurface.sizes.CInventoryContainerComponent_SCargoGridLockData,
            CInventoryContainerComponentSCargoGridLockData
        );
    }

    get allowTBInteraction() {
        return this.ptr.add(0x48 + 0x08).readU8() !== 0;
    }

    toObject(includeLocks = false) {
        const readWriteLock = this.readWriteLock;
        return {
            readWriteLock: readWriteLock.toObject(),
            locks: includeLocks ? this.locks.toArray(32).map(lock => lock.toObject()) : this.locks.toSummary(),
            allowTBInteraction: this.allowTBInteraction
        };
    }
}

class SInventoryEventListener {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityPtr() {
        return this.ptr.readPointer();
    }

    get componentId() {
        return this.ptr.add(0x08).readU16();
    }

    toObject() {
        return {
            entityPtr: this.entityPtr.toString(),
            componentId: this.componentId
        };
    }
}

class LockedInventoryEventListeners {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get listeners() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.SInventoryEventListener, SInventoryEventListener);
    }

    get lock() {
        return new CIGRWLock(this.ptr.add(0x18));
    }

    toObject(includeListeners = false) {
        const lock = this.lock;
        return {
            listeners: includeListeners ? this.listeners.toArray(32).map(listener => listener.toObject()) : this.listeners.toSummary(),
            lock: lock.toObject()
        };
    }
}

class CInventoryContainerComponentSOpenAttachmentOcclusionDebug {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get occlusionTestZoneIdRaw() {
        return this.ptr.readU32();
    }

    get occlusionTest() {
        return new OBBd(this.ptr.add(0x08));
    }

    get currentOccludingEntityPtr() {
        return this.ptr.add(0x80).readPointer();
    }

    get frameId() {
        return this.ptr.add(0x88).readS32();
    }

    toObject() {
        return {
            occlusionTestZoneIdRaw: this.occlusionTestZoneIdRaw,
            occlusionTest: this.occlusionTest.toObject(),
            currentOccludingEntityPtr: this.currentOccludingEntityPtr.toString(),
            frameId: this.frameId
        };
    }
}

class IItemPortModificationApiSAttachRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entity() {
        return new SInventoryEntity(this.ptr);
    }

    get newParentEntity() {
        return new SInventoryEntity(this.ptr.add(0x20));
    }

    get newItemPort() {
        return this.ptr.add(0x40).readU32();
    }

    get disassembleCurrentAttachment() {
        return this.ptr.add(0x44).readU8() !== 0;
    }

    toObject() {
        return {
            entity: this.entity.toObject(),
            newParentEntity: this.newParentEntity.toObject(),
            newItemPort: this.newItemPort,
            disassembleCurrentAttachment: this.disassembleCurrentAttachment
        };
    }
}

class IItemPortModificationApiSDetachRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityId() {
        return readEntityId(this.ptr);
    }

    get newInventoryId() {
        return new SInventoryId(this.ptr.add(0x08));
    }

    get disassembleCurrentAttachment() {
        return this.ptr.add(0x20).readU8() !== 0;
    }

    get ownershipBehavior() {
        return this.ptr.add(0x24).readS32();
    }

    toObject() {
        return {
            entityId: this.entityId,
            newInventoryId: this.newInventoryId.toObject(),
            disassembleCurrentAttachment: this.disassembleCurrentAttachment,
            ownershipBehavior: this.ownershipBehavior
        };
    }
}

class IItemPortModificationApiSModifyItemPortRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get attachCommands() {
        return new StdVector(this.ptr, 0x10);
    }

    get detachCommands() {
        return new StdVector(this.ptr.add(0x18), 0x10);
    }

    get changeSnapshotCommands() {
        return new StdVector(this.ptr.add(0x30), 0x10);
    }

    get eraseCommands() {
        return new StdVector(this.ptr.add(0x48), 0x10);
    }

    toObject() {
        return {
            attachCommands: this.attachCommands.toSummary(),
            detachCommands: this.detachCommands.toSummary(),
            changeSnapshotCommands: this.changeSnapshotCommands.toSummary(),
            eraseCommands: this.eraseCommands.toSummary()
        };
    }
}

class CInventoryContainerComponent extends EntityComponent {
    constructor(ptrValue) {
        super(ptrValue, "CInventoryContainerComponent");
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    addressOf(name) {
        const slot = InventoryManagementSurface.cInventoryContainerComponentVtable[name];
        if (slot === undefined) throw new Error(`unknown CInventoryContainerComponent vfunc: ${name}`);
        return this.vfuncAddress(slot);
    }

    get userToken() {
        return this.ptr.add(0x48);
    }

    get inventoryUser() {
        return new CSerializedVariable(this.ptr.add(0x58), p => readEntityId(p), "EntityId", 0x08);
    }

    get previousInventoryUser() {
        return readEntityId(this.ptr.add(0x68));
    }

    get userRequestLock() {
        return this.ptr.add(0x70);
    }

    get userRequestId() {
        return readEntityId(this.ptr.add(0x90));
    }

    get userRequestCallback() {
        return this.ptr.add(0x98);
    }

    get containerOccupancy() {
        return new CSerializedVariable(this.ptr.add(0xB0), p => new SCargoAmount(p), "SCargoAmount", InventoryManagementSurface.sizes.SCargoAmount);
    }

    get spawnedPopulateLoot() {
        return new CSerializedVariable(
            this.ptr.add(0xC8),
            p => new StdVector(p, InventoryManagementSurface.sizes.SLootRequest, SLootRequest),
            "std::vector<SLootRequest>",
            InventoryManagementSurface.sizes.StdVector
        );
    }

    get snapshotInventoryLock() {
        return this.ptr.add(0xE8);
    }

    get snapshotInventoryGridItems() {
        return new CSerializedVariable(
            this.ptr.add(0x110),
            p => new StdVector(p, InventoryManagementSurface.sizes.SInventoryContainerGridItem, SInventoryContainerGridItem),
            "std::vector<SInventoryContainerGridItem>",
            InventoryManagementSurface.sizes.StdVector
        );
    }

    get lootGenerationRequest() {
        return new CSerializedVariable(
            this.ptr.add(0x130),
            p => new SInventoryContainerItemGenerationRequest(p),
            "SInventoryContainerItemGenerationRequest",
            InventoryManagementSurface.sizes.SInventoryContainerItemGenerationRequest
        );
    }

    get packingPlan() {
        return new ContainerPackingSPackingPlan(this.ptr.add(0x150));
    }

    get containerFreeSpaces() {
        return new CSerializedVariable(
            this.ptr.add(0x170),
            p => new StdVector(p, InventoryManagementSurface.sizes.SSerializeableFreeSpace, SSerializeableFreeSpace),
            "std::vector<SSerializeableFreeSpace>",
            InventoryManagementSurface.sizes.StdVector
        );
    }

    get hasInitialized() {
        return new CSerializedVariable(this.ptr.add(0x190), p => p.readU8() !== 0, "bool", 0x01);
    }

    get inventoryCreated() {
        return new CSerializedVariable(this.ptr.add(0x1A0), p => p.readU8() !== 0, "bool", 0x01);
    }

    get interactionLock() {
        return this.ptr.add(0x1B0);
    }

    get containerOpen() {
        return new CSerializedVariable(this.ptr.add(0x1C0), p => p.readU8() !== 0, "bool", 0x01);
    }

    get cargoGridLocks() {
        return new CInventoryContainerComponentSSerializedAndLockedCargoGridsLocks(this.ptr.add(0x1D0));
    }

    get eventListeners() {
        return new LockedInventoryEventListeners(this.ptr.add(0x228));
    }

    get firstAuthorityChangeHasQueueOpening() {
        return this.ptr.add(0x268).readU8() !== 0;
    }

    get openInteractionName() {
        return new CStringHash(this.ptr.add(0x270));
    }

    get openLootingInteractionName() {
        return new CStringHash(this.ptr.add(0x288));
    }

    get openAttachmentOcclusionDebug() {
        return new CInventoryContainerComponentSOpenAttachmentOcclusionDebug(this.ptr.add(0x2A0));
    }

    get legacyEventSystem() {
        return new ILegacyEventSystem(this.ptr.add(0x330));
    }

    surface(includeAddresses = false) {
        const out = {
            ptr: this.ptr.toString(),
            vtable: this.ptr.readPointer().toString(),
            size: InventoryManagementSurface.sizes.CInventoryContainerComponent,
            offsets: InventoryManagementSurface.cInventoryContainerComponentOffsets,
            vtableSlots: InventoryManagementSurface.cInventoryContainerComponentVtable
        };

        if (includeAddresses) {
            const addresses = {};
            for (const [name, slot] of Object.entries(InventoryManagementSurface.cInventoryContainerComponentVtable)) {
                addresses[`${name}Address`] = this.vfuncAddress(slot).toString();
            }
            out.vtableAddresses = addresses;
        }

        return out;
    }

    toObject(includeGridItems = false) {
        const legacyEventSystem = this.legacyEventSystem;
        return {
            ...this.surface(false),
            ptr: this.ptr.toString(),
            inventoryUser: this.inventoryUser.toObject(),
            previousInventoryUser: this.previousInventoryUser,
            userRequestId: this.userRequestId,
            containerOccupancy: this.containerOccupancy.toObject(),
            spawnedPopulateLoot: this.spawnedPopulateLoot.toObject(),
            snapshotInventoryGridItems: includeGridItems
                ? { ...this.snapshotInventoryGridItems.toObject(), value: this.snapshotInventoryGridItems.value.toArray(64).map(item => item.toObject()) }
                : this.snapshotInventoryGridItems.toObject(),
            lootGenerationRequest: this.lootGenerationRequest.toObject(),
            packingPlan: this.packingPlan.toObject(includeGridItems),
            containerFreeSpaces: includeGridItems
                ? { ...this.containerFreeSpaces.toObject(), value: this.containerFreeSpaces.value.toArray(64).map(space => space.toObject()) }
                : this.containerFreeSpaces.toObject(),
            hasInitialized: this.hasInitialized.toObject(),
            inventoryCreated: this.inventoryCreated.toObject(),
            containerOpen: this.containerOpen.toObject(),
            cargoGridLocks: this.cargoGridLocks.toObject(false),
            eventListeners: this.eventListeners.toObject(false),
            firstAuthorityChangeHasQueueOpening: this.firstAuthorityChangeHasQueueOpening,
            openInteractionName: this.openInteractionName.toObject(),
            openLootingInteractionName: this.openLootingInteractionName.toObject(),
            openAttachmentOcclusionDebug: this.openAttachmentOcclusionDebug.toObject(),
            legacyEventSystem: legacyEventSystem.toObject()
        };
    }
}

class CSCLocalPlayerPersonalThoughtComponent extends EntityComponent {
    constructor(ptrValue) {
        super(ptrValue, "CSCLocalPlayerPersonalThoughtComponent");
    }

    get dragItemPorts() { return new StdVector(this.ptr.add(0xD0), 0x10); }
    get inventorySectionLock() { return new CIGCriticalSection(this.ptr.add(0xE8)); }
    get playerSection() { return new PersonalThoughtInventorySection(this.ptr.add(0x108)); }
    get externalSection() { return new PersonalThoughtInventorySection(this.ptr.add(0x148)); }
    get sectionsData() { return new PersonalThoughtInventorySectionsAndContainers(this.ptr.add(0x188)); }
    get lootAnimation() {
        return {
            state: this.ptr.add(0x200).readS32(),
            requestId: this.ptr.add(0x204).readU16()
        };
    }
    get configDefPtr() { return this.ptr.add(0x208).readPointer(); }
    get playerChoicePtr() { return componentPtrInfo(this.ptr.add(0x210)); }
    get actorPtr() { return componentPtrInfo(this.ptr.add(0x218)); }
    get playerPtr() { return componentPtrInfo(this.ptr.add(0x220)); }
    get currentState() { return this.ptr.add(0x228).readS32(); }
    get currentInternalState() { return this.ptr.add(0x22C).readS32(); }
    get currentVersion() { return this.ptr.add(0x230).readS32(); }
    get currentMenuIndex() { return this.ptr.add(0x234).readS32(); }
    get selectedChoiceIndex() { return this.ptr.add(0x238).readS32(); }
    get hoverFavoriteIndex() { return this.ptr.add(0x23C).readS32(); }
    get previousFavoriteIndex() { return this.ptr.add(0x240).readS32(); }
    get lastFavoriteUpdated() { return this.ptr.add(0x244).readS32(); }
    get cursorType() { return this.ptr.add(0x248).readS32(); }
    get thoughtMenus() { return new StdVector(this.ptr.add(0x250), InventoryManagementSurface.sizes.StdVector); }
    get categoriesActions() { return stdMapInfo(this.ptr.add(0x268)); }
    get favorites() {
        return new StdVector(
            this.ptr.add(0x278),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SPITFavorite,
            PersonalThoughtPITFavorite
        );
    }
    get quickAccessMenus() { return new StdVector(this.ptr.add(0x290), PTR_SIZE); }
    get quickAccessActions() { return stdMapInfo(this.ptr.add(0x2A8)); }
    get quickAccessEventHashes() { return stdMapInfo(this.ptr.add(0x2B8)); }
    get rebuildMenu() { return this.ptr.add(0x2C8).readU8() !== 0; }
    get rebuildMenuTimer() { return this.ptr.add(0x2D0).readS64().toString(); }
    get inventoryView() { return new SharedPtr(this.ptr.add(0x2D8), "ICameraView"); }
    get inventoryCameraInteractionEnabled() { return this.ptr.add(0x2E8).readU8() !== 0; }
    get lastLocationId() { return this.ptr.add(0x2EC).readU32(); }
    get lastLandingZoneLocationId() { return this.ptr.add(0x2F0).readU32(); }
    get pendingLocationInventoryQuery() { return this.ptr.add(0x2F4).readU8() !== 0; }
    get pendingVehicleInventoryQuery() { return this.ptr.add(0x2F5).readU8() !== 0; }
    get locationInventoryQueryRetries() { return this.ptr.add(0x2F8).readS32(); }
    get vehicleInventoryQueryRetries() { return this.ptr.add(0x2FC).readS32(); }
    get entityInventoryQueryRetries() { return stdMapInfo(this.ptr.add(0x300)); }
    get personalInventoryContainers() {
        return new LockedMap(
            this.ptr.add(0x310),
            "LockedMap<SInventoryId, CSCLocalPlayerPersonalThoughtComponent::SPersonalThoughtInventoryContainer>"
        );
    }
    get entitiesBlockingInteraction() { return new StdVector(this.ptr.add(0x348), PTR_SIZE); }
    get hadInteractionBlockingEntities() { return this.ptr.add(0x360).readU8() !== 0; }
    get closeInventoryForBlockingItemsCleared() { return this.ptr.add(0x361).readU8() !== 0; }
    get lastRequestTimeStamp() { return this.ptr.add(0x368).readS64().toString(); }
    get lastRequestCompleteTimeStamp() { return this.ptr.add(0x370).readS64().toString(); }
    get requestInventoryDataTimeStamp() { return stdMapInfo(this.ptr.add(0x378)); }
    get recentRequestElapsedTimes() {
        return {
            ptr: this.ptr.add(0x388).toString(),
            type: "eastl::deque<float,eastl::allocator,16>"
        };
    }
    get inventoryManagementLock() { return new CIGCriticalSection(this.ptr.add(0x3E0)); }
    get inventoryMoves() {
        return new LockedDeque(
            this.ptr.add(0x400),
            InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventoryMove,
            PersonalThoughtInventoryMove,
            "LockedDeque<CSCLocalPlayerPersonalThoughtComponent::SInventoryMove>"
        );
    }
    get confirmedLocalAttachments() { return stdMapInfo(this.ptr.add(0x450)); }
    get externalInventoryEntityPtr() { return lower48(this.ptr.add(0x460).readPointer()); }
    get extInventoryEntities() { return new StdVector(this.ptr.add(0x468), PTR_SIZE); }
    get extInventoryEntitiesDebug() { return new StdVector(this.ptr.add(0x480), PTR_SIZE); }
    get externalEntityHostilityReaction() { return this.ptr.add(0x498).readU32(); }
    get previousStance() { return this.ptr.add(0x49C).readU8(); }
    get isLooting() { return this.ptr.add(0x49D).readU8() !== 0; }
    get selectedInventoryId() { return new SInventoryId(this.ptr.add(0x4A0)); }
    get focusOnEntityPtr() { return lower48(this.ptr.add(0x4B8).readPointer()); }
    get currentRequesterKioskEntityPtr() { return lower48(this.ptr.add(0x4C0).readPointer()); }
    get requestedCamera() { return readCryGuid(this.ptr.add(0x4C8)); }
    get focusBothEntities() { return this.ptr.add(0x4D8).readU8() !== 0; }
    get dragItem() { return new PersonalThoughtDragItem(this.ptr.add(0x4E0)); }
    get softAttachedItemInfo() { return new PersonalThoughtSoftAttachItemInfo(this.ptr.add(0x6A0)); }
    get swapPortDraggedItem() { return new PersonalThoughtSwapPortDraggedItem(this.ptr.add(0x6C0)); }
    get pendingSwapItem() { return new PersonalThoughtPendingSwapItem(this.ptr.add(0x6F8)); }
    get hiddenItemPorts() { return new StdVector(this.ptr.add(0x720), PTR_SIZE); }
    get thoughtMenusLock() { return new CIGCriticalSection(this.ptr.add(0x738)); }
    get attachmentPtr() { return lower48(this.ptr.add(0x758).readPointer()); }
    get legacyEventSystem() { return new ILegacyEventSystem(this.ptr.add(0x760)); }
    get chatAlreadyDisabled() { return this.ptr.add(0x8C0).readU8() !== 0; }
    get showDisabledActions() { return this.ptr.add(0x8C1).readU8() !== 0; }
    get showTriedToEquipClothingWithUndersuitHint() { return this.ptr.add(0x8C2).readU8() !== 0; }
    get chatEnabledOnOpen() { return this.ptr.add(0x8C3).readU8() !== 0; }
    get processingOnAction() { return this.ptr.add(0x8C4).readU8() !== 0; }
    get ammoRepooling() { return this.ptr.add(0x8C5).readU8() !== 0; }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent,
            offsets: InventoryManagementSurface.cscLocalPlayerPersonalThoughtComponentOffsets,
            functions: InventoryManagementSurface.personalThoughtFunctions
        };
    }

    operationSurface() {
        return {
            ptr: this.ptr.toString(),
            selectedInventoryId: this.selectedInventoryId.toObject(),
            isLooting: this.isLooting,
            currentState: this.currentState,
            currentInternalState: this.currentInternalState,
            currentVersion: this.currentVersion,
            personalInventoryContainers: this.personalInventoryContainers.toObject(),
            inventoryMoves: this.inventoryMoves.deque.toSummary(),
            pendingLocationInventoryQuery: this.pendingLocationInventoryQuery,
            pendingVehicleInventoryQuery: this.pendingVehicleInventoryQuery,
            locationInventoryQueryRetries: this.locationInventoryQueryRetries,
            vehicleInventoryQueryRetries: this.vehicleInventoryQueryRetries,
            entityInventoryQueryRetries: this.entityInventoryQueryRetries,
            externalInventoryEntityPtr: this.externalInventoryEntityPtr.toString(),
            focusOnEntityPtr: this.focusOnEntityPtr.toString(),
            functions: InventoryManagementSurface.personalThoughtFunctions
        };
    }

    inventoryMoveEntries(limit = 16, includeNested = false) {
        return this.inventoryMoves.deque.toArray(limit).map(move => move.toObject(includeNested));
    }

    toObject(includeNested = false) {
        return {
            ...this.surface(),
            dragItemPorts: this.dragItemPorts.toSummary(),
            playerSection: this.playerSection.toObject(includeNested),
            externalSection: this.externalSection.toObject(includeNested),
            sectionsData: this.sectionsData.toObject(includeNested),
            lootAnimation: this.lootAnimation,
            configDefPtr: this.configDefPtr.toString(),
            playerChoicePtr: this.playerChoicePtr,
            actorPtr: this.actorPtr,
            playerPtr: this.playerPtr,
            currentState: this.currentState,
            currentInternalState: this.currentInternalState,
            currentVersion: this.currentVersion,
            currentMenuIndex: this.currentMenuIndex,
            selectedChoiceIndex: this.selectedChoiceIndex,
            hoverFavoriteIndex: this.hoverFavoriteIndex,
            previousFavoriteIndex: this.previousFavoriteIndex,
            lastFavoriteUpdated: this.lastFavoriteUpdated,
            cursorType: this.cursorType,
            thoughtMenus: this.thoughtMenus.toSummary(),
            categoriesActions: this.categoriesActions,
            favorites: includeNested ? this.favorites.toArray(16).map(fav => fav.toObject(false)) : this.favorites.toSummary(),
            quickAccessMenus: this.quickAccessMenus.toSummary(),
            quickAccessActions: this.quickAccessActions,
            quickAccessEventHashes: this.quickAccessEventHashes,
            rebuildMenu: this.rebuildMenu,
            rebuildMenuTimer: this.rebuildMenuTimer,
            inventoryView: this.inventoryView.toObject(),
            inventoryCameraInteractionEnabled: this.inventoryCameraInteractionEnabled,
            lastLocationId: this.lastLocationId,
            lastLandingZoneLocationId: this.lastLandingZoneLocationId,
            pendingLocationInventoryQuery: this.pendingLocationInventoryQuery,
            pendingVehicleInventoryQuery: this.pendingVehicleInventoryQuery,
            locationInventoryQueryRetries: this.locationInventoryQueryRetries,
            vehicleInventoryQueryRetries: this.vehicleInventoryQueryRetries,
            entityInventoryQueryRetries: this.entityInventoryQueryRetries,
            personalInventoryContainers: this.personalInventoryContainers.toObject(),
            entitiesBlockingInteraction: this.entitiesBlockingInteraction.toSummary(),
            hadInteractionBlockingEntities: this.hadInteractionBlockingEntities,
            closeInventoryForBlockingItemsCleared: this.closeInventoryForBlockingItemsCleared,
            lastRequestTimeStamp: this.lastRequestTimeStamp,
            lastRequestCompleteTimeStamp: this.lastRequestCompleteTimeStamp,
            requestInventoryDataTimeStamp: this.requestInventoryDataTimeStamp,
            recentRequestElapsedTimes: this.recentRequestElapsedTimes,
            inventoryMoves: this.inventoryMoves.toObject(includeNested, 16),
            confirmedLocalAttachments: this.confirmedLocalAttachments,
            externalInventoryEntityPtr: this.externalInventoryEntityPtr.toString(),
            extInventoryEntities: this.extInventoryEntities.toSummary(),
            extInventoryEntitiesDebug: this.extInventoryEntitiesDebug.toSummary(),
            externalEntityHostilityReaction: this.externalEntityHostilityReaction,
            previousStance: this.previousStance,
            isLooting: this.isLooting,
            selectedInventoryId: this.selectedInventoryId.toObject(),
            focusOnEntityPtr: this.focusOnEntityPtr.toString(),
            currentRequesterKioskEntityPtr: this.currentRequesterKioskEntityPtr.toString(),
            requestedCamera: this.requestedCamera,
            focusBothEntities: this.focusBothEntities,
            dragItem: this.dragItem.toObject(includeNested),
            softAttachedItemInfo: this.softAttachedItemInfo.toObject(),
            swapPortDraggedItem: this.swapPortDraggedItem.toObject(),
            pendingSwapItem: this.pendingSwapItem.toObject(),
            hiddenItemPorts: this.hiddenItemPorts.toSummary(),
            attachmentPtr: this.attachmentPtr.toString(),
            legacyEventSystem: includeNested ? this.legacyEventSystem.toObject() : { ptr: this.legacyEventSystem.ptr.toString() },
            chatAlreadyDisabled: this.chatAlreadyDisabled,
            showDisabledActions: this.showDisabledActions,
            showTriedToEquipClothingWithUndersuitHint: this.showTriedToEquipClothingWithUndersuitHint,
            chatEnabledOnOpen: this.chatEnabledOnOpen,
            processingOnAction: this.processingOnAction,
            ammoRepooling: this.ammoRepooling
        };
    }
}

class CSCPlayerInventory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get pendingDataRequests() {
        return stdMapInfo(this.ptr);
    }

    get pendingDataRequestsLock() {
        return this.ptr.add(0x10);
    }

    get lastPendingRequestId() {
        return this.ptr.add(0x30).readU32();
    }

    get inventoryManagementQueueLock() {
        return this.ptr.add(0x38);
    }

    get inventoryManagementQueue() {
        return new StdDeque(this.ptr.add(0x58), InventoryManagementSurface.sizes.SInventoryManagementRequest, SInventoryManagementRequest);
    }

    inventoryManagementQueueEntries(limit = 16, includeNested = false) {
        return this.inventoryManagementQueue.toArray(limit).map(request => request.toObject(includeNested));
    }

    get unspawnedEntities() {
        return new LockedMap(this.ptr.add(0x80), "LockedMap<unsigned int,EntityId>");
    }

    get pendingMoveTimer() {
        return this.ptr.add(0xB8).readS64().toString();
    }

    get lockedMoveRequestId() {
        return this.ptr.add(0xC0).readU32();
    }

    get rmTokenTerminateAccessToInventory() {
        return new CSerializedRemoteMethod(this.ptr.add(0xC8), "void(SInventoryId)");
    }

    get rmAuthorityProcessInventoryManagementOperation() {
        return new CSerializedRemoteMethod(this.ptr.add(0xE8), "void(SInventoryManagementRequest const &)");
    }

    get rmTokenRequestInventoryManagementOperation() {
        return new CSerializedRemoteMethod(this.ptr.add(0x108), "void(SInventoryManagementRequest const &)");
    }

    get rmAuthorityRequestDropEquippedItem() {
        return new CSerializedRemoteMethod(this.ptr.add(0x128), "void(EntityId)");
    }

    get rmAuthorityNotifyLootEntityAccessed() {
        return new CSerializedRemoteMethod(this.ptr.add(0x148), "void(EntityId,bool)");
    }

    get rmAuthorityNotifyReserveCarryable() {
        return new CSerializedRemoteMethod(this.ptr.add(0x168), "void(EntityId,bool)");
    }

    get rmAuthorityRequestChangePortOnEquippedItem() {
        return new CSerializedRemoteMethod(this.ptr.add(0x188), "void(SItemPortId,EntityId)");
    }

    get rmAuthorityRequestSwapPortOnEquippedItem() {
        return new CSerializedRemoteMethod(this.ptr.add(0x1A8), "void(SItemPortId,EntityId,SItemPortId)");
    }

    get rmTokenReceivePersonalInventoryData() {
        return new CSerializedRemoteMethod(this.ptr.add(0x1C8), "void(SPersonalInventoryReceivedData)");
    }

    get rmTokenMoveRequestCompleted() {
        return new CSerializedRemoteMethod(this.ptr.add(0x1E8), "void(bool,unsigned int,EntityId)");
    }

    get rmTokenRefreshLocationInventory() {
        return new CSerializedRemoteMethod(this.ptr.add(0x208), "void()");
    }

    get rmOnTokenSetHideEntity() {
        return new CSerializedRemoteMethod(this.ptr.add(0x228), "void(EntityId,bool)");
    }

    get rmTokenRequestInventoryData() {
        return new CSerializedRemoteMethod(this.ptr.add(0x248), "void(EPlayerInventoryType,SInventoryId)");
    }

    get rmAuthorityRequestOpenInventory() {
        return new CSerializedRemoteMethod(this.ptr.add(0x268), "void(EntityId)");
    }

    get rmAuthorityRequestCloseInventory() {
        return new CSerializedRemoteMethod(this.ptr.add(0x288), "void(EntityId)");
    }

    get rmAuthorityProcessDataRequest() {
        return new CSerializedRemoteMethod(this.ptr.add(0x2A8), "void(unsigned int,EInventoryDataRequestType,SInventoryDataRequest)");
    }

    get rmTokenDataResponse() {
        return new CSerializedRemoteMethod(this.ptr.add(0x2C8), "void(unsigned int,bool,SInventoryDataRequest)");
    }

    get entityChangeRequestInProgress() {
        return this.ptr.add(0x2E8).readU8() !== 0;
    }

    get currentProcessingRequest() {
        return readCryStringHandle(this.ptr.add(0x2F0));
    }

    get itemTypeFilteredInventoryCache() {
        return new StdVector(
            this.ptr.add(0x2F8),
            InventoryManagementSurface.sizes.SInventoryContainerManagerDataCachePair,
            SInventoryContainerManagerDataCachePair
        );
    }

    itemTypeFilteredInventoryCacheEntries(limit = 16, includeEntries = false) {
        return this.itemTypeFilteredInventoryCache.toArray(limit).map(item => item.toObject(includeEntries));
    }

    get resetInventoryCache() {
        return new CSerializedVariable(this.ptr.add(0x310), p => new SInventoryId(p), "SInventoryId", InventoryManagementSurface.sizes.SInventoryId);
    }

    get authNotifyCloseInventories() {
        return new StdVector(this.ptr.add(0x330), InventoryManagementSurface.sizes.SInventoryId, SInventoryId);
    }

    get player() {
        const playerPtr = this.ptr.add(0x348).readPointer();
        return playerPtr.isNull() ? null : new CSCPlayer(playerPtr);
    }

    get storedSwappedPortId() {
        return new SItemPortId(this.ptr.add(0x350));
    }

    get responseEntityPtr() {
        return this.ptr.add(0x360).readPointer();
    }

    functionSurface() {
        return InventoryManagementSurface.cscPlayerInventoryFunctions;
    }

    remoteMethodSurface() {
        return {
            terminateAccessToInventory: this.rmTokenTerminateAccessToInventory.toObject(),
            processInventoryManagementOperation: this.rmAuthorityProcessInventoryManagementOperation.toObject(),
            requestInventoryManagementOperation: this.rmTokenRequestInventoryManagementOperation.toObject(),
            requestInventoryData: this.rmTokenRequestInventoryData.toObject(),
            processDataRequest: this.rmAuthorityProcessDataRequest.toObject(),
            dataResponse: this.rmTokenDataResponse.toObject(),
            requestOpenInventory: this.rmAuthorityRequestOpenInventory.toObject(),
            requestCloseInventory: this.rmAuthorityRequestCloseInventory.toObject(),
            moveRequestCompleted: this.rmTokenMoveRequestCompleted.toObject()
        };
    }

    operationSurface(limit = 8, includeNested = false) {
        const queued = [];
        try {
            queued.push(...this.inventoryManagementQueue.toArray(limit).map(request => request.toSummary(includeNested)));
        } catch (e) {
            queued.push({ error: e.message });
        }

        return {
            ptr: this.ptr.toString(),
            requestPath: InventoryManagementSurface.inventoryRequestPath,
            queue: this.inventoryManagementQueue.toSummary(),
            queued,
            pendingDataRequests: this.pendingDataRequests,
            lastPendingRequestId: this.lastPendingRequestId,
            lockedMoveRequestId: this.lockedMoveRequestId,
            currentProcessingRequest: this.currentProcessingRequest,
            entityChangeRequestInProgress: this.entityChangeRequestInProgress,
            cache: {
                itemTypeFilteredInventoryCache: this.itemTypeFilteredInventoryCache.toSummary(),
                resetInventoryCache: this.resetInventoryCache.toObject(),
                authNotifyCloseInventories: this.authNotifyCloseInventories.toSummary()
            },
            remoteMethods: this.remoteMethodSurface(),
            functions: this.functionSurface()
        };
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            size: InventoryManagementSurface.sizes.CSCPlayerInventory,
            offsets: InventoryManagementSurface.cscPlayerInventoryOffsets,
            functions: this.functionSurface(),
            requestPath: InventoryManagementSurface.inventoryRequestPath,
            inventoryManagementQueue: this.inventoryManagementQueue.toSummary()
        };
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            pendingDataRequests: this.pendingDataRequests,
            pendingDataRequestsLock: this.pendingDataRequestsLock.toString(),
            lastPendingRequestId: this.lastPendingRequestId,
            inventoryManagementQueueLock: this.inventoryManagementQueueLock.toString(),
            inventoryManagementQueue: this.inventoryManagementQueue.toSummary(),
            unspawnedEntities: this.unspawnedEntities.toObject(),
            pendingMoveTimer: this.pendingMoveTimer,
            lockedMoveRequestId: this.lockedMoveRequestId,
            remoteMethods: {
                tokenTerminateAccessToInventory: this.rmTokenTerminateAccessToInventory.toObject(),
                authorityProcessInventoryManagementOperation: this.rmAuthorityProcessInventoryManagementOperation.toObject(),
                tokenRequestInventoryManagementOperation: this.rmTokenRequestInventoryManagementOperation.toObject(),
                authorityRequestDropEquippedItem: this.rmAuthorityRequestDropEquippedItem.toObject(),
                authorityNotifyLootEntityAccessed: this.rmAuthorityNotifyLootEntityAccessed.toObject(),
                authorityNotifyReserveCarryable: this.rmAuthorityNotifyReserveCarryable.toObject(),
                authorityRequestChangePortOnEquippedItem: this.rmAuthorityRequestChangePortOnEquippedItem.toObject(),
                authorityRequestSwapPortOnEquippedItem: this.rmAuthorityRequestSwapPortOnEquippedItem.toObject(),
                tokenReceivePersonalInventoryData: this.rmTokenReceivePersonalInventoryData.toObject(),
                tokenMoveRequestCompleted: this.rmTokenMoveRequestCompleted.toObject(),
                tokenRefreshLocationInventory: this.rmTokenRefreshLocationInventory.toObject(),
                onTokenSetHideEntity: this.rmOnTokenSetHideEntity.toObject(),
                tokenRequestInventoryData: this.rmTokenRequestInventoryData.toObject(),
                authorityRequestOpenInventory: this.rmAuthorityRequestOpenInventory.toObject(),
                authorityRequestCloseInventory: this.rmAuthorityRequestCloseInventory.toObject(),
                authorityProcessDataRequest: this.rmAuthorityProcessDataRequest.toObject(),
                tokenDataResponse: this.rmTokenDataResponse.toObject()
            },
            entityChangeRequestInProgress: this.entityChangeRequestInProgress,
            currentProcessingRequest: this.currentProcessingRequest,
            itemTypeFilteredInventoryCache: this.itemTypeFilteredInventoryCache.toSummary(),
            resetInventoryCache: this.resetInventoryCache.toObject(),
            authNotifyCloseInventories: this.authNotifyCloseInventories.toSummary(),
            player: this.player?.ptr.toString() ?? null,
            storedSwappedPortId: this.storedSwappedPortId.toObject(),
            responseEntityPtr: this.responseEntityPtr.toString(),
            functions: this.functionSurface()
        };
    }
}

class IInventoryManagementApi {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    get queryInventoryListDeprecatedAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.queryInventoryListDeprecated);
    }

    get queryInventoryConfigurationAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.queryInventoryConfiguration);
    }

    get updateInventoryConfigurationAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.updateInventoryConfiguration);
    }

    get createInventoryAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.createInventory);
    }

    get destroyInventoryAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.destroyInventory);
    }

    get withExistingInventoryAddress() {
        return this.vfuncAddress(InventoryManagementSurface.iInventoryManagementApiVtable.withExistingInventory);
    }

    surface() {
        const slots = InventoryManagementSurface.iInventoryManagementApiVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

class IInventoryManagementApiSQueryFiltersContext {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get context() {
        return this.ptr.readS32();
    }

    get subjectId() {
        const engaged = this.ptr.add(0x10).readU8() !== 0;
        return {
            engaged,
            value: engaged ? this.ptr.add(0x08).readU64().toString() : null
        };
    }

    toObject() {
        return {
            context: this.context,
            subjectId: this.subjectId
        };
    }
}

class IInventoryManagementApiSQueryFilters {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get owners() {
        return new StdVector(this.ptr, InventoryManagementSurface.sizes.EntityId);
    }

    get holderIds() {
        return new StdVector(this.ptr.add(0x18), InventoryManagementSurface.sizes.EntityId);
    }

    get contexts() {
        return new StdVector(
            this.ptr.add(0x30),
            InventoryManagementSurface.sizes.IInventoryManagementApi_SQueryFiltersContext,
            IInventoryManagementApiSQueryFiltersContext
        );
    }

    toObject(includeContexts = false) {
        return {
            owners: this.owners.toSummary(),
            holderIds: this.holderIds.toSummary(),
            contexts: includeContexts ? this.contexts.toArray(32).map(context => context.toObject()) : this.contexts.toSummary()
        };
    }
}

class IInventoryManagementApiSUpdateInventoryRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get id() {
        return new SInventoryId(this.ptr);
    }

    get typeRaw() {
        return {
            ptr: this.ptr.add(0x18),
            rawSize: "0xc",
            which: this.ptr.add(0x20).readU8()
        };
    }

    toObject() {
        return {
            id: this.id.toObject(),
            typeRaw: {
                ptr: this.typeRaw.ptr.toString(),
                rawSize: this.typeRaw.rawSize,
                which: this.typeRaw.which
            }
        };
    }
}

class IItemPortModificationApi {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    addressOf(name) {
        const slot = InventoryManagementSurface.iItemPortModificationApiVtable[name];
        if (slot === undefined) throw new Error(`unknown IItemPortModificationApi vfunc: ${name}`);
        return this.vfuncAddress(slot);
    }

    surface() {
        const slots = InventoryManagementSurface.iItemPortModificationApiVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

class IInventoryContainerManager {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    addressOf(name) {
        const slot = InventoryManagementSurface.iInventoryContainerManagerVtable[name];
        if (slot === undefined) throw new Error(`unknown IInventoryContainerManager vfunc: ${name}`);
        return this.vfuncAddress(slot);
    }

    surface() {
        const slots = InventoryManagementSurface.iInventoryContainerManagerVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }

    get callbackQueue() {
        return new CDeferredCallbackQueueU64(this.ptr.add(0x08));
    }

    get lockedRequests() {
        return new ReadWriteLockableValue(
            this.ptr.add(0x40),
            p => stdMapInfo(p),
            "SReadWriteLockableValue<std::set<unsigned __int64> >"
        );
    }

    get currentRequestId() {
        return this.ptr.add(0x78).readU64().toString();
    }

    get config() {
        return this.ptr.add(0x80).readPointer();
    }

    get inventoryConfig() {
        return this.ptr.add(0x88).readPointer();
    }

    get pendingDataRequests() {
        return stdMapInfo(this.ptr.add(0x90));
    }

    get lastPendingRequestId() {
        return this.ptr.add(0xA0).readU64().toString();
    }

    get pendingDataRequestsLock() {
        return this.ptr.add(0xA8);
    }

    get pendingInventoryOpenRequests() {
        return new LockedOpenPendingRequests(this.ptr.add(0xC8));
    }

    get currentOpenRequest() {
        return this.ptr.add(0x108).readU64().toString();
    }

    get openRequestPending() {
        return this.ptr.add(0x110).readU8() !== 0;
    }

    get closedInventoryNonStorableItemTypes() {
        return eastlMapInfo(this.ptr.add(0x118));
    }

    toObject() {
        return {
            ...this.surface(),
            callbackQueue: this.callbackQueue.toObject(),
            lockedRequests: this.lockedRequests.toObject(),
            currentRequestId: this.currentRequestId,
            config: this.config.toString(),
            inventoryConfig: this.inventoryConfig.toString(),
            pendingDataRequests: this.pendingDataRequests,
            lastPendingRequestId: this.lastPendingRequestId,
            pendingDataRequestsLock: this.pendingDataRequestsLock.toString(),
            pendingInventoryOpenRequests: this.pendingInventoryOpenRequests.toObject(false),
            currentOpenRequest: this.currentOpenRequest,
            openRequestPending: this.openRequestPending,
            closedInventoryNonStorableItemTypes: this.closedInventoryNonStorableItemTypes,
            functions: InventoryManagementSurface.cInventoryContainerManagerFunctions
        };
    }

    getEntireInventoryQuery(inventoryIdPtr) {
        const idPtr = ptr(inventoryIdPtr);
        const result = Memory.alloc(InventoryManagementSurface.sizes.SInventoryEntityQuery);
        result.writeByteArray(new Uint8Array(InventoryManagementSurface.sizes.SInventoryEntityQuery));
        callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.getEntireInventoryQuery,
            "pointer",
            ["pointer", "pointer"],
            [result, idPtr],
            "CInventoryContainerManager::GetEntireInventoryQuery"
        );
        const wrapper = new SInventoryEntityQuery(result);
        wrapper._buffer = result;
        return wrapper;
    }

    isUserStowValid(userEntityId, targetInventoryIdPtr, entityIEntityPtr) {
        const res = callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.isUserStowValid,
            "char",
            ["uint64", "pointer", "uint64"],
            [uint64(String(userEntityId)), ptr(targetInventoryIdPtr), uint64(String(entityIEntityPtr))],
            "CInventoryContainerManager::IsUserStowValid"
        );
        return res !== 0;
    }

    isItemTypePermissibleInInventory(containerDefPtr, itemDefinitionPtr) {
        const res = callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.isItemTypePermissibleInInventory,
            "char",
            ["pointer", "pointer"],
            [ptr(containerDefPtr), ptr(itemDefinitionPtr)],
            "CInventoryContainerManager::IsItemTypePermissibleInInventory"
        );
        return res !== 0;
    }

    getBlockedClosedInventoryItems() {
        const arrPtr = callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.getBlockedClosedInventoryItems,
            "pointer",
            [],
            [],
            "CInventoryContainerManager::GetBlockedClosedInventoryItems"
        );
        if (arrPtr.isNull()) return null;
        return {
            ptr: arrPtr.toString(),
            type: "SInventoryItemTypes",
            blockedItemTypes: eastlMapInfo(arrPtr)
        };
    }

    getItemTypeOpenInventoryOccupantProperties() {
        const arrPtr = callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.getItemTypeOpenInventoryOccupantProperties,
            "pointer",
            [],
            [],
            "CInventoryContainerManager::GetItemTypeOpenInventoryOccupantProperties"
        );
        if (arrPtr.isNull()) return null;
        return {
            ptr: arrPtr.toString(),
            ...dataCoreArrayInfo(arrPtr),
            elementType: "SOpenInventoryOccupantItemTypeProperties"
        };
    }

    getDefaultOpenInventoryOccupantProperties() {
        const propsPtr = callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.getDefaultOpenInventoryOccupantProperties,
            "pointer",
            [],
            [],
            "CInventoryContainerManager::GetDefaultOpenInventoryOccupantProperties"
        );
        return propsPtr.isNull() ? null : { ptr: propsPtr.toString(), type: "SCargoGridOccupantProperties" };
    }

    cancelCallback(requestId) {
        callVFunc(
            this.ptr,
            InventoryManagementSurface.iInventoryContainerManagerVtable.cancelCallback,
            "void",
            ["uint64"],
            [uint64(String(requestId))],
            "CInventoryContainerManager::CancelCallback"
        );
        return { requestId: String(requestId), cancelled: true };
    }
}

class IPlatformInventoryManager {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    surface() {
        const slots = InventoryManagementSurface.iPlatformInventoryManagerVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

class IPlayerInventoryManager {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    surface() {
        const slots = InventoryManagementSurface.iPlayerInventoryManagerVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

class ISCActorInventory {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    surface() {
        const slots = InventoryManagementSurface.iscActorInventoryVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

class CSCActorInventory extends ISCActorInventory {
    get attachedItems() {
        return new StdVector(this.ptr.add(0x48), PTR_SIZE);
    }

    get attachedItemsLock() {
        return new CIGCriticalSection(this.ptr.add(0x60));
    }

    get attachedWeapons() {
        return new StdVector(this.ptr.add(0x80), PTR_SIZE);
    }

    toObject() {
        return {
            ...this.surface(),
            attachedItems: this.attachedItems.toSummary(),
            attachedWeapons: this.attachedWeapons.toSummary(),
            actor: this.ptr.add(0x98).readPointer().toString(),
            cachedTotalEquipmentMass: this.ptr.add(0xA0).readFloat(),
            cachedArmorMovementFactor: this.ptr.add(0xA4).readFloat(),
            availableHelmet: componentPtrInfo(this.ptr.add(0xA8)),
            availableBodyArmor: componentPtrInfo(this.ptr.add(0xB0)),
            availableLegArmor: componentPtrInfo(this.ptr.add(0xB8)),
            availableArmArmor: componentPtrInfo(this.ptr.add(0xC0))
        };
    }
}

class IInventoryApi {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    vfuncAddress(index) {
        return this.ptr.readPointer().add(index * PTR_SIZE).readPointer();
    }

    addressOf(name) {
        const slot = InventoryManagementSurface.iInventoryApiVtable[name];
        if (slot === undefined) throw new Error(`unknown IInventoryApi vfunc: ${name}`);
        return this.vfuncAddress(slot);
    }

    get inventoryManagementApi() {
        const apiPtr = tryCallVFunc(this.ptr, InventoryManagementSurface.iInventoryApiVtable.getInventoryManagementApi, "pointer", [], [], "IInventoryApi::GetInventoryManagementApi");
        if (!apiPtr) return null;
        return apiPtr.isNull() ? null : new IInventoryManagementApi(apiPtr);
    }

    get itemPortModificationApi() {
        const apiPtr = tryCallVFunc(this.ptr, InventoryManagementSurface.iInventoryApiVtable.getItemPortModificationApi, "pointer", [], [], "IInventoryApi::GetItemPortModificationApi");
        if (!apiPtr) return null;
        return apiPtr.isNull() ? null : new IItemPortModificationApi(apiPtr);
    }

    surface() {
        const slots = InventoryManagementSurface.iInventoryApiVtable;
        return {
            ptr: this.ptr.toString(),
            vtableSlots: slots,
            ...vtableAddressMap(this, slots)
        };
    }
}

const EProfiledSubsystem = Object.freeze({
    PROFILE_GAME_MISSIONS: 0x52
});

const EActorStatType = Object.freeze({
    OverdoseLevel: 0x03,
    SuitTemperature: 0x05,
    Stun: 0x06,
    Pressure: 0x08,
    GasSaturationO2: 0x09,
    DownedDamage: 0x0A,
    HealthHead: 0x0C,
    HealthTorso: 0x0D,
    HealthLeftArm: 0x0E,
    HealthRightArm: 0x0F,
    HealthLeftLeg: 0x10,
    HealthRightLeg: 0x11,
    WearHead: 0x12,
    WearTorso: 0x13,
    WearLeftArm: 0x14,
    WearRightArm: 0x15,
    WearLeftLeg: 0x16,
    WearRightLeg: 0x17,
    BodyRadiation: 0x18,
    SuitRadiation: 0x19,
    GasSaturationCO2: 0x1A,
    GasSaturationCO: 0x1B,
    Hygiene: 0x1C
});

const EHealthChangeReason = Object.freeze({
    initialDamage: 0x01
});

const EInvulnerableFlags = Object.freeze({
    Enabled: 0x01,
    IgnoreAllHits: 0x02,
    PropagatwDamageToParent: 0x04
});

const CSCBodyHealthComponentSurface = Object.freeze({
    source: "types.h verified",
    sizes: {
        IEntityComponentHealth: 0x1A8,
        CSCBodyHealthComponent: 0x6B8,
        CSerializedRemoteMethod_AuthorityRequestHit: 0x20,
        SPartIdCache: 0x18,
        SBodyPart: 0x50,
        CInvulnerabilityParams: 0x01,
        CSerializedVariable_CInvulnerabilityParams: 0x10,
        SRecentAttackerData: 0x48,
        CBindingsVariableFloat: 0x48,
        SDamageInfo: 0x20,
        CSerializedVariable_TrackedDamageMap: 0x18
    },
    offsets: {
        m_rmAuthorityRequestHit: 0x1B0,
        m_rmAuthorityRequestHitWithJointOffsets: 0x1D0,
        m_partIdCache: 0x1F0,
        m_bodyParts: 0x200,
        m_bodyPartsDamageOverTime: 0x218,
        m_vehicleCollisionBodyPartId: 0x230,
        m_bodyMapping: 0x238,
        m_healthConfig: 0x240,
        m_pActor: 0x248,
        m_invulnerabilityParams: 0x250,
        m_collisionInvulnerableFrames: 0x260,
        m_bIsPlayer: 0x264,
        m_electronDamageHandler: 0x268,
        m_recentAttackerData: 0x530,
        m_bvHitAngle: 0x578,
        m_bvHitAlpha: 0x5C0,
        m_bvHitScale: 0x608,
        m_hitTimeList: 0x650,
        m_lastExplosionExposure: 0x668,
        m_deferredDetatchedArmorPieces: 0x680,
        m_pHealthEffects: 0x698,
        m_trackedDamage: 0x6A0
    },
    sBodyPartOffsets: {
        m_config: 0x00,
        m_partHealthStat: 0x08,
        m_partWearStat: 0x0C,
        m_pArmor: 0x10,
        bodyPartRef: 0x18,
        physPartIds: 0x30,
        partNameCRC32: 0x48
    },
    sPartIdCacheOffsets: {
        physPartId: 0x00,
        jointDefIndex: 0x08,
        bodyPartIndex: 0x10
    },
    recentAttackerDataOffsets: {
        pLastAttackerEntity: 0x00,
        pLastAttackingWeapon: 0x08,
        pEntityWhoCausedBleeding: 0x10,
        pEntityWhoCausedDowned: 0x18,
        pEntityWhoCausedUnconscious: 0x20,
        pEntityWhoCausedDead: 0x28,
        lastHitType: 0x30,
        recentAttackersWhileDowned: 0x38
    },
    vtable: {
        getHealth: 221,
        getMaxHealth: 222,
        getHealthRatio: 223,
        setHealth: 224,
        setHealthRatio: 225,
        adjustHealth: 226,
        isDead: 227,
        processShield: 231,
        processHit: 232,
        getHealthPartCount: 249,
        getDamageMap: 251,
        isSalvagable: 253,
        isRepairable: 254,
        isInvulnerable: 255,
        isHeadShot: 257,
        isUsingIntegrityDamageHandling: 258,
        getDamageResistance: 266,
        applyDamageResistance: 267,
        startTrackingDamage: 268,
        stopTrackingDamage: 269,
        getTrackedDamage: 270,
        debugGUIDisplay: 271,
        triggerDamageMapUpdate: 272
    }
});

const EMissionObjectiveStates = Object.freeze({
    MISSION_OBJECTIVE_STATE_UNSPECIFIED: 0,
    MISSION_OBJECTIVE_STATE_INPROGRESS: 1,
    MISSION_OBJECTIVE_STATE_COMPLETED: 2,
    MISSION_OBJECTIVE_STATE_FAILED: 3,
    MISSION_OBJECTIVE_STATE_WITHDRAWN: 4
});

const MissionServiceInternalSurface = Object.freeze({
    source: "types.h verified",
    profileGameMissions: EProfiledSubsystem.PROFILE_GAME_MISSIONS,
    sizes: {
        CryGUID: 0x10,
        CTimeValue: 0x08,
        CryStringT_char: 0x08,
        EastlVector: 0x18,
        SMissionObjectiveContributor: 0x18,
        SMissionObjective: 0xA0,
        SUpsertObjectiveRequest: 0xA8,
        CFuture_CigOptionalErrorResult_CigError: 0x20,
        CigOptionalErrorResult_CigError: 0x50
    },
    smissionObjectiveOffsets: {
        objectiveId: 0x00,
        parentObjectiveId: 0x08,
        missionId: 0x10,
        timerStart: 0x20,
        expiry: 0x28,
        state: 0x30,
        shortDescId: 0x34,
        longDescId: 0x38,
        markerIds: 0x40,
        progressCounterCurrent: 0x58,
        progressCounterMax: 0x60,
        reward: 0x68,
        flags: 0x6C,
        uiDisplayPriority: 0x70,
        uiDisplayTextId: 0x74,
        contributors: 0x78,
        ignoreObjectiveContributors: 0x90,
        uiExtendedTextItemIndex: 0x94,
        autoCompletePolicy: 0x98
    },
    sUpsertObjectiveRequestOffsets: {
        objective: 0x00,
        completed: 0xA0
    },
    imissionServiceInternalVtable: {
        dtor: 0,
        createMission: 1,
        endMission: 2,
        createMissionPhase: 3,
        updateMissionPhase: 4,
        completeMissionPhase: 5,
        upsertObjective: 6,
        updateObjectiveProgress: 7,
        updateObjective: 8,
        completeObjective: 9,
        addContributorToObjective: 10,
        removeContributorFromObjective: 11,
        disableMissionExpiry: 12,
        enableMissionExpiry: 13
    }
});

class SMissionObjectiveContributor {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            playerId: this.ptr.readU64().toString(),
            contributionCounter: this.ptr.add(0x08).readS64().toString(),
            active: this.ptr.add(0x10).readU8() !== 0
        };
    }
}

class SMissionObjective {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get objectiveId() {
        return readCryStringHandle(this.ptr.add(0x00));
    }

    get parentObjectiveId() {
        return readCryStringHandle(this.ptr.add(0x08));
    }

    get missionId() {
        return readCryGuid(this.ptr.add(0x10));
    }

    get markerIds() {
        return new StdVector(this.ptr.add(0x40), 0x08);
    }

    get contributors() {
        return new StdVector(this.ptr.add(0x78), 0x18, SMissionObjectiveContributor);
    }

    toObject(includeNested = true) {
        const out = {
            ptr: this.ptr.toString(),
            objectiveId: this.objectiveId,
            parentObjectiveId: this.parentObjectiveId,
            missionId: this.missionId,
            timerStart: this.ptr.add(0x20).readS64().toString(),
            expiry: this.ptr.add(0x28).readS64().toString(),
            state: this.ptr.add(0x30).readS32(),
            shortDescId: this.ptr.add(0x34).readU32(),
            longDescId: this.ptr.add(0x38).readU32(),
            markerIds: this.markerIds.toSummary(),
            progressCounterCurrent: this.ptr.add(0x58).readS64().toString(),
            progressCounterMax: this.ptr.add(0x60).readS64().toString(),
            rewardRaw: this.ptr.add(0x68).readU8(),
            flags: this.ptr.add(0x6C).readU32(),
            uiDisplayPriority: this.ptr.add(0x70).readS32(),
            uiDisplayTextId: this.ptr.add(0x74).readU32(),
            contributors: this.contributors.toSummary(),
            ignoreObjectiveContributors: this.ptr.add(0x90).readU8() !== 0,
            uiExtendedTextItemIndex: this.ptr.add(0x94).readU32(),
            autoCompletePolicy: this.ptr.add(0x98).readS32()
        };

        if (includeNested) {
            out.markerIds.values = this.markerIds.toArray(64).map(idPtr => readEntityId(idPtr));
            out.contributors.values = this.contributors.toArray(64).map(contributor => contributor.toObject());
        }

        return out;
    }
}

class SUpsertObjectiveRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get objective() {
        return new SMissionObjective(this.ptr);
    }

    toObject(includeNested = true) {
        return {
            ptr: this.ptr.toString(),
            objective: this.objective.toObject(includeNested),
            completed: this.ptr.add(0xA0).readU8() !== 0
        };
    }
}

class IMissionServiceInternal {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get vtable() {
        return this.ptr.readPointer();
    }

    vfuncAddress(slot) {
        return this.vtable.add(slot * PTR_SIZE).readPointer();
    }

    surface() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.vtable.toString(),
            upsertObjectiveSlot: MissionServiceInternalSurface.imissionServiceInternalVtable.upsertObjective,
            upsertObjectiveAddress: this.vfuncAddress(MissionServiceInternalSurface.imissionServiceInternalVtable.upsertObjective).toString()
        };
    }

    upsertObjective(resultPtr, missionIdPtr, activeMissionKeyPtr, requestsPtr, profileTag = EProfiledSubsystem.PROFILE_GAME_MISSIONS) {
        return callVFunc(
            this.ptr,
            MissionServiceInternalSurface.imissionServiceInternalVtable.upsertObjective,
            "pointer",
            ["pointer", "pointer", "pointer", "pointer", "uint32"],
            [ptr(resultPtr), ptr(missionIdPtr), ptr(activeMissionKeyPtr), ptr(requestsPtr), profileTag >>> 0],
            "IMissionServiceInternal::UpsertObjective"
        );
    }
}

class SMissionProperty {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get variableName() {
        return {
            raw0: this.ptr.readU64().toString(),
            raw1: this.ptr.add(0x08).readU64().toString(),
            raw2: this.ptr.add(0x10).readU64().toString()
        };
    }

    get extendedTextToken() {
        return readCryString(this.ptr.add(0x18));
    }

    get id() {
        return this.ptr.add(0x20).readU32();
    }

    get textColor() {
        return this.ptr.add(0x24).readS32();
    }

    get type() {
        return this.ptr.add(0x28).readS32();
    }

    get valueVariantIndex() {
        return this.ptr.add(0x30 + 0x28).readU8();
    }

    get optionalAlternativeValuesHasValue() {
        return this.ptr.add(0x60 + 0x18).readU8() !== 0;
    }

    get displayValueVariantIndex() {
        return this.ptr.add(0x80 + 0x10).readU8();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            variableName: this.variableName,
            extendedTextToken: this.extendedTextToken,
            id: this.id,
            textColor: this.textColor,
            type: this.type,
            valueVariantIndex: this.valueVariantIndex,
            optionalAlternativeValuesHasValue: this.optionalAlternativeValuesHasValue,
            displayValueVariantIndex: this.displayValueVariantIndex
        };
    }
}

class MissionObjective {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get id() {
        return readCryString(this.ptr.add(0x08));
    }

    get parent() {
        return readCryString(this.ptr.add(0x10));
    }

    get missionLogEntryId() {
        return readCryGuid(this.ptr.add(0x18));
    }

    get shortDescId() {
        return this.ptr.add(0x28).readU32();
    }

    get longDescId() {
        return this.ptr.add(0x2C).readU32();
    }

    get category() {
        return this.ptr.add(0x30).readS32();
    }

    get group() {
        return this.ptr.add(0x34).readU32();
    }

    get reward() {
        return this.ptr.add(0x38).readU32();
    }

    get missionPhaseId() {
        return readCryGuid(this.ptr.add(0x40));
    }

    get embeddedProperties() {
        return new StdVector(this.ptr.add(0x50), 0x98, SMissionProperty);
    }

    get objectiveTypeTag() {
        return this.ptr.add(0x68).readU32();
    }

    get showInteriorMapWaypoint() {
        return this.ptr.add(0x70).readU8() !== 0;
    }

    get flags() {
        return this.ptr.add(0x74).readU32();
    }

    toObject(includeProperties = false) {
        const out = {
            ptr: this.ptr.toString(),
            vtable: this.ptr.readPointer().toString(),
            id: this.id,
            parent: this.parent,
            missionLogEntryId: this.missionLogEntryId,
            missionPhaseId: this.missionPhaseId,
            category: this.category,
            group: this.group,
            reward: this.reward,
            extendedTextItemIndex: this.ptr.add(0x3C).readU32(),
            shortDescId: this.shortDescId,
            longDescId: this.longDescId,
            embeddedPropertyCount: this.embeddedProperties.count,
            objectiveTypeTag: this.objectiveTypeTag,
            showInteriorMapWaypoint: this.showInteriorMapWaypoint,
            flags: this.flags
        };

        if (includeProperties) {
            out.embeddedProperties = this.embeddedProperties.toArray(32).map(property => property.toObject());
        }

        return out;
    }
}

class PendingMissionObjective extends MissionObjective {
    get counterMax() {
        return this.ptr.add(0x78).readS64();
    }

    get hideOnHUD() {
        return this.ptr.add(0x80).readU8() !== 0;
    }

    toObject(includeProperties = false) {
        return {
            ...super.toObject(includeProperties),
            counterMax: Number(this.counterMax),
            hideOnHUD: this.hideOnHUD
        };
    }
}

class ActiveMissionObjective extends MissionObjective {
    get markerIds() {
        return new StdVector(this.ptr.add(0x78), 0x08);
    }

    get markerPlayerIds() {
        return new StdVector(this.ptr.add(0x90), 0x08);
    }

    get counterValue() {
        return this.ptr.add(0xB0).readS64();
    }

    get counterMax() {
        return this.ptr.add(0xB8).readS64();
    }

    get timerDuration() {
        return this.ptr.add(0xC8).readFloat();
    }

    get timerWarningTime() {
        return this.ptr.add(0xCC).readFloat();
    }

    get uiDisplayPriority() {
        return this.ptr.add(0xF0).readS32();
    }

    get uiDisplayTextId() {
        return this.ptr.add(0xF4).readU32();
    }

    get areaRadius() {
        return this.ptr.add(0xF8).readFloat();
    }

    get areaMarkerType() {
        return this.ptr.add(0xFC).readS32();
    }

    get progressInverted() {
        return this.ptr.add(0x100).readU8() !== 0;
    }

    get progressStartingValue() {
        return this.ptr.add(0x104).readFloat();
    }

    get progressDangerThreshold() {
        return this.ptr.add(0x108).readFloat();
    }

    toObject(includeProperties = false) {
        return {
            ...super.toObject(includeProperties),
            counterValue: Number(this.counterValue),
            counterMax: Number(this.counterMax),
            timerStart: this.ptr.add(0xC0).readS64().toString(),
            timerDuration: this.timerDuration,
            timerWarningTime: this.timerWarningTime,
            uiDisplayPriority: this.uiDisplayPriority,
            uiDisplayTextId: this.uiDisplayTextId,
            areaRadius: this.areaRadius,
            areaMarkerType: this.areaMarkerType,
            progressInverted: this.progressInverted,
            progressStartingValue: this.progressStartingValue,
            progressDangerThreshold: this.progressDangerThreshold,
            markerCount: this.markerIds.count,
            markerIds: this.markerIds.toSummary(),
            markerPlayerCount: this.markerPlayerIds.count,
            markerPlayerIds: this.markerPlayerIds.toSummary()
        };
    }
}

class CompletedMissionObjective extends MissionObjective {
    get endReason() {
        return this.ptr.add(0x78).readU32();
    }

    get state() {
        return this.ptr.add(0x7C).readS32();
    }

    toObject() {
        return {
            ...super.toObject(),
            endReason: this.endReason,
            state: this.state
        };
    }
}

class SObjectiveTokenPropertyLink {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            outputPhaseId: readCryGuid(this.ptr),
            outputPropertyId: this.ptr.add(0x10).readU32(),
            inputPhaseId: readCryGuid(this.ptr.add(0x18)),
            inputPropertyId: this.ptr.add(0x28).readU32()
        };
    }
}

class SObjectiveToken {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get properties() {
        return new StdVector(this.ptr.add(0x30), 0x98, SMissionProperty);
    }

    get pendingObjectives() {
        return new StdVector(this.ptr.add(0x48), 0x88, PendingMissionObjective);
    }

    get childMissionPhases() {
        return new StdVector(this.ptr.add(0x60), 0x10);
    }

    toObject(includeNested = false) {
        const out = {
            ptr: this.ptr.toString(),
            id: readCryGuid(this.ptr),
            parentId: readCryGuid(this.ptr.add(0x10)),
            state: this.ptr.add(0x20).readS32(),
            objectiveId: readCryString(this.ptr.add(0x28)),
            propertyCount: this.properties.count,
            pendingObjectiveCount: this.pendingObjectives.count,
            childMissionPhaseCount: this.childMissionPhases.count,
            childMissionPhases: this.childMissionPhases.toArray(32).map(p => readCryGuid(p)),
            seed: this.ptr.add(0x78).readU32(),
            overrideMissionTitle: this.ptr.add(0x7C).readU32(),
            overrideMissionDescription: this.ptr.add(0x80).readU32(),
            objectiveHandlerVariantIndex: this.ptr.add(0x88 + 0x68).readU8()
        };

        if (includeNested) {
            out.properties = this.properties.toArray(32).map(property => property.toObject());
            out.pendingObjectives = this.pendingObjectives.toArray(32).map(objective => objective.toObject(true));
        }

        return out;
    }
}

class SMissionUIDisplayInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            flags: this.ptr.readU32(),
            raceObjectives: {
                scoresVariable: this.ptr.add(0x08).readPointer().toString(),
                playerPosition: this.ptr.add(0x10).readU8(),
                totalOpponents: this.ptr.add(0x11).readU8(),
                score: this.ptr.add(0x12).readU16(),
                scoreMax: this.ptr.add(0x14).readU16(),
                positionString: this.ptr.add(0x18).readU32(),
                scoreString: this.ptr.add(0x1C).readU32()
            },
            timeTrial: {
                currentCheckpoint: this.ptr.add(0x20).readU8(),
                totalCheckpoints: this.ptr.add(0x21).readU8(),
                targetTime: this.ptr.add(0x24).readFloat(),
                intervalTime: this.ptr.add(0x28).readFloat(),
                colorRank: this.ptr.add(0x2C).readU8(),
                splitRaceTime: this.ptr.add(0x30).readFloat(),
                targetSplit: this.ptr.add(0x34).readFloat(),
                startTimeFrame: this.ptr.add(0x38).readS64().toString(),
                finishTimeFrame: this.ptr.add(0x40).readS64().toString(),
                checkpointTimeFrame: this.ptr.add(0x48).readS64().toString(),
                finishStatus: this.ptr.add(0x50).readU32(),
                isPersonalBest: this.ptr.add(0x54).readU8() !== 0
            }
        };
    }
}

class SMissionEntryDetails {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get seed() {
        return this.ptr.readU32();
    }

    get title() {
        return this.ptr.add(0x04).readU32();
    }

    get titleHUD() {
        return this.ptr.add(0x08).readU32();
    }

    get description() {
        return this.ptr.add(0x0C).readU32();
    }

    get reward() {
        return this.ptr.add(0x18).readS32();
    }

    get rewardMax() {
        return this.ptr.add(0x1C).readS32();
    }

    get buyInAmount() {
        return this.ptr.add(0x20).readS32();
    }

    get creationFee() {
        return this.ptr.add(0x24).readS32();
    }

    get currencyType() {
        return this.ptr.add(0x28).readU8();
    }

    get missionType() {
        return readCryGuid(this.ptr.add(0x30));
    }

    get timeOutTime() {
        return this.ptr.add(0x40).readS64().toString();
    }

    get brokerEntryId() {
        return readCryGuid(this.ptr.add(0x48));
    }

    get contractTemplateId() {
        return readCryGuid(this.ptr.add(0x58));
    }

    get missionId() {
        return readCryGuid(this.ptr.add(0x80));
    }

    get properties() {
        return new StdVector(this.ptr.add(0x68), 0x98, SMissionProperty);
    }

    get cannotShareWithPlayerIds() {
        return new StdVector(this.ptr.add(0x90), 0x08);
    }

    get objectiveTokens() {
        return new StdVector(this.ptr.add(0xB8), 0xF8, SObjectiveToken);
    }

    get propertyLinks() {
        return new StdVector(this.ptr.add(0xD0), 0x30, SObjectiveTokenPropertyLink);
    }

    get flags() {
        return this.ptr.add(0xA8).readU32();
    }

    get missionOwnerId() {
        return this.ptr.add(0xB0).readU64();
    }

    get creatorId() {
        return this.ptr.add(0xE8).readU64();
    }

    get contractDefinitionId() {
        return readCryGuid(this.ptr.add(0xF0));
    }

    get contractId() {
        return readCryGuid(this.ptr.add(0x118));
    }

    toObject(includeNested = false) {
        const out = {
            seed: this.seed,
            title: this.title,
            titleHUD: this.titleHUD,
            description: this.description,
            missionGiverName: this.ptr.add(0x10).readU32(),
            missionDifficulty: this.ptr.add(0x14).readS32(),
            reward: this.reward,
            rewardMax: this.rewardMax,
            buyInAmount: this.buyInAmount,
            creationFee: this.creationFee,
            currencyType: this.currencyType,
            missionType: this.missionType,
            timeOutTime: this.timeOutTime,
            brokerEntryId: this.brokerEntryId,
            contractTemplateId: this.contractTemplateId,
            propertyCount: this.properties.count,
            missionId: this.missionId,
            cannotShareWithPlayerCount: this.cannotShareWithPlayerIds.count,
            flags: this.flags,
            missionOwnerId: this.missionOwnerId.toString(),
            objectiveTokenCount: this.objectiveTokens.count,
            propertyLinkCount: this.propertyLinks.count,
            creatorId: this.creatorId.toString(),
            contractDefinitionId: this.contractDefinitionId,
            abandonedCooldownTime: this.ptr.add(0x100).readFloat(),
            abandonedCooldownTimeVariation: this.ptr.add(0x104).readFloat(),
            personalCooldownTime: this.ptr.add(0x108).readFloat(),
            personalCooldownTimeVariation: this.ptr.add(0x10C).readFloat(),
            timeToCompleteOverride: this.ptr.add(0x110).readFloat(),
            contractId: this.contractId,
            failedPropertyInfo: readCryString(this.ptr.add(0x128)),
            maxPlayersPerInstance: this.ptr.add(0x130).readS32()
        };

        if (includeNested) {
            out.properties = this.properties.toArray(64).map(property => property.toObject());
            out.cannotShareWithPlayerIds = this.cannotShareWithPlayerIds.toArray(64).map(idPtr => readEntityId(idPtr));
            out.objectiveTokens = this.objectiveTokens.toArray(64).map(token => token.toObject(true));
            out.propertyLinks = this.propertyLinks.toArray(64).map(link => link.toObject());
        }

        return out;
    }
}

class CMissionLogEntry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get missionId() {
        return readCryGuid(this.ptr.add(0x08));
    }

    get details() {
        return new SMissionEntryDetails(this.ptr.add(0x18));
    }

    get state() {
        return this.ptr.add(0x150).readS32();
    }

    get rewardBonusMultiplier() {
        return this.ptr.add(0x154).readFloat();
    }

    get read() {
        return this.ptr.add(0x158).readU8() !== 0;
    }

    get shared() {
        return this.ptr.add(0x159).readU8() !== 0;
    }

    get playerMissionId() {
        return readCryGuid(this.ptr.add(0x160));
    }

    get activeObjectives() {
        return new StdVector(this.ptr.add(0x180), 0x110, ActiveMissionObjective);
    }

    get completedObjectives() {
        return new StdVector(this.ptr.add(0x1B8), 0x80, CompletedMissionObjective);
    }

    get uiDisplayInfo() {
        return new SMissionUIDisplayInfo(this.ptr.add(0x1F8));
    }

    get activeMissionPlayers() {
        return new StdVector(this.ptr.add(0x250), 0x08);
    }

    get missionPlayerCount() {
        return this.ptr.add(0x268).readS32();
    }

    toObject(includeObjectives = true, includeNestedDetails = false) {
        const details = this.details;
        const out = {
            ptr: this.ptr.toString(),
            vtable: this.ptr.readPointer().toString(),
            missionId: this.missionId,
            playerMissionId: this.playerMissionId,
            state: this.state,
            read: this.read,
            shared: this.shared,
            rewardBonusMultiplier: this.rewardBonusMultiplier,
            missionTimerEndFrame: this.ptr.add(0x170).readS64().toString(),
            missionDeadlineTimeDisplay: this.ptr.add(0x178).readFloat(),
            endReason: this.ptr.add(0x1F0).readU32(),
            missionPlayerCount: this.missionPlayerCount,
            activeMissionModifierFlags: this.ptr.add(0x26C).readU32(),
            objectiveTokenMarkerHandlers: this.ptr.add(0x270).readPointer().toString(),
            activeMissionPlayers: this.activeMissionPlayers.toArray(64).map(idPtr => readEntityId(idPtr)),
            uiDisplayInfo: this.uiDisplayInfo.toObject(),
            details: details.toObject(includeNestedDetails),
            contractDebugName: gEnv.missionSystem?.getContractDebugName(details.ptr.add(0xF0)) ?? null,
            activeObjectiveCount: this.activeObjectives.count,
            completedObjectiveCount: this.completedObjectives.count
        };

        if (includeObjectives) {
            out.activeObjectives = this.activeObjectives.toArray(64).map(objective => objective.toObject(true));
            out.completedObjectives = this.completedObjectives.toArray(64).map(objective => objective.toObject(true));
        }

        return out;
    }
}

class SRegisteredObjectiveMarker {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            missionId: readCryGuid(this.ptr),
            objectiveId: readCryString(this.ptr.add(0x10)),
            markerEntityPtr: lower48(this.ptr.add(0x18).readPointer()).toString()
        };
    }
}

class CSCPlayerMissionLog extends EntityComponent {
    constructor(ptrValue) {
        super(ptrValue, "SCPlayerMissionLog");
    }

    get missions() {
        return new StdVector(this.ptr.add(0x448 + 0x08), 0x278, CMissionLogEntry);
    }

    get serializedMissions() {
        return this.missions;
    }

    get missionsLocal() {
        return new StdVector(this.ptr.add(0x468), 0x278, CMissionLogEntry);
    }

    get trackedMissionsLogEntries() {
        return new StdVector(this.ptr.add(0x480), 0x278, CMissionLogEntry);
    }

    get completedMissions() {
        return new StdVector(this.ptr.add(0x4B8 + 0x08), 0x278, CMissionLogEntry);
    }

    get completedMissionsLocal() {
        return new StdVector(this.ptr.add(0x4D8), 0x278, CMissionLogEntry);
    }

    get trackedMissionId() {
        return readCryGuid(this.ptr.add(0x4F0 + 0x08));
    }

    get lastActiveTrackedMissionId() {
        return readCryGuid(this.ptr.add(0x508));
    }

    get prevTrackedMissionId() {
        return readCryGuid(this.ptr.add(0x518));
    }

    get tutorialMode() {
        return this.ptr.add(0x528 + 0x08).readU8() !== 0;
    }

    get waitingForTutorialMission() {
        return this.ptr.add(0x538 + 0x08).readU8() !== 0;
    }

    get tutorialMissionIds() {
        return new StdVector(this.ptr.add(0x548 + 0x08), 0x10);
    }

    get acceptedMissionRequests() {
        return stdMapInfo(this.ptr.add(0x568));
    }

    get missionUIDisplayInfoMap() {
        return stdMapInfo(this.ptr.add(0x578 + 0x08));
    }

    get objectiveVisibilityMap() {
        return stdMapInfo(this.ptr.add(0x590 + 0x08));
    }

    get notifiedActiveObjectives() {
        return stdMapInfo(this.ptr.add(0x5A8));
    }

    get tutorialMissionId() {
        return readCryGuid(this.ptr.add(0x5B8 + 0x08));
    }

    get activeBeacons() {
        return stdMapInfo(this.ptr.add(0x5F0 + 0x08));
    }

    get beaconCooldowns() {
        return stdMapInfo(this.ptr.add(0x628 + 0x08));
    }

    get completedMissionTagsRaw() {
        return this.ptr.add(0x640).readU32();
    }

    get startMissionTrackingTime() {
        return this.ptr.add(0x648).readS64().toString();
    }

    get prevMissionStates() {
        return stdMapInfo(this.ptr.add(0x650));
    }

    get displayedMissionObjectives() {
        return new StdVector(this.ptr.add(0x1098), 0x120);
    }

    get objectiveMarkers() {
        return new StdVector(this.ptr.add(0x1130), 0x20, SRegisteredObjectiveMarker);
    }

    get missionsWithErrors() {
        return new StdVector(this.ptr.add(0x11B0), 0x10);
    }

    get pendingUnsubscribes() {
        return new StdVector(this.ptr.add(0x13C0), 0x10);
    }

    get targetAppGuid() {
        return readCryGuid(this.ptr.add(0x14F0));
    }

    get activeTrackedContractName() {
        return readCString(callVFunc(
            this.ptr,
            223,
            "pointer",
            ["pointer"],
            [Memory.allocUtf8String("")],
            "ISCPlayerMissionLog::GetActiveTrackedContractName"
        ));
    }

    get activeTrackedContractDefId() {
        const output = Memory.alloc(0x10);
        callVFunc(
            this.ptr,
            224,
            "pointer",
            ["pointer"],
            [output],
            "ISCPlayerMissionLog::GetActiveTrackedContractDefId"
        );
        return readCryGuid(output);
    }

    get hasAcceptedMission() {
        return callVFunc(this.ptr, 225, "bool", [], [], "ISCPlayerMissionLog::HasAcceptedMission");
    }

    get activeTrackedMissionId() {
        const output = Memory.alloc(0x10);
        callVFunc(this.ptr, 226, "pointer", ["pointer"], [output], "ISCPlayerMissionLog::GetActiveTrackedMissionId");
        return readCryGuid(output);
    }

    get lastActiveTrackedMissionIdFromInterface() {
        const output = Memory.alloc(0x10);
        callVFunc(this.ptr, 227, "pointer", ["pointer"], [output], "ISCPlayerMissionLog::GetLastActiveTrackedMissionId");
        return readCryGuid(output);
    }

    get isTutorialModeActive() {
        return callVFunc(this.ptr, 233, "bool", [], [], "ISCPlayerMissionLog::IsTutorialModeActive");
    }

    get waitingForTutorialMissionFromInterface() {
        return callVFunc(this.ptr, 234, "bool", [], [], "ISCPlayerMissionLog::GetWaitingForTutorialMission");
    }

    get playerAcceptedMissionsLimitAmount() {
        return callVFunc(this.ptr, 251, "int", [], [], "ISCPlayerMissionLog::GetPlayerAcceptedMissionsLimitAmount");
    }

    get playerAcceptedMissionsAmount() {
        return callVFunc(this.ptr, 252, "int", [], [], "ISCPlayerMissionLog::GetPlayerAcceptedMissionsAmount");
    }

    get baseFields() {
        return {
            vtable: this.ptr.readPointer().toString(),
            legacyEventSystemPtr: this.ptr.add(0x48).toString()
        };
    }

    get remoteMethods() {
        const names = [
            "rmClNotifyUIMissionAvailable",
            "rmClNotifyUIReward",
            "rmClNotifyUIObjectiveEvent",
            "rmClNotifyUIMissionShared",
            "rmClOnMissionAccepted",
            "rmClNotifyUICommsNotification",
            "rmClNotifyUICustomNotification",
            "rmClNotifyUIObjectiveCommsNotification",
            "rmClOnDisplayRewardNotification",
            "rmClNotifyUIRegularNotification",
            "rmClSetMissionHasErrors",
            "rmAuthMissionShareResponse",
            "rmAuthTrackMissionEntry",
            "rmAuthAcceptMission",
            "rmAuthCreateMissionServiceBeacon",
            "rmAuthCancelMissionServiceBeacon",
            "rmAuthCompleteMissionServiceBeacon"
        ];
        const start = 0x228;
        const out = {};
        for (let i = 0; i < names.length; i++) {
            out[names[i]] = this.ptr.add(start + i * 0x20).toString();
        }
        return out;
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            baseFields: this.baseFields,
            remoteMethods: this.remoteMethods,
            missions: this.missions.toSummary(),
            missionsLocal: this.missionsLocal.toSummary(),
            trackedMissionsLogEntries: this.trackedMissionsLogEntries.toSummary(),
            completedMissions: this.completedMissions.toSummary(),
            completedMissionsLocal: this.completedMissionsLocal.toSummary(),
            trackedMissionId: this.trackedMissionId,
            lastActiveTrackedMissionId: this.lastActiveTrackedMissionId,
            prevTrackedMissionId: this.prevTrackedMissionId,
            tutorialMode: this.tutorialMode,
            waitingForTutorialMission: this.waitingForTutorialMission,
            tutorialMissionIds: this.tutorialMissionIds.toArray(64).map(p => readCryGuid(p)),
            acceptedMissionRequests: this.acceptedMissionRequests,
            missionUIDisplayInfoMap: this.missionUIDisplayInfoMap,
            objectiveVisibilityMap: this.objectiveVisibilityMap,
            notifiedActiveObjectives: this.notifiedActiveObjectives,
            tutorialMissionId: this.tutorialMissionId,
            activeBeacons: this.activeBeacons,
            beaconCooldowns: this.beaconCooldowns,
            completedMissionTagsRaw: this.completedMissionTagsRaw,
            startMissionTrackingTime: this.startMissionTrackingTime,
            prevMissionStates: this.prevMissionStates,
            displayedMissionObjectives: this.displayedMissionObjectives.toSummary(),
            missionActorMarkers: {
                parent: lower48(this.ptr.add(0x10B0).readPointer()).toString(),
                objectDataBank: componentPtrInfo(this.ptr.add(0x10B8)),
                markedEntities: new StdVector(this.ptr.add(0x10C0), 0x08).toSummary(),
                trackedActors: new StdVector(this.ptr.add(0x10D8 + 0x08), 0x08).toSummary(),
                missionAlliedNPCs: new StdVector(this.ptr.add(0x1118), 0x18).toSummary()
            },
            objectiveMarkers: this.objectiveMarkers.toArray(64).map(marker => marker.toObject()),
            flags: {
                isS42: this.ptr.add(0x1168).readU8() !== 0,
                doFade: this.ptr.add(0x1169).readU8() !== 0,
                updateMission: this.ptr.add(0x116A).readU8() !== 0,
                constantRefresh: this.ptr.add(0x116B).readU8() !== 0,
                waitForMissionTitle: this.ptr.add(0x116C).readU8() !== 0,
                repopulateObjectives: this.ptr.add(0x116D).readU8() !== 0
            },
            updateDisplay: this.ptr.add(0x1170).readS32(),
            displayTime: this.ptr.add(0x1178).readS64().toString(),
            fadeTime: this.ptr.add(0x1180).readS64().toString(),
            fadeDelay: this.ptr.add(0x1188).readFloat(),
            missionsWithErrors: this.missionsWithErrors.toArray(64).map(p => readCryGuid(p)),
            pushMessages: this.ptr.add(0x11C8).toString(),
            analytics: {
                activeMissionData: stdMapInfo(this.ptr.add(0x12F8 + 0x08)),
                parent: componentPtrInfo(this.ptr.add(0x1310)),
                phaseName: readCryString(this.ptr.add(0x1318))
            },
            warehouseOrders: {
                missionLog: componentPtrInfo(this.ptr.add(0x1320)),
                createdOrders: new StdVector(this.ptr.add(0x1328 + 0x08), 0x20).toSummary(),
                operationQueue: eastlDequeInfo(this.ptr.add(0x1348))
            },
            pendingUnsubscribes: this.pendingUnsubscribes.toArray(64).map(p => readCryGuid(p)),
            listeners: this.ptr.add(0x13F8).toString(),
            elevatorRewardManager: this.ptr.add(0x1438).readPointer().toString(),
            scenarioProgress: {
                missionLog: componentPtrInfo(this.ptr.add(0x1440)),
                operationQueue: eastlDequeInfo(this.ptr.add(0x1448)),
                processingOperation: this.ptr.add(0x14A0).readU8() !== 0
            },
            playerNotificationManager: {
                vtable: this.ptr.add(0x14C8).readPointer().toString(),
                cachedOneTimeCommsTokenIds: new StdVector(this.ptr.add(0x14D0), 0x08).toSummary(),
                missionLog: componentPtrInfo(this.ptr.add(0x14E8))
            },
            targetAppGuid: this.targetAppGuid,
            numberOfActiveNotForReleaseMissions: this.ptr.add(0x1500).readS32(),
            interfaceState: {
                activeTrackedContractName: this.activeTrackedContractName,
                activeTrackedContractDefId: this.activeTrackedContractDefId,
                hasAcceptedMission: this.hasAcceptedMission,
                activeTrackedMissionId: this.activeTrackedMissionId,
                lastActiveTrackedMissionId: this.lastActiveTrackedMissionIdFromInterface,
                isTutorialModeActive: this.isTutorialModeActive,
                waitingForTutorialMission: this.waitingForTutorialMissionFromInterface,
                playerAcceptedMissionsLimitAmount: this.playerAcceptedMissionsLimitAmount,
                playerAcceptedMissionsAmount: this.playerAcceptedMissionsAmount
            }
        };
    }

    listActiveContracts(includeObjectives = true, includeNestedDetails = false) {
        const local = this.missionsLocal.count > 0 ? this.missionsLocal : this.missions;
        return local.toArray(256).map(entry => entry.toObject(includeObjectives, includeNestedDetails));
    }
}

class CPhysicalProxy extends EntityComponent {
    constructor(ptrValue) {
        super(ptrValue, "CPhysicalProxy");
    }

    get physicalEntity() {
        const physicalEntityPtr = lower48(this.ptr.add(0x350).readPointer());
        return physicalEntityPtr.isNull() ? null : new CPhysicalEntity(physicalEntityPtr);
    }

    get cachedPhysicalEntity() {
        const physicalEntityPtr = lower48(this.ptr.add(0x358).readPointer());
        return physicalEntityPtr.isNull() ? null : new CPhysicalEntity(physicalEntityPtr);
    }
}

class SDamageInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get damageValues() {
        const values = [];
        for (let i = 0; i < 6; i++) values.push(this.ptr.add(0x08 + i * 0x04).readFloat());
        return values;
    }

    get totalDamage() {
        return this.damageValues.reduce((sum, value) => Number.isFinite(value) ? sum + value : sum, 0);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            damageValues: this.damageValues,
            totalDamage: this.totalDamage
        };
    }
}

class CBindingsVariableFloat {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get previousValue() {
        return this.ptr.add(0x40).readFloat();
    }

    get dirtyValue() {
        return this.ptr.add(0x44).readFloat();
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            previousValue: this.previousValue,
            dirtyValue: this.dirtyValue
        };
    }
}

class CSCBodyHealthSPartIdCache {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            physPartId: this.ptr.readS32(),
            jointDefIndex: this.ptr.add(0x08).readU64().toString(),
            bodyPartIndex: this.ptr.add(0x10).readU64().toString()
        };
    }
}

class CSCBodyHealthSBodyPart {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get physPartIds() {
        return new StdVector(this.ptr.add(0x30), 0x08);
    }

    toObject(includePhysPartIds = true, physPartLimit = 32) {
        const healthStat = this.ptr.add(0x08).readS32();
        const wearStat = this.ptr.add(0x0C).readS32();
        return {
            ptr: this.ptr.toString(),
            config: this.ptr.readPointer().toString(),
            partHealthStat: healthStat,
            partHealthStatName: enumName(EActorStatType, healthStat),
            partWearStat: wearStat,
            partWearStatName: enumName(EActorStatType, wearStat),
            armor: componentPtrInfo(this.ptr.add(0x10)),
            bodyPartRef: typedMemberInfo(this.ptr.add(0x18), "DataCoreRecordRef<SBodyPartDef>", 0x18),
            physPartIds: includePhysPartIds ? this.physPartIds.toArray(physPartLimit).map(p => p.readU64().toString()) : this.physPartIds.toSummary(),
            partNameCRC32: this.ptr.add(0x48).readU32()
        };
    }
}

class SRecentAttackerData {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            pLastAttackerEntity: componentPtrInfo(this.ptr.add(0x00)),
            pLastAttackingWeapon: componentPtrInfo(this.ptr.add(0x08)),
            pEntityWhoCausedBleeding: componentPtrInfo(this.ptr.add(0x10)),
            pEntityWhoCausedDowned: componentPtrInfo(this.ptr.add(0x18)),
            pEntityWhoCausedUnconscious: componentPtrInfo(this.ptr.add(0x20)),
            pEntityWhoCausedDead: componentPtrInfo(this.ptr.add(0x28)),
            lastHitType: this.ptr.add(0x30).readS32(),
            recentAttackersWhileDowned: stdMapInfo(this.ptr.add(0x38))
        };
    }
}

function readInvulnerabilityParams(value) {
    const flags = ptr(value).readU8();
    const names = Object.entries(EInvulnerableFlags)
        .filter(([, bit]) => (flags & bit) !== 0)
        .map(([name]) => name);
    return {
        flags,
        flagsHex: `0x${flags.toString(16).padStart(2, "0")}`,
        names
    };
}

class CSCBodyHealthComponent extends EntityComponent {
    constructor(ptrValue) {
        super(ptrValue, "CSCBodyHealthComponent");
    }

    vfuncAddress(slot) {
        return this.ptr.readPointer().add(slot * PTR_SIZE).readPointer();
    }

    get parentActor() {
        const actorPtr = lower48(this.ptr.add(0x248).readPointer());
        return actorPtr.isNull() ? null : new CActor(actorPtr);
    }

    get health() {
        return callVFunc(this.ptr, 221, "float", [], [], "CSCBodyHealthComponent::GetHealth");
    }

    get maxHealth() {
        return callVFunc(this.ptr, 222, "float", [], [], "CSCBodyHealthComponent::GetMaxHealth");
    }

    get healthRatio() {
        return callVFunc(this.ptr, 223, "float", [], [], "CSCBodyHealthComponent::GetHealthRatio");
    }

    get isDead() {
        return callVFunc(this.ptr, 227, "bool", [], [], "CSCBodyHealthComponent::IsDead");
    }

    get isInvulnerable() {
        return callVFunc(this.ptr, 255, "bool", [], [], "CSCBodyHealthComponent::IsInvulnerable");
    }

    get isSalvagable() {
        return callVFunc(this.ptr, 253, "bool", [], [], "CSCBodyHealthComponent::IsSalvagable");
    }

    get isRepairable() {
        return callVFunc(this.ptr, 254, "bool", [], [], "CSCBodyHealthComponent::IsRepairable");
    }

    get isUsingIntegrityDamageHandling() {
        return callVFunc(this.ptr, 258, "bool", [], [], "CSCBodyHealthComponent::IsUsingIntegrityDamageHandling");
    }

    get healthPartCount() {
        return callVFunc(this.ptr, 249, "uint64", [], [], "CSCBodyHealthComponent::GetHealthPartCount").toString();
    }

    setHealth(value, modifierId = 0, reason = 1) {
        callVFunc(
            this.ptr,
            224,
            "void",
            ["float", "int64", "uint8"],
            [parseFiniteFloat(value, "health"), int64(modifierId), parseS32(reason, "reason") & 0xFF],
            "CSCBodyHealthComponent::SetHealth"
        );
    }

    restoreToMax(reason = 1) {
        const maxHealth = this.maxHealth;
        this.setHealth(maxHealth, 0, reason);
        return this.toObject();
    }

    get authorityRequestHitRemoteMethod() {
        return new CSerializedRemoteMethod(this.ptr.add(0x1B0), "CSerializedRemoteMethod<void(HitInfo const &, patches...)>");
    }

    get authorityRequestHitWithJointOffsetsRemoteMethod() {
        return new CSerializedRemoteMethod(this.ptr.add(0x1D0), "CSerializedRemoteMethod<void(HitInfo const &, HitInfoNetJointOffsets const &, patches...)>");
    }

    get partIdCacheMap() {
        return this.ptr.add(0x1F0);
    }

    partIdCache(limit = 128) {
        return traverseStdTreeMap(this.partIdCacheMap, node => ({
            key: node.add(0x20).readS32(),
            ...new CSCBodyHealthSPartIdCache(node.add(0x28)).toObject()
        }), limit);
    }

    get bodyPartsVector() {
        return new StdVector(this.ptr.add(0x200), 0x50, CSCBodyHealthSBodyPart);
    }

    bodyParts(limit = 32, includePhysPartIds = true) {
        return this.bodyPartsVector.toArray(limit).map(part => part.toObject(includePhysPartIds));
    }

    get bodyPartsDamageOverTimeVector() {
        return new StdVector(this.ptr.add(0x218), 0x168, HitInfo);
    }

    bodyPartsDamageOverTime(limit = 8) {
        return this.bodyPartsDamageOverTimeVector.toArray(limit).map(hit => hit.toObject());
    }

    get invulnerabilityParams() {
        return new CSerializedVariable(
            this.ptr.add(0x250),
            readInvulnerabilityParams,
            "CInvulnerabilityParams",
            0x01
        );
    }

    get recentAttackerData() {
        return new SRecentAttackerData(this.ptr.add(0x530));
    }

    get hitTimeList() {
        return new StdVector(this.ptr.add(0x650), 0x08);
    }

    get lastExplosionExposure() {
        return new StdVector(this.ptr.add(0x668), 0x08);
    }

    get deferredDetatchedArmorPieces() {
        return new StdVector(this.ptr.add(0x680), 0x08);
    }

    trackedDamageMap(limit = 64) {
        return traverseStdTreeMap(this.ptr.add(0x6A8), node => ({
            key: new CStringHash(node.add(0x20)).toObject(),
            damage: new SDamageInfo(node.add(0x38)).toObject()
        }), limit);
    }

    surface(includeAddresses = true) {
        const slots = CSCBodyHealthComponentSurface.vtable;
        return {
            ptr: this.ptr.toString(),
            surface: CSCBodyHealthComponentSurface,
            vtable: this.ptr.readPointer().toString(),
            addresses: includeAddresses ? vtableAddressMap(this, slots) : null
        };
    }

    get state() {
        return this.toObject();
    }

    toJSON() {
        return this.toObject();
    }

    toObject(options = {}) {
        const bodyPartLimit = Number.isInteger(Number(options.bodyPartLimit)) ? Number(options.bodyPartLimit) : 16;
        const includeBodyParts = options.includeBodyParts !== false;
        const includeDamageOverTime = options.includeDamageOverTime === true;
        const includeTrackedDamage = options.includeTrackedDamage === true;
        const includePartIdCache = options.includePartIdCache === true;
        return {
            ...super.toObject(),
            ptr: this.ptr.toString(),
            health: this.health,
            maxHealth: this.maxHealth,
            healthRatio: this.healthRatio,
            isDead: this.isDead,
            isInvulnerable: this.isInvulnerable,
            isSalvagable: this.isSalvagable,
            isRepairable: this.isRepairable,
            isUsingIntegrityDamageHandling: this.isUsingIntegrityDamageHandling,
            healthPartCount: this.healthPartCount,
            parentActor: this.parentActor?.ptr.toString() ?? null,
            vehicleCollisionBodyPartId: this.ptr.add(0x230).readS32(),
            bodyMapping: this.ptr.add(0x238).readPointer().toString(),
            healthConfig: this.ptr.add(0x240).readPointer().toString(),
            actorComponentPtr: componentPtrInfo(this.ptr.add(0x248)),
            invulnerabilityParams: this.invulnerabilityParams.toObject(),
            collisionInvulnerableFrames: this.ptr.add(0x260).readS32(),
            isPlayer: this.ptr.add(0x264).readU8() !== 0,
            electronDamageHandler: typedMemberInfo(this.ptr.add(0x268), "CElectronDamageHandler", 0x2C8),
            recentAttackerData: this.recentAttackerData.toObject(),
            hitBindings: {
                angle: new CBindingsVariableFloat(this.ptr.add(0x578)).toObject(),
                alpha: new CBindingsVariableFloat(this.ptr.add(0x5C0)).toObject(),
                scale: new CBindingsVariableFloat(this.ptr.add(0x608)).toObject()
            },
            hitTimeList: this.hitTimeList.toSummary(),
            lastExplosionExposure: this.lastExplosionExposure.toSummary(),
            deferredDetatchedArmorPieces: this.deferredDetatchedArmorPieces.toSummary(),
            healthEffects: this.ptr.add(0x698).readPointer().toString(),
            trackedDamage: includeTrackedDamage ? this.trackedDamageMap(options.trackedDamageLimit ?? 32) : stdMapInfo(this.ptr.add(0x6A8)),
            partIdCache: includePartIdCache ? this.partIdCache(options.partIdCacheLimit ?? 128) : stdMapInfo(this.partIdCacheMap),
            bodyParts: includeBodyParts ? this.bodyParts(bodyPartLimit, options.includePhysPartIds !== false) : this.bodyPartsVector.toSummary(),
            bodyPartsDamageOverTime: includeDamageOverTime ? this.bodyPartsDamageOverTime(options.damageOverTimeLimit ?? 8) : this.bodyPartsDamageOverTimeVector.toSummary(),
            remoteMethods: {
                authorityRequestHit: this.authorityRequestHitRemoteMethod.toObject(),
                authorityRequestHitWithJointOffsets: this.authorityRequestHitWithJointOffsetsRemoteMethod.toObject()
            }
        };
    }
}

class CRenderProxy {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get slotsBegin() {
        return this.ptr.add(0x0B8).readPointer();
    }

    get slotsEnd() {
        return this.ptr.add(0x0C0).readPointer();
    }

    get slotsCapacity() {
        return this.ptr.add(0x0C8).readPointer();
    }

    get slotCount() {
        const begin = this.slotsBegin;
        const end = this.slotsEnd;
        return begin.isNull() || end.isNull() ? 0 : end.sub(begin).toInt32() / PTR_SIZE;
    }

    get lastEmptySlotId() {
        return this.ptr.add(0x0D0).readS32();
    }
}

class CActor {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get storage() {
        return this.ptr.add(0x240).readPointer();
    }

    get healthComponent() {
        const componentPtr = lower48(this.ptr.add(0x550).readPointer());
        return componentPtr.isNull() ? null : new CSCBodyHealthComponent(componentPtr);
    }

    get animatedCharacter() {
        const componentPtr = lower48(this.ptr.add(0x5A8).readPointer());
        return componentPtr.isNull() ? null : new CAnimatedCharacter(componentPtr);
    }

    get physicalProxyComponentPtr() {
        return componentPtrInfo(this.ptr.add(0x5D8));
    }

    get playerComponentPtr() {
        return componentPtrInfo(this.ptr.add(0x690));
    }

    get jumpFallLandConfigCache() {
        return new SharedPtr(this.ptr.add(0xB40), "SCJumpConfig::SCConfigCache const");
    }

    get clientPlayerDamageRemoteMethod() {
        return new CSerializedRemoteMethod(this.ptr.add(0x8E0), "CSerializedRemoteMethod<void(SPlayerDamageReport)>");
    }

    get multicastKillRemoteMethod() {
        return new CSerializedRemoteMethod(this.ptr.add(0x900), "CSerializedRemoteMethod<void(SKillParams)>");
    }


    getBoneTransform(boneId) {
        const id = Number(boneId);
        const output = Memory.alloc(0x20);
        zeroMemory(output, 0x20);
        try {
            const returned = cActorGetBoneTransformNative()(this.ptr, output, id);
            const transform = new QuatTFloat(output);
            return {
                actor: this.ptr.toString(),
                boneId: id,
                name: boneName(id),
                returned: returned.toString(),
                transform: transform.toObject(),
                valid: transform.finite && !transform.identityFallback,
            };
        } catch (error) {
            return {
                actor: this.ptr.toString(),
                boneId: id,
                name: boneName(id),
                valid: false,
                error: String(error && error.stack ? error.stack : error),
            };
        }
    }

    getBoneTransforms(bones = BoneList) {
        return bones.map(([boneId]) => this.getBoneTransform(boneId));
    }

    scanBoneIds(maxBoneId = 0x16) {
        const result = [];
        for (let id = 0; id <= maxBoneId; id++) {
            result.push(this.getBoneTransform(id));
        }
        return result;
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            storage: this.storage.toString(),
            isPlayer: this.ptr.add(0x3B0).readU8() !== 0,
            isAIControlled: this.ptr.add(0x3B1).readU8() !== 0,
            healthComponent: this.healthComponent?.ptr.toString() ?? null,
            animatedCharacter: this.animatedCharacter?.toObject() ?? null,
            physicalProxyComponent: this.physicalProxyComponentPtr,
            playerComponent: this.playerComponentPtr,
            desiredMovementGaitRaw: bytesToHex(this.ptr.add(0x6B0), 0x04),
            actualMovementGaitRaw: bytesToHex(this.ptr.add(0x6B4), 0x04),
            shouldCollideWithPlayers: new CSerializedVariable(this.ptr.add(0x878), p => p.readU8() !== 0, "bool", 0x01).toObject(),
            shouldCollideWithNPCs: new CSerializedVariable(this.ptr.add(0x888), p => p.readU8() !== 0, "bool", 0x01).toObject(),
            colliderDesiredScaleFactor: new CSerializedVariable(this.ptr.add(0x8A0), p => p.readFloat(), "float", 0x04).toObject(),
            lastRequestedVelocity: readVec3f(this.ptr.add(0x9B0)),
            request: typedMemberInfo(this.ptr.add(0xA30), "SCharacterMoveRequest", 0x50),
            jumpFallLandConfigCache: this.jumpFallLandConfigCache.toObject(),
            clientPlayerDamageRemoteMethod: this.clientPlayerDamageRemoteMethod.toObject(),
            multicastKillRemoteMethod: this.multicastKillRemoteMethod.toObject()
        };
    }
}

class CEntity {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get flags() {
        return this.ptr.add(0x08).readU32();
    }

    get id() {
        return this.ptr.add(0x10).readS64();
    }

    get entityClassPtr() {
        return lower48(this.ptr.add(0x20).readPointer());
    }

    get entityClass() {
        const classPtr = this.entityClassPtr;
        return classPtr.isNull() ? null : new CEntityClass(classPtr);
    }

    get zonePos() {
        return new DVec3(
            this.ptr.add(0x48).readDouble(),
            this.ptr.add(0x50).readDouble(),
            this.ptr.add(0x58).readDouble()
        );
    }

    get entityFlags() {
        return this.ptr.add(0x128).readU32();
    }

    get name() {
        return readCryString(this.ptr.add(0x2A8));
    }

    get zoneFromMemory() {
        const zonePtr = this.ptr.add(0x2C0).readPointer();
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    get zone() {
        return this.getZone();
    }

    get childCount() {
        return callVFunc(this.ptr, 46, "int", [], [], "IEntity::GetChildCount");
    }

    getChild(index) {
        const output = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 47, "pointer", ["pointer", "int"], [output, index], "IEntity::GetChild");
        const entityPtr = lower48(output.readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get parent() {
        const output = Memory.alloc(PTR_SIZE);
        callVFunc(this.ptr, 48, "pointer", ["pointer"], [output], "IEntity::GetParent");
        const entityPtr = lower48(output.readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get localPos() {
        const output = Memory.alloc(0x18);
        callVFunc(this.ptr, 86, "pointer", ["pointer", "uint32"], [output, 0], "IEntity::GetZonePos");
        return new DVec3(output.readDouble(), output.add(0x08).readDouble(), output.add(0x10).readDouble());
    }

    get worldPos() {
        const output = Memory.alloc(0x18);
        callVFunc(this.ptr, 98, "pointer", ["pointer", "uint32"], [output, 0], "IEntity::GetWorldPos_2");
        return new DVec3(output.readDouble(), output.add(0x08).readDouble(), output.add(0x10).readDouble());
    }

    get isHidden() {
        return callVFunc(this.ptr, 108, "bool", [], [], "IEntity::IsHidden");
    }

    getComponentById(componentId) {
        const output = Memory.alloc(PTR_SIZE * 2);
        output.writePointer(NULL);
        output.add(PTR_SIZE).writePointer(NULL);

        const id = Memory.alloc(0x02);
        id.writeU16(componentId);

        const result = callVFunc(
            this.ptr,
            113,
            "pointer",
            ["pointer", "pointer"],
            [output, id],
            "IEntity::QueryComponent"
        );

        const componentPtr = lower48(output.readPointer());
        return !result.isNull() && !componentPtr.isNull() ? componentPtr : NULL;
    }

    getComponentByName(componentName) {
        const componentSystem = gEnv.entityComponentSystem;
        if (!componentSystem) return null;

        const id = componentSystem.getComponentIdByName(componentName);
        if (!id.success || id.componentId === 0xFFFF) return null;

        const componentPtr = this.getComponentById(id.componentId);
        return componentPtr.isNull() ? null : componentPtr;
    }

    queryAllComponentIds() {
        throw new Error("IEntity::QueryAllComponents_2 requires native temp-vector construction/destruction; use unsafeQueryAllComponentIds only when that allocator path is confirmed");
    }

    unsafeQueryAllComponentIds(limit = 512) {
        const vector = Memory.alloc(0x18);
        zeroMemory(vector, 0x18);

        callVFunc(
            this.ptr,
            120,
            "void",
            ["pointer"],
            [vector],
            "IEntity::QueryAllComponents_2"
        );

        const begin = vector.readPointer();
        const end = vector.add(0x08).readPointer();
        if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return [];

        const count = Math.min(Math.floor(end.sub(begin).toUInt32() / 0x02), Number(limit));
        const out = [];
        for (let i = 0; i < count; i++) {
            out.push(begin.add(i * 0x02).readU16());
        }
        return out;
    }

    declaredComponentIds(limit = 256) {
        return this.entityClass?.componentIds(limit) ?? [];
    }

    getComponent(componentId) {
        const componentSystem = gEnv.entityComponentSystem;
        const id = parseU16(componentId, "componentId");
        const componentPtr = this.getComponentById(id);
        if (componentPtr.isNull()) return null;
        return new EntityComponent(componentPtr, componentSystem?.getComponentNameById(id) ?? `component_${id}`);
    }

    listComponents(options = {}) {
        const componentSystem = gEnv.entityComponentSystem;
        const includeMissing = options.includeMissing === true;
        const limit = Number.isInteger(Number(options.limit)) ? Number(options.limit) : 512;
        let source = options.source ?? "declaredClass";
        let ids = [];
        const infoById = new Map();
        let queryAllError = null;

        if (source === "queryAll") {
            if (options.allowUnsafeNativeVector !== true) {
                throw new Error("source=queryAll calls IEntity::QueryAllComponents_2 and is disabled unless allowUnsafeNativeVector is true");
            }
            try {
                ids = this.unsafeQueryAllComponentIds(limit);
            } catch (e) {
                queryAllError = e.message;
                source = "declaredClass";
            }
        }

        if (source === "declaredClass") {
            ids = this.declaredComponentIds(limit);
        } else if (source === "hybrid" || source === "declaredPlusRegisteredScan") {
            ids = this.declaredComponentIds(limit);
            const maxId = options.maxId === undefined ? null : parseU16(options.maxId, "maxId");
            if (componentSystem) {
                ids.push(...componentSystem.registeredComponentIds(maxId, options.allowRegisteredRangeFallback === true));
            }
            source = "declaredPlusRegisteredScan";
        } else if (source === "registeredScan") {
            const maxId = options.maxId === undefined ? null : parseU16(options.maxId, "maxId");
            if (componentSystem) {
                ids = componentSystem.registeredComponentIds(maxId, options.allowRegisteredRangeFallback === true);
            }
        }

        const seen = new Set();
        const components = [];
        for (const componentId of ids) {
            const id = parseU16(componentId, "componentId");
            if (seen.has(id)) continue;
            seen.add(id);

            const componentPtr = this.getComponentById(id);
            if (componentPtr.isNull()) {
                if (includeMissing) {
                    const info = infoById.get(id) ?? componentSystem?.componentInfoById(id) ?? { componentId: id, name: null };
                    components.push({
                        ...info,
                        ptr: null,
                        installed: false
                    });
                }
                continue;
            }

            const info = infoById.get(id) ?? componentSystem?.componentInfoById(id) ?? { componentId: id, name: null };
            components.push({
                ...info,
                ptr: componentPtr.toString(),
                installed: true
            });
        }

        return {
            entity: this.summary(),
            source,
            notes: {
                declaredClass: "checks component ids declared by the entity class",
                registeredScan: "checks every component id from IEntityComponentSystem::GetAllComponents with IEntity::QueryComponent; maxId can cap the ids; numeric range fallback is disabled unless allowRegisteredRangeFallback is true",
                declaredPlusRegisteredScan: "declaredClass plus registeredScan; use this to identify installed dynamic-only components without QueryAllComponents_2"
            },
            queryAllError,
            count: components.length,
            components
        };
    }

    get renderProxy() {
        const componentPtr = this.getComponentByName("CRenderProxy");
        return componentPtr ? new CRenderProxy(componentPtr) : null;
    }

    get physicalProxy() {
        const componentPtr = lower48(this.ptr.add(0x500).readPointer());
        return componentPtr.isNull() ? null : new CPhysicalProxy(componentPtr);
    }

    get healthComponent() {
        const componentPtr = this.getComponentByName("SCBodyHealthComponent");
        return componentPtr ? new CSCBodyHealthComponent(componentPtr) : null;
    }

    get missionLog() {
        const componentPtr = this.getComponentByName("SCPlayerMissionLog");
        return componentPtr ? new CSCPlayerMissionLog(componentPtr) : null;
    }

    get inventoryContainerComponent() {
        for (const componentName of ["CInventoryContainerComponent", "InventoryContainerComponent", "InventoryContainer"]) {
            const componentPtr = this.getComponentByName(componentName);
            if (componentPtr) return new CInventoryContainerComponent(componentPtr);
        }

        return null;
    }

    get personalThoughtComponent() {
        for (const componentName of ["CSCLocalPlayerPersonalThoughtComponent", "LocalPlayerPersonalThoughtComponent", "PersonalThoughtComponent"]) {
            const componentPtr = this.getComponentByName(componentName);
            if (componentPtr) return new CSCLocalPlayerPersonalThoughtComponent(componentPtr);
        }

        return null;
    }

    get actor() {
        const componentPtr = this.getComponentByName("Actor");
        return componentPtr ? new CActor(componentPtr) : null;
    }

    get actorEntity() {
        const directOffsets = [0xF20, 0xFD8];
        for (const offset of directOffsets) {
            try {
                const actorEntityPtr = lower48(this.ptr.add(offset).readPointer());
                if (actorEntityPtr.isNull()) continue;
                const parentPtr = lower48(actorEntityPtr.add(0xC0).readPointer());
                if (parentPtr.equals(this.ptr)) return new CActorEntity(actorEntityPtr);
            } catch (_) {}
        }

        try {
            const proxyPtr = lower48(this.ptr.add(0x4E8).readPointer());
            if (!proxyPtr.isNull()) {
                const actorEntityPtr = lower48(proxyPtr.add(0x410).readPointer());
                if (!actorEntityPtr.isNull() && lower48(actorEntityPtr.add(0xC0).readPointer()).equals(this.ptr)) {
                    return new CActorEntity(actorEntityPtr);
                }
            }
        } catch (_) {}

        return null;
    }

    get ecusGroupParent() {
        const entityPtr = lower48(this.ptr.add(0x4E8).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get ecusGroupRoot() {
        const entityPtr = lower48(this.ptr.add(0x4F0).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get entityOwners() {
        const owners = [];
        for (let i = 0; i < 3; i++) {
            const entityPtr = lower48(this.ptr.add(0x508 + i * PTR_SIZE).readPointer());
            owners.push(entityPtr.isNull() ? null : new CEntity(entityPtr));
        }
        return owners;
    }

    getZone() {
        const zonePtr = callVFunc(this.ptr, 215, "pointer", [], [], "IEntity::GetZone");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    get hostedZone() {
        const zonePtr = callVFunc(this.ptr, 219, "pointer", [], [], "IEntity::GetHostedZone");
        return zonePtr.isNull() ? null : new CZone(lower48(zonePtr));
    }

    summary() {
        const read = (fn, fallback = null) => {
            try {
                return fn();
            } catch (e) {
                return fallback;
            }
        };

        return {
            ptr: this.ptr.toString(),
            id: read(() => String(this.id)),
            name: read(() => this.name),
            className: read(() => this.entityClass?.name ?? null),
            classPtr: read(() => this.entityClassPtr.toString()),
            flags: read(() => this.flags),
            entityFlags: read(() => this.entityFlags),
            isHidden: read(() => this.isHidden),
            childCount: read(() => this.childCount),
            worldPos: read(() => this.worldPos)
        };
    }

    directSummary() {
        const read = (fn, fallback = null) => {
            try {
                return fn();
            } catch (_) {
                return fallback;
            }
        };

        return {
            ptr: this.ptr.toString(),
            id: read(() => String(this.id)),
            name: read(() => this.name),
            className: read(() => this.entityClass?.name ?? null),
            classPtr: read(() => this.entityClassPtr.toString()),
            flags: read(() => this.flags),
            entityFlags: read(() => this.entityFlags),
            zonePos: read(() => this.zonePos)
        };
    }

    toObject(includeComponents = false) {
        const out = this.summary();
        if (includeComponents) out.components = this.listComponents().components;
        return out;
    }
}

class CActorEntity extends CPhysicalEntity {
    get parentEntity() {
        const entityPtr = lower48(this.ptr.add(0x0C0).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get gravity() { return readVec3f(this.ptr.add(0x400)); }
    get velocity() { return readVec3f(this.ptr.add(0x40C)); }
    get requestedVelocity() { return readVec3f(this.ptr.add(0x43C)); }
    get groundVelocity() { return readVec3f(this.ptr.add(0x448)); }
    get collisionVelocity() { return readVec3f(this.ptr.add(0x454)); }
    get localGForce() { return readVec3f(this.ptr.add(0x46C)); }
    get localCollisionGForce() { return readVec3f(this.ptr.add(0x478)); }
    get maxVelGround() { return this.ptr.add(0x4CC).readFloat(); }
    get maxVelActor() { return this.ptr.add(0x4D0).readFloat(); }
    get maxVelActorOverride() { return this.ptr.add(0x4D4).readFloat(); }
    get mass() { return this.ptr.add(0x4E4).readFloat(); }
    get airControl() { return this.ptr.add(0x4F4).readFloat(); }
    get airResistance() { return this.ptr.add(0x4F8).readFloat(); }
    get slopeFall() { return this.ptr.add(0x50C).readFloat(); }
    get collTypes() { return this.ptr.add(0x538).readS32(); }
    get actorFlags0() { return this.ptr.add(0x9BA).readU8(); }
    get actorFlags1() { return this.ptr.add(0x9BB).readU8(); }

    movementObject() {
        return {
            ptr: this.ptr.toString(),
            vtable: this.ptr.readPointer().toString(),
            parentEntity: this.parentEntity?.ptr.toString() ?? null,
            gravity: this.gravity,
            velocity: this.velocity,
            requestedVelocity: this.requestedVelocity,
            groundVelocity: this.groundVelocity,
            collisionVelocity: this.collisionVelocity,
            localGForce: this.localGForce,
            localCollisionGForce: this.localCollisionGForce,
            maxVelGround: this.maxVelGround,
            maxVelActor: this.maxVelActor,
            maxVelActorOverride: this.maxVelActorOverride,
            mass: this.mass,
            airControl: this.airControl,
            airResistance: this.airResistance,
            slopeFall: this.slopeFall,
            collTypes: this.collTypes,
            actorFlags0: this.actorFlags0,
            actorFlags1: this.actorFlags1
        };
    }

    setMovementFields(fields = {}) {
        const before = this.movementObject();
        if (Object.prototype.hasOwnProperty.call(fields, "gravity")) writeVec3f(this.ptr.add(0x400), fields.gravity);
        if (Object.prototype.hasOwnProperty.call(fields, "maxVelGround")) this.ptr.add(0x4CC).writeFloat(parseFiniteFloat(fields.maxVelGround, "maxVelGround"));
        if (Object.prototype.hasOwnProperty.call(fields, "maxVelActor")) this.ptr.add(0x4D0).writeFloat(parseFiniteFloat(fields.maxVelActor, "maxVelActor"));
        if (Object.prototype.hasOwnProperty.call(fields, "maxVelActorOverride")) this.ptr.add(0x4D4).writeFloat(parseFiniteFloat(fields.maxVelActorOverride, "maxVelActorOverride"));
        if (Object.prototype.hasOwnProperty.call(fields, "airControl")) this.ptr.add(0x4F4).writeFloat(parseFiniteFloat(fields.airControl, "airControl"));
        if (Object.prototype.hasOwnProperty.call(fields, "airResistance")) this.ptr.add(0x4F8).writeFloat(parseFiniteFloat(fields.airResistance, "airResistance"));
        if (Object.prototype.hasOwnProperty.call(fields, "slopeFall")) this.ptr.add(0x50C).writeFloat(parseFiniteFloat(fields.slopeFall, "slopeFall"));
        if (Object.prototype.hasOwnProperty.call(fields, "collTypes")) this.ptr.add(0x538).writeS32(parseS32(fields.collTypes, "collTypes"));
        return {
            before,
            after: this.movementObject()
        };
    }

    toObject() {
        return this.movementObject();
    }
}

const EPE_Action = Object.freeze({
    ePE_action_move: 0x00,
    ePE_action_impulse: 0x01,
    ePE_action_set_velocity: 0x08,
    ePE_action_set_acceleration: 0x09
});

const EPEActionMoveMode = Object.freeze({
    JumpOverride: 0x01,
    JumpAdditive: 0x02,
    JumpOverrideVertical: 0x04,
    ForceGround: 0x05,
    ForceAirControl: 0x07
});

class PEActionMove {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get type() { return this.ptr.readS32(); }
    get rot() {
        return {
            v: readVec3f(this.ptr.add(0x04)),
            w: this.ptr.add(0x10).readFloat()
        };
    }
    get dir() { return readVec3f(this.ptr.add(0x14)); }
    get mode() { return this.ptr.add(0x20).readU8(); }
    get dt() { return this.ptr.add(0x24).readFloat(); }

    writeDir(dir) {
        writeVec3f(this.ptr.add(0x14), dir);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            type: this.type,
            rot: this.rot,
            dir: this.dir,
            mode: this.mode,
            dt: this.dt
        };
    }
}

const ECharacterMoveType = Object.freeze({
    eCMT_None: 0x00,
    eCMT_Normal: 0x01,
    eCMT_ClientAuthGrounded: 0x02,
    eCMT_Fly: 0x03,
    eCMT_Swim: 0x04,
    eCMT_Jump: 0x05,
    eCMT_ZGAttached: 0x06,
    eCMT_ZGDetached: 0x07
});

class SMotionParameters {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get numParams() { return this.ptr.add(0x28).readU8(); }

    scaleParameter(parameterId, scale) {
        const numParams = Math.min(this.numParams, 8);
        let scaled = false;
        for (let i = 0; i < numParams; i++) {
            if (this.ptr.add(0x20 + i).readU8() !== parameterId) continue;
            const valuePtr = this.ptr.add(i * 0x04);
            valuePtr.writeFloat(valuePtr.readFloat() * scale);
            scaled = true;
        }
        return scaled;
    }

    toObject() {
        const numParams = Math.min(this.numParams, 8);
        const params = [];
        for (let i = 0; i < numParams; i++) {
            params.push({
                id: this.ptr.add(0x20 + i).readU8(),
                value: this.ptr.add(i * 0x04).readFloat()
            });
        }
        return {
            ptr: this.ptr.toString(),
            numParams,
            params
        };
    }
}

class SCharacterMoveRequest {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get type() { return this.ptr.readS32(); }
    get velocity() { return readVec3f(this.ptr.add(0x04)); }
    get rotation() {
        return {
            v: readVec3f(this.ptr.add(0x10)),
            w: this.ptr.add(0x1C).readFloat()
        };
    }
    get updateType() { return this.ptr.add(0x20).readU8(); }
    get motionParameters() { return new SMotionParameters(this.ptr.add(0x24)); }

    writeVelocity(velocity) {
        writeVec3f(this.ptr.add(0x04), velocity);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            type: this.type,
            velocity: this.velocity,
            rotation: this.rotation,
            updateType: this.updateType,
            motionParameters: this.motionParameters.toObject()
        };
    }
}

class CAnimatedCharacter extends EntityComponent {
    get moveRequest() { return new SCharacterMoveRequest(this.ptr.add(0xFC)); }
    get lastRequestedVelocity() { return readVec3f(this.ptr.add(0x26C)); }
    get requestedEntityMovement() {
        return {
            q: {
                v: readVec3f(this.ptr.add(0x2E4)),
                w: this.ptr.add(0x2F0).readFloat()
            },
            t: readVec3f(this.ptr.add(0x2F4))
        };
    }
    get physActionMoveMode() { return this.ptr.add(0x300).readU8(); }
    get smoothedEntityVelocityHorizontal() {
        return {
            x: this.ptr.add(0x324).readFloat(),
            y: this.ptr.add(0x328).readFloat()
        };
    }
    get smoothedMotionParamTravelSpeed() { return this.ptr.add(0x340).readFloat(); }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            moveRequest: this.moveRequest.toObject(),
            lastRequestedVelocity: this.lastRequestedVelocity,
            requestedEntityMovement: this.requestedEntityMovement,
            physActionMoveMode: this.physActionMoveMode,
            smoothedEntityVelocityHorizontal: this.smoothedEntityVelocityHorizontal,
            smoothedMotionParamTravelSpeed: this.smoothedMotionParamTravelSpeed
        };
    }
}

class CEntityArray {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get maxSize() {
        return Number(this.ptr.readU64());
    }

    get currSize() {
        return Number(this.ptr.add(0x08).readU64());
    }

    get dataPtr() {
        return this.ptr.add(0x18).readPointer();
    }

    at(index) {
        if (index < 0 || index >= this.maxSize) return null;
        const entityPtr = lower48(this.dataPtr.add(index * PTR_SIZE).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    toArray() {
        const entities = [];
        for (let i = 0; i < this.maxSize; i++) {
            try {
                const entity = this.at(i);
                if (entity) entities.push(entity);
            } catch (_) {}
        }
        return entities;
    }
}

class CEntityClassRegistry {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    findClass(name) {
        const namePtr = Memory.allocUtf8String(name);
        const classPtr = callVFunc(
            this.ptr,
            4,
            "pointer",
            ["pointer"],
            [namePtr],
            "IEntityClassRegistry::FindClass_3"
        );
        return classPtr.isNull() ? null : new CEntityClass(lower48(classPtr));
    }

    findClassByCrc(classCrc) {
        const classPtr = callVFunc(
            this.ptr,
            2,
            "pointer",
            ["uint32"],
            [Number(classCrc) >>> 0],
            "IEntityClassRegistry::FindClass"
        );
        return classPtr.isNull() ? null : new CEntityClass(lower48(classPtr));
    }

    findClassByGuid(classGuid) {
        throw new Error(`IEntityClassRegistry::FindClass(CryGUID) takes a by-value CryGUID; unsupported until that ABI wrapper is confirmed (${classGuid})`);
    }

    get classCount() {
        return callVFunc(this.ptr, 15, "int", [], [], "IEntityClassRegistry::GetClassCount");
    }

    get classCountFromMap() {
        return Number(this.ptr.add(0x40).add(0x08).readU64());
    }

    get defaultClass() {
        const classPtr = callVFunc(this.ptr, 5, "pointer", [], [], "IEntityClassRegistry::GetDefaultClass");
        return classPtr.isNull() ? null : new CEntityClass(lower48(classPtr));
    }

    get defaultClassFromMemory() {
        const classPtr = this.ptr.add(0x110).readPointer();
        return classPtr.isNull() ? null : new CEntityClass(lower48(classPtr));
    }

    classMapEntries(limit = 4096, includeComponents = false) {
        const mapPtr = this.ptr.add(0x40);
        const head = mapPtr.readPointer();
        if (head.isNull()) return { map: null, classes: [] };

        const max = Math.max(0, Number(limit) || 0);
        const size = Number(mapPtr.add(0x08).readU64());
        const root = head.add(0x08).readPointer();
        if (root.isNull() || root.equals(head) || root.add(0x19).readU8() !== 0) {
            return {
                map: {
                    ptr: mapPtr.toString(),
                    head: head.toString(),
                    root: root.toString(),
                    size
                },
                classes: []
            };
        }

        const classes = [];
        const stack = [root];
        const seen = new Set();
        while (stack.length > 0 && classes.length < max) {
            const node = stack.pop();
            const nodeKey = node.toString();
            if (seen.has(nodeKey) || node.isNull() || node.equals(head)) continue;
            seen.add(nodeKey);
            if (node.add(0x19).readU8() !== 0) continue;

            const left = node.readPointer();
            const right = node.add(0x10).readPointer();
            if (!right.isNull() && !right.equals(head)) stack.push(right);
            if (!left.isNull() && !left.equals(head)) stack.push(left);

            const classPtr = node.add(0x28).readPointer();
            if (!classPtr.isNull()) {
                try {
                    classes.push({
                        key: node.add(0x20).readU64().toString(),
                        ...new CEntityClass(lower48(classPtr)).toObject(includeComponents)
                    });
                } catch (e) {
                    classes.push({ ptr: ptr(classPtr).toString(), error: e.message });
                }
            }
        }

        return {
            map: {
                ptr: mapPtr.toString(),
                head: head.toString(),
                root: root.toString(),
                size
            },
            classes
        };
    }

    forEachClass(limit = 4096, includeComponents = false) {
        return this.classMapEntries(limit, includeComponents).classes;
    }

    findClassesByName(pattern, scanLimit = 32768, includeComponents = false, resultLimit = 256) {
        const re = pattern instanceof RegExp ? pattern : new RegExp(String(pattern), "i");
        return this.forEachClass(scanLimit, includeComponents)
            .filter(entityClass => re.test(entityClass.name ?? ""))
            .slice(0, Math.max(0, Number(resultLimit) || 0));
    }

    findClassByNameDirect(name, includeComponents = false) {
        const wanted = String(name);
        return this.forEachClass(32768, includeComponents).find(entityClass => entityClass.name === wanted) ?? null;
    }

    findClassByCrcDirect(classCrc, includeComponents = false) {
        const wanted = Number(classCrc) >>> 0;
        return this.forEachClass(32768, includeComponents).find(entityClass => entityClass.classCrc === wanted) ?? null;
    }

    toObject(limit = 64, includeComponents = false) {
        const classMap = limit > 0 ? this.classMapEntries(limit, includeComponents) : { map: null, classes: [] };
        return {
            ptr: this.ptr.toString(),
            classCount: classMap.map?.size ?? this.classCountFromMap,
            defaultClass: this.defaultClassFromMemory?.toObject(false) ?? null,
            offsets: {
                m_mapClassName: "0x40",
                m_classMap: "0x60",
                m_componentCreationOrder: "0xC8",
                m_uniqueClasses: "0x100",
                m_pDefaultClass: "0x110"
            },
            classMap: classMap.map,
            classes: classMap.classes
        };
    }
}

class CEntitySystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get entityArray() {
        return new CEntityArray(this.ptr.add(0x1A8));
    }

    get entityComponentSystem() {
        const componentSystemPtr = this.ptr.add(0x948).readPointer();
        return componentSystemPtr.isNull() ? null : new CEntityComponentSystem(componentSystemPtr);
    }

    get classRegistry() {
        const registryPtr = callVFunc(this.ptr, 24, "pointer", [], [], "IEntitySystem::GetClassRegistry");
        if (!registryPtr.isNull()) return new CEntityClassRegistry(registryPtr);

        const fallbackPtr = this.ptr.add(0xBE0).readPointer();
        return fallbackPtr.isNull() ? null : new CEntityClassRegistry(fallbackPtr);
    }

    get classRegistryFromMemory() {
        const registryPtr = this.ptr.add(0xBE0).readPointer();
        return registryPtr.isNull() ? null : new CEntityClassRegistry(registryPtr);
    }

    getClassByName(name) {
        const registry = this.classRegistry;
        return registry ? registry.findClass(name) : null;
    }

    get numEntities() {
        return callVFunc(this.ptr, 45, "uint32", [], [], "IEntitySystem::GetNumEntities");
    }

    get entityCount() {
        return callVFunc(this.ptr, 76, "uint32", [], [], "IEntitySystem::GetEntityCount");
    }

    getEntity(entityId) {
        const entityPtr = callVFunc(
            this.ptr,
            35,
            "pointer",
            ["uint64"],
            [uint64(String(entityId))],
            "IEntitySystem::GetEntity"
        );
        return entityPtr.isNull() ? null : new CEntity(lower48(entityPtr));
    }

    findEntityByName(name) {
        const output = Memory.alloc(PTR_SIZE);
        output.writePointer(NULL);
        callVFunc(
            this.ptr,
            40,
            "pointer",
            ["pointer", "pointer"],
            [output, Memory.allocUtf8String(name)],
            "IEntitySystem::FindEntityByName_SlowDebugCodeOnly"
        );
        const entityPtr = lower48(output.readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    findEntities(options = {}) {
        let out = this.entityArray.toArray();
        if (options.className !== undefined) {
            const re = options.className instanceof RegExp ? options.className : new RegExp(String(options.className), "i");
            out = out.filter(entity => {
                try {
                    return re.test(entity.entityClass?.name ?? "");
                } catch (_) {
                    return false;
                }
            });
        }
        if (options.name !== undefined) {
            const re = options.name instanceof RegExp ? options.name : new RegExp(String(options.name), "i");
            out = out.filter(entity => {
                try {
                    return re.test(entity.name ?? "");
                } catch (_) {
                    return false;
                }
            });
        }
        if (options.component !== undefined) {
            const componentSystem = this.entityComponentSystem ?? gEnv.entityComponentSystem;
            let componentId;
            if (typeof options.component === "number" || /^0x/i.test(String(options.component))) {
                componentId = parseU16(options.component, "component");
            } else if (componentSystem) {
                const componentInfo = componentSystem.getComponentIdByName(String(options.component));
                if (componentInfo.success && componentInfo.componentId !== 0xFFFF) {
                    componentId = componentInfo.componentId;
                }
            }
            out = out.filter(entity => {
                try {
                    return componentId !== undefined && !entity.getComponentById(componentId).isNull();
                } catch (_) {
                    return false;
                }
            });
        }

        const limit = Number.isInteger(Number(options.limit)) ? Number(options.limit) : out.length;
        return out.slice(0, limit);
    }

    findEntitiesOfKind(kind, options = {}) {
        const mode = options.mode ?? "className";
        if (mode === "component") {
            return this.findEntities({ ...options, component: kind });
        }
        if (mode === "name") {
            return this.findEntities({ ...options, name: kind });
        }
        return this.findEntities({ ...options, className: kind });
    }

    toObject(options = {}) {
        return {
            ptr: this.ptr.toString(),
            numEntities: this.numEntities,
            entityCount: this.entityCount,
            entityLookup: {
                offset: "0x1A8",
                maxSize: this.entityArray.maxSize,
                currSize: this.entityArray.currSize,
                dataPtr: this.entityArray.dataPtr.toString()
            },
            entityComponentSystem: this.entityComponentSystem?.toObject(options.includeAllComponentsMap === true) ?? null,
            classRegistry: this.classRegistry ? {
                ptr: this.classRegistry.ptr.toString(),
                classCount: this.classRegistry.classCount
            } : null,
            offsets: {
                m_allEntitiesUnordered: "0x148",
                m_entityLookup: "0x1A8",
                m_pEntityComponentSystem: "0x948",
                m_pClassRegistry: "0xBE0",
                m_actorComponentHash: "0x1320",
                m_vehicleComponentHash: "0x1328",
                m_ocComponentHash: "0x1330"
            }
        };
    }

    toDirectObject(options = {}) {
        const componentSystem = this.entityComponentSystem;
        const registry = this.classRegistryFromMemory;
        const registryMap = registry ? registry.classMapEntries(0, false).map : null;
        return {
            ptr: this.ptr.toString(),
            entityLookup: {
                offset: "0x1A8",
                maxSize: this.entityArray.maxSize,
                currSize: this.entityArray.currSize,
                dataPtr: this.entityArray.dataPtr.toString()
            },
            entityComponentSystem: componentSystem ? {
                ptr: componentSystem.ptr.toString()
            } : null,
            classRegistry: registry ? {
                ptr: registry.ptr.toString(),
                mapSize: registryMap?.size ?? null
            } : null,
            offsets: {
                m_allEntitiesUnordered: "0x148",
                m_entityLookup: "0x1A8",
                m_pEntityComponentSystem: "0x948",
                m_pClassRegistry: "0xBE0",
                m_actorComponentHash: "0x1320",
                m_vehicleComponentHash: "0x1328",
                m_ocComponentHash: "0x1330"
            }
        };
    }
}

class CRenderer {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    projectToScreen(pos, resolution = { x: 1920, y: 1080 }, camera = NULL) {
        const out = Memory.alloc(0x0C);
        const result = callVFunc(
            this.ptr,
            65,
            "bool",
            ["double", "double", "double", "pointer", "pointer", "pointer", "pointer"],
            [pos.x, pos.y, pos.z, out, out.add(0x04), out.add(0x08), camera],
            "IRenderer::ProjectToScreen"
        );

        const z = out.add(0x08).readFloat();
        return {
            x: out.readFloat() * resolution.x,
            y: out.add(0x04).readFloat() * resolution.y,
            z,
            success: !!result && z > 0
        };
    }
}

class CSystem {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get cameraWorldPos() {
        return new DVec3(
            this.ptr.add(0x40).readDouble(),
            this.ptr.add(0x60).readDouble(),
            this.ptr.add(0x80).readDouble()
        );
    }

    get cameraForward() {
        return new DVec3(
            this.ptr.add(0x30).readDouble(),
            this.ptr.add(0x50).readDouble(),
            this.ptr.add(0x70).readDouble()
        );
    }

    get cameraUp() {
        return new DVec3(
            this.ptr.add(0x38).readDouble(),
            this.ptr.add(0x58).readDouble(),
            this.ptr.add(0x78).readDouble()
        );
    }

    get internalXFOV() {
        return this.ptr.add(0x118).readFloat();
    }
}

class CGame {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get player() {
        const playerPtr = lower48(this.ptr.add(0x0C18).readPointer());
        return playerPtr.isNull() ? null : new CSCPlayer(playerPtr);
    }

    get inventoryContainerManager() {
        const managerPtr = tryCallVFunc(
            this.ptr,
            InventoryManagementSurface.cGameVtable.getInventoryContainerManager,
            "pointer",
            [],
            [],
            "CGame::GetIInventoryContainerManager"
        );
        if (!managerPtr) return null;
        return managerPtr.isNull() ? null : new IInventoryContainerManager(managerPtr);
    }
}

class CSCPlayer {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get owningEntity() {
        const entityPtr = lower48(this.ptr.add(0x08).readPointer());
        return entityPtr.isNull() ? null : new CEntity(entityPtr);
    }

    get name() {
        return readCryString(this.ptr.add(0x3A0));
    }

    get currentActor() {
        const actorPtr = lower48(this.ptr.add(0x3B8).readPointer());
        return actorPtr.isNull() ? null : new CActor(actorPtr);
    }

    get playerInventory() {
        return new CSCPlayerInventory(this.ptr.add(0x1498));
    }
}

class GEnv {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get zoneSystem() {
        const systemPtr = this.ptr.add(0x10).readPointer();
        return systemPtr.isNull() ? null : new CZoneSystem(systemPtr);
    }

    get cZoneSystem() {
        return this.zoneSystem;
    }

    get physicalWorld() {
        const worldPtr = this.ptr.add(0x28).readPointer();
        return worldPtr.isNull() ? null : new CPhysicalWorld(worldPtr);
    }

    get dataCore() {
        const dataCorePtr = this.ptr.add(0x80).readPointer();
        return dataCorePtr.isNull() ? null : dataCorePtr;
    }

    get game() {
        const gamePtr = this.ptr.add(0xA0).readPointer();
        return gamePtr.isNull() ? null : new CGame(gamePtr);
    }

    get entitySystem() {
        const entitySystemPtr = this.ptr.add(0xA8).readPointer();
        return entitySystemPtr.isNull() ? null : new CEntitySystem(entitySystemPtr);
    }

    get entityComponentSystem() {
        const componentSystemPtr = this.ptr.add(0xB0).readPointer();
        return componentSystemPtr.isNull() ? null : new CEntityComponentSystem(componentSystemPtr);
    }

    get engineComponentScheduler() {
        return this.entityComponentSystem;
    }

    get console() {
        const consolePtr = this.ptr.add(0xB8).readPointer();
        return consolePtr.isNull() ? null : consolePtr;
    }

    get cSystem() {
        const systemPtr = this.ptr.add(0xC8).readPointer();
        return systemPtr.isNull() ? null : new CSystem(systemPtr);
    }

    get cRenderer() {
        const rendererPtr = this.ptr.add(0xF8).readPointer();
        return rendererPtr.isNull() ? null : new CRenderer(rendererPtr);
    }

    get gen12Renderer() {
        const rendererPtr = this.ptr.add(0x100).readPointer();
        return rendererPtr.isNull() ? null : rendererPtr;
    }

    get cigServices() {
        const servicesPtr = this.ptr.add(0x188).readPointer();
        return servicesPtr.isNull() ? null : new ICIGServicesInternal(servicesPtr);
    }

    get missionSystem() {
        const missionSystemPtr = this.ptr.add(0x1B8).readPointer();
        return missionSystemPtr.isNull() ? null : new IMissionSystem(missionSystemPtr);
    }
}

const gEnv = new GEnv(GENV_ADDR);

function player() {
    return gEnv.game?.player?.owningEntity ?? null;
}

function scPlayer() {
    return gEnv.game?.player ?? null;
}

function currentActorEntity() {
    return player()?.actorEntity ?? null;
}

function currentAnimatedCharacter() {
    const sc = scPlayer();
    const actor = sc?.currentActor ?? player()?.actor ?? null;
    return actor?.animatedCharacter ?? null;
}

function actorPathSurface() {
    const sc = scPlayer();
    const ent = player();
    const actor = sc?.currentActor ?? ent?.actor ?? null;
    const actorEntity = ent?.actorEntity ?? null;

    return {
        path: "gEnv.game.player -> CSCPlayer.owningEntity -> CEntity.actorEntity",
        offsets: {
            CGame_player: "0x0C18",
            CSCPlayer_owningEntity: "0x08",
            CSCPlayer_currentActor: "0x3B8",
            CEntity_actorEntity_currentBuild: "0xF20",
            CEntity_actorEntity_legacyFallback: "0xFD8",
            CActorEntity_parentEntity: "0x0C0",
            CActorEntity_movementBlock: "0x400..0x53C",
            CActorEntity_maxVelGround: "0x4CC",
            CActorEntity_maxVelActor: "0x4D0",
            CActorEntity_maxVelActorOverride: "0x4D4",
            CActor_clientPlayerDamageRemoteMethod: "0x8E0"
        },
        damageTypes: {
            collision: 0x08,
            fallDamage: 0x09
        },
        scPlayer: sc ? {
            ptr: sc.ptr.toString(),
            name: sc.name,
            currentActor: sc.currentActor?.ptr.toString() ?? null
        } : null,
        entity: ent ? {
            ptr: ent.ptr.toString(),
            id: String(ent.id),
            name: ent.name,
            className: ent.entityClass?.name ?? null
        } : null,
        actor: actor ? actor.toObject() : null,
        actorEntity: actorEntity ? actorEntity.toObject() : null
    };
}


function safe(callable, fallback = null) {
    try {
        return callable();
    } catch (_) {
        return fallback;
    }
}

function summarizeBoneTransforms(bones) {
    const valid = bones.filter(bone => bone.valid);
    const identity = bones.filter(bone => bone.transform && bone.transform.identityFallback);
    const errors = bones.filter(bone => bone.error);
    return {
        total: bones.length,
        valid: valid.length,
        identityFallback: identity.length,
        errors: errors.length,
        validBoneIds: valid.map(bone => bone.boneId),
        errorSamples: errors.slice(0, 4).map(bone => ({ boneId: bone.boneId, name: bone.name, error: bone.error })),
    };
}

function resolveActorForBoneProbe(entity) {
    if (!entity) return null;
    try {
        const actor = entity.actor;
        if (actor && !actor.ptr.isNull()) return actor;
    } catch (_) {}
    try {
        const actorEntity = entity.actorEntity;
        const parent = actorEntity ? actorEntity.parentEntity : null;
        if (parent && !parent.ptr.equals(entity.ptr)) {
            const actor = parent.actor;
            if (actor && !actor.ptr.isNull()) return actor;
        }
    } catch (_) {}
    try {
        const playerObject = player();
        if (playerObject && playerObject.ptr.equals(entity.ptr)) {
            const localPlayer = scPlayer();
            if (localPlayer && localPlayer.currentActor && !localPlayer.currentActor.ptr.isNull()) return localPlayer.currentActor;
        }
    } catch (_) {}
    return null;
}

function boneProbeEntity(entityValue, options = {}) {
    const entity = entityValue instanceof CEntity ? entityValue : new CEntity(lower48(ptr(entityValue)));
    const actor = options.actor ? (options.actor instanceof CActor ? options.actor : new CActor(lower48(ptr(options.actor)))) : resolveActorForBoneProbe(entity);
    const result = {
        entity: entity.ptr.toString(),
        entityId: safe(() => entity.id.toString(), null),
        name: safe(() => entity.name, null),
        className: safe(() => entity.className, null),
        worldPos: safe(() => entity.worldPos, null),
        actor: actor ? actor.ptr.toString() : null,
        actorEntity: safe(() => entity.actorEntity ? entity.actorEntity.ptr.toString() : null, null),
        bones: [],
        summary: null,
    };
    if (!actor || actor.ptr.isNull()) {
        result.error = "No CActor component resolved for entity";
        return result;
    }
    result.bones = actor.getBoneTransforms();
    result.summary = summarizeBoneTransforms(result.bones);
    if (options.rawScan === true) {
        result.scan = actor.scanBoneIds(options.scanMaxBoneId ?? 0x16);
        result.scanSummary = summarizeBoneTransforms(result.scan);
    }
    return result;
}

function boneProbe(options = {}) {
    const limit = options.limit ?? 24;
    const result = {
        getBoneTransform: CActor__GetBoneTransform_ADDR.toString(),
        local: null,
        candidates: [],
        summary: {
            candidateCount: 0,
            actorCount: 0,
            validCandidateCount: 0,
        },
    };

    const localEntity = safe(() => player(), null);
    if (localEntity) {
        result.local = boneProbeEntity(localEntity, options);
    }

    const candidates = safe(() => gEnv.entitySystem.findEntities({ component: "Actor", limit }), []) || [];
    for (const candidate of candidates) {
        if (!candidate || !candidate.ptr || candidate.ptr.isNull()) continue;
        if (localEntity && candidate.ptr.equals(localEntity.ptr)) continue;
        const probe = boneProbeEntity(candidate, options);
        result.candidates.push(probe);
    }

    result.summary.candidateCount = result.candidates.length;
    result.summary.actorCount = result.candidates.filter(candidate => !!candidate.actor).length + (result.local && result.local.actor ? 1 : 0);
    result.summary.validCandidateCount = result.candidates.filter(candidate => candidate.summary && candidate.summary.valid > 0).length +
        (result.local && result.local.summary && result.local.summary.valid > 0 ? 1 : 0);
    return result;
}

function foobar(options = {}) {
    const result = boneProbe({ limit: 4, ...options });
    const compactEntity = entity => entity ? ({
        entity: entity.entity,
        entityId: entity.entityId,
        name: entity.name,
        className: entity.className,
        actor: entity.actor,
        actorEntity: entity.actorEntity,
        worldPos: entity.worldPos,
        summary: entity.summary,
        sampleBones: (entity.bones || []).filter(bone => bone.valid).slice(0, 3).map(bone => ({
            id: bone.boneId,
            name: bone.name,
            t: bone.transform.t,
            q: bone.transform.q,
        })),
        error: entity.error,
    }) : null;
    const compact = {
        getBoneTransform: result.getBoneTransform,
        summary: result.summary,
        local: compactEntity(result.local),
        candidates: result.candidates.map(compactEntity),
    };
    console.log(JSON.stringify(compact, null, 2));
    return compact.summary;
}

function actorEntityMovementState() {
    const actorEntity = currentActorEntity();
    if (!actorEntity) throw new Error("current CActorEntity is unavailable");
    const animatedCharacter = currentAnimatedCharacter();
    return {
        actorEntity: actorEntity.movementObject(),
        animatedCharacter: animatedCharacter?.toObject() ?? null
    };
}

function setActorEntityMovementFields(fields = {}) {
    const actorEntity = currentActorEntity();
    if (!actorEntity) throw new Error("current CActorEntity is unavailable");
    return actorEntity.setMovementFields(fields);
}

function setActorWalkingSpeed(args = {}) {
    return installAnimatedCharacterMovementSpeedHook(args);
}

let actorActionMoveHook = null;

function resolveCurrentActorActionTarget() {
    const actorEntity = currentActorEntity();
    if (!actorEntity) throw new Error("current CActorEntity is unavailable");

    const vtable = actorEntity.ptr.readPointer();
    if (vtable.isNull()) throw new Error("current CActorEntity has null vtable");

    const actionPtr = vtable.add(0x30).readPointer();
    if (actionPtr.isNull()) throw new Error("current CActorEntity::Action slot is null");

    return {
        actorEntity,
        vtable,
        actionPtr
    };
}

function actorActionMoveSurface() {
    const target = resolveCurrentActorActionTarget();
    return {
        actorEntity: target.actorEntity.movementObject(),
        vtable: target.vtable.toString(),
        actionSlot: 6,
        actionVtableOffset: "0x30",
        actionPtr: target.actionPtr.toString(),
        peAction: {
            type: "0x00",
            size: "0x04"
        },
        peActionMove: {
            size: "0x28",
            type: "0x00",
            rot: "0x04",
            dir: "0x14",
            mode: "0x20",
            dt: "0x24"
        },
        epeAction: EPE_Action,
        epeActionMoveMode: EPEActionMoveMode
    };
}

function normalizeActionMoveOptions(args = {}) {
    const sampleLimit = Object.prototype.hasOwnProperty.call(args, "sampleLimit") ? parseS32(args.sampleLimit, "sampleLimit") : 32;
    const scale = Object.prototype.hasOwnProperty.call(args, "scale") ? parseFiniteFloat(args.scale, "scale")
        : Object.prototype.hasOwnProperty.call(args, "speedScale") ? parseFiniteFloat(args.speedScale, "speedScale")
        : 1.0;

    if (scale < 0 || scale > 20) throw new Error("scale must be between 0 and 20");
    if (sampleLimit < 0 || sampleLimit > 256) throw new Error("sampleLimit must be between 0 and 256");

    return {
        scale,
        enabled: args.enabled !== false,
        scaleAllAxes: args.scaleAllAxes === true,
        sampleLimit,
        captureNonMove: args.captureNonMove === true
    };
}

function installActorActionMoveHook(args = {}) {
    if (actorActionMoveHook?.listener) uninstallActorActionMoveHook();

    const options = normalizeActionMoveOptions(args);
    const target = resolveCurrentActorActionTarget();
    const state = {
        installed: true,
        targetActorEntity: target.actorEntity.ptr.toString(),
        actionPtr: target.actionPtr.toString(),
        actionSlot: 6,
        actionVtableOffset: "0x30",
        options,
        totalCalls: 0,
        actorCalls: 0,
        moveCalls: 0,
        modifiedCalls: 0,
        nonMoveCalls: 0,
        errors: 0,
        samples: []
    };

    const listener = Interceptor.attach(target.actionPtr, {
        onEnter(args) {
            const thisPtr = args[0];
            const actionPtr = args[1];
            const actionFlags = args[2];
            state.totalCalls++;

            try {
                if (!ptr(thisPtr).equals(target.actorEntity.ptr)) return;
                state.actorCalls++;

                const action = ptr(actionPtr);
                if (action.isNull()) return;

                const actionType = action.readS32();
                if (actionType !== EPE_Action.ePE_action_move) {
                    state.nonMoveCalls++;
                    if (options.captureNonMove && state.samples.length < options.sampleLimit) {
                        state.samples.push({
                            actionPtr: action.toString(),
                            type: actionType,
                            flags: ptr(actionFlags).toString()
                        });
                    }
                    return;
                }

                state.moveCalls++;
                const move = new PEActionMove(action);
                const before = move.dir;
                let after = before;

                if (options.enabled && options.scale !== 1.0) {
                    after = {
                        x: before.x * options.scale,
                        y: before.y * options.scale,
                        z: options.scaleAllAxes ? before.z * options.scale : before.z
                    };
                    move.writeDir(after);
                    state.modifiedCalls++;
                }

                if (state.samples.length < options.sampleLimit) {
                    state.samples.push({
                        actionPtr: action.toString(),
                        flags: ptr(actionFlags).toString(),
                        before,
                        after,
                        mode: move.mode,
                        dt: move.dt
                    });
                }
            } catch (e) {
                state.errors++;
                state.lastError = String(e);
            }
        }
    });

    actorActionMoveHook = { listener, state };
    return state;
}

function installActorActionMoveMonitor(args = {}) {
    return installActorActionMoveHook({
        ...args,
        enabled: false,
        scale: 1.0
    });
}

function installActorActionMoveSpeedHook(args = {}) {
    const scale = Object.prototype.hasOwnProperty.call(args, "scale") ? args.scale
        : Object.prototype.hasOwnProperty.call(args, "speedScale") ? args.speedScale
        : Object.prototype.hasOwnProperty.call(args, "speed") ? (() => {
            const requestedSpeed = parseFiniteFloat(args.speed, "speed");
            const baseSpeed = currentActorEntity()?.maxVelGround ?? 0;
            const saneBaseSpeed = baseSpeed > 0 && baseSpeed <= 100 ? baseSpeed : 10;
            return requestedSpeed / saneBaseSpeed;
        })()
        : 1.5;
    return installActorActionMoveHook({
        ...args,
        enabled: true,
        scale
    });
}

function uninstallActorActionMoveHook() {
    if (!actorActionMoveHook?.listener) return { installed: false };
    const state = actorActionMoveHook.state;
    actorActionMoveHook.listener.detach();
    actorActionMoveHook = null;
    return {
        ...state,
        installed: false
    };
}

function actorActionMoveHookState() {
    return actorActionMoveHook?.state ?? { installed: false };
}

let animatedCharacterAddMovementHook = null;

function resolveCurrentAnimatedCharacterAddMovementTarget() {
    const animatedCharacter = currentAnimatedCharacter();
    if (!animatedCharacter) throw new Error("current CAnimatedCharacter is unavailable");

    const vtable = animatedCharacter.ptr.readPointer();
    if (vtable.isNull()) throw new Error("current CAnimatedCharacter has null vtable");

    const addMovementPtr = vtable.add(0x730).readPointer();
    if (addMovementPtr.isNull()) throw new Error("current CAnimatedCharacter::AddMovement slot is null");

    return {
        animatedCharacter,
        vtable,
        addMovementPtr
    };
}

function animatedCharacterMovementSurface() {
    const target = resolveCurrentAnimatedCharacterAddMovementTarget();
    return {
        animatedCharacter: target.animatedCharacter.toObject(),
        vtable: target.vtable.toString(),
        addMovementSlot: 230,
        addMovementVtableOffset: "0x730",
        addMovementPtr: target.addMovementPtr.toString(),
        sCharacterMoveRequest: {
            size: "0x50",
            type: "0x00",
            velocity: "0x04",
            rotation: "0x10",
            updateType: "0x20",
            motionParameters: "0x24"
        },
        eCharacterMoveType: ECharacterMoveType
    };
}

function normalizeAnimatedMovementOptions(args = {}) {
    const sampleLimit = Object.prototype.hasOwnProperty.call(args, "sampleLimit") ? parseS32(args.sampleLimit, "sampleLimit") : 32;
    const scale = Object.prototype.hasOwnProperty.call(args, "scale") ? parseFiniteFloat(args.scale, "scale")
        : Object.prototype.hasOwnProperty.call(args, "speedScale") ? parseFiniteFloat(args.speedScale, "speedScale")
        : 1.0;

    if (scale < 0 || scale > 20) throw new Error("scale must be between 0 and 20");
    if (sampleLimit < 0 || sampleLimit > 256) throw new Error("sampleLimit must be between 0 and 256");

    return {
        scale,
        enabled: args.enabled !== false,
        scaleAllAxes: args.scaleAllAxes === true,
        includeJump: args.includeJump === true,
        scaleTravelSpeedMotionParam: args.scaleTravelSpeedMotionParam !== false,
        sampleLimit
    };
}

function installAnimatedCharacterAddMovementHook(args = {}) {
    if (animatedCharacterAddMovementHook?.listener) uninstallAnimatedCharacterAddMovementHook();

    const options = normalizeAnimatedMovementOptions(args);
    const target = resolveCurrentAnimatedCharacterAddMovementTarget();
    const state = {
        installed: true,
        targetAnimatedCharacter: target.animatedCharacter.ptr.toString(),
        addMovementPtr: target.addMovementPtr.toString(),
        addMovementSlot: 230,
        addMovementVtableOffset: "0x730",
        options,
        totalCalls: 0,
        actorCalls: 0,
        modifiedCalls: 0,
        skippedJumpCalls: 0,
        errors: 0,
        samples: []
    };

    const listener = Interceptor.attach(target.addMovementPtr, {
        onEnter(args) {
            const thisPtr = args[0];
            const requestPtr = args[1];
            const elapsed = args[2];
            const force = args[3];
            state.totalCalls++;

            try {
                if (!ptr(thisPtr).equals(target.animatedCharacter.ptr)) return;
                state.actorCalls++;

                const requestAddress = ptr(requestPtr);
                if (requestAddress.isNull()) return;

                const request = new SCharacterMoveRequest(requestAddress);
                const before = request.velocity;
                const motionParametersBefore = request.motionParameters.toObject();
                let after = before;
                const type = request.type;
                let scaledTravelSpeedMotionParam = false;

                if (type === ECharacterMoveType.eCMT_Jump && !options.includeJump) {
                    state.skippedJumpCalls++;
                } else if (options.enabled && options.scale !== 1.0) {
                    after = {
                        x: before.x * options.scale,
                        y: before.y * options.scale,
                        z: options.scaleAllAxes ? before.z * options.scale : before.z
                    };
                    request.writeVelocity(after);
                    if (options.scaleTravelSpeedMotionParam) {
                        scaledTravelSpeedMotionParam = request.motionParameters.scaleParameter(0, options.scale);
                    }
                    state.modifiedCalls++;
                }

                if (state.samples.length < options.sampleLimit) {
                    state.samples.push({
                        requestPtr: requestAddress.toString(),
                        type,
                        updateType: request.updateType,
                        elapsed: Number(elapsed),
                        force: Number(force) !== 0,
                        before,
                        after,
                        scaledTravelSpeedMotionParam,
                        motionParametersBefore,
                        motionParametersAfter: request.motionParameters.toObject()
                    });
                }
            } catch (e) {
                state.errors++;
                state.lastError = String(e);
            }
        }
    });

    animatedCharacterAddMovementHook = { listener, state };
    return state;
}

function installAnimatedCharacterMovementMonitor(args = {}) {
    return installAnimatedCharacterAddMovementHook({
        ...args,
        enabled: false,
        scale: 1.0
    });
}

function installAnimatedCharacterMovementSpeedHook(args = {}) {
    const scale = Object.prototype.hasOwnProperty.call(args, "scale") ? args.scale
        : Object.prototype.hasOwnProperty.call(args, "speedScale") ? args.speedScale
        : Object.prototype.hasOwnProperty.call(args, "speed") ? (() => {
            const requestedSpeed = parseFiniteFloat(args.speed, "speed");
            return requestedSpeed / 10;
        })()
        : 1.5;
    return installAnimatedCharacterAddMovementHook({
        ...args,
        enabled: true,
        scale
    });
}

function uninstallAnimatedCharacterAddMovementHook() {
    if (!animatedCharacterAddMovementHook?.listener) return { installed: false };
    const state = animatedCharacterAddMovementHook.state;
    animatedCharacterAddMovementHook.listener.detach();
    animatedCharacterAddMovementHook = null;
    return {
        ...state,
        installed: false
    };
}

function animatedCharacterAddMovementHookState() {
    return animatedCharacterAddMovementHook?.state ?? { installed: false };
}

const ActorDamageToKillType = Object.freeze({
    melee: 0x01,
    unarmedMelee: 0x02,
    explosion: 0x03,
    bullet: 0x04,
    suffocate: 0x05,
    drown: 0x06,
    energyWeapon: 0x07,
    collision: 0x08,
    fallDamage: 0x09,
    crash: 0x0A,
    suicide: 0x0B
});

class SPlayerDamageReport {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get shooterId() { return readEntityId(this.ptr); }
    get totalDamage() { return this.ptr.add(0x08).readFloat(); }
    get damageType() { return this.ptr.add(0x0C).readS8(); }
    get partId() { return this.ptr.add(0x0D).readS8(); }
    get isLethal() { return this.ptr.add(0x0E).readU8() !== 0; }

    zero() {
        this.ptr.add(0x08).writeFloat(0);
        this.ptr.add(0x0E).writeU8(0);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            shooterId: this.shooterId,
            totalDamage: this.totalDamage,
            damageType: this.damageType,
            partId: this.partId,
            isLethal: this.isLethal
        };
    }
}

class SKillParams {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get shooterEntity() { return lower48(this.ptr.readPointer()); }
    get weaponEntity() { return lower48(this.ptr.add(0x18).readPointer()); }
    get projectileEntity() { return lower48(this.ptr.add(0x20).readPointer()); }
    get weaponClassId() { return this.ptr.add(0x28).readU32(); }
    get impulseScale() { return this.ptr.add(0x2C).readFloat(); }
    get dir() { return readVec3f(this.ptr.add(0x30)); }
    get hitType() { return this.ptr.add(0x3C).readS32(); }
    get hitPartId() { return this.ptr.add(0x40).readU16(); }
    get projectileClassId() { return this.ptr.add(0x44).readU32(); }
    get winningKill() { return this.ptr.add(0x48).readU8() !== 0; }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            shooterEntity: this.shooterEntity.toString(),
            weaponEntity: this.weaponEntity.toString(),
            projectileEntity: this.projectileEntity.toString(),
            weaponClassId: this.weaponClassId,
            impulseScale: this.impulseScale,
            dir: this.dir,
            hitType: this.hitType,
            hitPartId: this.hitPartId,
            projectileClassId: this.projectileClassId,
            winningKill: this.winningKill
        };
    }
}

const EHitType = Object.freeze({
    Invalid: 0x00,
    Melee: 0x01,
    Collision: 0x02,
    Crash: 0x03,
    Frag: 0x04,
    Explosion: 0x05,
    TakeDown: 0x06,
    Punish: 0x07,
    Normal: 0x08,
    Fire: 0x09,
    Bullet: 0x0A,
    VehicleDestruction: 0x0B,
    EventDamage: 0x0C,
    BleedOut: 0x0D,
    ElectricArc: 0x0E,
    Repair: 0x0F,
    Suffocate: 0x10,
    Suicide: 0x11,
    SelfDestruct: 0x12,
    BoundaryViolation: 0x13,
    Drown: 0x14,
    DamageOverTime: 0x15,
    Hazard: 0x16,
    Extraction: 0x17
});

class HitInfo {
    constructor(ptrValue) {
        this.ptr = ptr(ptrValue);
    }

    get shooterEntity() { return lower48(this.ptr.readPointer()); }
    get targetEntity() { return lower48(this.ptr.add(0x08).readPointer()); }
    get weaponEntity() { return lower48(this.ptr.add(0x10).readPointer()); }
    get projectileEntity() { return lower48(this.ptr.add(0x20).readPointer()); }
    get damageValues() {
        const values = [];
        for (let i = 0; i < 6; i++) values.push(this.ptr.add(0x40 + i * 0x04).readFloat());
        return values;
    }
    get totalDamage() {
        return this.damageValues.reduce((sum, value) => Number.isFinite(value) ? sum + value : sum, 0);
    }
    get maxDamageLimitRatio() { return this.ptr.add(0x58).readFloat(); }
    get impulseScale() { return this.ptr.add(0x60).readFloat(); }
    get material() { return this.ptr.add(0x74).readS32(); }
    get type() { return this.ptr.add(0x78).readS32(); }
    get partId() { return this.ptr.add(0x7C).readS32(); }
    get colliderId() { return this.ptr.add(0x80).readS32(); }
    get pos() { return readVec3d(this.ptr.add(0x98)); }
    get dir() { return readVec3f(this.ptr.add(0xB0)); }
    get normal() { return readVec3f(this.ptr.add(0xBC)); }
    get projectileClassId() { return this.ptr.add(0xE4).readU32(); }
    get weaponClassId() { return this.ptr.add(0xE8).readU32(); }
    get remote() { return this.ptr.add(0xEC).readU8() !== 0; }
    get explosion() { return this.ptr.add(0xED).readU8() !== 0; }
    get isInitialDamage() { return this.ptr.add(0xEE).readU8() !== 0; }
    get isFriendlyFire() { return this.ptr.add(0xF2).readU8() !== 0; }
    get pCollisionEvent() { return this.ptr.add(0xF8).readPointer(); }
    get hitDuration() { return this.ptr.add(0x100).readFloat(); }

    zeroDamage() {
        for (let i = 0; i < 6; i++) this.ptr.add(0x40 + i * 0x04).writeFloat(0);
        this.ptr.add(0x58).writeFloat(0);
        this.ptr.add(0x60).writeFloat(0);
    }

    toObject() {
        return {
            ptr: this.ptr.toString(),
            shooterEntity: this.shooterEntity.toString(),
            targetEntity: this.targetEntity.toString(),
            weaponEntity: this.weaponEntity.toString(),
            projectileEntity: this.projectileEntity.toString(),
            damageValues: this.damageValues,
            totalDamage: this.totalDamage,
            maxDamageLimitRatio: this.maxDamageLimitRatio,
            impulseScale: this.impulseScale,
            material: this.material,
            type: this.type,
            partId: this.partId,
            colliderId: this.colliderId,
            pos: this.pos,
            dir: this.dir,
            normal: this.normal,
            projectileClassId: this.projectileClassId,
            weaponClassId: this.weaponClassId,
            remote: this.remote,
            explosion: this.explosion,
            isInitialDamage: this.isInitialDamage,
            isFriendlyFire: this.isFriendlyFire,
            pCollisionEvent: this.pCollisionEvent.toString(),
            hitDuration: this.hitDuration
        };
    }
}

let actorDamageNullHook = null;
let actorKillNullHook = null;
let actorHealthHitNullHook = null;

function playerDamageReportFromArgs(arg1, arg2, arg3, damageTypes) {
    const candidates = [
        [1, arg1],
        [2, arg2],
        [3, arg3]
    ];
    for (const [index, arg] of candidates) {
        try {
            const report = new SPlayerDamageReport(arg);
            if (report.ptr.isNull()) continue;
            const damageType = report.damageType;
            const totalDamage = report.totalDamage;
            if (!damageTypes.has(damageType) || !Number.isFinite(totalDamage)) continue;
            return { index, report, damageType, totalDamage };
        } catch (_) {}
    }
    return null;
}

function installActorDamageNullHook(options = {}) {
    const actor = scPlayer()?.currentActor ?? player()?.actor ?? null;
    if (!actor) throw new Error("current CActor is unavailable");

    const method = actor.clientPlayerDamageRemoteMethod;
    const target = method.handler.dispatcherOrDirectCall;
    if (target.isNull()) throw new Error("CActor player damage remote-method handler is null");

    if (actorDamageNullHook?.listener) {
        actorDamageNullHook.listener.detach();
        actorDamageNullHook = null;
    }

    const types = new Set((options.damageTypes ?? [0x08, 0x09, 0x0A]).map(value => parseS32(value, "damageType")));
    const sampleLimit = Object.prototype.hasOwnProperty.call(options, "sampleLimit") ? parseS32(options.sampleLimit, "sampleLimit") : 16;
    const state = {
        installed: true,
        target: target.toString(),
        damageTypes: Array.from(types),
        hits: 0,
        last: null,
        samples: []
    };

    const listener = Interceptor.attach(target, {
        onEnter(args) {
            const arg1 = args[1];
            const arg2 = args[2];
            const arg3 = args[3];
            const found = playerDamageReportFromArgs(arg1, arg2, arg3, types);
            if (!found) return;

            state.hits++;
            state.last = {
                argIndex: found.index,
                damageType: found.damageType,
                totalDamage: found.totalDamage
            };
            if (state.samples.length < sampleLimit) {
                state.samples.push(found.report.toObject());
            }
            found.report.zero();
        }
    });

    actorDamageNullHook = { listener, state };
    return {
        installed: true,
        actor: actor.ptr.toString(),
        remoteMethod: method.toObject(),
        ...state
    };
}

function uninstallActorDamageNullHook() {
    if (!actorDamageNullHook?.listener) return { installed: false };
    const state = actorDamageNullHook.state;
    actorDamageNullHook.listener.detach();
    actorDamageNullHook = null;
    return {
        installed: false,
        previous: state
    };
}

function actorDamageNullHookState() {
    return actorDamageNullHook?.state ?? { installed: false };
}

function killParamsFromArgs(arg1, arg2, arg3, hitTypes) {
    const candidates = [
        [1, arg1],
        [2, arg2],
        [3, arg3]
    ];
    for (const [index, arg] of candidates) {
        try {
            const params = new SKillParams(arg);
            if (params.ptr.isNull()) continue;
            const hitType = params.hitType;
            if (!hitTypes.has(hitType)) continue;
            return { index, params, hitType };
        } catch (_) {}
    }
    return null;
}

function installActorKillNullHook(options = {}) {
    const actor = scPlayer()?.currentActor ?? player()?.actor ?? null;
    if (!actor) throw new Error("current CActor is unavailable");

    const method = actor.multicastKillRemoteMethod;
    const handler = method.handler;
    const target = handler.dispatcherOrDirectCall;
    if (target.isNull()) throw new Error("CActor kill remote-method handler is null");
    if (handler.storage.isNull()) throw new Error("CActor kill remote-method storage is null; unsupported direct-call handler shape");

    if (actorKillNullHook?.target) uninstallActorKillNullHook();

    const hitTypes = new Set((options.hitTypes ?? [
        ActorDamageToKillType.collision,
        ActorDamageToKillType.fallDamage,
        ActorDamageToKillType.crash
    ]).map(value => parseS32(value, "hitType")));
    const sampleLimit = Object.prototype.hasOwnProperty.call(options, "sampleLimit") ? parseS32(options.sampleLimit, "sampleLimit") : 16;
    const suppressUnparsed = options.suppressUnparsed === true;

    const original = new NativeFunction(target, "void", ["pointer", "pointer", "pointer"]);
    const state = {
        installed: true,
        target: target.toString(),
        storage: handler.storage.toString(),
        hitTypes: Array.from(hitTypes),
        calls: 0,
        suppressed: 0,
        passed: 0,
        unparsed: 0,
        errors: 0,
        suppressUnparsed,
        last: null,
        samples: []
    };

    const replacement = new NativeCallback((storage, context, paramsPtr) => {
        state.calls++;
        try {
            const found = killParamsFromArgs(storage, context, paramsPtr, hitTypes);
            if (found) {
                state.suppressed++;
                const sample = found.params.toObject();
                state.last = {
                    argIndex: found.index,
                    hitType: found.hitType,
                    params: sample
                };
                if (state.samples.length < sampleLimit) state.samples.push(sample);
                return;
            }

            let parsedAny = false;
            try {
                const params = new SKillParams(paramsPtr);
                parsedAny = !params.ptr.isNull() && Number.isInteger(params.hitType);
                state.lastNonMatching = params.toObject();
            } catch (_) {}

            if (!parsedAny) {
                state.unparsed++;
                if (suppressUnparsed) {
                    state.suppressed++;
                    return;
                }
            }

            state.passed++;
            original(storage, context, paramsPtr);
        } catch (e) {
            state.errors++;
            state.lastError = String(e);
            if (suppressUnparsed) {
                state.suppressed++;
                return;
            }
            original(storage, context, paramsPtr);
        }
    }, "void", ["pointer", "pointer", "pointer"]);

    try {
        Interceptor.revert(target);
        Interceptor.flush();
    } catch (_) {}

    try {
        Interceptor.replace(target, replacement);
        Interceptor.flush();
        actorKillNullHook = { target, replacement, state };
    } catch (e) {
        state.installed = false;
        state.installError = String(e);
        return {
            installed: false,
            actor: actor.ptr.toString(),
            remoteMethod: method.toObject(),
            ...state
        };
    }
    return {
        installed: true,
        actor: actor.ptr.toString(),
        remoteMethod: method.toObject(),
        ...state
    };
}

function uninstallActorKillNullHook() {
    if (!actorKillNullHook?.target) return { installed: false };
    const state = actorKillNullHook.state;
    Interceptor.revert(actorKillNullHook.target);
    Interceptor.flush();
    actorKillNullHook = null;
    return {
        installed: false,
        previous: state
    };
}

function actorKillNullHookState() {
    return actorKillNullHook?.state ?? { installed: false };
}

function resolveCurrentBodyHealthProcessHitTarget() {
    const actor = scPlayer()?.currentActor ?? player()?.actor ?? null;
    if (!actor) throw new Error("current CActor is unavailable");
    const health = actor.healthComponent;
    if (!health) throw new Error("current CSCBodyHealthComponent is unavailable");

    const vtable = health.ptr.readPointer();
    if (vtable.isNull()) throw new Error("current CSCBodyHealthComponent has null vtable");

    const processHitPtr = vtable.add(0x740).readPointer();
    if (processHitPtr.isNull()) throw new Error("CSCBodyHealthComponent::ProcessHit slot is null");

    return { actor, health, vtable, processHitPtr };
}

function actorHealthHitSurface() {
    const target = resolveCurrentBodyHealthProcessHitTarget();
    return {
        actor: target.actor.ptr.toString(),
        healthComponent: target.health.toObject(),
        vtable: target.vtable.toString(),
        processHitSlot: 232,
        processHitVtableOffset: "0x740",
        processHitPtr: target.processHitPtr.toString(),
        hitInfo: {
            size: "0x168",
            targetEntity: "0x08",
            damage: "0x38",
            damageValues: "0x40",
            maxDamageLimitRatio: "0x58",
            impulseScale: "0x60",
            type: "0x78",
            partId: "0x7C",
            pCollisionEvent: "0xF8"
        },
        eHitType: EHitType
    };
}

function installActorHealthHitNullHook(options = {}) {
    const target = resolveCurrentBodyHealthProcessHitTarget();
    if (actorHealthHitNullHook?.target) uninstallActorHealthHitNullHook();

    const hitTypes = new Set((options.hitTypes ?? [EHitType.Collision, EHitType.Crash]).map(value => parseS32(value, "hitType")));
    const sampleLimit = Object.prototype.hasOwnProperty.call(options, "sampleLimit") ? parseS32(options.sampleLimit, "sampleLimit") : 16;
    const suppressAll = options.suppressAll === true;
    const zeroInsteadOfSuppress = options.zeroInsteadOfSuppress === true;
    const restoreHealth = options.restoreHealth === true;
    const original = new NativeFunction(target.processHitPtr, "void", ["pointer", "pointer"]);

    const state = {
        installed: true,
        target: target.processHitPtr.toString(),
        actor: target.actor.ptr.toString(),
        healthComponent: target.health.ptr.toString(),
        hitTypes: Array.from(hitTypes),
        suppressAll,
        zeroInsteadOfSuppress,
        restoreHealth,
        initialHealth: target.health.health,
        initialMaxHealth: target.health.maxHealth,
        calls: 0,
        matched: 0,
        suppressed: 0,
        zeroed: 0,
        passed: 0,
        errors: 0,
        mode: "replace",
        samples: [],
        last: null,
        lastPassed: null
    };

    const replacement = new NativeCallback((healthPtr, hitInfoPtr) => {
        state.calls++;
        try {
            const isCurrentHealth = ptr(healthPtr).equals(target.health.ptr);
            if (!isCurrentHealth) {
                original(healthPtr, hitInfoPtr);
                return;
            }

            const hit = new HitInfo(hitInfoPtr);
            const type = hit.type;
            const shouldBlock = suppressAll || hitTypes.has(type);
            const sample = hit.toObject();

            if (shouldBlock) {
                state.matched++;
                state.last = sample;
                if (state.samples.length < sampleLimit) state.samples.push(sample);

                if (zeroInsteadOfSuppress) {
                    hit.zeroDamage();
                    state.zeroed++;
                    original(healthPtr, hitInfoPtr);
                } else {
                    state.suppressed++;
                }
                if (restoreHealth) {
                    target.health.restoreToMax();
                    state.lastRestoredHealth = target.health.health;
                }
                return;
            }

            state.passed++;
            state.lastPassed = {
                type: sample.type,
                totalDamage: sample.totalDamage,
                targetEntity: sample.targetEntity,
                pCollisionEvent: sample.pCollisionEvent
            };
            original(healthPtr, hitInfoPtr);
        } catch (e) {
            state.errors++;
            state.lastError = String(e);
            original(healthPtr, hitInfoPtr);
        }
    }, "void", ["pointer", "pointer"]);

    try {
        Interceptor.revert(target.processHitPtr);
        Interceptor.flush();
    } catch (_) {}

    try {
        Interceptor.replace(target.processHitPtr, replacement);
        Interceptor.flush();
        actorHealthHitNullHook = { target: target.processHitPtr, replacement, state };
    } catch (e) {
        state.mode = "attach-zero";
        state.replaceError = String(e);
        const listener = Interceptor.attach(target.processHitPtr, {
            onEnter(args) {
                const healthPtr = args[0];
                const hitInfoPtr = args[1];
                state.calls++;
                try {
                    if (!ptr(healthPtr).equals(target.health.ptr)) return;
                    const hit = new HitInfo(hitInfoPtr);
                    const type = hit.type;
                    const shouldBlock = suppressAll || hitTypes.has(type);
                    const sample = hit.toObject();
                    if (!shouldBlock) {
                        state.passed++;
                        state.lastPassed = {
                            type: sample.type,
                            totalDamage: sample.totalDamage,
                            targetEntity: sample.targetEntity,
                            pCollisionEvent: sample.pCollisionEvent
                        };
                        return;
                    }

                    state.matched++;
                    state.zeroed++;
                    state.last = sample;
                    if (state.samples.length < sampleLimit) state.samples.push(sample);
                    hit.zeroDamage();
                    if (restoreHealth) {
                        target.health.restoreToMax();
                        state.lastRestoredHealth = target.health.health;
                    }
                } catch (inner) {
                    state.errors++;
                    state.lastError = String(inner);
                }
            }
        });
        actorHealthHitNullHook = { listener, state };
    }
    return state;
}

function uninstallActorHealthHitNullHook() {
    if (!actorHealthHitNullHook) return { installed: false };
    const state = actorHealthHitNullHook.state;
    if (actorHealthHitNullHook.listener) {
        actorHealthHitNullHook.listener.detach();
    } else if (actorHealthHitNullHook.target) {
        Interceptor.revert(actorHealthHitNullHook.target);
        Interceptor.flush();
    }
    actorHealthHitNullHook = null;
    return {
        installed: false,
        previous: state
    };
}

function actorHealthHitNullHookState() {
    return actorHealthHitNullHook?.state ?? { installed: false };
}

function actorHealthState() {
    const target = resolveCurrentBodyHealthProcessHitTarget();
    return {
        actor: target.actor.ptr.toString(),
        healthComponent: target.health.toObject(),
        healthHitHook: actorHealthHitNullHookState()
    };
}

function currentBodyHealthComponent() {
    const actor = scPlayer()?.currentActor ?? player()?.actor ?? null;
    if (actor?.healthComponent) return actor.healthComponent;
    const componentPtr = player()?.getComponentByName?.("SCBodyHealthComponent") ?? null;
    return componentPtr ? new CSCBodyHealthComponent(componentPtr) : null;
}

function bodyHealthComponentForEntity(entityId = null) {
    if (entityId === null || entityId === undefined) return currentBodyHealthComponent();
    const entity = gEnv.entitySystem?.getEntity(entityId);
    if (!entity) throw new Error(`entity ${entityId} is unavailable`);
    const componentPtr = entity.getComponentByName("SCBodyHealthComponent");
    if (!componentPtr) throw new Error(`entity ${entityId} has no SCBodyHealthComponent`);
    return new CSCBodyHealthComponent(componentPtr);
}

function bodyHealthSurface(entityId = null, includeAddresses = true) {
    const health = bodyHealthComponentForEntity(entityId);
    return {
        surface: CSCBodyHealthComponentSurface,
        actorStatTypes: EActorStatType,
        healthChangeReasons: EHealthChangeReason,
        invulnerableFlags: EInvulnerableFlags,
        live: health ? health.surface(includeAddresses) : null
    };
}

function bodyHealthState(entityId = null, options = {}) {
    const health = bodyHealthComponentForEntity(entityId);
    if (!health) throw new Error("CSCBodyHealthComponent is unavailable");
    return health.toObject(options);
}

function restoreActorHealth(reason = 1) {
    const target = resolveCurrentBodyHealthProcessHitTarget();
    return {
        actor: target.actor.ptr.toString(),
        healthComponent: target.health.restoreToMax(reason)
    };
}

function installActorDamageAndKillNullHooks(options = {}) {
    return {
        healthHit: installActorHealthHitNullHook(options),
        damage: installActorDamageNullHook(options),
        kill: installActorKillNullHook(options)
    };
}

function uninstallActorDamageAndKillNullHooks() {
    return {
        healthHit: uninstallActorHealthHitNullHook(),
        damage: uninstallActorDamageNullHook(),
        kill: uninstallActorKillNullHook()
    };
}

function entities() {
    return gEnv.entitySystem?.entityArray.toArray() ?? [];
}

function entitySystemSurface(options = {}) {
    const system = gEnv.entitySystem;
    return {
        sizes: {
            CEntitySystem: 0x1410,
            CEntityClassRegistry: 0x150,
            CEntityClass: 0xA0,
            IComponent: 0x48,
            CIGInplaceTrie_EComponentTypeIndex_SEntry: 0x02,
            SComponentParamsPair: 0x20,
            StdMap_U32_ComponentId: 0x10,
            StdMapNode_U32_ComponentId: 0x28,
            CEntityLookup: 0x7A0
        },
        vtables: {
            IEntityClass: {
                getClassGuid: 2,
                getName: 3,
                getGroup: 4,
                getClassCrc: 5,
                getFlags: 6,
                containsComponent: 11,
                getClassComponentParams: 12,
                isUniqueEntityClass: 17
            },
            IEntityClassRegistry: {
                findClassByCrc: 2,
                findClassByGuid: "3 (CryGUID by-value ABI not wrapped)",
                findClassByName: 4,
                getDefaultClass: 5,
                forEachEntityClass: "14 (not used; CigTemporaryFunction dispatcher ABI is not wrapped)",
                getClassCount: 15
            },
            IEntityComponentSystem: {
                getComponentId: 2,
                getComponentName: 4,
                getComponentSubSystem: 5,
                getComponentNameAlias: 6,
                getComponentSize: 8,
                getAllComponents: 16,
                getComponentRegistryHash: 30
            },
            IEntity: {
                getId: 1,
                getClass: 4,
                getName: 14,
                getChildCount: 46,
                queryComponent: 113,
                queryAllComponents: 119,
                queryAllComponentIds: "120 (unsafe unless native temp-vector lifetime is wrapped)",
                getZone: 215,
                getHostedZone: 219
            },
            IEntitySystem: {
                getClassRegistry: 24,
                getEntity: 35,
                findEntityByName: 40,
                getNumEntities: 45,
                forEachEntity: 46,
                queryEntities: 56,
                getEntityCount: 76
            }
        },
        offsets: {
            CEntitySystem: {
                m_allEntitiesUnordered: "0x148",
                m_entityLookup: "0x1A8",
                m_pEntityComponentSystem: "0x948",
                m_pClassRegistry: "0xBE0",
                m_actorComponentHash: "0x1320",
                m_vehicleComponentHash: "0x1328",
                m_ocComponentHash: "0x1330"
            },
            CEntityClass: {
                m_nFlags: "0x08",
                m_sName: "0x10",
                m_sGroup: "0x18",
                m_classCRC: "0x20",
                m_componentParams: "0x28",
                m_pPropertyHandler: "0x40",
                m_EditorClassInfo: "0x48",
                m_pRecordRef: "0x70",
                m_classGUID: "0x88",
                m_tagList: "0x98",
                m_bIsUnique: "0x9C"
            },
            IComponent: {
                m_pEntityPtr: "0x08",
                m_params: "0x18",
                m_componentID: "0x3A",
                m_nDebugUpdateIndex: "0x40"
            },
            StdMapNode_U32_ComponentId: {
                left: "0x00",
                parent: "0x08",
                right: "0x10",
                isNil: "0x19",
                key: "0x1C",
                componentId: "0x20"
            },
            CEntity: {
                m_flags: "0x08",
                m_id: "0x10",
                m_pClass: "0x20",
                m_zonePos: "0x48",
                m_entityFlags: "0x128",
                m_name: "0x2A8",
                m_zone: "0x2C0"
            }
        },
        live: system ? (
            options.directOnly === true
                ? system.toDirectObject(options)
                : system.toObject({
                    includeAllComponentsMap: options.includeAllComponentsMap === true
                })
        ) : null
    };
}

function entitySystemCoverageAudit(includeLive = false) {
    const deliverables = [
        {
            requirement: "catalog IEntityClassRegistry",
            status: "implemented",
            evidence: [
                "CEntityClassRegistry.findClass",
                "CEntityClassRegistry.findClassByCrc",
                "CEntityClassRegistry.classMapEntries",
                "CEntityClassRegistry.findClassesByName",
                "rpc.exports.entityclassregistry",
                "rpc.exports.entityclassbyname",
                "rpc.exports.entityclassbycrc",
                "rpc.exports.entityclassbyguid",
                "rpc.exports.findentityclasses"
            ],
            notes: "Class enumeration parses confirmed m_mapClassName std::map layout; CigTemporaryFunction callback enumeration is intentionally not used."
        },
        {
            requirement: "catalog IEntityClass / CEntityClass",
            status: "implemented",
            evidence: [
                "CEntityClass direct field decoders",
                "CEntityClass.componentIds",
                "CEntityClass.components",
                "CEntityClass.toObject"
            ],
            notes: "Name/group/crc/flags/guid/component params read from confirmed CEntityClass offsets."
        },
        {
            requirement: "catalog CEntitySystem / IEntitySystem",
            status: "implemented",
            evidence: [
                "CEntitySystem.entityArray",
                "CEntitySystem.entityComponentSystem",
                "CEntitySystem.classRegistry",
                "CEntitySystem.getEntity",
                "CEntitySystem.findEntityByName",
                "CEntitySystem.findEntities",
                "CEntitySystem.findEntitiesOfKind",
                "rpc.exports.entitysystemsurface"
            ],
            notes: "Entity lookup uses confirmed CEntitySystem.m_entityLookup; surface reports confirmed sizes, offsets, and vtable slots."
        },
        {
            requirement: "find entities of a specific kind",
            status: "implemented",
            evidence: [
                "findEntities",
                "findEntitiesOfKind",
                "findByClassName",
                "CEntity.directSummary",
                "rpc.exports.findentities",
                "rpc.exports.findentitiesofkind"
            ],
            notes: "Kind matching supports className, entity name, or component mode; RPCs default to direct summaries unless includeComponents is requested."
        },
        {
            requirement: "identify installed components on an entity",
            status: "implemented_verified_live",
            evidence: [
                "CEntityComponentSystem.GetAllComponents map parser",
                "CEntityComponentSystem.registeredComponentIds",
                "CEntity.listComponents source=declaredClass",
                "CEntity.listComponents source=registeredScan",
                "CEntity.listComponents source=declaredPlusRegisteredScan/hybrid",
                "rpc.exports.entitycomponents",
                "rpc.exports.registeredcomponents",
                "rpc.exports.registeredcomponentids"
            ],
            notes: "Safe modes avoid IEntity::QueryAllComponents_2 and identify installed components via IEntity::QueryComponent over declared and/or registered component ids; live hybrid smoke verified declaredPlusRegisteredScan after the prior crash."
        },
        {
            requirement: "avoid crash-prone component vector enumeration",
            status: "guarded",
            evidence: [
                "CEntity.queryAllComponentIds throws",
                "CEntity.unsafeQueryAllComponentIds requires allowUnsafeNativeVector"
            ],
            notes: "The native temp-vector path is blocked unless explicitly requested after allocator/destructor wrapping is confirmed."
        }
    ];

    return {
        objective: "entity system/class registry/entity class/entity finding/component identification coverage",
        deliverables,
        verification: {
            syntax: "node --check star.js",
            liveSmoke: includeLive ? "included" : "not included by default",
            liveSmokeRecommended: [
                "rpc.exports.entitysystemsurface()",
                "rpc.exports.entitysystemsmoketest({ includeFindEntities: false, includeEntityComponents: false, includeRegisteredComponents: false })",
                "rpc.exports.entityclassregistry(3, false)",
                "rpc.exports.registeredcomponents(null).length",
                "rpc.exports.entitycomponents(null, { source: 'hybrid', limit: 256 })",
                "rpc.exports.findentitiesofkind('Player', { limit: 3 })"
            ]
        },
        live: includeLive ? entitySystemSurface({ directOnly: true, includeAllComponentsMap: false }).live : null
    };
}

function entitySystemSmokeTest(options = {}) {
    const classLimit = Number.isInteger(Number(options.classLimit)) ? Number(options.classLimit) : 3;
    const entityLimit = Number.isInteger(Number(options.entityLimit)) ? Number(options.entityLimit) : 3;
    const componentLimit = Number.isInteger(Number(options.componentLimit)) ? Number(options.componentLimit) : 256;
    const componentSource = options.componentSource ?? "declaredClass";
    const includeEntityComponents = options.includeEntityComponents === true;
    const includeRegisteredComponents = options.includeRegisteredComponents === true;
    const includeFindEntities = options.includeFindEntities === true;

    const run = (name, fn) => {
        try {
            return {
                ok: true,
                value: fn()
            };
        } catch (e) {
            return {
                ok: false,
                error: e.message
            };
        }
    };

    const out = {
        options: {
            classLimit,
            entityLimit,
            componentLimit,
            componentSource,
            includeEntityComponents,
            includeRegisteredComponents,
            includeFindEntities
        },
        unsafePathsDisabled: {
            queryAllComponents2: true,
            allowUnsafeNativeVector: false
        },
        steps: {}
    };

    out.steps.surface = run("surface", () => {
        const surface = entitySystemSurface({ directOnly: true, includeAllComponentsMap: false });
        return {
            entitySystem: surface.live?.ptr ?? null,
            entityLookupCurrSize: surface.live?.entityLookup?.currSize ?? null,
            classRegistry: surface.live?.classRegistry?.ptr ?? null,
            classRegistryMapSize: surface.live?.classRegistry?.mapSize ?? null,
            componentSystem: surface.live?.entityComponentSystem?.ptr ?? null
        };
    });

    out.steps.classRegistry = run("classRegistry", () => {
        const registryPtr = gEnv.entitySystem?.classRegistryFromMemory ?? null;
        const classMap = registryPtr ? registryPtr.classMapEntries(classLimit, false) : null;
        return {
            classCount: classMap?.map?.size ?? null,
            mapSize: classMap?.map?.size ?? null,
            classes: classMap?.classes?.map(entityClass => ({
                name: entityClass.name,
                classCrc: entityClass.classCrc,
                classGuid: entityClass.classGuid
            })) ?? []
        };
    });

    if (includeRegisteredComponents || includeEntityComponents) {
        out.steps.registeredComponentIds = run("registeredComponentIds", () => {
            const ids = registeredComponentIds(null, false);
            return {
                count: ids.length,
                sample: ids.slice(0, 16)
            };
        });
    }

    if (includeFindEntities) {
        out.steps.findPlayers = run("findPlayers", () => findEntitiesOfKind("Player", {
            limit: entityLimit,
            safeSummary: true
        }));
    }

    if (includeEntityComponents) {
        out.steps.currentEntityComponents = run("currentEntityComponents", () => {
            const result = entityComponents(null, {
                source: componentSource,
                limit: componentLimit,
                allowUnsafeNativeVector: false,
                allowRegisteredRangeFallback: false
            });
            return {
                entity: result.entity,
                source: result.source,
                count: result.count,
                components: result.components.map(component => ({
                    componentId: component.componentId,
                    componentIdHex: component.componentIdHex,
                    name: component.name,
                    ptr: component.ptr,
                    installed: component.installed
                }))
            };
        });
    }

    out.ok = Object.values(out.steps).every(step => step.ok);
    return out;
}

function entityClassRegistryState(limit = 64, includeComponents = false) {
    const registry = gEnv.entitySystem?.classRegistry ?? null;
    if (!registry) return null;
    return registry.toObject(limit, includeComponents);
}

function entityClassByName(name, includeComponents = false) {
    const registry = gEnv.entitySystem?.classRegistryFromMemory ?? null;
    return registry ? registry.findClassByNameDirect(name, includeComponents) : null;
}

function entityClassByCrc(classCrc, includeComponents = false) {
    const registry = gEnv.entitySystem?.classRegistryFromMemory ?? null;
    return registry ? registry.findClassByCrcDirect(classCrc, includeComponents) : null;
}

function entityClassByGuid(classGuid, includeComponents = false) {
    const registry = gEnv.entitySystem?.classRegistryFromMemory ?? null;
    if (!registry) return null;
    return registry.forEachClass(32768, includeComponents).find(entityClass => entityClass.classGuid === String(classGuid).toLowerCase()) ?? null;
}

function findEntityClasses(pattern, scanLimit = 32768, includeComponents = false, resultLimit = 256) {
    const registry = gEnv.entitySystem?.classRegistryFromMemory ?? null;
    if (!registry) return [];
    return registry.findClassesByName(pattern, scanLimit, includeComponents, resultLimit);
}

function registeredComponents(maxId = null, allowRangeFallback = false) {
    const componentSystem = gEnv.entityComponentSystem;
    if (!componentSystem) return [];
    return componentSystem.registeredComponents(maxId, false, allowRangeFallback);
}

function registeredComponentIds(maxId = null, allowRangeFallback = false) {
    const componentSystem = gEnv.entityComponentSystem;
    if (!componentSystem) return [];
    return componentSystem.registeredComponentIds(maxId, allowRangeFallback);
}

function entityComponents(entityId = null, options = {}) {
    const entity = entityId === null || entityId === undefined
        ? player()
        : gEnv.entitySystem?.getEntity(entityId);
    if (!entity) throw new Error("entity is unavailable");
    return entity.listComponents(options);
}

function findEntities(options = {}) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) return [];
    return entitySystem.findEntities(options).map(entity => {
        const includeComponents = options.includeComponents === true;
        if (options.safeSummary !== false && !includeComponents) return entity.directSummary();
        return entity.toObject(includeComponents);
    });
}

function findEntitiesOfKind(kind, options = {}) {
    const entitySystem = gEnv.entitySystem;
    if (!entitySystem) return [];
    return entitySystem.findEntitiesOfKind(kind, options).map(entity => {
        const includeComponents = options.includeComponents === true;
        if (options.safeSummary !== false && !includeComponents) return entity.directSummary();
        return entity.toObject(includeComponents);
    });
}

function findByClassName(pattern) {
    const re = pattern instanceof RegExp ? pattern : new RegExp(String(pattern), "i");
    return entities().filter(entity => {
        try {
            return re.test(entity.entityClass?.name ?? "");
        } catch (_) {
            return false;
        }
    });
}

function listPlayers() {
    return findByClassName(/^(Player|PlayerCorpse)$/).map(entity => ({
        entity,
        id: entity.id,
        name: entity.name,
        className: entity.entityClass?.name ?? null,
        worldPos: entity.worldPos
    }));
}

function playerMissionLog() {
    return player()?.missionLog ?? null;
}

function listContracts(includeObjectives = true, includeNestedDetails = false) {
    const missionLog = playerMissionLog();
    return missionLog ? missionLog.listActiveContracts(includeObjectives, includeNestedDetails) : [];
}

function auditContracts() {
    const missionSystem = gEnv.missionSystem;
    const missionService = missionSystem?.missionService ?? null;
    const missionLog = playerMissionLog();

    return {
        missionSystem: missionSystem?.ptr.toString() ?? null,
        cigServices: gEnv.cigServices?.ptr.toString() ?? null,
        cigServicesInternal: gEnv.cigServices?.internal?.ptr.toString() ?? null,
        missionServiceInternal: resolveMissionServiceInternal()?.ptr.toString() ?? null,
        missionService: missionService?.ptr.toString() ?? null,
        hasDebugCompleteAllObjectivesSlot: missionService?.hasDebugCompleteAllObjectivesSlot ?? false,
        missionLog: missionLog?.ptr.toString() ?? null,
        activeTrackedContractName: missionLog?.activeTrackedContractName ?? null,
        activeTrackedContractDefId: missionLog?.activeTrackedContractDefId ?? null,
        confirmedMissionLogLayout: {
            onlineActiveMissionsOffset: "0x468",
            offlineActiveMissionsOffset: "0x450",
            missionLockOffset: "0x498",
            onlineCompletedMissionsOffset: "0x4D8",
            offlineCompletedMissionsOffset: "0x4C0",
            missionEntrySize: "0x278"
        },
        activeContractCount: missionLog?.missionsLocal.count ?? 0,
        replicatedContractCount: missionLog?.missions.count ?? 0,
        completedContractCount: missionLog?.completedMissionsLocal.count ?? 0,
        contracts: listContracts(false, false)
    };
}

function missionLogState() {
    const missionLog = playerMissionLog();
    return missionLog ? missionLog.toObject() : null;
}

function missionSystemState() {
    const missionSystem = gEnv.missionSystem;
    return missionSystem ? missionSystem.toObject() : null;
}

function resolveInventoryApi() {
    const services = gEnv.cigServices;
    if (!services) return null;

    const externalFromRoot = services instanceof ICIGServices ? services.external : null;
    if (externalFromRoot?.inventoryApi) return externalFromRoot.inventoryApi;

    const externalFromSamePtr = new ICIGServices(services.ptr).external;
    if (externalFromSamePtr?.inventoryApi) return externalFromSamePtr.inventoryApi;

    return null;
}

function inventoryManagementSurface() {
    return {
        ...InventoryManagementSurface,
        enums: {
            EInventoryContext,
            EItemOwnershipStatus,
            EInventoryQueryOrderBy,
            EPersonalInventoryOperationType,
            EPlayerInventoryType,
            EInventoryDataRequestType,
            EInventoryRequestResult,
            SInventoryManagementRequestFlags
        },
        userPath: {
            uiOwner: "CSCLocalPlayerPersonalThoughtComponent",
            backendDispatcher: "CSCPlayerInventory",
            requestEnvelope: "SInventoryManagementRequest",
            containerManager: "CInventoryContainerManager",
            openNestedInventory: {
                handleClickOpenContainer: "0x1462ED6F0",
                doOpenNestedInventory: "0x1462C3F60",
                requestInventoryManagementOperation: "0x1445DFE70",
                processRequest: "0x1445B56A0",
                queryInventoryInternal: "0x1445BA6C0",
                processRequestStoredItemInventory: "0x1445B5FF0"
            },
            managerEntrypoints: {
                queueOpenInventoryContainer: "0x1445BB060",
                asyncOpenInventoryContainer: "0x1444A5240",
                asyncQueryInventory: "0x1444A5E50",
                processPendingInventoryContainerOpens: "0x1445B3C50"
            }
        }
    };
}

function inventoryOperationSurface() {
    const playerComponent = scPlayer();
    const playerInventory = playerComponent?.playerInventory ?? null;
    const personalThought = playerPersonalThoughtComponent(true);
    const containerManager = gEnv.game?.inventoryContainerManager ?? null;
    const inventoryApi = resolveInventoryApi();

    return {
        requestPath: InventoryManagementSurface.inventoryRequestPath,
        playerInventory: playerInventory ? playerInventory.surface() : null,
        playerInventoryOperations: playerInventory ? playerInventory.operationSurface(0, false) : null,
        personalThought: personalThought ? personalThought.operationSurface() : null,
        inventoryApi: inventoryApi ? inventoryApi.surface() : null,
        inventoryManagementApi: inventoryApi?.inventoryManagementApi?.surface() ?? null,
        itemPortModificationApi: inventoryApi?.itemPortModificationApi?.surface() ?? null,
        containerManager: containerManager ? containerManager.surface() : null
    };
}

function inventoryCoverageAudit() {
    const sizes = InventoryManagementSurface.sizes;
    const requiredSizes = [
        "CSCPlayerInventory",
        "CSCLocalPlayerPersonalThoughtComponent",
        "CInventoryContainerManager",
        "CInventoryContainerComponent",
        "SInventoryManagementRequest",
        "SInventoryContainerTypeBaseDef",
        "SInventoryOpenContainerTypeDef",
        "SInventoryOpenAlwaysContainerTypeDef",
        "SInventoryClosedContainerTypeDef",
        "SInventoryContainerItemTypeFilter",
        "SInventoryParams",
        "SInventoryGamePersistentData",
        "SInventoryItemMapEntry",
        "SInventoryContainerUIParams",
        "SInventorySortMode",
        "SInventoryDropDetachRules",
        "SInventoryStateModifier",
        "SStowPolicyCache",
        "SCargoGridOccupantFace",
        "SCargoGridOccupantProperties",
        "SOpenInventoryOccupantItemTypeProperties",
        "SInventoryContainerManagerDef",
        "SInventoryContainerGridCellSizeBase",
        "SInventoryContainerGridCellSizeCentimeters",
        "SInventoryContainerGridCellSizeMeters",
        "SMoveStackRequest",
        "SMoveItemRequest",
        "SUnstackEntityRequestParams",
        "SUnstackEntityRequest",
        "SMoveEntityStackParam",
        "IInventoryApi_SMoveResult",
        "IInventoryApi_SMoveRequest",
        "SEntityStackChangeParam",
        "SIncreaseEntityStackRequest",
        "SDecreaseEntityStackRequest",
        "SSetEntityStackRequest",
        "SMoveEntityStackRequest",
        "STransferEntityAggregateRequest",
        "SCreateEntityToInventoryRequest",
        "IInventoryApi_SCreateEntityToInventoryRequest",
        "SUnstowItemRequestParams",
        "SEntityUnstowParams",
        "SUnstowRequest",
        "SSPlitStackRequestParams",
        "SSplitStackRequest",
        "SDeleteItemRequestParams",
        "SDeleteItemRequest",
        "SStowEntityRequest",
        "SStowRequest",
        "SDestroyEntityPreconditions",
        "SDestroyEntityParam",
        "SDestroyEntityRequest",
        "SOptionalArguments",
        "IItemPortModificationApi_SAttachRequest",
        "IItemPortModificationApi_SDetachRequest",
        "IItemPortModificationApi_SModifyItemPortRequest",
        "SPlayerInventoryQuery",
        "SInventoryContainerEntry",
        "SInventoryContainerGridItem",
        "SGridItemRequest",
        "SInventoryDataRequest",
        "SInventoryContainerManagerEntriesCache",
        "SInventoryContainerManagerDataCache",
        "SPersonalInventoryReceivedData",
        "SPersonalInventoryData",
        "SInventoryContainerFilterCacheKey",
        "SInventoryContainerManagerDataCachePair",
        "SInventoryContainerManagerData",
        "CInventoryContainerManager_CInventoryQueryPendingRequest",
        "CInventoryContainerManager_CInventoryOpenPendingRequest",
        "CInventoryContainerManager_AsyncQueryInventoryData_SQueryEntry",
        "CInventoryContainerManager_AsyncStowEntity_SAsyncStowSharedData",
        "CInventoryContainerManager_ProcessPendingInventoryContainerOpens_SUnstowRequestInfo"
    ];
    const requiredOffsets = [
        "cscPlayerInventoryOffsets",
        "cscLocalPlayerPersonalThoughtComponentOffsets",
        "cInventoryContainerManagerOffsets",
        "cInventoryContainerComponentOffsets",
        "sInventoryManagementRequestOffsets",
        "sInventoryOpenContainerTypeDefOffsets",
        "sInventoryContainerItemTypeFilterOffsets",
        "sInventoryClosedContainerTypeDefOffsets",
        "sInventoryParamsOffsets",
        "sInventoryGamePersistentDataOffsets",
        "sInventoryItemMapEntryOffsets",
        "sInventoryContainerUIParamsOffsets",
        "sInventorySortModeOffsets",
        "sInventoryDropDetachRulesOffsets",
        "sInventoryStateModifierOffsets",
        "sStowPolicyCacheOffsets",
        "sCargoGridOccupantFaceOffsets",
        "sCargoGridOccupantPropertiesOffsets",
        "sOpenInventoryOccupantItemTypePropertiesOffsets",
        "sInventoryContainerManagerDefOffsets",
        "sInventoryContainerGridCellSizeCentimetersOffsets",
        "sInventoryContainerGridCellSizeMetersOffsets",
        "sMoveStackRequestOffsets",
        "sMoveItemRequestOffsets",
        "sUnstackEntityRequestParamsOffsets",
        "sUnstackEntityRequestOffsets",
        "sMoveEntityStackParamOffsets",
        "iInventoryApiMoveResultOffsets",
        "iInventoryApiMoveRequestOffsets",
        "sEntityStackChangeParamOffsets",
        "sEntityStackChangeRequestOffsets",
        "sMoveEntityStackRequestOffsets",
        "sTransferEntityAggregateRequestOffsets",
        "sCreateEntityToInventoryRequestOffsets",
        "iInventoryApiCreateEntityToInventoryRequestOffsets",
        "sUnstowItemRequestParamsOffsets",
        "sEntityUnstowParamsOffsets",
        "sUnstowRequestOffsets",
        "sSplitStackRequestParamsOffsets",
        "sSplitStackRequestOffsets",
        "sDeleteItemRequestParamsOffsets",
        "sDeleteItemRequestOffsets",
        "sStowEntityRequestOffsets",
        "sStowRequestOffsets",
        "sDestroyEntityPreconditionsOffsets",
        "sDestroyEntityParamOffsets",
        "sDestroyEntityRequestOffsets",
        "sOptionalArgumentsOffsets",
        "iItemPortModificationApiAttachRequestOffsets",
        "iItemPortModificationApiDetachRequestOffsets",
        "iItemPortModificationApiModifyItemPortRequestOffsets",
        "sPlayerInventoryQueryOffsets",
        "sInventoryContainerEntryOffsets",
        "sInventoryContainerGridItemOffsets",
        "sGridItemRequestOffsets",
        "sInventoryContainerManagerDataOffsets",
        "sInventoryDataRequestOffsets",
        "sInventoryContainerFilterCacheKeyOffsets",
        "sInventoryContainerManagerEntriesCacheOffsets",
        "sInventoryContainerManagerDataCacheOffsets",
        "sInventoryContainerManagerDataCachePairOffsets",
        "cInventoryQueryPendingRequestOffsets",
        "cInventoryOpenPendingRequestOffsets",
        "cInventoryContainerManagerAsyncQueryInventoryDataSQueryEntryOffsets",
        "cInventoryContainerManagerAsyncStowEntitySAsyncStowSharedDataOffsets",
        "cInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfoOffsets",
        "sPersonalInventoryReceivedDataOffsets",
        "sPersonalInventoryDataOffsets",
        "personalThoughtInventoryMoveOffsets",
        "personalThoughtInventoryMoveLocalAttachDataOffsets"
    ];
    const missingSizes = requiredSizes.filter(name => sizes[name] === undefined);
    const missingOffsets = requiredOffsets.filter(name => InventoryManagementSurface[name] === undefined);
    const catalogs = InventoryManagementSurface.headerFunctionCatalogs;

    return {
        source: InventoryManagementSurface.source,
        missingSizes,
        missingOffsets,
        vtableSlots: {
            IInventoryContainerManager: Object.keys(InventoryManagementSurface.iInventoryContainerManagerVtable).length,
            CInventoryContainerComponent: Object.keys(InventoryManagementSurface.cInventoryContainerComponentVtable).length,
            IInventoryApi: Object.keys(InventoryManagementSurface.iInventoryApiVtable).length,
            IInventoryManagementApi: Object.keys(InventoryManagementSurface.iInventoryManagementApiVtable).length,
            IItemPortModificationApi: Object.keys(InventoryManagementSurface.iItemPortModificationApiVtable).length,
            IPlayerInventoryManager: Object.keys(InventoryManagementSurface.iPlayerInventoryManagerVtable).length,
            IPlatformInventoryManager: Object.keys(InventoryManagementSurface.iPlatformInventoryManagerVtable).length,
            ISCActorInventory: Object.keys(InventoryManagementSurface.iscActorInventoryVtable).length
        },
        headerFunctionCatalogCounts: {
            CSCPlayerInventory: catalogs.CSCPlayerInventory.length,
            CInventoryContainerManager: catalogs.CInventoryContainerManager.length,
            CSCLocalPlayerPersonalThoughtComponent: catalogs.CSCLocalPlayerPersonalThoughtComponent.length
        },
        eventSchemaCount: Object.keys(InventoryEventSchemas).length,
        decoderCount: inventoryDecoderSurface().decoders.length,
        requestPathCovered: !!InventoryManagementSurface.inventoryRequestPath,
        readOnlyInventorySurface: true,
        notes: [
            "This audit checks the script manifest for the major player inventory/container-management surfaces.",
            "It does not prove every unrelated Inventory* type in types.h is decoded."
        ]
    };
}

function listInventoryContainers(includeGridItems = false, limit = 64) {
    const out = [];
    for (const entity of entities()) {
        if (out.length >= limit) break;

        const component = entity.inventoryContainerComponent;
        if (!component) continue;

        out.push({
            entityId: String(entity.id),
            entityName: entity.name,
            className: entity.entityClass?.name ?? null,
            component: component.toObject(includeGridItems)
        });
    }

    return out;
}

function inventoryContainerComponentForEntity(entityId) {
    const entity = gEnv.entitySystem?.getEntity(entityId);
    if (!entity) throw new Error(`entity ${entityId} is unavailable`);
    const component = entity.inventoryContainerComponent;
    if (!component) throw new Error(`entity ${entityId} has no CInventoryContainerComponent`);
    return { entity, component };
}

function requireInventoryContainerManager() {
    const manager = gEnv.game?.inventoryContainerManager ?? null;
    if (!manager) throw new Error("CInventoryContainerManager unavailable");
    return manager;
}

function allocSInventoryId(holderEntityId, context = 0, subject = "0") {
    const buf = Memory.alloc(InventoryManagementSurface.sizes.SInventoryId);
    buf.writeByteArray(new Uint8Array(InventoryManagementSurface.sizes.SInventoryId));
    buf.writeU64(uint64(String(holderEntityId)));
    buf.add(0x08).writeS32(context | 0);
    buf.add(0x10).writeU64(uint64(String(subject)));
    return buf;
}

function buildInventoryId(holderEntityId, context = 0, subject = "0") {
    const buf = allocSInventoryId(holderEntityId, context, subject);
    return {
        ptr: buf.toString(),
        wrapper: new SInventoryId(buf),
        ...new SInventoryId(buf).toObject()
    };
}

function getEntireInventoryQuery(entityId, context = 0, subject = "0") {
    const manager = requireInventoryContainerManager();
    const idBuf = allocSInventoryId(entityId, context, subject);
    const query = manager.getEntireInventoryQuery(idBuf);
    return {
        inventoryId: new SInventoryId(idBuf).toObject(),
        query: query.toObject()
    };
}

function inventoryContainerIsUserStowValid(userEntityId, targetHolderEntityId, targetContext = 0, targetSubject = "0", entityIEntityPtr = "0") {
    const manager = requireInventoryContainerManager();
    const idBuf = allocSInventoryId(targetHolderEntityId, targetContext, targetSubject);
    return {
        userEntityId: String(userEntityId),
        targetInventoryId: new SInventoryId(idBuf).toObject(),
        entityIEntityPtr: String(entityIEntityPtr),
        valid: manager.isUserStowValid(userEntityId, idBuf, entityIEntityPtr)
    };
}

function inventoryContainerIsItemTypePermissible(containerDefPtr, itemDefinitionPtr) {
    const manager = requireInventoryContainerManager();
    return {
        containerDefPtr: ptr(containerDefPtr).toString(),
        itemDefinitionPtr: ptr(itemDefinitionPtr).toString(),
        permissible: manager.isItemTypePermissibleInInventory(containerDefPtr, itemDefinitionPtr)
    };
}

function inventoryContainerOccupantProperties() {
    const manager = requireInventoryContainerManager();
    return {
        defaultOpenInventoryOccupantProperties: manager.getDefaultOpenInventoryOccupantProperties(),
        itemTypeOpenInventoryOccupantProperties: manager.getItemTypeOpenInventoryOccupantProperties(),
        blockedClosedInventoryItems: manager.getBlockedClosedInventoryItems()
    };
}

function inventoryContainerSnapshot(entityId, options = {}) {
    const includeGridItems = options.includeGridItems !== false;
    const includeFreeSpaces = options.includeFreeSpaces === true;
    const includeLootRequests = options.includeLootRequests === true;
    const gridItemLimit = options.gridItemLimit ?? 256;
    const { entity, component } = inventoryContainerComponentForEntity(entityId);

    const snapshotVar = component.snapshotInventoryGridItems;
    const gridItemsVec = snapshotVar.value;
    const gridItems = includeGridItems
        ? gridItemsVec.toArray(gridItemLimit).map(item => item.toObject())
        : null;
    const gridItemSummary = gridItemsVec.toSummary();

    const occupancyVar = component.containerOccupancy;
    const freeSpacesVar = component.containerFreeSpaces;
    const lootVar = component.spawnedPopulateLoot;

    return {
        entityId: String(entity.id),
        entityName: entity.name,
        entityClass: entity.entityClass?.name ?? null,
        componentPtr: component.ptr.toString(),
        inventoryUser: component.inventoryUser.toObject(),
        previousInventoryUser: component.previousInventoryUser,
        hasInitialized: component.hasInitialized.toObject(),
        inventoryCreated: component.inventoryCreated.toObject(),
        containerOpen: component.containerOpen.toObject(),
        occupancy: occupancyVar.toObject(),
        snapshotGridItemSummary: gridItemSummary,
        snapshotGridItems: gridItems,
        freeSpaces: includeFreeSpaces
            ? freeSpacesVar.value.toArray(64).map(space => space.toObject())
            : freeSpacesVar.toObject(),
        spawnedPopulateLoot: includeLootRequests
            ? lootVar.value.toArray(64).map(req => req.toObject())
            : lootVar.toObject(),
        cargoGridLocks: component.cargoGridLocks.toObject(false),
        eventListenerCount: component.eventListeners.listeners.count
    };
}

function inventoryContainerEntireQuery(entityId, context = 0) {
    const { entity, component } = inventoryContainerComponentForEntity(entityId);
    const result = getEntireInventoryQuery(entity.id, context, "0");
    return {
        entityId: String(entity.id),
        entityName: entity.name,
        entityClass: entity.entityClass?.name ?? null,
        componentPtr: component.ptr.toString(),
        ...result
    };
}

function listInventoryContainerContents(options = {}) {
    const limit = options.limit ?? 64;
    const includeGridItems = options.includeGridItems !== false;
    const includeEntireQuery = options.includeEntireQuery === true;
    const includeFreeSpaces = options.includeFreeSpaces === true;
    const queryContext = options.queryContext ?? 0;
    const gridItemLimit = options.gridItemLimit ?? 64;
    const manager = options.includeEntireQuery ? requireInventoryContainerManager() : null;

    const out = [];
    for (const entity of entities()) {
        if (out.length >= limit) break;

        const component = entity.inventoryContainerComponent;
        if (!component) continue;

        const gridVec = component.snapshotInventoryGridItems.value;
        const entry = {
            entityId: String(entity.id),
            entityName: entity.name,
            className: entity.entityClass?.name ?? null,
            componentPtr: component.ptr.toString(),
            occupancy: component.containerOccupancy.toObject(),
            hasInitialized: component.hasInitialized.value,
            inventoryCreated: component.inventoryCreated.value,
            containerOpen: component.containerOpen.value,
            snapshotGridItemCount: gridVec.count,
            snapshotGridItems: includeGridItems
                ? gridVec.toArray(gridItemLimit).map(item => item.toObject())
                : null,
            freeSpaces: includeFreeSpaces
                ? component.containerFreeSpaces.value.toArray(64).map(s => s.toObject())
                : null
        };

        if (includeEntireQuery && manager) {
            try {
                const idBuf = allocSInventoryId(entity.id, queryContext, "0");
                const query = manager.getEntireInventoryQuery(idBuf);
                entry.entireInventoryQuery = {
                    inventoryId: new SInventoryId(idBuf).toObject(),
                    query: query.toObject()
                };
            } catch (e) {
                entry.entireInventoryQueryError = e.message;
            }
        }

        out.push(entry);
    }

    return out;
}

function inventoryContainerByEntityId(entityId, options = {}) {
    const includeGridItems = options.includeGridItems !== false;
    const includeEntireQuery = options.includeEntireQuery !== false;
    const queryContext = options.queryContext ?? 0;
    const gridItemLimit = options.gridItemLimit ?? 256;
    const { entity, component } = inventoryContainerComponentForEntity(entityId);

    const snapshot = inventoryContainerSnapshot(entity.id, {
        includeGridItems,
        gridItemLimit,
        includeFreeSpaces: options.includeFreeSpaces === true,
        includeLootRequests: options.includeLootRequests === true
    });

    if (includeEntireQuery) {
        try {
            const manager = requireInventoryContainerManager();
            const idBuf = allocSInventoryId(entity.id, queryContext, "0");
            const query = manager.getEntireInventoryQuery(idBuf);
            snapshot.entireInventoryQuery = {
                inventoryId: new SInventoryId(idBuf).toObject(),
                query: query.toObject()
            };
        } catch (e) {
            snapshot.entireInventoryQueryError = e.message;
        }
    }

    snapshot.componentDetail = component.toObject(includeGridItems);
    return snapshot;
}

function cancelInventoryCallback(requestId) {
    const manager = requireInventoryContainerManager();
    return manager.cancelCallback(requestId);
}

const InventoryQueryLambdaRVAs = Object.freeze({
    asyncQueryInventoryData_l2_lambda1:  ptr("0x144458D70").sub(ptr("0x140000000")),
    asyncQueryInventoryData_l15_lambda1: ptr("0x14446D7B0").sub(ptr("0x140000000")),
    asyncQueryInventory_l2_lambda2:      ptr("0x144472990").sub(ptr("0x140000000")),
    asyncQueryInventoryData_l29_lambda2: ptr("0x1444760C0").sub(ptr("0x140000000")),
    asyncQueryInventoryData_l34_lambda3: ptr("0x14447CBC0").sub(ptr("0x140000000")),
    apiAsyncQueryInventory_l2_lambda1:               ptr("0x140FB4D00").sub(ptr("0x140000000")),
    apiAsyncQueryInventoryAutoPagination_l2_lambda1: ptr("0x140FB58F0").sub(ptr("0x140000000")),
    playerMgrGetPersonalEntityInventoryId_l2_lambda3:        ptr("0x143A6C810").sub(ptr("0x140000000")),
    playerInvRequestOrCreatePersonalInventoryData_l2_lambda1: ptr("0x14445F410").sub(ptr("0x140000000")),
    playerInvRequestPersonalInventoryData_l2_lambda1:         ptr("0x14445F840").sub(ptr("0x140000000")),
    playerInvAsyncRequestAccessToInventory_l16_lambda1:       ptr("0x14446B530").sub(ptr("0x140000000")),
    playerInvAsyncRequestAccessToInventory_l30_lambda2:       ptr("0x144476340").sub(ptr("0x140000000")),
    playerInvProcessRequest:                                  ptr("0x1445B56A0").sub(ptr("0x140000000")),
    playerInvProcessRequestStoredItemInventory:               ptr("0x1445B5FF0").sub(ptr("0x140000000"))
});

let inventoryQueryHookState = null;

function installInventoryQueryHooks(options = {}) {
    if (inventoryQueryHookState?.listeners?.length) {
        uninstallInventoryQueryHooks();
    }

    const verbose = options.verbose !== false;
    const sampleLimit = options.sampleLimit ?? 64;
    const captureEntities = options.captureEntities !== false;
    const entityCap = options.entityCap ?? 64;

    const state = {
        installed: true,
        sampleLimit,
        verbose,
        captureEntities,
        entityCap,
        fired: 0,
        samples: [],
        byLambda: {}
    };
    const listeners = [];

    const decodeQueryResult = (queryResultPtr) => {
        try {
            const qr = new SInventoryQueryResult(queryResultPtr);
            const inv = qr.inventory;
            const roots = captureEntities
                ? inv.inventoryStowedAggregateRoots.toArray(entityCap).map(p => {
                    try { return lower48(p.readPointer()).toString(); } catch (_) { return null; }
                })
                : inv.inventoryStowedAggregateRoots.toSummary();
            return {
                entityGraph: qr.entityGraphResultEntities,
                inventory: {
                    inventoryStowedAggregateRoots: roots,
                    totalOccupancy: inv.totalOccupancy
                }
            };
        } catch (e) {
            return { error: e.message };
        }
    };

    const decodeInventoryIdAt = (lambdaThisPtr, off) => {
        try {
            return new SInventoryId(lambdaThisPtr.add(off)).toObject();
        } catch (e) {
            return { error: e.message };
        }
    };

    const push = (label, snapshot) => {
        state.fired++;
        state.byLambda[label] = (state.byLambda[label] ?? 0) + 1;
        if (state.samples.length < sampleLimit) state.samples.push(snapshot);
        if (verbose) {
            console.log(`[invq] ${label} #${state.fired} ${JSON.stringify(snapshot)}`);
        }
    };

    const dataLambdaHandler = (label, inventoryIdOffset) => ({
        onEnter(args) {
            const lambdaThis = args[0];
            const result = args[1];
            const pageInfo = args[2];
            const queryResult = args[3];
            const a4 = args[4];
            const snapshot = {
                label,
                ts: Date.now(),
                lambdaThis: lambdaThis.toString(),
                inventoryId: decodeInventoryIdAt(lambdaThis, inventoryIdOffset),
                resultRaw: result.toString(),
                pageInfo: pageInfo.toString(),
                queryResult: queryResult.toString(),
                a4: a4.toString(),
                decoded: decodeQueryResult(queryResult)
            };
            push(label, snapshot);
        }
    });

    const queryInventoryLambdaHandler = (label) => ({
        onEnter(args) {
            const lambdaThis = args[0];
            const result = args[1];
            const a2 = args[2];
            let requestId = null;
            try { requestId = lambdaThis.add(0x08).readU64().toString(); } catch (_) {}
            const snapshot = {
                label,
                ts: Date.now(),
                lambdaThis: lambdaThis.toString(),
                requestId,
                result: result.toString(),
                a2: a2.toString(),
                resultTypeByte: (() => { try { return a2.readU8(); } catch (_) { return null; } })()
            };
            push(label, snapshot);
        }
    });

    const minimalLambdaHandler = (label) => ({
        onEnter(args) {
            const snapshot = {
                label,
                ts: Date.now(),
                lambdaThis: args[0].toString(),
                arg1: args[1].toString(),
                arg2: args[2].toString(),
                arg3: args[3].toString()
            };
            // try to read a SInventoryId at +0x08 or +0x10 — best-effort
            try { snapshot.inventoryIdAt08 = new SInventoryId(args[0].add(0x08)).toObject(); } catch (_) {}
            try { snapshot.inventoryIdAt10 = new SInventoryId(args[0].add(0x10)).toObject(); } catch (_) {}
            push(label, snapshot);
        }
    });

    const inventoryRequestHandler = (label) => ({
        onEnter(args) {
            const reqPtr = args[1];
            const snapshot = {
                label,
                ts: Date.now(),
                thisPtr: args[0].toString(),
                requestPtr: reqPtr.toString()
            };
            try {
                const req = new SInventoryManagementRequest(reqPtr);
                snapshot.request = {
                    requestMoveId: req.requestMoveId,
                    type: req.type,
                    typeName: req.typeName,
                    userId: req.userId,
                    sourceInventoryId: req.sourceInventoryId.toObject(),
                    targetInventoryId: req.targetInventoryId.toObject()
                };
            } catch (e) {
                snapshot.requestDecodeError = e.message;
            }
            push(label, snapshot);
        }
    });

    // NOTE: do NOT hook CInventoryApi::AsyncQueryInventory::__l2::<lambda_1> (0x140FB4D00)
    // or its AutoPagination sibling (0x140FB58F0). They run on the main-thread gRPC dispatch
    // path every frame and use AVX-256 SIMD heavily; Frida's Interceptor trampoline doesn't
    // reliably preserve YMM state across the JS callback and the game will crash inside the
    // lambda (observed: SIGSEGV inside `_mm256_storeu_ps`).
    const attachments = [
        ["asyncQueryInventoryData_l2_lambda1",  "AsyncQueryInventoryData::__l2::<lambda_1>",  dataLambdaHandler("AsyncQueryInventoryData::__l2::<lambda_1>", 0x08)],
        ["asyncQueryInventoryData_l15_lambda1", "AsyncQueryInventoryData::__l15::<lambda_1>", dataLambdaHandler("AsyncQueryInventoryData::__l15::<lambda_1>", 0x10)],
        ["asyncQueryInventoryData_l29_lambda2", "AsyncQueryInventoryData::__l29::<lambda_2>", dataLambdaHandler("AsyncQueryInventoryData::__l29::<lambda_2>", 0x08)],
        ["asyncQueryInventoryData_l34_lambda3", "AsyncQueryInventoryData::__l34::<lambda_3>", dataLambdaHandler("AsyncQueryInventoryData::__l34::<lambda_3>", 0x08)],
        ["asyncQueryInventory_l2_lambda2",      "AsyncQueryInventory::__l2::<lambda_2>",      queryInventoryLambdaHandler("AsyncQueryInventory::__l2::<lambda_2>")],
        ["playerMgrGetPersonalEntityInventoryId_l2_lambda3",         "CPlayerInventoryManager::AsyncGetPersonalEntityInventoryId::__l2::<lambda_3>",  minimalLambdaHandler("CPlayerInventoryManager::AsyncGetPersonalEntityInventoryId::__l2::<lambda_3>")],
        ["playerInvRequestOrCreatePersonalInventoryData_l2_lambda1", "CSCPlayerInventory::RequestOrCreatePersonalInventoryData::__l2::<lambda_1>",   minimalLambdaHandler("CSCPlayerInventory::RequestOrCreatePersonalInventoryData::__l2::<lambda_1>")],
        ["playerInvRequestPersonalInventoryData_l2_lambda1",         "CSCPlayerInventory::RequestPersonalInventoryData::__l2::<lambda_1>",          minimalLambdaHandler("CSCPlayerInventory::RequestPersonalInventoryData::__l2::<lambda_1>")],
        ["playerInvAsyncRequestAccessToInventory_l16_lambda1",       "CSCPlayerInventory::AsyncRequestAccessToInventory::__l16::<lambda_1>",        minimalLambdaHandler("CSCPlayerInventory::AsyncRequestAccessToInventory::__l16::<lambda_1>")],
        ["playerInvAsyncRequestAccessToInventory_l30_lambda2",       "CSCPlayerInventory::AsyncRequestAccessToInventory::__l30::<lambda_2>",        minimalLambdaHandler("CSCPlayerInventory::AsyncRequestAccessToInventory::__l30::<lambda_2>")],
        ["playerInvProcessRequest",                    "CSCPlayerInventory::ProcessRequest",                    inventoryRequestHandler("CSCPlayerInventory::ProcessRequest")],
        ["playerInvProcessRequestStoredItemInventory", "CSCPlayerInventory::ProcessRequestStoredItemInventory", inventoryRequestHandler("CSCPlayerInventory::ProcessRequestStoredItemInventory")]
    ];

    const attached = [];
    for (const [key, label, handler] of attachments) {
        const target = MODULE_BASE.add(InventoryQueryLambdaRVAs[key]);
        try {
            const listener = Interceptor.attach(target, handler);
            listeners.push(listener);
            attached.push({ key, label, target: target.toString() });
            state.byLambda[label] = 0;
        } catch (e) {
            attached.push({ key, label, target: target.toString(), error: e.message });
        }
    }

    state.attached = attached;
    inventoryQueryHookState = { listeners, state };
    if (verbose) console.log(`[invq] hooks installed: ${attached.length}`);
    return { installed: true, attached, ...state };
}

function uninstallInventoryQueryHooks() {
    if (!inventoryQueryHookState?.listeners?.length) return { installed: false };
    for (const l of inventoryQueryHookState.listeners) {
        try { l.detach(); } catch (_) {}
    }
    const previous = inventoryQueryHookState.state;
    inventoryQueryHookState = null;
    return { installed: false, previous };
}

function inventoryQueryHookState_() {
    return inventoryQueryHookState?.state ?? { installed: false };
}

function inventoryQueryHookSamples(clear = false) {
    const s = inventoryQueryHookState?.state;
    if (!s) return { installed: false };
    const samples = s.samples.slice();
    if (clear) s.samples = [];
    return { installed: true, fired: s.fired, byLambda: s.byLambda, samples };
}

function auditInventoryManagement(options = {}) {
    const includeEntityScan = options.includeEntityScan === true;
    const includePlayerInventoryDetails = options.includePlayerInventoryDetails !== false;
    const includePersonalThoughtDetails = options.includePersonalThoughtDetails !== false;
    const includeManagerDetails = options.includeManagerDetails !== false;
    const services = gEnv.cigServices;
    const inventoryApi = resolveInventoryApi();
    const inventoryManagementApi = inventoryApi?.inventoryManagementApi ?? null;
    const containerManager = gEnv.game?.inventoryContainerManager ?? null;
    const playerComponent = scPlayer();
    const playerEntity = player();
    const personalThought = playerEntity?.personalThoughtComponent ?? null;

    return {
        cigServices: services?.ptr.toString() ?? null,
        inventoryApi: inventoryApi?.surface() ?? null,
        inventoryManagementApi: inventoryManagementApi?.surface() ?? null,
        inventoryContainerManager: containerManager
            ? (includeManagerDetails ? containerManager.toObject() : containerManager.surface())
            : null,
        playerInventory: playerComponent
            ? (includePlayerInventoryDetails ? playerComponent.playerInventory.toObject() : { ptr: playerComponent.playerInventory.ptr.toString() })
            : null,
        personalThought: personalThought
            ? (includePersonalThoughtDetails ? personalThought.toObject(false) : personalThought.surface())
            : null,
        playerEntity: includeEntityScan && playerEntity ? {
            ptr: playerEntity.ptr.toString(),
            id: String(playerEntity.id),
            name: playerEntity.name,
            hasInventoryContainerComponent: playerEntity.inventoryContainerComponent !== null,
            hasPersonalThoughtComponent: personalThought !== null
        } : null,
        inventoryContainerEntityCount: includeEntityScan ? listInventoryContainers(false, options.entityScanLimit ?? 64).length : null,
        surface: inventoryManagementSurface()
    };
}

function playerInventorySurface() {
    const playerComponent = scPlayer();
    if (!playerComponent) return null;
    return playerComponent.playerInventory.surface();
}

function playerInventoryState(includeDetails = true) {
    const playerComponent = scPlayer();
    if (!playerComponent) return null;
    return includeDetails ? playerComponent.playerInventory.toObject() : playerComponent.playerInventory.surface();
}

function playerInventoryOperations(limit = 8, includeNested = false) {
    const playerComponent = scPlayer();
    if (!playerComponent) return null;
    return playerComponent.playerInventory.operationSurface(limit, includeNested);
}

function findPersonalThoughtComponents(limit = 512) {
    const out = [];
    const names = ["CSCLocalPlayerPersonalThoughtComponent", "LocalPlayerPersonalThoughtComponent", "PersonalThoughtComponent"];
    for (const entity of entities()) {
        if (out.length >= limit) break;
        for (const name of names) {
            const componentPtr = entity.getComponentByName(name);
            if (!componentPtr) continue;
            out.push({
                entity,
                component: new CSCLocalPlayerPersonalThoughtComponent(componentPtr),
                componentName: name
            });
            break;
        }
    }
    return out;
}

function playerPersonalThoughtComponent(scanFallback = true) {
    const direct = player()?.personalThoughtComponent ?? null;
    if (direct || !scanFallback) return direct;

    const currentPlayer = player();
    const playerId = currentPlayer ? String(currentPlayer.id) : null;
    const matches = findPersonalThoughtComponents(512);
    if (matches.length === 0) return null;

    const playerMatch = playerId ? matches.find(match => String(match.entity.id) === playerId) : null;
    return (playerMatch ?? matches[0]).component;
}

function playerPersonalThoughtState(includeNested = false, scanFallback = true) {
    const component = playerPersonalThoughtComponent(scanFallback);
    if (!component) return null;
    return component.toObject(includeNested);
}

function inventoryManagementQueueState(limit = 0, includeNested = false) {
    const playerComponent = scPlayer();
    if (!playerComponent) return null;

    const inventory = playerComponent.playerInventory;
    const queue = inventory.inventoryManagementQueue;
    const out = {
        playerInventory: inventory.ptr.toString(),
        queue: queue.toSummary()
    };

    if (limit > 0) {
        try {
            out.entries = inventory.inventoryManagementQueueEntries(limit, includeNested);
        } catch (e) {
            out.entriesError = e.message;
        }
    }

    return out;
}

function inventoryPathState(limit = 8, includeNested = false) {
    const playerComponent = scPlayer();
    const personalThought = playerPersonalThoughtComponent(true);
    const containerManager = gEnv.game?.inventoryContainerManager ?? null;

    return {
        path: InventoryManagementSurface.inventoryRequestPath,
        ui: personalThought ? personalThought.operationSurface() : null,
        backend: playerComponent ? playerComponent.playerInventory.operationSurface(limit, includeNested) : null,
        containerManager: containerManager ? containerManager.toObject() : null
    };
}

function inventoryApiSurface() {
    const api = resolveInventoryApi();
    if (!api) return null;

    let inventoryManagementApi = null;
    let itemPortModificationApi = null;
    try {
        inventoryManagementApi = api.inventoryManagementApi?.surface() ?? null;
    } catch (e) {
        inventoryManagementApi = { error: e.message };
    }
    try {
        itemPortModificationApi = api.itemPortModificationApi?.surface() ?? null;
    } catch (e) {
        itemPortModificationApi = { error: e.message };
    }

    return {
        inventoryApi: api.surface(),
        inventoryManagementApi,
        itemPortModificationApi
    };
}

function inventoryContainerManagerState(includeDetails = true) {
    const manager = gEnv.game?.inventoryContainerManager ?? null;
    if (!manager) return null;
    return includeDetails ? manager.toObject() : manager.surface();
}

function upsertObjectiveSurface() {
    return {
        ...MissionServiceInternalSurface,
        notes: [
            "CryStringT<char> is a pointer-sized CryString handle in this build, not the 0x20 MSVC std::string-shaped layout from the report.",
            "SMissionObjective and SUpsertObjectiveRequest sizes are taken from types.h for this target build.",
            "Upsert localization helpers build a single shallow request from an existing active objective and override short_desc_id/long_desc_id."
        ]
    };
}

function verifyUpsertObjectiveSurface() {
    const contracts = listContracts(true, false);
    const missionLog = playerMissionLog();
    const missions = missionLog ? (missionLog.missionsLocal.count > 0 ? missionLog.missionsLocal : missionLog.missions) : null;
    const entry = missions && missions.count > 0 ? missions.at(0) : null;
    const objective = entry && entry.activeObjectives.count > 0 ? entry.activeObjectives.at(0) : null;

    const sample = entry && objective ? {
        missionIdSource: {
            cmLogEntryOffset: "0x08",
            value: entry.missionId
        },
        liveActiveObjective: {
            objectiveId: objective.id,
            parentObjectiveId: objective.parent,
            counterCurrent: Number(objective.counterValue),
            counterMax: Number(objective.counterMax),
            timerStart: objective.ptr.add(0xC0).readS64().toString(),
            uiDisplayPriority: objective.uiDisplayPriority,
            uiDisplayTextId: objective.uiDisplayTextId,
            flags: objective.flags,
            uiExtendedTextItemIndex: objective.ptr.add(0x3C).readU32(),
            markerCount: objective.markerIds.count,
            markerPlayerCount: objective.markerPlayerIds.count
        },
        expectedWireOffsets: {
            objectiveId: "SMissionObjective + 0x00",
            parentObjectiveId: "SMissionObjective + 0x08",
            missionId: "SMissionObjective + 0x10",
            timerStart: "SMissionObjective + 0x20",
            state: "SMissionObjective + 0x30",
            markerIds: "SMissionObjective + 0x40",
            progressCounterCurrent: "SMissionObjective + 0x58",
            progressCounterMax: "SMissionObjective + 0x60",
            flags: "SMissionObjective + 0x6C",
            uiDisplayPriority: "SMissionObjective + 0x70",
            uiDisplayTextId: "SMissionObjective + 0x74",
            contributors: "SMissionObjective + 0x78",
            ignoreObjectiveContributors: "SMissionObjective + 0x90",
            uiExtendedTextItemIndex: "SMissionObjective + 0x94",
            autoCompletePolicy: "SMissionObjective + 0x98"
        }
    } : null;

    return {
        profileGameMissions: EProfiledSubsystem.PROFILE_GAME_MISSIONS,
        missionObjectiveStates: EMissionObjectiveStates,
        upsertObjectiveSlot: MissionServiceInternalSurface.imissionServiceInternalVtable.upsertObjective,
        confirmedSizes: MissionServiceInternalSurface.sizes,
        reportCorrections: {
            cryStringTCharSize: "0x08, not 0x20",
            smissionObjectiveSize: "0xA0, not 0xC0",
            sUpsertObjectiveRequestSize: "0xA8, not 0xD0",
            profileGameMissions: "0x52, not 0",
            upsertObjectiveVtableSlot: "6, offset 0x30"
        },
        activeContractCount: contracts.length,
        sample
    };
}

function parseU32(value, name) {
    const n = typeof value === "string" && /^0x/i.test(value) ? parseInt(value, 16) : Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 0xFFFFFFFF) {
        throw new Error(`${name} must be a uint32`);
    }
    return n >>> 0;
}

function parseS32(value, name) {
    const n = Number(value);
    if (!Number.isInteger(n) || n < -0x80000000 || n > 0x7FFFFFFF) {
        throw new Error(`${name} must be an int32`);
    }
    return n | 0;
}

function parseS64(value, name) {
    const n = typeof value === "bigint" ? value : BigInt(value);
    if (n < -0x8000000000000000n || n > 0x7FFFFFFFFFFFFFFFn) {
        throw new Error(`${name} must be an int64`);
    }
    return n;
}

function parseBool(value, name) {
    if (typeof value === "boolean") return value;
    if (value === 0 || value === 1) return value !== 0;
    throw new Error(`${name} must be a boolean`);
}

function parseFiniteFloat(value, name) {
    const n = Number(value);
    if (!Number.isFinite(n)) {
        throw new Error(`${name} must be a finite float`);
    }
    return n;
}

function findActiveMissionObjective(missionId = null, objectiveId = null) {
    const missionLog = playerMissionLog();
    if (!missionLog) throw new Error("player mission log is unavailable");

    const stores = [missionLog.missionsLocal, missionLog.missions];
    const missionNeedle = missionId ? String(missionId).toLowerCase() : null;
    const objectiveNeedle = objectiveId ? String(objectiveId) : null;

    for (const missions of stores) {
        for (let i = 0; i < missions.count; i++) {
            const entry = missions.at(i);
            if (missionNeedle && entry.missionId.toLowerCase() !== missionNeedle) continue;

            for (let j = 0; j < entry.activeObjectives.count; j++) {
                const objective = entry.activeObjectives.at(j);
                if (objectiveNeedle && objective.id !== objectiveNeedle) continue;
                return { entry, objective, missionIndex: i, objectiveIndex: j };
            }
        }
    }

    throw new Error(`active objective not found: missionId=${missionId ?? "*"} objectiveId=${objectiveId ?? "*"}`);
}

function writeVectorHeader(destination, vector) {
    const out = ptr(destination);
    out.writePointer(vector.begin);
    out.add(0x08).writePointer(vector.end);
    out.add(0x10).writePointer(vector.capacityEnd);
}

const UpsertObjectiveFieldWriters = Object.freeze({
    timerStart: { offset: 0x20, type: "s64" },
    expiry: { offset: 0x28, type: "s64" },
    state: { offset: 0x30, type: "s32" },
    shortDescId: { offset: 0x34, type: "u32" },
    longDescId: { offset: 0x38, type: "u32" },
    progressCounterCurrent: { offset: 0x58, type: "s64" },
    progressCounterMax: { offset: 0x60, type: "s64" },
    reward: { offset: 0x68, type: "u32" },
    flags: { offset: 0x6C, type: "u32" },
    uiDisplayPriority: { offset: 0x70, type: "s32" },
    uiDisplayTextId: { offset: 0x74, type: "u32" },
    ignoreObjectiveContributors: { offset: 0x90, type: "bool" },
    uiExtendedTextItemIndex: { offset: 0x94, type: "u32" },
    autoCompletePolicy: { offset: 0x98, type: "s32" }
});

function normalizeObjectiveUpsertFields(args = {}) {
    const fields = { ...(args.fields ?? args.overrides ?? {}) };
    for (const name of Object.keys(UpsertObjectiveFieldWriters)) {
        if (Object.prototype.hasOwnProperty.call(args, name)) fields[name] = args[name];
    }

    const unknown = Object.keys(fields).filter(name => !Object.prototype.hasOwnProperty.call(UpsertObjectiveFieldWriters, name));
    if (unknown.length > 0) {
        throw new Error(`unsupported objective upsert field(s): ${unknown.join(", ")}`);
    }

    return fields;
}

function writeObjectiveField(destination, name, value) {
    const spec = UpsertObjectiveFieldWriters[name];
    const field = ptr(destination).add(spec.offset);

    if (spec.type === "u32") field.writeU32(parseU32(value, name));
    else if (spec.type === "s32") field.writeS32(parseS32(value, name));
    else if (spec.type === "s64") field.writeS64(parseS64(value, name));
    else if (spec.type === "bool") field.writeU8(parseBool(value, name) ? 1 : 0);
    else throw new Error(`unsupported objective field type: ${spec.type}`);
}

function writeSMissionObjectiveFromActive(destination, entry, objective, fields = {}) {
    const out = ptr(destination);
    zeroMemory(out, MissionServiceInternalSurface.sizes.SMissionObjective);

    out.add(0x00).writePointer(objective.ptr.add(0x08).readPointer());
    out.add(0x08).writePointer(objective.ptr.add(0x10).readPointer());
    Memory.copy(out.add(0x10), entry.ptr.add(0x08), 0x10);
    out.add(0x20).writeS64(objective.ptr.add(0xC0).readS64());
    out.add(0x28).writeS64(0);
    out.add(0x30).writeS32(EMissionObjectiveStates.MISSION_OBJECTIVE_STATE_INPROGRESS);
    out.add(0x34).writeU32(objective.shortDescId);
    out.add(0x38).writeU32(objective.longDescId);
    writeVectorHeader(out.add(0x40), objective.markerIds);
    out.add(0x58).writeS64(objective.counterValue);
    out.add(0x60).writeS64(objective.counterMax);
    out.add(0x68).writeU32(objective.reward);
    out.add(0x6C).writeU32(objective.flags);
    out.add(0x70).writeS32(objective.uiDisplayPriority);
    out.add(0x74).writeU32(objective.uiDisplayTextId);
    out.add(0x90).writeU8(0);
    out.add(0x94).writeU32(objective.ptr.add(0x3C).readU32());
    out.add(0x98).writeS32(0);

    for (const [name, value] of Object.entries(fields)) {
        writeObjectiveField(out, name, value);
    }
}

function buildUpsertObjectiveRequest(entry, objective, fields = {}, completed = false) {
    const request = Memory.alloc(MissionServiceInternalSurface.sizes.SUpsertObjectiveRequest);
    zeroMemory(request, MissionServiceInternalSurface.sizes.SUpsertObjectiveRequest);
    writeSMissionObjectiveFromActive(request, entry, objective, fields);
    request.add(0xA0).writeU8(parseBool(completed, "completed") ? 1 : 0);

    const requests = Memory.alloc(MissionServiceInternalSurface.sizes.EastlVector);
    zeroMemory(requests, MissionServiceInternalSurface.sizes.EastlVector);
    requests.writePointer(request);
    requests.add(0x08).writePointer(request.add(MissionServiceInternalSurface.sizes.SUpsertObjectiveRequest));
    requests.add(0x10).writePointer(request.add(MissionServiceInternalSurface.sizes.SUpsertObjectiveRequest));

    const activeMissionKey = Memory.alloc(MissionServiceInternalSurface.sizes.CryGUID);
    zeroMemory(activeMissionKey, MissionServiceInternalSurface.sizes.CryGUID);

    const result = Memory.alloc(MissionServiceInternalSurface.sizes.CFuture_CigOptionalErrorResult_CigError);
    zeroMemory(result, MissionServiceInternalSurface.sizes.CFuture_CigOptionalErrorResult_CigError);

    return { request, requests, activeMissionKey, result };
}

function previewUpsertObjective(args = {}) {
    const fields = normalizeObjectiveUpsertFields(args);
    const found = findActiveMissionObjective(args.missionId ?? null, args.objectiveId ?? null);
    const allocation = buildUpsertObjectiveRequest(found.entry, found.objective, fields, args.completed ?? false);
    const wireObjective = new SMissionObjective(allocation.request);

    return {
        missionId: found.entry.missionId,
        objectiveId: found.objective.id,
        missionIndex: found.missionIndex,
        objectiveIndex: found.objectiveIndex,
        liveBefore: {
            shortDescId: found.objective.shortDescId,
            longDescId: found.objective.longDescId,
            counterValue: Number(found.objective.counterValue),
            counterMax: Number(found.objective.counterMax),
            markerCount: found.objective.markerIds.count,
            uiDisplayPriority: found.objective.uiDisplayPriority,
            uiDisplayTextId: found.objective.uiDisplayTextId,
            uiExtendedTextItemIndex: found.objective.ptr.add(0x3C).readU32(),
            flags: found.objective.flags
        },
        requested: fields,
        completed: parseBool(args.completed ?? false, "completed"),
        wireRequest: new SUpsertObjectiveRequest(allocation.request).toObject(false),
        requestVector: new StdVector(
            allocation.requests,
            MissionServiceInternalSurface.sizes.SUpsertObjectiveRequest,
            SUpsertObjectiveRequest
        ).toSummary(),
        decodedWireObjective: wireObjective.toObject(false)
    };
}

function previewUpsertObjectiveLocalization(args = {}) {
    return previewUpsertObjective(args);
}

function resolveMissionServiceInternal() {
    const services = gEnv.cigServices;
    if (!services) return null;

    const internal = services.internal;
    const fromInternal = internal?.missionServiceInternal ?? null;
    if (fromInternal) return fromInternal;

    const direct = new ICIGServicesInternal(services.ptr).missionServiceInternal;
    return direct ?? null;
}

function upsertObjective(args = {}) {
    const fields = normalizeObjectiveUpsertFields(args);
    const found = findActiveMissionObjective(args.missionId ?? null, args.objectiveId ?? null);
    const service = resolveMissionServiceInternal();
    if (!service) throw new Error("IMissionServiceInternal is unavailable");

    const allocation = buildUpsertObjectiveRequest(found.entry, found.objective, fields, args.completed ?? false);
    const returned = service.upsertObjective(
        allocation.result,
        found.entry.ptr.add(0x08),
        allocation.activeMissionKey,
        allocation.requests,
        EProfiledSubsystem.PROFILE_GAME_MISSIONS
    );

    return {
        missionServiceInternal: service.surface(),
        missionId: found.entry.missionId,
        objectiveId: found.objective.id,
        requested: fields,
        completed: parseBool(args.completed ?? false, "completed"),
        resultPtr: allocation.result.toString(),
        returnedResultPtr: returned.toString(),
        requestPtr: allocation.request.toString(),
        requestVectorPtr: allocation.requests.toString(),
        activeMissionKeyPtr: allocation.activeMissionKey.toString()
    };
}

function upsertObjectiveLocalization(args = {}) {
    return upsertObjective(args);
}

function ent(ptrValue) {
    return new CEntity(ptr(ptrValue));
}

function physent(ptrValue) {
    return new CPhysicalEntity(ptr(ptrValue));
}

function rigent(ptrValue) {
    return new CRigidEntity(ptr(ptrValue));
}

function zone(ptrValue) {
    return new CZone(ptr(ptrValue));
}

function entclass(ptrValue) {
    return new CEntityClass(ptr(ptrValue));
}

function entcomp(ptrValue, componentName = "Unknown") {
    return new EntityComponent(ptr(ptrValue), componentName);
}

function bodyhealth(ptrValue) {
    return new CSCBodyHealthComponent(ptr(ptrValue));
}

function inventoryapi(ptrValue) {
    return new IInventoryApi(ptr(ptrValue));
}

function itemportmodapi(ptrValue) {
    return new IItemPortModificationApi(ptr(ptrValue));
}

function inventorycontainer(ptrValue) {
    return new CInventoryContainerComponent(ptr(ptrValue));
}

function personalthought(ptrValue) {
    return new CSCLocalPlayerPersonalThoughtComponent(ptr(ptrValue));
}

function inventorymanagementrequest(ptrValue) {
    return new SInventoryManagementRequest(ptr(ptrValue));
}

function inventorydatarequest(ptrValue) {
    return new SInventoryDataRequest(ptr(ptrValue));
}

function inventorycontainerdef(ptrValue) {
    return new SInventoryContainerDef(ptr(ptrValue));
}

function inventoryupdateitem(ptrValue) {
    return new SInventoryUpdateItem(ptr(ptrValue));
}

function stowcontext(ptrValue) {
    return new SStowContext(ptr(ptrValue));
}

function stowitemrequestparams(ptrValue) {
    return new SStowItemRequestParams(ptr(ptrValue));
}

function inventoryuiitemport(ptrValue) {
    return new InventoryUIItemPort(ptr(ptrValue));
}

const InventoryEventSchemas = Object.freeze({
    SCEvtControl_OnInventorySelectItemOption: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageSelectedItemIndex", 0x18, "s32"], ["optionIndex", 0x1C, "s32"]] },
    SCEvtControl_OnInventoryChangeTab: { size: 0x08, fields: [["playerSection", 0x00, "bool"], ["tabIndex", 0x04, "s32"]] },
    SCEvtControl_OnInventoryShowOptions: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageSelectedItemIndex", 0x18, "s32"]] },
    SCEvtControl_OnInventoryItemOptionChangeAmount: { size: 0x28, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageSelectedItemIndex", 0x18, "s32"], ["optionIndex", 0x1C, "s32"], ["amount", 0x20, "s32"]] },
    SCEvtControl_OnInventoryCloseContainer: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtControl_OnInventoryEnableCameraInteractions: { size: 0x01, fields: [["enable", 0x00, "bool"]] },
    SCEvtControl_OnInventorySortContainer: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtControl_OnInventoryRequestNewPage: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageDirection", 0x18, "s32"]] },
    SCEvtControl_OnApplyFilterToInventory: { size: 0x50, fields: [["inventoryId", 0x00, "SInventoryId"], ["activeFilter", 0x18, "eastlMap"], ["categoryFilter", 0x48, "bool"], ["clear", 0x49, "bool"]] },
    SCEvtControl_OnInventoryEquippedItemHovered: { size: 0x08, fields: [["entityHovered", 0x00, "componentPtr"]] },
    SCEvtControl_OnInventoryCloseOpenItemMenu: { size: 0x01, fields: [] },
    SCEvtControl_OnInventoryContainerItemHovered: { size: 0x01, fields: [["rollOn", 0x00, "bool"]] },
    SCEvtControl_OnInventoryDropItem: { size: 0x01, fields: [] },
    SCEvtControl_OnInventorySwapOrChangePortOnEquippedItem: { size: 0x18, fields: [["itemPortId", 0x00, "SItemPortId"], ["entityToAttach", 0x10, "componentPtr"]] },
    SCEvtControl_OnInventorySwapPortOnEquippedItem: { size: 0x28, fields: [["itemPortId", 0x00, "SItemPortId"], ["entityToAttach", 0x10, "componentPtr"], ["optionalSwapItemPortId", 0x18, "SItemPortId"]] },
    SCEvtControl_OnInventoryChangePortOnEquippedItem: { size: 0x18, fields: [["itemPortId", 0x00, "SItemPortId"], ["entityToAttach", 0x10, "componentPtr"]] },
    SCEvtControl_OnInventorySetPortsToRefresh: { size: 0x01, fields: [] },
    SCEvtControl_OnInventoryMoveAll: { size: 0x30, fields: [["inventoryId", 0x00, "SInventoryId"], ["moveToInventoryIds", 0x18, "vector:SInventoryId"]] },
    SCEvtControl_OnInventoryStackAll: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtControl_OnInventoryMoveAllRollOver: { size: 0x38, fields: [["inventoryId", 0x00, "SInventoryId"], ["moveToInventoryIds", 0x18, "vector:SInventoryId"], ["rollOn", 0x30, "bool"]] },
    SCEvtControl_OnInventoryQuickMoveItem: { size: 0x38, fields: [["inventoryId", 0x00, "SInventoryId"], ["moveToInventoryIds", 0x18, "vector:SInventoryId"], ["pageSelectedItemIndex", 0x30, "s32"]] },
    SCEvtControl_OnInventoryClickOpenContainer: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["index", 0x18, "s32"]] },
    SCEvtControl_OnDragInventoryItemStart: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["index", 0x18, "s32"]] },
    SCEvtControl_OnDragInventoryItemStop: { size: 0x01, fields: [] },
    SCEvtControl_OnDragInventoryEquipmentItemStart: { size: 0x08, fields: [["dragEntity", 0x00, "ptr"]] },
    SCEvtControl_OnDragInventoryClearHiddenItemPorts: { size: 0x01, fields: [] },
    SCEvtControl_OnInventoryCheckDropItem: { size: 0x01, fields: [["blockItem", 0x00, "bool"]] },
    SCEvtControl_OnDragInventoryItemModifyTarget: { size: 0x38, fields: [["equip", 0x00, "bool"], ["softAttachPortId", 0x08, "SItemPortId"], ["softAttachItemPortContainer", 0x18, "componentPtr"], ["targetInventoryId", 0x20, "SInventoryId"]] },
    SCEvtControl_OnInventoryExpandFilter: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["expanded", 0x18, "bool"]] },
    SCEvtControl_OnInventoryExitAction: { size: 0x01, fields: [] },
    SCEvtControl_OnInventoryMoveItemOntoUnoccupiedPosition: { size: 0x40, fields: [["sourceInventoryId", 0x00, "SInventoryId"], ["targetInventoryId", 0x18, "SInventoryId"], ["pageSelectedItemIndex", 0x30, "s32"], ["targetPageItemIndex", 0x34, "s32"], ["moveTo", 0x38, "s32"]] },
    SCEvtControl_OnInventoryMoveOntoOccupiedGridPosition: { size: 0x38, fields: [["sourceInventoryId", 0x00, "SInventoryId"], ["targetInventoryId", 0x18, "SInventoryId"], ["sourcePageSelectedItemIndex", 0x30, "s32"], ["targetPageSelectedItemIndex", 0x34, "s32"]] },
    SCEvtControl_OnInventorySortItem: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageOwnerSelectedItemIndex", 0x18, "s32"], ["pageSelectedNewItemIndex", 0x1C, "s32"]] },
    SCEvtControl_OnInventoryPopUpAction: { size: 0x04, fields: [["action", 0x00, "s32"]] },
    SCEvtControl_OnInventoryStoreItem: { size: 0x28, fields: [["entity", 0x00, "ptr"], ["inventoryId", 0x08, "SInventoryId"], ["index", 0x20, "s32"], ["moveTo", 0x24, "s32"]] },
    SCEvtControl_OnInventoryQuickEquipItem: { size: 0x28, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageSelectedItemIndex", 0x18, "s32"], ["targetPort", 0x20, "ptr"]] },
    SCEvtControl_OnInventoryEquipItem: { size: 0x18, fields: [["itemPortId", 0x00, "SItemPortId"], ["portContainer", 0x10, "componentPtr"]] },
    SCEvtControl_OnLootingDropItem: { size: 0x08, fields: [["entity", 0x00, "ptr"]] },
    SCEvtControl_OnLootingRepoolAmmo: { size: 0x08, fields: [["entity", 0x00, "ptr"]] },
    SCEvtControl_OnLootingDropItemFromContainer: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["pageSelectedItemIndex", 0x18, "s32"]] },
    SCEvtNotify_OnPITItemSelected: { size: 0x08, fields: [["index", 0x00, "s32"], ["hasBlockingCondition", 0x04, "bool"]] },
    SCEvtNotify_OnPITSubMenuItemSelected: { size: 0x08, fields: [["selectedItem", 0x00, "s32"], ["subMenuSelected", 0x04, "s32"]] },
    SCEvtNotify_OnPITClearItemSelection: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITItemSecondaryInteraction: { size: 0x04, fields: [["index", 0x00, "s32"]] },
    SCEvtNotify_OnPITPageNavigation: { size: 0x04, fields: [["direction", 0x00, "s32"]] },
    SCEvtNotify_OnPITBackAction: { size: 0x01, fields: [["rightClick", 0x00, "bool"]] },
    SCEvtNotify_OnPITExitAction: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITSetItemSelected: { size: 0x08, fields: [["selectedItem", 0x00, "s32"], ["menuContext", 0x04, "s32"]] },
    SCEvtControl_OnPITKeybindingButton: { size: 0x04, fields: [["buttonId", 0x00, "s32"]] },
    SCEvtNotify_OnPITHideMenu: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITPopulateMenu: { size: 0x40, fields: [["thoughts", 0x00, "vectorRaw"], ["backButtonData", 0x18, "InventoryUIData"]] },
    SCEvtNotify_OnPITPopulateFavoriteMenu: { size: 0x48, fields: [["thoughts", 0x00, "vectorRaw"], ["menuInfoDisplayStr", 0x18, "CLocString"], ["newFavoriteName", 0x20, "CLocString"], ["newFavoriteItemEntityClass", 0x28, "CryString"], ["previousFavoriteIndex", 0x30, "s32"], ["previousFavoriteName", 0x38, "CLocString"], ["previousFavoriteItemEntityClass", 0x40, "CryString"]] },
    SCEvtNotify_OnPITRequestInventoryView: { size: 0x04, fields: [["view", 0x00, "s32"]] },
    SCEvtNotify_OnPITInventoryLootToggleView: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITOpenLooting: { size: 0x38, fields: [["hostilityReaction", 0x00, "s32"], ["backButtonData", 0x08, "InventoryUIData"], ["gridCellPixelSize", 0x30, "float"]] },
    SCEvtNotify_OnPITToggleInteractionModeMessage: { size: 0x10, fields: [["active", 0x00, "bool"], ["message", 0x08, "CLocString"]] },
    SCEvtNotify_OnPITStartRebindKey: { size: 0x20, fields: [["actionMap", 0x00, "CryString"], ["actionName", 0x08, "CryString"], ["actionLabel", 0x10, "CLocString"], ["actionInput", 0x18, "CLocString"]] },
    SCEvtNotify_OnPITCancelRebindKey: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITUpdateRebindKey: { size: 0x04, fields: [["timeLeft", 0x00, "float"]] },
    SCEvtNotify_OnPITPopUpConfirmationNewBindKey: { size: 0x10, fields: [["conflictingActions", 0x00, "CLocString"], ["newRebindKey", 0x08, "CryString"]] },
    SCEvtNotify_OnPITOpenQuickAccessWheel: { size: 0x18, fields: [["thoughts", 0x00, "vectorRaw"]] },
    SCEvtNotify_OnPITCloseQuickAccessWheel: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITChangePageQuickAccessWheel: { size: 0x04, fields: [["page", 0x00, "s32"]] },
    SCEvtNotify_OnPITOpenContextualMenuQuickAccessWheel: { size: 0x08, fields: [["open", 0x00, "bool"], ["index", 0x04, "s32"]] },
    SCEvtNotify_OnPITRequestOpenExternalInventory: { size: 0x30, fields: [["requesterId", 0x00, "EntityId"], ["externalInventoryEntity", 0x08, "ptr"], ["requesterKioskEntity", 0x10, "ptr"], ["view", 0x18, "s32"], ["showLocationInventory", 0x1C, "bool"], ["cameraGuid", 0x20, "CryGUID"]] },
    SCEvtNotify_OnPITRequestLootEntity: { size: 0x18, fields: [["requesterId", 0x00, "EntityId"], ["lootingEntityId", 0x08, "EntityId"], ["allowStorageInteractions", 0x10, "bool"], ["view", 0x14, "s32"]] },
    SCEvtNotify_OnPITInventoryEquippedItemOnFocus: { size: 0x08, fields: [["itemOnFocus", 0x00, "ptr"]] },
    SCEvtNotify_OnPITInventoryRequestCompleted: { size: 0x10, fields: [["succeed", 0x00, "bool"], ["requestMoveId", 0x04, "u32"], ["itemEntityId", 0x08, "EntityId"]] },
    SCEvtNotify_OnPITInventoryRequestStoreItem: { size: 0x30, fields: [["item", 0x00, "ptr"], ["inventoryId", 0x08, "SInventoryId"], ["targetRank", 0x20, "CryString"], ["moveItemTo", 0x28, "s32"]] },
    SCEvtNotify_OnPITInventoryRequestUpdatedContainer: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnInventoryItemOption: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["itemIndex", 0x18, "s32"], ["optionIndex", 0x1C, "s32"]] },
    SCEvtNotify_OnInventoryItemOptionChangeAmount: { size: 0x28, fields: [["inventoryId", 0x00, "SInventoryId"], ["itemIndex", 0x18, "s32"], ["optionIndex", 0x1C, "s32"], ["amount", 0x20, "s32"]] },
    SCEvtNotify_OnInventoryItemStartDragging: { size: 0x08, fields: [["containerId", 0x00, "s32"], ["index", 0x04, "s32"]] },
    SCEvtNotify_OnInventoryItemStopDragging: { size: 0x08, fields: [["containerId", 0x00, "s32"], ["index", 0x04, "s32"]] },
    SCEvtNotify_InventoryStopDraggingEquipment: { size: 0x01, fields: [] },
    SCEvtNotify_OnInventoryBackAction: { size: 0x01, fields: [] },
    SCEvtNotify_OnInventoryExitAction: { size: 0x01, fields: [] },
    SCEvtNotify_OnInventorySettingsAction: { size: 0x01, fields: [] },
    SCEvtNotify_OnInventoryChangeVersion: { size: 0x04, fields: [["version", 0x00, "s32"]] },
    SCEvtNotify_OnInventoryClearInventorySection: { size: 0x01, fields: [["playerSection", 0x00, "bool"]] },
    SCEvtNotify_OnInventoryInvalidMovement: { size: 0x28, fields: [["inventoryId", 0x00, "SInventoryId"], ["invalidMessagePersistentCondition", 0x18, "CLocString"], ["invalidMessageTemporaryCondition", 0x20, "CLocString"]] },
    SCEvtNotify_OnInventoryMoveAllIndexs: { size: 0x30, fields: [["inventoryId", 0x00, "SInventoryId"], ["moveItemIndexes", 0x18, "vectorRaw"]] },
    SCEvtNotify_OnInventoryItemInfoIconRollOver: { size: 0x01, fields: [] },
    SCEvtNotify_OnInventoryUpdate: { size: 0x01, fields: [] },
    SCEvtNotify_OnCloseInventory: { size: 0x01, fields: [] },
    SCEvtNotify_OnJSONInventoryData: { size: 0x08, fields: [["jsonData", 0x00, "ptr"]] },
    SCEvtNotify_InventoryCameraFocus: { size: 0x04, fields: [["percentage", 0x00, "float"]] },
    SCEvtNotify_HelmetInventoryAttachPending: { size: 0x01, fields: [["failed", 0x00, "bool"]] },
    SCEvtNotify_HelmetInventoryDetachPending: { size: 0x01, fields: [["failed", 0x00, "bool"]] },
    SCEvtNotify_EquipItemsFromInventory: { size: 0x20, fields: [["attachingEntities", 0x00, "vectorRaw"], ["actorId", 0x18, "EntityId"]] },
    SCEvtNotify_OnCarryableDroppedFromInventory: { size: 0x10, fields: [["droppedEntity", 0x00, "ptr"], ["actor", 0x08, "ptr"]] },
    SCEvtNotify_AssetInventoryIdReceived: { size: 0x28, fields: [["directoryEntityId", 0x00, "EntityId"], ["selectedDirectoryId", 0x08, "s32"], ["inventoryId", 0x10, "SInventoryId"]] },
    SCEvtNotify_OnInventoryContainerInitialized: { size: 0x28, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnInventoryContainerClose: { size: 0x01, fields: [] },
    SCEvtNotify_OnOpenInventoryAttachmentChanged: { size: 0x01, fields: [["isAttach", 0x00, "bool"]] },
    SCEvtNotify_OnOpenInventoryOccupancyChanged: { size: 0x10, fields: [["occupancy", 0x00, "SCargoAmount"]] },
    SCEvtNotify_OnInventoryCloseInventory: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnInventoryRequestFullSort: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnInventoryApplyCategoryFilter: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["filterLabel", 0x18, "CryString"]] },
    SCEvtNotify_OnInventoryStackAll: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnInventoryItemSingleClickCheck: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["isPlayerInventory", 0x18, "bool"]] },
    SCEvtNotify_OnInventoryRequestPopulateInventoryGrid: { size: 0xB8, fields: [["inventoryId", 0x00, "SInventoryId"], ["inventoryRequestId", 0x18, "u32"], ["requestedItemTypes", 0x20, "SInventoryContainerFilterCacheKey"], ["pageInfo", 0x40, "SPaginationInfo"], ["inventoryClassCRC", 0x58, "u32"], ["parentInventoryId", 0x60, "SInventoryId"], ["type", 0x78, "s32"], ["inventoryContainerDimensions", 0x7C, "Vec3f"], ["items", 0x88, "vector:InventoryItemData"], ["armorMaxCapacity", 0xA0, "s64"], ["usedCapacity", 0xA8, "s64"], ["responseEntity", 0xB0, "ptr"]] },
    SCEvtNotify_OnFailedPopulateInventoryGrid: { size: 0x38, fields: [["inventoryId", 0x00, "SInventoryId"], ["parentInventoryId", 0x18, "SInventoryId"], ["inventoryRequestId", 0x30, "u32"], ["type", 0x34, "s32"]] },
    SCEvtNotify_OnOpenInventory: { size: 0x30, fields: [["backButtonData", 0x00, "InventoryUIData"], ["gridCellPixelSize", 0x28, "float"], ["inventoryVersion", 0x2C, "s32"]] },
    SCEvtNotify_OnUpdateInventory: { size: 0x70, fields: [["inventoryId", 0x00, "SInventoryId"], ["inventoryUIData", 0x18, "vector:InventoryUIData"], ["inventoryData", 0x30, "vector:InventoryItemData"], ["armorMaxCapacity", 0x48, "s64"], ["usedCapacity", 0x50, "s64"], ["usedCapacityPercentage", 0x58, "float"], ["hasNextPage", 0x5C, "bool"], ["hasPreviousPage", 0x5D, "bool"], ["currentPage", 0x60, "s32"], ["totalPages", 0x64, "s32"], ["filterString", 0x68, "CryString"]] },
    SCEvtNotify_OnRemoveExternalInventory: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnLoadingInventory: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    SCEvtNotify_OnPopulateInventoryGridItemMenu: { size: 0x38, fields: [["inventoryId", 0x00, "SInventoryId"], ["itemIndex", 0x18, "s32"], ["inventoryUIData", 0x20, "vector:InventoryUIMenuOptionData"]] },
    SCEvtNotify_OnPITInventoryRefreshItemPorts: { size: 0x18, fields: [["callback", 0x00, "CigFunctionBase"]] },
    SCEvtNotify_OnPITInventoryDraggingEquipment: { size: 0x04, fields: [["start", 0x00, "s32"]] },
    SCEvtNotify_OnPITInventoryDraggingLootEquipment: { size: 0x08, fields: [["id", 0x00, "s32"], ["start", 0x04, "bool"]] },
    SCEvtNotify_OnPITInventoryLootItemRollOver: { size: 0x08, fields: [["id", 0x00, "s32"], ["rollOn", 0x04, "bool"]] },
    SCEvtNotify_OnPITInventoryLootItemAction: { size: 0x03, fields: [["isPrimary", 0x00, "bool"], ["isSecondary", 0x01, "bool"], ["isDouble", 0x02, "bool"]] },
    SCEvtNotify_OnPITLootRequestTakeAllFromGroup: { size: 0x04, fields: [["lootGroup", 0x00, "s32"]] },
    SCEvtNotify_OnPITLootRequestTakeAllAttachments: { size: 0x18, fields: [["attachments", 0x00, "vectorRaw"]] },
    SCEvtNotify_OnPITInventoryLootContainerAttachmentsToggle: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITInventoryEquipmentItemPorts: { size: 0x48, fields: [["itemPorts", 0x00, "vector:InventoryUIItemPort"], ["groupedItemPorts", 0x18, "eastlMap"]] },
    SCEvtNotify_OnPITInventoryRefreshAllPorts: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITInventoryLootGrouppedPorts: { size: 0x60, fields: [["groupedPlayerItemPorts", 0x00, "eastlMap"], ["groupedLootItemPorts", 0x30, "eastlMap"]] },
    SCEvtNotify_OnPITInventoryResetItemPorts: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITInventoryItemQuickEquip: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["index", 0x18, "s32"]] },
    SCEvtNotify_OnPITInventoryUpdateDropAction: { size: 0x10, fields: [["blocked", 0x00, "bool"], ["tooltipText", 0x08, "CLocString"]] },
    SCEvtNotify_OnPITDisplayEquippedItemOnFocus: { size: 0x30, fields: [["entity", 0x00, "ptr"], ["entityClassName", 0x08, "CryString"], ["lightGroupEntityClassName", 0x10, "CryString"], ["uiDimensions", 0x18, "Vec3f"], ["uiOrientation", 0x24, "Vec3f"]] },
    SCEvtNotify_OnPITInventoryEquippedItemHovered: { size: 0x08, fields: [["entity", 0x00, "ptr"]] },
    SCEvtNotify_OnPITOpenMenu: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITCloseMenu: { size: 0x01, fields: [] },
    SCEvtNotify_OnPITShowStatusWidgets: { size: 0x01, fields: [["show", 0x00, "bool"]] },
    InventoryGridCommons_SCEvtNotify_InventoryBase: { size: 0x18, fields: [["inventoryId", 0x00, "SInventoryId"]] },
    InventoryGridCommons_SCEvtNotify_UpdateInventorySortModes: { size: 0x30, fields: [["inventoryId", 0x00, "SInventoryId"], ["menu", 0x18, "vectorRaw"]] },
    InventoryGridCommons_SCEvtNotify_OnInventorySortModeChanged: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["sortMode", 0x18, "s32"]] },
    InventoryGridCommons_SCEvtControl_OnInventorySortModeChanged: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["sortMode", 0x18, "s32"]] },
    InventoryGridCommons_SCEvtNotify_OnInventoryFilterUpdated: { size: 0x08, fields: [["filterType", 0x00, "s32"], ["source", 0x04, "u32"]] },
    InventoryGridCommons_SCEvtNotify_OnUpdatePersonalWeight: { size: 0x04, fields: [["weightRatio", 0x00, "float"]] },
    InventoryGridCommons_SCEvtNotify_UpdatePlayerCompatibleAttachments: { size: 0x01, fields: [] },
    InventoryGridCommons_SCEvtControl_OnInventoryFilterStringUpdated: { size: 0x20, fields: [["inventoryId", 0x00, "SInventoryId"], ["filterString", 0x18, "CryString"]] },
    SCEvt_Law_DetachFromOpenInventory: { size: 0x10, fields: [["entityOwnerId", 0x00, "EntityId"], ["vehicleOwnerId", 0x08, "EntityId"]] }
});

function decodeInventorySchemaField(base, field, includeNested = false) {
    const [, offset, type] = field;
    const p = base.add(offset);
    if (type === "bool") return p.readU8() !== 0;
    if (type === "u8") return p.readU8();
    if (type === "s32") return p.readS32();
    if (type === "u32") return p.readU32();
    if (type === "s64") return p.readS64().toString();
    if (type === "float") return p.readFloat();
    if (type === "EntityId") return readEntityId(p);
    if (type === "CryGUID") return readCryGuid(p);
    if (type === "ptr") return p.readPointer().toString();
    if (type === "componentPtr") return componentPtrInfo(p);
    if (type === "CigFunctionBase") return new CigFunctionBase(p).toObject();
    if (type === "CryString") return readCryStringHandle(p);
    if (type === "CLocString") return readCLocString(p);
    if (type === "Vec3f") return readVec3f(p);
    if (type === "SInventoryId") return new SInventoryId(p).toObject();
    if (type === "SItemPortId") return new SItemPortId(p).toObject();
    if (type === "SCargoAmount") return new SCargoAmount(p).toObject();
    if (type === "SInventoryContainerFilterCacheKey") return new SInventoryContainerFilterCacheKey(p).toObject();
    if (type === "SPaginationInfo") return new SPaginationInfo(p).toObject();
    if (type === "InventoryUIData") return new InventoryUIData(p).toObject();
    if (type === "eastlMap") return eastlMapInfo(p);
    if (type === "vectorRaw") return stdVectorRawInfo(p);
    if (type === "vector:SInventoryId") return new StdVector(p, InventoryManagementSurface.sizes.SInventoryId, SInventoryId).toSummary();
    if (type === "vector:InventoryItemData") {
        const vector = new StdVector(p, InventoryManagementSurface.sizes.InventoryUI_SInventoryItemData, InventoryItemData);
        return includeNested ? vector.toArray(128).map(item => item.toObject()) : vector.toSummary();
    }
    if (type === "vector:InventoryUIData") {
        const vector = new StdVector(p, InventoryManagementSurface.sizes.InventoryUI_SInventoryUIData, InventoryUIData);
        return includeNested ? vector.toArray(128).map(item => item.toObject()) : vector.toSummary();
    }
    if (type === "vector:InventoryUIMenuOptionData") {
        const vector = new StdVector(p, InventoryManagementSurface.sizes.InventoryUI_SInventoryMenuOptionData, InventoryUIMenuOptionData);
        return includeNested ? vector.toArray(64).map(item => item.toObject()) : vector.toSummary();
    }
    if (type === "vector:InventoryUIItemPort") {
        const vector = new StdVector(p, InventoryManagementSurface.sizes.InventoryUI_SInventoryItemPort, InventoryUIItemPort);
        return includeNested ? vector.toArray(64).map(item => item.toObject(false)) : vector.toSummary();
    }
    return { ptr: p.toString(), type };
}

function decodeInventoryEvent(type, ptrValue, includeNested = false) {
    const schema = InventoryEventSchemas[String(type)];
    if (!schema) throw new Error(`unsupported inventory event decoder: ${type}`);
    const p = ptr(ptrValue);
    const fields = {};
    for (const field of schema.fields) {
        fields[field[0]] = decodeInventorySchemaField(p, field, includeNested);
    }
    return {
        type: String(type),
        ptr: p.toString(),
        size: schema.size,
        fields
    };
}

function decodeInventoryStruct(type, ptrValue, includeNested = false) {
    const p = ptr(ptrValue);
    const decoders = {
        DataCoreArrayBase: () => new DataCoreArrayBase(p).toObject(),
        DCString: () => new DCString(p).toObject(),
        CLocIdentifier: () => new CLocIdentifier(p).toObject(),
        STypeSubtypeParams: () => new STypeSubtypeParams(p).toObject(),
        SItemCategory: () => new SItemCategory(p).toObject(),
        SInventoryInteractionBlockingAttachedEntities: () => new SInventoryInteractionBlockingAttachedEntities(p).toObject(),
        SPlayerInventoryDef: () => new SPlayerInventoryDef(p).toObject(),
        SInventoryConfig: () => new SInventoryConfig(p).toObject(),
        SOpenInventory: () => new SOpenInventory(p).toObject(),
        SLootGeneration: () => new SLootGeneration(p).toObject(),
        SInventoryContainerCVars: () => new SInventoryContainerCVars(p).toObject(),
        SInventoryId: () => new SInventoryId(p).toObject(),
        SInventoryEntity: () => new SInventoryEntity(p).toObject(),
        SInventoryConfiguration: () => new SInventoryConfiguration(p).toObject(),
        SInventoryContainerDef: () => new SInventoryContainerDef(p).toObject(),
        SInventoryContainerTypeBaseDef: () => new SInventoryContainerTypeBaseDef(p).toObject(),
        SInventoryOpenContainerTypeDef: () => new SInventoryOpenContainerTypeDef(p).toObject(),
        SInventoryOpenAlwaysContainerTypeDef: () => new SInventoryOpenAlwaysContainerTypeDef(p).toObject(),
        SInventoryClosedContainerTypeDef: () => new SInventoryClosedContainerTypeDef(p).toObject(),
        SInventoryContainerItemTypeFilter: () => new SInventoryContainerItemTypeFilter(p).toObject(),
        SInventoryParams: () => new SInventoryParams(p).toObject(),
        SInventoryGamePersistentData: () => new SInventoryGamePersistentData(p).toObject(),
        SInventoryItemMapEntry: () => new SInventoryItemMapEntry(p).toObject(),
        SInventoryContainerUIParams: () => new SInventoryContainerUIParams(p).toObject(),
        SInventorySortMode: () => new SInventorySortMode(p).toObject(),
        SInventoryDropDetachRules: () => new SInventoryDropDetachRules(p).toObject(),
        SInventoryStateModifier: () => new SInventoryStateModifier(p).toObject(),
        SStowPolicyCache: () => new SStowPolicyCache(p).toObject(),
        SCargoGridOccupantFace: () => new SCargoGridOccupantFace(p).toObject(),
        SCargoGridOccupantProperties: () => new SCargoGridOccupantProperties(p).toObject(),
        SOpenInventoryOccupantItemTypeProperties: () => new SOpenInventoryOccupantItemTypeProperties(p).toObject(),
        SInventoryContainerManagerDef: () => new SInventoryContainerManagerDef(p).toObject(),
        SInventoryContainerGridCellSizeBase: () => new SInventoryContainerGridCellSizeBase(p).toObject(),
        SInventoryContainerGridCellSizeCentimeters: () => new SInventoryContainerGridCellSizeCentimeters(p).toObject(),
        SInventoryContainerGridCellSizeMeters: () => new SInventoryContainerGridCellSizeMeters(p).toObject(),
        SInventoryItemTypes: () => new SInventoryItemTypes(p).toObject(),
        SInventoryUpdateItem: () => new SInventoryUpdateItem(p).toObject(),
        SStowContext: () => new SStowContext(p).toObject(),
        SStowItemRequestParams: () => new SStowItemRequestParams(p).toObject(),
        SInventoryManagementRequest: () => new SInventoryManagementRequest(p).toObject(includeNested),
        SMoveStackRequest: () => new SMoveStackRequest(p).toObject(),
        SMoveItemRequest: () => new SMoveItemRequest(p).toObject(),
        SUnstackEntityRequestParams: () => new SUnstackEntityRequestParams(p).toObject(),
        SUnstackEntityRequest: () => new SUnstackEntityRequest(p).toObject(includeNested),
        SMoveEntityStackParam: () => new SMoveEntityStackParam(p).toObject(),
        IInventoryApiSMoveResult: () => new IInventoryApiSMoveResult(p).toObject(),
        IInventoryApiSMoveRequest: () => new IInventoryApiSMoveRequest(p).toObject(),
        SEntityStackChangeParam: () => new SEntityStackChangeParam(p).toObject(),
        SIncreaseEntityStackRequest: () => new SIncreaseEntityStackRequest(p).toObject(includeNested),
        SDecreaseEntityStackRequest: () => new SDecreaseEntityStackRequest(p).toObject(includeNested),
        SSetEntityStackRequest: () => new SSetEntityStackRequest(p).toObject(includeNested),
        SMoveEntityStackRequest: () => new SMoveEntityStackRequest(p).toObject(includeNested),
        STransferEntityAggregateRequest: () => new STransferEntityAggregateRequest(p).toObject(includeNested),
        SCreateEntityToInventoryRequest: () => new SCreateEntityToInventoryRequest(p).toObject(),
        IInventoryApiSCreateEntityToInventoryRequest: () => new IInventoryApiSCreateEntityToInventoryRequest(p).toObject(),
        SUnstowItemRequestParams: () => new SUnstowItemRequestParams(p).toObject(),
        SEntityUnstowParams: () => new SEntityUnstowParams(p).toObject(),
        SUnstowRequest: () => new SUnstowRequest(p).toObject(includeNested),
        SSPlitStackRequestParams: () => new SSPlitStackRequestParams(p).toObject(),
        SSplitStackRequestParams: () => new SSPlitStackRequestParams(p).toObject(),
        SSplitStackRequest: () => new SSplitStackRequest(p).toObject(includeNested),
        SDeleteItemRequestParams: () => new SDeleteItemRequestParams(p).toObject(),
        SDeleteItemRequest: () => new SDeleteItemRequest(p).toObject(includeNested),
        SStowEntityRequest: () => new SStowEntityRequest(p).toObject(),
        SStowRequest: () => new SStowRequest(p).toObject(),
        SDestroyEntityPreconditions: () => new SDestroyEntityPreconditions(p).toObject(),
        SDestroyEntityParam: () => new SDestroyEntityParam(p).toObject(),
        SDestroyEntityRequest: () => new SDestroyEntityRequest(p).toObject(includeNested),
        SOptionalArguments: () => new SOptionalArguments(p).toObject(),
        IItemPortModificationApiSAttachRequest: () => new IItemPortModificationApiSAttachRequest(p).toObject(),
        IItemPortModificationApiSDetachRequest: () => new IItemPortModificationApiSDetachRequest(p).toObject(),
        IItemPortModificationApiSModifyItemPortRequest: () => new IItemPortModificationApiSModifyItemPortRequest(p).toObject(),
        SInventoryDataRequest: () => new SInventoryDataRequest(p).toObject(includeNested),
        SPlayerInventoryQuery: () => new SPlayerInventoryQuery(p).toObject(includeNested),
        SInventoryContainerEntry: () => new SInventoryContainerEntry(p).toObject(),
        SInventoryContainerGridItem: () => new SInventoryContainerGridItem(p).toObject(),
        SGridItemRequest: () => new SGridItemRequest(p).toObject(),
        SInventoryContainerManagerEntry: () => new SInventoryContainerManagerEntry(p).toObject(includeNested),
        PersonalThoughtInventoryMoveLocalAttachData: () => new PersonalThoughtInventoryMoveLocalAttachData(p).toObject(),
        PersonalThoughtInventoryMove: () => new PersonalThoughtInventoryMove(p).toObject(includeNested),
        InventoryUINavigationData: () => new InventoryUINavigationData(p).toObject(),
        InventoryUIMenuOptionData: () => new InventoryUIMenuOptionData(p).toObject(),
        InventoryUIFilterData: () => new InventoryUIFilterData(p).toObject(),
        InventoryUICategoryFilterData: () => new InventoryUICategoryFilterData(p).toObject(includeNested),
        InventoryUIItemPort: () => new InventoryUIItemPort(p).toObject(includeNested),
        SInventoryContent: () => new SInventoryContent(p).toObject(),
        SInventoryItemKey: () => new SInventoryItemKey(p).toObject(),
        SFreightElevatorRequest: () => new SFreightElevatorRequest(p).toObject(),
        CBindingsShopInventoryItem: () => new CBindingsShopInventoryItem(p).toObject(),
        SBindingsInventoryItemResourceContents: () => new SBindingsInventoryItemResourceContents(p).toObject(),
        InventoryGridCommonsSBindingsInventoryItemCraftedStat: () => new InventoryGridCommonsSBindingsInventoryItemCraftedStat(p).toObject(),
        SBindingsInventoryItemMenuOptions: () => new SBindingsInventoryItemMenuOptions(p).toObject(),
        SBindingsInventoryItemHologram: () => new SBindingsInventoryItemHologram(p).toObject(),
        SBindingsInventoryItemPersistence: () => new SBindingsInventoryItemPersistence(p).toObject(),
        SBindingsInventoryItemDesc: () => new SBindingsInventoryItemDesc(p).toObject(),
        SBindingsInventoryCustomSubFilter: () => new SBindingsInventoryCustomSubFilter(p).toObject(),
        SBindingsInventoryCustomFilter: () => new SBindingsInventoryCustomFilter(p).toObject(),
        SBindingsInventoryItemFilter: () => new SBindingsInventoryItemFilter(p).toObject(),
        SBindingsInventoryInvalidMoveData: () => new SBindingsInventoryInvalidMoveData(p).toObject(),
        SBindingsInventoryItem: () => new SBindingsInventoryItem(p).toObject(),
        SBindingsInventoryPopBox: () => new SBindingsInventoryPopBox(p).toObject(),
        SBindingsInventoryContainerTabMenu: () => new SBindingsInventoryContainerTabMenu(p).toObject(),
        SBindingsInventorySection: () => new SBindingsInventorySection(p).toObject(),
        InventoryGridCommonsSBindingsTooltipData: () => new InventoryGridCommonsSBindingsTooltipData(p).toObject(),
        SBindingsInventoryGridData: () => new SBindingsInventoryGridData(p).toObject(includeNested),
        InventoryGridCommonsCSCBaseInventoryGrid: () => new InventoryGridCommonsCSCBaseInventoryGrid(p).toObject(),
        SCFreightKioskInventoryGrid: () => new SCFreightKioskInventoryGrid(p).toObject(),
        SBindingsFreightElevatorUI: () => new SBindingsFreightElevatorUI(p).toObject(),
        SBindingsInventoryContainer: () => new SBindingsInventoryContainer(p).toObject(),
        SBindingsInventoryContainerTab: () => new SBindingsInventoryContainerTab(p).toObject(),
        CSCInventoryDisplay: () => new CSCInventoryDisplay(p).toObject(),
        CEntityComponentFreightElevatorUIProviderSClientData: () => new CEntityComponentFreightElevatorUIProviderSClientData(p).toObject(),
        CEntityComponentFreightElevatorUIProvider: () => new CEntityComponentFreightElevatorUIProvider(p).toObject(),
        CPlayerAssetManagerProvider: () => new CPlayerAssetManagerProvider(p).toObject(),
        SBindingsLootItemSlotState: () => new SBindingsLootItemSlotState(p).toObject(),
        SBindingsEquipItemPortInfo: () => new SBindingsEquipItemPortInfo(p).toObject(includeNested),
        SBindingsEquipGroupItemPorts: () => new SBindingsEquipGroupItemPorts(p).toObject(),
        SBindingsPITInventoryDragEquipment: () => new SBindingsPITInventoryDragEquipment(p).toObject(includeNested),
        SBindingsPITInventoryHoveredCharacterItemInfo: () => new SBindingsPITInventoryHoveredCharacterItemInfo(p).toObject(),
        SBindingsPITLootingFocusItem: () => new SBindingsPITLootingFocusItem(p).toObject(),
        SBindingsPITLootPortContainerGroup: () => new SBindingsPITLootPortContainerGroup(p).toObject(includeNested),
        SBindingsPITLootingArmour: () => new SBindingsPITLootingArmour(p).toObject(includeNested),
        SBindingsPITLootingClothing: () => new SBindingsPITLootingClothing(p).toObject(includeNested),
        SBindingsPITLootingStorage: () => new SBindingsPITLootingStorage(p).toObject(includeNested),
        SBindingsPITLootingSection: () => new SBindingsPITLootingSection(p).toObject(includeNested),
        SBindingsPITInventoryLooting: () => new SBindingsPITInventoryLooting(p).toObject(includeNested),
        SBindingsPITInventoryItem: () => new SBindingsPITInventoryItem(p).toObject(includeNested),
        SBindingsPITInventoryGrid: () => new SBindingsPITInventoryGrid(p).toObject(includeNested),
        CSCPersonalThoughtDisplay: () => new CSCPersonalThoughtDisplay(p).toObject(includeNested),
        SUnstowInfo: () => new SUnstowInfo(p).toObject(includeNested),
        SStowInfo: () => new SStowInfo(p).toObject(),
        CInventoryContainerManagerSLootableBox: () => new CInventoryContainerManagerSLootableBox(p).toObject(),
        CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry: () => new CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry(p).toObject(),
        CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData: () => new CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData(p).toObject(includeNested),
        CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo: () => new CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo(p).toObject(includeNested)
    };

    const decode = decoders[String(type)];
    if (!decode) {
        throw new Error(`unsupported inventory struct decoder: ${type}`);
    }

    return {
        type: String(type),
        ptr: p.toString(),
        value: decode()
    };
}

function inventoryDecoderSurface() {
    const eventSchemas = {};
    for (const [name, schema] of Object.entries(InventoryEventSchemas)) {
        eventSchemas[name] = {
            size: schema.size,
            fields: schema.fields.map(([field, offset, type]) => ({ field, offset, type }))
        };
    }

    return {
        source: InventoryManagementSurface.source,
        sizes: {
            SInventoryId: InventoryManagementSurface.sizes.SInventoryId,
            SInventoryEntity: InventoryManagementSurface.sizes.SInventoryEntity,
            SInventoryConfiguration: InventoryManagementSurface.sizes.SInventoryConfiguration,
            SInventoryContainerDef: InventoryManagementSurface.sizes.SInventoryContainerDef,
            SInventoryContainerTypeBaseDef: InventoryManagementSurface.sizes.SInventoryContainerTypeBaseDef,
            SInventoryOpenContainerTypeDef: InventoryManagementSurface.sizes.SInventoryOpenContainerTypeDef,
            SInventoryOpenAlwaysContainerTypeDef: InventoryManagementSurface.sizes.SInventoryOpenAlwaysContainerTypeDef,
            SInventoryClosedContainerTypeDef: InventoryManagementSurface.sizes.SInventoryClosedContainerTypeDef,
            SInventoryContainerItemTypeFilter: InventoryManagementSurface.sizes.SInventoryContainerItemTypeFilter,
            SInventoryParams: InventoryManagementSurface.sizes.SInventoryParams,
            SInventoryGamePersistentData: InventoryManagementSurface.sizes.SInventoryGamePersistentData,
            SInventoryItemMapEntry: InventoryManagementSurface.sizes.SInventoryItemMapEntry,
            SInventoryContainerUIParams: InventoryManagementSurface.sizes.SInventoryContainerUIParams,
            SInventorySortMode: InventoryManagementSurface.sizes.SInventorySortMode,
            SInventoryDropDetachRules: InventoryManagementSurface.sizes.SInventoryDropDetachRules,
            SInventoryStateModifier: InventoryManagementSurface.sizes.SInventoryStateModifier,
            SStowPolicyCache: InventoryManagementSurface.sizes.SStowPolicyCache,
            SCargoGridOccupantFace: InventoryManagementSurface.sizes.SCargoGridOccupantFace,
            SCargoGridOccupantProperties: InventoryManagementSurface.sizes.SCargoGridOccupantProperties,
            SOpenInventoryOccupantItemTypeProperties: InventoryManagementSurface.sizes.SOpenInventoryOccupantItemTypeProperties,
            SInventoryContainerManagerDef: InventoryManagementSurface.sizes.SInventoryContainerManagerDef,
            SInventoryContainerGridCellSizeBase: InventoryManagementSurface.sizes.SInventoryContainerGridCellSizeBase,
            SInventoryContainerGridCellSizeCentimeters: InventoryManagementSurface.sizes.SInventoryContainerGridCellSizeCentimeters,
            SInventoryContainerGridCellSizeMeters: InventoryManagementSurface.sizes.SInventoryContainerGridCellSizeMeters,
            IPlatformInventoryManager: InventoryManagementSurface.sizes.IPlatformInventoryManager,
            IPlayerInventoryManager: InventoryManagementSurface.sizes.IPlayerInventoryManager,
            ISCActorInventory: InventoryManagementSurface.sizes.ISCActorInventory,
            CSCActorInventory: InventoryManagementSurface.sizes.CSCActorInventory,
            SInventoryItemTypes: InventoryManagementSurface.sizes.SInventoryItemTypes,
            SInventoryUpdateItem: InventoryManagementSurface.sizes.SInventoryUpdateItem,
            SStowContext: InventoryManagementSurface.sizes.SStowContext,
            SStowItemRequestParams: InventoryManagementSurface.sizes.SStowItemRequestParams,
            SInventoryManagementRequest: InventoryManagementSurface.sizes.SInventoryManagementRequest,
            SMoveStackRequest: InventoryManagementSurface.sizes.SMoveStackRequest,
            SMoveItemRequest: InventoryManagementSurface.sizes.SMoveItemRequest,
            SUnstackEntityRequestParams: InventoryManagementSurface.sizes.SUnstackEntityRequestParams,
            SUnstackEntityRequest: InventoryManagementSurface.sizes.SUnstackEntityRequest,
            SMoveEntityStackParam: InventoryManagementSurface.sizes.SMoveEntityStackParam,
            IInventoryApiSMoveResult: InventoryManagementSurface.sizes.IInventoryApi_SMoveResult,
            IInventoryApiSMoveRequest: InventoryManagementSurface.sizes.IInventoryApi_SMoveRequest,
            SEntityStackChangeParam: InventoryManagementSurface.sizes.SEntityStackChangeParam,
            SIncreaseEntityStackRequest: InventoryManagementSurface.sizes.SIncreaseEntityStackRequest,
            SDecreaseEntityStackRequest: InventoryManagementSurface.sizes.SDecreaseEntityStackRequest,
            SSetEntityStackRequest: InventoryManagementSurface.sizes.SSetEntityStackRequest,
            SMoveEntityStackRequest: InventoryManagementSurface.sizes.SMoveEntityStackRequest,
            STransferEntityAggregateRequest: InventoryManagementSurface.sizes.STransferEntityAggregateRequest,
            SCreateEntityToInventoryRequest: InventoryManagementSurface.sizes.SCreateEntityToInventoryRequest,
            IInventoryApiSCreateEntityToInventoryRequest: InventoryManagementSurface.sizes.IInventoryApi_SCreateEntityToInventoryRequest,
            SUnstowItemRequestParams: InventoryManagementSurface.sizes.SUnstowItemRequestParams,
            SEntityUnstowParams: InventoryManagementSurface.sizes.SEntityUnstowParams,
            SUnstowRequest: InventoryManagementSurface.sizes.SUnstowRequest,
            SSPlitStackRequestParams: InventoryManagementSurface.sizes.SSPlitStackRequestParams,
            SSplitStackRequest: InventoryManagementSurface.sizes.SSplitStackRequest,
            SDeleteItemRequestParams: InventoryManagementSurface.sizes.SDeleteItemRequestParams,
            SDeleteItemRequest: InventoryManagementSurface.sizes.SDeleteItemRequest,
            SStowEntityRequest: InventoryManagementSurface.sizes.SStowEntityRequest,
            SStowRequest: InventoryManagementSurface.sizes.SStowRequest,
            SDestroyEntityPreconditions: InventoryManagementSurface.sizes.SDestroyEntityPreconditions,
            SDestroyEntityParam: InventoryManagementSurface.sizes.SDestroyEntityParam,
            SDestroyEntityRequest: InventoryManagementSurface.sizes.SDestroyEntityRequest,
            SOptionalArguments: InventoryManagementSurface.sizes.SOptionalArguments,
            IItemPortModificationApiSAttachRequest: InventoryManagementSurface.sizes.IItemPortModificationApi_SAttachRequest,
            IItemPortModificationApiSDetachRequest: InventoryManagementSurface.sizes.IItemPortModificationApi_SDetachRequest,
            IItemPortModificationApiSModifyItemPortRequest: InventoryManagementSurface.sizes.IItemPortModificationApi_SModifyItemPortRequest,
            SInventoryDataRequest: InventoryManagementSurface.sizes.SInventoryDataRequest,
            SPlayerInventoryQuery: InventoryManagementSurface.sizes.SPlayerInventoryQuery,
            SInventoryContainerEntry: InventoryManagementSurface.sizes.SInventoryContainerEntry,
            SInventoryContainerGridItem: InventoryManagementSurface.sizes.SInventoryContainerGridItem,
            SGridItemRequest: InventoryManagementSurface.sizes.SGridItemRequest,
            SInventoryContainerManagerEntry: InventoryManagementSurface.sizes.SInventoryContainerManagerEntry,
            SInventoryContainerManagerEntriesCache: InventoryManagementSurface.sizes.SInventoryContainerManagerEntriesCache,
            SInventoryContainerFilterCacheKey: InventoryManagementSurface.sizes.SInventoryContainerFilterCacheKey,
            SInventoryContainerManagerDataCache: InventoryManagementSurface.sizes.SInventoryContainerManagerDataCache,
            SInventoryContainerManagerDataCachePair: InventoryManagementSurface.sizes.SInventoryContainerManagerDataCachePair,
            SPersonalInventoryReceivedData: InventoryManagementSurface.sizes.SPersonalInventoryReceivedData,
            SPersonalInventoryData: InventoryManagementSurface.sizes.SPersonalInventoryData,
            CInventoryQueryPendingRequest: InventoryManagementSurface.sizes.CInventoryContainerManager_CInventoryQueryPendingRequest,
            CInventoryOpenPendingRequest: InventoryManagementSurface.sizes.CInventoryContainerManager_CInventoryOpenPendingRequest,
            PersonalThoughtInventoryMoveLocalAttachData: InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventoryMove_SLocalAttachData,
            PersonalThoughtInventoryMove: InventoryManagementSurface.sizes.CSCLocalPlayerPersonalThoughtComponent_SInventoryMove,
            InventoryUINavigationData: InventoryManagementSurface.sizes.InventoryUI_SInventoryNavigationData,
            InventoryUIMenuOptionData: InventoryManagementSurface.sizes.InventoryUI_SInventoryMenuOptionData,
            InventoryUIFilterData: InventoryManagementSurface.sizes.InventoryUI_SInventoryFilterData,
            InventoryUICategoryFilterData: InventoryManagementSurface.sizes.InventoryUI_SInventoryCategoryFilterData,
            InventoryUIItemPort: InventoryManagementSurface.sizes.InventoryUI_SInventoryItemPort,
            SInventoryContent: InventoryManagementSurface.sizes.SInventoryContent,
            SInventoryItemKey: InventoryManagementSurface.sizes.SInventoryItemKey,
            SFreightElevatorRequest: InventoryManagementSurface.sizes.SFreightElevatorRequest,
            CBindingsShopInventoryItem: InventoryManagementSurface.sizes.CBindingsShopInventoryItem,
            SBindingsInventoryItem: InventoryManagementSurface.sizes.SBindingsInventoryItem,
            SBindingsInventoryItemResourceContents: InventoryManagementSurface.sizes.SBindingsInventoryItemResourceContents,
            InventoryGridCommonsSBindingsInventoryItemCraftedStat: InventoryManagementSurface.sizes.InventoryGridCommons_SBindingsInventoryItemCraftedStat,
            SBindingsInventoryItemMenuOptions: InventoryManagementSurface.sizes.SBindingsInventoryItemMenuOptions,
            SBindingsInventoryItemHologram: InventoryManagementSurface.sizes.SBindingsInventoryItemHologram,
            SBindingsInventoryItemPersistence: InventoryManagementSurface.sizes.SBindingsInventoryItemPersistence,
            SBindingsInventoryItemDesc: InventoryManagementSurface.sizes.SBindingsInventoryItemDesc,
            SBindingsInventoryCustomSubFilter: InventoryManagementSurface.sizes.SBindingsInventoryCustomSubFilter,
            SBindingsInventoryCustomFilter: InventoryManagementSurface.sizes.SBindingsInventoryCustomFilter,
            SBindingsInventoryItemFilter: InventoryManagementSurface.sizes.SBindingsInventoryItemFilter,
            SBindingsInventoryInvalidMoveData: InventoryManagementSurface.sizes.SBindingsInventoryInvalidMoveData,
            SBindingsInventoryContainer: InventoryManagementSurface.sizes.SBindingsInventoryContainer,
            SBindingsInventoryContainerTab: InventoryManagementSurface.sizes.SBindingsInventoryContainerTab,
            SBindingsInventoryPopBox: InventoryManagementSurface.sizes.SBindingsInventoryPopBox,
            SBindingsInventoryContainerTabMenu: InventoryManagementSurface.sizes.SBindingsInventoryContainerTabMenu,
            SBindingsInventorySection: InventoryManagementSurface.sizes.SBindingsInventorySection,
            InventoryGridCommonsSBindingsTooltipData: InventoryManagementSurface.sizes.InventoryGridCommons_SBindingsTooltipData,
            SBindingsInventoryGridData: InventoryManagementSurface.sizes.SBindingsInventoryGridData,
            InventoryGridCommonsCSCBaseInventoryGrid: InventoryManagementSurface.sizes.InventoryGridCommons_CSCBaseInventoryGrid,
            SCFreightKioskInventoryGrid: InventoryManagementSurface.sizes.SCFreightKioskInventoryGrid,
            SBindingsFreightElevatorUI: InventoryManagementSurface.sizes.SBindings_FreightElevatorUI,
            CBindingsMapSInventoryItemKeySBindingsInventoryItem: InventoryManagementSurface.sizes.CBindingsMap_SInventoryItemKey_SBindingsInventoryItem,
            CSCInventoryDisplay: InventoryManagementSurface.sizes.CSCInventoryDisplay,
            CEntityComponentFreightElevatorUIProviderSClientData: InventoryManagementSurface.sizes.CEntityComponentFreightElevatorUIProvider_SClientData,
            CEntityComponentFreightElevatorUIProvider: InventoryManagementSurface.sizes.CEntityComponentFreightElevatorUIProvider,
            CPlayerAssetManagerProvider: InventoryManagementSurface.sizes.CPlayerAssetManagerProvider,
            CPlayerAssetManagerProviderSAssetDirectory: InventoryManagementSurface.sizes.CPlayerAssetManagerProvider_SAssetDirectory,
            CSCPersonalThoughtDisplay: InventoryManagementSurface.sizes.CSCPersonalThoughtDisplay,
            SBindingsLootItemSlotState: InventoryManagementSurface.sizes.SBindingsLootItemSlotState,
            SBindingsEquipGroupItemPorts: InventoryManagementSurface.sizes.SBindingsEquipGroupItemPorts,
            SBindingsEquipItemPortInfo: InventoryManagementSurface.sizes.SBindingsEquipItemPortInfo,
            SBindingsPITInventoryDragEquipment: InventoryManagementSurface.sizes.SBindingsPITInventoryDragEquipment,
            SBindingsPITInventoryHoveredCharacterItemInfo: InventoryManagementSurface.sizes.SBindingsPITInventoryHoveredCharacterItemInfo,
            SBindingsPITLootingFocusItem: InventoryManagementSurface.sizes.SBindingsPITLootingFocusItem,
            SBindingsPITLootPortContainerGroup: InventoryManagementSurface.sizes.SBindingsPITLootPortContainerGroup,
            SBindingsPITLootingArmour: InventoryManagementSurface.sizes.SBindingsPITLootingArmour,
            SBindingsPITLootingClothing: InventoryManagementSurface.sizes.SBindingsPITLootingClothing,
            SBindingsPITLootingStorage: InventoryManagementSurface.sizes.SBindingsPITLootingStorage,
            SBindingsPITLootingSection: InventoryManagementSurface.sizes.SBindingsPITLootingSection,
            SBindingsPITInventoryLooting: InventoryManagementSurface.sizes.SBindingsPITInventoryLooting,
            SBindingsPITInventoryItem: InventoryManagementSurface.sizes.SBindingsPITInventoryItem,
            SBindingsPITInventoryGrid: InventoryManagementSurface.sizes.SBindingsPITInventoryGrid,
            SUnstowInfo: InventoryManagementSurface.sizes.SUnstowInfo,
            SStowInfo: InventoryManagementSurface.sizes.SStowInfo,
            CInventoryContainerManagerSLootableBox: InventoryManagementSurface.sizes.CInventoryContainerManager_SLootableBox,
            CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry: InventoryManagementSurface.sizes.CInventoryContainerManager_AsyncQueryInventoryData_SQueryEntry,
            CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData: InventoryManagementSurface.sizes.CInventoryContainerManager_AsyncStowEntity_SAsyncStowSharedData,
            CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo: InventoryManagementSurface.sizes.CInventoryContainerManager_ProcessPendingInventoryContainerOpens_SUnstowRequestInfo,
            SInventoryInteractionBlockingAttachedEntities: InventoryManagementSurface.sizes.SInventoryInteractionBlockingAttachedEntities,
            SPlayerInventoryDef: InventoryManagementSurface.sizes.SPlayerInventoryDef,
            SInventoryConfig: InventoryManagementSurface.sizes.SInventoryConfig,
            SOpenInventory: InventoryManagementSurface.sizes.SOpenInventory,
            SLootGeneration: InventoryManagementSurface.sizes.SLootGeneration,
            SInventoryContainerCVars: InventoryManagementSurface.sizes.SInventoryContainerCVars
        },
        offsets: {
            SInventoryId: InventoryManagementSurface.sInventoryIdOffsets,
            SInventoryContainerDef: InventoryManagementSurface.sInventoryContainerDefOffsets,
            SInventoryOpenContainerTypeDef: InventoryManagementSurface.sInventoryOpenContainerTypeDefOffsets,
            SInventoryOpenAlwaysContainerTypeDef: InventoryManagementSurface.sInventoryOpenContainerTypeDefOffsets,
            SInventoryClosedContainerTypeDef: InventoryManagementSurface.sInventoryClosedContainerTypeDefOffsets,
            SInventoryContainerItemTypeFilter: InventoryManagementSurface.sInventoryContainerItemTypeFilterOffsets,
            SInventoryParams: InventoryManagementSurface.sInventoryParamsOffsets,
            SInventoryGamePersistentData: InventoryManagementSurface.sInventoryGamePersistentDataOffsets,
            SInventoryItemMapEntry: InventoryManagementSurface.sInventoryItemMapEntryOffsets,
            SInventoryContainerUIParams: InventoryManagementSurface.sInventoryContainerUIParamsOffsets,
            SInventorySortMode: InventoryManagementSurface.sInventorySortModeOffsets,
            SInventoryDropDetachRules: InventoryManagementSurface.sInventoryDropDetachRulesOffsets,
            SInventoryStateModifier: InventoryManagementSurface.sInventoryStateModifierOffsets,
            SStowPolicyCache: InventoryManagementSurface.sStowPolicyCacheOffsets,
            SCargoGridOccupantFace: InventoryManagementSurface.sCargoGridOccupantFaceOffsets,
            SCargoGridOccupantProperties: InventoryManagementSurface.sCargoGridOccupantPropertiesOffsets,
            SOpenInventoryOccupantItemTypeProperties: InventoryManagementSurface.sOpenInventoryOccupantItemTypePropertiesOffsets,
            SInventoryContainerManagerDef: InventoryManagementSurface.sInventoryContainerManagerDefOffsets,
            SInventoryContainerGridCellSizeCentimeters: InventoryManagementSurface.sInventoryContainerGridCellSizeCentimetersOffsets,
            SInventoryContainerGridCellSizeMeters: InventoryManagementSurface.sInventoryContainerGridCellSizeMetersOffsets,
            SInventoryUpdateItem: InventoryManagementSurface.sInventoryUpdateItemOffsets,
            SStowContext: InventoryManagementSurface.sStowContextOffsets,
            SStowItemRequestParams: InventoryManagementSurface.sStowItemRequestParamsOffsets,
            SInventoryManagementRequest: InventoryManagementSurface.sInventoryManagementRequestOffsets,
            SMoveStackRequest: InventoryManagementSurface.sMoveStackRequestOffsets,
            SMoveItemRequest: InventoryManagementSurface.sMoveItemRequestOffsets,
            SUnstackEntityRequestParams: InventoryManagementSurface.sUnstackEntityRequestParamsOffsets,
            SUnstackEntityRequest: InventoryManagementSurface.sUnstackEntityRequestOffsets,
            SMoveEntityStackParam: InventoryManagementSurface.sMoveEntityStackParamOffsets,
            IInventoryApiSMoveResult: InventoryManagementSurface.iInventoryApiMoveResultOffsets,
            IInventoryApiSMoveRequest: InventoryManagementSurface.iInventoryApiMoveRequestOffsets,
            SEntityStackChangeParam: InventoryManagementSurface.sEntityStackChangeParamOffsets,
            SIncreaseEntityStackRequest: InventoryManagementSurface.sEntityStackChangeRequestOffsets,
            SDecreaseEntityStackRequest: InventoryManagementSurface.sEntityStackChangeRequestOffsets,
            SSetEntityStackRequest: InventoryManagementSurface.sEntityStackChangeRequestOffsets,
            SMoveEntityStackRequest: InventoryManagementSurface.sMoveEntityStackRequestOffsets,
            STransferEntityAggregateRequest: InventoryManagementSurface.sTransferEntityAggregateRequestOffsets,
            SCreateEntityToInventoryRequest: InventoryManagementSurface.sCreateEntityToInventoryRequestOffsets,
            IInventoryApiSCreateEntityToInventoryRequest: InventoryManagementSurface.iInventoryApiCreateEntityToInventoryRequestOffsets,
            SUnstowItemRequestParams: InventoryManagementSurface.sUnstowItemRequestParamsOffsets,
            SEntityUnstowParams: InventoryManagementSurface.sEntityUnstowParamsOffsets,
            SUnstowRequest: InventoryManagementSurface.sUnstowRequestOffsets,
            SSPlitStackRequestParams: InventoryManagementSurface.sSplitStackRequestParamsOffsets,
            SSplitStackRequest: InventoryManagementSurface.sSplitStackRequestOffsets,
            SDeleteItemRequestParams: InventoryManagementSurface.sDeleteItemRequestParamsOffsets,
            SDeleteItemRequest: InventoryManagementSurface.sDeleteItemRequestOffsets,
            SStowEntityRequest: InventoryManagementSurface.sStowEntityRequestOffsets,
            SStowRequest: InventoryManagementSurface.sStowRequestOffsets,
            SDestroyEntityPreconditions: InventoryManagementSurface.sDestroyEntityPreconditionsOffsets,
            SDestroyEntityParam: InventoryManagementSurface.sDestroyEntityParamOffsets,
            SDestroyEntityRequest: InventoryManagementSurface.sDestroyEntityRequestOffsets,
            SOptionalArguments: InventoryManagementSurface.sOptionalArgumentsOffsets,
            IItemPortModificationApiSAttachRequest: InventoryManagementSurface.iItemPortModificationApiAttachRequestOffsets,
            IItemPortModificationApiSDetachRequest: InventoryManagementSurface.iItemPortModificationApiDetachRequestOffsets,
            IItemPortModificationApiSModifyItemPortRequest: InventoryManagementSurface.iItemPortModificationApiModifyItemPortRequestOffsets,
            SInventoryDataRequest: InventoryManagementSurface.sInventoryDataRequestOffsets,
            SPlayerInventoryQuery: InventoryManagementSurface.sPlayerInventoryQueryOffsets,
            SInventoryContainerEntry: InventoryManagementSurface.sInventoryContainerEntryOffsets,
            SInventoryContainerGridItem: InventoryManagementSurface.sInventoryContainerGridItemOffsets,
            SGridItemRequest: InventoryManagementSurface.sGridItemRequestOffsets,
            SInventoryContainerManagerEntriesCache: InventoryManagementSurface.sInventoryContainerManagerEntriesCacheOffsets,
            SInventoryContainerFilterCacheKey: InventoryManagementSurface.sInventoryContainerFilterCacheKeyOffsets,
            SInventoryContainerManagerDataCache: InventoryManagementSurface.sInventoryContainerManagerDataCacheOffsets,
            SInventoryContainerManagerDataCachePair: InventoryManagementSurface.sInventoryContainerManagerDataCachePairOffsets,
            SPersonalInventoryReceivedData: InventoryManagementSurface.sPersonalInventoryReceivedDataOffsets,
            SPersonalInventoryData: InventoryManagementSurface.sPersonalInventoryDataOffsets,
            CInventoryQueryPendingRequest: InventoryManagementSurface.cInventoryQueryPendingRequestOffsets,
            CInventoryOpenPendingRequest: InventoryManagementSurface.cInventoryOpenPendingRequestOffsets,
            CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry: InventoryManagementSurface.cInventoryContainerManagerAsyncQueryInventoryDataSQueryEntryOffsets,
            CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData: InventoryManagementSurface.cInventoryContainerManagerAsyncStowEntitySAsyncStowSharedDataOffsets,
            CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo: InventoryManagementSurface.cInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfoOffsets,
            PersonalThoughtInventoryMoveLocalAttachData: InventoryManagementSurface.personalThoughtInventoryMoveLocalAttachDataOffsets,
            PersonalThoughtInventoryMove: InventoryManagementSurface.personalThoughtInventoryMoveOffsets,
            InventoryUINavigationData: InventoryManagementSurface.inventoryUINavigationDataOffsets,
            InventoryUIMenuOptionData: InventoryManagementSurface.inventoryUIMenuOptionDataOffsets,
            InventoryUICategoryFilterData: InventoryManagementSurface.inventoryUICategoryFilterDataOffsets,
            InventoryUIItemPort: InventoryManagementSurface.inventoryUIItemPortOffsets,
            SInventoryContent: InventoryManagementSurface.sInventoryContentOffsets,
            SInventoryItemKey: InventoryManagementSurface.sInventoryItemKeyOffsets,
            SFreightElevatorRequest: InventoryManagementSurface.sFreightElevatorRequestOffsets,
            CBindingsShopInventoryItem: InventoryManagementSurface.cBindingsShopInventoryItemOffsets,
            SBindingsInventoryItemResourceContents: InventoryManagementSurface.sBindingsInventoryItemResourceContentsOffsets,
            InventoryGridCommonsSBindingsInventoryItemCraftedStat: InventoryManagementSurface.inventoryGridCommonsCraftedStatOffsets,
            SBindingsInventoryItemMenuOptions: InventoryManagementSurface.sBindingsInventoryItemMenuOptionsOffsets,
            SBindingsInventoryItemHologram: InventoryManagementSurface.sBindingsInventoryItemHologramOffsets,
            SBindingsInventoryItemPersistence: InventoryManagementSurface.sBindingsInventoryItemPersistenceOffsets,
            SBindingsInventoryItemDesc: InventoryManagementSurface.sBindingsInventoryItemDescOffsets,
            SBindingsInventoryCustomSubFilter: InventoryManagementSurface.sBindingsInventoryCustomSubFilterOffsets,
            SBindingsInventoryCustomFilter: InventoryManagementSurface.sBindingsInventoryCustomFilterOffsets,
            SBindingsInventoryItemFilter: InventoryManagementSurface.sBindingsInventoryItemFilterOffsets,
            SBindingsInventoryInvalidMoveData: InventoryManagementSurface.sBindingsInventoryInvalidMoveDataOffsets,
            SBindingsInventoryItem: InventoryManagementSurface.sBindingsInventoryItemOffsets,
            SBindingsInventoryContainer: InventoryManagementSurface.sBindingsInventoryContainerOffsets,
            SBindingsInventoryContainerTab: InventoryManagementSurface.sBindingsInventoryContainerTabOffsets,
            SBindingsInventoryPopBox: InventoryManagementSurface.sBindingsInventoryPopBoxOffsets,
            SBindingsInventoryContainerTabMenu: InventoryManagementSurface.sBindingsInventoryContainerTabMenuOffsets,
            SBindingsInventorySection: InventoryManagementSurface.sBindingsInventorySectionOffsets,
            InventoryGridCommonsSBindingsTooltipData: InventoryManagementSurface.inventoryGridCommonsTooltipDataOffsets,
            SBindingsInventoryGridData: InventoryManagementSurface.sBindingsInventoryGridDataOffsets,
            InventoryGridCommonsCSCBaseInventoryGrid: InventoryManagementSurface.inventoryGridCommonsBaseInventoryGridOffsets,
            SBindingsFreightElevatorUI: InventoryManagementSurface.sBindingsFreightElevatorUIOffsets,
            CSCInventoryDisplay: InventoryManagementSurface.cscInventoryDisplayOffsets,
            CEntityComponentFreightElevatorUIProviderSClientData: InventoryManagementSurface.freightElevatorUIProviderClientDataOffsets,
            CEntityComponentFreightElevatorUIProvider: InventoryManagementSurface.freightElevatorUIProviderOffsets,
            CPlayerAssetManagerProvider: InventoryManagementSurface.playerAssetManagerProviderOffsets,
            CSCPersonalThoughtDisplay: InventoryManagementSurface.personalThoughtDisplayOffsets,
            SBindingsLootItemSlotState: InventoryManagementSurface.sBindingsLootItemSlotStateOffsets,
            SBindingsEquipGroupItemPorts: InventoryManagementSurface.sBindingsEquipGroupItemPortsOffsets,
            SBindingsEquipItemPortInfo: InventoryManagementSurface.sBindingsEquipItemPortInfoOffsets,
            SBindingsPITInventoryDragEquipment: InventoryManagementSurface.sBindingsPITInventoryDragEquipmentOffsets,
            SBindingsPITInventoryHoveredCharacterItemInfo: InventoryManagementSurface.sBindingsPITInventoryHoveredCharacterItemInfoOffsets,
            SBindingsPITLootingFocusItem: InventoryManagementSurface.sBindingsPITLootingFocusItemOffsets,
            SBindingsPITLootPortContainerGroup: InventoryManagementSurface.sBindingsPITLootPortContainerGroupOffsets,
            SBindingsPITLootingArmour: InventoryManagementSurface.sBindingsPITLootingArmourOffsets,
            SBindingsPITLootingClothing: InventoryManagementSurface.sBindingsPITLootingClothingOffsets,
            SBindingsPITLootingStorage: InventoryManagementSurface.sBindingsPITLootingStorageOffsets,
            SBindingsPITLootingSection: InventoryManagementSurface.sBindingsPITLootingSectionOffsets,
            SBindingsPITInventoryLooting: InventoryManagementSurface.sBindingsPITInventoryLootingOffsets,
            SBindingsPITInventoryItem: InventoryManagementSurface.sBindingsPITInventoryItemOffsets,
            SBindingsPITInventoryGrid: InventoryManagementSurface.sBindingsPITInventoryGridOffsets,
            SUnstowInfo: InventoryManagementSurface.sUnstowInfoOffsets,
            SStowInfo: InventoryManagementSurface.sStowInfoOffsets,
            SInventoryConfig: InventoryManagementSurface.sInventoryConfigOffsets,
            SInventoryContainerCVars: InventoryManagementSurface.sInventoryContainerCVarsOffsets
        },
        decoders: [
            "DataCoreArrayBase",
            "DCString",
            "CLocIdentifier",
            "STypeSubtypeParams",
            "SItemCategory",
            "SInventoryInteractionBlockingAttachedEntities",
            "SPlayerInventoryDef",
            "SInventoryConfig",
            "SOpenInventory",
            "SLootGeneration",
            "SInventoryContainerCVars",
            "SInventoryId",
            "SInventoryEntity",
            "SInventoryConfiguration",
            "SInventoryContainerDef",
            "SInventoryContainerTypeBaseDef",
            "SInventoryOpenContainerTypeDef",
            "SInventoryOpenAlwaysContainerTypeDef",
            "SInventoryClosedContainerTypeDef",
            "SInventoryContainerItemTypeFilter",
            "SInventoryParams",
            "SInventoryGamePersistentData",
            "SInventoryItemMapEntry",
            "SInventoryContainerUIParams",
            "SInventorySortMode",
            "SInventoryDropDetachRules",
            "SInventoryStateModifier",
            "SStowPolicyCache",
            "SCargoGridOccupantFace",
            "SCargoGridOccupantProperties",
            "SOpenInventoryOccupantItemTypeProperties",
            "SInventoryContainerManagerDef",
            "SInventoryContainerGridCellSizeBase",
            "SInventoryContainerGridCellSizeCentimeters",
            "SInventoryContainerGridCellSizeMeters",
            "SInventoryItemTypes",
            "SInventoryUpdateItem",
            "SStowContext",
            "SStowItemRequestParams",
            "SInventoryManagementRequest",
            "SMoveStackRequest",
            "SMoveItemRequest",
            "SUnstackEntityRequestParams",
            "SUnstackEntityRequest",
            "SMoveEntityStackParam",
            "IInventoryApiSMoveResult",
            "IInventoryApiSMoveRequest",
            "SEntityStackChangeParam",
            "SIncreaseEntityStackRequest",
            "SDecreaseEntityStackRequest",
            "SSetEntityStackRequest",
            "SMoveEntityStackRequest",
            "STransferEntityAggregateRequest",
            "SCreateEntityToInventoryRequest",
            "IInventoryApiSCreateEntityToInventoryRequest",
            "SUnstowItemRequestParams",
            "SEntityUnstowParams",
            "SUnstowRequest",
            "SSPlitStackRequestParams",
            "SSplitStackRequest",
            "SDeleteItemRequestParams",
            "SDeleteItemRequest",
            "SStowEntityRequest",
            "SStowRequest",
            "SDestroyEntityPreconditions",
            "SDestroyEntityParam",
            "SDestroyEntityRequest",
            "SOptionalArguments",
            "IItemPortModificationApiSAttachRequest",
            "IItemPortModificationApiSDetachRequest",
            "IItemPortModificationApiSModifyItemPortRequest",
            "SInventoryDataRequest",
            "SPlayerInventoryQuery",
            "SInventoryContainerEntry",
            "SInventoryContainerGridItem",
            "SGridItemRequest",
            "SInventoryContainerManagerEntry",
            "SInventoryContainerManagerEntriesCache",
            "SInventoryContainerFilterCacheKey",
            "SInventoryContainerManagerDataCache",
            "SInventoryContainerManagerDataCachePair",
            "SPersonalInventoryReceivedData",
            "SPersonalInventoryData",
            "CInventoryQueryPendingRequest",
            "CInventoryOpenPendingRequest",
            "PersonalThoughtInventoryMoveLocalAttachData",
            "PersonalThoughtInventoryMove",
            "InventoryUINavigationData",
            "InventoryUIMenuOptionData",
            "InventoryUIFilterData",
            "InventoryUICategoryFilterData",
            "InventoryUIItemPort",
            "SInventoryContent",
            "SInventoryItemKey",
            "SFreightElevatorRequest",
            "CBindingsShopInventoryItem",
            "SBindingsInventoryItemResourceContents",
            "InventoryGridCommonsSBindingsInventoryItemCraftedStat",
            "SBindingsInventoryItemMenuOptions",
            "SBindingsInventoryItemHologram",
            "SBindingsInventoryItemPersistence",
            "SBindingsInventoryItemDesc",
            "SBindingsInventoryCustomSubFilter",
            "SBindingsInventoryCustomFilter",
            "SBindingsInventoryItemFilter",
            "SBindingsInventoryInvalidMoveData",
            "SBindingsInventoryItem",
            "SBindingsInventoryPopBox",
            "SBindingsInventoryContainerTabMenu",
            "SBindingsInventorySection",
            "InventoryGridCommonsSBindingsTooltipData",
            "SBindingsInventoryGridData",
            "InventoryGridCommonsCSCBaseInventoryGrid",
            "SCFreightKioskInventoryGrid",
            "SBindingsFreightElevatorUI",
            "SBindingsInventoryContainer",
            "SBindingsInventoryContainerTab",
            "CSCInventoryDisplay",
            "CEntityComponentFreightElevatorUIProviderSClientData",
            "CEntityComponentFreightElevatorUIProvider",
            "CPlayerAssetManagerProvider",
            "SBindingsLootItemSlotState",
            "SBindingsEquipItemPortInfo",
            "SBindingsEquipGroupItemPorts",
            "SBindingsPITInventoryDragEquipment",
            "SBindingsPITInventoryHoveredCharacterItemInfo",
            "SBindingsPITLootingFocusItem",
            "SBindingsPITLootPortContainerGroup",
            "SBindingsPITLootingArmour",
            "SBindingsPITLootingClothing",
            "SBindingsPITLootingStorage",
            "SBindingsPITLootingSection",
            "SBindingsPITInventoryLooting",
            "SBindingsPITInventoryItem",
            "SBindingsPITInventoryGrid",
            "CSCPersonalThoughtDisplay",
            "SUnstowInfo",
            "SStowInfo",
            "CInventoryContainerManagerSLootableBox",
            "CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry",
            "CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData",
            "CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo"
        ],
        eventSchemas
    };
}

Object.assign(globalThis, {
    DVec3,
    QuatT,
    QuatTS,
    CEntityClass,
    CZone,
    CPhysicalWorld,
    CPhysicalEntity,
    CRigidEntity,
    CZoneSystem,
    CEntityComponentSystem,
    EntityComponent,
    StdVector,
    StdDeque,
    CigFunctionBase,
    SharedPtr,
    StdFunction,
    DataCoreRecordRef,
    CIGRWLock,
    CIGCriticalSection,
    LockedDeque,
    CSerializedRemoteMethod,
    CSerializedVariable,
    LockedMap,
    ReadWriteLockableValue,
    CDeferredCallbackQueueU64,
    SCigEventSystem,
    SCigEventSystemWithLinks,
    SCigEventDispatcher,
    ILegacyEventSystem,
    ICIGServices,
    ICIGServicesExternal,
    ICIGServicesInternal,
    EInventoryContext,
    EInventoryContainerType,
    EInventoryContainerGridCellSizeUnit,
    EItemOwnershipStatus,
    EInventoryQueryOrderBy,
    EPersonalInventoryOperationType,
    EPlayerInventoryType,
    EInventoryDataRequestType,
    EInventoryRequestResult,
    SInventoryManagementRequestFlags,
    InventoryManagementSurface,
    DataCoreArrayBase,
    DCString,
    CLocIdentifier,
    STypeSubtypeParams,
    SItemCategory,
    SInventoryInteractionBlockingAttachedEntities,
    SPlayerInventoryDef,
    SInventoryConfig,
    SOpenInventory,
    SLootGeneration,
    SInventoryContainerCVars,
    SInventoryId,
    SInventoryEntity,
    SInventoryConfiguration,
    SVec3Def,
    CigVariantI64DoubleCryGuidEntityIdCryString,
    CSCURN,
    SInventoryContainerDef,
    SInventoryContainerTypeBaseDef,
    SInventoryOpenContainerTypeDef,
    SInventoryOpenAlwaysContainerTypeDef,
    SInventoryClosedContainerTypeDef,
    SInventoryContainerItemTypeFilter,
    SInventoryParams,
    SInventoryGamePersistentData,
    SInventoryItemMapEntry,
    SInventoryContainerUIParams,
    SInventorySortMode,
    SInventoryDropDetachRules,
    SInventoryStateModifier,
    SStowPolicyCache,
    SCargoGridOccupantFace,
    SCargoGridOccupantProperties,
    SOpenInventoryOccupantItemTypeProperties,
    SInventoryContainerManagerDef,
    SInventoryContainerGridCellSizeBase,
    SInventoryContainerGridCellSizeCentimeters,
    SInventoryContainerGridCellSizeMeters,
    SInventoryItemTypes,
    SInventoryUpdateItem,
    SStowContext,
    SStowItemRequestParams,
    EastlOptionalInventoryConfiguration,
    CTagList,
    SEntityLocationInfo,
    STraceId,
    SCargoAmount,
    SPaginationArguments,
    SPaginationInfo,
    SInventoryEntry,
    SGridBox,
    SLootRequest,
    SInventoryContainerItemGenerationRequest,
    ContainerPackingSFreeSpace,
    OBBd,
    ContainerPackingSItem,
    ContainerPackingSContainer,
    ContainerPackingSPackingPlan,
    SSerializeableFreeSpace,
    SItemPortId,
    SInventoryManagementRequestClassItemRank,
    SInventoryContainerEntry,
    SPlayerInventoryQuery,
    SGridItemRequest,
    SMoveStackRequest,
    SMoveItemRequest,
    SUnstackEntityRequestParams,
    SUnstackEntityRequest,
    SMoveEntityStackParam,
    IInventoryApiSMoveResult,
    IInventoryApiSMoveRequest,
    EntityGraphSChangeRankParam,
    EntityGraphSMoveParam,
    EntityGraphSMoveAllParam,
    EntityGraphSAttachEntry,
    EntityGraphSAttachParam,
    EntityGraphSDetachEntry,
    EntityGraphSDetachParam,
    EntityGraphSChangeSnapshotParam,
    EntityGraphSEraseParam,
    SEntityStackChangeRequest,
    SIncreaseEntityStackRequest,
    SDecreaseEntityStackRequest,
    SSetEntityStackRequest,
    SMoveEntityStackRequest,
    STransferEntityAggregateRequest,
    SCreateEntityToInventoryRequest,
    IInventoryApiSCreateEntityToInventoryRequest,
    SUnstowItemRequestParams,
    SEntityUnstowParams,
    SUnstowInfo,
    SStowInfo,
    SUnstowRequest,
    SSPlitStackRequestParams,
    SSplitStackRequestParams,
    SSplitStackRequest,
    SDeleteItemRequestParams,
    SDeleteItemRequest,
    SInventoryManagementRequest,
    SInventoryDataRequest,
    SInventoryContainerManagerEntriesCache,
    SInventoryContainerFilterCacheKey,
    SInventoryContainerManagerDataCache,
    SInventoryContainerManagerDataCachePair,
    EntityGraphQueryFilterParams,
    SInventoryEntityQuery,
    SInventoryQueryResultInventory,
    SInventoryQueryResult,
    SInventoryQueryResponse,
    SInventoryQueryResultInfo,
    CInventoryQueryPendingRequest,
    CInventoryOpenPendingRequest,
    CInventoryContainerManagerSLootableBox,
    CInventoryContainerManagerAsyncQueryInventoryDataSQueryEntry,
    CInventoryContainerManagerAsyncStowEntitySAsyncStowSharedData,
    CInventoryContainerManagerProcessPendingInventoryContainerOpensSUnstowRequestInfo,
    LockedOpenPendingRequests,
    SPersonalInventoryReceivedData,
    SPersonalInventoryData,
    InventoryUIData,
    InventoryUINavigationData,
    InventoryUIMenuOptionData,
    InventoryUIFilterData,
    InventoryUICategoryFilterData,
    InventoryUIItemPort,
    SInventoryContent,
    SInventoryItemKey,
    SFreightElevatorRequest,
    CBindingsShopInventoryItem,
    SBindingsInventoryItemResourceContents,
    InventoryGridCommonsSBindingsInventoryItemCraftedStat,
    SBindingsInventoryItemMenuOptions,
    SBindingsInventoryItemHologram,
    SBindingsInventoryItemPersistence,
    SBindingsInventoryItemDesc,
    SBindingsInventoryCustomSubFilter,
    SBindingsInventoryCustomFilter,
    SBindingsInventoryItemFilter,
    SBindingsInventoryInvalidMoveData,
    SBindingsInventoryItem,
    SBindingsInventoryPopBox,
    SBindingsInventoryContainerTabMenu,
    SBindingsInventorySection,
    InventoryGridCommonsSBindingsTooltipData,
    SBindingsInventoryGridData,
    InventoryGridCommonsCSCBaseInventoryGrid,
    SCFreightKioskInventoryGrid,
    SBindingsFreightElevatorUI,
    SBindingsInventoryContainer,
    SBindingsInventoryContainerTab,
    CSCInventoryDisplay,
    CEntityComponentFreightElevatorUIProviderSClientData,
    CEntityComponentFreightElevatorUIProvider,
    CPlayerAssetManagerProvider,
    SBindingsLootItemSlotState,
    SBindingsEquipItemPortInfo,
    SBindingsEquipGroupItemPorts,
    SBindingsPITInventoryDragEquipment,
    SBindingsPITInventoryHoveredCharacterItemInfo,
    SBindingsPITLootingFocusItem,
    SBindingsPITLootPortContainerGroup,
    SBindingsPITLootingArmour,
    SBindingsPITLootingClothing,
    SBindingsPITLootingStorage,
    SBindingsPITLootingSection,
    SBindingsPITInventoryLooting,
    SBindingsPITInventoryItem,
    SBindingsPITInventoryGrid,
    CSCPersonalThoughtDisplay,
    CStringHash,
    InteractionPointId,
    InventoryItemWeakenedData,
    InventoryItemDataDesc,
    InventoryItemData,
    SelectedInventoryThoughtOption,
    InventoryGridThoughtOption,
    PersonalThoughtInventoryLocalPageInfo,
    PersonalThoughtInventoryContainer,
    PersonalThoughtInventorySectionTab,
    PersonalThoughtLootingTabInventory,
    PersonalThoughtLootingInventoryData,
    PersonalThoughtInventorySection,
    PersonalThoughtSectionState,
    PersonalThoughtInventorySectionsAndContainers,
    PersonalThoughtSelectedThoughtOption,
    PersonalThoughtOption,
    PersonalThoughtPITFavorite,
    PersonalThoughtQuickAccessMenu,
    PersonalThoughtInventoryMoveLocalAttachData,
    PersonalThoughtInventoryMove,
    PersonalThoughtDragItem,
    PersonalThoughtSoftAttachItemInfo,
    PersonalThoughtSwapPortDraggedItem,
    PersonalThoughtPendingSwapItem,
    PersonalThoughtLootingEquipment,
    SInventoryContainerGridItem,
    SInventoryContainerManagerEntry,
    SInventoryContainerManagerData,
    SInventoryUpdateContext,
    SEntityStackChangeParam,
    SStowEntityRequest,
    SStowRequest,
    SDestroyEntityPreconditions,
    SDestroyEntityParam,
    SDestroyEntityRequest,
    SOptionalArguments,
    IItemPortModificationApiSAttachRequest,
    IItemPortModificationApiSDetachRequest,
    IItemPortModificationApiSModifyItemPortRequest,
    CInventoryContainerComponentSCargoGridLockData,
    CInventoryContainerComponentSSerializedAndLockedCargoGridsLocks,
    SInventoryEventListener,
    LockedInventoryEventListeners,
    CInventoryContainerComponentSOpenAttachmentOcclusionDebug,
    CInventoryContainerComponent,
    CSCLocalPlayerPersonalThoughtComponent,
    CSCPlayerInventory,
    IInventoryContainerManager,
    IPlatformInventoryManager,
    IPlayerInventoryManager,
    ISCActorInventory,
    CSCActorInventory,
    IInventoryApi,
    IInventoryManagementApi,
    IInventoryManagementApiSQueryFiltersContext,
    IInventoryManagementApiSQueryFilters,
    IInventoryManagementApiSUpdateInventoryRequest,
    IItemPortModificationApi,
    IMissionSystem,
    IMissionService,
    EProfiledSubsystem,
    EActorStatType,
    EHealthChangeReason,
    EInvulnerableFlags,
    CSCBodyHealthComponentSurface,
    EMissionObjectiveStates,
    MissionServiceInternalSurface,
    SMissionObjectiveContributor,
    SMissionObjective,
    SUpsertObjectiveRequest,
    IMissionServiceInternal,
    SMissionProperty,
    MissionObjective,
    PendingMissionObjective,
    ActiveMissionObjective,
    CompletedMissionObjective,
    SObjectiveTokenPropertyLink,
    SObjectiveToken,
    SMissionUIDisplayInfo,
    SMissionEntryDetails,
    CMissionLogEntry,
    SRegisteredObjectiveMarker,
    CSCPlayerMissionLog,
    CPhysicalProxy,
    SDamageInfo,
    CBindingsVariableFloat,
    CSCBodyHealthSPartIdCache,
    CSCBodyHealthSBodyPart,
    SRecentAttackerData,
    CSCBodyHealthComponent,
    CRenderProxy,
    CActor,
    CEntity,
    CActorEntity,
    QuatTFloat,
    BoneId,
    BoneList,
    BoneConnections,
    boneProbeEntity,
    boneProbe,
    foobar,
    EPE_Action,
    EPEActionMoveMode,
    PEActionMove,
    CEntityArray,
    CEntityClassRegistry,
    CEntitySystem,
    entitySystemSurface,
    entitySystemCoverageAudit,
    entitySystemSmokeTest,
    entityClassRegistryState,
    entityClassByName,
    entityClassByCrc,
    entityClassByGuid,
    findEntityClasses,
    registeredComponents,
    registeredComponentIds,
    entityComponents,
    findEntities,
    findEntitiesOfKind,
    bodyHealthSurface,
    bodyHealthState,
    CRenderer,
    CSystem,
    CGame,
    CSCPlayer,
    GEnv,
    gEnv,
    player,
    scPlayer,
    currentActorEntity,
    currentAnimatedCharacter,
    actorPathSurface,
    actorEntityMovementState,
    setActorEntityMovementFields,
    setActorWalkingSpeed,
    ECharacterMoveType,
    SMotionParameters,
    SCharacterMoveRequest,
    CAnimatedCharacter,
    actorActionMoveSurface,
    installActorActionMoveHook,
    installActorActionMoveMonitor,
    installActorActionMoveSpeedHook,
    uninstallActorActionMoveHook,
    actorActionMoveHookState,
    animatedCharacterMovementSurface,
    installAnimatedCharacterAddMovementHook,
    installAnimatedCharacterMovementMonitor,
    installAnimatedCharacterMovementSpeedHook,
    uninstallAnimatedCharacterAddMovementHook,
    animatedCharacterAddMovementHookState,
    installActorDamageNullHook,
    uninstallActorDamageNullHook,
    actorDamageNullHookState,
    installActorKillNullHook,
    uninstallActorKillNullHook,
    actorKillNullHookState,
    actorHealthHitSurface,
    actorHealthState,
    restoreActorHealth,
    installActorHealthHitNullHook,
    uninstallActorHealthHitNullHook,
    actorHealthHitNullHookState,
    installActorDamageAndKillNullHooks,
    uninstallActorDamageAndKillNullHooks,
    ActorDamageToKillType,
    EHitType,
    SPlayerDamageReport,
    SKillParams,
    HitInfo,
    entities,
    entitySystemSurface,
    entityClassRegistryState,
    registeredComponents,
    entityComponents,
    findEntities,
    findByClassName,
    listPlayers,
    playerMissionLog,
    listContracts,
    auditContracts,
    missionLogState,
    missionSystemState,
    resolveInventoryApi,
    inventoryManagementSurface,
    inventoryOperationSurface,
    inventoryCoverageAudit,
    playerInventorySurface,
    playerInventoryState,
    playerInventoryOperations,
    playerPersonalThoughtComponent,
    playerPersonalThoughtState,
    findPersonalThoughtComponents,
    inventoryManagementQueueState,
    inventoryPathState,
    inventoryApiSurface,
    inventoryContainerManagerState,
    listInventoryContainers,
    auditInventoryManagement,
    buildInventoryId,
    getEntireInventoryQuery,
    inventoryContainerIsUserStowValid,
    inventoryContainerIsItemTypePermissible,
    inventoryContainerOccupantProperties,
    inventoryContainerSnapshot,
    inventoryContainerEntireQuery,
    inventoryContainerByEntityId,
    listInventoryContainerContents,
    cancelInventoryCallback,
    installInventoryQueryHooks,
    uninstallInventoryQueryHooks,
    inventoryQueryHookSamples,
    upsertObjectiveSurface,
    verifyUpsertObjectiveSurface,
    findActiveMissionObjective,
    resolveMissionServiceInternal,
    UpsertObjectiveFieldWriters,
    normalizeObjectiveUpsertFields,
    previewUpsertObjective,
    upsertObjective,
    previewUpsertObjectiveLocalization,
    upsertObjectiveLocalization,
    ent,
    physent,
    rigent,
    zone,
    entclass,
    entcomp,
    bodyhealth,
    inventoryapi,
    itemportmodapi,
    inventorycontainer,
    personalthought,
    inventorymanagementrequest,
    inventorydatarequest,
    inventorycontainerdef,
    inventoryupdateitem,
    stowcontext,
    stowitemrequestparams,
    inventoryuiitemport,
    decodeInventoryStruct,
    decodeInventoryEvent,
    InventoryEventSchemas,
    inventoryDecoderSurface
});

NativePointer.prototype.ent = function() { return new CEntity(this); };
NativePointer.prototype.physent = function() { return new CPhysicalEntity(this); };
NativePointer.prototype.rigent = function() { return new CRigidEntity(this); };

NativePointer.prototype.actor = function() { return new CActor(this); };
NativePointer.prototype.boneprobe = function(options = {}) { return boneProbeEntity(this, options); };
NativePointer.prototype.actorent = function() { return new CActorEntity(this); };
NativePointer.prototype.peactionmove = function() { return new PEActionMove(this); };
NativePointer.prototype.charactermoverequest = function() { return new SCharacterMoveRequest(this); };
NativePointer.prototype.animatedcharacter = function() { return new CAnimatedCharacter(this); };
NativePointer.prototype.playerdamagereport = function() { return new SPlayerDamageReport(this); };
NativePointer.prototype.killparams = function() { return new SKillParams(this); };
NativePointer.prototype.hitinfo = function() { return new HitInfo(this); };
NativePointer.prototype.zone = function() { return new CZone(this); };
NativePointer.prototype.entclass = function() { return new CEntityClass(this); };
NativePointer.prototype.entcomp = function(componentName = "Unknown") { return new EntityComponent(this, componentName); };
NativePointer.prototype.bodyhealth = function() { return new CSCBodyHealthComponent(this); };
NativePointer.prototype.inventoryapi = function() { return new IInventoryApi(this); };
NativePointer.prototype.itemportmodapi = function() { return new IItemPortModificationApi(this); };
NativePointer.prototype.inventorycontainermanager = function() { return new IInventoryContainerManager(this); };
NativePointer.prototype.inventorymanagementapi = function() { return new IInventoryManagementApi(this); };
NativePointer.prototype.inventoryid = function() { return new SInventoryId(this); };
NativePointer.prototype.inventoryentityquery = function() { return new SInventoryEntityQuery(this); };
NativePointer.prototype.inventoryqueryresponse = function() { return new SInventoryQueryResponse(this); };
NativePointer.prototype.inventoryqueryresult = function() { return new SInventoryQueryResult(this); };
NativePointer.prototype.inventorycontainer = function() { return new CInventoryContainerComponent(this); };
NativePointer.prototype.personalthought = function() { return new CSCLocalPlayerPersonalThoughtComponent(this); };
NativePointer.prototype.inventorymanagementrequest = function() { return new SInventoryManagementRequest(this); };
NativePointer.prototype.inventorydatarequest = function() { return new SInventoryDataRequest(this); };
NativePointer.prototype.inventorycontainerdef = function() { return new SInventoryContainerDef(this); };
NativePointer.prototype.inventoryupdateitem = function() { return new SInventoryUpdateItem(this); };
NativePointer.prototype.griditemrequest = function() { return new SGridItemRequest(this); };
NativePointer.prototype.stowcontext = function() { return new SStowContext(this); };
NativePointer.prototype.stowitemrequestparams = function() { return new SStowItemRequestParams(this); };
NativePointer.prototype.inventoryuiitemport = function() { return new InventoryUIItemPort(this); };
NativePointer.prototype.inventoryitemkey = function() { return new SInventoryItemKey(this); };
NativePointer.prototype.freightelevatorrequest = function() { return new SFreightElevatorRequest(this); };
NativePointer.prototype.shopinventoryitem = function() { return new CBindingsShopInventoryItem(this); };
NativePointer.prototype.bindingsinventoryitem = function() { return new SBindingsInventoryItem(this); };
NativePointer.prototype.bindingsinventoryitemfilter = function() { return new SBindingsInventoryItemFilter(this); };
NativePointer.prototype.bindingsinventorygriddata = function() { return new SBindingsInventoryGridData(this); };
NativePointer.prototype.bindingsinventorysection = function() { return new SBindingsInventorySection(this); };
NativePointer.prototype.inventorygridbase = function() { return new InventoryGridCommonsCSCBaseInventoryGrid(this); };
NativePointer.prototype.freightkioskinventorygrid = function() { return new SCFreightKioskInventoryGrid(this); };
NativePointer.prototype.bindingsfreightelevatorui = function() { return new SBindingsFreightElevatorUI(this); };
NativePointer.prototype.bindingsinventorycontainer = function() { return new SBindingsInventoryContainer(this); };
NativePointer.prototype.bindingsinventorycontainertab = function() { return new SBindingsInventoryContainerTab(this); };
NativePointer.prototype.inventorydisplay = function() { return new CSCInventoryDisplay(this); };
NativePointer.prototype.freightelevatoruiprovider = function() { return new CEntityComponentFreightElevatorUIProvider(this); };
NativePointer.prototype.assetmanagerprovider = function() { return new CPlayerAssetManagerProvider(this); };
NativePointer.prototype.lootitemslotstate = function() { return new SBindingsLootItemSlotState(this); };
NativePointer.prototype.equipitemportinfo = function() { return new SBindingsEquipItemPortInfo(this); };
NativePointer.prototype.equipgroupitemports = function() { return new SBindingsEquipGroupItemPorts(this); };
NativePointer.prototype.pitinventorydragequipment = function() { return new SBindingsPITInventoryDragEquipment(this); };
NativePointer.prototype.pithoveredcharacteritem = function() { return new SBindingsPITInventoryHoveredCharacterItemInfo(this); };
NativePointer.prototype.pitlootingfocusitem = function() { return new SBindingsPITLootingFocusItem(this); };
NativePointer.prototype.pitlootportcontainergroup = function() { return new SBindingsPITLootPortContainerGroup(this); };
NativePointer.prototype.pitlootingsection = function() { return new SBindingsPITLootingSection(this); };
NativePointer.prototype.pitinventorylooting = function() { return new SBindingsPITInventoryLooting(this); };
NativePointer.prototype.pitinventoryitem = function() { return new SBindingsPITInventoryItem(this); };
NativePointer.prototype.pitinventorygrid = function() { return new SBindingsPITInventoryGrid(this); };
NativePointer.prototype.personalthoughtdisplay = function() { return new CSCPersonalThoughtDisplay(this); };
NativePointer.prototype.stddeque = function(elemSize, ElemClass = null) { return new StdDeque(this, elemSize, ElemClass); };

rpc.exports = {
    listcontracts(includeObjectives = true, includeNestedDetails = false) {
        return listContracts(includeObjectives, includeNestedDetails);
    },
    auditcontracts() {
        return auditContracts();
    },
    missionlog() {
        return missionLogState();
    },
    missionsystem() {
        return missionSystemState();
    },
    inventorymanagementsurface() {
        return inventoryManagementSurface();
    },
    inventoryoperationsurface() {
        return inventoryOperationSurface();
    },
    inventorycoverageaudit() {
        return inventoryCoverageAudit();
    },
    inventorydecodersurface() {
        return inventoryDecoderSurface();
    },
    decodeinventorystruct(type, ptrValue, includeNested = false) {
        return decodeInventoryStruct(type, ptrValue, includeNested);
    },
    decodeinventoryevent(type, ptrValue, includeNested = false) {
        return decodeInventoryEvent(type, ptrValue, includeNested);
    },
    playerinventorysurface() {
        return playerInventorySurface();
    },
    playerinventory(includeDetails = true) {
        return playerInventoryState(includeDetails);
    },
    playerinventoryoperations(limit = 8, includeNested = false) {
        return playerInventoryOperations(limit, includeNested);
    },
    playerpersonalthought(includeNested = false, scanFallback = true) {
        return playerPersonalThoughtState(includeNested, scanFallback);
    },
    findpersonalthoughtcomponents(limit = 512) {
        return findPersonalThoughtComponents(limit).map(match => ({
            entityId: String(match.entity.id),
            entityName: match.entity.name,
            className: match.entity.entityClass?.name ?? null,
            componentName: match.componentName,
            componentPtr: match.component.ptr.toString()
        }));
    },
    inventorymanagementqueue(limit = 0, includeNested = false) {
        return inventoryManagementQueueState(limit, includeNested);
    },
    inventorypathstate(limit = 8, includeNested = false) {
        return inventoryPathState(limit, includeNested);
    },
    inventoryapisurface() {
        return inventoryApiSurface();
    },
    inventorycontainermanager(includeDetails = true) {
        return inventoryContainerManagerState(includeDetails);
    },
    auditinventorymanagement(options = {}) {
        return auditInventoryManagement(options);
    },
    listinventorycontainers(includeGridItems = false, limit = 64) {
        return listInventoryContainers(includeGridItems, limit);
    },
    buildinventoryid(holderEntityId, context = 0, subject = "0") {
        return buildInventoryId(holderEntityId, context, subject);
    },
    getentireinventoryquery(entityId, context = 0, subject = "0") {
        return getEntireInventoryQuery(entityId, context, subject);
    },
    inventorycontainerentirequery(entityId, context = 0) {
        return inventoryContainerEntireQuery(entityId, context);
    },
    isuserstowvalid(userEntityId, targetHolderEntityId, targetContext = 0, targetSubject = "0", entityIEntityPtr = "0") {
        return inventoryContainerIsUserStowValid(userEntityId, targetHolderEntityId, targetContext, targetSubject, entityIEntityPtr);
    },
    isitemtypepermissibleininventory(containerDefPtr, itemDefinitionPtr) {
        return inventoryContainerIsItemTypePermissible(containerDefPtr, itemDefinitionPtr);
    },
    inventorycontaineroccupantproperties() {
        return inventoryContainerOccupantProperties();
    },
    inventorycontainersnapshot(entityId, options = {}) {
        return inventoryContainerSnapshot(entityId, options);
    },
    inventorycontainerbyentityid(entityId, options = {}) {
        return inventoryContainerByEntityId(entityId, options);
    },
    listinventorycontainercontents(options = {}) {
        return listInventoryContainerContents(options);
    },
    cancelinventorycallback(requestId) {
        return cancelInventoryCallback(requestId);
    },
    installinventoryqueryhooks(options = {}) {
        return installInventoryQueryHooks(options);
    },
    uninstallinventoryqueryhooks() {
        return uninstallInventoryQueryHooks();
    },
    inventoryqueryhooksamples(clear = false) {
        return inventoryQueryHookSamples(clear);
    },
    inventoryqueryhookstate() {
        return inventoryQueryHookState_();
    },
    entitysystemsurface(options = {}) {
        return entitySystemSurface(options);
    },
    entitysystemcoverageaudit(includeLive = false) {
        return entitySystemCoverageAudit(includeLive);
    },
    entitysystemsmoketest(options = {}) {
        return entitySystemSmokeTest(options);
    },
    entityclassregistry(limit = 64, includeComponents = false) {
        return entityClassRegistryState(limit, includeComponents);
    },
    entityclassbyname(name, includeComponents = false) {
        return entityClassByName(name, includeComponents);
    },
    entityclassbycrc(classCrc, includeComponents = false) {
        return entityClassByCrc(classCrc, includeComponents);
    },
    entityclassbyguid(classGuid, includeComponents = false) {
        return entityClassByGuid(classGuid, includeComponents);
    },
    findentityclasses(pattern, scanLimit = 32768, includeComponents = false, resultLimit = 256) {
        return findEntityClasses(pattern, scanLimit, includeComponents, resultLimit);
    },
    registeredcomponents(maxId = null, allowRangeFallback = false) {
        return registeredComponents(maxId, allowRangeFallback);
    },
    registeredcomponentids(maxId = null, allowRangeFallback = false) {
        return registeredComponentIds(maxId, allowRangeFallback);
    },
    entitycomponents(entityId = null, options = {}) {
        return entityComponents(entityId, options);
    },
    findentities(options = {}) {
        return findEntities(options);
    },
    findentitiesofkind(kind, options = {}) {
        return findEntitiesOfKind(kind, options);
    },
    bodyhealthsurface(entityId = null, includeAddresses = true) {
        return bodyHealthSurface(entityId, includeAddresses);
    },
    bodyhealthstate(entityId = null, options = {}) {
        return bodyHealthState(entityId, options);
    },
    upsertobjectivesurface() {
        return upsertObjectiveSurface();
    },
    verifyupsertobjectivesurface() {
        return verifyUpsertObjectiveSurface();
    },
    previewupsertobjective(args = {}) {
        return previewUpsertObjective(args);
    },
    upsertobjective(args = {}) {
        return upsertObjective(args);
    },
    previewupsertobjectivelocalization(args = {}) {
        return previewUpsertObjectiveLocalization(args);
    },
    upsertobjectivelocalization(args = {}) {
        return upsertObjectiveLocalization(args);
    },
    actorpathsurface() {
        return actorPathSurface();
    },
    actoractionmovesurface() {
        return actorActionMoveSurface();
    },
    actorentitymovement() {
        return actorEntityMovementState();
    },
    setactorentitymovement(args = {}) {
        return setActorEntityMovementFields(args);
    },
    setactorwalkingspeed(args = {}) {
        return setActorWalkingSpeed(args);
    },
    installactoractionmovehook(args = {}) {
        return installActorActionMoveHook(args);
    },
    installactoractionmovemonitor(args = {}) {
        return installActorActionMoveMonitor(args);
    },
    installactoractionmovespeedhook(args = {}) {
        return installActorActionMoveSpeedHook(args);
    },
    uninstallactoractionmovehook() {
        return uninstallActorActionMoveHook();
    },
    actoractionmovehookstate() {
        return actorActionMoveHookState();
    },
    animatedcharactermovementsurface() {
        return animatedCharacterMovementSurface();
    },
    installanimatedcharacteraddmovementhook(args = {}) {
        return installAnimatedCharacterAddMovementHook(args);
    },
    installanimatedcharactermovementmonitor(args = {}) {
        return installAnimatedCharacterMovementMonitor(args);
    },
    installanimatedcharactermovementspeedhook(args = {}) {
        return installAnimatedCharacterMovementSpeedHook(args);
    },
    uninstallanimatedcharacteraddmovementhook() {
        return uninstallAnimatedCharacterAddMovementHook();
    },
    animatedcharacteraddmovementhookstate() {
        return animatedCharacterAddMovementHookState();
    },
    installactordamagenullhook(args = {}) {
        return installActorDamageNullHook(args);
    },
    uninstallactordamagenullhook() {
        return uninstallActorDamageNullHook();
    },
    actordamagenullhookstate() {
        return actorDamageNullHookState();
    },
    installactorkillnullhook(args = {}) {
        return installActorKillNullHook(args);
    },
    uninstallactorkillnullhook() {
        return uninstallActorKillNullHook();
    },
    actorkillnullhookstate() {
        return actorKillNullHookState();
    },
    actorhealthhitsurface() {
        return actorHealthHitSurface();
    },
    actorhealthstate() {
        return actorHealthState();
    },
    restoreactorhealth(reason = 1) {
        return restoreActorHealth(reason);
    },
    installactorhealthhitnullhook(args = {}) {
        return installActorHealthHitNullHook(args);
    },
    uninstallactorhealthhitnullhook() {
        return uninstallActorHealthHitNullHook();
    },
    actorhealthhitnullhookstate() {
        return actorHealthHitNullHookState();
    },
    installactordamageandkillnullhooks(args = {}) {
        return installActorDamageAndKillNullHooks(args);
    },
    uninstallactordamageandkillnullhooks() {
        return uninstallActorDamageAndKillNullHooks();
    }
};

console.log("[*] star.js loaded");

// -------------------------------------------------------------------------------------------
// ANY "EXPLORATORY STUFF" MUST BE BELOW, ABOVE MUST ONLY BE CONFIRMED STRUCTURES
// -------------------------------------------------------------------------------------------
//
//rpc.exports.actorhealthstate();
//rpc.exports.restoreactorhealth();
//rpc.exports.installactorhealthhitnullhook({
//    suppressAll: true,
//    restoreHealth: true,
//    sampleLimit: 16
//});
//rpc.exports.setactorwalkingspeed({ scale: 5.5, sampleLimit: 32 });

Interceptor.attach(
    ptr(0x147741480),
    {
        onEnter(args) {
            const that = args[0];
            const sRpcName = args[1];
            const sData = args[2];
            const handlers = args[0];

            console.log('--' + sRpcName.readPointer().readCString() + ' x ' + sData.readPointer().readCString());
        }
    }
);

(() => {
    const x = ptr('0x147740dc0');

    Interceptor.attach(
        x,
        {
            onEnter(args) {
                const that = args[0];
                const sRpcName = args[1];
                const sData = args[2];
                const handlers = args[0];

                console.log('--' + sRpcName.readPointer().readCString() + ' x ' + sData.readPointer().readCString());
            }
        }
    );
})();

'use strict';

const FN_ENTRY   = ptr('0x146763C70');
const FN_AFTER_SPILL = ptr('0x146763C78');  // after vmovss [rax+10h], xmm1

// Capture `this` at entry (RCX), and dt at post-spill point
const thisByThread = new Map();

Interceptor.attach(FN_ENTRY, {
    onEnter(args) {
        thisByThread.set(this.threadId, {
            self: args[0],
            ts: Date.now(),
        });
    }
});
