'use strict';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const RVAS = {
    // ?SendRemoteMethodCall@CSerializedComponent@@...
    SendRemoteMethodCall: 0x2A5B330,
};

// SSerializedRemoteMethodReg, sizeof 0x40. Offsets confirmed against decompile.
const REG_SIZE = 0x40;
const REG_NAME = 0x00; // CryStringT<char>::m_str -> char*
const REG_COMPONENT = 0x0C; // u16, key for GetComponentName/SubSystem
const REG_DIRECTION = 0x10; // u32, switch 0/1/2
const REG_MODE = 0x14; // u8,  compared ==1 / ==2
const REG_DISPATCH = 0x18; // SRemoteMethodBase* m_pRemoteMethod
const REG_ARGDISP = 0x20; // arg serializer: [0]=sizeInBits(args), [1]=serialize
const REG_STATS = 0x28; // counter obj: +0x28 calls, +0x2C accumulated bytes
const REG_GATE = 0x30; // ptr; +0x8D byte gates direction routing
const REG_DIRTY = 0x3C; // u16, dirty-flags variable index

// CSerializedComponent layout (table region used for id-indexed lookup).
const TABLE_BEGIN = 0x98;
const TABLE_END = 0xA0;

const MAX_TABLE_SPAN = 1 << 22;
const MAX_NAME_LEN = 512;

const DUMP_ARGS = true;
const ARG_DUMP_LEN = 48;
const MEASURE_ARG_BITS = true; // calls vtable[0] on the arg-serializer; size-only, no side effects per decompile

// Substring filters against the resolved method name. Empty = no filtering.
// '<unresolved>' entries bypass both lists so they are never hidden.
const SHOW_ONLY = [];
const SUPPRESS = [
    'CSCActorActionHandler::RmAuthoritySendActions'
];

// ---------------------------------------------------------------------------
// Triage mode: builds a per-method profile so decoder targets can be picked
// from real traffic. Live logging is unchanged; triage runs alongside it.
// ---------------------------------------------------------------------------

const TRIAGE_ENABLED = false;
const TRIAGE_PATH = '/tmp/diffusion_rpc_triage.json';
const TRIAGE_FLUSH_EVERY = 2000; // total RMI sends between auto-flushes
const TRIAGE_FP_HEX_LEN = 32; // bytes of raw argRefs captured on first sight
const TRIAGE_SLOT_PROBE = 4; // pointer slots in argRefs to deref
const TRIAGE_SLOT_HEAD_LEN = 16; // bytes read from each derefed slot
const TRIAGE_SIZE_SAMPLES = 32; // measureArgBits calls per reg (min/max only need a handful)

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

const mainModule = Process.enumerateModules()[0];
const base = mainModule.base;
const rva = (offset) => base.add(offset);

console.log(`[+] module=${mainModule.name} base=${base}`);

// ---------------------------------------------------------------------------
// Safe memory readers
// ---------------------------------------------------------------------------

function readPointer(address) {
    try {
        return (address && !address.isNull()) ? address.readPointer() : NULL;
    } catch (_) {
        return NULL;
    }
}

function readU8(address) {
    try {
        return address.readU8();
    } catch (_) {
        return -1;
    }
}

function readU16(address) {
    try {
        return address.readU16();
    } catch (_) {
        return -1;
    }
}

function readU32(address) {
    try {
        return address.readU32();
    } catch (_) {
        return -1;
    }
}

function readHex(address, length) {
    if (!address || address.isNull()) return '';
    const bytes = [];
    for (let i = 0; i < length; i++) {
        const value = readU8(address.add(i));
        if (value < 0) break;
        bytes.push(value.toString(16).padStart(2, '0'));
    }
    return bytes.join(' ');
}

// ---------------------------------------------------------------------------
// Name resolution (CryStringT is a single char*, so one deref reaches the text)
// ---------------------------------------------------------------------------

const nameCache = new Map();

function readName(stringPointer) {
    if (!stringPointer || stringPointer.isNull()) return null;

    const key = stringPointer.toString();
    if (nameCache.has(key)) return nameCache.get(key);

    let name = null;

    // Null-terminated read first: never over-reads past the terminator, so it
    // can't fault on a string that sits near a page boundary.
    try {
        const raw = stringPointer.readUtf8String();
        if (raw && raw.length >= 3 && raw.length < MAX_NAME_LEN && /^[\x20-\x7e]+$/.test(raw)) {
            name = raw;
        }
    } catch (_) {
        // Fallback: byte-by-byte up to the terminator, tolerant of page-crossing.
        name = readNameBytewise(stringPointer);
    }

    nameCache.set(key, name);
    return name;
}

function readNameBytewise(stringPointer) {
    const bytes = [];
    for (let i = 0; i < MAX_NAME_LEN; i++) {
        const value = readU8(stringPointer.add(i));
        if (value < 0) return null; // hit unmapped memory before terminator
        if (value === 0) break; // end of string
        if (value < 0x20 || value > 0x7e) return null; // not an RMI name
        bytes.push(value);
    }
    if (bytes.length < 3 || bytes.length >= MAX_NAME_LEN) return null;
    return String.fromCharCode.apply(null, bytes);
}

// ---------------------------------------------------------------------------
// Table resolution
// ---------------------------------------------------------------------------

const tableCache = new Map();

let resolveFailCount = 0;
const RESOLVE_FAIL_LOG_LIMIT = 20;

function resolveTable(thisPointer) {
    if (!thisPointer || thisPointer.isNull()) return null;

    const begin = readPointer(thisPointer.add(TABLE_BEGIN));
    const end = readPointer(thisPointer.add(TABLE_END));

    if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return null;
    try {
        const span = end.sub(begin).toUInt32();
        if (span > 0 && span <= MAX_TABLE_SPAN && (span % REG_SIZE) === 0) {
            return { begin, end, count: span / REG_SIZE };
        }
    } catch (_) {}
    return null;
}

function registrationAt(thisPointer, id) {
    const table = resolveTable(thisPointer);
    if (!table || id < 0 || id >= table.count) return null;
    return table.begin.add(id * REG_SIZE);
}

// ---------------------------------------------------------------------------
// Registration decode
// ---------------------------------------------------------------------------

function directionName(value) {
    return {
        0: 'Default',
        1: 'Dir1',
        2: 'Dir2'
    } [value] || `Dir${value}`;
}

function modeName(value) {
    return {
        0: 'Local',
        1: 'Respond',
        2: 'RemoteRespond'
    } [value] || `Mode${value}`;
}

function sourceName(value) {
    return {
        0: 'Local',
        1: 'Respond',
        2: 'Remote'
    } [value] || 'Unknown';
}

function readRegistration(thisPointer, id) {
    const reg = registrationAt(thisPointer, id);
    if (!reg) {
        return {
            reg: NULL,
            name: null
        };
    }

    const namePointer = readPointer(reg.add(REG_NAME));
    const name = readName(namePointer);
    const stats = readPointer(reg.add(REG_STATS));
    const gate = readPointer(reg.add(REG_GATE));

    return {
        reg,
        name,
        namePointer,
        nameBytes: name ? '' : readHex(namePointer, 32),
        componentId: readU16(reg.add(REG_COMPONENT)),
        direction: readU32(reg.add(REG_DIRECTION)),
        mode: readU8(reg.add(REG_MODE)),
        dirtyIndex: readU16(reg.add(REG_DIRTY)),
        dispatch: readPointer(reg.add(REG_DISPATCH)),
        argDispatch: readPointer(reg.add(REG_ARGDISP)),
        stats,
        gate,
        statCalls: stats.isNull() ? -1 : readU32(stats.add(0x28)),
        statBytes: stats.isNull() ? -1 : readU32(stats.add(0x2C)),
        gateByte: gate.isNull() ? -1 : readU8(gate.add(0x8D)),
    };
}

// Measures serialized arg size in bits by calling the size dispatcher (index 0).
// Side-effect free per the decompile, but isolated so a fault never costs a log line.
function measureArgBits(argDispatch, argRefs) {
    if (argDispatch.isNull() || argRefs.isNull()) return -1;
    try {
        const vtable = readPointer(argDispatch);
        if (vtable.isNull()) return -1;
        const sizeFn = new NativeFunction(vtable, 'uint64', ['pointer']);
        return sizeFn(argRefs).toNumber();
    } catch (_) {
        return -1;
    }
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

function isFiltered(name) {
    if (!name) return false; // never hide unresolved entries
    if (SHOW_ONLY.length && !SHOW_ONLY.some((s) => name.indexOf(s) !== -1)) return true;
    if (SUPPRESS.some((s) => name.indexOf(s) !== -1)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Per-method payload decoders, keyed by resolved name.
//
// argRefs is `const SArgRefs<TArgs...>*` — the same struct passed to the
// dispatch template's Write/GetBufferBitSize. The struct is recursively
// defined: `SArgRefs<A, B, C>` derives from `SArgRefs<B, C>` and adds a
// trailing `const A* m_head`. Standard C++ layout places the base subobject
// first, so the in-memory order is REVERSE of the template order:
//
//   SArgRefs<A,B,C>  @ +0x00 : SArgRefs<B,C>  base
//                              @ +0x00 : SArgRefs<C> base
//                                        @ +0x00 : const C* m_head
//                              @ +0x08 : const B* m_head
//                    @ +0x10 : const A* m_head
//
// So: physical offset 0 always holds the LAST template arg, offset 8 the
// second-to-last, etc. The ctx ref is NOT in SArgRefs — it travels through
// CSerializedComponent::SendRemoteMethodCall as its own arg.
//
// Each slot is a pointer to the actual arg value, even for scalars.
// ---------------------------------------------------------------------------

// Read SArgRefs slot N where slot 0 == last template param. Helpers below
// chain that with a typed deref of the pointed-at arg value.
function slotPtr(argRefs, slot) {
    return readPointer(argRefs.add(slot * 8));
}
function argU8(argRefs, slot)   { const p = slotPtr(argRefs, slot); return p.isNull() ? -1 : readU8(p); }
function argU16(argRefs, slot)  { const p = slotPtr(argRefs, slot); return p.isNull() ? -1 : readU16(p); }
function argU32(argRefs, slot)  { const p = slotPtr(argRefs, slot); return p.isNull() ? -1 : readU32(p); }
function argU64Hex(argRefs, slot) {
    const p = slotPtr(argRefs, slot);
    if (p.isNull()) return '?';
    try { return '0x' + p.readU64().toString(16); } catch (_) { return '?'; }
}
function argFloat(argRefs, slot) {
    const p = slotPtr(argRefs, slot);
    if (p.isNull()) return NaN;
    try { return p.readFloat(); } catch (_) { return NaN; }
}
function argBool(argRefs, slot) {
    const v = argU8(argRefs, slot);
    return v < 0 ? '?' : (v ? 'true' : 'false');
}
function argI32(argRefs, slot) {
    const p = slotPtr(argRefs, slot);
    if (p.isNull()) return '?';
    try { return p.readS32(); } catch (_) { return '?'; }
}
function argI64Hex(argRefs, slot) { return argU64Hex(argRefs, slot); }
function argDouble(argRefs, slot) {
    const p = slotPtr(argRefs, slot);
    if (p.isNull()) return NaN;
    try { return p.readDouble(); } catch (_) { return NaN; }
}

function readU64(address) {
  try { return address.readU64().toString(16); } catch (_) { return '?'; }
}
function readU64Raw(address) {
  try { return address.readU64(); } catch (_) { return null; }
}

// CryStringT<char>: single member `char* m_str` at offset 0. The arg-ref points
// to the wrapper, so one deref gives the C string base.
function readCryString(wrapperPtr, maxLen) {
    if (!wrapperPtr || wrapperPtr.isNull()) return null;
    try {
        const strPtr = wrapperPtr.readPointer();
        if (strPtr.isNull()) return '';
        return strPtr.readUtf8String(maxLen || 64);
    } catch (_) { return null; }
}

// std::vector<T>: { _Myfirst, _Mylast, _Myend } at offsets 0/8/0x10. Returns
// element count given a known element size. Returns -1 on read failure.
function readVectorSize(vecPtr, elemSize) {
    if (!vecPtr || vecPtr.isNull() || !elemSize) return -1;
    try {
        const first = vecPtr.readPointer();
        const last  = vecPtr.add(8).readPointer();
        if (first.isNull() || last.isNull() || last.compare(first) < 0) return -1;
        const bytes = last.sub(first).toUInt32();
        return Math.floor(bytes / elemSize);
    } catch (_) { return -1; }
}

// CryGUID is two u64s at offsets 0 and 8. Stringify as `hi-lo` for compactness.
function readGuid(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        const lo = ptr.readU64().toString(16);
        const hi = ptr.add(8).readU64().toString(16);
        return `${hi}-${lo}`;
    } catch (_) { return null; }
}

// Vec3<float> and Vec3<double>.
function readVec3f(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return `(${ptr.readFloat().toFixed(3)},${ptr.add(4).readFloat().toFixed(3)},${ptr.add(8).readFloat().toFixed(3)})`; }
    catch (_) { return null; }
}
function readVec3d(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return `(${ptr.readDouble().toFixed(3)},${ptr.add(8).readDouble().toFixed(3)},${ptr.add(16).readDouble().toFixed(3)})`; }
    catch (_) { return null; }
}

// CTimeValue is i64 nanoseconds in CryEngine.
function readTimeValue(ptr) {
    if (!ptr || ptr.isNull()) return '?';
    try { return ptr.readS64().toString(); } catch (_) { return '?'; }
}

// ---- Enum tables (extracted verbatim from types.h; only defined values are
// listed. Unknown numeric values render as `<number>(?)`.) ----
// EHailStatus @ types.h:93410
const E_HAIL_STATUS         = { 1: 'Calling', 2: 'IncomingCall', 3: 'Established' };
// Missile::EExplosionSafety @ types.h:35740
const E_EXPLOSION_SAFETY    = { 0: 'SafetyOn', 1: 'SafetyOff' };
// ERespawnSettingType (bitmask) @ types.h:135420
const E_RESPAWN_SETTING     = { 1: 'Transferring', 2: 'Releasing' };
// ECommsRequestType = EMobiGlasAppType::Enum @ types.h:131888
const E_COMMS_REQUEST       = {
    0:  'MissionMgr',    1:  'EasyShop',        2:  'CryAstro',
    3:  'PortModification', 5: 'Notification',  6:  'Cargo',
    7:  'Finance',       8:  'SkyLine',         9:  'PersonalManager',
    10: 'VehicleManager',11: 'InventoryManager',12: 'ContactsScreen',
};
// EDisconnectType @ types.h:116726
const E_DISCONNECT_TYPE     = { 1: 'VehicleBedLogout' };
// EAIQTReason @ types.h:93442
const E_AI_QT_REASON        = { 0: 'Escape', 1: 'Travel', 2: 'NonAIQT' };
// EDockingTubeAnimationStage @ types.h:38280
const E_DOCKING_TUBE_STAGE  = { 0: 'NotSet', 2: 'PreDocked', 3: 'Docked' };
// EOperatorMode @ types.h:37813 (only high values defined in decompile)
const E_OPERATOR_MODE       = { 7: 'Mining', 8: 'QuantumNavigation', 9: 'Refuel', 10: 'AirTrafficController' };
// CSCItemElevator::EElevatorState @ types.h:145429
const E_ELEVATOR_STATE      = {
    0: 'Rest', 1: 'OpeningDoor', 2: 'OpenForPassengers',
    3: 'ClosingDoor', 4: 'InTransit',
};
// CIGRadarSystem::EPingWaveActions @ types.h:121193
const E_PING_WAVE           = { 0: 'StartWave', 1: 'ReleaseWave' };
// ESnapshotSlotType @ types.h:23173
const E_SNAPSHOT_SLOT       = { 2: 'Customized' };
// Weapon::ECommand @ types.h:117133
const E_WEAPON_COMMAND      = {
    0x02: 'ChangeFiremode', 0x03: 'AuxiliaryAction', 0x04: 'PauseAuxActionAuth',
    0x05: 'ResetCooldown',  0x06: 'ZeroingIncrease', 0x07: 'ZeroingDecrease',
    0x08: 'ActivateChargeDrainPrimed', 0x09: 'SetRegenRateAuth',
    0x0A: 'SetAdditionalBurstShots',   0x0B: 'SetMaxAmmoCountAuth',
    0x0C: 'SetModInterpolFactorAuth',  0x0D: 'SetEnergyConsumpMultAuth',
    0x0E: 'SetFireModeAuth',           0x0F: 'SetSalvageRepairAmmoCount',
    0x10: 'SetSalvageRepairTarget',    0x11: 'SetSalvageHasCargoSpace',
    0x12: 'SetAmmoContainer',          0x13: 'SetGimbalModeModifier',
    0x14: 'EnableFireModeSwitching',   0x15: 'SetOverheatLockedState',
    0x16: 'SetMisfireState',           0x17: 'ShootTractorBeamTargetInDir',
    0x18: 'ReqDesiredTractorBeamDist', 0x19: 'RequestTractorBeamTarget',
    0x1A: 'ZoomInOut',                 0x1B: 'CancelCharge',
    0x1C: 'SetTrackviewSeed',
};
// Weapon::ETrigger @ types.h:117181
const E_WEAPON_TRIGGER      = { 0: 'Press', 1: 'Release' };
// Weapon::Network::EValidationState @ types.h:118415
const E_WEAPON_VAL_STATE    = { 2: 'TooLate', 3: 'OutOfOrder' };
// Missile::ELaunchStates @ types.h:35718 (bitmask).
const E_LAUNCH_STATES       = { 1: 'ReadyToFire', 2: 'Ejected' };

function enumName(table, v) {
    if (v < 0) return '?';
    return table[v] || '?';
}

// CStringHash @ types.h:208505 sizeof=0x18: m_hash(u32)@0, m_str(char*)@8, m_strLen(u64)@0x10.
// Returns "0xHEX(name)" if the name pointer is readable, else "0xHEX".
function stringHashStr(p) {
    if (!p || p.isNull()) return '?';
    const hash = readU32(p.add(0)) >>> 0;
    const name = readCryString(p.add(8), 64);
    return name ? `0x${hash.toString(16)}(${name})` : `0x${hash.toString(16)}`;
}

// SInteractionMetaData shared decoder used by SvRequestInteract/SvRequestSharedInteract.
function interactionMetaDecoder(p) {
    if (!p || p.isNull()) return '?';
    const interactorType = readU32(p.add(0)) >>> 0;
    const interactorData = readU32(p.add(4)) >>> 0;
    const interableType  = readU32(p.add(8)) >>> 0;
    const interableData  = readU32(p.add(0xC)) >>> 0;
    const skipUsable     = readU8(p.add(0x10));
    const skipUse        = readU8(p.add(0x11));
    return `(iorType=${interactorType} iorData=${interactorData} iableType=${interableType} iableData=${interableData} skipUsable=${skipUsable} skipUse=${skipUse})`;
}

// SNavTarget shared decoder (used under two registered names).
function navTargetDecoder(argRefs) {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const refEntity = readU64(p.add(0));
    const shape     = readU32(p.add(0x30));
    let radius = NaN, distance = NaN;
    try { radius   = p.add(0x48).readDouble(); } catch (_) {}
    try { distance = p.add(0x50).readDouble(); } catch (_) {}
    const beyond    = readU8(p.add(0x58));
    const permanent = readU8(p.add(0x59));
    return `refEntity=0x${refEntity} shape=${shape} radius=${radius} distance=${distance} beyondRange=${beyond} permanent=${permanent}`;
}

const decoders = {
  // SArgRefs<SRemoteObservableUpdateInfo>  (sizeof 8: one slot)
  // SRemoteObservableUpdateInfo @ 0x10: eId(u64) idx(u32) visible(u8) fov(u8) stance(u8)
  'CVisionComponent::RmAuthorityRemoteObservableUpdate': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const eId     = readU64(p.add(0x00));
    const idx     = readU32(p.add(0x08));
    const visible = readU8(p.add(0x0C));
    const fov     = readU8(p.add(0x0D));
    const stance  = readU8(p.add(0x0E));
    return `eId=0x${eId} idx=${idx} visible=${visible} fov=${fov} stance=${stance}`;
  },

  // SArgRefs<__int64>  — single scalar; observed values ~small ints
  'RmAuthorityConsumeThrusterFuel': (argRefs) => {
    return `value=${argU64Hex(argRefs, 0)}`;
  },

  // SArgRefs<SAttachableSerializationAttach>  — single struct ptr
  // Struct 0x70: entity(EntityId)@0x00, port(SItemPortId)@0x08, reason(u32)@0x18,
  // detach(u32)@0x1C, animTrig@0x24, useOffset@0x25, useInterior@0x26,
  // offset(QuatT<double>)@0x28, jointCRC(int)@0x60, isStatic@0x64, instigator(EID)@0x68
  'AuthorityAttachToPort': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const entity     = readU64(p.add(0x00));
    const reason     = readU32(p.add(0x18));
    const detach     = readU32(p.add(0x1C));
    const animTrig   = readU8(p.add(0x24));
    const jointCRC   = readU32(p.add(0x60));
    const isStatic   = readU8(p.add(0x64));
    const instigator = readU64(p.add(0x68));
    return `entity=0x${entity} reason=${reason} detach=${detach} anim=${animTrig} jointCRC=0x${(jointCRC>>>0).toString(16)} static=${isStatic} instigator=0x${instigator}`;
  },

  // SArgRefs<HitInfo const &>  — single struct ptr (HitInfo, 0x168 bytes)
  // Key fields read here; full layout in types.h:289013.
  'CSCPlayerGameRulesNetworkComponent::m_rmAuthorityRequestHit': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    // IEntityPtr is a shared-ptr-like; offset 0 is the raw entity ptr.
    const pShooter    = readPointer(p.add(0x00));
    const pTarget     = readPointer(p.add(0x08));
    const pWeapon     = readPointer(p.add(0x10));
    const projId      = readU32(p.add(0x28));
    const material    = readU32(p.add(0x74));
    const type        = readU32(p.add(0x78));
    const partId      = readU32(p.add(0x7C));
    const projCls     = readU32(p.add(0xE4));
    const weaponCls   = readU32(p.add(0xE8));
    const remote      = readU8(p.add(0xEC));
    const explosion   = readU8(p.add(0xED));
    return `shooter=${pShooter} target=${pTarget} weapon=${pWeapon} projId=${projId} type=${type} material=${material} partId=${partId} projCls=0x${(projCls>>>0).toString(16)} weaponCls=0x${(weaponCls>>>0).toString(16)} remote=${remote} expl=${explosion}`;
  },

  // SArgRefs<bool>
  'CSCPlayer::RmAuthorityOnInteractionStateChange': (argRefs) => `enabled=${argBool(argRefs, 0)}`,
  'AuthorityOnInteractionStateChange':              (argRefs) => `enabled=${argBool(argRefs, 0)}`,

  // SArgRefs<CStringHash, EHailStatus>  — last template at @0
  'm_rmMulticastSetHailStatus': (argRefs) => {
    const status = argU8(argRefs, 0);
    const hash   = stringHashStr(slotPtr(argRefs, 1));
    return `hash=${hash} status=${status}(${enumName(E_HAIL_STATUS, status)})`;
  },

  // SArgRefs<unsigned __int16, float>  — @0 = float, @8 = u16
  'RmAuthorityUpdateInputDevice': (argRefs) => {
    const time   = argFloat(argRefs, 0);
    const device = argU16(argRefs, 1);
    return `device=${device} time=${time}`;
  },

  // SArgRefs<EntityId target, EntityId newMainTractor>
  'CTractorBeamMultitractorUtils::RmAuthorityRequestNewLead': (argRefs) => {
    const newLead = argU64Hex(argRefs, 0);
    const target  = argU64Hex(argRefs, 1);
    return `target=${target} newLead=${newLead}`;
  },

  // SArgRefs<EntityId, CTimeValue>  — CTimeValue is 8 bytes (int64 nanoseconds)
  'CWeaponActionFireTractorBeam::RmAuthoritySetTarget': (argRefs) => {
    const time   = argU64Hex(argRefs, 0);
    const target = argU64Hex(argRefs, 1);
    return `target=${target} time=${time}`;
  },

  // SArgRefs<int>  — ammo count
  'CWeaponActionFireTractorBeam::RmAuthoritySetAmmoCount': (argRefs) => `count=${argU32(argRefs, 0)}`,

  // SArgRefs<EntityId>
  'CEntityComponentKioskInteraction::RmAuthoritySetUserId': (argRefs) => `userId=${argU64Hex(argRefs, 0)}`,

  // SArgRefs<Missile::EExplosionSafety>
  'RmAuthorityRequestExplosionSafety': (argRefs) => {
    const v = argU8(argRefs, 0);
    return `safety=${v}(${E_EXPLOSION_SAFETY[v] || '?'})`;
  },

  // SArgRefs<unsigned int>
  'CSCItemElevator::RmMulticastSetTargetStop': (argRefs) => {
    const v = argU32(argRefs, 0) >>> 0;
    return `targetStop=${v === 0xFFFFFFFF ? '-1' : v}`;
  },

  // SArgRefs<unsigned __int8>  — CSCItemElevator::EElevatorState
  'CSCItemElevator::RmMulticastSetElevatorState': (argRefs) => {
    const v = argU8(argRefs, 0);
    return `state=${v}(${enumName(E_ELEVATOR_STATE, v)})`;
  },

  // ============================================================================
  // The remaining decoders below are mechanical and grounded against
  // CRemoteMethodDispatchTemplate<void, TArgs...>::s_dispatch signatures in
  // /media/null/ares/StarCitizen.exe.c. SArgRefs layout: last template arg
  // at offset 0 (base-class first), first template arg at largest offset.
  // ctx is never in SArgRefs.
  // ============================================================================

  // ---- No-arg ----------------------------------------------------------------
  // SArgRefs<>  (zero bits) — these names all share dispatch 0x14850f690.
  'CTargetedEntries::m_rmAuthorityRemoveAllPinnedTargets': () => '(no args)',
  'AuthorityRestoreMarkerState':                            () => '(no args)',
  'rmAuthorityReportPersonalReputationData':                () => '(no args)',

  // ---- Single scalar / enum --------------------------------------------------
  // SArgRefs<EDisconnectType>  — single byte enum (size 8 bits)
  'CActor::RmAuthorityRequestDisconnect': (argRefs) => {
    const v = argU8(argRefs, 0);
    return `disconnect=${v}(${E_DISCONNECT_TYPE[v] || '?'})`;
  },

  // SArgRefs<EAIQTReason>
  'RmAuthorityOnActionTryBeginQuantumTravel': (argRefs) => {
    const v = argU8(argRefs, 0);
    return `reason=${v}(${E_AI_QT_REASON[v] || '?'})`;
  },

  // SArgRefs<ERespawnSettingType>
  'CEntityComponentCloneLocationUIProvider::RmAuthorityOnPopupChanged': (argRefs) => {
    const v = argU8(argRefs, 0);
    return `popup=${v}(${E_RESPAWN_SETTING[v] || '?'})`;
  },

  // SArgRefs<CStringHash>  — surfaces the string name if available.
  'irc_authoritySetState': (argRefs) => `hash=${stringHashStr(slotPtr(argRefs, 0))}`,

  // ---- Two-scalar / id pairs -------------------------------------------------
  // SArgRefs<bool extract, bool snap>
  'RmAuthRequestStateChange': (argRefs) => `extract=${argBool(argRefs, 1)} snap=${argBool(argRefs, 0)}`,

  // SArgRefs<EntityId, bool>
  'pi.RmAuthorityNotifyLootEntityAccessed': (argRefs) =>
    `entity=${argU64Hex(argRefs, 1)} bool=${argBool(argRefs, 0)}`,

  // SArgRefs<EntityId, int>
  'shopUI.rmAuthSetTransactionMode': (argRefs) =>
    `entity=${argU64Hex(argRefs, 1)} mode=${argI32(argRefs, 0)}`,

  // SArgRefs<EPingWaveActions, CTimeValue>
  'ping.requestWaveState': (argRefs) => {
    const t = readTimeValue(slotPtr(argRefs, 0));
    const a = argU8(argRefs, 1);
    return `action=${a}(${E_PING_WAVE[a] || '?'}) time=${t}`;
  },

  // SArgRefs<IEntityPtr, bool>  — IEntityPtr first 8 bytes is the raw entity*
  'CSCItemNavigation:RmAuthorityBeginRouteCalculation': (argRefs) => {
    const p = slotPtr(argRefs, 1);
    const ent = p.isNull() ? NULL : readPointer(p);
    return `entity=${ent} bool=${argBool(argRefs, 0)}`;
  },

  // SArgRefs<EntityId, unsigned __int64>  — request id
  'commodityUI.m_rmAuthority_CargoLocationDataRequest': (argRefs) =>
    `playerId=${argU64Hex(argRefs, 1)} requestId=${argU64Hex(argRefs, 0)}`,

  // SArgRefs<EntityId, ECommsRequestType>
  'RmAuthorityATCRequest': (argRefs) => {
    const t = argU8(argRefs, 0);
    return `playerId=${argU64Hex(argRefs, 1)} type=${t}(${E_COMMS_REQUEST[t] || '?'})`;
  },

  // SArgRefs<EntityId, CStringHash>
  'm_rmAuthorityStopCommunicationWith': (argRefs) =>
    `partner=${argU64Hex(argRefs, 1)} channel=${stringHashStr(slotPtr(argRefs, 0))}`,

  // SArgRefs<unsigned int id, int index>
  'CEntityComponentCriminalRecordUIProvider::RmAuthorityPayFine': (argRefs) =>
    `id=${argU32(argRefs, 1) >>> 0} index=${argI32(argRefs, 0)}`,

  // SArgRefs<SItemPortId, EntityId>
  // SItemPortId @ types.h:291067 sizeof=0x10: Owner(EntityId)@0, Id(u16)@8
  'pi.m_rmAuthorityRequestChangePortOnEquippedItem': (argRefs) => {
    const entity = argU64Hex(argRefs, 0);
    const portPtr = slotPtr(argRefs, 1);
    if (portPtr.isNull()) return `entity=${entity} port=?`;
    const owner = readU64(portPtr.add(0));
    const id    = readU16(portPtr.add(8));
    return `entity=${entity} port=(owner=0x${owner} id=${id})`;
  },

  // ---- Three+ scalars --------------------------------------------------------
  // SArgRefs<EntityId inv, EntityId by, bool start>
  'pi.RmAuthorityOnContainerAccessed': (argRefs) =>
    `inv=${argU64Hex(argRefs, 2)} by=${argU64Hex(argRefs, 1)} start=${argBool(argRefs, 0)}`,

  // SArgRefs<int prio, int toggle, bool ignore>
  'CSCItemEnergyController::RmAuthorityRequestTogglePowerGroupState': (argRefs) =>
    `priorityGroup=${argI32(argRefs, 2)} toggleMode=${argI32(argRefs, 1)} ignoreControl=${argBool(argRefs, 0)}`,

  // SArgRefs<int index, unsigned int selectId, unsigned int removeId, unsigned int payId>
  'CEntityComponentCriminalRecordUIProvider::RmAuthoritySetBindingTriggerIds': (argRefs) =>
    `index=${argI32(argRefs, 3)} selectId=${argU32(argRefs, 2) >>> 0} removeId=${argU32(argRefs, 1) >>> 0} payId=${argU32(argRefs, 0) >>> 0}`,

  // SArgRefs<EntityId, unsigned int, unsigned __int64>
  'RmAuthorityRequestActiveInventoryId': (argRefs) =>
    `entity=${argU64Hex(argRefs, 2)} u32=${argU32(argRefs, 1) >>> 0} u64=${argU64Hex(argRefs, 0)}`,

  // SArgRefs<EOperatorMode, CTimeValue, CTimeValue>
  'ControlContext_AuthorityRequestOperatorMode': (argRefs) => {
    const t1 = readTimeValue(slotPtr(argRefs, 1));
    const t0 = readTimeValue(slotPtr(argRefs, 0));
    const m  = argU8(argRefs, 2);
    return `mode=${m}(${E_OPERATOR_MODE[m] || '?'}) t1=${t1} t0=${t0}`;
  },

  // SArgRefs<CryGUID, EntityId>  — CryGUID is 16 bytes (hi,lo)
  'RmAuthorityRequestVehicleInfos': (argRefs) =>
    `entity=${argU64Hex(argRefs, 0)} guid=${readGuid(slotPtr(argRefs, 1))}`,

  // SArgRefs<EntityId poi, Vec3<double>* eyePos, Vec3<float>* eyeDir>
  'CSCActorSpatialAwareness::RmAuthorityLookAtPOIRequest': (argRefs) => {
    const eyeDir  = readVec3f(slotPtr(argRefs, 0));
    const eyePos  = readVec3d(slotPtr(argRefs, 1));
    const poi     = argU64Hex(argRefs, 2);
    return `poi=${poi} eyePos=${eyePos} eyeDir=${eyeDir}`;
  },

  // ---- Single struct ptr -----------------------------------------------------
  // SArgRefs<SBufferedCommand>
  // SBufferedCommand @ types.h:314473 sizeof=0x38:
  //   tick(u32)@0, command(Weapon::ECommand u8)@4, trigger(Weapon::ETrigger u8)@5,
  //   validationState(Weapon::Network::EValidationState u8)@6,
  //   data(CigVariant<...> sizeof=0x30)@8 with m_which at offset 8+0x28 = 0x30
  'CWeaponCommandBuffer::RmAuthorityRequestCommand': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const tick     = readU32(p.add(0)) >>> 0;
    const cmd      = readU8(p.add(4));
    const trig     = readU8(p.add(5));
    const valState = readU8(p.add(6));
    const which    = readU8(p.add(0x30));
    const VARIANT = ['SEntityCommandData','SSetAmmoContainerData','SSetGimbalModeModifierData',
                     'SSetModifierInterpolationData','Vec3f','EntityId','float','int','uint','uchar'];
    const variantName = VARIANT[which] || '?';
    return `tick=${tick} cmd=${cmd}(${enumName(E_WEAPON_COMMAND, cmd)}) trig=${trig}(${enumName(E_WEAPON_TRIGGER, trig)}) valState=${valState}(${enumName(E_WEAPON_VAL_STATE, valState)}) data=${which}(${variantName})`;
  },

  // SArgRefs<SNavTarget>
  // SNavTarget @ types.h:390238 sizeof=0x60:
  //   m_referenceEntityId@0, m_targetPos_zs(SZoneTransform<Vec3<double>> 0x28)@8,
  //   m_traversalShape(u32)@0x30, m_arrivalRadius(double)@0x48,
  //   m_travelDistance(double)@0x50, m_bTargetBeyondRange@0x58,
  //   m_bIsPermanentQuantumMarker@0x59
  // Triage name has no class prefix (registered string differs from C++ symbol).
  'RmAuthorityOnAlignedToTarget':                       (argRefs) => navTargetDecoder(argRefs),
  'CSCItemQuantumDrive::RmAuthorityOnAlignedToTarget':  (argRefs) => navTargetDecoder(argRefs),

  // SArgRefs<SInventoryManagementRequest const &>
  // SInventoryManagementRequest @ types.h:300881 sizeof=0x1D0
  'pi.RmAuthorityProcessInventoryManagementOperation': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const moveId   = readU32(p.add(0)) >>> 0;
    const type     = readU32(p.add(4)) >>> 0;
    const userId   = readU64(p.add(8));
    const srcInv   = readU64(p.add(0x10));
    const dstInv   = readU64(p.add(0x28));
    const srcCls   = readU32(p.add(0x58)) >>> 0;
    const srcAmt   = readU32(p.add(0x5C));
    const dstCls   = readU32(p.add(0x80)) >>> 0;
    const dstAmt   = readU32(p.add(0x84));
    const itemEnt  = readU64(p.add(0xA8));
    const bStack   = readU8(p.add(0xC4));
    const flags    = readU8(p.add(0x1C8));
    return `move=${moveId} type=${type} user=0x${userId} src=(inv=0x${srcInv} cls=0x${srcCls.toString(16)} amt=${srcAmt}) dst=(inv=0x${dstInv} cls=0x${dstCls.toString(16)} amt=${dstAmt}) item=0x${itemEnt} stack=${bStack} flags=0x${flags.toString(16)}`;
  },

  // SArgRefs<SMasterModeData>
  // SMasterModeData @ types.h:292159 sizeof=0x10:
  //   state(EMasterMode u32)@0, spooledTimestamp(CTimeValue i64)@8
  'ControllableManager_RequestMasterMode': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const state = readU32(p.add(0));
    const ts    = readTimeValue(p.add(8));
    return `state=${state} spooledAt=${ts}`;
  },

  // SArgRefs<SSerializationReserveUserRequest>
  // SSerializationReserveUserRequest @ types.h:2187092 sizeof=0x8:
  //   m_userId(EntityId)@0
  'AuthorityReserveUser': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    return `userId=0x${readU64(p.add(0))}`;
  },

  // SArgRefs<SLocation const &>
  // CEntityComponentShopUIProvider::SLocation @ types.h:3483325 sizeof=0x68:
  //   m_nameHash(CLocIdentifierHash u32)@0, m_entityId(EntityId)@8,
  //   m_inventoryId(SInventoryId 0x18)@0x10, m_inventoryParams(CryGUID)@0x28,
  //   m_inventoryCapacity(i64)@0x38, m_inventoryOccupancy(i64)@0x40,
  //   m_inventoryVolume(Vec3f)@0x48, m_locationSource(u8)@0x54,
  //   m_itemType(EItemType u32)@0x58, m_itemSubType(u32)@0x5C,
  //   m_state(ELocationState u32)@0x60
  'shopUI.m_rmAuthority_OnSelectedLocationChanged': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const nameHash = readU32(p.add(0)) >>> 0;
    const entity   = readU64(p.add(8));
    let cap = '?', occ = '?';
    try { cap = p.add(0x38).readS64().toString(); } catch (_) {}
    try { occ = p.add(0x40).readS64().toString(); } catch (_) {}
    const vol      = readVec3f(p.add(0x48));
    const src      = readU8(p.add(0x54));
    const itemType = readU32(p.add(0x58)) >>> 0;
    const subType  = readU32(p.add(0x5C)) >>> 0;
    const state    = readU32(p.add(0x60)) >>> 0;
    return `nameHash=0x${nameHash.toString(16)} entity=0x${entity} cap=${cap} occ=${occ} vol=${vol} src=${src} itemType=${itemType} subType=${subType} state=${state}`;
  },

  // SArgRefs<SServiceBeaconParams const &>
  // SServiceBeaconParams @ types.h:376078 sizeof=0xA0:
  //   ___u0(0x20 variant)@0, creator(SServiceBeaconCreator 0x28)@0x20,
  //   contractor(SServiceBeaconContractor 0x10)@0x48,
  //   missionProperties(SServiceBeaconMissionProperties 0x18)@0x58,
  //   queriedObjectivePosition_zs(Vec3<double>)@0x70, zoneHostId@0x88,
  //   uecAmount(u32)@0x90, creationFeeAmount(u32)@0x94,
  //   eBeaconType(EServiceBeaconType u32)@0x98, reputationRequirement(float)@0x9C
  'pml.AuthCreateMissionServiceBeacon': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const pos     = readVec3d(p.add(0x70));
    const host    = readU64(p.add(0x88));
    const uec     = readU32(p.add(0x90)) >>> 0;
    const fee     = readU32(p.add(0x94)) >>> 0;
    const type    = readU32(p.add(0x98)) >>> 0;
    let rep = NaN;
    try { rep = p.add(0x9C).readFloat(); } catch (_) {}
    return `pos=${pos} zoneHost=0x${host} uec=${uec} creationFee=${fee} beaconType=${type} rep=${rep}`;
  },

  // SArgRefs<SShopRentalRequest const &>
  // SShopRentalRequest : SShopRequest(0x20) — base @ 0..0x1F
  //   playerId@0, shopId@8, kioskId@0x10, amount(double)@0x18
  //   + itemClassGuid(CryGUID)@0x20, rentalOffering(u64)@0x30,
  //     days(u8)@0x38, licenseAwarded(bool)@0x39
  'RmRentalRequest': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const player = readU64(p.add(0));
    const shop   = readU64(p.add(8));
    const kiosk  = readU64(p.add(0x10));
    let amount = NaN;
    try { amount = p.add(0x18).readDouble(); } catch (_) {}
    const guid   = readGuid(p.add(0x20));
    const offering = readU64(p.add(0x30));
    const days   = readU8(p.add(0x38));
    const lic    = readU8(p.add(0x39));
    return `player=0x${player} shop=0x${shop} kiosk=0x${kiosk} amount=${amount} item=${guid} offering=0x${offering} days=${days} licenseAwarded=${lic}`;
  },

  // SArgRefs<SShopBuyRequest const &>
  // SShopBuyRequest : SShopRequest(0x20) — base same as above
  //   + itemClassGuid(CryGUID)@0x20, attachmentGuids(vec<CryGUID>)@0x30,
  //     quantity(u64)@0x48, inventoryId(SInventoryId 0x18)@0x50
  'RmStandardItemBuyShopRequest': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const player = readU64(p.add(0));
    const shop   = readU64(p.add(8));
    const kiosk  = readU64(p.add(0x10));
    let amount = NaN;
    try { amount = p.add(0x18).readDouble(); } catch (_) {}
    const guid   = readGuid(p.add(0x20));
    const att    = readVectorSize(p.add(0x30), 0x10);
    const qty    = readU64(p.add(0x48));
    const inv    = readU64(p.add(0x50));
    return `player=0x${player} shop=0x${shop} kiosk=0x${kiosk} amount=${amount} item=${guid} attachments=${att} qty=0x${qty} inv=0x${inv}`;
  },

  // SArgRefs<SReducedDamageMapHitInfo const &>
  // SReducedDamageMapHitInfo @ types.h:2262847 sizeof=0x48:
  //   hitType(EDamageMapHitType u8)@0, requesterId@8, pos_ls(Vec3f)@0x10,
  //   dir_ls(Vec3f)@0x1C, totalEnergyDamage(float)@0x28,
  //   physicalDamage(float)@0x2C, projectileHitTime(float)@0x30,
  //   hitRadius(float)@0x34, seed(u32)@0x38, timeStamp(CTimeValue)@0x40
  'RmAuthorityRequestDamageMapHitFromHitInfo': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const hitType   = readU8(p.add(0));
    const requester = readU64(p.add(8));
    const pos       = readVec3f(p.add(0x10));
    const dir       = readVec3f(p.add(0x1C));
    let energyDmg = NaN, physDmg = NaN, projTime = NaN, radius = NaN;
    try { energyDmg = p.add(0x28).readFloat(); } catch (_) {}
    try { physDmg   = p.add(0x2C).readFloat(); } catch (_) {}
    try { projTime  = p.add(0x30).readFloat(); } catch (_) {}
    try { radius    = p.add(0x34).readFloat(); } catch (_) {}
    const seed      = readU32(p.add(0x38)) >>> 0;
    const ts        = readTimeValue(p.add(0x40));
    return `hitType=${hitType} requester=0x${requester} pos=${pos} dir=${dir} energy=${energyDmg} phys=${physDmg} t=${projTime} radius=${radius} seed=${seed} ts=${ts}`;
  },

  // SArgRefs<SCEvtControl_BuildingBlocksSetState>
  // @ types.h:1849964 sizeof=0x10: m_userPtr(IEntityPtr)@0, m_stateType(u32)@8, m_state(u32)@0xC
  'CEntityComponentUIBindingsInteractions::RmBuildingBlocksSetState': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const user = readPointer(p.add(0));
    const stateType = readU32(p.add(8)) >>> 0;
    const state     = readU32(p.add(0xC)) >>> 0;
    return `user=${user} stateType=0x${stateType.toString(16)} state=0x${state.toString(16)}`;
  },

  // SArgRefs<SCEvtControl_BuildingBlocksPerformInteraction>
  // @ types.h:1849971 sizeof=0x10: m_userPtr(IEntityPtr)@0, m_interaction(u32)@8
  'CEntityComponentUIBindingsInteractions::RmBuildingBlocksPerformInteraction': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const user = readPointer(p.add(0));
    const interaction = readU32(p.add(8)) >>> 0;
    return `user=${user} interaction=0x${interaction.toString(16)}`;
  },

  // SArgRefs<vector<SInventoryId> &&, unsigned __int64>
  // SInventoryId is typically 0x18 bytes (CryGUID + extras); read vector size + reqId.
  'commodityUI.m_rmAuthority_CargoInventoryDataRequest': (argRefs) => {
    const vec = slotPtr(argRefs, 1);
    const sz  = readVectorSize(vec, 0x18);
    return `inventoryIds.size=${sz} requestId=${argU64Hex(argRefs, 0)}`;
  },

  // ---- Complex multi-arg with struct ----------------------------------------
  // SArgRefs<CTimeValue start, SActionCollectionBase*, CTimeValue sendTime>
  'CSCActorActionHandler::RmAuthoritySendActions': (argRefs) => {
    const sendTime = readTimeValue(slotPtr(argRefs, 0));
    const actions  = slotPtr(argRefs, 1);
    const start    = readTimeValue(slotPtr(argRefs, 2));
    return `start=${start} sendTime=${sendTime} actions=${actions}`;
  },

  // SArgRefs<CryGUID, EntityId, unsigned int>
  'mbi.AuthAbandonMissionRequest': (argRefs) => {
    const guid    = readGuid(slotPtr(argRefs, 2));
    const player  = argU64Hex(argRefs, 1);
    const reqId   = argU32(argRefs, 0) >>> 0;
    return `guid=${guid} playerId=${player} requestId=${reqId}`;
  },

  // SArgRefs<SMissionEntryDetails const &, EntityId, unsigned int>
  // SMissionEntryDetails @ types.h:376540 sizeof=0x138:
  //   seed(u32)@0, title(CLocIdentifierHash u32)@4, titleHUD@8, description@0xC,
  //   missionGiverName@0x10, missionDifficulty(int)@0x14, reward(int)@0x18,
  //   rewardMax(int)@0x1C, buyInAmount(int)@0x20, creationFee(int)@0x24,
  //   currencyType(u8)@0x28, missionType(CryGUID)@0x30,
  //   timeOutTime(CTimeValue)@0x40, brokerEntryId(CryGUID)@0x48,
  //   contractTemplateId(CryGUID)@0x58, properties(vec)@0x68,
  //   missionId(CryGUID)@0x80, cannotShareWith(vec)@0x90,
  //   flags(EMissionEntryFlags u32)@0xA8, missionOwnerId@0xB0,
  //   objectiveTokens(vec)@0xB8
  'mbi.AuthAcceptMissionRequest': (argRefs) => {
    const player  = argU64Hex(argRefs, 1);
    const reqId   = argU32(argRefs, 0) >>> 0;
    const p       = slotPtr(argRefs, 2);
    if (p.isNull()) return `playerId=${player} requestId=${reqId} details=?`;
    const seed       = readU32(p.add(0)) >>> 0;
    const difficulty = readU32(p.add(0x14));
    const reward     = readU32(p.add(0x18));
    const rewardMax  = readU32(p.add(0x1C));
    const buyIn      = readU32(p.add(0x20));
    const fee        = readU32(p.add(0x24));
    const currency   = readU8(p.add(0x28));
    const missionTy  = readGuid(p.add(0x30));
    const ts         = readTimeValue(p.add(0x40));
    const brokerId   = readGuid(p.add(0x48));
    const tmplId     = readGuid(p.add(0x58));
    const missionId  = readGuid(p.add(0x80));
    const flags      = readU32(p.add(0xA8)) >>> 0;
    const owner      = readU64(p.add(0xB0));
    return `playerId=${player} requestId=${reqId} seed=${seed} difficulty=${difficulty} reward=${reward}..${rewardMax} buyIn=${buyIn} fee=${fee} currency=${currency} missionType=${missionTy} brokerId=${brokerId} tmplId=${tmplId} missionId=${missionId} flags=0x${flags.toString(16)} owner=0x${owner} timeOut=${ts}`;
  },

  // SArgRefs<unsigned int varId, SUserVariableBase<float> const &>
  // SUserVariableBase carries a current value at offset 0 typically.
  'CEntityComponentUserVariables::RmAuthorityChangeFloatVariable': (argRefs) => {
    const ub  = slotPtr(argRefs, 0);
    const varId = argU32(argRefs, 1) >>> 0;
    let val = NaN;
    try { val = ub.isNull() ? NaN : ub.readFloat(); } catch (_) {}
    return `varId=${varId} value=${val}`;
  },

  // SArgRefs<unsigned int varId, SUserVariableBase<bool> const &>
  'CEntityComponentUserVariables::RmAuthorityChangeBoolVariable': (argRefs) => {
    const ub  = slotPtr(argRefs, 0);
    const varId = argU32(argRefs, 1) >>> 0;
    const val = ub.isNull() ? -1 : readU8(ub);
    return `varId=${varId} value=${val}`;
  },

  // SArgRefs<CryStringT<char>, EntityId>
  'AuthoritySendAISignal': (argRefs) => {
    const name  = readCryString(slotPtr(argRefs, 1), 64);
    const rcpt  = argU64Hex(argRefs, 0);
    return `signal=${JSON.stringify(name)} recipient=${rcpt}`;
  },

  // SArgRefs<vector<CryGUID> const &, CryGUID const &, bool>
  'RmHandleAppData': (argRefs) => {
    const vec  = slotPtr(argRefs, 2);
    const sz   = readVectorSize(vec, 0x10);
    const guid = readGuid(slotPtr(argRefs, 1));
    const flag = argBool(argRefs, 0);
    return `recordGUIDs.size=${sz} appGUID=${guid} isDefault=${flag}`;
  },

  // SArgRefs<EDockingTubeAnimationStage, bool>
  'SvOnSetState': (argRefs) => {
    const stage = argU8(argRefs, 1);
    const flag  = argBool(argRefs, 0);
    return `stage=${stage}(${E_DOCKING_TUBE_STAGE[stage] || '?'}) flag=${flag}`;
  },

  // SArgRefs<int, vector<CryGUID>>
  'RmAuthorityFetchPrices': (argRefs) => {
    const vec = slotPtr(argRefs, 0);
    const sz  = readVectorSize(vec, 0x10);
    return `int=${argI32(argRefs, 1)} guids.size=${sz}`;
  },

  // SArgRefs<CryGUID, CSCURN, ESnapshotSlotType, double>
  // CSCURN @ types.h:296463 sizeof=0x28 — pointer slot reads first 8 bytes for compact display.
  // ESnapshotSlotType @ types.h:23173 (bitmask, only Customized=0x2 defined).
  'RmAuthorityRequestClaim': (argRefs) => {
    const dbl  = argDouble(argRefs, 0);
    const slot = argU8(argRefs, 1);
    const urn  = argU64Hex(argRefs, 2);
    const guid = readGuid(slotPtr(argRefs, 3));
    return `guid=${guid} urn=${urn} slot=${slot}(${enumName(E_SNAPSHOT_SLOT, slot)}) double=${dbl}`;
  },

  // SArgRefs<SATCActionRequest, bool>
  // SATCActionRequest @ types.h:562209 sizeof=0x80:
  //   m_playerId@0, m_vehicleId@8, m_tokenId@0x10,
  //   m_requestMode(EATCActionRequestType u32)@0x18,
  //   m_notificationType(EATCNotificationType u32)@0x1C,
  //   m_validAreaFlags(u8)@0x20, m_requestTime(CTimeValue)@0x28,
  //   m_atcLocationId(u32)@0x30, m_locationInventoryId(SInventoryId)@0x38,
  //   m_notifiedWaitingOperator(bool)@0x50, m_notifiedWaitingQueue(bool)@0x51,
  //   m_lastTimeWaitingNotified(CTimeValue)@0x58,
  //   m_requestEntityClassName(CryStringT)@0x60, m_nameFilter(CryStringT)@0x68
  'RmAuthorityRequestPermission': (argRefs) => {
    const requeued = argBool(argRefs, 0);
    const p = slotPtr(argRefs, 1);
    if (p.isNull()) return `requeued=${requeued} req=?`;
    const player    = readU64(p.add(0));
    const vehicle   = readU64(p.add(8));
    const token     = readU64(p.add(0x10));
    const mode      = readU32(p.add(0x18));
    const notify    = readU32(p.add(0x1C));
    const flags     = readU8(p.add(0x20));
    const reqTime   = readTimeValue(p.add(0x28));
    const locId     = readU32(p.add(0x30)) >>> 0;
    const locInv    = readU64(p.add(0x38));
    const cls       = readCryString(p.add(0x60), 64);
    return `requeued=${requeued} player=0x${player} vehicle=0x${vehicle} token=0x${token} mode=${mode} notify=${notify} areaFlags=0x${flags.toString(16)} reqTime=${reqTime} locId=${locId} locInv=0x${locInv} class=${JSON.stringify(cls)}`;
  },

  // SArgRefs<CStringHash typeName, CStringHash stateName, int index>
  'RmAuthorityOnSelectNavigationTab': (argRefs) =>
    `typeName=${stringHashStr(slotPtr(argRefs, 2))} stateName=${stringHashStr(slotPtr(argRefs, 1))} index=${argI32(argRefs, 0)}`,

  // SArgRefs<CStringHash, CStringHash>
  'RmAuthoritySetInteractionState': (argRefs) =>
    `typeName=${stringHashStr(slotPtr(argRefs, 1))} stateName=${stringHashStr(slotPtr(argRefs, 0))}`,

  // SArgRefs<EntityId, EntityId, EntityId, float>  — from dispatcher signature
  'CTargetedEntries::m_rmAuthorityOnExchangedLockedTarget': (argRefs) => {
    const m  = argFloat(argRefs, 0);
    const e3 = argU64Hex(argRefs, 1);
    const e2 = argU64Hex(argRefs, 2);
    const e1 = argU64Hex(argRefs, 3);
    return `e1=${e1} e2=${e2} e3=${e3} m=${m}`;
  },

  // SArgRefs<unsigned int index, float dosage>
  'RmAuthoritySetDrugDose': (argRefs) =>
    `index=${argU32(argRefs, 1) >>> 0} dose=${argFloat(argRefs, 0)}`,

  // ---- Vector/Map containers -------------------------------------------------
  // SArgRefs<vector<SJournalEntryId_GUID>>
  // SJournalEntryId_GUID @ types.h:1487647 sizeof=0x20 (guid + missionId, both CryGUID).
  // Also sample the first entry when present.
  'journal.rmAuthEntriesViewed': (argRefs) => {
    const vec = slotPtr(argRefs, 0);
    const sz  = readVectorSize(vec, 0x20);
    if (sz <= 0) return `entries.size=${sz}`;
    let firstGuid = null, firstMission = null;
    try {
        const first = vec.readPointer();
        firstGuid    = readGuid(first);
        firstMission = readGuid(first.add(0x10));
    } catch (_) {}
    return `entries.size=${sz} first.guid=${firstGuid} first.missionId=${firstMission}`;
  },

  // SArgRefs<VectorMap<EItemType, __int64>>  — VectorMap is a vector<pair<K,V>> wrapper;
  // first 0x18 mirrors std::vector layout. Pair sizeof = 1 byte enum + 7 padding + 8 i64 = 0x10.
  'rmAuthorityRequestPoolTargets': (argRefs) => {
    const vmap = slotPtr(argRefs, 0);
    const sz   = readVectorSize(vmap, 0x10);
    return `targets.size=${sz}`;
  },

  // ---- Big multi-arg interact -----------------------------------------------
  // SInteractionMetaData @ types.h:296940 sizeof=0x14.
  // IEntityPtr is sizeof=0x8 (raw entity ptr at offset 0).

  // SArgRefs<CTimeValue, u64, u32, EntityId, SInteractionMetaData, IEntityPtr>
  // Handler: CInteractableComponent::OnSharedInteractImpl(
  //   CTimeValue interactionStartTime, u64 requestId, u32 interactionId,
  //   EntityId interactorId, SInteractionMetaData*, IEntityPtr pInitialInteractable, ...)
  // @ decomp:132624
  'SvRequestSharedInteract': (argRefs) => {
    const startTime     = readTimeValue(slotPtr(argRefs, 5));
    const requestId     = argU64Hex(argRefs, 4);
    const interactionId = argU32(argRefs, 3) >>> 0;
    const interactorId  = argU64Hex(argRefs, 2);
    const meta          = interactionMetaDecoder(slotPtr(argRefs, 1));
    const ePtr          = slotPtr(argRefs, 0);
    const pInitial      = ePtr.isNull() ? '0x0' : readPointer(ePtr).toString();
    return `startTime=${startTime} requestId=${requestId} interactionId=0x${interactionId.toString(16)} interactor=${interactorId} meta=${meta} pInitial=${pInitial}`;
  },

  // SArgRefs<CTimeValue, u64, u32, u32, EntityId, SInteractionMetaData, IEntityPtr>
  // Handler: CInteractableComponent::OnInteractImpl(
  //   CTimeValue interactionStartTime, u64 requestId,
  //   u32 ipId, u32 interactionId,
  //   EntityId interactorId, SInteractionMetaData*, IEntityPtr pInitialInteractable, ...)
  // @ decomp:132555. ipId / interactionId are CRC32-style hashes of names.
  'SvRequestInteract': (argRefs) => {
    const startTime     = readTimeValue(slotPtr(argRefs, 6));
    const requestId     = argU64Hex(argRefs, 5);
    const ipId          = argU32(argRefs, 4) >>> 0;
    const interactionId = argU32(argRefs, 3) >>> 0;
    const interactorId  = argU64Hex(argRefs, 2);
    const meta          = interactionMetaDecoder(slotPtr(argRefs, 1));
    const ePtr          = slotPtr(argRefs, 0);
    const pInitial      = ePtr.isNull() ? '0x0' : readPointer(ePtr).toString();
    return `startTime=${startTime} requestId=${requestId} ipId=0x${ipId.toString(16)} interactionId=0x${interactionId.toString(16)} interactor=${interactorId} meta=${meta} pInitial=${pInitial}`;
  },

  // SArgRefs<int, SPlayerTradeRequest>
  // SPlayerTradeRequest @ types.h:2758665 sizeof=0x10:
  //   currencyType(ECurrencyType u8)@0, currencyAmount(i64)@8
  'SvRequestTrade': (argRefs) => {
    const intArg = argI32(argRefs, 1);
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return `int=${intArg} req=?`;
    const curType = readU8(p.add(0));
    let amount = '?';
    try { amount = p.add(8).readS64().toString(); } catch (_) {}
    return `int=${intArg} currencyType=${curType} amount=${amount}`;
  },

  // ============================================================================
  // Names observed in live trace but not in the original triage JSON.
  // Each is grounded against a decompile reference.
  // ============================================================================

  // pi.RmRequestOpenInventory @ decomp:15377232 dispatches <EntityId>.
  // Shares argDispatch with CEntityComponentKioskInteraction::RmAuthoritySetUserId.
  'pi.RmRequestOpenInventory': (argRefs) => `entity=${argU64Hex(argRefs, 0)}`,
  // Same family.
  'pi.RmRequestCloseInventory': (argRefs) => `entity=${argU64Hex(argRefs, 0)}`,

  // CEntityComponentHealth::m_rmAuthorityRequestHit shares dispatch
  // 0x148aa8400 with CSCPlayerGameRulesNetworkComponent::m_rmAuthorityRequestHit
  // — both take <HitInfo> (decomp:182841, 186703).
  'CEntityComponentHealth::m_rmAuthorityRequestHit': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const pShooter    = readPointer(p.add(0x00));
    const pTarget     = readPointer(p.add(0x08));
    const pWeapon     = readPointer(p.add(0x10));
    const projId      = readU32(p.add(0x28));
    const material    = readU32(p.add(0x74));
    const type        = readU32(p.add(0x78));
    const partId      = readU32(p.add(0x7C));
    const projCls     = readU32(p.add(0xE4));
    const weaponCls   = readU32(p.add(0xE8));
    const remote      = readU8(p.add(0xEC));
    const explosion   = readU8(p.add(0xED));
    return `shooter=${pShooter} target=${pTarget} weapon=${pWeapon} projId=${projId} type=${type} material=${material} partId=${partId} projCls=0x${(projCls>>>0).toString(16)} weaponCls=0x${(weaponCls>>>0).toString(16)} remote=${remote} expl=${explosion}`;
  },

  // SArgRefs<float, bool>
  // CEntityComponentMiningLaser::RmAuthoritySetDesiredThrottle(ctx, float throttle, bool immediate)
  // @ decomp:188369. Reverse layout: @0=&bool, @8=&float.
  'CEntityComponentMiningLaser::RmAuthoritySetDesiredThrottle': (argRefs) => {
    const throttle  = argFloat(argRefs, 1);
    const immediate = argBool(argRefs, 0);
    return `throttle=${throttle} immediate=${immediate}`;
  },

  // SArgRefs<SReadWriteLockableValue<SNavigationRoute>>
  // CSCItemNavigation::RmAuthoritySyncClientSetRoute(ctx, SReadWriteLockableValue<SNavigationRoute>*)
  // @ decomp:231959. SReadWriteLockableValue is sizeof=0x530 wrapping
  // SNavigationRoute (sizeof=0x508): m_Route(SNavigationNode[20])@0,
  // m_CurrentIndex(char)@0x500, m_FinalStopInRoute(char)@0x501.
  // SNavigationNode per-element size = 0x500/20 = 0x40.
  'CSCItemNavigation:RmAuthoritySyncClientSetRoute': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const cur   = readU8(p.add(0x500));
    const final_ = readU8(p.add(0x501));
    // First node first 8 bytes (often an EntityId or a packed key) for orientation.
    const firstNode = readU64(p.add(0));
    return `currentIndex=${cur} finalStop=${final_} firstNode[0]=0x${firstNode}`;
  },

  // SArgRefs<CryGUID>
  // CSCItemMissileController::RmAuthoritySetMissileClassKey(ctx, __m128 *newClassGUID)
  // @ decomp:275330. __m128 here is the 16-byte CryGUID payload.
  'RmAuthoritySetMissileClassKey': (argRefs) => {
    const guid = readGuid(slotPtr(argRefs, 0));
    return `classGuid=${guid}`;
  },

  // SArgRefs<CryGUID, int>
  // CSCItemMissileController::RmAuthoritySetNetworkedUserMaxArmed(
  //   ctx, __m128 *classGUID, int newMax) @ decomp:275331.
  // Reverse layout: @0=&int, @8=&CryGUID.
  'RmAuthoritySetNetworkedUserMaxArmed': (argRefs) => {
    const newMax = argI32(argRefs, 0);
    const guid   = readGuid(slotPtr(argRefs, 1));
    return `classGuid=${guid} newMax=${newMax}`;
  },

  // SArgRefs<EASpawn::CClientItinerary>
  // CSCElectronicAccessPlayerComponent::RmAuthRequestSpawn(ctx, CClientItinerary*)
  // @ decomp:229140. CClientItinerary @ types.h:2550715 sizeof=0x50,
  // extends CSpawnItinerary<CClientItinerary> (sizeof=0x28):
  //   base (0..0x27):
  //     m_spawnReservation (CSpawnReservation 0x20) @ 0:
  //       m_spawnToken(u16)@0, m_spawnLocationId@8,
  //       m_spawnGroupId@0x10, m_spawnSlotId@0x18
  //     m_flags(CCryFlags<EItineraryFlags> u8)@0x20
  //   m_vehicleLoadoutHandle(CTypesafeId u32)@0x28
  //   m_loadoutItemExchange(vector)@0x30
  //   m_loadoutSelectionIndex(u8)@0x48
  'EAPlayer.authRequestSpawn': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const token   = readU16(p.add(0x00));
    const loc     = readU64(p.add(0x08));
    const grp     = readU64(p.add(0x10));
    const slot    = readU64(p.add(0x18));
    const flags   = readU8(p.add(0x20));
    const loadout = readU32(p.add(0x28)) >>> 0;
    const selIdx  = readU8(p.add(0x48));
    return `token=${token} location=0x${loc} group=0x${grp} slot=0x${slot} flags=0x${flags.toString(16)} loadoutHandle=${loadout} selectionIdx=${selIdx}`;
  },

  // SArgRefs<CTimeValue, SActorTeleportParams>
  // CSCActorActionHandler::RmTokenForceTeleportInStaging(ctx, CTimeValue ts, SActorTeleportParams*)
  // @ decomp:264424. SActorTeleportParams @ types.h:330089 sizeof=0x80:
  //   m_zoneEntityId@0, m_destination(QuatTS<double> 0x40)@8,
  //   m_worldPos(Vec3<double>)@0x48, m_aimRotation(Quat<float>)@0x60,
  //   m_lookOffsetAngles(AngYPR<float>)@0x70, m_bFadeAfterTeleport@0x7C,
  //   m_bDephysicalizeAfterTeleport@0x7D, m_bWaitForFloor@0x7E,
  //   m_bDelayAfterUnlink@0x7F
  // Reverse layout: @0=&SActorTeleportParams, @8=&CTimeValue.
  'CSCActorActionHandler::RmTokenForceTeleportInStaging': (argRefs) => {
    const ts = readTimeValue(slotPtr(argRefs, 1));
    const p  = slotPtr(argRefs, 0);
    if (p.isNull()) return `ts=${ts} params=?`;
    const zone   = readU64(p.add(0x00));
    const wpos   = readVec3d(p.add(0x48));
    const fade   = readU8(p.add(0x7C));
    const dephys = readU8(p.add(0x7D));
    const waitFl = readU8(p.add(0x7E));
    const delay  = readU8(p.add(0x7F));
    return `ts=${ts} zone=0x${zone} worldPos=${wpos} fade=${fade} dephys=${dephys} waitFloor=${waitFl} delay=${delay}`;
  },

  // SArgRefs<IEntityPtr>
  // CEntityComponentEAPlayableAreaController::RmMulticastPlayAudio(this, IEntityPtr pPlayer)
  // @ decomp:223164.
  'CEntityComponentEAPlayableAreaController::m_rmMulticastPlayAudio': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const player = readPointer(p);
    return `player=${player}`;
  },

  // SArgRefs<unsigned int>
  // CWeaponCommandBuffer::RmMulticastReceiveFirePress(ctx, u32 tick)
  // @ decomp:266242 / registration @ decomp:19532589 confirms template `<u32 const &>`.
  // (Hex-Rays shows a `double a4` but the dispatch template is single-arg —
  // that's a hallucinated register-state arg.)
  'CWeaponCommandBuffer::RmMulticastReceiveFirePress': (argRefs) => {
    return `tick=${argU32(argRefs, 0) >>> 0}`;
  },

  // SArgRefs<CryStringT<char>, bool, bool>
  // CSubsumptionMissionAudioComponent::MulticastEnqueueMissionAudio(
  //   ctx, CryStringT triggerName, bool isDialogue, bool isImmediate)
  // @ decomp:169706, dispatch confirmed @ decomp:12710589.
  // Reverse: @0=&bool isImmediate, @8=&bool isDialogue, @0x10=&CryStringT triggerName.
  'smac.rmMulticastEnqueueMissionAudio': (argRefs) => {
    const trig = readCryString(slotPtr(argRefs, 2), 96);
    const dlg  = argBool(argRefs, 1);
    const imm  = argBool(argRefs, 0);
    return `trigger=${JSON.stringify(trig)} isDialogue=${dlg} isImmediate=${imm}`;
  },

  // SArgRefs<EntityId, bool> — shares 0x14859f530 with pi.RmAuthorityNotifyLootEntityAccessed.
  // Different semantic: target entity + the new "attacker" flag value.
  'CTargetedEntries::m_rmMulticastUpdateAttackerFlag': (argRefs) =>
    `entity=${argU64Hex(argRefs, 1)} isAttacker=${argBool(argRefs, 0)}`,

  // SArgRefs<EntityId, EntityId> — shares 0x14859f478 with RequestNewLead.
  // Different semantic: (lockedTarget, requestor). Kept distinct for clarity.
  'RmAuthorityRequestLockTarget': (argRefs) =>
    `target=${argU64Hex(argRefs, 1)} requester=${argU64Hex(argRefs, 0)}`,

  // SArgRefs<float>
  // Weapon::CSCItemMissile::RmAuthorityRequestLockRatio(ctx, float lockRatio)
  // @ decomp:220848.
  'RmAuthorityRequestLockRatio': (argRefs) => `lockRatio=${argFloat(argRefs, 0)}`,

  // SArgRefs<float> — shares disp 0x1488b19c8 with LockRatio (same template,
  // different semantic). CSCActorCombatStats::RmMulticastGetMostUsedNonKbInput(
  //   this, float time) @ decomp:151520.
  'RmMulticastGetMostUsedNonKbInput': (argRefs) => `time=${argFloat(argRefs, 0)}`,

  // SArgRefs<EntityId, EntityId, __int16, unsigned __int8, unsigned int>
  // CSCPlayerGameRulesNetworkComponent::RmMulticastAddPoints(
  //   ctx, EntityId playerId, EntityId killedEntityId,
  //   i16 changeToScore, u8 type, u32 currentTeamScore) @ decomp:186708.
  // Reverse: @0=&u32, @8=&u8, @0x10=&i16, @0x18=&EntityId killed, @0x20=&EntityId player.
  'CSCPlayerGameRulesNetworkComponent::m_rmMulticastAddPoints': (argRefs) => {
    const player    = argU64Hex(argRefs, 4);
    const killed    = argU64Hex(argRefs, 3);
    const pChange   = slotPtr(argRefs, 2);
    const change   = pChange.isNull() ? '?' : (pChange.readS16());
    const type      = argU8(argRefs, 1);
    const teamScore = argU32(argRefs, 0) >>> 0;
    return `player=${player} killed=${killed} change=${change} type=${type} teamScore=${teamScore}`;
  },

  // SArgRefs<IEntityPtr, float>
  // CEntityComponentHostility::AuthNotifyHostileAction(this, IEntityPtr pShooter, float damage)
  // @ decomp:93464. Reverse: @0=&float, @8=&IEntityPtr.
  'ph.rmAuthNotifyHostileAction': (argRefs) => {
    const dmg     = argFloat(argRefs, 0);
    const sp      = slotPtr(argRefs, 1);
    const shooter = sp.isNull() ? '0x0' : readPointer(sp).toString();
    return `shooter=${shooter} damage=${dmg}`;
  },

  // SArgRefs<IEntityPtr, bool, float>
  // CEntityComponentHostility::AuthNotifyHostileActionPerformed(
  //   this, IEntityPtr pVictim, bool hitByMissile, float damage) @ decomp:93465.
  // Reverse: @0=&float, @8=&bool, @0x10=&IEntityPtr.
  'ph.rmAuthNotifyHostileActionPerformed': (argRefs) => {
    const dmg     = argFloat(argRefs, 0);
    const missile = argBool(argRefs, 1);
    const vp      = slotPtr(argRefs, 2);
    const victim  = vp.isNull() ? '0x0' : readPointer(vp).toString();
    return `victim=${victim} hitByMissile=${missile} damage=${dmg}`;
  },

  // SArgRefs<SKillParams>
  // CActor::RmMulticastKill(this, SKillParams*) @ decomp:151521.
  // SKillParams @ types.h:289195 sizeof=0x50:
  //   pShooter(IEntityPtr)@0, recentAttackers(set)@8, pWeapon@0x18,
  //   pProjectile@0x20, weaponClassId(u32)@0x28, impulseScale(float)@0x2C,
  //   dir(Vec3f)@0x30, hit_type(int)@0x3C, hit_partId(u16)@0x40,
  //   projectileClassId(u32)@0x44, winningKill(bool)@0x48
  'CActor::RmMulticastKill': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const shooter   = readPointer(p.add(0x00));
    const weapon    = readPointer(p.add(0x18));
    const proj      = readPointer(p.add(0x20));
    const wpnCls    = readU32(p.add(0x28)) >>> 0;
    let imp = NaN;
    try { imp = p.add(0x2C).readFloat(); } catch (_) {}
    const dir       = readVec3f(p.add(0x30));
    const hitType   = readU32(p.add(0x3C));
    const partId    = readU16(p.add(0x40));
    const projCls   = readU32(p.add(0x44)) >>> 0;
    const winning   = readU8(p.add(0x48));
    return `shooter=${shooter} weapon=${weapon} proj=${proj} weaponCls=0x${wpnCls.toString(16)} impulse=${imp} dir=${dir} hitType=${hitType} partId=${partId} projCls=0x${projCls.toString(16)} winning=${winning}`;
  },

  // SArgRefs<int, IEntityPtr, IEntityPtr>
  // CEntityComponentEAPlayableAreaController::RmMulticastInvokeAreaListener(
  //   this, int listenerToInvoke, IEntityPtr pPlayer, IEntityPtr pArea) @ decomp:223161.
  // Reverse: @0=&IEntityPtr area, @8=&IEntityPtr player, @0x10=&int listener.
  'CEntityComponentEAPlayableAreaController::m_rmMulticastInvokeAreaListener': (argRefs) => {
    const listener = argI32(argRefs, 2);
    const pPlayer  = slotPtr(argRefs, 1);
    const pArea    = slotPtr(argRefs, 0);
    const player   = pPlayer.isNull() ? '0x0' : readPointer(pPlayer).toString();
    const area     = pArea.isNull()   ? '0x0' : readPointer(pArea).toString();
    return `listener=${listener} player=${player} area=${area}`;
  },

  // SArgRefs<EntityId, CStringHash, SCommsConnectionParams>
  // CSCCommsComponent::RmAuthorityEstablishCommunicationWith(
  //   this, EntityId partnerId, CStringHash channelId, SCommsConnectionParams params)
  // @ decomp:248081. SCommsConnectionParams @ types.h:373005 sizeof=0x30:
  //   m_priority(int)@0, m_allowOutputVideo(bool)@4, m_allowInputVideo(bool)@5,
  //   m_autoOpenMobiglas(bool)@6, m_receiverFilterAreas(vec)@8,
  //   m_bFakeCommsCall(bool)@0x20, m_bDisableRTTCamera(bool)@0x21,
  //   m_fakeCallVideoPath(CryStringT)@0x28.
  // Reverse: @0=&SCommsConnectionParams, @8=&CStringHash, @0x10=&EntityId.
  'm_rmAuthorityEstablishCommunicationWith': (argRefs) => {
    const partner = argU64Hex(argRefs, 2);
    const channel = stringHashStr(slotPtr(argRefs, 1));
    const p       = slotPtr(argRefs, 0);
    if (p.isNull()) return `partner=${partner} channel=${channel} params=?`;
    const prio    = readU32(p.add(0));
    const outVid  = readU8(p.add(4));
    const inVid   = readU8(p.add(5));
    const autoMG  = readU8(p.add(6));
    const filtSz  = readVectorSize(p.add(8), 8);
    const fakeCC  = readU8(p.add(0x20));
    const noRTT   = readU8(p.add(0x21));
    return `partner=${partner} channel=${channel} priority=${prio} outVid=${outVid} inVid=${inVid} autoMG=${autoMG} filterAreas.size=${filtSz} fakeCall=${fakeCC} noRTT=${noRTT}`;
  },

  // SArgRefs<SCommsConnection>
  // CSCCommsComponent::RmMulticastAddConnection(this, SCommsConnection*)
  // @ decomp:248088. SCommsConnection @ types.h:1518759 sizeof=0xC0:
  //   m_connectionId(CStringHash 0x18)@0, m_channelId(CStringHash 0x18)@0x18,
  //   m_private(bool)@0x30, m_hailStatus(u32)@0x34,
  //   m_previousHailStatus(u32)@0x38, m_timeEnteredState(CTimeValue)@0x40,
  //   m_removeFlag(bool)@0x48, m_commsPartner(SCommsConnectionPeer 0x10)@0x50,
  //   m_receivingVideoType(u32)@0x80, m_preferredVideoType(u32)@0x84.
  'm_rmMulticastAddConnection': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const connId   = stringHashStr(p.add(0x00));
    const chanId   = stringHashStr(p.add(0x18));
    const priv     = readU8(p.add(0x30));
    const hail     = readU32(p.add(0x34));
    const prevHail = readU32(p.add(0x38));
    const ts       = readTimeValue(p.add(0x40));
    const rmFlag   = readU8(p.add(0x48));
    return `connId=${connId} channel=${chanId} private=${priv} hail=${hail}(${enumName(E_HAIL_STATUS, hail)}) prevHail=${prevHail}(${enumName(E_HAIL_STATUS, prevHail)}) enteredAt=${ts} removeFlag=${rmFlag}`;
  },

  // SArgRefs<EntityId, CLocTranslated>
  // CSCPlayerGameRulesNetworkComponent::RmMulticastFriendlyFireMessage(
  //   ctx, EntityId playerId, CLocTranslated msg) @ decomp:186713.
  // CLocTranslated @ types.h:501160 sizeof=0x8: single CryStringT<wchar_t> m_content.
  // Reverse: @0=&CLocTranslated, @8=&EntityId.
  'CSCPlayerGameRulesNetworkComponent::m_rmMulticastFriendlyFireMessage': (argRefs) => {
    const player = argU64Hex(argRefs, 1);
    const msgP   = slotPtr(argRefs, 0);
    // m_content is a CryStringT<wchar_t> (UTF-16). Surface the raw pointer.
    const wstrPtr = msgP.isNull() ? NULL : readPointer(msgP);
    return `player=${player} msg=${wstrPtr}`;
  },

  // SArgRefs<Missile::ELaunchStates>
  // Weapon::CEntityComponentExplosiveOrdnance::RmAuthorityRequestLaunchState(
  //   ctx, ELaunchStates state) @ decomp:220847.
  'RmAuthorityRequestLaunchState': (argRefs) => {
    const v = argU32(argRefs, 0) >>> 0;
    return `state=${v}(${enumName(E_LAUNCH_STATES, v)})`;
  },

  // SArgRefs<Vec3<double>, Vec3<float>, EntityId, Vec3<float>, bool>
  // Weapon::CEntityComponentExplosiveOrdnance::RmMulticastExplode(
  //   ctx, Vec3<double> position_ws, Vec3<float> direction_ws,
  //   EntityId colEntityId, Vec3<float> impactVelocity_ws, bool isImpact)
  // @ decomp:220850, dispatch confirmed @ decomp:16224064.
  // Reverse: @0=&bool, @8=&Vec3<float> impactVel, @0x10=&EntityId,
  //   @0x18=&Vec3<float> dir, @0x20=&Vec3<double> pos.
  'RmMulticastExplode': (argRefs) => {
    const isImpact   = argBool(argRefs, 0);
    const impactVel  = readVec3f(slotPtr(argRefs, 1));
    const colEntity  = argU64Hex(argRefs, 2);
    const direction  = readVec3f(slotPtr(argRefs, 3));
    const position   = readVec3d(slotPtr(argRefs, 4));
    return `position=${position} direction=${direction} colEntity=${colEntity} impactVel=${impactVel} isImpact=${isImpact}`;
  },

  // SArgRefs<EntityId, unsigned __int8>
  // CSCElectronicAccessPlayerComponent::RmAuthEntitySpawnNotification(
  //   ctx, EntityId entityId, u8 notificationId) @ decomp:229133.
  // Dispatcher type confirmed @ decomp:16716159.
  // Reverse layout: @0=&u8, @8=&EntityId.
  'EAPlayer.authEntitySpawnNotification': (argRefs) => {
    const entity         = argU64Hex(argRefs, 1);
    const notificationId = argU8(argRefs, 0);
    return `entity=${entity} notificationId=${notificationId}`;
  },

  // SArgRefs<Vec3<double>, Vec3<float>, EntityId>
  // CEntityComponentHealth::m_rmMulticastExplode (registered as "Explode" at
  // decomp:15792043). Dispatch template confirmed @ decomp:15792060.
  // Reverse layout: @0=&EntityId, @8=&Vec3<float>, @0x10=&Vec3<double>.
  'Explode': (argRefs) => {
    const colEntity   = argU64Hex(argRefs, 0);
    const direction   = readVec3f(slotPtr(argRefs, 1));
    const position    = readVec3d(slotPtr(argRefs, 2));
    return `position=${position} direction=${direction} colEntity=${colEntity}`;
  },

  // SArgRefs<IEntityPtr, float, double, __int64, IEntityPtr, __int64>
  // CEntityComponentEAPlayableAreaController::RmMulticastUpdateUI(
  //   this, IEntityPtr pPlayer, float timer, double redoutStrength,
  //   __int64 phaseChange, IEntityPtr pClosestArea, __int64 reset)
  // @ decomp:223170. Reverse layout: slot 0=reset, slot 1=pClosest,
  //   slot 2=phaseChange, slot 3=redout, slot 4=timer, slot 5=pPlayer.
  'CEntityComponentEAPlayableAreaController::m_rmMulticastUpdateUI': (argRefs) => {
    const reset    = argI64Hex(argRefs, 0);
    const closeP   = slotPtr(argRefs, 1);
    const phase    = argI64Hex(argRefs, 2);
    const redout   = argDouble(argRefs, 3);
    const timer    = argFloat(argRefs, 4);
    const playerP  = slotPtr(argRefs, 5);
    const player   = playerP.isNull() ? '0x0' : readPointer(playerP).toString();
    const closest  = closeP.isNull()  ? '0x0' : readPointer(closeP).toString();
    return `player=${player} timer=${timer} redout=${redout} phaseChange=${phase} closestArea=${closest} reset=${reset}`;
  },

  // SArgRefs<EASpawn::CSpawnReservation>
  // CSCElectronicAccessPlayerComponent::RmAuthRequestSlotBooking(ctx, CSpawnReservation*)
  // dispatcher signature @ decomp:16716191; struct @ types.h:2550659 sizeof=0x20:
  //   m_spawnToken(u16)@0, m_spawnLocationId(EntityId)@8,
  //   m_spawnGroupId(EntityId)@0x10, m_spawnSlotId(EntityId)@0x18
  'EAPlayer.authRequestSlotBooking': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const token = readU16(p.add(0x00));
    const loc   = readU64(p.add(0x08));
    const grp   = readU64(p.add(0x10));
    const slot  = readU64(p.add(0x18));
    return `token=${token} location=0x${loc} group=0x${grp} slot=0x${slot}`;
  },

  // SArgRefs<SAttachableSerializationDetach>
  // CAttachableComponent::m_rmMulticastDetachFromEntity dispatcher signature
  // confirmed via lambda binding @ decomp:10060442.
  // SAttachableSerializationDetach @ types.h:564823 sizeof=0x28:
  //   entity(EntityId)@0, port(SItemPortId 0x10)@8,
  //   attachReason(EPersistentModificationReason u32)@0x18,
  //   detachBehavior(ItemPort::SDetachBehavior u32)@0x1C,
  //   bAnimationTriggered(bool)@0x24
  'MulticastDetachFromEntity': (argRefs) => {
    const p = slotPtr(argRefs, 0);
    if (p.isNull()) return null;
    const entity     = readU64(p.add(0x00));
    const portOwner  = readU64(p.add(0x08));
    const portId     = readU16(p.add(0x10));
    const reason     = readU32(p.add(0x18)) >>> 0;
    const detach     = readU32(p.add(0x1C)) >>> 0;
    const animTrig   = readU8(p.add(0x24));
    return `entity=0x${entity} port=(owner=0x${portOwner} id=${portId}) reason=${reason} detach=${detach} anim=${animTrig}`;
  },
};

// Dispatch-pointer fallback. When two RMIs share the same `argDispatch`
// pointer they share an identical SArgRefs layout, so a decoder keyed by
// dispatch resolves any newly observed name automatically.
//
// Pre-seeded from the original triage so the cache hits cold (the first
// time we see e.g. `pi.RmRequestOpenInventory` we resolve it via the
// `<EntityId>` decoder that ships with the script). Lazily extended at
// runtime when a name-keyed lookup succeeds (see decodePayload).
const dispatchDecoders = new Map();

// Absolute dispatch pointers observed in /tmp/diffusion_rpc_triage.json
// (module base 0x140000000). Each maps to the canonical decoder name in
// the `decoders` table above; siblings sharing the same dispatch get
// resolved through this map after the first name-keyed lookup.
const KNOWN_DISPATCH_PTRS = {
  '0x148f09f08': 'CSCActorActionHandler::RmAuthoritySendActions',
  '0x148b520b0': 'RmAuthorityConsumeThrusterFuel',
  '0x148b7dbe0': 'CVisionComponent::RmAuthorityRemoteObservableUpdate',
  '0x148f25358': 'CWeaponCommandBuffer::RmAuthorityRequestCommand',
  '0x14850f690': 'CTargetedEntries::m_rmAuthorityRemoveAllPinnedTargets',
  '0x1487a6d98': 'AuthorityAttachToPort',
  '0x148aa8400': 'CSCPlayerGameRulesNetworkComponent::m_rmAuthorityRequestHit',
  '0x14850f5d0': 'AuthorityOnInteractionStateChange',
  '0x148e3dab0': 'm_rmMulticastSetHailStatus',
  '0x1488b19a8': 'RmAuthorityUpdateInputDevice',
  '0x14859f478': 'CTractorBeamMultitractorUtils::RmAuthorityRequestNewLead',
  '0x148e62600': 'RmAuthorityOnAlignedToTarget',
  '0x1487a61b8': 'SvRequestSharedInteract',
  '0x148b7dc88': 'AuthoritySendAISignal',
  '0x148ad3ae8': 'pi.RmAuthorityOnContainerAccessed',
  '0x148caee10': 'RmAuthorityRequestExplosionSafety',
  '0x148d43980': 'RmHandleAppData',
  '0x148f5e9f0': 'CWeaponActionFireTractorBeam::RmAuthoritySetTarget',
  '0x1487a6198': 'SvRequestInteract',
  '0x148de3e50': 'SvOnSetState',
  '0x14850f4e0': 'CWeaponActionFireTractorBeam::RmAuthoritySetAmmoCount',
  '0x14850f6d0': 'CEntityComponentKioskInteraction::RmAuthoritySetUserId',
  '0x1489809e8': 'CTargetedEntries::m_rmAuthorityOnExchangedLockedTarget',
  '0x148c02870': 'pi.RmAuthorityProcessInventoryManagementOperation',
  '0x1487a7200': 'irc_authoritySetState',
  '0x148a12e48': 'CSCItemElevator::RmMulticastSetTargetStop',
  '0x148b1b0f8': 'CSCItemElevator::RmMulticastSetElevatorState',
  '0x1485dc6b0': 'mbi.AuthAbandonMissionRequest',
  '0x1485dc690': 'mbi.AuthAcceptMissionRequest',
  '0x148c03be0': 'RmAuthoritySetInteractionState',
  '0x148de4600': 'shopUI.m_rmAuthority_OnSelectedLocationChanged',
  '0x1487ebef0': 'RmAuthRequestStateChange',
  '0x1487a7608': 'shopUI.rmAuthSetTransactionMode',
  '0x14897c1e8': 'ping.requestWaveState',
  '0x1486fc678': 'CEntityComponentUserVariables::RmAuthorityChangeFloatVariable',
  '0x148c4f490': 'RmAuthorityRequestDamageMapHitFromHitInfo',
  '0x148bae918': 'ControllableManager_RequestMasterMode',
  '0x148f16dc0': 'AuthorityReserveUser',
  '0x148d163a8': 'RmAuthorityRequestVehicleInfos',
  '0x148e3d9f0': 'm_rmAuthorityStopCommunicationWith',
  '0x14859f530': 'pi.RmAuthorityNotifyLootEntityAccessed',
  '0x1485d86c8': 'journal.rmAuthEntriesViewed',
  '0x148b51d18': 'RmStandardItemBuyShopRequest',
  '0x148baf038': 'CSCItemEnergyController::RmAuthorityRequestTogglePowerGroupState',
  '0x148e62e30': 'RmAuthorityATCRequest',
  '0x1486fc538': 'CEntityComponentUIBindingsInteractions::RmBuildingBlocksSetState',
  '0x1489e1da0': 'RmAuthoritySetDrugDose',
  '0x148e76ac0': 'CEntityComponentCloneLocationUIProvider::RmAuthorityOnPopupChanged',
  '0x148e62620': 'RmAuthorityOnActionTryBeginQuantumTravel',
  '0x1486fc558': 'CEntityComponentUIBindingsInteractions::RmBuildingBlocksPerformInteraction',
  '0x148de47a0': 'commodityUI.m_rmAuthority_CargoLocationDataRequest',
  '0x148bae058': 'ControlContext_AuthorityRequestOperatorMode',
  '0x148ee8fd8': 'CSCActorSpatialAwareness::RmAuthorityLookAtPOIRequest',
  '0x1487a74f8': 'rmAuthorityRequestPoolTargets',
  '0x148c041b8': 'RmAuthorityOnSelectNavigationTab',
  '0x148d50370': 'CSCItemNavigation:RmAuthorityBeginRouteCalculation',
  '0x148de4800': 'commodityUI.m_rmAuthority_CargoInventoryDataRequest',
  '0x14859f458': 'CEntityComponentCriminalRecordUIProvider::RmAuthoritySetBindingTriggerIds',
  '0x148d502c0': 'RmAuthorityRequestActiveInventoryId',
  '0x148d16388': 'RmAuthorityFetchPrices',
  '0x148d16348': 'RmAuthorityRequestClaim',
  '0x148de3718': 'RmAuthorityRequestPermission',
  '0x1485db8d0': 'pml.AuthCreateMissionServiceBeacon',
  '0x148b51d58': 'RmRentalRequest',
  '0x1486fc638': 'CEntityComponentUserVariables::RmAuthorityChangeBoolVariable',
  '0x148c02890': 'pi.m_rmAuthorityRequestChangePortOnEquippedItem',
  '0x1488b1cd0': 'CActor::RmAuthorityRequestDisconnect',
  '0x14859f438': 'CEntityComponentCriminalRecordUIProvider::RmAuthorityPayFine',
  '0x148a81c58': 'SvRequestTrade',
  // Additions discovered post-triage:
  '0x148d50390': 'CSCItemNavigation:RmAuthoritySyncClientSetRoute',
  '0x148ae8020': 'CEntityComponentMiningLaser::RmAuthoritySetDesiredThrottle',
  '0x148f96d28': 'RmAuthoritySetMissileClassKey',
  '0x148f96d48': 'RmAuthoritySetNetworkedUserMaxArmed',
  '0x1487a6db8': 'MulticastDetachFromEntity',
  '0x148d2b410': 'EAPlayer.authRequestSlotBooking',
  '0x148d2b3f0': 'EAPlayer.authRequestSpawn',
  '0x148f09f28': 'CSCActorActionHandler::RmTokenForceTeleportInStaging',
  '0x148cd1b48': 'CEntityComponentEAPlayableAreaController::m_rmMulticastUpdateUI',
  '0x14858cea0': 'CEntityComponentEAPlayableAreaController::m_rmMulticastPlayAudio',
  '0x148f25398': 'CWeaponCommandBuffer::RmMulticastReceiveFirePress',
  '0x148c4f450': 'Explode',
  '0x148ad3c08': 'EAPlayer.authEntitySpawnNotification',
  '0x1489e1d80': 'smac.rmMulticastEnqueueMissionAudio',
  '0x1488b19c8': 'RmAuthorityRequestLockRatio',
  '0x148ad3bc8': 'CSCPlayerGameRulesNetworkComponent::m_rmMulticastAddPoints',
  '0x14858ce60': 'ph.rmAuthNotifyHostileAction',
  '0x14858ce80': 'ph.rmAuthNotifyHostileActionPerformed',
  '0x1488af5f8': 'CActor::RmMulticastKill',
  '0x148cd1b68': 'CEntityComponentEAPlayableAreaController::m_rmMulticastInvokeAreaListener',
  '0x148e3d9d0': 'm_rmAuthorityEstablishCommunicationWith',
  '0x148e3da90': 'm_rmMulticastAddConnection',
  '0x148ad3ba8': 'CSCPlayerGameRulesNetworkComponent::m_rmMulticastFriendlyFireMessage',
  '0x148caedf0': 'RmAuthorityRequestLaunchState',
  '0x148caee30': 'RmMulticastExplode',
};

function bootstrapDispatchDecoders() {
    let seeded = 0, missing = 0;
    for (const [ptrStr, name] of Object.entries(KNOWN_DISPATCH_PTRS)) {
        const d = decoders[name];
        if (!d) { missing++; continue; }
        dispatchDecoders.set(ptrStr, d);
        seeded++;
    }
    console.log(`[dispatch] seeded ${seeded} dispatch->decoder mappings (${missing} unmapped names)`);
}

function decodePayload(name, argRefs, argDispatch) {
  if (!argRefs || argRefs.isNull()) return null;
  let decoder = decoders[name];
  const dispKey = (argDispatch && !argDispatch.isNull()) ? argDispatch.toString() : null;

  // Name match wins; also record the dispatch -> decoder mapping so the next
  // observation of a sibling name (same dispatch, new name string) resolves.
  if (decoder) {
    if (dispKey && !dispatchDecoders.has(dispKey)) dispatchDecoders.set(dispKey, decoder);
  } else if (dispKey) {
    decoder = dispatchDecoders.get(dispKey);
  }
  if (!decoder) return null;
  try {
    return decoder(argRefs);
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Inventory: one entry per unique reg. Full record on first sight; thereafter
// only a periodic stats snapshot, so repeated hot calls don't flood output.
// ---------------------------------------------------------------------------

// Dedup the live log by *logical method*, not per-instance reg. The same RMI
// method shares one argDispatch across every entity/component instance, so
// keying by argDispatch collapses N reg pointers down to one "(new)" log.
// Name is fallback when argDispatch is null; reg is last-resort.
const inventory = new Map(); // methodKey -> { count, lastLoggedCount }
const SNAPSHOT_EVERY = 5000; // re-log a known method every N total calls

function methodKey(reg, name) {
    if (reg.argDispatch && !reg.argDispatch.isNull()) return `disp:${reg.argDispatch}`;
    if (name) return `name:${name}`;
    return `reg:${reg.reg}`;
}

function shouldLog(reg, name) {
    const key = methodKey(reg, name);
    const entry = inventory.get(key);
    if (!entry) {
        inventory.set(key, {
            count: 1,
            lastLoggedCount: 1
        });
        return {
            log: true,
            first: true
        };
    }
    entry.count++;
    if (entry.count - entry.lastLoggedCount >= SNAPSHOT_EVERY) {
        entry.lastLoggedCount = entry.count;
        return {
            log: true,
            first: false
        };
    }
    return {
        log: false,
        first: false
    };
}

// ---------------------------------------------------------------------------
// Triage state
// ---------------------------------------------------------------------------
//
// Keyed by reg pointer so duplicate (this, id) pairs collapse to the same
// registration. Each entry carries:
//   - identity:   name, componentId, direction, mode, dispatch, argDispatch
//   - load:       count, resultCounts {OK, NotRegistered, ...}, sourceCounts
//   - payload:    sizeBitsMin/Max/Sum/Count (if MEASURE_ARG_BITS), argRefsHex
//   - shape:      slots[]  — per-pointer probe of argRefs[0..N], captured once
//
// Same argDispatch ptr across methods => same serializer => same arg layout,
// so the dispatch ptr is the canonical grouping key for decoder reuse.

const triage = TRIAGE_ENABLED ? new Map() : null; // reg.toString() -> entry
let triageCalls = 0;

function captureFingerprint(argRefs) {
    if (!argRefs || argRefs.isNull()) return null;
    const hex = readHex(argRefs, TRIAGE_FP_HEX_LEN);
    const slots = [];
    for (let i = 0; i < TRIAGE_SLOT_PROBE; i++) {
        const slotAddr = argRefs.add(i * Process.pointerSize);
        const ptr = readPointer(slotAddr);
        if (ptr.isNull()) {
            slots.push({ ptr: '0x0', head: null });
            continue;
        }
        slots.push({ ptr: ptr.toString(), head: readHex(ptr, TRIAGE_SLOT_HEAD_LEN) || null });
    }
    return { hex, slots };
}

function triageRecord(reg, source, argRefs) {
    if (!triage) return;
    const key = (reg.argDispatch && !reg.argDispatch.isNull())
        ? `disp:${reg.argDispatch}`
        : `reg:${reg.reg}`;
    let entry = triage.get(key);
    if (!entry) {
        entry = {
            reg: key,
            name: reg.name,
            nameBytes: reg.name ? null : reg.nameBytes,
            componentId: reg.componentId,
            direction: reg.direction,
            directionName: directionName(reg.direction),
            mode: reg.mode,
            modeName: modeName(reg.mode),
            dispatch: reg.dispatch.toString(),
            argDispatch: reg.argDispatch.toString(),
            dirtyIndex: reg.dirtyIndex,
            count: 0,
            sourceCounts: {},
            resultCounts: {},
            sizeBitsMin: null,
            sizeBitsMax: null,
            sizeBitsSum: 0,
            sizeBitsCount: 0,
            fingerprint: captureFingerprint(argRefs),
            firstSeenSeq: triageCalls + 1,
        };
        triage.set(key, entry);
    }
    entry.count++;
    const sk = String(source);
    entry.sourceCounts[sk] = (entry.sourceCounts[sk] || 0) + 1;

    // Cap size sampling per reg: enough for min/max characterization on
    // variable-length args without paying the vtable call on every hot send.
    if (MEASURE_ARG_BITS && entry.sizeBitsCount < TRIAGE_SIZE_SAMPLES &&
        argRefs && !argRefs.isNull() && !reg.argDispatch.isNull()) {
        const bits = measureArgBits(reg.argDispatch, argRefs);
        if (bits >= 0 && bits < (1 << 30)) {
            entry.sizeBitsSum += bits;
            entry.sizeBitsCount++;
            if (entry.sizeBitsMin === null || bits < entry.sizeBitsMin) entry.sizeBitsMin = bits;
            if (entry.sizeBitsMax === null || bits > entry.sizeBitsMax) entry.sizeBitsMax = bits;
        }
    }
}

function triageRecordResult(reg, resultCode) {
    if (!triage) return;
    const entry = triage.get(reg.reg.toString());
    if (!entry) return;
    const rk = String(resultCode);
    entry.resultCounts[rk] = (entry.resultCounts[rk] || 0) + 1;
}

function triageFlush(reason) {
    if (!triage) return 0;
    const rows = [];
    for (const entry of triage.values()) {
        rows.push({
            name: entry.name || `<unresolved:${entry.nameBytes || ''}>`,
            count: entry.count,
            componentId: entry.componentId,
            direction: `${entry.direction}(${entry.directionName})`,
            mode: `${entry.mode}(${entry.modeName})`,
            argDispatch: entry.argDispatch,
            dispatch: entry.dispatch,
            sizeBits: entry.sizeBitsCount ? {
                min: entry.sizeBitsMin,
                max: entry.sizeBitsMax,
                mean: Math.round(entry.sizeBitsSum / entry.sizeBitsCount),
                samples: entry.sizeBitsCount,
            } : null,
            sourceCounts: entry.sourceCounts,
            resultCounts: entry.resultCounts,
            reg: entry.reg,
            firstSeenSeq: entry.firstSeenSeq,
            fingerprint: entry.fingerprint,
        });
    }
    rows.sort((a, b) => b.count - a.count);
    const payload = {
        ts: Date.now(),
        reason,
        totalCalls: triageCalls,
        uniqueRegs: rows.length,
        moduleBase: base.toString(),
        rows,
    };
    try {
        const f = new File(TRIAGE_PATH, 'w');
        f.write(JSON.stringify(payload, null, 2));
        f.close();
        console.log(`[triage] ${reason}: ${rows.length} regs, ${triageCalls} calls -> ${TRIAGE_PATH}`);
    } catch (e) {
        console.log(`[triage] write failed: ${e && e.message}`);
    }
    return rows.length;
}

rpc.exports = {
    report() { return triageFlush('rpc'); },
    clear() {
        if (triage) triage.clear();
        triageCalls = 0;
        return 0;
    },
    top(n) {
        if (!triage) return [];
        const rows = Array.from(triage.values())
            .sort((a, b) => b.count - a.count)
            .slice(0, n || 20)
            .map((e) => ({ name: e.name || '<unresolved>', count: e.count, argDispatch: e.argDispatch }));
        return rows;
    },
};

function isPlausibleReg(reg) {
    // Strong invariants from the struct/decompile. A reg violating these came
    // from a mis-resolved table — never feed it to measureArgBits (which calls
    // through reg.argDispatch's vtable) or to triage (which persists it).
    if (!reg.reg || reg.reg.isNull()) return false;
    if (reg.componentId < 0 || reg.componentId > 0xFFFF) return false;
    if (reg.direction > 2) return false;   // ESerializedRemoteMethodDirection: 0/1/2
    if (reg.mode > 3) return false;          // observed 0/1/2
    if (!reg.name && reg.namePointer.isNull()) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

let sequence = 0;

function hook() {
    const target = rva(RVAS.SendRemoteMethodCall);
    console.log(`[+] hooking SendRemoteMethodCall @ ${target}`);
    console.log(`[+] symbol=${DebugSymbol.fromAddress(target)}`);

    Interceptor.attach(target, {
        onEnter(args) {
            const thisPointer = args[0];
            const result = args[1];
            const id = args[2].toInt32() & 0xFFFF;
            const callContext = args[3]; // SSerializedRemoteMethodCallContext*, NOT this.context

            let argRefs = NULL;
            try {
                argRefs = this.context.rsp.add(0x28).readPointer(); // here this.context (CPU regs) IS correct
            } catch (_) {}

            const reg = readRegistration(thisPointer, id);

            if (!isPlausibleReg(reg)) {
                if (resolveFailCount < RESOLVE_FAIL_LOG_LIMIT) {
                    resolveFailCount++;
                    console.log(`[RMI] resolve fail #${resolveFailCount}: this=${thisPointer} id=${id} reg=${reg.reg} component=${reg.componentId} dir=${reg.direction}`);
                }
                this.state = { skip: true };
                return;
            }

            const name = reg.name || '<unresolved>';
            const skip = isFiltered(name);

            const source = readU32(callContext);
            triageCalls++;
            if (reg.reg && !reg.reg.isNull()) {
                triageRecord(reg, source, argRefs);
                if (TRIAGE_ENABLED && (triageCalls % TRIAGE_FLUSH_EVERY) === 0) {
                    triageFlush('auto');
                }
            }

            this.state = {
                result,
                reg,
                skip
            };
            if (skip) return;

            const decision = shouldLog(reg, reg.name);
            if (!decision.log) {
                this.state.quiet = true;
                return;
            }

            const payload = decodePayload(reg.name, argRefs, reg.argDispatch);

            sequence++;
            console.log('');
            console.log(`[RMI #${sequence}] ${decision.first ? '(new)' : '(snapshot)'} id=${id} name=${JSON.stringify(name)} source=${source}(${sourceName(source)})`);
            console.log(`    this=${thisPointer} reg=${reg.reg} component=${reg.componentId} direction=${reg.direction}(${directionName(reg.direction)}) mode=${reg.mode}(${modeName(reg.mode)})`);
            console.log(`    pRemoteMethod=${reg.dispatch} pArgDispatch=${reg.argDispatch} dirtyIndex=${reg.dirtyIndex} gateByte=0x${(reg.gateByte >>> 0).toString(16)}`);
            console.log(`    stats=${reg.stats} calls=${reg.statCalls} accumBytes=${reg.statBytes}`);

            if (payload) {
                console.log(`    payload: ${payload}`);
            } else if (DUMP_ARGS && !argRefs.isNull()) {
                console.log(`    args@${argRefs}: ${readHex(argRefs, ARG_DUMP_LEN)}`);
            }
        },

        onLeave() {
            const state = this.state;
            if (!state) return;

            let resultCode = -1;
            let callLocalImmediate = -1;
            try {
                if (state.result && !state.result.isNull()) {
                    resultCode = state.result.readU32();
                    callLocalImmediate = state.result.add(4).readU8();
                }
            } catch (_) {}

            if (state.reg && state.reg.reg && !state.reg.reg.isNull()) {
                triageRecordResult(state.reg, resultCode);
            }

            if (state.skip || state.quiet) return;

            const resultName = {
                0: 'OK',
                1: 'NotRegistered',
                2: 'NotBoundToNetwork',
                3: 'OverBudget',
            } [resultCode] || resultCode;

            const callsAfter = (state.reg && !state.reg.stats.isNull()) ?
                readU32(state.reg.stats.add(0x28)) :
                -1;

            console.log(`[RMI #${sequence}] -> result=${resultCode}(${resultName}) callLocalImmediate=${callLocalImmediate} callsAfter=${callsAfter}`);
        },
    });
}

bootstrapDispatchDecoders();
hook();

if (TRIAGE_ENABLED) {
    console.log(`[triage] enabled — auto-flush every ${TRIAGE_FLUSH_EVERY} calls to ${TRIAGE_PATH}`);
    console.log('[triage] interactive: rpc.exports.report() | .top(n) | .clear()');
}

// Frida invokes this when the script is unloaded. Last chance to persist data.
function dispose() {
    if (TRIAGE_ENABLED) triageFlush('dispose');
}
// eslint-disable-next-line no-undef
globalThis.dispose = dispose;
