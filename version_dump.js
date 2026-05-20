'use strict';

const MODULE_NAME = "StarCitizen.exe";
const RVA_GetGameHashValues = 0x69CBFE0;

const mod = Process.getModuleByName(MODULE_NAME);
const pGetGameHashValues = mod.base.add(RVA_GetGameHashValues);

console.log(`[+] Module ${MODULE_NAME} @ ${mod.base}`);
console.log(`[+] GetGameHashValues @ ${pGetGameHashValues}`);

// ---------------------------------------------------------------------------
// CryString reader — tries multiple known header layouts, falls back to
// raw NUL-terminated read, and finally dumps surrounding bytes for inspection.
// ---------------------------------------------------------------------------

function tryReadString(dataPtr, len) {
    if (len < 0 || len > 0x1000) return null;
    try {
        return dataPtr.readUtf8String(len);
    } catch (_) {
        return null;
    }
}

function readCryString(pCryString, dumpOnFail) {
    let dataPtr;
    try {
        dataPtr = pCryString.readPointer();
    } catch (e) {
        return `<bad string ptr: ${e.message}>`;
    }
    if (dataPtr.isNull()) return "<null>";

    // Candidate length offsets (CryEngine variants):
    //   layout A (classic):  refcnt:-0x10, len:-0x08, alloc:-0x04
    //   layout B:            refcnt:-0x10, len:-0x0C, alloc:-0x08
    //   layout C (CE5/SC):   refcnt:-0x10, alloc:-0x0C, len:-0x08
    const lenOffsets = [-0x08, -0x0C, -0x04];
    for (const off of lenOffsets) {
        try {
            const len = dataPtr.add(off).readS32();
            const s = tryReadString(dataPtr, len);
            if (s !== null && /^[\x20-\x7E]*$/.test(s) && s.length === len) {
                return s;
            }
        } catch (_) { /* keep trying */ }
    }

    // Fallback: NUL-terminated
    try {
        const s = dataPtr.readCString();
        if (s !== null) return s;
    } catch (_) {}

    if (dumpOnFail) {
        try {
            console.log("    [hexdump of string region]");
            console.log(hexdump(dataPtr.sub(0x10), { length: 0x40, ansi: false }));
        } catch (_) {}
    }
    return "<unreadable>";
}

// ---------------------------------------------------------------------------
// Hash combine — Boost-style, 64-bit seed, for verification
// ---------------------------------------------------------------------------

function mix64(seed, value) {
    // seed ^= value + 0x9E3779B9 + (seed << 6) + (seed >> 2)
    const PHI = 0x9E3779B9n;
    const v = BigInt.asUintN(64, BigInt(value));
    const s = BigInt.asUintN(64, seed);
    const term = BigInt.asUintN(64, v + PHI + ((s << 6n) & 0xFFFFFFFFFFFFFFFFn) + (s >> 2n));
    return BigInt.asUintN(64, s ^ term);
}

function computeExpectedIdentifier(gv, cmp, cls, arc, dc, oc) {
    let h = BigInt(gv);
    h = mix64(h, cmp);   // a2[1] — component
    h = mix64(h, cls);   // a2[2] — class
    h = mix64(h, arc);   // a2[3] — archetypes
    h = mix64(h, dc);    // a2[4] — datacore
    h = mix64(h, oc);    // a2[5] — objContainers
    const bytes = [];
    for (let i = 7; i >= 0; i--) {
        bytes.push(Number((h >> BigInt(8 * i)) & 0xFFn).toString(16).padStart(2, '0'));
    }
    return bytes.slice(0, 4).join('') + '-' + bytes.slice(4).join('');
}

// ---------------------------------------------------------------------------
// Dumper
// ---------------------------------------------------------------------------

function dumpSGameHashValues(pOut, tag, dumpStringRegion) {
    const gv    = pOut.add(0x00).readU32();
    const cmp   = pOut.add(0x04).readU32();
    const cls   = pOut.add(0x08).readU32();
    const arc   = pOut.add(0x0C).readU32();
    const dc    = pOut.add(0x10).readU32();
    const oc    = pOut.add(0x14).readU32();
    const vid   = readCryString(pOut.add(0x18), dumpStringRegion);
    const hex   = (n) => "0x" + (n >>> 0).toString(16).padStart(8, '0');

    console.log(`\n========== SGameHashValues @ ${pOut} [${tag}] ==========`);
    console.log(`  m_gameVersion          : ${gv}  (${hex(gv)})`);
    console.log(`  m_componentRegistryCRC : ${hex(cmp)}`);
    console.log(`  m_classRegistryCRC     : ${hex(cls)}`);
    console.log(`  m_entityArchetypesCRC  : ${hex(arc)}`);
    console.log(`  m_dataCoreCRC          : ${hex(dc)}`);
    console.log(`  m_objectContainersCRC  : ${hex(oc)}`);
    console.log(`  m_versionIdentifier    : "${vid}"`);
    if (gv === 1) {
        const expected = computeExpectedIdentifier(gv, cmp, cls, arc, dc, oc);
        console.log(`  computed (verify)      : "${expected}"`);
    }
    console.log(`==========================================================\n`);
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

Interceptor.attach(pGetGameHashValues, {
    onEnter(args) {
        this.pOut = args[1];
        // Skip onEnter dump — the buffer is uninitialized stack memory and the
        // numeric fields you saw were garbage. Only post-fill is meaningful.
    },
    onLeave(retval) {
        dumpSGameHashValues(this.pOut, "onLeave", /*dumpStringRegion=*/true);
    }
});

console.log(`[+] Hook installed.`);
