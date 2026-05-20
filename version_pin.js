'use strict';

// ============================================================================
// Config — captured from a known-good session
// ============================================================================

const MODULE_NAME = "StarCitizen.exe";
//const RVA_GetGameHashValues = 0x69CBFE0;
const RVA_GetGameHashValues   = 0x69cca40;

// Frozen CRCs from the reference build. These hash to "00a54543-aef7ab74".
const PINNED = {
    gameVersion:        0x00000001,
    componentRegistry:  0x05909E82,
    classRegistry:      0x1624EC2F,
    entityArchetypes:   0x88EB7307,
    dataCore:           0x8D0A14DB,
    objectContainers:   0xCDA53F2D,
};

const EXPECTED_DIGEST = "00a54543-aef7ab74";

// Set to true to also verify by reading m_versionIdentifier after pinning.
const VERIFY_AFTER_PIN = true;
// Set to false to silence per-call logs once you've confirmed it works.
const VERBOSE = true;

// ============================================================================
// Resolution
// ============================================================================

const mod = Process.getModuleByName(MODULE_NAME);
const pGetGameHashValues = mod.base.add(RVA_GetGameHashValues);

console.log(`[+] Module ${MODULE_NAME} @ ${mod.base}`);
console.log(`[+] GetGameHashValues @ ${pGetGameHashValues}`);
console.log(`[+] Target digest: ${EXPECTED_DIGEST}`);

// ============================================================================
// CryString reader (for verification only)
// ============================================================================

function readCryString(pCryString) {
    try {
        const dataPtr = pCryString.readPointer();
        if (dataPtr.isNull()) return "<null>";
        // Header layout established empirically: length at dataPtr - 0x08
        const lenOffsets = [-0x08, -0x0C, -0x04];
        for (const off of lenOffsets) {
            try {
                const len = dataPtr.add(off).readS32();
                if (len >= 0 && len < 0x1000) {
                    const s = dataPtr.readUtf8String(len);
                    if (s !== null && s.length === len && /^[\x20-\x7E]*$/.test(s)) {
                        return s;
                    }
                }
            } catch (_) {}
        }
        return dataPtr.readCString() || "<unreadable>";
    } catch (e) {
        return `<error: ${e.message}>`;
    }
}

// ============================================================================
// Hook — pin the six u32 fields on the way out
// ============================================================================

let callCount = 0;

Interceptor.attach(pGetGameHashValues, {
    onEnter(args) {
        this.pOut = args[1];
    },
    onLeave(retval) {
        callCount++;
        const out = this.pOut;

        // Snapshot pre-pin values for logging
        let pre = null;
        if (VERBOSE) {
            pre = {
                gv:  out.add(0x00).readU32(),
                cmp: out.add(0x04).readU32(),
                cls: out.add(0x08).readU32(),
                arc: out.add(0x0C).readU32(),
                dc:  out.add(0x10).readU32(),
                oc:  out.add(0x14).readU32(),
                vid: readCryString(out.add(0x18)),
            };
        }

        // ---- Pin numeric fields ----
        out.add(0x00).writeU32(PINNED.gameVersion);
        out.add(0x04).writeU32(PINNED.componentRegistry);
        out.add(0x08).writeU32(PINNED.classRegistry);
        out.add(0x0C).writeU32(PINNED.entityArchetypes);
        out.add(0x10).writeU32(PINNED.dataCore);
        out.add(0x14).writeU32(PINNED.objectContainers);

        // ---- Rewrite the formatted string ----
        // The engine already computed and wrote m_versionIdentifier using the
        // ORIGINAL CRCs before we got here. Since we just overwrote the CRCs,
        // the string is now inconsistent. We must rewrite it.
        //
        // Two options:
        //   (a) Call the engine's CryStringT::FormatVArgs to keep refcounting
        //       consistent. Requires resolving that function.
        //   (b) Overwrite the underlying char buffer in place. Safe because
        //       the new string is the same length (17 chars) as the original.
        //
        // We use (b) — simpler, no extra resolution, no allocation churn.

        const pStr = out.add(0x18);
        try {
            const dataPtr = pStr.readPointer();
            if (!dataPtr.isNull()) {
                // Original string is exactly 17 bytes ("xxxxxxxx-xxxxxxxx").
                // EXPECTED_DIGEST is also 17 bytes. Overwrite in place + NUL.
                const bytes = [];
                for (let i = 0; i < EXPECTED_DIGEST.length; i++) {
                    bytes.push(EXPECTED_DIGEST.charCodeAt(i));
                }
                bytes.push(0);
                dataPtr.writeByteArray(bytes);
            }
        } catch (e) {
            console.error(`[!] Failed to rewrite version string: ${e.message}`);
        }

        if (VERBOSE) {
            const post = {
                gv:  out.add(0x00).readU32(),
                cmp: out.add(0x04).readU32(),
                cls: out.add(0x08).readU32(),
                arc: out.add(0x0C).readU32(),
                dc:  out.add(0x10).readU32(),
                oc:  out.add(0x14).readU32(),
                vid: readCryString(out.add(0x18)),
            };
            const hex = (n) => "0x" + (n >>> 0).toString(16).padStart(8, '0');
            const changed = (a, b) => a === b ? "" : "  [CHANGED]";

            console.log(`\n========== Call #${callCount} @ ${out} ==========`);
            console.log(`  m_gameVersion          : ${hex(pre.gv)}  →  ${hex(post.gv)}${changed(pre.gv, post.gv)}`);
            console.log(`  m_componentRegistryCRC : ${hex(pre.cmp)}  →  ${hex(post.cmp)}${changed(pre.cmp, post.cmp)}`);
            console.log(`  m_classRegistryCRC     : ${hex(pre.cls)}  →  ${hex(post.cls)}${changed(pre.cls, post.cls)}`);
            console.log(`  m_entityArchetypesCRC  : ${hex(pre.arc)}  →  ${hex(post.arc)}${changed(pre.arc, post.arc)}`);
            console.log(`  m_dataCoreCRC          : ${hex(pre.dc)}  →  ${hex(post.dc)}${changed(pre.dc, post.dc)}`);
            console.log(`  m_objectContainersCRC  : ${hex(pre.oc)}  →  ${hex(post.oc)}${changed(pre.oc, post.oc)}`);
            console.log(`  m_versionIdentifier    : "${pre.vid}"  →  "${post.vid}"`);

            if (VERIFY_AFTER_PIN && post.vid !== EXPECTED_DIGEST) {
                console.warn(`  [!] String mismatch — expected "${EXPECTED_DIGEST}"`);
            }
            console.log(`==============================================\n`);
        }
    }
});

console.log(`[+] Hook installed. All future calls will yield ${EXPECTED_DIGEST}.`);
