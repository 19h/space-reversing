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

const DEVTOOLS_MODULE_CANDIDATES = [
    "CIGDevelopmentTools.dll",
    "__kv_bin_0001__.dll",
];

const DEVTOOLS_RVA = {
    InitializeModule_CIGDevelopmentTools: 0x5DA230,
    DevelopmentTools_Init:              0x419AD0,
    CServerConsoleCmd_Init:             0x418B90,
    RegisterConsoleCommandsDevelopment: 0x0E95B0,
    gEnv:                               0x9B3A40,
};

const GENV_OFFSET_PCONSOLE = 0xB8;

console.log(`[+] Module ${MODULE_NAME} @ ${mod.base}`);
console.log(`[+] GetGameHashValues @ ${pGetGameHashValues}`);
console.log(`[+] Target digest: ${EXPECTED_DIGEST}`);


// ============================================================================
// Devtools DLL registration recon
// ============================================================================

let devtoolsReconHooksInstalled = false;
let devtoolsRetryTimer = null;
let lastDevelopmentToolsThis = NULL;
let lastServerConsoleCmdThis = NULL;
let devtoolsInitCount = 0;
let serverConsoleInitCount = 0;
let registerConsoleCommandsDevelopmentCount = 0;

function findDevtoolsModule() {
    for (const name of DEVTOOLS_MODULE_CANDIDATES) {
        const module = Process.findModuleByName(name);
        if (module !== null) return module;
    }
    return null;
}

function readCStringSafe(p) {
    if (p.isNull()) return "<null>";
    try {
        return p.readCString() || "";
    } catch (e) {
        return `<unreadable: ${e.message}>`;
    }
}

function getDevtoolsPointers() {
    const devtools = findDevtoolsModule();
    if (devtools === null) {
        return { devtools: null, gEnv: NULL, pConsole: NULL };
    }

    let gEnv = NULL;
    let pConsole = NULL;
    try {
        gEnv = devtools.base.add(DEVTOOLS_RVA.gEnv).readPointer();
        if (!gEnv.isNull()) {
            pConsole = gEnv.add(GENV_OFFSET_PCONSOLE).readPointer();
        }
    } catch (e) {
        console.warn(`[devtools-recon] Failed reading gEnv/pConsole: ${e.message}`);
    }

    return { devtools, gEnv, pConsole };
}

function installDevtoolsReconHooks() {
    if (devtoolsReconHooksInstalled) return true;

    const { devtools, gEnv, pConsole } = getDevtoolsPointers();
    if (devtools === null) return false;

    const pInitializeModule = devtools.base.add(DEVTOOLS_RVA.InitializeModule_CIGDevelopmentTools);
    const pDevelopmentToolsInit = devtools.base.add(DEVTOOLS_RVA.DevelopmentTools_Init);
    const pServerConsoleCmdInit = devtools.base.add(DEVTOOLS_RVA.CServerConsoleCmd_Init);
    const pRegisterConsoleCommandsDevelopment = devtools.base.add(DEVTOOLS_RVA.RegisterConsoleCommandsDevelopment);

    console.log(`[devtools-recon] ${devtools.name} @ ${devtools.base}`);
    console.log(`[devtools-recon] gEnv=${gEnv} pConsole=${pConsole}`);
    console.log(`[devtools-recon] InitializeModule_CIGDevelopmentTools @ ${pInitializeModule}`);
    console.log(`[devtools-recon] DevelopmentTools::Init @ ${pDevelopmentToolsInit}`);
    console.log(`[devtools-recon] CServerConsoleCmd::Init @ ${pServerConsoleCmdInit}`);
    console.log(`[devtools-recon] RegisterConsoleCommandsDevelopment @ ${pRegisterConsoleCommandsDevelopment}`);

    Interceptor.attach(pInitializeModule, {
        onEnter(args) {
            console.log(`[devtools-recon] InitializeModule_CIGDevelopmentTools enter pSystem=${args[0]} initParams=${args[1]}`);
        },
        onLeave(retval) {
            lastDevelopmentToolsThis = retval;
            console.log(`[devtools-recon] InitializeModule_CIGDevelopmentTools leave DevelopmentTools*=${retval}`);
        }
    });

    Interceptor.attach(pDevelopmentToolsInit, {
        onEnter(args) {
            devtoolsInitCount++;
            lastDevelopmentToolsThis = args[0];
            console.log(`[devtools-recon] DevelopmentTools::Init #${devtoolsInitCount} this=${args[0]}`);
        }
    });

    Interceptor.attach(pServerConsoleCmdInit, {
        onEnter(args) {
            serverConsoleInitCount++;
            lastServerConsoleCmdThis = args[0];
            console.log(`[devtools-recon] CServerConsoleCmd::Init #${serverConsoleInitCount} this=${args[0]}`);
        }
    });

    Interceptor.attach(pRegisterConsoleCommandsDevelopment, {
        onEnter(args) {
            registerConsoleCommandsDevelopmentCount++;
            console.log(`[devtools-recon] RegisterConsoleCommandsDevelopment #${registerConsoleCommandsDevelopmentCount} pConsole=${args[0]}`);
        },
        onLeave() {
            console.log(`[devtools-recon] RegisterConsoleCommandsDevelopment complete`);
        }
    });

    devtoolsReconHooksInstalled = true;
    return true;
}

function scheduleDevtoolsReconHookInstall() {
    if (installDevtoolsReconHooks()) return;

    console.log(`[devtools-recon] Devtools DLL not loaded yet; waiting to install hooks`);
    devtoolsRetryTimer = setInterval(() => {
        if (installDevtoolsReconHooks()) {
            clearInterval(devtoolsRetryTimer);
            devtoolsRetryTimer = null;
        }
    }, 1000);
}

function invokeRegisterConsoleCommandsDevelopment() {
    const { devtools, gEnv, pConsole } = getDevtoolsPointers();
    if (devtools === null) {
        throw new Error("CIGDevelopmentTools module is not loaded");
    }
    if (gEnv.isNull()) {
        throw new Error("CIGDevelopmentTools gEnv is null");
    }
    if (pConsole.isNull()) {
        throw new Error("gEnv->pConsole is null");
    }

    const fn = new NativeFunction(
        devtools.base.add(DEVTOOLS_RVA.RegisterConsoleCommandsDevelopment),
        'void',
        ['pointer']
    );

    console.log(`[devtools-recon] Manually invoking RegisterConsoleCommandsDevelopment(${pConsole})`);
    fn(pConsole);
    console.log(`[devtools-recon] Manual RegisterConsoleCommandsDevelopment returned`);

    return {
        module: devtools.name,
        moduleBase: devtools.base.toString(),
        gEnv: gEnv.toString(),
        pConsole: pConsole.toString(),
        registerConsoleCommandsDevelopment: devtools.base.add(DEVTOOLS_RVA.RegisterConsoleCommandsDevelopment).toString(),
    };
}

rpc.exports = {
    installdevtoolsreconhooks() {
        return installDevtoolsReconHooks();
    },
    registerdevconsolecommands() {
        return invokeRegisterConsoleCommandsDevelopment();
    },
    devtoolsreconstate() {
        const { devtools, gEnv, pConsole } = getDevtoolsPointers();
        return {
            hooksInstalled: devtoolsReconHooksInstalled,
            module: devtools !== null ? devtools.name : null,
            moduleBase: devtools !== null ? devtools.base.toString() : null,
            gEnv: gEnv.toString(),
            pConsole: pConsole.toString(),
            lastDevelopmentToolsThis: lastDevelopmentToolsThis.toString(),
            lastServerConsoleCmdThis: lastServerConsoleCmdThis.toString(),
            devtoolsInitCount,
            serverConsoleInitCount,
            registerConsoleCommandsDevelopmentCount,
        };
    },
    readcstring(address) {
        return readCStringSafe(ptr(address));
    },
};

scheduleDevtoolsReconHookInstall();

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
const ShouldAutoComplete = ptr('0x14757EA60');
const ShouldRegister     = ptr('0x14757EF80');
const ShouldExecute      = ptr('0x14757EBC0');
const CigMalloc = new NativeFunction(ptr('0x14807E43B'), 'pointer', ['uint64']);

Interceptor.replace(ShouldExecute, new NativeCallback((a1, a2, a3, a4) => {
    const cell = CigMalloc(0x18);
    cell.writePointer(cell);
    cell.add(8).writePointer(cell);
    return cell;
}, 'pointer', ['pointer', 'pointer', 'char', 'char']));

Interceptor.replace(ShouldAutoComplete, new NativeCallback(
    (_this, _badge, _name) => 1,
    'uint8', ['pointer', 'uint8', 'pointer']
));
Interceptor.replace(ShouldRegister, new NativeCallback(
    (_this, _name, _flags) => 1,
    'uint8', ['pointer', 'pointer', 'uint32']
));

// ------------------------------------------------------------------------------------------------

// CSystem::Init version compare block:
// 0x1475486E6: 75 45  jnz fail
// 0x1475486EE: 75 3D  jnz fail
// 0x1475486F7: 75 34  jnz fail
// 0x1475486FF: 75 2C  jnz fail
const VERSION_GATE_JNZ_RVAS = [
    0x75486E6,
    0x75486EE,
    0x75486F7,
    0x75486FF,
];

for (const rva of VERSION_GATE_JNZ_RVAS) {
    const p = mod.base.add(rva);

    Memory.patchCode(p, 2, code => {
        const writer = new X86Writer(code, { pc: p });
        writer.putNop();
        writer.putNop();
        writer.flush();
    });

    console.log(`[devtools-gate] NOPed jnz @ ${p} RVA=0x${rva.toString(16)}`);
}

console.log("[devtools-gate] CIGDevelopmentTools file-version mismatch checks bypassed");

// ------------------------------------------------------------------------------------------------

const CGame_GetClientPlayer = mod.base.add(0x2F5A8B0);
const VTBL_GetBadgeMaskInfo_OFFSET = 0x768;

const EXTRA_BADGES = [
    1, 5, 14, 101, 102, 103, 104, 105, 107, 108, 109, 110,
    112, 113, 115, 116, 117, 118, 119, 120, 121, 126, 127,
    799, 1212, 1213,
    1973, 1974, 1975, 1976, 1977, 1978, 1979, 1980,
    1983, 1984, 1985, 1986, 1987, 1988, 1989, 1990, 1991,
    2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040,
    2041, 2042, 2043, 2044, 2045, 2046,
    2050, 2051, 2052, 2053, 2054, 2055, 2056,
    2065, 2066,
    2075,
    2097, 2098, 2099, 2100, 2101, 2106, 2107,
    2138, 2141, 2146,
    2171, 2172, 2173, 2174, 2175, 2176, 2177, 2178, 2179, 2180,
    2200, 2201, 2207, 2209, 2211, 2213,
    2297,
    2355, 2359, 2367, 2369, 2371, 2373,
    2399, 2401,
    2411, 2413, 2415, 2417, 2419,
    2421, 2423, 2425, 2427, 2429,
    2431, 2433, 2435, 2437, 2439,
    2441, 2443, 2445, 2447, 2449,
    2479, 2480, 2481,
    2486, 2487, 2488, 2489, 2490, 2491, 2492, 2493, 2494, 2495,
    2496, 2497, 2498, 2499, 2500, 2501, 2502, 2503, 2504, 2505,
    2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513,

    0x1, 0x3, 0x4, 0x5, 0x9, 0xE, 0x7B, 0x7D, 0x7E, 0x70, 0x73,
    0x79, 0x31F, 0x7C2, 0x7BF, 0x7C0, 0x7C1, 0x7C3, 0x7C4, 0x7C5,
    0x7C6, 0x7C7, 0x81B, 0x933, 0x937, 0x9AF, 0x9B0, 0x9B1, 0x83A,
    0x83B, 0x862, 0x89F, 0x8A1, 0x8A5, 0x8A3, 0x8F9, 0x93F, 0x941,
    0x943, 0x945, 0x95F, 0x961, 0x812, 0x811, 0x97F, 0x975, 0x96B,
    0x989, 0x981, 0x977, 0x96D, 0x98B, 0x983, 0x979, 0x96F, 0x98D,
    0x985, 0x97B, 0x971, 0x98F, 0x987, 0x97D, 0x973, 0x991, 0x9B6,
    0x9B7, 0x9B8, 0x9B9, 0x9BA, 0x9BB, 0x9BC, 0x9BD, 0x9BE, 0x9BF,
    0x9C0, 0x9C1, 0x9C2, 0x9C3, 0x9C4, 0x9C5, 0x9C6, 0x9C7, 0x9C8,
    0x9C9, 0x9CA, 0x9CB, 0x9CC, 0x9CD, 0x9CE, 0x9CF, 0x9D0, 0x9D1,
    0x4BD, 0x802, 0x803, 0x804, 0x805, 0x806, 0x807, 0x808, 0x835,
    0x834, 0x833, 0x832, 0x831, 0x85A, 0x85D, 0x899, 0x898, 0x87B,
    0x87C, 0x87D, 0x87E, 0x87F, 0x880, 0x881, 0x882, 0x883, 0x884,
    0x8EA,
]; // add more required badges here

const fakeInfos = [];
const fakeBadgeArrays = [];
let hookedGetBadgeMaskInfo = false;

function installGetBadgeMaskInfoHook(clientPlayer) {
    if (hookedGetBadgeMaskInfo || clientPlayer.isNull()) return;

    const vtbl = clientPlayer.readPointer();
    const fn = vtbl.add(VTBL_GetBadgeMaskInfo_OFFSET).readPointer();

    Interceptor.attach(fn, {
        onLeave(retval) {
            if (retval.isNull()) return;

            // Original layout observed in CEALobby::ValidateGameModes:
            // +0x04 flags, +0x20 badge begin, +0x28 badge end.
            const flags = retval.add(0x04).readU8();
            if ((flags & 3) === 0) {
                retval.add(0x04).writeU8(flags | 3);
            }

            const begin = retval.add(0x20).readPointer();
            const end = retval.add(0x28).readPointer();

            let badges = [];
            if (!begin.isNull() && !end.isNull() && end.compare(begin) >= 0) {
                const count = end.sub(begin).toInt32() / 2;
                for (let i = 0; i < count; i++) {
                    badges.push(begin.add(i * 2).readU16());
                }
            }

            let changed = false;
            for (const badge of EXTRA_BADGES) {
                if (!badges.includes(badge)) {
                    badges.push(badge);
                    changed = true;
                }
            }

            if (!changed) return;

            const badgeArray = Memory.alloc(badges.length * 2);
            for (let i = 0; i < badges.length; i++) {
                badgeArray.add(i * 2).writeU16(badges[i]);
            }

            const fakeInfo = Memory.alloc(0x40);
            Memory.copy(fakeInfo, retval, 0x40);
            fakeInfo.add(0x04).writeU8(fakeInfo.add(0x04).readU8() | 3);
            fakeInfo.add(0x20).writePointer(badgeArray);
            fakeInfo.add(0x28).writePointer(badgeArray.add(badges.length * 2));

            fakeInfos.push(fakeInfo);
            fakeBadgeArrays.push(badgeArray);

            retval.replace(fakeInfo);

            //console.log(`[badge-lookup] Added badge(s) ${EXTRA_BADGES.join(", ")} to BadgeMaskInfo`);
        }
    });

    hookedGetBadgeMaskInfo = true;
    console.log(`[badge-lookup] Hooked GetBadgeMaskInfo @ ${fn}`);
}

Interceptor.attach(CGame_GetClientPlayer, {
    onLeave(retval) {
        installGetBadgeMaskInfoHook(retval);
    }
});

console.log("[badge-lookup] Waiting for client player to resolve GetBadgeMaskInfo");

// ------------------------------------------------------------------------------------------------

// CActor::CanUseServerDevTools()
// EA  0x142F03BB0
// RVA 0x2F03BB0
const pCanUseServerDevTools = mod.base.add(0x2F03BB0);

Memory.patchCode(pCanUseServerDevTools, 6, code => {
    code.writeByteArray([
        0xB0, 0x01, // mov al, 1
        0xC3,       // ret
        0x90, 0x90, 0x90
    ]);
});

console.log(`[server-devtools] CActor::CanUseServerDevTools patched true @ ${pCanUseServerDevTools}`);