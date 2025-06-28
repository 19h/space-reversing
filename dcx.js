/*
 *  ssm_weapon_dump.js
 *  ──────────────────
 *  • hooks the game’s heap allocator (sub_1402A1E30)
 *  • records every heap‑resident SSalvageModifier object (size 0x18)
 *  • removes them again on destructor
 *  • writes a complete JSON dump of the parent SWeaponStats block once
 *    the set has stabilised (no new objects for 3 s)
 *
 *  Drop into Frida:
 *      frida -l ssm_weapon_dump.js -f com.your.game --no-pause
 *
 *  You will see “[WeaponDump] …” in the console when the dump is ready.
 *  You can also call rpc.exports.dumpall() interactively.
 */

'use strict';

(function () {

    /* ───────────────────────────────── CONSTANTS ───────────────────────────────── */

    const MODULE_NAME         = 'StarCitizen.exe';            // change if needed
    const BASE                = Module.findBaseAddress(MODULE_NAME);
    if (!BASE) throw new Error(`${MODULE_NAME} not loaded`);

    const RVA   = off => BASE.add(ptr(off));

    const ALLOC_RVA           = 0x2A1E30;            // sub_1402A1E30
    const VTABLE_RVA          = 0x83A3860;            // off_1483A3860 − 0x140000000
    const SIZE_MODIFIER       = 0x18;                  // sizeof(SSalvageModifier)
    const CHILD_TO_PARENT     = 0x388;                 // offset salvageModifier → weapon
    const WEAPON_BLK_SIZE     = 0x3A4;                 // readable span for sanity

    /* scalar layout for the JSON dumper (partial, expand as needed) */
    const F32 = 0, U32 = 1, U8 = 2;
    const WEAPON_LAYOUT = [
        [0x008, 4, 'fireRate',                       F32],
        [0x00C, 4, 'fireRateMultiplier',             F32],
        [0x010, 4, 'damageMultiplier',               F32],
        [0x014, 4, 'damageOverTimeMultiplier',       F32],
        [0x018, 4, 'projectileSpeedMultiplier',      F32],
        [0x01C, 4, 'pellets',                        U32],
        [0x020, 4, 'burstShots',                     U32],
        [0x024, 4, 'ammoCost',                       U32],
        [0x028, 4, 'ammoCostMultiplier',             F32],
        [0x02C, 4, 'heatGenerationMultiplier',       F32],
        [0x030, 4, 'soundRadiusMultiplier',          F32],
        [0x034, 4, 'chargeTimeMultiplier',           F32],

        [0x388 + 0x08, 4, 'salvageSpeedMultiplier',  F32],
        [0x388 + 0x0C, 4, 'salvageRadiusMultiplier', F32],
        [0x388 + 0x10, 4, 'extractionEfficiency',    F32],

        [0x3A0, 1, 'useAlternateProjectileVisuals',  U8],
        [0x3A1, 1, 'useAugmentedRealityProjectiles', U8],
    ];

    const ALLOC                = RVA(ALLOC_RVA);
    const VTABLE               = RVA(VTABLE_RVA);
    const DESTRUCTOR           = Memory.readPointer(VTABLE);   // first slot = scalar dtor

    const DUMP_DELAY_MS        = 3000;          // no‑new‑objects window before dump
    const POLL_MS              = 500;           // interval for stability checker

    /* ───────────────────────────────── STATE ───────────────────────────────────── */

    const tracked     = new Set();              // live SSalvageModifier*
    let   lastAddTime = Date.now();
    let   dumped      = false;

    /* ────────────────────────────── HELPERS ───────────────────────────────────── */

    function saneExtraction(ptrMod) {
        try {
            const eff = Memory.readFloat(ptrMod.add(0x10));
            return Number.isFinite(eff) && eff >= 0 && eff <= 20;
        } catch { return false; }
    }

    /* parent weapon sanity: fireRate > 0 && < 1000  */
    function saneWeapon(ptrMod) {
        try {
            const rate = Memory.readFloat(ptrMod.sub(CHILD_TO_PARENT).add(0x08));
            return Number.isFinite(rate) && rate > 0 && rate < 1000;
        } catch { return false; }
    }

    function track(ptrMod) {
        if (!saneExtraction(ptrMod) || !saneWeapon(ptrMod)) return;
        if (!tracked.has(ptrMod)) {
            tracked.add(ptrMod);
            lastAddTime = Date.now();
        }
    }

    function untrack(ptrMod) { tracked.delete(ptrMod); }

    /* read primitive field */
    function readFld(base, off, type) {
        const addr = base.add(off);
        switch (type) {
            case F32: return Memory.readFloat(addr);
            case U32: return Memory.readU32(addr);
            case U8 : return Memory.readU8(addr);
            default : return null;
        }
    }

    function weaponJSON(ptrMod) {
        const weapon = ptrMod.sub(CHILD_TO_PARENT);
        const obj = {};
        for (const [off,, name, type] of WEAPON_LAYOUT)
            obj[name] = readFld(weapon, off, type);
        return obj;
    }

    function dumpAll() {
        const arr = Array.from(tracked).map(p => ({
            ptr: p.toString(),
            stats: weaponJSON(p)
        }));
        console.log('[WeaponDump]', JSON.stringify(arr, null, 2));
    }

    /* ────────────────────────────── HOOKS ─────────────────────────────────────── */

    /* allocator */
    Interceptor.attach(ALLOC, {
        onEnter(args) { this.req = args[0].toInt32(); },
        onLeave(ret) {
            const sz = this.req;

            /* single object */
            if (sz === SIZE_MODIFIER) {
                track(ptr(ret));
                return;
            }

            /* array object: 8‑byte header with count */
            if (sz > 8 && (sz - 8) % SIZE_MODIFIER === 0) {
                let p = ptr(ret).add(8);
                const count = (sz - 8) / SIZE_MODIFIER;
                for (let i = 0; i < count; ++i, p = p.add(SIZE_MODIFIER))
                    track(p);
            }
        }
    });

    /* destructor */
    Interceptor.attach(DESTRUCTOR, {
        onEnter() { untrack(this.context.rcx); }
    });

    /* ────────────────────────── DUMP‑ON‑STABLE TIMER ─────────────────────────── */

    const timer = setInterval(() => {
        if (!dumped &&
            tracked.size &&
            (Date.now() - lastAddTime) > DUMP_DELAY_MS) {
            dumpAll();
            dumped = true;
            clearInterval(timer);
        }
    }, POLL_MS);

    /* ───────────────────────────── RPC (optional) ────────────────────────────── */

    rpc.exports = {
        list()     { return Array.from(tracked).map(p => p.toString()); },
        dump(ptr)  { return weaponJSON(ptr(ptr)); },
        dumpall()  { return Array.from(tracked).map(p => ({ptr:p.toString(), stats:weaponJSON(p)})); }
    };

    console.log('[SSM‑DUMP] script loaded, allocator hook active at', ALLOC);

})();
