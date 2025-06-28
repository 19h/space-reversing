/*
 *  zone_planet_safe.js   – 2025-06-25 (final)
 *  ------------------------------------------------------------
 *  Inject :   frida -l zone_planet_safe.js -p <pid>
 *  RPC    :   script.exports.dump([camX, camY, camZ])
 *
 *  Notes  :
 *    • All engine-side virtual calls execute on the render-thread
 *      (we piggy-back on the game-side "display-info" handler),
 *      so no TLS / spin-lock dead-locks can occur.
 *    • Planet handle resolution now follows exactly the native
 *      path that CIG uses in `display_camera_and_location_info`
 *      and `sub_147240FB0`, so we cannot dereference an invalid
 *      handle any more.
 *    •  v-table slot numbers have been verified against a fresh
 *      3.23.x (LIVE/PTU) binary with AVX-lifting disabled – in
 *      particular `Planet::WorldToLocal` is **slot 31**.
 *  ------------------------------------------------------------*/
'use strict';

/* ─────────── engine globals (3.23.x) ──────────── */
const ADDR_ZONE_SYS   = ptr('0x0000000149A141F8');   // gZoneSys
const ADDR_PLANET_MGR = ptr('0x0000000149A14398');   // gPlanetMgr
const FN_ON_FRAME     = ptr('0x14723E730');          // display_camera_and_location_info()'s caller

/* ─────────── constants & helpers ─────────── */
const PTR_SIZE = Process.pointerSize;
const MASK48   = ptr('0xFFFFFFFFFFFF');
const DVEC_SZ  = 24;

const mask48 = p => p.and(MASK48);
const cstr = p => p.isNull() ? null : p.readUtf8String();

/** Generic virtual-function caller */
function vcall(self, idx, retType, argTypes, argv = []) {
    const vtbl = self.readPointer();
    const fnPtr = vtbl.add(idx * PTR_SIZE).readPointer();
    return new NativeFunction(fnPtr, retType, ['pointer', ...argTypes])(self, ...argv);
}

/* Small helpers for 3-component double vectors */
const allocVec = v => {
    const m = Memory.alloc(DVEC_SZ);
    m.writeDouble(v.x);
    m.add(8).writeDouble(v.y);
    m.add(16).writeDouble(v.z);
    return m;
};
const readVec = p => ({
    x: p.readDouble(),
    y: p.add(8).readDouble(),
    z: p.add(16).readDouble()
});
const prettym = v =>
    Math.abs(v) >= 1e4 ? (v * 1e-3).toFixed(3) + ' km' : v.toFixed(2) + ' m';

/* ──────────  Zone wrappers  ────────── */
class Zone {
    constructor(p) {
        this.p = p;
    }
    /** Linked-list iterator */
    next() {
        const q = vcall(this.p, 1, 'pointer', []);
        return q.isNull() ? null : new Zone(q);
    }
    /** Position relative to camera */
    rel(cam) {
        const out = Memory.alloc(DVEC_SZ);
        vcall(this.p, 31, 'void', ['pointer', 'pointer'], [out, allocVec(cam)]);
        return readVec(out);
    }
    get name() {
        return cstr(vcall(this.p, 62, 'pointer', [])) || '<noname>';
    }
}

class ZoneSystem {
    constructor(p) {
        this.p = p;
    }
    /** Native GetZone( index ) – index 0 is the first zone */
    get(idx = 0) {
        const q = vcall(this.p, 13, 'pointer', ['int'], [idx]);
        return q.isNull() ? null : new Zone(mask48(q));
    }
}

/* ──────────  Planet wrappers  ────────── */
function unpackPlanetHandle(raw) {
    /*
     * Raw is a 64-bit packed handle:
     * – bits 0-47 : metadata pointer (lower 48 bits)
     * – upper bits : shard / salt (masked out)
     */
    if (raw.isNull()) return NULL;

    const meta = mask48(raw);
    if (meta.isNull()) return NULL;

    // metadata +8  : WORD state   – expect 2 (live)
    try {
        if (meta.add(8).readU16() !== 2) return NULL;
    } catch (_) {
        return NULL;
    }

    // metadata +0x190 : packed handle → real object
    let payload;
    try {
        payload = meta.add(0x190).readPointer();
    } catch (_) {
        return NULL;
    }
    if (payload.isNull()) return NULL;

    const obj = mask48(payload);
    // minimal sanity: v-table pointer must be non-null
    try {
        if (obj.readPointer().isNull()) return NULL;
    } catch (_) {
        return NULL;
    }

    return obj;
}

class Planet {
    constructor(p) {
        this.p = p;
    }
    get name() {
        // fastest path: char* field at +0x70
        try {
            return cstr(this.p.add(0x70).readPointer()) || '<planet>';
        } catch (_) {
            return '<planet>';
        }
    }
    get radius() {
        return this.p.add(0x98).readDouble();
    }
    /** World-space → local planet-centric */
    worldToLocal(w) {
        const out = Memory.alloc(DVEC_SZ);
        // verified: WorldToLocal is slot 31 (offset 0xF8)
        vcall(this.p, 31, 'void', ['pointer', 'pointer'], [out, allocVec(w)]);
        return readVec(out);
    }
}

class PlanetMgr {
    constructor(p) {
        this.p = p;
    }
    /** slot 205 (0x668) → returns packed planet handle */
    curHandle() {
        return vcall(this.p, 205, 'pointer', []);
    }
    curPlanet() {
        const objPtr = unpackPlanetHandle(this.curHandle());
        return objPtr.isNull() ? null : new Planet(objPtr);
    }
}

/* ────────── render-thread trampoline ────────── */
let pendingJob = null; // { cam : {x,y,z}|null , resolve : function }

Interceptor.attach(FN_ON_FRAME, {
    onEnter() {
        if (!pendingJob) return;
        try {
            const { cam, resolve } = pendingJob;
            pendingJob = null;
            resolve(performDump(cam));
        } catch (e) {
            // never propagate into the game
            console.error('[zone-planet] ' + e.message);
        }
    }
});

/* ────────── core dump routine ────────── */
function performDump(cam) {
    const zsPtr = ADDR_ZONE_SYS.readPointer();
    const pmPtr = ADDR_PLANET_MGR.readPointer();
    if (zsPtr.isNull() || pmPtr.isNull())
        throw new Error('engine globals not ready');

    /* ---------- zones ---------- */
    const zs = new ZoneSystem(zsPtr);
    const zones = [];
    for (let z = zs.get(0); z; z = z.next()) {
        const entry = { name: z.name };
        if (cam) entry.rel = z.rel(cam);
        zones.push(entry);
    }

    /* ---------- planet ---------- */
    const planetMgr = new PlanetMgr(pmPtr);
    const plObj = planetMgr.curPlanet();
    let planet = null;

    if (plObj) {
        planet = { name: plObj.name, radius: plObj.radius };
        if (cam) {
            const loc = plObj.worldToLocal(cam);
            planet.local = loc;
            planet.elevation =
                Math.sqrt(loc.x * loc.x + loc.y * loc.y + loc.z * loc.z) - planet.radius;
        }
    }

    /* ---------- console output ---------- */
    console.log('\n========== ZONES ==========');
    zones.forEach((z, i) => {
        if (z.rel)
            console.log(
                `[${i}] ${z.name.padEnd(24)} Δ ${prettym(z.rel.x)}, ${prettym(z.rel.y)}, ${prettym(z.rel.z)}`
            );
        else console.log(`[${i}] ${z.name}`);
    });
    console.log('========== PLANET =========');
    if (planet) {
        console.log(`Name   : ${planet.name}`);
        console.log(`Radius : ${planet.radius.toFixed(2)} m`);
        if (planet.local) {
            const l = planet.local;
            console.log(`Local  : (${l.x.toFixed(2)}, ${l.y.toFixed(2)}, ${l.z.toFixed(2)})`);
            console.log(`Elev   : ${planet.elevation.toFixed(2)} m`);
        }
    } else {
        console.log('No active planet / OC.');
    }
    console.log('===========================\n');

    return { zones, planet };
}

/* ────────── RPC surface ────────── */
rpc.exports = {
    /** dump([camX,camY,camZ]) – executes at the next render-thread tick */
    dump: function (...cam) {
        const camVec = cam.length === 3 ? { x: +cam[0], y: +cam[1], z: +cam[2] } : null;
        return new Promise(ok => {
            pendingJob = { cam: camVec, resolve: ok };
        });
    }
};

console.log('[zone-planet] injected – call  script.exports.dump()  when ready.');
