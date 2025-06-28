/*  vtable-path-finder.js  —  drop-in Frida agent  */

'use strict';

/* ----------  compile-time parameters (override per-call if desired) ------- */
const DEFAULT_MAX_DISTANCE = 0x4000;         // 16 384 B  positive scan window
const DEFAULT_STEP         = Process.pointerSize; // 8 B on 64-bit, 4 B on 32-bit
const DEFAULT_MAX_DEPTH    = 8;              // dereference depth limit
const ACCESS_TEST_SIZE     = 1;              // #bytes for quick readability probe

/* ----------  exported RPC -------------------------------------------------- */
rpc.exports = {
    /**
     * Breadth-first search for a pointer path.
     *
     * @param {String|Number} basePtr   – starting NativePointer (hex str or num)
     * @param {String|Number} targetPtr – sought NativePointer (hex str or num)
     * @param {Object}  [opt]           – { maxDistance, step, maxDepth, verbose }
     * @returns  {Object|null}          – { pretty, steps[] } or null
     */
    locatepath: locatePathRpc
};

/* ----------  implementation ---------------------------------------------- */
function locatePathRpc(basePtr, targetPtr, opt = {}) {
    const cfg = {
        maxDistance : opt.maxDistance ?? DEFAULT_MAX_DISTANCE,
        step        : opt.step        ?? DEFAULT_STEP,
        maxDepth    : opt.maxDepth    ?? DEFAULT_MAX_DEPTH,
        verbose     : opt.verbose     ?? false
    };

    const root   = ptr(basePtr);
    const target = ptr(targetPtr);

    if (cfg.verbose) {
        console.log('[+] search parameters:',
            JSON.stringify({...cfg, basePtr: root, targetPtr: target}, null, 2));
    }

    const found = bfsSearch(root, target, cfg);

    if (found) {
        console.log('[✓] path found:', found.pretty);
    } else {
        console.log('[×] no path found inside constraints');
    }
    return found;
}

/* -----  BFS core ---------------------------------------------------------- */
function bfsSearch(root, target, cfg) {
    /** Each queue element: { ptr:NativePointer, path:[Step] } */
    const q = [{ ptr: root, path: [] }];
    const visited = new Set([ root.toString() ]);

    let i = 0;

    while (q.length) {
        i += 1000;

        const { ptr: cur, path } = q.shift();

        if (i % 10000 === 0) {
            console.log(`[!] BFS progress: ${i} iterations`);
            console.log(`[!] stack size: ${q.length}`);
        }

        for (let off = 0; off < cfg.maxDistance; off += cfg.step) {
            const candidateAddr = cur.add(off);

            /* ---- round 1 : no dereference -------------------------------- */
            if (candidateAddr.equals(target))
                return buildResult(path.concat([{ offset: off, deref: false }]));

            /* ==== validity check & single dereference ===================== */
            let derefVal;
            if (isReadable(candidateAddr)) {
                try {
                    derefVal = candidateAddr.readPointer();
                } catch (_) { /* unreadable as pointer ↛ skip */ }
            }
            if (!derefVal) continue;

            /* ---- round 2 : single dereference ---------------------------- */
            if (derefVal.equals(target))
                return buildResult(path.concat([{ offset: off, deref: true }]));

            /* ---- recursion guard ---------------------------------------- */
            if (path.length + 1 < cfg.maxDepth) {
                const key = derefVal.toString();
                if (!visited.has(key)) {
                    visited.add(key);
                    q.push({
                        ptr  : derefVal,
                        path : path.concat([{ offset: off, deref: true }])
                    });
                }
            }
        }
    }
    return null;        // exhausted queue
}

/* ----------  helpers ------------------------------------------------------ */
function isReadable(addr) {
    try {
        Memory.readByteArray(addr, ACCESS_TEST_SIZE);
        return true;
    } catch (_) { return false; }
}

function buildResult(path) {
    const pretty = path.map(s =>
        `${s.deref ? '*':'&'}+0x${s.offset.toString(16)}`
    ).join('  ->  ');
    return { pretty, steps: path };
}
