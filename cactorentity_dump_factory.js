/* -------------------------------------------------------------
   actor_factory_safe4.js  –  fast & non-blocking
   ------------------------------------------------------------- */
'use strict';

const FACTORY      = ptr('0x149d30960');      // CActorEntity factory

/* factory layout (gleaned from sub_1463F4C80 & friends) */
const OFF_ARENA_BEGIN  = 0x110;               // QWORD* first slot
const OFF_ARENA_END    = 0x118;               // QWORD* one-past-last
const OFF_PER_ARENA    = 0x148;               // DWORD  objects / arena

const OBJ_SZ       = 0xB80;                   // size-of(CActorEntity)
const SALT_OFF     = 0xB40;                   // uint16 salt inside object

/* sanity caps – never reached in practice */
const MAX_PER_ARENA = 0x4000;   // 16 384 objects
const MAX_ARENAS    = 0x0400;   // 1 024 arenas

/* ----------------------------------------------------- helpers */

function isReadable (addr) {
  const r = Process.findRangeByAddress(addr);
  if (!r || !r.protection.includes('r')) return false;
  try { addr.readU8(); return true; } catch (_) { return false; }
}

function readPtrSafe (p) {
  try { return p.readPointer(); } catch (_) { return NULL; }
}

/* ----------------------------------------------------- RPC API */

rpc.exports = {
  list  () { return enumerate(false); },
  dump  () { return enumerate(true ); }
};

/* ------------------------------------------------ enumerate() */

function enumerate (wantInfo) {
  return new Promise((resolve, _reject) => {

    const perArena = Math.min(
        Math.max(FACTORY.add(OFF_PER_ARENA).readU32(), 1),
        MAX_PER_ARENA);

    /* arena array [begin … end) --------------------------------*/
    const arenaBegin = FACTORY.add(OFF_ARENA_BEGIN).readPointer();
    const arenaEnd   = FACTORY.add(OFF_ARENA_END  ).readPointer();
    let arenaCount   = arenaEnd.sub(arenaBegin).toUInt32()
                      / Process.pointerSize;

    if (arenaCount === 0 || arenaCount > MAX_ARENAS)
        arenaCount = MAX_ARENAS;

    const results = [];
    let a = 0, i = 0;

    /* asynchronous walk – yields back to the JS VM every 100 ms */
    function step () {

      const t0 = Date.now();

      while (a < arenaCount) {

        const arenaPtr = readPtrSafe(arenaBegin.add(a * Process.pointerSize));
        a++;

        if (arenaPtr.isNull() || !isReadable(arenaPtr))
            continue;

        const arenaEndPtr = arenaPtr.add(perArena * OBJ_SZ);
        i = 0;

        /* scan this arena */
        while (i < perArena) {

          const obj = arenaPtr.add(i * OBJ_SZ);
          if (!isReadable(obj)) break;               // end of commit
          i++;

          /* skip freelist nodes */
          const fwd = readPtrSafe(obj);
          if (!fwd.isNull() &&
              fwd.compare(arenaPtr) >= 0 &&
              fwd.compare(arenaEndPtr) < 0)
              continue;

          if (wantInfo) {
            const salt = obj.add(SALT_OFF).readU16();
            results.push({ addr: obj, arena: arenaPtr, index: i - 1, salt });
          } else {
            results.push(obj.toString());
          }

          /* --------------- throttle: break every 100 ms --------*/
          if (Date.now() - t0 > 100) {
            setTimeout(step, 0);      // reschedule
            return;
          }
        }
      }
      /* done */
      resolve(results);
    }
    /* kick-off */
    step();
  });
}

