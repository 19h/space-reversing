/* ───────────────────────────── utilities ─────────────────────────────── */

function isReadable(p) {
  try { return !p.isNull() && Process.findRangeByAddress(p); }
  catch { return false; }
}

function readUtf8Safe(p) {
  try { return isReadable(p) ? p.readCString() : null; }
  catch { return null; }
}

/* RTTI lookup (MSVC):  *vtable[-1] → _RTTICompleteObjLocator               */
/* COL->pTypeDescriptor->name                                               */
function rttiName(obj) {
  const vtbl = obj.readPointer();
  const col  = vtbl.sub(Process.pointerSize).readPointer();
  if (!isReadable(col)) return null;

  const typeDesc = col.add(2 * Process.pointerSize).readPointer();
  if (!isReadable(typeDesc)) return null;

  // MSVC prepends ".?AV" / ".?AU"
  const raw = typeDesc.add(2 * Process.pointerSize).readCString();
  return raw ? raw.replace(/^\.\?A[VU]/, '') : null;
}

function virtualCall(obj, slot, ret = 'pointer', args = ['pointer']) {
  const vtbl = obj.readPointer();
  const tgt  = vtbl.add(slot * Process.pointerSize).readPointer();
  if (!isReadable(tgt)) return null;
  return new NativeFunction(tgt, ret, args);
}

/* ─────────────────────────────── hook ────────────────────────────────── */

const registry = new Map();   // by IEngineModule ptr

Interceptor.attach(ptr('0x140566F20') /* InitializeModule */, {
  onEnter(args) {               // char const* path
    this.path = readUtf8Safe(args[0]) ?? '<static>';
  },

  onLeave(retVal) {
    if (!isReadable(retVal))          // NULL or bad pointer → ignore
      return;

    /* try the official API first … */
    let name = null, category = null;

    const getName = virtualCall(retVal, 1);
    if (getName)
      name = readUtf8Safe(getName(retVal));

    const getCat  = virtualCall(retVal, 2);
    if (getCat) {
      const raw = getCat(retVal);
      category  = (raw.toUInt32() < 0x10000) ? raw.toUInt32().toString()
                                             : readUtf8Safe(raw);
    }

    /* … fall back to RTTI */
    if (!name)
      name = rttiName(retVal) ?? '<no-name>';

    category ??= '<n/a>';

    console.log(`${name.padEnd(30)} ${category.padEnd(10)} ← ${this.path}`);

    registry.set(retVal.toString(), { ptr: retVal, name, category, path: this.path });
  }
});

/* ─────────────────────── grabbing the real interface ─────────────────── */
/* Every Cry/Star module (that offers one) places its main interface at    */
/* virtual slot #5 :  IEngineModule::GetSystemInterface() --> void*        */

function queryInterface(modName /* e.g. "CryEntitySystem" */) {
  const rec = [...registry.values()].find(r => r.name === modName);
  if (!rec) return null;

  const getIface = virtualCall(rec.ptr, 5);         // returns void*
  return getIface ? getIface(rec.ptr) : null;
}

/* small convenience exported to the REPL */
global.queryInterface = queryInterface;

/* example after the game is fully up:      */
setTimeout(() => {
  const pES = queryInterface('CryEntitySystem');
  console.log('\nIEntitySystem @', pES);
}, 20000);
