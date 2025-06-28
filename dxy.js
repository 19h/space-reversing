/**************************************************************************
 *  dump_datacore_structs.js
 *  frida -l dump_datacore_structs.js -f <target.exe> --no-pause
 *
 *  Requires the “reflection collector” helper the game already exports
 *  ( 0x14723EB40 in the current dump ).
 **************************************************************************/
'use strict';

/* ------------ ✂  ONLY THESE VALUES NEED TWEAKING  ✂ ------------------ */
const DATA_CORE_PTR   = ptr('0x14981d200').add(0x78).readPointer(); // CDataCore*
const HASH_MAP_OFF    = 0x130;   // pDataCore + 304 = registration hash‑map
const COLLECT_ADDR    = ptr('0x14723EB40');  // sub_DataCoreCollectFields
const INCLUDE_BASES   = 1;       // 1 == walk inheritance chain
/* --------------------------------------------------------------------- */

const SLOT = Process.pointerSize;
const collect = new NativeFunction(
        COLLECT_ADDR,               // rax := std::vector<TraceField>&
        'pointer',                  // return begin()
        ['pointer','pointer','pointer','uchar'] ); // (core, name, vecMeta, recurse)

/* --------------------------- helpers --------------------------------- */
function safeUtf8(p) {
    try {
        const s = Memory.readUtf8String(p);
        return (/^[\x20-\x7E]{1,128}$/).test(s) ? s : null;
    } catch (_) { return null; }
}

function resolveTypeName(descPtr) {
    if (descPtr.isNull()) return null;
    for (let off = 0x10; off <= 0x40; off += 8) {
        const maybe = descPtr.add(off).readPointer();
        const s = safeUtf8(maybe);
        if (s) return s;
    }
    return null;
}

/* traverse robin‑hood hash‑map at +0x130 --------------------------------*/
function* iterateStructDesc() {
    const map = DATA_CORE_PTR.add(HASH_MAP_OFF);
    const ctrl   = map.readPointer();           // byte*   (hash/control)
    const data   = map.add(SLOT).readPointer(); // entry*  (72‑byte slots)
    const mask   = map.add(SLOT*3).readU64();   // capacityMask
    const entrySz = 72;

    for (let i = 0n; i <= mask; ++i) {
        const ctrlByte = ctrl.add(Number(i)).readU8();
        if (ctrlByte === 0x80 || ctrlByte === 0xFE) continue; // empty / tomb
        const entry = data.add(Number(i*BigInt(entrySz)));
        const structNamePtr = entry.readPointer();        // char*
        const structName    = safeUtf8(structNamePtr);
        if (!structName) continue;                        // shouldn't happen
        yield {name:structName, namePtr:structNamePtr};
    }
}

/* one‑shot collector for a single structure ----------------------------*/
function grabFields(structNamePtr) {
    // vecMeta = {begin,end,cap}
    const vecMeta = Memory.alloc(SLOT*3)
          .writePointer(ptr(0))
          .add(SLOT).writePointer(ptr(0))
          .add(SLOT).writePointer(ptr(0));

    collect(DATA_CORE_PTR, structNamePtr, vecMeta, INCLUDE_BASES);

    const begin = vecMeta.readPointer();
    const end   = vecMeta.add(SLOT).readPointer();
    const count = end.sub(begin).toUInt32() / SLOT;

    const fields = [];
    for (let i=0;i<count;++i) {
        const rec = begin.add(i*SLOT).readPointer();
        const fnamePtr = rec.readPointer();             // 0x00
        const size     = rec.add(0x08).readU32();       // 0x08
        const typeId   = rec.add(0x10).readU32();       // 0x10
        const offset   = rec.add(0x18).readU32();       // 0x18
        const descPtr  = rec.add(0x20).readPointer();   // 0x20

        const fieldName = safeUtf8(fnamePtr) || "<non‑utf8>";
        const typeName  = resolveTypeName(descPtr) || `builtin:${typeId}`;

        fields.push({off:offset, size, type:typeName, name:fieldName});
    }
    return fields;
}

/* ========================  MAIN  ===================================== */
console.log(`[+] DataCore @ ${DATA_CORE_PTR}`);
let globalBytes = 0;
const summary   = {};

for (const {name,namePtr} of iterateStructDesc()) {
    const fields = grabFields(namePtr);
    const structSize = fields.reduce((a,f)=>a+f.size,0);
    globalBytes += structSize;

    console.log(`\n=== ${name} (${structSize} bytes, ${fields.length} fields) ===`);
    fields.sort((a,b)=>a.off-b.off)
          .forEach(f=>console.log(
              `${f.off.toString(16).padStart(4,'0')}  ` +
              `${f.size.toString().padStart(4)}  ` +
              `${f.type.padEnd(26)}  ${f.name}` ));

    // aggregate
    summary[name] = {count:fields.length, bytes:structSize};
}

/* ------------------- aggregate report -------------------------------- */
console.log('\n********  Totals  ********');
console.log(`Structures found : ${Object.keys(summary).length}`);
console.log(`Total bytes       : ${globalBytes}\n`);

Object.entries(summary)
      .sort((a,b)=>b[1].bytes-a[1].bytes)
      .forEach(([n,info]) =>
          console.log(`${n.padEnd(32)} : ${info.count.toString().padStart(3)} fld, ${info.bytes} B`));
