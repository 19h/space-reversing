/*
 *  frida-hook-CActorEntity-Action.js
 *
 *  Attach to CryEngine's CActorEntity::Action (sub_1466BAFD0) and, **after the
 *  function returns**, dump every scalar field that routine manipulates.
 *
 *  Build-ID / RVA
 *  -------------- -------------------------------------------------------------
 *  Shipping build where the listing came from uses absolute RVA 0x1466BAFD0.
 *  If your DLL/EXE is rebased, change `FUNC_RVA` below or use an exported
 *  symbol name in DebugSymbol.fromName().
 *
 *  Usage:
 *      frida -l frida-hook-CActorEntity-Action.js -f YourGame.exe --no-pause
 */

const MODULE_NAME = "StarCitizen.exe";          // <— put the module that owns the code
const FUNC_RVA    = 0x0066BAFD0;         // <— RVA inside the PE image

/* ------------------------------------------------------------------------- */

function ptrFromRva(modName, rva) {
    const base = Module.findBaseAddress(modName);
    if (base === null)
        throw new Error(`module ${modName} not loaded`);
    return base.add(rva);
}

// Safety wrapper for reading floats: returns null if not a plausible float
function safeReadFloat(ptr) {
    try {
        const val = Memory.readFloat(ptr);
        // Check for NaN, Infinity, or absurd values
        if (!Number.isFinite(val)) return null;
        // Optionally, clamp to plausible float range for game data
        if (Math.abs(val) > 1e6) return null;
        return val;
    } catch (e) {
        return null;
    }
}

function extractLower48(ptrVal) {
    // Mask with 0xFFFFFFFFFFFF
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

const target = ptrFromRva(MODULE_NAME, FUNC_RVA);
// alternatively, if the symbol is exported / present in PDBs:
// const target = DebugSymbol.fromName("sub_1466BAFD0").address;

console.log("[*] Hooking " + target);

// Interceptor.attach(target, {
//     onEnter(args) {
//         // RCX = first fastcall argument = CActorEntity* (this)
//         this.actor = args[0];        // save for onLeave

//         console.log(this.actor, this.actor.readPointer(), extractLower48(this.actor.readPointer()));

//         // Make a memory snapshot of the actor to prevent issues if it's deleted
//         if (!this.actor.isNull()) {
//             try {
//                 // Create a buffer to store actor memory
//                 const memorySize = 0x0B40; // Size covering all fields we need
//                 this.actorMemory = Memory.alloc(memorySize);

//                 // Copy actor memory to our safe buffer
//                 Memory.copy(this.actorMemory, this.actor, memorySize);

//                 console.log("[*] Actor memory snapshot created");
//             } catch (e) {
//                 console.error("[!] Failed to create memory snapshot: " + e);
//                 this.actorMemory = null;
//             }
//         }
//     },

//     onLeave(retval) {
//         try {
//             // Use the memory snapshot instead of the original actor pointer
//             const a = this.actorMemory || this.actor;
//             if (a.isNull()) return;    // sanity

//             const dump = {
//                 actor         : a,

//                 returnValue   : retval.toInt32(),

//                 /* ===== basic kinematics ===== */
//                 FacingDir     : [
//                     safeReadFloat(a.add(0x03C0)),
//                     safeReadFloat(a.add(0x03C4)),
//                     safeReadFloat(a.add(0x03C8))
//                 ],
//                 PositionWS    : [
//                     safeReadFloat(a.add(0x03CC)),
//                     safeReadFloat(a.add(0x03D0)),
//                     safeReadFloat(a.add(0x03D4))
//                 ],
//                 LookDir       : [
//                     safeReadFloat(a.add(0x03FC)),
//                     safeReadFloat(a.add(0x400)),
//                     safeReadFloat(a.add(0x404))
//                 ],
//                 RootOffset    : [
//                     safeReadFloat(a.add(0x0420)),
//                     safeReadFloat(a.add(0x0424)),
//                     safeReadFloat(a.add(0x0428))
//                 ],

//                 /* ===== limits & misc scalars ===== */
//                 MassScale     : safeReadFloat(a.add(0x04A0)),

//                 LookSpeed     : safeReadFloat(a.add(0x0698)),
//                 AimSpeed      : safeReadFloat(a.add(0x0738)),

//                 LookConstraintDir : [
//                     safeReadFloat(a.add(0x0938)),
//                     safeReadFloat(a.add(0x093C)),
//                     safeReadFloat(a.add(0x0940))
//                 ],
//                 AimConstraintDir  : [
//                     safeReadFloat(a.add(0x0944)),
//                     safeReadFloat(a.add(0x0948)),
//                     safeReadFloat(a.add(0x094C))
//                 ],
//                 AimTargetPoint    : [
//                     safeReadFloat(a.add(0x0950)),
//                     safeReadFloat(a.add(0x0954)),
//                     safeReadFloat(a.add(0x0958))
//                 ],

//                 PitchMin      : safeReadFloat(a.add(0x095C)),
//                 PitchMax      : safeReadFloat(a.add(0x0960)),
//                 YawMin        : safeReadFloat(a.add(0x0964)),
//                 YawMax        : safeReadFloat(a.add(0x0968)),
//                 InvTanFOV     : safeReadFloat(a.add(0x096C)),

//                 /* ===== status / mode flags ===== */
//                 FlagsLookAim  : Memory.readU16(a.add(0x0970)),
//                 FlagsStatusA  : Memory.readU8 (a.add(0x0972)),
//                 FlagsStatusB  : Memory.readU8 (a.add(0x0973)),

//                 /* ===== ring-buffer cursors ===== */
//                 RingBegin     : Memory.readPointer(a.add(0x0B20)),
//                 RingWrite     : Memory.readPointer(a.add(0x0B28)),
//                 RingEnd       : Memory.readPointer(a.add(0x0B30))
//             };

//             send(dump);      // forward as structured JSON
//         }
//         catch (e) {
//             console.error("[!] Dump failed: " + e);
//         }
//     }
// });

/*
 *  Hook for sub_146437910
 *
 *  Prototype:
 *      __int64 __fastcall sub_146437910(int a1, __int64 a2, __int64 a3, const char *Source, __int64 r8_0a, int n2)
 *
 *  Args (fastcall x64):
 *      RCX: int a1
 *      RDX: __int64 a2
 *      R8 : __int64 a3
 *      R9 : const char *Source
 *      [stack+0x20]: __int64 r8_0a
 *      [stack+0x28]: int n2
 */

 const target2 = ptr(0x146437910); // absolute virtual address – adjust if ASLR
 console.log('[*] Installing CModule hook at ' + target2);

 /******************************************************************************/
 /*                                C MODULE                                   */
 /******************************************************************************/

 const EVENT_CAPACITY = 2048;           // power‑of‑two strongly recommended

 const cSource = `
 #include <stdint.h>

 #define EVENT_CAPACITY ${EVENT_CAPACITY}

 typedef struct {
     void *retval;
     void *src_ptr;   // Pointer captured as‑is; JS will dereference lazily
 } event_t;

 static volatile uint32_t write_idx = 0;
 static event_t           events[EVENT_CAPACITY];

 static inline uint32_t atomic_fetch_inc(volatile uint32_t *p)
 {
 #if defined(__clang__) || defined(__GNUC__)
     return __sync_fetch_and_add(p, 1u);
 #else
     uint32_t old = *p;
     *p = old + 1u;
     return old;
 #endif
 }

 static void buffer_event(uint64_t ret, const void *src)
 {
     const uint32_t slot = atomic_fetch_inc(&write_idx) & (EVENT_CAPACITY - 1);
     events[slot].retval   = (void *)(uintptr_t) ret;
     events[slot].src_ptr  = (void *)src;
 }

 extern uint64_t (*orig_func)(int32_t, int64_t, int64_t, const char *);

 uint64_t replacement(int32_t a1, int64_t a2, int64_t a3, const char *Source)
 {
     uint64_t rv = orig_func(a1, a2, a3, Source);
     if (a1 == 11)
         buffer_event(rv, Source);
     return rv;
 }

 void *get_events(void)        { return events; }
 uint32_t get_write_index(void) { return write_idx; }
 `;

 /* Provide `orig_func` to the CModule via the imports object */
 const cm = new CModule(cSource, {
     orig_func: target2
 });

 /* Create a JS‑side NativeCallback that points to the C replacement */
 const replacementPtr = cm.replacement; // NativePointer
 Interceptor.replace(target2, replacementPtr);
 console.log('[+] Hook active; events will be buffered when a1 == 11');

 /******************************************************************************/
 /*                        JS‑side buffer utilities                            */
 /******************************************************************************/

 const eventSize  = Process.pointerSize * 2; // retval + src_ptr
 const eventsBase = cm.get_events();
 const idxPtr     = cm.get_write_index;

 function readBufferedEvents(startIdx = 0) {
     const cur = Memory.readU32(idxPtr);
     for (let i = startIdx; i < cur; ++i) {
         const off  = (i & (EVENT_CAPACITY - 1)) * eventSize;
         const base = eventsBase.add(off);
         const rv   = Memory.readPointer(base);
         const srcP = Memory.readPointer(base.add(Process.pointerSize));

         let srcStr = null;
         try {
             if (!srcP.isNull()) srcStr = Memory.readUtf8String(srcP);
         } catch (_) { /* keep as null */ }

         console.log(JSON.stringify({ idx: i, retval: rv, Source: srcStr, srcPtr: srcP }));
     }
     return cur;
 }

 rpc.exports.readBufferedEvents = readBufferedEvents;
 console.log('[*] Use readBufferedEvents() from the REPL to dump the ring buffer.');


// console.log("[*] Hooking sub_146437910 at " + target2);

// const entityMap = {
//     1: 'CPhysicalEntity',
//     2: 'CRigidEntity',
//     3: 'CWheeledVehicleEntity',
//     4: 'CRopeEntityEx',
//     5: 'CParticleEntity',
//     6: 'CArticulatedEntity',
//     7: 'CRopeEntity',
//     8: 'CSoftEntity',
//     9: 'CPhysArea',
//     10: 'CSpaceshipEntity',
//     11: 'CActorEntity',
//     12: 'CPhysPlanetEntity',
//     13: 'CSoftEntityEx',
//     14: 'CHoverEntity',
// };

// Interceptor.attach(target2, {
//     onEnter(args) {
//         if (args[0].toInt32() !== 11) return;
//         // args[0] = RCX = int a1
//         // args[1] = RDX = __int64 a2
//         // args[2] = R8  = __int64 a3
//         // args[3] = R9  = const char *Source

//         // Stack args: [rsp+0x20] and [rsp+0x28]
//         // On Windows x64, Frida exposes stack args via this.context.rsp
//         const rsp = this.context.rsp;
//         // Skip return address (0x00), shadow space (0x08, 0x10, 0x18), then stack args
//         // [rsp+0x20] = 0x20
//         // [rsp+0x28] = 0x28
//         const r8_0a = Memory.readS64(rsp.add(0x20));
//         const n2    = Memory.readS32(rsp.add(0x28));

//         let sourceStr = null;
//         try {
//             if (!args[3].isNull()) {
//                 sourceStr = Memory.readCString(args[3]);
//             }
//         } catch (e) {
//             sourceStr = null;
//         }

//         this.args = {
//             a1      : args[0].toInt32(),
//             a2      : args[1].toString(),
//             a3      : args[2].toString(),
//             Source  : sourceStr,
//             r8_0a   : r8_0a.toString(),
//             n2      : n2
//         };
//     },
//     onLeave(retval) {
//         console.log(
//             JSON.stringify(
//                 {
//                     ...this.args,
//                     retval,
//                     entityType: entityMap[this.args.a1] || 'Unknown',
//                 },
//                 null,
//                 4,
//             ),
//         );
//     }
// });
