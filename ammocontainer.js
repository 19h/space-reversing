// frida script: force SetAmmoCount to always fill to capacity, always trigger update & always write to container

'use strict';

// 1. Adjust these to match your target module/executable
const module = Process.enumerateModulesSync()[0];
const base = module.base;

const targetAddr = ptr(0x145819810);
console.log(`🔗 Hooking SetAmmoCount at ${targetAddr}`);

const SET_AMMO_CNT      = ptr(0x145819810);      // sub_145819810
const extendedFuncOffset  = 0x1457F1050;      // sub_1457F1050
const capacityFuncOffset  = 0x1458005D0;      // sub_1458005D0
const getTransformOffset  = 0x145819948;      // IEntity__GetTransformComponent
const NOTIFY_LISTENERS = ptr('0x1457D7580');  // sub_1457D7580

// // wrap engine helpers
// const getCapacity = new NativeFunction(
//   base.add(capacityFuncOffset - base.toUInt32()),
//   'uint32', ['pointer']
// );

// const getExtended = new NativeFunction(
//   base.add(extendedFuncOffset - base.toUInt32()),
//   'uint64', ['pointer']
// );

// const getTransform = new NativeFunction(
//   base.add(getTransformOffset - base.toUInt32()),
//   'pointer', ['pointer']
// );

// function dumpVtable(thisPtr, count = 16) {
//   const vt = thisPtr.readPointer();
//   console.log(`\n[vtable @ ${vt}]`);
//   for (let i = 0; i < count; i++) {
//     const fn = vt.add(i * Process.pointerSize).readPointer();
//     console.log(`  [${i.toString().padStart(2,'0')}] → ${fn}`);
//   }
// }

// function tryReadString(p) {
//   try {
//     const s = Memory.readUtf8String(p, 64);
//     if (s && s.length >= 4) return `"${s.split('\0')[0]}"`;
//   } catch(e){}
//   return null;
// }

// function dumpPointersAndStrings(thisPtr, len = 0x200) {
//   console.log('\n[pointers → ASCII]');
//   for (let off = 0; off < len; off += Process.pointerSize) {
//     const p = thisPtr.add(off).readPointer();
//     // only consider addresses in a known module
//     if (Process.findModuleByAddress(p)) {
//       const str = tryReadString(p);
//       console.log(` [0x${off.toString(16)}] → ${p}` + (str ? ` ${str}` : ''));
//     }
//   }
// }

// function dumpListenerTable(thisPtr, start = 0x120, end = 0x1B8) {
//   console.log('\n[listeners @ 0x120–0x1B8]');
//   for (let off = start; off <= end; off += 8) {
//     const fptr = thisPtr.add(off).readPointer();
//     if (!fptr.isNull()) {
//       console.log(` [0x${off.toString(16)}] callback → ${fptr}`);
//     }
//   }
// }

// // Hook SetAmmoCount to run our dumps after each call
// Interceptor.attach(SET_AMMO_CNT, {
//   onEnter(args) {
//     this.ptr = args[0];
//   },
//   onLeave(ret) {
//     console.log(`\n── AmmoContainer @ ${this.ptr}`);
//     dumpVtable(this.ptr);
//     dumpPointersAndStrings(this.ptr);
//     dumpListenerTable(this.ptr);
//     console.log('────────────────────────────────────────\n');
//   }
// });

// // Hook the listener-notify routine itself to see real notifications!
// Interceptor.attach(NOTIFY_LISTENERS, {
//   onEnter(args) {
//     // signature: __fastcall sub_1457D7580(this, callbackPtr, newCount, oldCount, …)
//     const cb = args[1];
//     const newCount = args[2].toInt32();
//     const oldCount = args[3].toInt32();
//     console.log(`→ Notify listener ${cb}:  new=${newCount}  old=${oldCount}`);
//   }
// });

// function dumpAmmoContainer(thisPtr) {
//   console.log('\n── AmmoContainer @', thisPtr);

//   // 1) raw memory
//   //hexdumpRegion(thisPtr, 0x200);

//   // 2) direct fields
//   const vtable      = thisPtr.readPointer();
//   const meshHandle  = thisPtr.add(0x08).readPointer();
//   const capacityF   = thisPtr.add(0xF0).readU32();
//   const ammoCount   = thisPtr.add(0xF4).readU32();

//   console.log(' [0x00] vtable           =', vtable);
//   console.log(' [0x08] meshHandle       =', meshHandle);
//   console.log(' [0xF0] capacity (fld)   =', capacityF);
//   console.log(' [0xF4] ammoCount (fld)  =', ammoCount);
// }

// 3. Intercept and override
Interceptor.attach(targetAddr, {
    onEnter: function (args) {
        // args[0] = thisPtr (rcx)
        // args[1] = requestedCount (edx)
        // args[2] = modeFlag       (r8b)
        const thisPtr = args[0];

        // Read the component's capacity from offset +240
        const capacity = Memory.readU32(thisPtr.add(240));

        // --- Ensure "container always updated" ---
        // Force oldCount = 0 so newCount != oldCount and the code will store the new value
        Memory.writeU32(thisPtr.add(0xF4), 0);

        // --- Set new count to max capacity ---
        // Overwrite the requestedCount argument (edx) with capacity
        this.context.rdx = ptr(capacity);

        // --- Ensure update trigger always called ---
        // modeFlag == 2 will unconditionally run the UI + listener-notify path
        // modeFlag is passed in r8b (low byte of r8)
        this.context.r8 = ptr(2);

        console.log(`  ▶ thisPtr=${thisPtr}  capacity=${capacity}`);
    },
    onLeave: function (retval) {
      // rcx still holds thisPtr on exit
      //dumpAmmoContainer(this.context.rcx);
    }
});

/*
 *  force_full_health.js
 *
 *  • Hooks the big stat mutator (sub_1436BB390) completely at runtime.
 *  • When the stat being written is one of the health-pool/limb values
 *    it overwrites e->Current with 100.0f (0x42C80000) *after* the engine
 *    finishes its own bookkeeping.
 *  • Skips BloodDrugLevel (2) and OverdoseLevel (3) so healing no longer
 *    causes instant overdose death.
 *
 * Tested with 3.23.0-PTU.8906774,  Win-64,  25-Apr-2025 build.
 */

 /* force_full_health.js – RESILIENT BUILD                                    */
 /* ------------------------------------------------------------------------- */
 const FULL_BITS   = 0x42C80000;                       // 100.0f
 const EMPTY_BITS  = 0x00000000;                       // 0.0f
 const THIRTY_SIX = 0x42100000;
 const FORCE_FULL  = new Set();
 const EXCLUDE     = new Set([0x02,0x03]);

 const STAT_MAP = [
   [
     new Set([0x00,0x01,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11, 0x1c]),
     FULL_BITS,
   ],
   [
     new Set([0x02, 0x03, 0x06, 0x07, 0x0a, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]),
     EMPTY_BITS,
   ],
   [
     new Set([0x04, 0x05]),
     THIRTY_SIX,
   ],
 ]

 /* --- 1. signature(s) ----------------------------------------------------- */
 /* vmovss [rdi],xmm7  C5 FA 11 3F
  * cmp    byte ptr [rax+disp8],00   80 78 ?? 00      (disp8 used to be 2A)
  */
 const SIG_VMOVSS = "C5 FA 11 3F 80 78 ?? 00";
 const SIG_PROLOG = "48 89 5C 24 08 57 48 83 EC 50";

 /* --- 2. locate the first matching routine in ANY module ------------------ */
 function locateMutator () {
     for (const m of Process.enumerateModulesSync()) {
         const hits = Memory.scanSync(m.base, m.size, SIG_VMOVSS);
         if (hits.length === 0) continue;

         /* We take the first hit in this module. */
         const vmov = hits[0].address;

         /* Try to walk back ≤ 0x200 bytes to the prologue; else fallback −0x189 */
         const backBlock = vmov.sub(0x200);
         const prologHit = Memory.scanSync(backBlock, 0x200, SIG_PROLOG);
         const entry = prologHit.length ? prologHit[0].address : vmov.sub(0x189);

         return { entry, module: m.name, vmov };
     }
     return null;
 }

 const loc = locateMutator();
 if (!loc) {
     console.error("[!] vmovss signature not found in any loaded module.");
     throw new Error("Mutator function unresolved – update the mask.");
 }

 console.log(`[+] sub_1436BB390 located in ${loc.module}`);
 console.log("    vmovss @ " + loc.vmov + "  →  entry @ " + loc.entry);

 const seen = new Set();

 /* --- 3. hook ------------------------------------------------------------- */
 Interceptor.attach(loc.entry, {
     onEnter(args) {
         this.id  = args[1].toUInt32();
         this.ent = args[2];

         this.patch = null;

         for (const [stats, override] of STAT_MAP) {
           if (stats.has(this.id)) {
             this.patch = override;
             break;
           }
         }
     },
     onLeave() {
         if (this.patch && this.ent.toUInt32() > 1000) {
           Memory.writeU32(this.ent, this.patch)
         };
     }
 });

 /* --- 4. crash-guard ------------------------------------------------------ */
 Process.setExceptionHandler(d => { console.error("[!] native exception:", d); return false; });
