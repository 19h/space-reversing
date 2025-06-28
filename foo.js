// /******************************************************************************
//  * Star Citizen – mini‑math helpers tracer                                    *
//  *                                                                            *
//  *   ┌───────────────────────────────────────────────────────────────────────┐ *
//  *   │  Routine              RVA       Prototype                            │ *
//  *   ├───────────────────────────────────────────────────────────────────────┤ *
//  *   │  sub_14030C9A0   0x030C9A0   QWORD  tag_strip48(_QWORD *p)           │ *
//  *   │  sub_140330BC0   0x0330BC0   QWORD  deref_+0x40 (this)               │ *
//  *   │  sub_145936FF0   0x5936FF0   float  readf( *(this+0x40) + 0x2D0 )    │ *
//  *   └───────────────────────────────────────────────────────────────────────┘ *
//  *                                                                            *
//  ******************************************************************************/

// (function () {
//   "use strict";

//   /*****  Configuration  *****/

//   const MODULE = "StarCitizen.exe";
//   const RVA_TAGSTRIP48 = 0x030c9a0; // sub_14030C9A0
//   const RVA_DEREF40 = 0x0330bc0; // sub_140330BC0
//   const RVA_READF = 0x5936ff0; // sub_145936FF0

//   const MASK48 = 0xffffffffffffn;

//   /*****  Helpers  *****/

//   const hex = (x, pad = 16) => "0x" + x.toString(16).padStart(pad, "0");
//   const padF = (x) => x.toFixed(7).padStart(11, " ");

//   const base = Module.findBaseAddress(MODULE);
//   if (base === null)
//     throw new Error(`[!] ${MODULE} not present in current process`);

//   console.log(`[+] ${MODULE} base           : ${base}`);
//   console.log(`[+]  ├─ sub_14030C9A0 @      : ${base.add(RVA_TAGSTRIP48)}`);
//   console.log(`[+]  ├─ sub_140330BC0 @      : ${base.add(RVA_DEREF40)}`);
//   console.log(`[+]  └─ sub_145936FF0 @      : ${base.add(RVA_READF)}\n`);

//   /*****  Hook: tag‑stripper (sub_14030C9A0)  *****/

//   Interceptor.attach(base.add(RVA_TAGSTRIP48), {
//     onEnter(args) {
//       this.argPtr = args[0];
//       this.raw = this.argPtr.readU64();
//       this.payload = BigInt(this.raw.toString()) & MASK48;

//       console.log(
//         `[⇢] tag_strip48(a1=${hex(this.argPtr)})` + `   *a1=${hex(this.raw)}`,
//       );
//     },
//     onLeave(retval) {
//       console.log(
//         `[⇠]   → ${hex(retval)} ` + `(expected ${hex(this.payload, 12)})\n`,
//       );
//     },
//   });

//   /*****  Hook: deref+(0x40) (sub_140330BC0) *****/

//   Interceptor.attach(base.add(RVA_DEREF40), {
//     onEnter(args) {
//       this.thisPtr = args[0];
//     },
//     onLeave(retval) {
//       console.log(
//         `[⇢/⇠] deref_+0x40(this=${hex(this.thisPtr)})` + ` → ${hex(retval)}`,
//       );
//     },
//   });

//   /*****  Hook: read float (sub_145936FF0) *****/

//   Interceptor.attach(base.add(RVA_READF), {
//     /*
//      *  float readf(this):
//      *      obj  = *(__int64*)(this + 0x40);
//      *      fval = *(float*)(obj + 0x2D0);
//      *      return fval;
//      */

//     onEnter(args) {
//       this.thisPtr = args[0];

//       /* replicate the internal computation so we can cross‑check */
//       this.objPtr = this.thisPtr.add(0x40).readPointer();
//       this.f32 = this.objPtr.add(0x2d0).readFloat();
//     },

//     onLeave(retval) {
//       /* retval is a 64‑bit box containing the IEEE‑754 bits in xmm0.low­qword.
//                We convert via NativePointer->UInt32->Float. */
//       const retBits = retval.toUInt32();
//       const retF32 = new DataView(new ArrayBuffer(4));
//       retF32.setUint32(0, retBits, true);
//       const retValF = retF32.getFloat32(0, true);

//       console.log(
//         `[⇢] readf(this=${hex(this.thisPtr)})` +
//           ` → obj=${hex(this.objPtr)}` +
//           `  @+0x2D0=${padF(this.f32)}`,
//       );
//       console.log(
//         `[⇠]   returned=${padF(retValF)} ` + `(local calc=${padF(this.f32)})\n`,
//       );
//     },
//   });
// })();

// const SetParams = Module.findBaseAddress("StarCitizen.exe").add(0x66dbde0); // RVA you posted
// Interceptor.attach(SetParams, {
//   onEnter(args) {
//     this.entity = args[0];
//     this.pBlob = args[1];
//     this.kind = Memory.readU32(args[1]); // *a2
//     if (this.kind === 1 || this.kind === 34) {
//       // the interesting ones
//       // read the incoming position/quaternion from the blob
//       const px = Memory.readFloat(args[1].add(4));
//       const py = Memory.readFloat(args[1].add(8));
//       const pz = Memory.readFloat(args[1].add(12));
//       console.log(
//         `[SetParams] ent=${ptr(this.entity)} kind=${this.kind} pos=(${px.toFixed(2)},${py.toFixed(2)},${pz.toFixed(2)})`,
//       );
//     }
//   },
// });

/*
 *  Hook IEntity::GetTransformComponent – Star‑/Cry‑/Lumberyard builds
 *  ------------------------------------------------------------------
 *  1. Scans the main module for `48 8B 41 40 C3`
 *  2. Attaches an Interceptor
 *  3. Dumps the ‘this’ pointer’s v‑table on each call
 *
 *  © 2025  (feel free to use/modify – CC‑0)
 */

/*
 *  Safe hook for  IEntity::GetTransformComponent
 *  --------------------------------------------
 *  - skips PAGE_GUARD pages
 *  - otherwise identical behaviour
 */

"use strict";

Interceptor.attach(ptr("0x147C127B0"), {
  onLeave(retval) {
    console.log(retval);
    if (retval.isNull()) return;
    const vtbl = retval.readPointer();
    if (vtbl.isNull()) return;
    console.log(vtbl);
    if (vtbl.readPointer().equals(ptr("0x147C7F6D0"))) {
      // destructor matches
      hookTransform(vtbl);
      this.detach(); // we only needed it once
    }
  },
});

function hookTransform(vtbl) {
  const SetLocalTM = vtbl.add(2 * Process.pointerSize).readPointer();
  console.log(SetLocalTM);
  Interceptor.attach(SetLocalTM, {
    /* same as above */
  });
}
