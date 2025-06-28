/*  camera-dump.js  – arg_9-centric variant
 *  ───────────────────────────────────────────────────────────────────────────
 *  Requires:   frida-server inside the target session
 *  Usage:      frida -l camera-dump.js -p <pid>
 *              …or…
 *              frida -l camera-dump.js <GameExeName>
 * -------------------------------------------------------------------------*/

'use strict';

/* ------------------------------------------------------------------------- *
 * 1.  Configuration (unchanged)                                              *
 * ------------------------------------------------------------------------- */

const GAME_MODULE   = 'StarCitizen.exe';         // PE containing sub_140977A60
const FN_RVA        = 0x977A60;                  // <==  140977A60 – image base
const CAMERA_BASE   = 0x41CDn;                   // element index of camera array
const CAMERA_STRIDE = 0x888n;                    // elements per thread
const COLS          = 4;                         // pretty-printer (float4 per line)

/* ------------------------------------------------------------------------- *
 * 2.  Helpers (unchanged)                                                    *
 * ------------------------------------------------------------------------- */

const GetCurrentThreadId = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'GetCurrentThreadId'),
    'uint32', []
);

const f32 = addr => Memory.readFloat(ptr(addr));

function dumpCamera(camPtr) {

    const raw = Memory.readByteArray(camPtr, 0x40);  // 64 B
    console.log('──────────────── camera state @', camPtr);
    console.log(hexdump(raw, { length: 0x40, ansi: false }));

    let off = 0;
    for (let row = 0; row < 4; ++row) {
        const line = [];
        for (let col = 0; col < COLS; ++col, off += 4)
            line.push(f32(camPtr.add(off)).toFixed(6).padStart(12));
        console.log('[' + row + '] ' + line.join(' '));
    }
    console.log('──────────────────────────────────────────────\n');
}

/* ------------------------------------------------------------------------- *
 * 3.  Global state                                                           *
 * ------------------------------------------------------------------------- */

let gRootPtr   = ptr('0x0');   /* last-seen global root (a1)                 */
let gCamState  = ptr('0x0');   /* last-seen camera pointer (pref. arg_9)      */

/* ------------------------------------------------------------------------- *
 * 4.  Hook – captures a1 and arg_9                                           *
 * ------------------------------------------------------------------------- */

const base = Module.findBaseAddress(GAME_MODULE);
if (base.isNull())
    throw new Error('[camera-dump] target module not loaded – check name');

const fn977A60 = base.add(FN_RVA);
console.log('[+] sub_140977A60  @', fn977A60);

Interceptor.attach(fn977A60, {
    onEnter(args) {

        /* (a) update global root if changed */
        const a1 = args[0];
        if (!a1.equals(gRootPtr)) {
            gRootPtr = a1;
            console.log('[*] Updated gRootPtr →', gRootPtr);
        }

        /* (b) extract 9-th parameter (arg_9)                                 */
        const rsp   = this.context.rsp;
        const arg_9 = Memory.readPointer(rsp.add(0x30));

        /* (c) fallback determination (identical to original logic)           */
        let camBlk;
        if (!arg_9.isNull()) {
            //gCamState = arg_9;                // authoritative pointer
            //return;
        }

        /* – only executed when arg_9 == NULL –                               */
        const thrTbl    = Memory.readPointer(a1.add(0x260));  // a1[0x4C]
        const tid       = GetCurrentThreadId();
        const tid_main  = Memory.readU32(thrTbl.add(0x3C));   // [0xF]
        const tid_logic = Memory.readU32(thrTbl.add(0x38));   // [0xE]

        let idx;
        if (tid === tid_main)
            idx = Memory.readU32(thrTbl.add(0x2C)) & 1;       // [0xB] & 1
        else if (tid === tid_main || tid === tid_logic)
            idx = Memory.readU32(thrTbl.add(0x30));           // [0xC]
        else
            idx = Memory.readU32(thrTbl.add(0x34));           // [0xD]

        camBlk   = a1.add(
            Number((CAMERA_BASE + CAMERA_STRIDE * BigInt(idx)) << 3n)
        );
        gCamState = camBlk;                // fallback pointer

        console.log(tid, tid_main, tid_logic, idx, gCamState);
    }
});

/* ------------------------------------------------------------------------- *
 * 5.  Polling loop – reads gCamState directly                                *
 * ------------------------------------------------------------------------- */

function pollCamera() {
    if (gCamState.isNull())         // no pointer yet
        return;
    try {
        dumpCamera(gCamState);
    } catch (e) {
        /* pointer became stale – reset and wait for next hook hit           */
        console.error('[!] camera read failed –', e.message);
        gCamState = ptr('0x0');
    }
}

/* 100 ms cadence – adjust ad libitum. */
//setInterval(pollCamera, 100);

/* ------------------------------------------------------------------------- *
 * End of file                                                                *
 * ------------------------------------------------------------------------- */

 /* ------------------------------------------------------------------------- *
  * 6.  Hook for tCEntitySystem__Update                                        *
  * ------------------------------------------------------------------------- */

 const FN_ENTITY_UPDATE_RVA = ptr('0x69060B0'); // RVA for tCEntitySystem__Update (0x1469060B0 - 0x140000000)

 // 'base' is already defined and initialized in section 4.
 // const base = Module.findBaseAddress(GAME_MODULE);

 const fnEntityUpdate = base.add(FN_ENTITY_UPDATE_RVA);
 console.log('[+] tCEntitySystem__Update @', fnEntityUpdate);

 Interceptor.attach(fnEntityUpdate, {
     onEnter(args) {
         console.log('[+] tCEntitySystem__Update onEnter');
         // __fastcall on x64: first arg (int64_t) is in RCX, which is args[0]
         // For a C++ member function, this would be the 'this' pointer.
         this.entitySystemInstance = args[0];
         console.log('    this (rcx, int64_t):', this.entitySystemInstance);

         const threadId = GetCurrentThreadId();
         console.log('    threadId:', threadId);

         pollCamera();
     },
     onLeave(retval) {
         console.log('[+] tCEntitySystem__Update onLeave');
         // Return value is double, passed in XMM0.
         // 'retval' is a NativePointer whose value holds the bits of the double.
         // To convert to a JavaScript number:
         const doubleBits = retval.readU64(); // Get the 64-bit raw integer value
         const tempBuffer = Memory.alloc(8);   // Allocate a temporary 8-byte buffer
         Memory.writeU64(tempBuffer, doubleBits); // Write the bits into the buffer
         const doubleValue = Memory.readDouble(tempBuffer); // Read the buffer as a double

         console.log('    retval (double):', doubleValue);

         // Example of using data saved in onEnter:
         // console.log('    tCEntitySystem__Update was called on instance:', this.entitySystemInstance);
     }
 });
