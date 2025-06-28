/*  camera-dump.js  ──────────────────────────────────────────────────────────
 *  - Requires:  frida-server running inside the target session
 *  - Usage:     frida -l camera-dump.js -p <pid>
 *               …or…
 *               frida -l camera-dump.js <GameExeName>
 * -------------------------------------------------------------------------*/

'use strict';

/* ------------------------------------------------------------------------- *
 * 1.  Configuration                                                          *
 * ------------------------------------------------------------------------- */

const GAME_MODULE   = 'StarCitizen.exe';        // PE containing sub_140977A60
const FN_RVA        = 0x977A60;          // <==   140977A60 – image base
const CAMERA_BASE   = 0x41CDn;           // element index of camera array
const CAMERA_STRIDE = 0x888n;            // elements per thread
const COLS          = 4;                 // pretty-printer (float4 per line)

/* ------------------------------------------------------------------------- *
 * 2.  Helpers                                                                *
 * ------------------------------------------------------------------------- */

const GetCurrentThreadId = new NativeFunction(
    Module.getExportByName('kernel32.dll', 'GetCurrentThreadId'),
    'uint32', []
);

const f32 = addr => Memory.readFloat(ptr(addr));

/* nice raw + decoded console output */
function dumpCamera(camPtr) {

    const raw   = Memory.readByteArray(camPtr, 0x40);  // 64 bytes
    console.log('──────────────── camera state @', camPtr);
    console.log(hexdump(raw, { length: 0x40, ansi: false }));

    let off = 0;
    for (let row = 0; row < 4; ++row) {
        let line = [];
        for (let col = 0; col < COLS; ++col, off += 4)
            line.push(f32(camPtr.add(off)).toFixed(6).padStart(12));
        console.log('[' + row + '] ' + line.join(' '));
    }
    console.log('──────────────────────────────────────────────\n');
}

/* ------------------------------------------------------------------------- *
 * 3.  Hook                                                                   *
 * ------------------------------------------------------------------------- */

const base = Module.findBaseAddress(GAME_MODULE);
if (base.isNull()) {
    console.error('[!]   module not loaded – make sure the name is correct');
}

const fn977A60 = base.add(FN_RVA);
console.log('[+]   sub_140977A60  @', fn977A60);

Interceptor.attach(fn977A60, {

    onEnter(args) {

        /* -----------------------------------------------------------------
         * (a) parameters                                                    */

        const a1 = args[0];                     // RCX = global root
        const rsp = this.context.rsp;           // stack frame base
        const arg_9 = Memory.readPointer(rsp.add(0x30)); // 9-th param (a9)

        if (!arg_9.isNull()) return;

        console.log(a1, arg_9);

        console.log('\nBacktrace:\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(address => DebugSymbol.fromAddress(address).toString())
            .join('\n') + '\n');

        /* -----------------------------------------------------------------
         * (b) thread-local selector                                         */

        const thrTbl    = Memory.readPointer(a1.add(0x260));     // a1[0x4C]
        const tid       = GetCurrentThreadId();

        const tid_main  = Memory.readU32(thrTbl.add(0x3C));      // [0xF]
        const tid_logic = Memory.readU32(thrTbl.add(0x38));      // [0xE]

        let idx;
        if (tid === tid_main)
            idx = Memory.readU32(thrTbl.add(0x2C)) & 1;          // [0xB] & 1
        else if (tid === tid_main || tid === tid_logic)
            idx = Memory.readU32(thrTbl.add(0x30));              // [0xC]
        else
            idx = Memory.readU32(thrTbl.add(0x34));              // [0xD]

        console.log(
            tid,
            tid_main,
            tid_logic,
            tid === tid_main,
            tid === tid_logic,
        );

        /* -----------------------------------------------------------------
         * (c) camera block pointer                                          */

        const camBlk = a1.add( Number((CAMERA_BASE + CAMERA_STRIDE * BigInt(idx)) << 3n) );

        /* -----------------------------------------------------------------
         * (d) prefer caller-supplied pointer                                */

        const camState = arg_9.isNull() ? camBlk : arg_9;

        /* Show once per call – comment out if you need throttling. */
        dumpCamera(camState);
    }
});
