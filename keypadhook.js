// Hook for sub_14159D5C0
Interceptor.attach(ptr(0x14159D5C0), {
    onEnter: function(args) {
        console.log("[+] sub_14159D5C0 called");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    a3: " + args[2]);

        this.a1 = args[0];
        this.a2 = args[1];
        this.a3 = args[2];
    },
    onLeave: function(retval) {
        console.log("[+] sub_14159D5C0 returning");
        console.log("    return value: " + retval);

        // Read the values written to a2
        if (this.a2.isNull() == false) {
            try {
                var a2_value = ptr(this.a2).readPointer();
                var a2_plus_8_value = ptr(this.a2).add(8).readPointer();
                console.log("    *a2 (a2[0]): " + a2_value);
                console.log("    a2[1]: " + a2_plus_8_value);
            } catch (e) {
                console.log("    Error reading a2 values: " + e);
            }
        }
    }
});

// Hook for sub_1415DE320
Interceptor.attach(ptr(0x1415DE320), {
    onEnter: function(args) {
        console.log("[+] sub_1415DE320 called");
        console.log("    a1: " + args[0]);

        this.a1 = args[0];
    },
    onLeave: function(retval) {
        console.log("[+] sub_1415DE320 returning: " + retval);
    }
});

// Hook for sub_14033FE90
// Interceptor.attach(ptr(0x14033FE90), {
//     onEnter: function(args) {
//         console.log("[+] sub_14033FE90 called");
//         console.log("    a1: " + args[0]);
//         console.log("    a2: " + args[1]);

//         this.a1 = args[0];
//         this.a2 = args[1];
//     },
//     onLeave: function(retval) {
//         console.log("[+] sub_14033FE90 returning");
//         console.log("    return value: " + retval);

//         // Read the values written to a2
//         if (this.a2.isNull() == false) {
//             try {
//                 var a2_value = ptr(this.a2).readPointer();
//                 console.log("    *a2: " + a2_value);
//             } catch (e) {
//                 console.log("    Error reading a2 values: " + e);
//             }
//         }
//     }
// });

// Hook for sub_1415BEEF0
Interceptor.attach(ptr(0x1415BEEF0), {
    onEnter: function(args) {
        console.log("[+] sub_1415BEEF0 called");
        console.log("    a1: " + args[0]);
        console.log("    a1 + 0xA0: " + ptr(args[0]).add(0xA0));

        this.a1 = args[0];
    },
    onLeave: function(retval) {
        console.log("[+] sub_1415BEEF0 returning: " + retval);
    }
});

/***************************************************************************
 *  SCigEventSystem deep telemetry – Star Citizen (x64)                    *
 *  Author: ETHOUT – 2025‑06‑18                                            *
 ***************************************************************************/

'use strict';

const base  = Module.findBaseAddress('StarCitizen.exe');          // adjust if needed
const RVA   = 0x3BE7B0;                                           // sub_1403BE7B0
const FN    = base.add(RVA);

const EVT_STRIDE      = 0x20;
const CB_STRIDE       = 0x20;
const CB_FPTR_OFF     = 0x08;
const EVT_OFF_BEGIN   = 0x20;
const EVT_OFF_END     = 0x28;

/* ──── runtime feature switches ────────────────────────────────────────── */
const CFG = {
    HOOK_V15          : true,      // attach once per unique v15
    CAPTURE_LATENCY   : true,      // ns‑granular duration per callback
    CAPTURE_BACKTRACE : false,     // expensive – set true only when needed
    MAX_BACKTRACE_FR  : 24         // frames
};

/* ──── internal state ──────────────────────────────────────────────────── */
const seenV15 = new Set();
const stats    = new Map();   // key = v15Ptr.toString() → info blob

/* RTTI helpers – Windows specific */
function getRttiName(objPtr)
{
    try {
        const colPtr = objPtr         // vftable lives at [obj]
            .readPointer()           // vtable
            .sub(Process.pointerSize) // CompleteObjectLocator**
            .readPointer();          // CompleteObjectLocator*

        const typeDesc = colPtr
            .add(0x10)               // offsetof(CompleteObjectLocator, TypeDescriptor)
            .readPointer();          // TypeDescriptor*

        const namePtr = typeDesc.add(0x0C); // sizeof(void*)*2 + 4 (for Win64)
        return namePtr.readCString();
    } catch (_) {
        return '<no‑rtti>';
    }
}

/* centralised logging utility */
function note(v15, evId, idx, deltaNs, rtti)
{
    const k = v15.toString();
    if (!stats.has(k)) {
        stats.set(k, {
            v15          : v15,
            symbol       : DebugSymbol.fromAddress(v15).name || '<anon>',
            module       : Process.getModuleByAddress(v15).name,
            rtti         : rtti,
            eventIds     : new Set([evId]),
            callCount    : 1,
            cumLatencyNs : deltaNs
        });
    } else {
        const s = stats.get(k);
        s.callCount++;
        s.cumLatencyNs += deltaNs;
        s.eventIds.add(evId);
    }
}

/* dump helper – callable from REPL */
globalThis.dumpStats = function (fmt='table')
{
    const arr = Array.from(stats.values()).map(v => ({
        v15        : v.v15,
        symbol     : v.symbol,
        module     : v.module,
        rtti       : v.rtti,
        evtSet     : [...v.eventIds].map(id=>id.toString(16)).join('|'),
        calls      : v.callCount,
        avg_us     : (v.cumLatencyNs / v.callCount / 1000).toFixed(1)
    }));

    if (fmt === 'json') {
        console.log(JSON.stringify(arr, null, 2));
    } else {    // ASCII table
        const hdr = 'v15 | symbol | module | rtti | evts | calls | avg_us';
        console.log(hdr);
        console.log('-'.repeat(hdr.length));
        arr.forEach(o => {
            console.log(`${o.v15} | ${o.symbol} | ${o.module} | ${o.rtti} |
${o.evtSet} | ${o.calls} | ${o.avg_us}`);
        });
    }
};

/* ──── main InvokeCallbacks interceptor ───────────────────────────────── */
Interceptor.attach(FN, {
    onEnter(args) {
        const evSys   = args[0];
        const evId    = args[1].toInt32();
        const payload = args[2];

        /* locate event entry */
        let entry = evSys.add(EVT_OFF_BEGIN).readPointer();
        const end = evSys.add(EVT_OFF_END).readPointer();
        while (!entry.equals(end) && entry.readU32() !== evId)
            entry = entry.add(EVT_STRIDE);
        if (entry.equals(end))
            return;

        const cbBegin = entry.add(0x08).readPointer();
        const cbEnd   = entry.add(0x10).readPointer();
        const count   = cbEnd.sub(cbBegin).toUInt32() / CB_STRIDE;

        for (let i = 0; i < count; i++) {
            const cbEntry   = cbBegin.add(i * CB_STRIDE);
            const ctxPtr    = cbEntry.readPointer();                  // this / lambda object
            const v15       = cbEntry.add(CB_FPTR_OFF).readPointer();
            const rttiName  = getRttiName(ctxPtr);

            /* latency timestamp – only once per v15 call */
            const t0 = CFG.CAPTURE_LATENCY ? Process.getCurrentThreadId() /* dummy */ : 0;

            /* lazy attach to v15 */
            if (CFG.HOOK_V15 && !seenV15.has(v15.toString())) {
                seenV15.add(v15.toString());

                Interceptor.attach(v15, {
                    onEnter(cbArgs) {
                        if (CFG.CAPTURE_LATENCY) this._start = hrtime();
                        if (CFG.CAPTURE_BACKTRACE)
                            this._bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                            .slice(0, CFG.MAX_BACKTRACE_FR);
                    },
                    onLeave(retval) {
                        if (CFG.CAPTURE_LATENCY) {
                            const dt = hrtime(this._start);
                            note(v15, evId, i, dt, rttiName);
                        } else {
                            note(v15, evId, i, 0, rttiName);
                        }

                        if (CFG.CAPTURE_BACKTRACE && this._bt)
                            console.log('Backtrace @ '+v15+':\n' +
                                Thread.backtraceToString(this._bt, '    '));
                    }
                });
            }

            /* fast‑path – even if not attaching (HOOK_V15=false), still record */
            if (!CFG.HOOK_V15) {
                note(v15, evId, i, 0, rttiName);
            }
        }
    }
});

/* tiny ns timer using Process.getCurrentThreadId() as monotonic no‑VM‑exit
 * reference. Substitute with Polyfills/NativeFunction( QueryPerformanceCounter)
 * if you need cross‑thread accuracy. */
function hrtime(t0) {
    return (Process.getCurrentThreadId() - t0) * 1000; // ~1 ns granularity
}



// Hook for sub_141590B80
Interceptor.attach(ptr(0x141590B80), {
    onEnter: function(args) {
        console.log("[+] sub_141590B80 called");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    a3: " + args[2]);

        this.a1 = args[0];
        this.a2 = args[1];
        this.a3 = args[2];
    },
    onLeave: function(retval) {
        console.log("[+] sub_141590B80 returning");
        console.log("    return value: " + retval);

        // Read the values written to a2
        if (this.a2.isNull() == false) {
            try {
                var a2_0_value = ptr(this.a2).readPointer();
                var a2_8_value = ptr(this.a2).add(8).readPointer();
                var a2_16_value = ptr(this.a2).add(16).readPointer();
                console.log("    a2[0]: " + a2_0_value);
                console.log("    a2[1]: " + a2_8_value);
                console.log("    a2[2]: " + a2_16_value);
            } catch (e) {
                console.log("    Error reading a2 values: " + e);
            }
        }

        // Read the values written to a3
        if (this.a3.isNull() == false) {
            try {
                var a3_0_value = ptr(this.a3).readPointer();
                var a3_8_value = ptr(this.a3).add(8).readPointer();
                var a3_16_value = ptr(this.a3).add(16).readPointer();
                console.log("    a3[0]: " + a3_0_value);
                console.log("    a3[1]: " + a3_8_value);
                console.log("    a3[2]: " + a3_16_value);
            } catch (e) {
                console.log("    Error reading a3 values: " + e);
            }
        }
    }
});
