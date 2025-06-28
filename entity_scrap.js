/*
 * entity_class_registry_hooks.js   —   ASLR-off, x64
 *
 *  Revised: replaced Process.hrtime() with Date.now().
 */

'use strict';

/* ===================================================================== *
 *                               Helpers                                 *
 * ===================================================================== */

function dumpMem(ptrVal, len = 0x100) {
    try {
        console.log(
            hexdump(ptr(ptrVal), { offset: 0, length: len, header: true, ansi: false })
        );
    } catch (e) {
        console.log(`  [!!] Unable to read 0x${len.toString(16)} @ ${ptr(ptrVal)}: ${e}`);
    }
}

function dumpQwords(ptrVal, count = 8) {
    try {
        const base = ptr(ptrVal);
        const sz   = Process.pointerSize;
        let line   = '';
        for (let i = 0; i < count; i++) {
            const cur = base.add(i * sz);
            if ((i % 4) === 0) {
                if (i) console.log(line);
                line = `  +0x${(i * sz).toString(16).padStart(2, '0')}:`;
            }
            line += ` ${cur.readPointer()}`;
        }
        console.log(line);
    } catch (e) {
        console.log(`  [!!] QWORD dump failed @ ${ptr(ptrVal)}: ${e}`);
    }
}

function dumpContext(ctx) {
    const gpr = [
        'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
        'r8','r9','r10','r11','r12','r13','r14','r15','rip','rflags'
    ].map(r => `${r.toUpperCase()}: ${ctx[r]}`).join('  ');
    console.log(gpr);

    const xmm = ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']
        .map(x => `${x.toUpperCase()}: ${ctx[x]}`).join('  ');
    console.log(xmm);
}

function numFmt(v) {
    const u64 = ptr(v).toUInt32();
    return `${u64} / 0x${u64.toString(16)} / ${ptr(v).toInt32()}`;
}

/* ============================================================= *
 *                   Generic probe factory                        *
 * ============================================================= */

function makeProbe(name, argCount) {
    return {
        onEnter(args) {
            this.t0      = Date.now();
            this.thread  = Process.getCurrentThreadId();

            console.log('\n============================================================');
            console.log(`[+] ${name}  ⇒  thread=${this.thread}`);
            console.log('------------------------------------------------------------');

            dumpContext(this.context);

            for (let i = 0; i < argCount; i++) {
                const a = args[i];
                console.log(` Arg[${i}] = ${numFmt(a)} (${a})`);
                if (a.isNull()) continue;

                /* specialised decode: sub_1468F5DE0 arg2 = char* */
                if (name === 'sub_1468F5DE0' && i === 2) {
                    try { console.log(`  • C-string: "${Memory.readCString(a)}"`); } catch (_) {}
                }

                dumpQwords(a, 8);
                dumpMem(a, 0x100);
            }

            console.log(' Backtrace:');
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
        },

        onLeave(retval) {
            const dt = Date.now() - this.t0;          // ms
            console.log('------------------------------------------------------------');
            console.log(` Return @ ${name}: ${numFmt(retval)} (${retval})`);
            if (!retval.isNull()) dumpMem(retval, 0x100);
            console.log(` Latency: ${dt} ms`);
            console.log('============================================================\n');
        }
    };
}

/* ============================================================= *
 *                    Address map & hooks                         *
 * ============================================================= */

const targets = [
    { name: 'CEntityClassRegistry::FindClass-2BB0', addr: '0x1468D2BB0', argc: 2 },
    { name: 'CEntityClassRegistry::FindClass-2CC0', addr: '0x1468D2CC0', argc: 2 },
    { name: 'CEntityClassRegistry::FindClass-2DD0', addr: '0x1468D2DD0', argc: 2 },
    { name: 'CEntityClassRegistry::RegisterClass', addr: '0x1468F5DE0', argc: 3 },
    { name: 'CEntityClassRegistry::FindClassForArchetype', addr: '0x1468D2EB0', argc: 2 },
];

targets.forEach(t => {
    const p = ptr(t.addr);
    console.log(`[i] Attaching to ${t.name} @ ${p}`);
    Interceptor.attach(p, makeProbe(t.name, t.argc));
});
