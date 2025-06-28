'use strict';

(function() {
    // 1) Determine the base of the main module (assumed to be your executable)
    const mainModule = Process.enumerateModulesSync()[0];
    const baseAddr    = mainModule.base;
    console.log(`[+] Main module: ${mainModule.name} @ ${baseAddr}`);

    // 2) Offsets of each function from the module base (calc’d as 0x143F8D6B0 - 0x140000000, etc.)
    const OFFSETS = {
        sub_143EDD3D0: 0x3EDD3D0,
        sub_143F84580: 0x3F84580,
        sub_143F8D6B0: 0x3F8D6B0
    };

    // 3) Resolve full addresses
    const FUNCS = {};
    for (let name in OFFSETS) {
        FUNCS[name] = baseAddr.add(OFFSETS[name]);
        console.log(`    → ${name} @ ${FUNCS[name]}`);
    }

    // Helper to format a NativePointer as hex
    function hex(ptr) {
        return ptr.isNull() ? 'NULL' : ptr.toString();
    }

    // 4) Hook sub_143EDD3D0(__int64 a1)
    Interceptor.attach(FUNCS.sub_143EDD3D0, {
        onEnter(args) {
            this.a1       = args[0];
            this.startPtr = ptr( Memory.readU64(this.a1.add(112)) );
            this.endPtr   = ptr( Memory.readU64(this.a1.add(120)) );
            const bytes   = this.endPtr.toUInt32() - this.startPtr.toUInt32();
            this.count    = bytes >>> 5;
            console.log(`\n[+] sub_143EDD3D0 ➜ enter`);
            console.log(`    a1        = ${hex(this.a1)}`);
            console.log(`    startPtr  = ${hex(this.startPtr)}`);
            console.log(`    endPtr    = ${hex(this.endPtr)}`);
            console.log(`    count     = ${this.count}`);
        },
        onLeave(retval) {
            console.log(`[+] sub_143EDD3D0 ➜ return (u32) = ${retval.toUInt32()}`);
        }
    });

    // 5) Hook sub_143F84580(__int64 a1)
    Interceptor.attach(FUNCS.sub_143F84580, {
        onEnter(args) {
            this.a1 = args[0];
            console.log(`\n[+] sub_143F84580 ➜ enter`);
            console.log(`    a1 = ${hex(this.a1)}`);
        },
        onLeave(retval) {
            // retval is a char (0 or non-zero)
            console.log(`[+] sub_143F84580 ➜ return (u8) = ${retval.toUInt32()}`);
        }
    });

    // 6) Hook sub_143F8D6B0(__int64 a1)
    Interceptor.attach(FUNCS.sub_143F8D6B0, {
        onEnter(args) {
            this.a1 = args[0];
            console.log(`\n[+] sub_143F8D6B0 ➜ enter`);
            console.log(`    a1 = ${hex(this.a1)}`);
        },
        onLeave(retval) {
            console.log(`[+] sub_143F8D6B0 ➜ return (i64) = ${retval}`);
        }
    });

    console.log('[*] All hooks installed.');
})();
