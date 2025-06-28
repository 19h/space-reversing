// frida_struct_dump.js

function dumpStruct(addr) {
    if (addr.isNull()) {
        console.log("  [struct] NULL pointer");
        return;
    }
    try {
        // Read 8 QWORDs (64 bytes)
        let base = ptr(addr);
        let vtable1 = base.readPointer();
        let vtable2 = base.add(8).readPointer();
        let field2 = base.add(16).readU64();
        let field3 = base.add(24).readU64();
        let field4 = base.add(32).readU64();
        let field5 = base.add(40).readU64();
        let field6 = base.add(48).readU64();
        let field7 = base.add(56).readU64();

        console.log("  [struct] vtable1:", vtable1);
        console.log("  [struct] vtable2:", vtable2);
        console.log("  [struct] field2 :", field2);
        console.log("  [struct] field3 :", field3);
        console.log("  [struct] field4 :", field4);
        console.log("  [struct] field5 :", field5);
        console.log("  [struct] field6 :", field6);
        console.log("  [struct] field7 :", field7);
    } catch (e) {
        console.log("  [struct] Error reading struct:", e);
    }
}

function dumpArrayOfStructs(addr) {
    if (addr.isNull()) {
        console.log("  [array] NULL pointer");
        return;
    }
    try {
        let count = ptr(addr).readU64();
        console.log("  [array] count:", count);
        let base = ptr(addr).add(8);
        for (let i = 0; i < count; i++) {
            console.log(`  [array] struct[${i}]:`);
            dumpStruct(base.add(i * 64));
        }
    } catch (e) {
        console.log("  [array] Error reading array:", e);
    }
}

// Replace with actual addresses
const sub_14297CF30_addr = ptr('0x14297CF30');
const sub_142985FE0_addr = ptr('0x142985FE0');
const sub_1429853B0_addr = ptr('0x1429853B0');

// Hook sub_14297CF30
Interceptor.attach(sub_14297CF30_addr, {
    onEnter(args) {
        this.a1 = args[0];
        this.a2 = args[1];
        console.log('[sub_14297CF30] Called');
        console.log('  a1 =', this.a1);
        console.log('  a2 =', this.a2);
        // Optionally dump input struct if a2 is a pointer to struct/array
        if (!this.a2.isNull()) {
            dumpArrayOfStructs(this.a2);
        }
    },
    onLeave(retval) {
        console.log('[sub_14297CF30] Returned');
        console.log('  retval =', retval);
        // Dump returned struct/array
        if (!retval.isNull()) {
            dumpArrayOfStructs(retval);
        }
    }
});

// Hook sub_142985FE0
Interceptor.attach(sub_142985FE0_addr, {
    onEnter(args) {
        this.a1 = args[0];
        this.a2 = args[1];
        console.log('[sub_142985FE0] Called');
        console.log('  a1 =', this.a1);
        console.log('  a2 =', this.a2);
        if (!this.a2.isNull()) {
            dumpArrayOfStructs(this.a2);
        }
    },
    onLeave(retval) {
        console.log('[sub_142985FE0] Returned');
    }
});

// Hook sub_1429853B0
Interceptor.attach(sub_1429853B0_addr, {
    onEnter(args) {
        this.a1 = args[0];
        this.a2 = args[1];
        console.log('[sub_1429853B0] Called');
        console.log('  a1 =', this.a1);
        console.log('  a2 =', this.a2);
        if (!this.a2.isNull()) {
            dumpStruct(this.a2);
        }
    },
    onLeave(retval) {
        console.log('[sub_1429853B0] Returned');
        console.log('  retval =', retval);
        if (!retval.isNull()) {
            dumpStruct(retval);
        }
    }
});
