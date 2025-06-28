Interceptor.attach(ptr(0x140850F90), {
    onEnter: function(args) {
        console.log("[0x140850F90] CDamageMap::MT_CalculateWeaponDamage called");
        console.log("  a1 (int): " + args[0]);
        console.log("  a2 (__int64): " + args[1]);
        console.log("  n2 (char): " + args[2]);
        console.log("  a4 (double): " + args[3]);
        console.log("  a5 (float): " + args[4]);
        console.log("  a6 (float): " + args[5]);
        console.log("  a7 (float): " + args[6]);
        console.log("  a8 (int): " + args[7]);
        console.log("Backtrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("[0x140850F90] Return value: " + retval);
    }
});

Interceptor.attach(ptr(0x140854340), {
    onEnter: function(args) {
        console.log("[0x140854340] CDamageMap::MT_ExpandImpactToMinimumRadius called");
        console.log("  a1 (__int64): " + args[0]);
        console.log("  a2 (__int64): " + args[1]);
        console.log("  a3 (__m256*): " + args[2]);
        console.log("  a4 (float): " + args[3]);
        console.log("  a5 (unsigned int): " + args[4]);

        // Try to read some damage-related data from a2
        try {
            console.log("  Damage data at a2:");
            console.log("    +0x04: " + args[1].add(0x04).readFloat());
            console.log("    +0x08: " + args[1].add(0x08).readFloat());
            console.log("    +0x0C: " + args[1].add(0x0C).readFloat());
            console.log("    +0x10: " + args[1].add(0x10).readFloat());
        } catch (e) {
            console.log("  Could not read damage data: " + e.message);
        }

        console.log("Backtrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("[0x140854340] Return value: " + retval);

        // Try to read final damage values
        try {
            console.log("  Final damage values:");
            console.log("    +0x04: " + retval.add(0x04).readFloat());
            console.log("    +0x08: " + retval.add(0x08).readFloat());
            console.log("    +0x0C: " + retval.add(0x0C).readFloat());
            console.log("    +0x10: " + retval.add(0x10).readFloat());
        } catch (e) {
            console.log("  Could not read final damage values: " + e.message);
        }
    }
});
