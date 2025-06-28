// Frida hook for SVI_Weapon_SetAIAccuracy
Interceptor.attach(ptr(0x1411DB5E0), {
    onEnter: function(args) {
        var a1 = args[0];
        var a2 = args[1];

        // Read BEFORE values from a1 (destination)
        var a1_double_before = Memory.readDouble(a1.add(0x10));

        // Read values from a2 (source)
        var a2_double_value = Memory.readDouble(a2.add(0x10));

        // Store for comparison in onLeave
        this.a1 = a1;
        this.a1_double_before = a1_double_before;
        this.a2 = a2;
        this.a2_double_value = a2_double_value;
    },

    onLeave: function() {
        // Read AFTER values from a1 (destination)
        var a1_double_after = Memory.readDouble(this.a1.add(0x10));

        console.log("[+] SVI_Weapon_SetAIAccuracy | a1: " + this.a1 + " | a2: " + this.a2 + " | BEFORE a1 double: " + this.a1_double_before + " | Source a2 double: " + this.a2_double_value + " | AFTER a1 double: " + a1_double_after);
    }
});
