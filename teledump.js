var moduleBase = Module.findBaseAddress("StarCitizen.exe"); // Replace with actual executable name
var targetAddress = moduleBase.add(0x61C4930); // Replace with actual EA address

Interceptor.attach(targetAddress, {
    onEnter: function(args) {
        console.log("[setactorentitypos_sub_1461C4930] Called");
        console.log("  a1 (entity ptr): " + args[0]);
        console.log("  a2 (output coords ptr): " + args[1]);
        console.log("  a3 (flag): " + args[2]);

        this.outputPtr = args[1];
        this.a1 = args[0];
        this.a3 = args[2];
    },

    onLeave: function(retval) {
        if (this.outputPtr && !this.outputPtr.isNull()) {
            var x = this.outputPtr.readFloat();
            var y = this.outputPtr.add(4).readFloat();
            var z = this.outputPtr.add(8).readFloat();
            var w = this.outputPtr.add(12).readFloat();

            console.log("[setactorentitypos_sub_1461C4930] Output coordinates:");
            console.log("  X: " + x.toFixed(6));
            console.log("  Y: " + y.toFixed(6));
            console.log("  Z: " + z.toFixed(6));
            console.log("  W: " + w.toFixed(6));
            console.log("  Entity ptr: " + this.a1);
            console.log("  Flag: " + this.a3);
            console.log("  Return value: " + retval);
        }
    }
});
