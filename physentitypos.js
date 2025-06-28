// Frida hook to dump actor entity and a2 addresses
Interceptor.attach(ptr("0x14693EAF0"), {
    onEnter: function(args) {
        console.log("[+] sub_14693EAF0 called");
        console.log("    p_actor_entity: " + args[0]);
        console.log("    a2: " + args[1]);

        // Dump some memory content for context
        try {
            console.log("    a1 offset 0x1c0: " + args[0].add(0x1c0).readDouble());
            console.log("    a1 offset 0x1c8: " + args[0].add(0x1c8).readDouble());
            console.log("    a1 offset 0x1d0: " + args[0].add(0x1d0).readDouble());
        } catch (e) {
            console.log("    Error reading memory: " + e);
        }
    },
    onLeave: function(retval) {
        console.log("    Return value: " + retval);
    }
});
