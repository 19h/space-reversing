// Frida hook for sub_14030EFD0
Interceptor.attach(ptr("0x14030EFD0"), {
    onEnter: function(args) {
        console.log("[+] sub_14030EFD0 called");
        console.log("    this: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("    Return value: " + retval);
        console.log("[-] sub_14030EFD0 finished");
    }
});

// Frida hook for sub_1416EDA90
Interceptor.attach(ptr("0x1416EDA90"), {
    onEnter: function(args) {
        console.log("[+] sub_1416EDA90 called");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("    Return value (MissionReward*): " + retval);
        console.log("[-] sub_1416EDA90 finished");
    }
});

// Frida hook for sub_140846EE0
Interceptor.attach(ptr("0x140846EE0"), {
    onEnter: function(args) {
        console.log("[+] sub_140846EE0 called");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("    Return value: " + retval);
        console.log("[-] sub_140846EE0 finished");
    }
});

// Frida hook for sub_140846EC0
Interceptor.attach(ptr("0x140846EC0"), {
    onEnter: function(args) {
        console.log("[+] sub_140846EC0 called");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("    Return value: " + retval);
        console.log("[-] sub_140846EC0 finished");
    }
});
