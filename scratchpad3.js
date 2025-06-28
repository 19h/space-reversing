Interceptor.attach(ptr(0x143D69F00), {
    onEnter: function(args) {
        console.log("[sub_143D69F00] Called");
        console.log("  a1: " + args[0]);
        console.log("  __n: " + args[1]);
        console.log("Backtrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log("[sub_143D69F00] Return value: " + retval);
    }
});
