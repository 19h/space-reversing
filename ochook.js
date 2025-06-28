// Hook to capture the function address at offset 0xE0
let targetFunctionAddress = null;

// Hook the main function
const mainFunctionAddress = ptr(0x1474C0DB0);
if (mainFunctionAddress) {
    Interceptor.attach(mainFunctionAddress, {
        onEnter: function(args) {
            // args[1] is a2 (which becomes v55)
            const a2 = args[1];
            console.log(a2);
            if (a2) {
                // Read the pointer stored at a2 (this is *v55)
                const v55_deref = ptr(a2).readPointer();
                if (v55_deref) {
                    // Read the vtable pointer
                    const vtable = ptr(v55_deref).readPointer();
                    if (vtable) {
                        // Calculate the address of the function at offset 0xE0
                        targetFunctionAddress = ptr(vtable).add(0xE0).readPointer();
                        console.log("[*] Found target function address: " + targetFunctionAddress);

                        // Hook the target function if we found it
                        if (targetFunctionAddress && !targetFunctionAddress.isNull()) {
                            try {
                                Interceptor.attach(targetFunctionAddress, {
                                    onEnter: function(args) {
                                        console.log("[*] Target function called!");
                                        console.log("    arg0: " + args[0]);
                                        console.log("    arg1 (string): " + args[1].readCString());
                                        console.log("    arg2: " + args[2]);
                                    },
                                    onLeave: function(retval) {
                                        console.log("[*] Target function returned: " + retval);
                                    }
                                });
                                console.log("[*] Successfully hooked target function at " + targetFunctionAddress);
                            } catch (e) {
                                console.log("[!] Failed to hook target function: " + e.message);
                            }
                        }
                    }
                }
            }
        }
    });
} else {
    console.log("[!] Could not find main function");
}
