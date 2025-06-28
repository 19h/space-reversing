// Frida hooks for decompiled code analysis

// Hook sub_1400BF6E0 - Initialization function
Interceptor.attach(ptr("0x1400BF6E0"), {
    onEnter: function(args) {
        console.log("[+] sub_1400BF6E0 called - Initialization function");
    },
    onLeave: function(retval) {
        console.log("[+] sub_1400BF6E0 returned: " + retval);
    }
});

// Hook sub_14136BC80 - Destructor-like function
Interceptor.attach(ptr("0x14136BC80"), {
    onEnter: function(args) {
        console.log("[+] sub_14136BC80 called - Destructor function");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_14136BC80 returned: " + retval);
    }
});

// Hook sub_141375500 - Returns constant 0x130
Interceptor.attach(ptr("0x141375500"), {
    onEnter: function(args) {
        console.log("[+] sub_141375500 called - Returns size constant 0x130");
    },
    onLeave: function(retval) {
        console.log("[+] sub_141375500 returned: " + retval + " (0x" + retval.toString(16) + ")");
    }
});

// Hook sub_141375520 - Memory copy operation
//Interceptor.attach(ptr("0x141375520"), {
//    onEnter: function(args) {
//        console.log("[+] sub_141375520 called - Memory copy operation");
//        console.log("    Source: " + args[0]);
//        console.log("    Dest: " + args[1]);
//        try {
//            var data = Memory.readByteArray(args[0].add(0x18), 16);
//
//            //console.log("    Data being copied: " + hexdump(data, {length: 16}));
//
//            for (let i = 0; i < 32; ++i) {
//                try {
//                    console.log(i, args[0].add(0x18).add(i).readPointer() + ' -> ' + args[0].add(0x18).add(i).readPointer().readPointer());
//                } catch(e) {
//                }
//            }
//        } catch(e) {
//            console.log("    Could not read source data: " + e.message);
//        }
//    }
//});

// Hook sub_141377710 - Boolean check function
Interceptor.attach(ptr("0x141377710"), {
    onEnter: function(args) {
        console.log("[+] sub_141377710 called - Boolean check");
        console.log("    a1: " + args[0]);
        try {
            var value = Memory.readU32(args[0].add(0x98));
            console.log("    Value at offset 0x98: " + value);
        } catch(e) {
            console.log("    Could not read memory at offset 0x98");
        }
    },
    onLeave: function(retval) {
        console.log("[+] sub_141377710 returned: " + retval);
    }
});

// Hook sub_1413AF0B0 - TaskCreator AllocateRuntimeData
Interceptor.attach(ptr("0x1413AF0B0"), {
    onEnter: function(args) {
        console.log("[+] sub_1413AF0B0 called - TaskCreator AllocateRuntimeData");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    a3: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413AF0B0 allocated runtime data at: " + retval);
    }
});

// Hook sub_1413B1780 - Task allocation function
Interceptor.attach(ptr("0x1413B1780"), {
    onEnter: function(args) {
        console.log("[+] sub_1413B1780 called - Task allocation");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        try {
            var taskName = Memory.readCString(Memory.readPointer(args[0].add(8)));
            console.log("    Task name: " + taskName);
        } catch(e) {
            console.log("    Could not read task name");
        }
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413B1780 task allocated successfully");
    }
});

// Hook sub_1413B3AC0 - TaskCreator FreeRuntimeData
Interceptor.attach(ptr("0x1413B3AC0"), {
    onEnter: function(args) {
        console.log("[+] sub_1413B3AC0 called - TaskCreator FreeRuntimeData");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    a3: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413B3AC0 freed runtime data");
    }
});

// Hook sub_1413B67B0 - TaskCreator GetRuntimeData
Interceptor.attach(ptr("0x1413B67B0"), {
    onEnter: function(args) {
        console.log("[+] sub_1413B67B0 called - TaskCreator GetRuntimeData");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
        console.log("    a3: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413B67B0 returned runtime data: " + retval);
    }
});

// Hook sub_1413B8360 - Reward handling function
Interceptor.attach(ptr("0x1413B8360"), {
    onEnter: function(args) {
        console.log("[+] sub_1413B8360 called - Reward handling");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413B8360 reward processed: " + retval);
    }
});

// Hook sub_1413BA930 - SetMissionReward registration
Interceptor.attach(ptr("0x1413BA930"), {
    onEnter: function(args) {
        console.log("[+] sub_1413BA930 called - SetMissionReward registration");
        console.log("    a1: " + args[0]);
        console.log("    a2: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[+] sub_1413BA930 SetMissionReward registered: " + retval);
    }
});

console.log("[*] Frida hooks installed for decompiled code analysis");
