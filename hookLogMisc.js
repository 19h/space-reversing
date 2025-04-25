// Frida hook for sub_1405BD4A0
Interceptor.attach(ptr("0x1405BD4A0"), {
  onEnter: function (args) {
    console.log("------------ sub_1405BD4A0 called ------------");
    console.log("a1 (arg0): " + args[0]);
    console.log("a2 (arg1): " + args[1]);
    console.log("a3 (arg2): " + Memory.readUtf8String(args[2]));

    // Log variadic arguments
    console.log("Variadic args (not showing all):");
    try {
      if (args[3]) console.log("arg3: " + args[3]);
      if (args[4]) console.log("arg4: " + args[4]);
      if (args[5]) console.log("arg5: " + args[5]);
    } catch (e) {
      console.log("Error accessing variadic args: " + e);
    }

    // Log global variables
    console.log(
      "qword_14981D3D8: " +
        Module.findExportByName(null, "qword_14981D3D8") +
        " = " +
        Memory.readPointer(ptr("0x14981D3D8")),
    );
    console.log(
      "qword_14981D2C0: " +
        Module.findExportByName(null, "qword_14981D2C0") +
        " = " +
        Memory.readPointer(ptr("0x14981D2C0")),
    );

    // Calculate and log function pointer
    var qword_ptr = Memory.readPointer(ptr("0x14981D2C0"));
    if (qword_ptr !== 0) {
      var func_ptr = Memory.readPointer(qword_ptr.add(344));
      console.log(
        "Function ptr (*(_QWORD *)qword_14981D2C0 + 344LL): " + func_ptr,
      );
    } else {
      console.log("qword_14981D2C0 is null, can't calculate function pointer");
    }

    this.a1 = args[0];
    this.a2 = args[1];
    this.a3 = args[2];
  },

  onLeave: function (retval) {
    console.log("sub_1405BD4A0 returned: " + retval);
    console.log("-------------------------------------------");
    return retval;
  },
});
