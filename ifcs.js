/*
 * Frida script to hook and dump the parameters of the IFCS raw acceleration calculation function.
 * Target Function: sub_144048BA0
 * Game: Star Citizen
 *
 * This script will print the deltaTime and the calculated output vectors for acceleration
 * each time the function is called.
 */

// Helper function to read a Vec3 (3 consecutive floats) from a memory address.
// It formats the numbers to 4 decimal places for readability.
function readVec3(ptr) {
    if (ptr.isNull()) {
        return { x: "null_ptr", y: "null_ptr", z: "null_ptr" };
    }
    return {
        x: ptr.readFloat().toFixed(4),
        y: ptr.add(4).readFloat().toFixed(4),
        z: ptr.add(8).readFloat().toFixed(4)
    };
}

// --- Main Script Logic ---

// Find the base address of the main executable.
// You may need to change 'StarCitizen.exe' if the process has a different name.
const baseAddr = Module.findBaseAddress('StarCitizen.exe');
if (!baseAddr) {
    console.error("[!] Could not find StarCitizen.exe module. Is the process name correct? Attach with 'frida -U -f StarCitizen.exe'");
} else {
    // The Relative Virtual Address (RVA) of the target function from your dump.
    const functionRva = 0x4048BA0;
    const targetAddr = baseAddr.add(functionRva);

    console.log(`[+] Hooking IFCS calculation function at address: ${targetAddr}`);

    Interceptor.attach(targetAddr, {
        /**
         * onEnter is called when the function is entered.
         * We capture the arguments here, especially the pointers to the output buffers.
         * The actual data in the output buffers is not yet valid.
         */
        onEnter: function(args) {
            // The 'this' context is persistent between onEnter and onLeave for a single function call.
            // We store the arguments here so we can access them later in onLeave.

            // __int64 a1 (this pointer)
            this.thisPtr = args[0];

            // float a2 (deltaTime) - read its value immediately.
            this.deltaTime = args[1].toFloat();

            // float* dst_2 (out_LinearAcceleration) - store the pointer.
            this.pLinearAccel = args[2];

            // float* dst_6 (out_AngularAcceleration) - store the pointer.
            this.pAngularAccel = args[3];

            // float* dst_8 (out_LinearAccelerationUnmodified) - store the pointer.
            this.pLinearAccelUnmodified = args[4];

            // float* dst_7 (out_AngularAccelerationUnmodified) - store the pointer.
            this.pAngularAccelUnmodified = args[5];
        },

        /**
         * onLeave is called when the function is about to return.
         * Now, the output buffers pointed to by the arguments we saved in onEnter
         * have been filled with data by the function's execution.
         */
        onLeave: function(retval) {
            // Create a structured object for clean logging.
            const dump = {
                "Function": "sub_144048BA0 (CalculateRawAccelerations)",
                "this_ptr": this.thisPtr,
                "deltaTime": this.deltaTime.toFixed(6),
                "Outputs": {
                    "LinearAcceleration": readVec3(this.pLinearAccel),
                    "AngularAcceleration": readVec3(this.pAngularAccel),
                    "LinearAccelUnmodified": readVec3(this.pLinearAccelUnmodified),
                    "AngularAccelUnmodified": readVec3(this.pAngularAccelUnmodified)
                },
                "ReturnValue (double)": retval.toDouble()
            };

            // Log the captured data as a formatted JSON string.
            // This is much cleaner than multiple console.log calls.
            console.log(JSON.stringify(dump, null, 2));
        }
    });

    console.log("[+] Hook is active. Waiting for function calls...");
}
