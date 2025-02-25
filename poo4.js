// Frida script for camera direction calculations on Windows x64
// Usage: frida -l camdir.js -n "target_process.exe" --no-pause

// Configuration - modify these values to match your target application
const FUNCTION_OFFSET = "0x7000270";      // Offset within module (from 0x147000270)
const ABSOLUTE_ADDR = "0x147000270";  // Absolute address as fallback

// Helper function to convert radians to degrees
function radToDeg(rad) {
    return rad * (180.0 / Math.PI);
}

// Main function to hook the camera calculation function
function hookCameraFunction(functionOffset) {
    try {
        // Find the module
        const targetModule = Process.enumerateModulesSync().shift();
        console.log(`Found module: ${targetModule.name} at ${targetModule.base}`);
        
        // Calculate function address
        const targetAddr = targetModule.base.add(ptr(functionOffset));
        console.log(`Target function address: ${targetAddr}`);
        
        // Create a NativeFunction for the original function
        const origFunction = new NativeFunction(targetAddr, 'void', ['pointer', 'pointer', 'int']);
        
        // Replace the original function with our implementation
        Interceptor.replace(targetAddr, new NativeCallback(function(a1, a2, a3) {
            // Call the original function first
            origFunction(a1, a2, a3);
            
            // Skip if debug flag is 0
            if (a3 == 0) {
                return;
            }
            
            try {
                // Camera angle calculations
                const camBase = a1.add(1232);
                
                // Read double values from memory
                const dVal40 = camBase.add(0x40).readDouble();
                const dVal08 = camBase.add(0x08).readDouble();
                const dVal48 = camBase.add(0x48).readDouble();
                const dVal50 = camBase.add(0x50).readDouble();
                const dVal00 = camBase.add(0x00).readDouble();
                const dVal20 = camBase.add(0x20).readDouble();
                
                // Camera angle calculations as per the provided code
                let fVal40 = parseFloat(dVal40);
                let arcInput = -fVal40;
                if (arcInput > 1.0) arcInput = 1.0;
                if (arcInput < -1.0) arcInput = -1.0;
                let angleAsin = Math.asin(arcInput);
                
                let tmp = Math.abs(angleAsin);
                tmp = Math.abs(tmp - 1.5707964); // π/2
                let nearPiOver2 = (tmp < 0.01) ? 1 : 0;
                
                let angleB = 0.0;
                let fSecondY;
                if (nearPiOver2) {
                    angleAsin = 0.0;
                    let fVal08 = parseFloat(dVal08);
                    fSecondY = -fVal08;
                } else {
                    let fVal48 = parseFloat(dVal48);
                    let fVal50 = parseFloat(dVal50);
                    angleB = Math.atan2(fVal48, fVal50);
                    fSecondY = parseFloat(dVal20);
                }
                
                let angleAsinDeg = angleAsin * (180.0 / 3.1415926535);
                let angleBDeg = angleB * (180.0 / 3.1415926535);
                
                let fVal00 = parseFloat(dVal00);
                let angleC = Math.atan2(fSecondY, fVal00);
                let angleCDeg = angleC * (180.0 / 3.1415926535);
                
                // Log the calculated values
                console.log("Camera Angles (degrees):");
                console.log(`Pitch: ${angleAsinDeg.toFixed(2)}, Yaw: ${angleBDeg.toFixed(2)}, Roll: ${angleCDeg.toFixed(2)}`);
            } catch (e) {
                console.error(`Error in camera calculations: ${e.message}`);
            }
            
        }, 'void', ['pointer', 'pointer', 'int']));
        
        console.log("Successfully hooked camera function.");
        return true;
    } catch (e) {
        console.error(`Error setting up hook: ${e.message}`);
        return false;
    }
}

// Alternative approach using direct address
function hookCameraFunctionByAddress(addressStr) {
    try {
        const targetAddr = ptr(addressStr);
        console.log(`Target function address: ${targetAddr}`);
        
        // Create a NativeFunction for the original function
        const origFunction = new NativeFunction(targetAddr, 'void', ['pointer', 'pointer', 'int']);
        
        // Replace the function
        Interceptor.replace(targetAddr, new NativeCallback(function(a1, a2, a3) {
            // Call the original function
            origFunction(a1, a2, a3);
            
            // Skip if debug flag is 0
            if (a3 == 0) {
                return;
            }
            
            try {
                // Camera angle calculations
                const camBase = a1.add(1232);
                
                // Read double values from memory
                const dVal40 = camBase.add(0x40).readDouble();
                const dVal08 = camBase.add(0x08).readDouble();
                const dVal48 = camBase.add(0x48).readDouble();
                const dVal50 = camBase.add(0x50).readDouble();
                const dVal00 = camBase.add(0x00).readDouble();
                const dVal20 = camBase.add(0x20).readDouble();
                
                // Camera angle calculations
                let fVal40 = parseFloat(dVal40);
                let arcInput = -fVal40;
                if (arcInput > 1.0) arcInput = 1.0;
                if (arcInput < -1.0) arcInput = -1.0;
                let angleAsin = Math.asin(arcInput);
                
                let tmp = Math.abs(angleAsin);
                tmp = Math.abs(tmp - 1.5707964); // π/2
                let nearPiOver2 = (tmp < 0.01) ? 1 : 0;
                
                let angleB = 0.0;
                let fSecondY;
                if (nearPiOver2) {
                    angleAsin = 0.0;
                    let fVal08 = parseFloat(dVal08);
                    fSecondY = -fVal08;
                } else {
                    let fVal48 = parseFloat(dVal48);
                    let fVal50 = parseFloat(dVal50);
                    angleB = Math.atan2(fVal48, fVal50);
                    fSecondY = parseFloat(dVal20);
                }
                
                let angleAsinDeg = angleAsin * (180.0 / 3.1415926535);
                let angleBDeg = angleB * (180.0 / 3.1415926535);
                
                let fVal00 = parseFloat(dVal00);
                let angleC = Math.atan2(fSecondY, fVal00);
                let angleCDeg = angleC * (180.0 / 3.1415926535);
                
                // Log the calculated values
                console.log("Camera Angles (degrees):");
                console.log(`Pitch: ${angleAsinDeg.toFixed(2)}, Yaw: ${angleBDeg.toFixed(2)}, Roll: ${angleCDeg.toFixed(2)}`);
            } catch (e) {
                console.error(`Error in camera calculations: ${e.message}`);
            }
            
        }, 'void', ['pointer', 'pointer', 'int']));
        
        console.log("Successfully hooked camera function by address.");
        return true;
    } catch (e) {
        console.error(`Error setting up hook by address: ${e.message}`);
        return false;
    }
}

// Main function to start the script
function main() {
    console.log("Starting camera direction hook script...");
    
    // First try hooking by module+offset
    let success = hookCameraFunction(FUNCTION_OFFSET);

    if (success) {
        console.log("Camera direction hook installed successfully.");
    } else {
        console.error("Failed to install camera direction hook. Check module name and function offset.");
    }
}

// Start script with a slight delay to ensure process is fully loaded
setTimeout(main, 1000);
