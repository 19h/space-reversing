/*
 * Frida script to hook sub_147000270 and dump zone information
 * For Windows x64 platforms
 */

'use strict';

// Simplified logging function that works across all Frida versions
function writeToLog(message) {
    // Log to console
    console.log(message);
    
    // Optionally log to file (using a hard-coded path)
    try {
        // C:\frida_hook_log.txt on Windows
        const logPath = "C:\\frida_hook_log.txt";
        
        const file = new File(logPath, 'a');
        file.write(message + '\n');
        file.flush();
        file.close();
    } catch (e) {
        // If file writing fails, just continue with console logging
        console.log("[Error writing to log file: " + e + "]");
    }
}

// Format distance as meters or kilometers
function formatDistance(dist) {
    const ad = Math.abs(dist);
    if (ad < 10000.0)
        return dist.toFixed(2) + 'm';
    else
        return (dist / 1000.0).toFixed(4) + 'km';
}

// Main hook setup
function main() {
    writeToLog('[+] Frida script loaded');
    
    // Target base addresses - you need to specify your own module name
    // IMPORTANT: Replace 'YourGameModule.exe' with your actual game executable name
    const moduleName = 'StarCitizen.exe'; // CHANGE THIS!
    
    const baseAddr = Process.findModuleByName(moduleName).base;
    if (!baseAddr) {
        console.log('Failed to find base address of the module: ' + moduleName);
        console.log('Please make sure you replace YourGameModule.exe with your actual game executable name.');
        return;
    }
    
    writeToLog('[+] Base address of ' + moduleName + ': ' + baseAddr);
    
    // Function addresses - these are relative to the original base 0x140000000
    // Adjust these values to match your executable
    const sub147000270Offset = 0x7000270; // This is the offset from the base (0x147000270 - 0x140000000)
    const zoneMgrPtrOffset = 0x97EA428;   // This is the offset from the base (0x1497EA428 - 0x140000000)
    
    const sub147000270Addr = baseAddr.add(sub147000270Offset);
    const zoneMgrPtrAddr = baseAddr.add(zoneMgrPtrOffset);
    
    writeToLog('[+] sub_147000270 address: ' + sub147000270Addr);
    writeToLog('[+] zoneMgrPtr address: ' + zoneMgrPtrAddr);
    
    // Constants
    const PI = 3.1415926535;
    
    // Hook the main function
    Interceptor.attach(sub147000270Addr, {
        onEnter: function(args) {
            // Store arguments for use in onLeave
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2].toInt32();
            
            writeToLog('[+] sub_147000270 called with a3=' + this.a3);
        },
        
        onLeave: function(retval) {
            // Skip if debug flag is 0
            if (this.a3 === 0) {
                return;
            }
            
            try {
                // Camera angle calculations
                const camBase = this.a1.add(1232);
                const dVal40 = camBase.add(0x40).readDouble();
                const dVal08 = camBase.add(0x08).readDouble();
                const dVal48 = camBase.add(0x48).readDouble();
                const dVal50 = camBase.add(0x50).readDouble();
                const dVal00 = camBase.add(0x00).readDouble();
                const dVal20 = camBase.add(0x20).readDouble();
                
                const fVal40 = dVal40;
                let arcInput = -fVal40;
                if (arcInput > 1.0) arcInput = 1.0;
                if (arcInput < -1.0) arcInput = -1.0;
                let angleAsin = Math.asin(arcInput);
                
                const tmp = Math.abs(angleAsin);
                const tmpDiff = Math.abs(tmp - 1.5707964); // pi/2
                const nearPiOver2 = (tmpDiff < 0.01); // true or false
                
                let angleB = 0.0;
                let fSecondY;
                if (nearPiOver2) {
                    angleAsin = 0.0;
                    const fVal08 = dVal08;
                    fSecondY = -fVal08;
                } else {
                    const fVal48 = dVal48;
                    const fVal50 = dVal50;
                    angleB = Math.atan2(fVal48, fVal50);
                    fSecondY = dVal20;
                }
                
                const angleAsinDeg = angleAsin * (180.0 / PI);
                const angleBDeg = angleB * (180.0 / PI);
                
                const fVal00 = dVal00;
                const angleC = Math.atan2(fSecondY, fVal00);
                const angleCDeg = angleC * (180.0 / PI);
                
                // Zone iteration
                const zoneID = camBase.add(168).readInt();
                writeToLog('[+] Zone ID: ' + zoneID);
                
                if (zoneID === -1) {
                    return;
                }
                
                // Get zone manager pointer
                const zoneMgrPtrValue = zoneMgrPtrAddr.readPointer();
                if (zoneMgrPtrValue.isNull()) {
                    writeToLog('[-] Zone manager pointer is NULL');
                    return;
                }
                
                const zoneMgrObj = zoneMgrPtrValue.readPointer();
                if (zoneMgrObj.isNull()) {
                    writeToLog('[-] Zone manager object is NULL');
                    return;
                }
                
                // Get first zone function (offset 104 in vtable)
                const zoneMgrVtable = zoneMgrObj.readPointer();
                const getFirstZoneFnPtr = zoneMgrVtable.add(104).readPointer();
                
                // Call getFirstZone function
                // Use 'uint64' for 64-bit pointers in Windows x64
                const getFirstZone = new NativeFunction(getFirstZoneFnPtr, 'uint64', ['uint64']);
                let zoneAddr = ptr(getFirstZone(zoneMgrObj.toString()));
                
                writeToLog('[+] First zone at: ' + zoneAddr);
                
                if (zoneAddr.isNull()) {
                    writeToLog('[-] No zones found');
                    return;
                }
                
                const firstZoneAddr = zoneAddr;
                
                // Create buffers for position data
                const pos1 = Memory.alloc(24); // 3 * 8 bytes for doubles
                const pos2 = Memory.alloc(24); // 3 * 8 bytes for doubles
                
                // Begin zone iteration
                do {
                    // Clear memory blocks
                    Memory.writeByteArray(pos1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    Memory.writeByteArray(pos2, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    
                    // Get zone vtable
                    const zoneVtable = zoneAddr.readPointer();
                    
                    // Call GetPositions function (offset 248 in vtable)
                    const getPositionsFnPtr = zoneVtable.add(248).readPointer();
                    const getPositions = new NativeFunction(getPositionsFnPtr, 'void', ['uint64', 'pointer', 'pointer']);
                    
                    getPositions(zoneAddr.toString(), pos2, pos1);
                    
                    // Read position values
                    const valX = pos2.readDouble();
                    const valY = pos2.add(8).readDouble();
                    const valZ = pos2.add(16).readDouble();
                    
                    // Format positions
                    const posXStr = formatDistance(valX);
                    const posYStr = formatDistance(valY);
                    const posZStr = formatDistance(valZ);
                    
                    // Extra logging for first zone if a3 >= 2
                    if (this.a3 >= 2 && zoneAddr.equals(firstZoneAddr)) {
                        writeToLog('[+] First zone with additional debug (a3=' + this.a3 + ')');
                        // Additional first-zone specific logging could go here
                    }
                    
                    // Get zone name (offset 496 in vtable)
                    let zoneName = "Unknown";
                    const getNameFnPtr = zoneVtable.add(496).readPointer();
                    
                    if (!getNameFnPtr.isNull()) {
                        const getName = new NativeFunction(getNameFnPtr, 'uint64', ['uint64']);
                        const namePtr = ptr(getName(zoneAddr.toString()));
                        
                        if (!namePtr.isNull()) {
                            try {
                                zoneName = namePtr.readUtf8String();
                            } catch (e) {
                                zoneName = "Error reading name: " + e.message;
                            }
                        }
                    }
                    
                    // Log zone information
                    writeToLog('[+] Zone Details:');
                    writeToLog('    Zone: ' + zoneName);
                    writeToLog('    Pos: ' + posXStr + ' ' + posYStr + ' ' + posZStr + '\n');
                    
                    // Get next zone (offset 8 in vtable)
                    const getNextFnPtr = zoneVtable.add(8).readPointer();
                    
                    if (getNextFnPtr.isNull()) {
                        writeToLog('[-] No GetNext function found');
                        break;
                    }
                    
                    const getNext = new NativeFunction(getNextFnPtr, 'uint64', ['uint64']);
                    zoneAddr = ptr(getNext(zoneAddr.toString()));
                    
                    writeToLog('[+] Next zone at: ' + zoneAddr);
                    
                } while (!zoneAddr.isNull());
                
            } catch (e) {
                writeToLog('[-] Error: ' + e.message + '\n' + e.stack);
            }
        }
    });
    
    console.log('[+] Hooks installed');
}

// Execute the main function
main();