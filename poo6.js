'use strict';

function log(message) {
    console.log(message);
}

function formatDistance(dist) {
    const ad = Math.abs(dist);
    if (ad < 10000.0)
        return dist.toFixed(2) + 'm';
    else
        return (dist / 1000.0).toFixed(4) + 'km';
}

function main() {
    log('[+] Frida script loaded');
    
    // IMPORTANT: Replace with your actual module name
    const baseAddr = Process.findModuleByName('StarCitizen.exe').base;
    
    // Function addresses
    const sub147000270Offset = 0x7000270; // 0x147000270 - 0x140000000
    const zoneMgrPtrOffset = 0x97EA428;   // 0x1497EA428 - 0x140000000
    
    const sub147000270Addr = baseAddr.add(sub147000270Offset);
    const zoneMgrPtrAddr = baseAddr.add(zoneMgrPtrOffset);
    
    log('[+] sub_147000270 address: ' + sub147000270Addr);
    log('[+] zoneMgrPtr address: ' + zoneMgrPtrAddr);
    
    // Create buffers for position data
    const posBuffer1 = Memory.alloc(24); // 3 doubles (8 bytes each)
    const posBuffer2 = Memory.alloc(24); // 3 doubles (8 bytes each)
    
    // Hook the target function
    Interceptor.attach(sub147000270Addr, {
        onEnter: function(args) {
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2].toInt32();
        },
        
        onLeave: function(retval) {
            if (this.a3 === 0) {
                return;
            }
            
            try {
                // Camera base calculation
                const camBase = this.a1.add(1232);
                
                // Get zone ID
                const zoneID = camBase.add(168).readInt();
                log('[+] Zone ID: ' + zoneID);
                
                if (zoneID === -1) {
                    return;
                }
                
                // CORRECTED APPROACH: Looking at the decompiled code
                
                // Step 1: Get zoneMgrPtr and zoneMgrObj
                const zoneMgrPtr = zoneMgrPtrAddr.readPointer();
                log('[+] Zone manager pointer: ' + zoneMgrPtr);
                
                // Step 2: Get thiscall function from GetZone (sub_146E2DDF0)
                // The function signature is:
                // __int64 __fastcall sub_146E2DDF0(__int64 a1, __int64 a2)
                // In the original code, the zoneID (a2) is passed from v46
                
                try {
                    // Get the function using inline assembly style approach
                    const funcPtr = zoneMgrPtr.readPointer().add(104).readPointer();
                    log('[+] GetZone function: ' + funcPtr);
                    
                    // Create our wrapper function that correctly passes both this and zoneID
                    const getZoneFunc = new NativeFunction(funcPtr, 'pointer', ['pointer', 'int32']);
                    
                    // Call with both zoneMgrPtr (this) and zoneID
                    const zonePtr = getZoneFunc(zoneMgrPtr, zoneID);
                    log('[+] First zone pointer: ' + zonePtr);
                    
                    if (zonePtr.isNull()) {
                        log('[-] No zones found');
                        return;
                    }
                    
                    // Now iterate through the zones
                    let currentZone = zonePtr;
                    let zoneCount = 0;
                    
                    while (!currentZone.isNull() && zoneCount < 100) {
                        zoneCount++;
                        log('[+] Processing zone #' + zoneCount);
                        
                        try {
                            // Get the zone's vtable
                            const zoneVtable = currentZone.readPointer();
                            
                            // Get positions - at offset 248 in vtable
                            const getPosFunc = new NativeFunction(
                                zoneVtable.add(248).readPointer(),
                                'void',
                                ['pointer', 'pointer', 'pointer']
                            );
                            
                            try {
                                // Clear buffers
                                Memory.writeByteArray(posBuffer1, new Array(24).fill(0));
                                Memory.writeByteArray(posBuffer2, new Array(24).fill(0));
                                
                                // Get positions
                                getPosFunc(currentZone, posBuffer2, posBuffer1);
                                
                                // Read positions
                                const posX = posBuffer2.readDouble();
                                const posY = posBuffer2.add(8).readDouble();
                                const posZ = posBuffer2.add(16).readDouble();
                                
                                // Format positions
                                const formattedX = formatDistance(posX);
                                const formattedY = formatDistance(posY);
                                const formattedZ = formatDistance(posZ);
                                
                                log('[+] Position: ' + formattedX + ' ' + formattedY + ' ' + formattedZ);
                            } catch (e) {
                                log('[-] Error getting positions: ' + e.message);
                            }
                            
                            // Get zone name - at offset 496 in vtable
                            let zoneName = "Unknown";
                            const getNameFunc = new NativeFunction(
                                zoneVtable.add(496).readPointer(),
                                'pointer',
                                ['pointer']
                            );
                            
                            try {
                                const namePtr = getNameFunc(currentZone);
                                if (!namePtr.isNull()) {
                                    zoneName = namePtr.readUtf8String();
                                }
                            } catch (e) {
                                log('[-] Error getting zone name: ' + e.message);
                            }
                            
                            log('[+] Zone name: ' + zoneName);
                            
                            // Get next zone - at offset 8 in vtable
                            const getNextFunc = new NativeFunction(
                                zoneVtable.add(8).readPointer(),
                                'pointer',
                                ['pointer']
                            );
                            
                            try {
                                const nextZone = getNextFunc(currentZone);
                                log('[+] Next zone: ' + nextZone);
                                
                                // Break if we've reached the end
                                if (nextZone.isNull()) {
                                    log('[+] End of zone list');
                                    break;
                                }
                                
                                currentZone = nextZone;
                            } catch (e) {
                                log('[-] Error getting next zone: ' + e.message);
                                break;
                            }
                            
                        } catch (e) {
                            log('[-] Error processing zone: ' + e.message);
                            break;
                        }
                    }
                    
                    log('[+] Zone enumeration complete - processed ' + zoneCount + ' zones');
                    
                } catch (e) {
                    log('[-] Error in zone processing: ' + e.message);
                }
                
            } catch (e) {
                log('[-] Error in onLeave: ' + e.message);
                log(e.stack);
            }
        }
    });
    
    log('[+] Hook installed');
}

main();