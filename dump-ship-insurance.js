/*
 * ShipInsuranceParams Interceptor Script
 * 
 * Purpose: Intercept all functions mutating the ShipInsuranceParams structure and dump memory contents
 * Target functions:
 *   - sub_140190B40 (0x140190B40): Main initialization setting insurance values (666.0, 0.0, 0xA2C2A)
 *   - sub_14259AAD0 (0x14259AAD0): Initializes structure with hash and zeros fields
 *   - sub_1425638B0 (0x1425638B0): Sets up function pointers and string fields
 *   - sub_1403B1000 (0x1403B1000): Simple initializer
 */

// Configuration
const DUMP_SIZE = 128;            // Number of bytes to dump from structure
const LOG_ARGS = true;            // Enable argument logging
const LOG_REGISTERS = true;       // Enable register state logging
const CONFIG = {
    moduleNames: ["Game.exe"],    // Target module name(s) - modify based on your target
    baseAddr: ptr("0x0"),         // Will be set dynamically on module load
    shipInsuranceGlobalAddr: null // Will be discovered during runtime
};

// Utility functions for memory inspection
function hexdumpAddress(address, size, message) {
    if (!address || address.isNull()) {
        console.log(`[!] Cannot dump NULL address (${message})`);
        return;
    }
    try {
        const bytes = address.readByteArray(size);
        console.log(`${message}:\n${hexdump(bytes, { header: true, ansi: true })}`);
    } catch (e) {
        console.log(`[!] Error dumping memory at ${address}: ${e.message}`);
    }
}

function formatContext(context) {
    // Format CPU context for x64 architecture
    const regs = [];
    
    if (Process.arch === 'ia32') {
        // 32-bit registers
        regs.push(`EAX: ${context.eax.toString(16).padStart(8, '0')}`);
        regs.push(`EBX: ${context.ebx.toString(16).padStart(8, '0')}`);
        regs.push(`ECX: ${context.ecx.toString(16).padStart(8, '0')}`);
        regs.push(`EDX: ${context.edx.toString(16).padStart(8, '0')}`);
        regs.push(`ESI: ${context.esi.toString(16).padStart(8, '0')}`);
        regs.push(`EDI: ${context.edi.toString(16).padStart(8, '0')}`);
        regs.push(`EBP: ${context.ebp.toString(16).padStart(8, '0')}`);
        regs.push(`ESP: ${context.esp.toString(16).padStart(8, '0')}`);
        regs.push(`EIP: ${context.eip.toString(16).padStart(8, '0')}`);
    } else {
        // 64-bit registers
        regs.push(`RAX: ${context.rax.toString(16).padStart(16, '0')}`);
        regs.push(`RBX: ${context.rbx.toString(16).padStart(16, '0')}`);
        regs.push(`RCX: ${context.rcx.toString(16).padStart(16, '0')}`);
        regs.push(`RDX: ${context.rdx.toString(16).padStart(16, '0')}`);
        regs.push(`RSI: ${context.rsi.toString(16).padStart(16, '0')}`);
        regs.push(`RDI: ${context.rdi.toString(16).padStart(16, '0')}`);
        regs.push(`RBP: ${context.rbp.toString(16).padStart(16, '0')}`);
        regs.push(`RSP: ${context.rsp.toString(16).padStart(16, '0')}`);
        regs.push(`RIP: ${context.rip.toString(16).padStart(16, '0')}`);
        regs.push(`R8:  ${context.r8.toString(16).padStart(16, '0')}`);
        regs.push(`R9:  ${context.r9.toString(16).padStart(16, '0')}`);
        regs.push(`R10: ${context.r10.toString(16).padStart(16, '0')}`);
        regs.push(`R11: ${context.r11.toString(16).padStart(16, '0')}`);
        regs.push(`R12: ${context.r12.toString(16).padStart(16, '0')}`);
        regs.push(`R13: ${context.r13.toString(16).padStart(16, '0')}`);
        regs.push(`R14: ${context.r14.toString(16).padStart(16, '0')}`);
        regs.push(`R15: ${context.r15.toString(16).padStart(16, '0')}`);
    }
    
    return regs.join('\n');
}

function inspectFloatValues(address) {
    // Try to interpret memory regions as different data types
    try {
        const values = {
            floatAt0: address.readFloat(),
            floatAt4: address.add(4).readFloat(),
            floatAt8: address.add(8).readFloat(),
            doubleAt0: address.readDouble(),
            doubleAt8: address.add(8).readDouble(),
            int32At0: address.readS32(),
            int32At4: address.add(4).readS32(),
            int32At8: address.add(8).readS32(),
            int32AtC: address.add(12).readS32(),
            int32At10: address.add(16).readS32(),
            uint32At0: address.readU32(),
            uint32At4: address.add(4).readU32(),
            uint32At8: address.add(8).readU32(),
            uint32AtC: address.add(12).readU32(),
            uint32At10: address.add(16).readU32(),
            pointerAt0: address.readPointer(),
            pointerAt8: address.add(8).readPointer()
        };
        
        // Format as multi-line string
        let result = "Data interpretations:\n";
        for (const [key, value] of Object.entries(values)) {
            result += `  ${key}: ${value}\n`;
        }
        return result;
    } catch (e) {
        return `Failed to interpret values: ${e.message}`;
    }
}

function getStringAtPtr(ptr) {
    if (ptr.isNull()) return "NULL";
    try {
        return ptr.readCString() || "[Empty string]";
    } catch (e) {
        return `[Error reading string: ${e.message}]`;
    }
}

// Function to find ShipInsuranceParams global address by pattern scan
function findShipInsuranceParamsAddress() {
    // Multiple approaches to find the structure
    
    // Approach 1: Search for the "fallbackShipInsurance" string
    try {
        Memory.scan(CONFIG.baseAddr, Process.pageSize * 1000, "66 61 6c 6c 62 61 63 6b 53 68 69 70 49 6e 73 75 72 61 6e 63 65 00", {
            onMatch: function(address) {
                console.log(`[+] Found "fallbackShipInsurance" string at ${address}`);
                // The structure might be nearby or referenced
                return "continue";
            },
            onError: function(reason) {
                console.log(`[-] Memory scan error: ${reason}`);
            },
            onComplete: function() {
                console.log("[*] String scan completed");
            }
        });
    } catch (e) {
        console.log(`[-] Error during string scan: ${e.message}`);
    }
    
    // Approach 2: Look for the magic value 666.0 (0x4029400000000000 in double, 0x4429a000 in float)
    try {
        Memory.scan(CONFIG.baseAddr, Process.pageSize * 1000, "00 00 9a 42 44", {
            onMatch: function(address) {
                console.log(`[+] Found potential 666.0 float value at ${address}`);
                // Verify this is part of our structure by checking surrounding memory
                try {
                    const possibleStructStart = address.sub(16); // Estimate
                    hexdumpAddress(possibleStructStart, 64, "Potential ShipInsuranceParams structure");
                    // Store as possible candidate
                    if (CONFIG.shipInsuranceGlobalAddr === null) {
                        CONFIG.shipInsuranceGlobalAddr = possibleStructStart;
                    }
                } catch (e) {
                    console.log(`[-] Error examining potential structure: ${e.message}`);
                }
                return "continue";
            },
            onError: function(reason) {
                console.log(`[-] Memory scan error: ${reason}`);
            },
            onComplete: function() {
                console.log("[*] Value scan completed");
            }
        });
    } catch (e) {
        console.log(`[-] Error during value scan: ${e.message}`);
    }
    
    // Approach 3: Find global structure references (typically in .data section)
    // This would require more specific patterns depending on the binary
}

// Hooking functions
function hookMutatingFunctions() {
    console.log("[*] Setting up hooks for ShipInsuranceParams mutating functions");
    
    // Hook 1: Main initialization function (sub_140190B40)
    const initFunc = CONFIG.baseAddr.add(0x190B40);
    console.log(`[+] Hooking initialization function at ${initFunc}`);
    
    Interceptor.attach(initFunc, {
        onEnter: function(args) {
            console.log("\n======== ShipInsuranceParams Init Function Called ========");
            console.log(`[*] Function: sub_140190B40 (${initFunc})`);
            
            if (LOG_REGISTERS) {
                console.log(`[*] Register state:\n${formatContext(this.context)}`);
            }
            
            // Remember thread ID and stack pointer for tracking
            this.threadId = Process.getCurrentThreadId();
            this.stackPtr = this.context.rsp || this.context.esp;
            
            // Look for potential structure addresses in registers
            this.rcxValue = this.context.rcx;
            this.rdxValue = this.context.rdx;
            
            // Try to dump memory if we suspect the structure location
            if (CONFIG.shipInsuranceGlobalAddr) {
                hexdumpAddress(CONFIG.shipInsuranceGlobalAddr, DUMP_SIZE, "ShipInsuranceParams BEFORE init");
                console.log(inspectFloatValues(CONFIG.shipInsuranceGlobalAddr));
            }
        },
        onLeave: function(retval) {
            console.log(`[+] Leaving init function (thread ${this.threadId})`);
            
            // Check if we can find potential structure pointers
            try {
                // Look for structure address near qword_149E376F8 (from decompilation)
                const potentialAddr = ptr("0x149E376F8");
                let foundAddr = null;
                
                // Try to read from process memory to see if address is valid
                try {
                    foundAddr = potentialAddr.readPointer();
                    console.log(`[+] Found potential structure pointer at ${potentialAddr} -> ${foundAddr}`);
                    CONFIG.shipInsuranceGlobalAddr = foundAddr;
                } catch (e) {
                    console.log(`[-] Could not read from ${potentialAddr}: ${e.message}`);
                    
                    // Adjust for module base if needed
                    try {
                        // Calculate RVA and apply to current base
                        const rva = ptr("0x9E376F8");
                        const adjustedAddr = CONFIG.baseAddr.add(rva);
                        console.log(`[*] Trying adjusted address: ${adjustedAddr}`);
                        foundAddr = adjustedAddr.readPointer();
                        console.log(`[+] Found potential structure pointer at ${adjustedAddr} -> ${foundAddr}`);
                        CONFIG.shipInsuranceGlobalAddr = foundAddr;
                    } catch (e) {
                        console.log(`[-] Could not read from adjusted address: ${e.message}`);
                    }
                }
                
                // Try to find structure by scanning stack memory
                const stackData = this.stackPtr.readByteArray(128);
                console.log(`[*] Stack data at function exit:\n${hexdump(stackData, { header: true, ansi: true })}`);
                
                // Look for the specific values we expect in the structure
                // 666.0 (float) = 0x4429a000
                // 0xA2C2A (666666 decimal) = 0x000A2C2A
                
                // Dump structure after modification if we found it
                if (CONFIG.shipInsuranceGlobalAddr) {
                    hexdumpAddress(CONFIG.shipInsuranceGlobalAddr, DUMP_SIZE, "ShipInsuranceParams AFTER init");
                    console.log(inspectFloatValues(CONFIG.shipInsuranceGlobalAddr));
                }
            } catch (e) {
                console.log(`[-] Error during structure discovery: ${e.message}`);
            }
            
            console.log("======== End of Init Function ========\n");
        }
    });
    
    // Hook 2: Structure initialization function (sub_14259AAD0)
    const initStructFunc = CONFIG.baseAddr.add(0x259AAD0);
    console.log(`[+] Hooking structure initialization function at ${initStructFunc}`);
    
    Interceptor.attach(initStructFunc, {
        onEnter: function(args) {
            console.log("\n======== ShipInsuranceParams Structure Init Function Called ========");
            console.log(`[*] Function: sub_14259AAD0 (${initStructFunc})`);
            
            if (LOG_REGISTERS) {
                console.log(`[*] Register state:\n${formatContext(this.context)}`);
            }
            
            if (LOG_ARGS) {
                // Based on fastcall convention, args would be in RCX, RDX
                this.arg1 = this.context.rcx || args[0];  // a1 in decompilation
                this.arg2 = this.context.rdx || args[1];  // a2 in decompilation
                
                console.log(`[*] Argument 1 (a1): ${this.arg1}`);
                console.log(`[*] Argument 2 (a2): ${this.arg2}`);
                
                // Store arg2 as this is likely the structure ptr
                this.structPtr = this.arg2;
                
                // Dump memory at arg2 if it's a valid pointer
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory BEFORE initialization");
            }
        },
        onLeave: function(retval) {
            console.log(`[+] Leaving structure init function (retval: ${retval})`);
            
            // Dump memory after modification
            if (this.structPtr) {
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory AFTER initialization");
                
                // Try to interpret fields from the decompiled code
                try {
                    const dwordValue = this.structPtr.readU32(); // Hash value
                    console.log(`[*] Structure fields:`);
                    console.log(`    - Hash/dword value: 0x${dwordValue.toString(16)}`);
                    console.log(`    - Ptr at offset 8: ${this.structPtr.add(8).readPointer()}`);
                    console.log(`    - Ptr at offset 16: ${this.structPtr.add(16).readPointer()}`);
                    
                    // Update our global pointer if needed
                    if (!CONFIG.shipInsuranceGlobalAddr) {
                        CONFIG.shipInsuranceGlobalAddr = this.structPtr;
                    }
                } catch (e) {
                    console.log(`[-] Error reading structure fields: ${e.message}`);
                }
            }
            
            console.log("======== End of Structure Init Function ========\n");
        }
    });
    
    // Hook 3: Complex setup function (sub_1425638B0)
    const setupFunc = CONFIG.baseAddr.add(0x25638B0);
    console.log(`[+] Hooking complex setup function at ${setupFunc}`);
    
    Interceptor.attach(setupFunc, {
        onEnter: function(args) {
            console.log("\n======== ShipInsuranceParams Complex Setup Function Called ========");
            console.log(`[*] Function: sub_1425638B0 (${setupFunc})`);
            
            if (LOG_REGISTERS) {
                console.log(`[*] Register state:\n${formatContext(this.context)}`);
            }
            
            if (LOG_ARGS) {
                // First arg is likely structure ptr
                this.structPtr = this.context.rcx || args[0];
                console.log(`[*] Structure pointer: ${this.structPtr}`);
                
                // Dump memory before modification
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory BEFORE complex setup");
            }
        },
        onLeave: function(retval) {
            console.log(`[+] Leaving complex setup function (retval: ${retval})`);
            
            // Dump memory after modification
            if (this.structPtr) {
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory AFTER complex setup");
                
                // Try to interpret vtable fields based on decompiled code
                try {
                    console.log(`[*] Structure vtable pointers:`);
                    console.log(`    - Vtable ptr at offset 0: ${this.structPtr.readPointer()}`);
                    console.log(`    - Vtable ptr at offset 16: ${this.structPtr.add(16).readPointer()}`);
                    console.log(`    - Vtable ptr at offset 56: ${this.structPtr.add(56).readPointer()}`);
                    
                    // Attempt to read string fields
                    const strField1 = this.structPtr.add(64).readPointer();
                    console.log(`[*] String field at offset 64: ${getStringAtPtr(strField1)}`);
                    
                    const strField2 = this.structPtr.add(72).readPointer();
                    console.log(`[*] String field at offset 72: ${getStringAtPtr(strField2)}`);
                    
                    const strField3 = this.structPtr.add(88).readPointer();
                    console.log(`[*] String field at offset 88: ${getStringAtPtr(strField3)}`);
                } catch (e) {
                    console.log(`[-] Error reading structure vtable fields: ${e.message}`);
                }
            }
            
            console.log("======== End of Complex Setup Function ========\n");
        }
    });
    
    // Hook 4: Simple initializer function (sub_1403B1000)
    const simpleInitFunc = CONFIG.baseAddr.add(0x3B1000);
    console.log(`[+] Hooking simple initializer function at ${simpleInitFunc}`);
    
    Interceptor.attach(simpleInitFunc, {
        onEnter: function(args) {
            console.log("\n======== ShipInsuranceParams Simple Init Function Called ========");
            console.log(`[*] Function: sub_1403B1000 (${simpleInitFunc})`);
            
            if (LOG_REGISTERS) {
                console.log(`[*] Register state:\n${formatContext(this.context)}`);
            }
            
            if (LOG_ARGS) {
                // Based on fastcall convention and decompiled signature
                this.arg1 = this.context.rcx || args[0];  // a1 in decompilation
                this.arg2 = this.context.rdx || args[1];  // a2 in decompilation - likely structure ptr
                
                console.log(`[*] Argument 1 (a1): ${this.arg1}`);
                console.log(`[*] Argument 2 (a2/structure): ${this.arg2}`);
                
                // Store arg2 as this is likely the structure ptr
                this.structPtr = this.arg2;
                
                // Dump memory at arg2 if it's a valid pointer
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory BEFORE simple init");
            }
        },
        onLeave: function(retval) {
            console.log(`[+] Leaving simple init function (retval: ${retval})`);
            
            // Dump memory after modification
            if (this.structPtr) {
                hexdumpAddress(this.structPtr, DUMP_SIZE, "Structure memory AFTER simple init");
                
                // Examine structure based on decompiled code
                try {
                    console.log(`[*] Structure after simple initialization:`);
                    console.log(`    - DWORD at offset 0: 0x${this.structPtr.readU32().toString(16)}`);
                    console.log(`    - QWORD at offset 8: ${this.structPtr.add(8).readPointer()}`);
                    console.log(`    - QWORD at offset 16: ${this.structPtr.add(16).readPointer()}`);
                } catch (e) {
                    console.log(`[-] Error reading structure fields: ${e.message}`);
                }
            }
            
            console.log("======== End of Simple Init Function ========\n");
        }
    });
    
    // Additional hook for CreateStringObjectFromString (0x14035B2C0)
    // This function creates string objects which might be related to ShipInsuranceParams
    const createStringFunc = CONFIG.baseAddr.add(0x35B2C0);
    console.log(`[+] Hooking CreateStringObjectFromString function at ${createStringFunc}`);
    
    Interceptor.attach(createStringFunc, {
        onEnter: function(args) {
            // Only log if string contains "ShipInsurance" or "fallback"
            try {
                const stringPtr = this.context.rdx || args[1];
                if (!stringPtr || stringPtr.isNull()) return;
                
                const str = getStringAtPtr(stringPtr);
                if (str.includes("ShipInsurance") || str.includes("fallback")) {
                    console.log("\n======== CreateStringObjectFromString Called for Insurance ========");
                    console.log(`[*] Creating string: "${str}"`);
                    console.log(`[*] Output pointer: ${this.context.rcx || args[0]}`);
                    this.relevant = true;
                }
            } catch (e) {
                // Silently continue if we can't read the string
            }
        },
        onLeave: function(retval) {
            if (this.relevant) {
                console.log(`[+] String object created, return value: ${retval}`);
                console.log("======== End of CreateStringObjectFromString ========\n");
            }
        }
    });
}

// Main initialization routine
function initialize() {
    console.log("[*] ShipInsuranceParams Interceptor Script starting...");
    console.log(`[*] Process architecture: ${Process.arch}`);
    
    // Find the main module
    let mainModule = null;
    
    for (const moduleName of CONFIG.moduleNames) {
        try {
            mainModule = Process.findModuleByName(moduleName);
            if (mainModule) {
                console.log(`[+] Found target module: ${moduleName} at ${mainModule.base}`);
                CONFIG.baseAddr = mainModule.base;
                break;
            }
        } catch (e) {
            console.log(`[-] Error finding module ${moduleName}: ${e.message}`);
        }
    }
    
    if (!mainModule) {
        console.log("[!] Could not find any target module. Attempting to use current base.");
        // Try to use the first module as fallback
        try {
            mainModule = Process.enumerateModules()[0];
            CONFIG.baseAddr = mainModule.base;
            console.log(`[*] Using ${mainModule.name} at ${mainModule.base} as fallback`);
        } catch (e) {
            console.log(`[!] Failed to get any module: ${e.message}`);
            return;
        }
    }
    
    // Find ShipInsuranceParams global address
    findShipInsuranceParamsAddress();
    
    // Set up hooks for mutating functions
    hookMutatingFunctions();
    
    console.log("[*] Initialization complete. Waiting for functions to be called...");
}

// Start the script
initialize();
