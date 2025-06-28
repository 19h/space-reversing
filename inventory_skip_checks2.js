/**
 * Frida Script: Universal Inventory & Equip Bypass v8 (Maximum Debug Logging)
 *
 * This script is designed to trace the entire "Equip Item" call stack with
 * verbose logging of arguments and return values. Its purpose is to identify
 * the specific validation that is failing for the "special heavy helmet".
 *
 * All bypasses are kept active to ensure we get as far down the call stack as possible.
 */

// --- Configuration ---
const baseAddr = Module.findBaseAddress('StarCitizen.exe');
if (!baseAddr) {
    throw new Error("Could not find the base address for StarCitizen.exe. Is it running?");
}
const a = (offset) => baseAddr.add(offset);

// --- Target Addresses ---
const bypassTargets = {
    capacityAndDimensionCheck: { addr: a(0x140399EC0 - 0x140000000), retVal: 1 },
    unlootableCheck: { addr: a(0x1403BFB40 - 0x140000000), retVal: 0 },
    isContainerCheck: { addr: a(0x145C8BF90 - 0x140000000), retVal: 0 },
    equipmentMoveValidation: { addr: a(0x146294EA0 - 0x140000000), retVal: 1 },
    itemPortCompatibility: { addr: a(0x1403995E0 - 0x140000000), retVal: 1 },
    jobValidation: { addr: a(0x146298F50 - 0x140000000), retVal: 0, failVal: -1 },
    canEquipOrSwap: { addr: a(0x145C5B720 - 0x140000000), retVal: 1, failVal: 0 }
};

const debugLogTargets = {
    QuickEquipHandler: { addr: a(0x1462E2C30 - 0x140000000) },
    CanEquipOrSwapCheck: { addr: a(0x145C5B720 - 0x140000000) },
    EquipmentFilterCheck: { addr: a(0x146295F60 - 0x140000000) },
    ItemPortCompatibilityCheck: { addr: a(0x1403995E0 - 0x140000000) },
    //SpecialItemTypeCheck: { addr: a(0x145D28790 - 0x140000000) },
    TagBlockCheck: { addr: a(0x145C8A080 - 0x140000000) },
    //GenericTagCompare: { addr: a(0x1404C3C60 - 0x140000000) } // Very important for seeing what's checked
};

console.log(`[+] Base Address: ${baseAddr}`);

// --- Hook Management ---
const hooks = [];
let indent = "";

function logEnter(funcName, args) {
    console.log(`${indent}[>] ENTER ${funcName}`);
    indent += "  ";
    try {
        if (funcName === 'GenericTagCompare') {
            // Special handling to read the tag string being compared
            const tag = args[1].readCString();
            console.log(`${indent}|  Item Ptr: ${args[0]}`);
            console.log(`${indent}|  Tag Checked: "${tag}"`);
        } else {
            for (let i = 0; i < 4; i++) {
                if (args[i]) {
                    console.log(`${indent}|  arg${i}: ${args[i]}`);
                } else {
                    break;
                }
            }
        }
    } catch (e) {
        console.log(`${indent}|  (Error reading args: ${e.message})`);
    }
}

function logLeave(funcName, retval) {
    indent = indent.substring(2);
    console.log(`${indent}[<] LEAVE ${funcName} | Original Retval: ${retval.toInt32()}`);
}

// --- Attaching Hooks ---

// Attach Bypass Hooks
console.log('[+] Attaching bypass hooks...');
for (const key in bypassTargets) {
    const target = bypassTargets[key];
    try {
        const hook = Interceptor.attach(target.addr, {
            onLeave: function(retval) {
                const original = retval.toInt32();
                const failCondition = target.failVal !== undefined ? original === target.failVal : original === 0;
                if (failCondition) {
                    retval.replace(target.retVal);
                }
            }
        });
        hooks.push(hook);
    } catch (e) {
        console.error(`[-] Failed to attach bypass to ${key}: ${e.message}`);
    }
}
console.log('[+] Bypass hooks installed.');

// Attach Deep Debug Logging Hooks
console.log('[+] Attaching DEEP DEBUG logging hooks...');
for (const funcName in debugLogTargets) {
    const target = debugLogTargets[funcName];
    try {
        const hook = Interceptor.attach(target.addr, {
            onEnter: function(args) {
                if (funcName === 'SpecialItemTypeCheck' && args[0] && args[0].isNull()) {
                    this.shouldSkipLog = true;
                    return; // Don't log if arg0 is 0/null
                }
                this.shouldSkipLog = false;
                logEnter(funcName, args);
            },
            onLeave: function(retval) {
                if (this.shouldSkipLog) {
                    return; // Don't log leave if we didn't log enter
                }
                logLeave(funcName, retval);
            }
        });
        hooks.push(hook);
    } catch (e) {
        console.error(`[-] Failed to attach debug hook to ${funcName}: ${e.message}`);
    }
}
console.log('[+] Deep debug hooks installed.');

// --- Cleanup ---
rpc.exports = {
    disable: function() {
        console.log('[CLEANUP] Detaching all hooks...');
        hooks.forEach(hook => hook.detach());
        console.log('[CLEANUP] All hooks removed.');
    }
};

const targetFunc = baseAddr.add(0x62DEA00);
const pSystem = baseAddr.add(0x9B4FBE0);

Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        // identity_passthrough is likely just returning its argument
        const identity_passthrough = function(addr) { return addr; };

        // v6 = *(_QWORD *)(identity_passthrough((__int64)&pSystem) + 0x18)
        const v6 = identity_passthrough(pSystem).add(0x18).readPointer();

        // v13 = *(void (__fastcall **)(__int64, _BYTE *, const char *))(*(_QWORD *)v6 + 0x28LL)
        const v6_vtable = v6.readPointer();
        const v13 = v6_vtable.add(0x28).readPointer();

        console.log(`v13: ${v13} (offset: 0x${v13.sub(baseAddr).toString(16)})`);

        // v7 = *(_QWORD *)(identity_passthrough((__int64)&pSystem) + 0x18)
        const v7 = identity_passthrough(pSystem).add(0x18).readPointer();

        // v14 = *(void (__fastcall **)(__int64, _BYTE *, const char *))(*(_QWORD *)v7 + 0x28LL)
        const v7_vtable = v7.readPointer();
        const v14 = v7_vtable.add(0x28).readPointer();

        console.log(`v14: ${v14} (offset: 0x${v14.sub(baseAddr).toString(16)})`);
    }
});
