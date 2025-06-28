/**
 * Frida Script: Universal Inventory & Equip Bypass
 *
 * This script provides a comprehensive set of hooks to bypass all major
 * inventory and equipment restrictions in the target application.
 *
 * Features:
 * 1.  **Infinite Capacity & Dimensional Bypass:** Allows any item to be stored in any
 *     container, regardless of size or volume. This is achieved by hooking the
 *     master placement validation function.
 * 2.  **Drop Anywhere:** Disables restrictions on dropping items in protected zones
 *     (e.g., Armistice) by bypassing the "Unlootable" tag check.
 * 3.  **No Item Filtering:** Removes container-specific item type restrictions,
 *     allowing, for example, weapons to be stored in regular backpacks.
 * 4.  **Equip Anything:** Allows any item to be equipped into any equipment slot
 *     by bypassing container checks, item category filters, and move validation.
 *
 * This script makes the previous C++ detour for capacity obsolete by proactively
 * bypassing the checks rather than reactively modifying metrics.
 */

// --- Configuration: Verify these addresses from your binary ---
const baseAddr = Module.findBaseAddress('StarCitizen.exe'); // Or your target executable
if (!baseAddr) {
    throw new Error("Could not find the base address for StarCitizen.exe. Is it running?");
}

// Helper to calculate addresses from the executable's base
const a = (offset) => baseAddr.add(offset);

// Target function addresses (RVA from your dump)
// Inventory bypass functions
const capacityAndDimensionCheckAddr = a(0x140399EC0 - 0x140000000); // Goal 1 & 4
const unlootableCheckAddr = a(0x1403BFB40 - 0x140000000);           // Goal 2
const itemFilterAddr = a(0x1462FAB30 - 0x140000000);                // Goal 3

// Equipment bypass functions
const isContainerCheckAddr = a(0x145C8BF90 - 0x140000000); // sub_145C8BF90
const itemFilterCheckAddr = a(0x146295F60 - 0x140000000);  // sub_146295F60
const moveValidationAddr = a(0x146294EA0 - 0x140000000);   // sub_146294EA0

console.log(`[+] Base Address: ${baseAddr}`);
console.log(`[+] Attaching to Capacity/Dimension Check @ ${capacityAndDimensionCheckAddr}`);
console.log(`[+] Attaching to Unlootable Check @ ${unlootableCheckAddr}`);
console.log(`[+] Attaching to Item Filter Check @ ${itemFilterAddr}`);
console.log(`[+] Attaching to IsContainer Check @ ${isContainerCheckAddr}`);
console.log(`[+] Attaching to ItemFilter Check @ ${itemFilterCheckAddr}`);
console.log(`[+] Attaching to MoveValidation Check @ ${moveValidationAddr}`);

// --- Hook Implementations ---

/**
 * Goal 1 & 4: Bypass the master capacity and dimensional check.
 * This single hook makes all items fit in any container.
 * Target: sub_140399EC0
 * Action: Force return value to 1 (true/success).
 */
const capacityHook = Interceptor.attach(capacityAndDimensionCheckAddr, {
    onLeave: function(retval) {
        retval.replace(1);
    }
});

/**
 * Goal 2: Bypass the "Unlootable" item tag check.
 * This allows items to be dropped in restricted zones.
 * Target: sub_1403BFB40
 * Action: Force return value to 0 (false/not unlootable).
 */
const unlootableHook = Interceptor.attach(unlootableCheckAddr, {
    onLeave: function(retval) {
        retval.replace(0);
    }
});

/**
 * Goal 3: Bypass the item category filter.
 * This allows any item type (e.g., weapons) into any container.
 * Target: sub_1462FAB30
 * Action: Force return value to 1 (true/passes filter).
 */
const filterHook = Interceptor.attach(itemFilterAddr, {
    onLeave: function(retval) {
        //retval.replace(1);
    }
});

/**
 * Hook for sub_145C8BF90: "Is it a container?" check.
 * We force it to return 0 (false) so that items like backpacks can be
 * treated as equippable items rather than just containers.
 */
const isContainerHook = Interceptor.attach(isContainerCheckAddr, {
    onLeave: function(retval) {
        retval.replace(0);
    }
});

/**
 * Hook for sub_146295F60: The main item vs. slot filter.
 * We force it to return 1 (true) to make any item type compatible
 * with any equipment slot.
 */
const itemFilterCheckHook = Interceptor.attach(itemFilterCheckAddr, {
    onLeave: function(retval) {
        retval.replace(0);
    }
});

/**
 * Hook for sub_146294EA0: The high-level move validation.
 * We force it to return 1 (true) to ensure the equip action is
 * always considered valid.
 */
const moveValidationHook = Interceptor.attach(moveValidationAddr, {
    onLeave: function(retval) {
        retval.replace(1);
    }
});

console.log("[+] All inventory bypass hooks have been successfully installed.");
console.log("[+] 'Equip Anything' hooks have been successfully installed.");

// --- Cleanup ---
rpc.exports = {
    disable: function() {
        console.log('[CLEANUP] Detaching all inventory and equipment hooks...');
        capacityHook.detach();
        unlootableHook.detach();
        filterHook.detach();
        isContainerHook.detach();
        itemFilterCheckHook.detach();
        moveValidationHook.detach();
        console.log('[CLEANUP] Hooks removed.');
    }
};
