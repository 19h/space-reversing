function readStringFromPointer(ptr) {
    try {
        if (ptr.isNull()) {
            return "null";
        }
        const strPtr = ptr.readPointer();
        if (strPtr.isNull()) {
            return "null (inner)";
        }
        return strPtr.readUtf8String();
    } catch (e) {
        return `invalid_ptr (${ptr})`;
    }
}

// Helper for logging fields to keep the main block clean
function logField(label, value, extra = '') {
    console.log(`  ${label.padEnd(45)}: ${value} ${extra}`);
}

const MODULE_NAME = "StarCitizen.exe";
// Offset for the constructor: 0x145CCC690 - 0x140000000 = 0x5CCC690
const CONSTRUCTOR_OFFSET = 0x5CCC690;

const moduleBase = Module.findBaseAddress(MODULE_NAME);
if (!moduleBase) {
    console.error(`[!] Could not find module: ${MODULE_NAME}`);
} else {
    const targetAddr = moduleBase.add(CONSTRUCTOR_OFFSET);
    console.log(`[+] Found module ${MODULE_NAME} at ${moduleBase}`);
    console.log(`[+] Hooking CWeaponActionFireTractorBeam Constructor (sub_145CCC690) at: ${targetAddr}`);

    // Interceptor.attach(targetAddr, {
    //     onEnter: function(args) {
    //         // We can't modify the params here, as args[1] is likely read-only.
    //         // But we can store the pointers for the onLeave hook.
    //         this.thisPtr = args[0];   // Store the instance pointer
    //         this.paramsPtr = args[1]; // Store the original params pointer
    //     },
    //     onLeave: function(retval) {
    //         // This code runs *after* the original constructor has finished.
    //         // this.thisPtr is now a fully constructed, writeable object.

    //         const thisPtr = this.thisPtr;
    //         const paramsPtr = this.paramsPtr;

    //         if (paramsPtr.isNull() || thisPtr.isNull()) {
    //             return;
    //         }

    //         console.log("\n============================================================");
    //         console.log(`[+] CWeaponActionFireTractorBeam Constructor finished for instance at ${thisPtr}`);
    //         console.log("============================================================");

    //         // From sub_145DF0A00:
    //         //   *(float *)(a1 + 1388) = *(float *)(a2 + 320); // maxForce (0x140 in params) is at 0x56C in instance
    //         //   *(float *)(a1 + 2152) = *(float *)(a2 + 332); // maxDistance (0x14C in params) is at 0x868 in instance

    //         // --- MODIFY THE INSTANCE DATA ---
    //         const maxForcePtr = thisPtr.add(0x56C); // Offset of maxForce in the *instance*
    //         const maxDistancePtr = thisPtr.add(0x868); // Offset of maxDistance in the *instance*

    //         const originalMaxForce = maxForcePtr.readFloat();
    //         const originalMaxDist = maxDistancePtr.readFloat();

    //         const newMaxForce = originalMaxForce * 100;
    //         const newMaxDist = originalMaxDist * 2;

    //         maxForcePtr.writeFloat(newMaxForce);
    //         maxDistancePtr.writeFloat(newMaxDist);

    //         console.log("  --- Parameters Modified ---");
    //         logField("Max Force", `${originalMaxForce.toFixed(2)} -> ${newMaxForce.toFixed(2)}`);
    //         logField("Max Distance", `${originalMaxDist.toFixed(2)} -> ${newMaxDist.toFixed(2)}`);
    //         console.log("  ---------------------------");


    //         // --- Dumping SWeaponActionFireTractorBeamParams ---
    //         logField("C [0x008] name", readStringFromPointer(paramsPtr.add(0x8)));
    //         logField("C [0x018] localisedName", readStringFromPointer(paramsPtr.add(0x18)));

    //         // SMannequinTagParams is a struct, we'll just note its presence
    //         logField("C [0x020] mannequinTag", `(struct SMannequinTagParams at ${paramsPtr.add(0x20)})`);

    //         logField("C [0x040] entityTag", paramsPtr.add(0x40).readU32().toString(16));

    //         // DynArray pointers - just show the pointer for now
    //         logField("C [0x058] entityTags", `(struct TagList at ${paramsPtr.add(0x58)})`);
    //         logField("C [0x090] uiBindingsTag", paramsPtr.add(0x90).readU32().toString(16));

    //         logField("C [0x0B0] switchFireModeAudioTrigger", readStringFromPointer(paramsPtr.add(0xB0)));
    //         logField("C [0x0E0] hasReloadModesOnUI", paramsPtr.add(0xE0).readU8() ? 'true' : 'false');
    //         logField("C [0x0E8] localisedLiftingFunctionalityName", readStringFromPointer(paramsPtr.add(0xE8)));
    //         logField("C [0x0F0] localisedRotationFunctionalityName", readStringFromPointer(paramsPtr.add(0xF0)));
    //         logField("C [0x0F8] liftingFunctionalityTag", paramsPtr.add(0xF8).readU32().toString(16));
    //         logField("C [0x110] rotationFunctionalityTag", paramsPtr.add(0x110).readU32().toString(16));
    //         logField("C [0x128] fireHelper", readStringFromPointer(paramsPtr.add(0x128)));
    //         logField("C [0x138] toggle", paramsPtr.add(0x138).readU8() ? 'true' : 'false');

    //         // --- Core Tractor Beam Values ---
    //         logField("C [0x13C] minForce", paramsPtr.add(0x13C).readFloat().toFixed(2));
    //         logField("C [0x140] maxForce", paramsPtr.add(0x140).readFloat().toFixed(2));
    //         logField("C [0x144] additionalForceDuringZeroGHandholding", paramsPtr.add(0x144).readFloat().toFixed(2));
    //         logField("C [0x148] minDistance", paramsPtr.add(0x148).readFloat().toFixed(2));
    //         logField("C [0x14C] maxDistance", paramsPtr.add(0x14C).readFloat().toFixed(2));
    //         logField("C [0x150] fullStrengthDistance", paramsPtr.add(0x150).readFloat().toFixed(2));
    //         logField("C [0x154] maxAngle", paramsPtr.add(0x154).readFloat().toFixed(2));
    //         logField("C [0x158] maxVolume", paramsPtr.add(0x158).readFloat().toFixed(2));
    //         logField("C [0x15C] volumeForceCoefficient", paramsPtr.add(0x15C).readFloat().toFixed(2));
    //         logField("C [0x160] heatPerSecond", paramsPtr.add(0x160).readFloat().toFixed(2));
    //         logField("C [0x164] wearPerSecond", paramsPtr.add(0x164).readFloat().toFixed(2));
    //         logField("C [0x168] hitRadius", paramsPtr.add(0x168).readFloat().toFixed(2));
    //         logField("C [0x16C] tetherBreakTime", paramsPtr.add(0x16C).readFloat().toFixed(2));
    //         logField("C [0x170] safeRangeValueFactor", paramsPtr.add(0x170).readFloat().toFixed(2));
    //         logField("C [0x174] maxPlayerLookRotationScale", paramsPtr.add(0x174).readFloat().toFixed(2));
    //         logField("C [0x178] allowScrollingIntoBreakingRange", paramsPtr.add(0x178).readU8() ? 'true' : 'false');
    //         logField("C [0x179] shouldDryFireInGreenZones", paramsPtr.add(0x179).readU8() ? 'true' : 'false');
    //         logField("C [0x17A] shouldFireInHangars", paramsPtr.add(0x17A).readU8() ? 'true' : 'false');
    //         logField("C [0x17B] shouldTractorSelf", paramsPtr.add(0x17B).readU8() ? 'true' : 'false');

    //         // --- Other ---
    //         logField("C [0x180] entityTagBlacklist", `(DynArray* at ${paramsPtr.add(0x180).readPointer()})`);
    //         logField("C [0x1B0] ammoType", `0x${paramsPtr.add(0x1B0).readU32().toString(16)}`);
    //         logField("C [0x1B4] minEnergyDraw", paramsPtr.add(0x1B4).readFloat().toFixed(2));
    //         logField("C [0x1B8] maxEnergyDraw", paramsPtr.add(0x1B8).readFloat().toFixed(2));
    //         logField("C [0x1C0] hitType", readStringFromPointer(paramsPtr.add(0x1C0)));
    //         logField("C [0x210] recoilInterval", paramsPtr.add(0x210).readFloat().toFixed(2));

    //         console.log("============================================================\n");
    //     }
    // });
    // This is the function that sets a networked float value.
    // Signature: __int64 __fastcall sub_14154B8A0(__int64 propertyPtr, float* newValuePtr)
    const setNetworkedFloat = new NativeFunction(
        moduleBase.add(0x154B8A0), // Offset of sub_14154B8A0
        'pointer',
        ['pointer', 'pointer']
    );

    // This is the constructor we are hooking.
    const constructorAddr = moduleBase.add(0x5CCC690);

    console.log(`[+] Hooking CWeaponActionFireTractorBeam Constructor at: ${constructorAddr}`);

    Interceptor.attach(constructorAddr, {
        onEnter: function(args) {
            // Store the 'this' pointer for use in onLeave
            this.thisPtr = args[0];
        },
        onLeave: function(retval) {
            // This code runs *after* the original constructor has finished.
            // this.thisPtr is now a fully constructed, writeable object.
            const thisPtr = this.thisPtr;
            if (thisPtr.isNull()) return;

            console.log("\n============================================================");
            console.log(`[+] CWeaponActionFireTractorBeam Constructor finished for instance at ${thisPtr}`);
            console.log("============================================================");

            // --- Find the pointer to the component that holds the active state ---
            // From sub_145CEFF50, we know the params are applied to an object retrieved via sub_145BF61E0
            // Let's assume for now this component is at a fixed offset from the main object.
            // A common pattern is for it to be a member, let's find it.
            // From sub_145CEFF50, we see it calls sub_145BF61E0(this->m_pWeapon).
            // The weapon pointer is at thisPtr + 0x18.
            const weaponPtr = thisPtr.add(0x18).readPointer();
            if (weaponPtr.isNull()) {
                console.log("[!] Parent Weapon pointer is null. Cannot find state component.");
                return;
            }

            // Now we need to find the component that sub_145D5B6E0 writes to.
            // Let's assume it's the object returned by sub_145BF61E0, which is a complex lookup.
            // A simpler approach for now is to find where the constructor COPIED the params.
            // The constructor calls sub_145D5B6E0, which takes the component object as its first argument.
            // Let's assume the component object is at a fixed offset for simplicity.
            // Based on the RE, the component that holds these values is often called the "shared state" or "params component".
            // Let's find the pointer to the object that sub_145D5B6E0 writes to.
            // From sub_145CEFF50, we see it's the result of sub_145BF61E0(weaponPtr).
            // Let's trace that: sub_145BF61E0 reads from weaponPtr + 0x3210.
            const componentPtr = weaponPtr.add(0x3210).readPointer();
            if (componentPtr.isNull()) {
                console.log("[!] Active State Component pointer is null. Cannot modify params.");
                return;
            }

            console.log(`[+] Found Active State Component at: ${componentPtr}`);

            // --- MODIFY THE VALUES USING THE GAME'S FUNCTIONS ---

            // 1. Modify maxForce
            const maxForcePropertyPtr = componentPtr.add(0x2E0); // Destination from sub_145D5B6E0
            const newMaxForce = 257500.0 * 10; // Let's set it to 10x the default
            const newMaxForcePtr = Memory.alloc(4);
            newMaxForcePtr.writeFloat(newMaxForce);
            setNetworkedFloat(maxForcePropertyPtr, newMaxForcePtr);
            console.log(`  [*] Called setNetworkedFloat for maxForce with value: ${newMaxForce}`);

            // 2. Modify maxDistance
            const maxDistancePropertyPtr = componentPtr.add(0x250); // Destination from sub_145D5B6E0
            const newMaxDist = 100.0 * 2; // Let's double the default
            const newMaxDistPtr = Memory.alloc(4);
            newMaxDistPtr.writeFloat(newMaxDist);
            setNetworkedFloat(maxDistancePropertyPtr, newMaxDistPtr);
            console.log(`  [*] Called setNetworkedFloat for maxDistance with value: ${newMaxDist}`);

            console.log("============================================================\n");
        }
    });
}
