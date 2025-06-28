/**
 * Frida Hook for Star Citizen: CSCBodyHealthComponent::ProcessHit
 *
 * Target Function: sub_146321C50 (CSCBodyHealthComponent::ProcessHit)
 * Target Audience: Advanced x86 Reverse Engineers
 *
 * Purpose:
 * This script intercepts calls to the primary damage processing function for actors.
 * It parses the 'HitInfo' structure, which is passed as the second argument,
 * and logs its contents in a structured, human-readable format. This provides
 * invaluable real-time insight into damage events, including source, target,
 * damage type, amount, and spatial information.
 *
 * Methodology:
 * The script leverages the memory layout of the HitInfo structure, which was
 * previously determined through rigorous static and dynamic analysis of the binary.
 * It uses Frida's Interceptor API to hook the function at its entry point (`onEnter`)
 * and reads the structure's members directly from memory.
 *
 * Calling Convention Note:
 * The target function uses the Windows x64 `__fastcall` convention.
 * - 1st argument (pBodyHealthComponent): RCX -> args[0]
 * - 2nd argument (pHitInfo):           RDX -> args[1]
 * Frida's `args` array conveniently maps these register arguments for us.
 */

// Helper function to translate the integer hitType to a human-readable string.
// This mapping is derived from analysis of sub_14490F440.
function getHitTypeString(typeId) {
    const hitTypes = {
        0: 'Invalid',
        1: 'Melee',
        2: 'Collision',
        3: 'Crash',
        4: 'Frag',
        5: 'Explosion',
        6: 'TakeDown',
        7: 'Punish',
        8: 'Normal',
        9: 'Fire',
        10: 'Bullet',
        11: 'VehicleDestruction',
        12: 'EventDamage',
        13: 'BleedOut',
        14: 'ElectricArc',
        15: 'Repair',
        16: 'Suffocate',
        17: 'Suicide',
        18: 'SelfDestruct',
        19: 'BoundaryViolation',
        20: 'Drown',
        21: 'DamageOverTime',
        22: 'Hazard',
        23: 'Extraction'
    };
    return hitTypes[typeId] || `Unknown`;
}

// Helper function to get actor health from the BodyHealthComponent
function getActorHealth(pBodyHealthComponent) {
    try {
        const pActor = pBodyHealthComponent.add(0x270).readPointer();
        if (pActor.isNull()) return -1.0;

        const pActorStatus = pActor.add(0x6F70).readPointer(); // Hypothetical offset for CSCActorStatusComponent
        if (pActorStatus.isNull()) return -1.0;

        return pActorStatus.add(0x10).readFloat(); // Hypothetical offset for health
    } catch (e) {
        return -1.0; // Return an invalid value on error
    }
}

// Main execution block
try {
    // It is best practice to calculate the address dynamically to handle ASLR.
    // The base address of the main executable is required.
    // The offset is calculated from the function address in the provided dump.
    // Example: 0x146321C50 (function) - 0x140000000 (assumed image base) = 0x6321C50
    const baseAddr = Module.findBaseAddress('StarCitizen.exe');
    if (!baseAddr) {
        throw new Error("Could not find base address for StarCitizen.exe. Is the process name correct?");
    }
    const processHitPtr = baseAddr.add(0x6321C50);

    console.log(`[+] Hooking CSCBodyHealthComponent::ProcessHit at: ${processHitPtr}`);

    Interceptor.attach(processHitPtr, {
        onEnter: function(args) {
            try {
                // args[0] is pBodyHealthComponent (RCX)
                // args[1] is pHitInfo (RDX)
                const pBodyHealthComponent = args[0];
                const hitInfoPtr = args[1];

                // Store for onLeave callback
                this.pBodyHealthComponent = pBodyHealthComponent;
                this.hitInfoPtr = hitInfoPtr;

                // Store initial health for comparison in onLeave
                this.initialHealth = getActorHealth(this.pBodyHealthComponent);

                // Create a structured object to hold the parsed data
                const hitData = {};

                // --- Parse the HitInfo structure based on the verified memory layout ---

                // Offsets 0x00 - 0x18: Entity Identifiers
                hitData.targetId = hitInfoPtr.add(0x0).readU64().toString(16);
                hitData.shooterId = hitInfoPtr.add(0x8).readU64().toString(16);
                hitData.weaponId = hitInfoPtr.add(0x10).readU64().toString(16);

                // Offset 0x18: Damage
                hitData.damage = hitInfoPtr.add(0x18).readFloat();

                // Offsets 0x20 - 0x4C: Spatial Information (Vectors)
                hitData.pos = {
                    x: hitInfoPtr.add(0x20).readFloat().toFixed(2),
                    y: hitInfoPtr.add(0x24).readFloat().toFixed(2),
                    z: hitInfoPtr.add(0x28).readFloat().toFixed(2)
                };
                hitData.dir = {
                    x: hitInfoPtr.add(0x2C).readFloat().toFixed(2),
                    y: hitInfoPtr.add(0x30).readFloat().toFixed(2),
                    z: hitInfoPtr.add(0x34).readFloat().toFixed(2)
                };
                hitData.normal = {
                    x: hitInfoPtr.add(0x40).readFloat().toFixed(2),
                    y: hitInfoPtr.add(0x44).readFloat().toFixed(2),
                    z: hitInfoPtr.add(0x48).readFloat().toFixed(2)
                };

                // Offsets 0x58 - 0x7C: Hit Metadata
                hitData.partId = hitInfoPtr.add(0x58).readS32();
                hitData.materialId = hitInfoPtr.add(0x70).readS32(); // Corrected offset based on re-analysis
                const hitTypeId = hitInfoPtr.add(0x74).readS32();
                hitData.hitType = `${getHitTypeString(hitTypeId)} (${hitTypeId})`;
                hitData.projectileClassId = hitInfoPtr.add(0x7C).readS32();

                if (hitTypeId === 13 || hitTypeId === 2) {
                    return;
                }

                console.log(-1, this.threadId);
                console.log(-2, hitTypeId);

                // Offsets 0x80 - 0x108: Boolean Flags
                hitData.isMelee = hitInfoPtr.add(0x80).readU8() !== 0;
                hitData.isHeadshot = hitInfoPtr.add(0xEA).readU8() !== 0;
                hitData.isBackstab = hitInfoPtr.add(0xEB).readU8() !== 0;
                hitData.isPredicted = hitInfoPtr.add(0xEC).readU8() !== 0;
                hitData.isSplitOverParts = hitInfoPtr.add(0xED).readU8() !== 0;
                hitData.isKillingBlow = hitInfoPtr.add(0x108).readU8() !== 0;

                // --- Log the parsed data ---
                console.log("\n" + "-".repeat(80));
                console.log(`[+] CSCBodyHealthComponent::ProcessHit Intercepted at ${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}`);
                console.log(`    pBodyHealthComponent: ${pBodyHealthComponent}`);
                console.log(`    pHitInfo:             ${hitInfoPtr}`);
                console.log("-".repeat(80));

                // Format data in ASCII table
                console.log("┌─────────────────────┬─────────────────────────────────────────────────────┐");
                console.log("│ Field               │ Value                                               │");
                console.log("├─────────────────────┼─────────────────────────────────────────────────────┤");
                console.log(`│ Target ID           │ ${hitData.targetId.padEnd(51)} │`);
                console.log(`│ Shooter ID          │ ${hitData.shooterId.padEnd(51)} │`);
                console.log(`│ Weapon ID           │ ${hitData.weaponId.padEnd(51)} │`);
                console.log(`│ Damage              │ ${hitData.damage.toString().padEnd(51)} │`);
                console.log(`│ Position            │ X:${hitData.pos.x} Y:${hitData.pos.y} Z:${hitData.pos.z}${(' ').repeat(51 - (`X:${hitData.pos.x} Y:${hitData.pos.y} Z:${hitData.pos.z}`).length)} │`);
                console.log(`│ Direction           │ X:${hitData.dir.x} Y:${hitData.dir.y} Z:${hitData.dir.z}${(' ').repeat(51 - (`X:${hitData.dir.x} Y:${hitData.dir.y} Z:${hitData.dir.z}`).length)} │`);
                console.log(`│ Normal              │ X:${hitData.normal.x} Y:${hitData.normal.y} Z:${hitData.normal.z}${(' ').repeat(51 - (`X:${hitData.normal.x} Y:${hitData.normal.y} Z:${hitData.normal.z}`).length)} │`);
                console.log(`│ Part ID             │ ${hitData.partId.toString().padEnd(51)} │`);
                console.log(`│ Material ID         │ ${hitData.materialId.toString().padEnd(51)} │`);
                console.log(`│ Hit Type            │ ${hitData.hitType.padEnd(51)} │`);
                console.log(`│ Projectile Class ID │ ${hitData.projectileClassId.toString().padEnd(51)} │`);
                console.log(`│ Is Melee            │ ${hitData.isMelee.toString().padEnd(51)} │`);
                console.log(`│ Is Headshot         │ ${hitData.isHeadshot.toString().padEnd(51)} │`);
                console.log(`│ Is Backstab         │ ${hitData.isBackstab.toString().padEnd(51)} │`);
                console.log(`│ Is Predicted        │ ${hitData.isPredicted.toString().padEnd(51)} │`);
                console.log(`│ Is Split Over Parts │ ${hitData.isSplitOverParts.toString().padEnd(51)} │`);
                console.log(`│ Is Killing Blow     │ ${hitData.isKillingBlow.toString().padEnd(51)} │`);
                console.log("└─────────────────────┴─────────────────────────────────────────────────────┘");

                console.log("-".repeat(80) + "\n");

                // Call the original function with modified shooter ID
                try {
                    // Create a copy of the HitInfo structure
                    const hitInfoSize = 0x200; // Estimated size, adjust if needed
                    const modifiedHitInfo = Memory.alloc(hitInfoSize);
                    Memory.copy(modifiedHitInfo, hitInfoPtr, hitInfoSize);

                    // Overwrite the shooter ID with the target ID
                    const targetId = hitInfoPtr.add(0x0).readU64();
                    modifiedHitInfo.add(0x8).writeU64(targetId);

                    console.log(`[*] Calling original function with modified shooter ID: ${targetId.toString(16)}`);

                    // Get the original function pointer and call it
                    const originalFunction = new NativeFunction(processHitPtr, 'void', ['pointer', 'pointer']);
                    originalFunction(pBodyHealthComponent, modifiedHitInfo);

                    console.log(`[*] Original function called successfully with modified parameters`);
                } catch (e) {
                    console.error(`[!] Error calling original function: ${e.stack}`);
                }

            } catch (e) {
                console.error(`[!] Error in onEnter callback: ${e.stack}`);
            }
        },
        onLeave: function(retval) {
            try {
                const hitInfoPtr = this.hitInfoPtr;
                const hitTypeId = hitInfoPtr.add(0x74).readS32();

                // We are only interested in the BleedOut events revealed by the logs.
                if (hitTypeId === 13 || hitTypeId === 2) {
                    return;
                }

                const finalHealth = getActorHealth(this.pBodyHealthComponent);
                const damageDelta = this.initialHealth - finalHealth;

                // Read the repurposed vector component
                const repurposedDirX = hitInfoPtr.add(0x2C).readFloat();

                console.log("\n" + "=".repeat(80));
                console.log("[!] BleedOut Event Analysis:");
                console.log(`    Initial Health: ${this.initialHealth.toFixed(4)}`);
                console.log(`    Final Health:   ${finalHealth.toFixed(4)}`);
                console.log(`    Damage Delta:   ${damageDelta.toFixed(4)}`);
                console.log(`    Repurposed dir.x (likely dt): ${repurposedDirX.toFixed(4)}`);

                if (repurposedDirX > 0) {
                    const damagePerUnit = damageDelta / repurposedDirX;
                    console.log(`    Calculated Damage/Unit:     ${damagePerUnit.toFixed(4)}`);
                }
                console.log("=".repeat(80) + "\n");
            } catch (e) {
                console.error(`[!] Error in onLeave callback: ${e.stack}`);
            }
        }
    });

} catch (e) {
    console.error(`[!] Script failed to initialize: ${e.stack}`);
}

/*
frida -R -F -l hit_dump.js
s
--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4024f198
    pHitInfo:             0x7b8086b99060
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 788d100a5dd0                                        │
│ Shooter ID          │ 1788a40248c00                                       │
│ Weapon ID           │ 37889f0ce5de0                                       │
│ Damage              │ 1.2283653158455314e+34                              │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.57 Z:0.00                               │
│ Normal              │ X:0.00 Y:145800.00 Z:0.00                           │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4024f198
    pHitInfo:             0x7b8086b99060
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 788d100a5dd0                                        │
│ Shooter ID          │ 1788a40248c00                                       │
│ Weapon ID           │ 37889f0ce5de0                                       │
│ Damage              │ 1.2283653158455314e+34                              │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.57 Z:0.00                               │
│ Normal              │ X:0.00 Y:145800.00 Z:0.00                           │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4024f198
    pHitInfo:             0x7b8087700aa0
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 788d100a5dd0                                        │
│ Shooter ID          │ 1788a40248c00                                       │
│ Weapon ID           │ 27889f0d036a0                                       │
│ Damage              │ 1.2283653158455314e+34                              │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.57 Z:0.00                               │
│ Normal              │ X:0.00 Y:145800.00 Z:0.00                           │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a401c9718
    pHitInfo:             0x7b8087402300
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40259750                                       │
│ Shooter ID          │ 1788a401c3180                                       │
│ Weapon ID           │ 788a380a22b0                                        │
│ Damage              │ 2.587360382080078                                   │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.44 Z:0.00                               │
│ Normal              │ X:0.00 Y:12000.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a401c9718
    pHitInfo:             0x7b8087881680
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40259750                                       │
│ Shooter ID          │ 1788a401c3180                                       │
│ Weapon ID           │ 788a380a22b0                                        │
│ Damage              │ 2.587360382080078                                   │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.44 Z:0.00                               │
│ Normal              │ X:0.00 Y:12000.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a401c9718
    pHitInfo:             0x7b8087402300
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40259750                                       │
│ Shooter ID          │ 1788a401c3180                                       │
│ Weapon ID           │ 788a380a22b0                                        │
│ Damage              │ 2.587360382080078                                   │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.44 Z:0.00                               │
│ Normal              │ X:0.00 Y:12000.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4022daf8
    pHitInfo:             0x7b8087703280
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40216a10                                       │
│ Shooter ID          │ 1788a40227560                                       │
│ Weapon ID           │ 788ab0021550                                        │
│ Damage              │ 2.5220985412597656                                  │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.54 Z:0.00                               │
│ Normal              │ X:13000.00 Y:0.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4022daf8
    pHitInfo:             0x7b8087076420
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40216a10                                       │
│ Shooter ID          │ 1788a40227560                                       │
│ Weapon ID           │ 788ab0021550                                        │
│ Damage              │ 2.5220985412597656                                  │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.54 Z:0.00                               │
│ Normal              │ X:13000.00 Y:0.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================


--------------------------------------------------------------------------------
[+] CSCBodyHealthComponent::ProcessHit Intercepted at 0x1462d89a6
	0x1462f58ad
	0x146a27cd6
	0x146a48080
	0x146a23d50
	0x1474dfda3
	0x1474edbcc
	0x1403a734f
	0x6fffffec49a9
	0x6ffffff3fd3b
    pBodyHealthComponent: 0x788a4021cfa8
    pHitInfo:             0x7b8087865900
--------------------------------------------------------------------------------
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Field               │ Value                                               │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Target ID           │ 1788a40259750                                       │
│ Shooter ID          │ 1788a40216a10                                       │
│ Weapon ID           │ 788a380a22b0                                        │
│ Damage              │ 2.587360382080078                                   │
│ Position            │ X:0.00 Y:0.00 Z:0.00                                │
│ Direction           │ X:10.00 Y:2.52 Z:0.00                               │
│ Normal              │ X:0.00 Y:12000.00 Z:0.00                            │
│ Part ID             │ 1065353216                                          │
│ Material ID         │ 107                                                 │
│ Hit Type            │ Bullet (10)                                         │
│ Projectile Class ID │ 0                                                   │
│ Is Melee            │ true                                                │
│ Is Headshot         │ false                                               │
│ Is Backstab         │ false                                               │
│ Is Predicted        │ false                                               │
│ Is Split Over Parts │ false                                               │
│ Is Killing Blow     │ true                                                │
└─────────────────────┴─────────────────────────────────────────────────────┘
--------------------------------------------------------------------------------


================================================================================
[!] BleedOut Event Analysis:
    Initial Health: 0.0000
    Final Health:   0.0000
    Damage Delta:   0.0000
    Repurposed dir.x (likely dt): 10.0000
    Calculated Damage/Unit:     0.0000
================================================================================
*/
