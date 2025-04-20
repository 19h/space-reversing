'use strict';

// Frida script to hook the computeTotalBodyDamage function in StarCitizen.exe
// Pattern: C5 FA 10 41 ?? C5 FA 58 49 ?? C5 F2 58 51 ?? C5 EA 58 59 ?? C5 E2 58 41 ?? C5 FA 58 41 ?? C3
// Corresponds to:
//   vmovss  xmm0, [rcx+0x0C]
//   vaddss  xmm1, xmm0, [rcx+0x08]
//   vaddss  xmm2, xmm1, [rcx+0x10]
//   vaddss  xmm3, xmm2, [rcx+0x14]
//   vaddss  xmm0, xmm3, [rcx+0x18]
//   vaddss  xmm0, xmm0, [rcx+0x1C]
//   retn

function hookFunction() {
    const moduleName = 'StarCitizen.exe';
    // Define the raw byte pattern for the six SSE instructions + RET
    const pattern    = 'C5 FA 10 41 ?? C5 FA 58 49 ?? C5 F2 58 51 ?? C5 EA 58 59 ?? C5 E2 58 41 ?? C5 FA 58 41 ?? C3';

    // Find executable code ranges in the module
    const ranges = Module.enumerateRangesSync({ protection: 'r-x', module: moduleName });
    let funcAddr = null;

    // Scan each range for the byte pattern
    for (const range of ranges) {
        const matches = Memory.scanSync(range.base, range.size, pattern);
        if (matches.length > 0) {
            funcAddr = matches[0].address;
            break;
        }
    }

    if (!funcAddr) {
        console.error(`Pattern not found in ${moduleName}`);
        return;
    }

    console.log(`Hooking computeTotalBodyDamage at ${funcAddr}`);

    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            // args[0] = RCX = pointer to BodyDamage struct
            this.parts = args[0];
            console.log('[+] Enter computeTotalBodyDamage');
            console.log(`    RCX (bodyParts): ${this.parts}`);

            // Assembly: vmovss xmm0, dword ptr [rcx+0x0C]
            // Load headDamage from offset 0x0C
            this.headDamage = Memory.readFloat(this.parts.add(0x0C));
            console.log(`    headDamage = [rcx+0x0C] = ${this.headDamage}`);

            // Assembly: vaddss xmm1, xmm0, dword ptr [rcx+0x08]
            // torsoDamage at offset 0x08
            this.torsoDamage = Memory.readFloat(this.parts.add(0x08));
            console.log(`    torsoDamage = [rcx+0x08] = ${this.torsoDamage}`);

            // Assembly: vaddss xmm2, xmm1, dword ptr [rcx+0x10]
            // leftArmDamage at offset 0x10
            this.leftArmDamage = Memory.readFloat(this.parts.add(0x10));
            console.log(`    leftArmDamage = [rcx+0x10] = ${this.leftArmDamage}`);

            // Assembly: vaddss xmm3, xmm2, dword ptr [rcx+0x14]
            // rightArmDamage at offset 0x14
            this.rightArmDamage = Memory.readFloat(this.parts.add(0x14));
            console.log(`    rightArmDamage = [rcx+0x14] = ${this.rightArmDamage}`);

            // Assembly: vaddss xmm0, xmm3, dword ptr [rcx+0x18]
            // leftLegDamage at offset 0x18
            this.leftLegDamage = Memory.readFloat(this.parts.add(0x18));
            console.log(`    leftLegDamage = [rcx+0x18] = ${this.leftLegDamage}`);

            // Assembly: vaddss xmm0, xmm0, dword ptr [rcx+0x1C]
            // rightLegDamage at offset 0x1C
            this.rightLegDamage = Memory.readFloat(this.parts.add(0x1C));
            console.log(`    rightLegDamage = [rcx+0x1C] = ${this.rightLegDamage}`);
        },

        onLeave: function(retval) {
            console.log('[+] Leave computeTotalBodyDamage');

            // Assembly returns in XMM0 low lane
            // .toFloat() reads the low 32 bits
            const totalDamage = retval.toFloat();
            console.log(`    xmm0 (totalDamage returned) = ${totalDamage}`);

            // Verify by summing in JS
            const sum = this.headDamage
                      + this.torsoDamage
                      + this.leftArmDamage
                      + this.rightArmDamage
                      + this.leftLegDamage
                      + this.rightLegDamage;
            console.log(`    Recomputed sum = head + torso + leftArm + rightArm + leftLeg + rightLeg = ${sum}`);
        }
    });
}

rpc.exports = {
    init: hookFunction
};
