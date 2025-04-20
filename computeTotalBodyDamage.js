'use strict';

// Frida script to hook the ComputeTotalBodyDamage function in StarCitizen.exe
// Exposed via RPC: call `init()` after loading the script

function hookFunction() {
    const moduleName = 'StarCitizen.exe';
    const offset     = 0x3B3790; // Address of ComputeTotalBodyDamage relative to module base

    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error(`${moduleName} not found in process!`);
        return;
    }

    const funcAddr = baseAddr.add(offset);
    console.log(`[+] Hooking ComputeTotalBodyDamage at ${funcAddr}`);

    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            // RCX holds pointer to BodyDamage struct
            this.parts = args[0];
            console.log('[+] Enter ComputeTotalBodyDamage');
            console.log(`    BodyDamage pointer: ${this.parts}`);

            // Dump raw struct data (first 32 bytes)
            const structSize = 32;
            try {
                const raw = hexdump(this.parts, { length: structSize, header: true });
                console.log('    BodyDamage raw memory:\n' + raw);
            } catch (e) {
                console.error('    Failed to dump BodyDamage struct:', e);
            }

            // Read named damage components
            this.damage = {};
            const components = [
                { name: 'headDamage',    offset: 8 },
                { name: 'torsoDamage',   offset: 12 },
                { name: 'leftArmDamage', offset: 16 },
                { name: 'rightArmDamage',offset: 20 },
                { name: 'leftLegDamage', offset: 24 },
                { name: 'rightLegDamage',offset: 28 }
            ];

            components.forEach(({name, offset}) => {
                try {
                    const val = Memory.readFloat(this.parts.add(offset));
                    this.damage[name] = val;
                    console.log(`    ${name} (offset +0x${offset.toString(16)}): ${val}`);
                } catch (e) {
                    console.error(`    Failed to read ${name} at offset ${offset}:`, e);
                }
            });
        },

        onLeave: function (retval) {
            console.log('[+] Leave ComputeTotalBodyDamage');

            // Extract the returned sum from XMM0 (low lane)
            try {
                const total = retval.toFloat();
                console.log(`    Returned totalDamage: ${total}`);
            } catch (e) {
                console.error('    Failed to extract totalDamage from retval:', retval);
            }

            // Recompute sum for verification
            if (this.damage) {
                const sum = Object.values(this.damage).reduce((acc, v) => acc + v, 0);
                console.log(`    Recomputed totalDamage: ${sum}`);
            }
        }
    });
}

hookFunction();
