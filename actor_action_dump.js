/*
 * CActorEntity::Action  (absolute address 0x1466BAFD0)
 *
 *  ─ Offset 0x970  : 16-bit “pose / stance” flags
 *      bit 2  – No-clip / ghost stance
 *      bits 4-8 – 5-bit pose code (crouch, prone, cover …)
 *
 *  ─ Offset 0x972  : 8-bit “look / impulse” status
 *      bit 0  – Reverse impulse / just-reset marker
 *      bit 4  – Treat look vector as *absolute*
 *      bit 6  – Direction not unit-length
 *
 *  ─ Offset 0x973  : 8-bit secondary move flags
 *      bit 1  – Relative aim permitted
 *      bit 2  – Forced on-ground marker (cleared in no-clip)
 *
 *  ─ Offset 0x978 & 0x00C8 : 64-bit spin locks
 *      bit 21 (mask 0x200000) – thread-owner flag
 */

const BASE = ptr('0x1466BAFD0');

/* ------- helpers ------------------------------------------------------- */

function readFlags(base) {
    return {
        pose      : Memory.readU16(base.add(0x970)),
        look      : Memory.readU8 (base.add(0x972)),
        move2     : Memory.readU8 (base.add(0x973)),
        lockActor : Memory.readU64(base.add(0x978)).toNumber(),
        lockUpdate: Memory.readU64(base.add(0x00C8)).toNumber()
    };
}

function fmt(v, n) { return '0x' + v.toString(16).padStart(n, '0'); }

function show(label, stamp, f) {
    console.log(`${label} ${stamp}`);
    console.log(
        `  poseFlags  = ${fmt(f.pose,4)}  ` +
        `noClip:${(f.pose>>2)&1}  poseCode:${(f.pose>>4)&0x1F}`
    );
    console.log(
        `  lookFlags  = ${fmt(f.look,2)}  ` +
        `revImp:${f.look&1}  absLook:${(f.look>>4)&1}  badDir:${(f.look>>6)&1}`
    );
    console.log(
        `  move2Flags = ${fmt(f.move2,2)}  ` +
        `relAim:${(f.move2>>1)&1}  onGround:${(f.move2>>2)&1}`
    );
    console.log(
        `  lockActor.bit21 = ${(f.lockActor>>21)&1}  ` +
        `lockUpdate.bit21 = ${(f.lockUpdate>>21)&1}`
    );
}

function diff(before, after) {
    for (const k of Object.keys(before)) {
        if (before[k] !== after[k])
            console.log(`  Δ ${k}: ${fmt(before[k], 8)} → ${fmt(after[k], 8)}`);
    }
}

/* ------- hook ---------------------------------------------------------- */

const toggle_noclip = a1 => {
    const poseFlags = Memory.readU16(a1.add(0x970));
    const noclipBit = 1 << 2;
    const newPoseFlags = poseFlags ^ noclipBit; // Toggle bit 2
    Memory.writeU16(a1.add(0x970), newPoseFlags);
    //console.log(`  > Toggled no-clip bit: ${(poseFlags & noclipBit) ? "ON → OFF" : "OFF → ON"}`);
};

Interceptor.attach(BASE, {
    onEnter(args) {
        this.a1      = args[0];
        this.before  = readFlags(this.a1);
        //show('[sub_1466BAFD0] ' + this.a1, 'BEFORE', this.before);

        // Toggle no-clip by flipping bit 2 in pose flags
        toggle_noclip(this.a1);
    },

    onLeave(retval) {
        //const after = readFlags(this.a1);
        //show('[sub_1466BAFD0] ' + this.a1, 'AFTER ', after);
        //diff(this.before, after);
        toggle_noclip(this.a1);

        // retval is left untouched:
        return retval;
    }
});
