//  mineable_hooks.js
//  CryEngine - GameSDK - CEntityComponentMineable(+Health) runtime traces
//  ⟦ETHOUT – scientific / exhaustive instrumentation⟧
'use strict';

/* ------------------------------------------------------------------ *
 *  Helper – safe field read                                           *
 * ------------------------------------------------------------------ */
 const VERBOSE = 1;               // flip to 0 at run-time if too chatty
 const seenEnter = new WeakMap(); //  suppress duplicate ENTER/LEAVE pairs

 function hex(x, pad = 8) {
     const s = x.toString(16);
     return '0x' + '0'.repeat(Math.max(0, pad - s.length)) + s;
 }
 function readVal(addr, sz) {
     try {
         if (sz === 1)  return Memory.readU8(addr);
         if (sz === 4)  return Memory.readU32(addr);
         return Memory.readPointer(addr);
     } catch (_) { return 0; }
 }
 function dumpFields(selfPtr, fieldArray) {
     fieldArray.forEach(f => {
         const v = readVal(ptr(selfPtr).add(f.off), f.sz);
         const txt = (f.sz === 8 ? hex(v.toUInt32 ? v.toUInt32() : v) : hex(v, f.sz * 2));
         console.log(`    +${f.off.toString(16).padStart(4,'0')} ${f.desc} = ${txt}`);
     });
 }

/* ------------------------------------------------------------------ *
 *  Hook table – one row per disassembly symbol                        *
 * ------------------------------------------------------------------ */
const hooks = [
/* 1 */{
    ea: '0x14323A570',
    name: 'CEntityComponentMineableHealth::BindRM',
    fields: [
        {off: 0x218, sz: 8, desc: 'Breakable-handle'},
        {off: 0x1B8, sz: 8, desc: 'RM m_rmAuthorityRequestHit'},
        {off: 0x1E8, sz: 8, desc: 'RM m_rmAuthorityRequestHitWithJointOffsets'},
        {off: 0x008, sz: 8, desc: 'Entity-ptr (IActor*)'},
        {off: 0x010, sz: 2, desc: 'Network flags (word)'}
    ]
},
/* 2 */{
    ea: '0x14318AA70',
    name: 'CEntityComponentMineableHealth::LinearMapClampedSafe',
    fields: [ ]                //  pure math helper – no structures
},
/* 3 */{
    ea: '0x1431D0C30',
    name: 'CEntityComponentMineableHealth::AddStatObjToDamageMap',
    fields: [
        {off: 0x218, sz: 8, desc: 'Breakable component handle'},
        {off: 0x008, sz: 8, desc: 'Entity-ptr'},
        {off: 0x220, sz: 8, desc: 'Damage-map root'},
        {off: 0x226, sz: 1, desc: '#sub-objects (byte)'}
    ]
},
/* 4 */{
    ea: '0x143D915F0',
    name: 'CEntityComponentMineable::SvTryDestroy',
    fields: [
        {off: 0x300, sz: 8, desc: 'Explode-state struct'},
        {off: 0x308, sz: 1, desc: 'm_isDestroying'},
        {off: 0x320, sz: 1, desc: 'forceCatastrophic'},
        {off: 0x6F0, sz: 4, desc: 'health-ratio'},
        {off: 0x748, sz: 8, desc: 'RM RmMulticastDestroy'},
        {off: 0x3A8, sz: 8, desc: 'TargetingControllers root'}
    ]
},
/* 5 */{
    ea: '0x143D8F980',
    name: 'CEntityComponentMineable::SvDestroy',
    fields: [
        {off: 0x328, sz: 8, desc: 'vector<child> begin'},
        {off: 0x330, sz: 8, desc: 'vector<child> end'},
        {off: 0x6F0, sz: 4, desc: 'health-ratio'},
        {off: 0x300, sz: 8, desc: 'Explode-state struct (again)'},
        {off: 0x688, sz: 8, desc: 'lastShooterId'},
        {off: 0x708, sz: 4, desc: 'extractedFactor'},
        {off: 0x728, sz: 4, desc: 'numChildren'}
    ]
},
/* 6 */{
    ea: '0x143D8B830',
    name: 'CEntityComponentMineable::SpawnChildRocks',
    fields: [
        {off: 0x398, sz: 8, desc: 'Breakable-handle'},
        {off: 0x6F0, sz: 4, desc: 'health-ratio'},
        {off: 0x328, sz: 8, desc: 'vector<child> begin'},
        {off: 0x730, sz: 4, desc: '#pieces expected'}
    ]
},
/* 7 */{
    ea: '0x143D693A0',
    name: 'CEntityComponentMineable::RegisterRemoteMessages',
    fields: [
        {off: 0x688, sz: 8, desc: 'RM lastShooterId'},
        {off: 0x6A8, sz: 4, desc: 'RM power'},
        {off: 0x6C8, sz: 4, desc: 'RM controlledBreakingPool'},
        {off: 0x708, sz: 4, desc: 'RM extractedFactor'},
        {off: 0x728, sz: 4, desc: 'RM numChildren'},
        {off: 0x300, sz: 8, desc: 'RM mineableDestroying'},
        {off: 0x748, sz: 8, desc: 'RMI RmMulticastDestroy'},
        {off: 0x778, sz: 8, desc: 'RMI RmAuthorityReadyToExplode'}
    ]
},
/* 8 */{
    ea: '0x143D742E0',
    name: 'CEntityComponentMineable::RmAuthorityReadyToExplode',
    fields: [
        {off: 0x394, sz: 1, desc: 'readyToExplode'},
        {off: 0x730, sz: 4, desc: '#pieces exploded'}
    ]
},
/* 9 */{
    ea: '0x143D6BBA0',
    name: 'CEntityComponentMineable::RemoveTargettingController',
    fields: [
        {off: 0x3B8, sz: 4, desc: 'Spin-lock m_targettingControllersLock'},
        {off: 0x8F8, sz: 8, desc: 'std::map<float,int> root'}
    ]
},
/*10*/{
    ea: '0x143D3C520',
    name: 'CEntityComponentMineable::OnSpawnEntity',
    fields: [
        {off: 0x6B8, sz: 4, desc: 'Spawn-gate lock'},
        {off: 0x6C0, sz: 4, desc: 'poolIndex'},
        {off: 0x2B8, sz: 8, desc: 'vector<child> begin'}
    ]
},
/*11*/{
    ea: '0x143D330D0',
    name: 'CEntityComponentMineable::OnHitByMiningLaser',
    fields: [
        {off: 0x308, sz: 1, desc: 'm_isDestroying'},
        {off: 0x688, sz: 8, desc: 'lastShooterId'},
        {off: 0x6A8, sz: 4, desc: 'power'},
        {off: 0x6C8, sz: 4, desc: 'controlledBreakingPool'},
        {off: 0x300, sz: 8, desc: 'mineableDestroying flag'}
    ]
},
/*12*/{
    ea: '0x143B89370',
    name: 'CEntityComponentMineable::SendEventToControllers',
    fields: [
        {off: 0x3B8, sz: 4, desc: 'Spin-lock'},
        {off: 0x8F8, sz: 8, desc: 'Controllers map root'}
    ]
},
/*13*/{
    ea: '0x143C8CB70',
    name: 'CEntityComponentMineable::AddTargettingController',
    fields: [
        {off: 0x3B8, sz: 4, desc: 'Spin-lock'},
        {off: 0x8F8, sz: 8, desc: 'Controllers map root'}
    ]
}
];

/* ------------------------------------------------------------------ *
 *  Install every hook                                                 *
 * ------------------------------------------------------------------ */
hooks.forEach(h => {
    try {
        const addr = ptr(h.ea);
        console.log(`[*] Hooking ${h.name} @ ${h.ea}`);
        Interceptor.attach(addr, {
            onEnter(args) {
                this.self = args[0];
                console.log(`\n>>> ENTER ${h.name}`);
                if (h.fields.length && this.self) {
                    dumpFields(this.self, h.fields);
                }
            },
            onLeave(retval) {
                console.log(`<<< LEAVE ${h.name}  →  ${hex(retval.toInt32())}\n`);
            }
        });
    } catch (err) {
        console.error(`[-] Failed to hook ${h.name}: ${err}`);
    }
});
