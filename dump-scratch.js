/**
 * Frida instrumentation script for CSCBodyHealthComponent::ProcessHit
 * Target function: sub_146321C50
 * Address: 0x146321C50
 * Calling convention: __fastcall (x64)
 * Parameters: 
 *   - RCX: this pointer (CSCBodyHealthComponent instance)
 *   - RDX: HitInfo structure pointer
 * Return: double (likely damage value or status)
 */

// Configuration constants derived from static analysis
const PROCESS_HIT_ADDR = ptr('0x146321C50');
const OFFSETS = {
    // CSCBodyHealthComponent offsets
    HEALTH_CONFIG: 0x260,
    ACTOR_HANDLE: 0x268,
    INVULNERABLE_FLAG: 0x278,
    ZONE_CHANGE_COUNTER: 0x290,
    BODY_PARTS: 0x220,
    BODY_PARTS_END: 0x228,
    HIT_QUEUE: 0x238,
    HIT_QUEUE_END: 0x240,
    BODY_MAPPING: 0x258,
    TRACKVIEW_DATA: 0x5A8,
    LAST_SHOOTER: 0x570,
    LAST_DAMAGE_TYPE: 0x5A0,
    
    // HitInfo structure offsets
    SHOOTER_HANDLE: 0x00,
    WEAPON_HANDLE: 0x10,
    DAMAGE_VALUE: 0x18,
    HIT_PART_ID: 0x78,
    DAMAGE_TYPE: 0x74,
    FLAGS: 0xE8,
    SPLIT_OVER_PARTS_FLAG: 0xED,
    RECENT_DRIVER_FLAG: 0xEC,
    SKIP_INVULNERABLE_FLAG: 0xEA,
    SUPPRESS_SOUND_FLAG: 0xEB,
    BULLET_TIME_SCALE: 0x48,
    SHOOTER_CHANNEL: 0xAA,
    
    // HealthConfig offsets
    IS_INVULNERABLE: 0x48,
    VULNERABLE_ONLY_TO_PLAYER: 0x49
};

// Damage type enumeration derived from analysis
const DAMAGE_TYPES = {
    0: "UNDEFINED",
    1: "BULLET",
    2: "COLLISION", 
    7: "SCRIPTED",
    13: "ENVIRONMENTAL",
    17: "SPECIAL"
};

// Global state tracking
let hookState = {
    callCount: 0,
    damageHistory: [],
    invocationDepth: 0,
    activeInvocations: new Map(),
};

// Utility functions for safe memory reading
function safeReadPointer(ptr) {
    try {
        return ptr.isNull() ? NULL : ptr.readPointer();
    } catch (e) {
        return NULL;
    }
}

function safeReadU32(ptr) {
    try {
        return ptr.isNull() ? 0 : ptr.readU32();
    } catch (e) {
        return 0;
    }
}

function safeReadFloat(ptr) {
    try {
        return ptr.isNull() ? 0.0 : ptr.readFloat();
    } catch (e) {
        return 0.0;
    }
}

function safeReadU8(ptr) {
    try {
        return ptr.isNull() ? 0 : ptr.readU8();
    } catch (e) {
        return 0;
    }
}

// Function to extract HitInfo structure
function parseHitInfo(hitInfoPtr) {
    if (hitInfoPtr.isNull()) {
        return { valid: false };
    }
    
    try {
        const hitInfo = {
            valid: true,
            shooterHandle: hitInfoPtr.readPointer().and(0xFFFFFFFFFFFF),
            weaponHandle: hitInfoPtr.add(0x10).readPointer().and(0xFFFFFFFFFFFF),
            damageValue: safeReadFloat(hitInfoPtr.add(OFFSETS.DAMAGE_VALUE)),
            hitPartId: safeReadU32(hitInfoPtr.add(OFFSETS.HIT_PART_ID)),
            damageType: safeReadU32(hitInfoPtr.add(OFFSETS.DAMAGE_TYPE)),
            damageTypeName: DAMAGE_TYPES[safeReadU32(hitInfoPtr.add(OFFSETS.DAMAGE_TYPE))] || "UNKNOWN",
            bulletTimeScale: safeReadFloat(hitInfoPtr.add(OFFSETS.BULLET_TIME_SCALE)),
            shooterChannel: hitInfoPtr.add(OFFSETS.SHOOTER_CHANNEL).readU16(),
            flags: {
                skipInvulnerable: safeReadU8(hitInfoPtr.add(OFFSETS.SKIP_INVULNERABLE_FLAG)) !== 0,
                suppressSound: safeReadU8(hitInfoPtr.add(OFFSETS.SUPPRESS_SOUND_FLAG)) !== 0,
                recentDriver: safeReadU8(hitInfoPtr.add(OFFSETS.RECENT_DRIVER_FLAG)) !== 0,
                splitOverParts: safeReadU8(hitInfoPtr.add(OFFSETS.SPLIT_OVER_PARTS_FLAG)) !== 0
            }
        };
        
        // Extract damage location coordinates (offset 0x1C - 0x28 appears to be a vector)
        hitInfo.impactLocation = {
            x: safeReadFloat(hitInfoPtr.add(0x1C)),
            y: safeReadFloat(hitInfoPtr.add(0x20)),
            z: safeReadFloat(hitInfoPtr.add(0x24))
        };
        
        // Extract damage direction (offset 0x38 - 0x44)
        hitInfo.damageDirection = {
            x: safeReadFloat(hitInfoPtr.add(0x38)),
            y: safeReadFloat(hitInfoPtr.add(0x3C)),
            z: safeReadFloat(hitInfoPtr.add(0x40))
        };
        
        return hitInfo;
    } catch (e) {
        console.error(`[!] Error parsing HitInfo: ${e}`);
        return { valid: false, error: e.toString() };
    }
}

// Function to extract component state
function extractComponentState(thisPtr) {
    try {
        const state = {
            healthConfigPtr: safeReadPointer(thisPtr.add(OFFSETS.HEALTH_CONFIG)),
            actorHandle: thisPtr.add(OFFSETS.ACTOR_HANDLE).readU64().toString(16),
            isInvulnerable: false,
            vulnerableOnlyToPlayer: false,
            zoneChangeCounter: safeReadU32(thisPtr.add(OFFSETS.ZONE_CHANGE_COUNTER)),
            bodyMappingPtr: safeReadPointer(thisPtr.add(OFFSETS.BODY_MAPPING))
        };
        
        // Read health config flags
        if (!state.healthConfigPtr.isNull()) {
            state.isInvulnerable = safeReadU8(state.healthConfigPtr.add(OFFSETS.IS_INVULNERABLE)) !== 0;
            state.vulnerableOnlyToPlayer = safeReadU8(state.healthConfigPtr.add(OFFSETS.VULNERABLE_ONLY_TO_PLAYER)) !== 0;
        }
        
        // Read body parts array info
        const bodyPartsStart = safeReadPointer(thisPtr.add(OFFSETS.BODY_PARTS));
        const bodyPartsEnd = safeReadPointer(thisPtr.add(OFFSETS.BODY_PARTS_END));
        if (!bodyPartsStart.isNull() && !bodyPartsEnd.isNull()) {
            const elementSize = 0x18; // Derived from decompilation
            state.bodyPartCount = bodyPartsEnd.sub(bodyPartsStart).toInt32() / elementSize;
        }
        
        // Extract actor information from handle
        const actorHandleValue = thisPtr.add(OFFSETS.ACTOR_HANDLE).readPointer();
        const maskedHandle = actorHandleValue.and(0xFFFFFFFFFFFF); // Mask lower 48 bits

        console.log(actorHandleValue, maskedHandle);
        
        if (!maskedHandle.equals(ptr(0))) {
            try {
                const actorEntityPtr = maskedHandle;
                if (!actorEntityPtr.isNull()) {
                    // Read CActorEntity fields
                    const entityPtr = safeReadPointer(actorEntityPtr.add(0x8)).and(0xFFFFFFFFFFFF); // entity_ at offset 0xC0
                    const namePtr = safeReadPointer(actorEntityPtr.add(0xD8));   // name_ at offset 0xD8
                    const physicsStepTime = safeReadFloat(actorEntityPtr.add(0x4E4)); // physics_step_time_ at offset 0x4E4

                    state.actorInfo = {
                        entityPtr: entityPtr.isNull() ? "NULL" : entityPtr.toString(),
                        name: "",
                        physicsStepTime: physicsStepTime
                    };
                    
                    // Try to read the name string
                    if (!namePtr.isNull()) {
                        try {
                            state.actorInfo.name = namePtr.readCString();
                        } catch (e) {
                            //state.actorInfo.name = "READ_ERROR";
                        }
                    }
                    
                    if (!state.actorInfo.name && !entityPtr.isNull()) {
                        // If namePtr is null, try to get name from the entity
                        try {
                            const entityNamePtr = safeReadPointer(entityPtr.add(0x298)); // name_ at offset 0x298

                            if (!entityNamePtr.isNull()) {
                                state.actorInfo.name = entityNamePtr.readCString();
                            }
                        } catch (e) {
                            state.actorInfo.name = "ENTITY_READ_ERROR";
                        }
                    }
                }
            } catch (e) {
                console.error(`[!] Error reading actor entity: ${e}`);
            }
        }
        
        return state;
    } catch (e) {
        console.error(`[!] Error extracting component state: ${e}`);
        console.error(e.stack);
        return null;
    }
}

// Main hook implementation
Interceptor.attach(PROCESS_HIT_ADDR, {
  onEnter: function(args) {
      const invocationId = ++hookState.callCount;
      const startTime = Date.now();
      const depth = ++hookState.invocationDepth;
      
      // Store invocation data in the Map using thread ID as key
      const threadId = Process.getCurrentThreadId();
      hookState.activeInvocations.set(threadId, {
          invocationId,
          startTime,
          depth,
          thisPtr: args[0],
          hitInfoPtr: args[1]
      });

      console.log('penis');
      console.log(args[0], args[1], args[2], args[3]);

      const indent = '  '.repeat(Math.max(0, depth - 1));
      
      console.log(`\n${indent}[→] CSCBodyHealthComponent::ProcessHit #${invocationId}`);
      console.log(`${indent}    Thread: ${threadId}`);
      console.log(`${indent}    This: ${args[0]}`);
      console.log(`${indent}    HitInfo: ${args[1]}`);
      
      // Extract and log component state
      const componentState = extractComponentState(args[0]);
      if (componentState) {
          console.log(`${indent}    Component State:`);
          console.log(`${indent}      - Actor Handle: 0x${componentState.actorHandle}`);
          console.log(`${indent}      - Invulnerable: ${componentState.isInvulnerable}`);
          console.log(`${indent}      - Player Only: ${componentState.vulnerableOnlyToPlayer}`);
          console.log(`${indent}      - Zone Changes: ${componentState.zoneChangeCounter}`);
          console.log(`${indent}      - Body Parts: ${componentState.bodyPartCount || 'N/A'}`);
          
          // Log actor information if available
          if (componentState.actorInfo) {
              console.log(`${indent}      - Actor Info:`);
              console.log(`${indent}        - Entity Ptr: ${componentState.actorInfo.entityPtr}`);
              console.log(`${indent}        - Name: ${componentState.actorInfo.name}`);
              console.log(`${indent}        - Physics Step Time: ${componentState.actorInfo.physicsStepTime}`);
          }
      }
      
      // Extract and log hit information
      const hitInfo = parseHitInfo(args[1]);
      if (hitInfo.valid) {
          console.log(`${indent}    Hit Information:`);
          console.log(`${indent}      - Shooter: 0x${hitInfo.shooterHandle}`);
          console.log(`${indent}      - Weapon: 0x${hitInfo.weaponHandle}`);
          console.log(`${indent}      - Damage: ${hitInfo.damageValue.toFixed(4)}`);
          console.log(`${indent}      - Type: ${hitInfo.damageTypeName} (${hitInfo.damageType})`);
          console.log(`${indent}      - Part ID: ${hitInfo.hitPartId}`);
          console.log(`${indent}      - Location: (${hitInfo.impactLocation.x.toFixed(2)}, ${hitInfo.impactLocation.y.toFixed(2)}, ${hitInfo.impactLocation.z.toFixed(2)})`);
          console.log(`${indent}      - Direction: (${hitInfo.damageDirection.x.toFixed(2)}, ${hitInfo.damageDirection.y.toFixed(2)}, ${hitInfo.damageDirection.z.toFixed(2)})`);
          console.log(`${indent}      - Flags: Skip Invuln=${hitInfo.flags.skipInvulnerable}, Split=${hitInfo.flags.splitOverParts}, Recent=${hitInfo.flags.recentDriver}`);
          
          // Store hit info in the invocation data
          const invocationData = hookState.activeInvocations.get(threadId);
          if (invocationData) {
              invocationData.hitInfo = hitInfo;
          }
      }
      
      // Capture initial CPU state for forensic analysis
      const invocationData = hookState.activeInvocations.get(threadId);
      if (invocationData) {
          invocationData.initialContext = {
              rsp: this.context.rsp.toString(16),
              rbp: this.context.rbp.toString(16),
              rflags: this.context.rflags || 'N/A'
          };
      }
  },
  
  onLeave: function(retval) {
      const threadId = Process.getCurrentThreadId();
      const invocationData = hookState.activeInvocations.get(threadId);
      
      if (!invocationData) {
          console.error('[!] No invocation data found for thread ' + threadId);
          return;
      }
      
      const duration = Date.now() - invocationData.startTime;
      const result = retval.readDouble();

      const indent = '  '.repeat(Math.max(0, invocationData.depth - 1));
      
      console.log(`${indent}[←] CSCBodyHealthComponent::ProcessHit #${invocationData.invocationId}`);
      console.log(`${indent}    Duration: ${duration}ms`);
      console.log(`${indent}    Return Value: ${result}`);
      
      // Check for state changes
      const postState = extractComponentState(invocationData.thisPtr);
      if (postState) {
          // Check if last shooter was updated
          const lastShooter = invocationData.thisPtr.add(OFFSETS.LAST_SHOOTER).readU64().toString(16);
          console.log(`${indent}    Post-State:`);
          console.log(`${indent}      - Last Shooter: 0x${lastShooter}`);
          console.log(`${indent}      - Last Damage Type: ${safeReadU32(invocationData.thisPtr.add(OFFSETS.LAST_DAMAGE_TYPE))}`);
      }
      
      // Track damage history
      if (invocationData.hitInfo && invocationData.hitInfo.valid) {
          hookState.damageHistory.push({
              timestamp: Date.now(),
              invocationId: invocationData.invocationId,
              damage: invocationData.hitInfo.damageValue,
              type: invocationData.hitInfo.damageTypeName,
              result: result,
              duration: duration
          });
          
          // Keep only last 100 entries
          if (hookState.damageHistory.length > 100) {
              hookState.damageHistory.shift();
          }
      }
      
      hookState.invocationDepth--;
      // Clean up the invocation data
      hookState.activeInvocations.delete(threadId);
  }
});

// Additional hooks for related functions referenced in the decompilation

// Hook sub_1462C6640 - appears to get current health (returns double)
// const GET_HEALTH_ADDR = ptr('0x1462C6640');
// Interceptor.attach(GET_HEALTH_ADDR, {
//     onEnter: function(args) {
//         this.componentPtr = args[0];
//     },
//     onLeave: function(retval) {
//         // CRITICAL: For functions returning floating-point values,
//         // the return value is in XMM0 register, not a pointer.
//         // Must convert to number, not dereference as pointer.
//         try {
//             // Method 1: Direct conversion (most reliable for double returns)
//             const health = parseFloat(retval.toString());
            
//             // Validate the result is a reasonable health value
//             if (!isNaN(health) && isFinite(health)) {
//                 console.log(`    [i] GetHealth(${this.componentPtr}) = ${health.toFixed(4)}`);
//             } else {
//                 // Method 2: Access via context if Method 1 fails
//                 // Some Frida versions may require explicit XMM0 access
//                 if (this.context && this.context.xmm0) {
//                     const xmm0Bytes = this.context.xmm0;
//                     // XMM0 contains 128 bits, double is in lower 64 bits
//                     const buffer = new ArrayBuffer(8);
//                     const view = new DataView(buffer);
//                     // Copy lower 64 bits of XMM0 to buffer
//                     for (let i = 0; i < 8; i++) {
//                         view.setUint8(i, xmm0Bytes[i]);
//                     }
//                     const healthFromXmm0 = view.getFloat64(0, true); // little-endian
//                     console.log(`    [i] GetHealth(${this.componentPtr}) = ${healthFromXmm0.toFixed(4)} (via XMM0)`);
//                 } else {
//                     console.log(`    [!] GetHealth(${this.componentPtr}) returned invalid floating-point value`);
//                 }
//             }
//         } catch (e) {
//             console.error(`    [!] Error extracting health value: ${e}`);
//             // Fallback: Log raw retval for debugging
//             console.log(`    [!] Raw retval: ${retval} (type: ${typeof retval})`);
//         }
//     }
// });

// Hook sub_146295950 - appears to process damage application
const APPLY_DAMAGE_ADDR = ptr('0x146295950');
Interceptor.attach(APPLY_DAMAGE_ADDR, {
    onEnter: function(args) {
        console.log(`    [i] ApplyDamage(component=${args[0]}, damageInfo=${args[1]})`);
    },
    onLeave: function(retval) {
        const applied = retval.readU8();
        console.log(`    [i] ApplyDamage result: ${applied ? 'SUCCESS' : 'FAILED'}`);
    }
});

// Command interface for runtime analysis
rpc.exports = {
    getDamageHistory: function() {
        return hookState.damageHistory;
    },
    
    getCallCount: function() {
        return hookState.callCount;
    },
    
    resetStats: function() {
        hookState.callCount = 0;
        hookState.damageHistory = [];
        console.log('[*] Statistics reset');
    },
    
    // Force invulnerability by patching the health config check
    toggleInvulnerability: function(componentPtr) {
        try {
            const ptr = new NativePointer(componentPtr);
            const healthConfigPtr = safeReadPointer(ptr.add(OFFSETS.HEALTH_CONFIG));
            if (!healthConfigPtr.isNull()) {
                const currentValue = healthConfigPtr.add(OFFSETS.IS_INVULNERABLE).readU8();
                healthConfigPtr.add(OFFSETS.IS_INVULNERABLE).writeU8(currentValue ? 0 : 1);
                console.log(`[*] Invulnerability toggled to: ${!currentValue}`);
                return !currentValue;
            }
        } catch (e) {
            console.error(`[!] Failed to toggle invulnerability: ${e}`);
        }
        return false;
    }
};

console.log('[+] CSCBodyHealthComponent::ProcessHit instrumentation active');
console.log('[+] Monitoring damage processing at ' + PROCESS_HIT_ADDR);
