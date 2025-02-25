// Frida script to instrument the sub_146675AD0 function
// Base address of the program is 0x140000000

const baseAddress = ptr('0x140000000');
const functionOffset = ptr('0x6675AD0');
const functionAddress = baseAddress.add(functionOffset);

console.log('[+] Target function address: ' + functionAddress);

function readEntityFields(actorEntityPtr) {
    // Handle null pointer protection with bitwise operations
    if (actorEntityPtr.isNull() || actorEntityPtr.compare(ptr(0)) === 0) {
        console.error("[!] Null actorEntity pointer detected");
        return null;
    }
    
    // Architecture-specific constants
    const PTR_SIZE = Process.pointerSize;
    const QWORD_SIZE = 8;
    const DWORD_SIZE = 4;
    const WORD_SIZE = 2;
    const BYTE_SIZE = 1;
    
    try {
        // Create result object with nested structure for organized data access
        const result = {
            // Core entity identification
            core: {},
            // Spatial and transform data
            spatial: {},
            // Physical properties and simulation parameters
            physical: {},
            // Entity state flags and runtime status
            state: {},
            // Velocity and kinematic data
            kinematic: {},
            // Collision and interaction data
            collision: {},
            // Entity relationships and references
            references: {},
            // Debug metadata for introspection
            _debug: {
                memAddresses: {}
            }
        };
        
        // Store base address for debug purposes
        result._debug.memAddresses.actorEntity = actorEntityPtr;
        
        // ---- Core Entity Identification ----
        result.core.vtable = actorEntityPtr.readPointer();
        result.core.entityId = actorEntityPtr.add(0x0008).readU64();
        
        // ---- Process Dynamic Entity List ----
        // Calculate effective address of pEntities field (offset 0x2848 from actorEntity base)
        const pEntitiesPtr = actorEntityPtr.add(0x2848).readPointer();
        result._debug.memAddresses.pEntities = pEntitiesPtr;
        
        if (!pEntitiesPtr.isNull() && Process.findRangeByAddress(pEntitiesPtr)) {
            // Read entity list containers
            result.references.entitiesEndPtr = actorEntityPtr.add(0x2856).readPointer();
            result.references.entitiesCapacityPtr = actorEntityPtr.add(0x2864).readPointer();
            
            // Perform first-level indirection to resolve IPhysicalEntity* from array
            const physEntityPtr = pEntitiesPtr.readPointer();
            result._debug.memAddresses.physEntity = physEntityPtr;
            
            if (!physEntityPtr.isNull() && Process.findRangeByAddress(physEntityPtr)) {
                // Extract critical physical entity fields
                result.references.physEntity = {
                    vtable: physEntityPtr.readPointer(),
                    entityId: physEntityPtr.add(0x08).readU64(),
                    entityType: physEntityPtr.add(0x10).readU32(),
                    entityFlags: physEntityPtr.add(0x14).readU32()
                };
            }
        }
        
        // ---- Spatial Data ----
        // World bounds (AABB)
        result.spatial.worldBounds = {
            min: {
                x: actorEntityPtr.add(0x0010).readDouble(),
                y: actorEntityPtr.add(0x0018).readDouble(),
                z: actorEntityPtr.add(0x0020).readDouble()
            },
            max: {
                x: actorEntityPtr.add(0x0028).readDouble(),
                y: actorEntityPtr.add(0x0030).readDouble(),
                z: actorEntityPtr.add(0x0038).readDouble()
            }
        };
        
        // Position vector (as doubles for precision)
        result.spatial.position = {
            x: actorEntityPtr.add(0x01C0).readDouble(),
            y: actorEntityPtr.add(0x01C8).readDouble(),
            z: actorEntityPtr.add(0x01D0).readDouble()
        };
        
        // Orientation quaternion
        result.spatial.orientation = {
            x: actorEntityPtr.add(0x01D8).readFloat(),
            y: actorEntityPtr.add(0x01DC).readFloat(),
            z: actorEntityPtr.add(0x01E0).readFloat(),
            w: actorEntityPtr.add(0x01E4).readFloat()
        };
        
        // Scale factor (uniform scale)
        result.spatial.scale = actorEntityPtr.add(0x01E8).readFloat();
        
        // Grid cell coordinates (spatial partitioning)
        result.spatial.gridCell = {
            x: actorEntityPtr.add(0x0236).readS16(),
            y: actorEntityPtr.add(0x0238).readS16()
        };
        
        // ---- Kinematic State ----
        // Linear velocity vector
        result.kinematic.linearVelocity = {
            x: actorEntityPtr.add(0x03C0).readFloat(),
            y: actorEntityPtr.add(0x03C4).readFloat(),
            z: actorEntityPtr.add(0x03C8).readFloat()
        };
        
        // Previous/cached velocity
        result.kinematic.cachedVelocity = {
            x: actorEntityPtr.add(0x03CC).readFloat(),
            y: actorEntityPtr.add(0x03D0).readFloat(),
            z: actorEntityPtr.add(0x03D4).readFloat()
        };
        
        // Angular velocity vector
        result.kinematic.angularVelocity = {
            x: actorEntityPtr.add(0x03D8).readFloat(),
            y: actorEntityPtr.add(0x03DC).readFloat(),
            z: actorEntityPtr.add(0x03E0).readFloat()
        };
        
        // Angular speed (magnitude of angular velocity)
        result.kinematic.angularSpeed = actorEntityPtr.add(0x03E4).readFloat();
        
        // External acceleration (gravity, etc.)
        result.kinematic.externalAcceleration = {
            x: actorEntityPtr.add(0x03F0).readFloat(),
            y: actorEntityPtr.add(0x03F4).readFloat(),
            z: actorEntityPtr.add(0x03F8).readFloat()
        };
        
        // ---- Physical Properties ----
        // Inertia tensor (diagonal matrix)
        result.physical.inertiaTensor = {
            xx: actorEntityPtr.add(0x0478).readFloat(),
            yy: actorEntityPtr.add(0x047C).readFloat(),
            zz: actorEntityPtr.add(0x0480).readFloat()
        };
        
        // Mass properties
        result.physical.mass = actorEntityPtr.add(0x0488).readFloat();
        result.physical.invMass = actorEntityPtr.add(0x0484).readFloat();
        
        // Physics simulation parameters
        result.physical.sleepSpeedThreshold = actorEntityPtr.add(0x0490).readFloat();
        result.physical.maxTimeStep = actorEntityPtr.add(0x049C).readFloat();
        result.physical.dampingRatio = actorEntityPtr.add(0x04A0).readFloat();
        result.physical.frictionCoeff = actorEntityPtr.add(0x04B4).readFloat();
        result.physical.restitutionCoeff = actorEntityPtr.add(0x04B8).readFloat();
        
        // ---- State Flags and Runtime Status ----
        result.state.flags = actorEntityPtr.add(0x0520).readU32();
        result.state.stateFlags = actorEntityPtr.add(0x2416).readU16();
        result.state.simulationFlags = actorEntityPtr.add(0x2418).readU8();
        result.state.contactFlags = actorEntityPtr.add(0x2419).readU8();
        
        // Decompose state flags for easier analysis
        result.state.flagsAnalysis = {
            isDisabled: (result.state.flags & 0x20) !== 0,
            isConstrained: (result.state.flags & 0x40) !== 0,
            isAutoSleep: (result.state.flags & 0x80) !== 0,
            isSleeping: (result.state.flags & 0x100) !== 0
        };
        
        // Decompose simulation flags
        result.state.simulationFlagsAnalysis = {
            inCollision: (result.state.simulationFlags & 0x01) !== 0,
            forceApplied: (result.state.simulationFlags & 0x02) !== 0,
            requiresStep: (result.state.simulationFlags & 0x04) !== 0,
            timestepActive: (result.state.simulationFlags & 0x08) !== 0,
            velocityModified: (result.state.simulationFlags & 0x10) !== 0,
            positionModified: (result.state.simulationFlags & 0x40) !== 0
        };
        
        // ---- Collision Data ----
        result.collision.physicalEntityType = actorEntityPtr.add(0x0244).readU32();
        
        // Collision filter
        result.collision.collisionFilter = {
            physicalFlags: actorEntityPtr.add(0x0524).readU16(),
            physicalFlagsOR: actorEntityPtr.add(0x0526).readU16(),
            flagsGroupDst: actorEntityPtr.add(0x0530).readU8(),
            flagsGroupSrc: actorEntityPtr.add(0x0531).readU8()
        };
        
        // Latest contact point
        result.collision.contactPoint = {
            x: actorEntityPtr.add(0x0950).readFloat(),
            y: actorEntityPtr.add(0x0954).readFloat(),
            z: actorEntityPtr.add(0x0958).readFloat()
        };
        
        // ---- Entity References ----
        const pOwnerEntityPtr = actorEntityPtr.add(0x0184).readPointer();
        result.references.ownerEntityPtr = pOwnerEntityPtr;
        result.references.hasOwner = !pOwnerEntityPtr.isNull() && Process.findRangeByAddress(pOwnerEntityPtr);
        
        const pConstraintEntityPtr = actorEntityPtr.add(0x2552).readPointer();
        result.references.constraintEntityPtr = pConstraintEntityPtr;
        result.references.hasConstraint = !pConstraintEntityPtr.isNull() && Process.findRangeByAddress(pConstraintEntityPtr);
        
        const pPhysWorldPtr = actorEntityPtr.add(0x0704).readPointer();
        result.references.physWorldPtr = pPhysWorldPtr;
        
        // Read component subsystem pointers
        result.references.components = {
            hasFoliageInteraction: !actorEntityPtr.add(0x1624).readPointer().isNull(),
            hasWaterInteraction: !actorEntityPtr.add(0x1784).readPointer().isNull()
        };
        
        return result;
    } catch (e) {
        // Exception handler for access violations (EXCEPTION_ACCESS_VIOLATION)
        console.error("[!] Memory access violation during entity parsing: " + e.message);
        console.error("[!] Error occurred at: " + e.stack);
        return null;
    }
}

Interceptor.attach(functionAddress, {
    onEnter: function(args) {
        console.log('=== Entering sub_146675AD0 ===');
        this.entityPtr = args[0];
        
        console.log('Arguments:');
        console.log('  a1 (entity pointer): ' + this.entityPtr);

        console.log(
            JSON.stringify(
                readEntityFields(
                    this.entityPtr,
                ),
                null,
                4,
            ),
        );
    },
    
    onLeave: function(retval) {
        console.log('=== Leaving sub_146675AD0 ===');
        console.log('Return value: ' + retval);
        
        console.log('entityPtr: ' + this.entityPtr);
        try {
            if (this.entityPtr && this.entityPtr.toInt32() !== 0) {
                console.log('Updated entity data:');
                return;
            } else {
                console.log('Entity pointer no longer valid');
            }
        } catch (e) {
            console.log('Error reading updated entity data: ' + e);
        }

        console.log('=== Function execution completed ===');
    }
});

console.log('[+] Instrumentation complete');