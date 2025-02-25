// Frida script to instrument the sub_146675AD0 function
// Base address of the program is 0x140000000

const baseAddress = ptr('0x140000000');
const functionOffset = ptr('0x6675AD0');
const functionAddress = baseAddress.add(functionOffset);

console.log('[+] Target function address: ' + functionAddress);

function dumpCActorEntity(entityPtr) {
    // Architecture-specific constants
    const PTR_SIZE = Process.pointerSize;
    const QWORD_SIZE = 8;
    const DWORD_SIZE = 4;
    const WORD_SIZE = 2;
    const BYTE_SIZE = 1;
    
    // Helper function to safely read memory of various types
    function safeRead(address, size, type) {
        try {
            if (!address || address.isNull()) return "<null>";
            
            switch(type) {
                case "ptr":   return address.readPointer();
                case "u64":   return address.readU64();
                case "i64":   return address.readS64();
                case "u32":   return address.readU32();
                case "i32":   return address.readS32();
                case "u16":   return address.readU16();
                case "i16":   return address.readS16();
                case "u8":    return address.readU8();
                case "i8":    return address.readS8();
                case "float": return address.readFloat();
                case "double":return address.readDouble();
                case "cstr":  return address.readCString();
                case "vec3f": return {
                    x: address.readFloat(),
                    y: address.add(4).readFloat(),
                    z: address.add(8).readFloat()
                };
                case "vec3d": return {
                    x: address.readDouble(),
                    y: address.add(8).readDouble(), 
                    z: address.add(16).readDouble()
                };
                case "quat": return {
                    x: address.readFloat(),
                    y: address.add(4).readFloat(),
                    z: address.add(8).readFloat(), 
                    w: address.add(12).readFloat()
                };
            }
        } catch(e) {
            return `<error: ${e.message}>`;
        }
        return "<unknown>";
    }
    
    // Function to format values for output
    function formatValue(value, type) {
        if (value === null || value === undefined) return "<null>";
        
        if (typeof value === 'object') {
            if (type === "vec3f" || type === "vec3d")
                return `{x: ${value.x.toFixed(6)}, y: ${value.y.toFixed(6)}, z: ${value.z.toFixed(6)}}`;
            if (type === "quat")
                return `{x: ${value.x.toFixed(6)}, y: ${value.y.toFixed(6)}, z: ${value.z.toFixed(6)}, w: ${value.w.toFixed(6)}}`;
            return JSON.stringify(value);
        }
        
        if (type === "float" || type === "double")
            return value.toFixed(6);
        
        if (type === "ptr")
            return `0x${value.toString(16)}`;
            
        if (type.startsWith("u") || type.startsWith("i"))
            return `${value} (0x${value.toString(16)})`;
            
        return String(value);
    }
    
    // Begin entity data extraction
    const baseAddr = ptr(entityPtr);
    console.log(`\n=== CActorEntity at ${baseAddr} ===\n`);
    
    // Create a structured dump of the entity
    const entityData = {
        // Core entity data
        vtable:                 { offset: 0x0000, value: safeRead(baseAddr.add(0x0000), PTR_SIZE, "ptr"), type: "ptr" },
        entityId:               { offset: 0x0008, value: safeRead(baseAddr.add(0x0008), QWORD_SIZE, "u64"), type: "u64" },
        
        // WorldBounds
        worldBoundsMin:         { offset: 0x0010, value: safeRead(baseAddr.add(0x0010), 24, "vec3d"), type: "vec3d" },
        worldBoundsMax:         { offset: 0x0028, value: safeRead(baseAddr.add(0x0028), 24, "vec3d"), type: "vec3d" },
        
        // Entity references
        pOwnerEntity:           { offset: 0x0184, value: safeRead(baseAddr.add(0x0184), PTR_SIZE, "ptr"), type: "ptr" },
        pPhysicalEntityLinks:   { offset: 0x018C, value: safeRead(baseAddr.add(0x018C), PTR_SIZE, "ptr"), type: "ptr" },
        
        // Orientation matrix excluded (just showing pointers)
        
        // Position
        position:               { offset: 0x01C0, value: safeRead(baseAddr.add(0x01C0), 24, "vec3d"), type: "vec3d" },
        
        // Quaternion
        quaternion:             { offset: 0x01D8, value: safeRead(baseAddr.add(0x01D8), 16, "quat"), type: "quat" },
        
        // Thread synchronization
        lockUpdate:             { offset: 0x0200, value: safeRead(baseAddr.add(0x0200), QWORD_SIZE, "i64"), type: "i64" },
        
        // Grid cell indices
        gridCellX:              { offset: 0x0236, value: safeRead(baseAddr.add(0x0236), WORD_SIZE, "i16"), type: "i16" },
        gridCellY:              { offset: 0x0238, value: safeRead(baseAddr.add(0x0238), WORD_SIZE, "i16"), type: "i16" },
        
        // Entity state
        physicalEntityType:     { offset: 0x0244, value: safeRead(baseAddr.add(0x0244), DWORD_SIZE, "i32"), type: "i32" },
        
        // Linear velocity
        linearVelocity:         { offset: 0x03C0, value: safeRead(baseAddr.add(0x03C0), 12, "vec3f"), type: "vec3f" },
        prevLinearVelocity:     { offset: 0x03CC, value: safeRead(baseAddr.add(0x03CC), 12, "vec3f"), type: "vec3f" },
        
        // Angular velocity
        angularVelocity:        { offset: 0x03D8, value: safeRead(baseAddr.add(0x03D8), 16, "vec3f"), type: "vec3f" },
        angularVelocityMag:     { offset: 0x03E4, value: safeRead(baseAddr.add(0x03E4), DWORD_SIZE, "float"), type: "float" },
        
        // Environmental forces
        gravity:                { offset: 0x03F0, value: safeRead(baseAddr.add(0x03F0), 12, "vec3f"), type: "vec3f" },
        
        // Accumulated forces
        accumulatedForce:       { offset: 0x0414, value: safeRead(baseAddr.add(0x0414), 24, "vec3d"), type: "vec3d" },
        
        // Inertia tensor
        inertiaTensorXX:        { offset: 0x0478, value: safeRead(baseAddr.add(0x0478), DWORD_SIZE, "float"), type: "float" },
        inertiaTensorYY:        { offset: 0x047C, value: safeRead(baseAddr.add(0x047C), DWORD_SIZE, "float"), type: "float" },
        inertiaTensorZZ:        { offset: 0x0480, value: safeRead(baseAddr.add(0x0480), DWORD_SIZE, "float"), type: "float" },
        invMass:                { offset: 0x0484, value: safeRead(baseAddr.add(0x0484), DWORD_SIZE, "float"), type: "float" },
        
        // Physics parameters
        mass:                   { offset: 0x0488, value: safeRead(baseAddr.add(0x0488), DWORD_SIZE, "float"), type: "float" },
        sleepSpeedThreshold:    { offset: 0x0490, value: safeRead(baseAddr.add(0x0490), DWORD_SIZE, "float"), type: "float" },
        maxTimeStep:            { offset: 0x049C, value: safeRead(baseAddr.add(0x049C), DWORD_SIZE, "float"), type: "float" },
        dampingRatio:           { offset: 0x04A0, value: safeRead(baseAddr.add(0x04A0), DWORD_SIZE, "float"), type: "float" },
        dampingCoeff:           { offset: 0x04A4, value: safeRead(baseAddr.add(0x04A4), DWORD_SIZE, "float"), type: "float" },
        frictionCoeff:          { offset: 0x04B4, value: safeRead(baseAddr.add(0x04B4), DWORD_SIZE, "float"), type: "float" },
        restitutionCoeff:       { offset: 0x04B8, value: safeRead(baseAddr.add(0x04B8), DWORD_SIZE, "float"), type: "float" },
        contactHardness:        { offset: 0x04BC, value: safeRead(baseAddr.add(0x04BC), DWORD_SIZE, "float"), type: "float" },
        maxContactGap:          { offset: 0x04C0, value: safeRead(baseAddr.add(0x04C0), DWORD_SIZE, "float"), type: "float" },
        collisionRadius:        { offset: 0x04C4, value: safeRead(baseAddr.add(0x04C4), DWORD_SIZE, "float"), type: "float" },
        maxAngularVelocity:     { offset: 0x04C8, value: safeRead(baseAddr.add(0x04C8), DWORD_SIZE, "float"), type: "float" },
        totalEnergyThreshold:   { offset: 0x04DC, value: safeRead(baseAddr.add(0x04DC), DWORD_SIZE, "float"), type: "float" },
        
        // Timestep management
        timeRemaining:          { offset: 0x04E4, value: safeRead(baseAddr.add(0x04E4), DWORD_SIZE, "float"), type: "float" },
        timeProcessed:          { offset: 0x04E8, value: safeRead(baseAddr.add(0x04E8), DWORD_SIZE, "float"), type: "float" },
        
        // Flags
        flags:                  { offset: 0x0520, value: safeRead(baseAddr.add(0x0520), DWORD_SIZE, "u32"), type: "u32" },
        collisionFilterMask:    { offset: 0x0536, value: safeRead(baseAddr.add(0x0536), QWORD_SIZE, "u64"), type: "u64" },
        
        // Contact points and rest state
        contactPoint:           { offset: 0x0950, value: safeRead(baseAddr.add(0x0950), 12, "vec3f"), type: "vec3f" },
        sleepTimeThreshold:     { offset: 0x0960, value: safeRead(baseAddr.add(0x0960), DWORD_SIZE, "float"), type: "float" },
        restThreshold:          { offset: 0x0964, value: safeRead(baseAddr.add(0x0964), DWORD_SIZE, "float"), type: "float" },
        currentRestTime:        { offset: 0x0968, value: safeRead(baseAddr.add(0x0968), DWORD_SIZE, "float"), type: "float" },
        maxPenetration:         { offset: 0x096C, value: safeRead(baseAddr.add(0x096C), DWORD_SIZE, "float"), type: "float" },
        
        // System references 
        pPhysWorld:             { offset: 0x0648, value: safeRead(baseAddr.add(0x0648), PTR_SIZE, "ptr"), type: "ptr" },
        pPhysicsSystem:         { offset: 0x0704, value: safeRead(baseAddr.add(0x0704), PTR_SIZE, "ptr"), type: "ptr" },
        pActionQueue:           { offset: 0x1272, value: safeRead(baseAddr.add(0x1272), PTR_SIZE, "ptr"), type: "ptr" },
        pFoliageInteraction:    { offset: 0x1624, value: safeRead(baseAddr.add(0x1624), PTR_SIZE, "ptr"), type: "ptr" },
        pWaterInteraction:      { offset: 0x1784, value: safeRead(baseAddr.add(0x1784), PTR_SIZE, "ptr"), type: "ptr" },
        
        // State flags
        stateFlags:             { offset: 0x2416, value: safeRead(baseAddr.add(0x2416), WORD_SIZE, "u16"), type: "u16" },
        simulationFlags:        { offset: 0x2418, value: safeRead(baseAddr.add(0x2418), BYTE_SIZE, "u8"), type: "u8" },
        contactFlags:           { offset: 0x2419, value: safeRead(baseAddr.add(0x2419), BYTE_SIZE, "u8"), type: "u8" },
        
        // Thread safety
        lockActor:              { offset: 0x2424, value: safeRead(baseAddr.add(0x2424), QWORD_SIZE, "i64"), type: "i64" },
        
        // Constraint entity
        pConstraintEntity:      { offset: 0x2552, value: safeRead(baseAddr.add(0x2552), PTR_SIZE, "ptr"), type: "ptr" },
        
        // Dynamic entity list
        pDynamicEntities:       { offset: 0x2848, value: safeRead(baseAddr.add(0x2848), PTR_SIZE, "ptr"), type: "ptr" },
        pDynamicEntitiesEnd:    { offset: 0x2856, value: safeRead(baseAddr.add(0x2856), PTR_SIZE, "ptr"), type: "ptr" },
        pDynamicEntitiesCapacity:{ offset: 0x2864, value: safeRead(baseAddr.add(0x2864), PTR_SIZE, "ptr"), type: "ptr" }
    };
    
    // Print the entity data
    const padTo = 25; // For alignment
    for (const [key, data] of Object.entries(entityData)) {
        const paddedKey = key.padEnd(padTo, ' ');
        const hexOffset = `0x${data.offset.toString(16).padStart(4, '0')}`;
        const formattedValue = formatValue(data.value, data.type);
        console.log(`${paddedKey} [${hexOffset}]: ${formattedValue}`);
    }
    
    // Additional analysis of flags for better debugging
    const flags = entityData.flags.value;
    console.log("\n--- Entity Flags Analysis ---");
    console.log(`PHYSICAL_ENTITY_DISABLED:     ${(flags & 0x20) !== 0}`);
    console.log(`PHYSICAL_ENTITY_CONSTRAINED:  ${(flags & 0x40) !== 0}`);
    console.log(`PHYSICAL_ENTITY_AUTO_SLEEP:   ${(flags & 0x80) !== 0}`);
    console.log(`PHYSICAL_ENTITY_SLEEPING:     ${(flags & 0x100) !== 0}`);
    
    // Simulation flags analysis
    const simFlags = entityData.simulationFlags.value;
    console.log("\n--- Simulation Flags Analysis ---");
    console.log(`IN_COLLISION:                ${(simFlags & 0x01) !== 0}`);
    console.log(`FORCE_APPLIED:               ${(simFlags & 0x02) !== 0}`);
    console.log(`REQUIRES_STEP:               ${(simFlags & 0x04) !== 0}`);
    console.log(`TIMESTEP_ACTIVE:             ${(simFlags & 0x08) !== 0}`);
    console.log(`VELOCITY_MODIFIED:           ${(simFlags & 0x10) !== 0}`);
    console.log(`POSITION_MODIFIED:           ${(simFlags & 0x40) !== 0}`);
    
    return entityData; // Return the data for further processing if needed
}

Interceptor.attach(functionAddress, {
    onEnter: function(args) {
        console.log('=== Entering sub_146675AD0 ===');
        this.entityPtr = args[0];
        
        console.log('Arguments:');
        console.log('  a1 (entity pointer): ' + this.entityPtr);

        dumpCActorEntity(this.entityPtr);
        return;
        
        // Safely read entity data with error handling
        try {
            console.log('Entity data:');
            
            // Check if pointer is valid before trying to read fields
            if (this.entityPtr.toInt32() !== 0) {
                console.log('  Byte at offset 520: ' + this.entityPtr.add(520).readU8());
                console.log('  DWORD at offset 980: ' + this.entityPtr.add(980).readU32());
                console.log('  DWORD at offset 1052: ' + this.entityPtr.add(1052).readU32());
                console.log('  DWORD at offset 1064: ' + this.entityPtr.add(1064).readU32());
                
                // Position data (based on decompiled code offsets)
                try {
                    // Position is at offset 0x1C0, 0x1C8, 0x1D0 (based on code referencing [r14+1C0h], etc.)
                    console.log('Position data (1C0h, 1C8h, 1D0h):');
                    console.log('  X: ' + this.entityPtr.add(0x1C0).readDouble());
                    console.log('  Y: ' + this.entityPtr.add(0x1C8).readDouble());
                    console.log('  Z: ' + this.entityPtr.add(0x1D0).readDouble());
                } catch (e) {
                    console.log('Error reading position: ' + e);
                }
                
                // Orientation data
                try {
                    console.log('Orientation data:');
                    console.log('  1D8h: ' + this.entityPtr.add(0x1D8).readFloat());
                    console.log('  1DCh: ' + this.entityPtr.add(0x1DC).readFloat());
                    console.log('  1E0h: ' + this.entityPtr.add(0x1E0).readFloat());
                    console.log('  1E4h: ' + this.entityPtr.add(0x1E4).readFloat());
                } catch (e) {
                    console.log('Error reading orientation: ' + e);
                }
                
                // Velocity data
                try {
                    console.log('Velocity data:');
                    console.log('  3C0h: ' + this.entityPtr.add(0x3C0).readFloat());
                    console.log('  3C4h: ' + this.entityPtr.add(0x3C4).readFloat());
                    console.log('  3C8h: ' + this.entityPtr.add(0x3C8).readFloat());
                } catch (e) {
                    console.log('Error reading velocity: ' + e);
                }
            } else {
                console.log('Invalid entity pointer');
            }
        } catch (e) {
            console.log('Error reading entity data: ' + e);
        }
        
        // Monitor memory access only if the pointer is valid
        if (false && this.entityPtr.toInt32() !== 0) {
            // Define memory ranges to monitor using the correct format
            const memoryRanges = [
                { base: this.entityPtr.add(0x1C0), size: 24 }, // Position
                { base: this.entityPtr.add(0x1D8), size: 16 }, // Orientation
                { base: this.entityPtr.add(0x3C0), size: 12 }  // Velocity
            ];

            // Set up memory monitoring with a single call
            try {
                MemoryAccessMonitor.enable(memoryRanges, {
                    onAccess: function(details) {
                        // Determine which range was accessed
                        const rangeNames = ["Position", "Orientation", "Velocity"];
                        const rangeName = rangeNames[details.rangeIndex] || "Unknown";
                        
                        console.log(`Memory access to ${rangeName}:`);
                        console.log(`  Operation: ${details.operation}`);
                        console.log(`  From: ${details.from}`);
                        console.log(`  Address: ${details.address}`);
                        console.log(`  Page Index: ${details.pageIndex}`);
                        console.log(`  Progress: ${details.pagesCompleted}/${details.pagesTotal} pages`);
                    }
                });
                console.log(`[+] Memory monitoring enabled for entity data`);
                this.monitoringEnabled = true;
            } catch (e) {
                console.log(`[-] Failed to enable memory monitoring: ${e}`);
                this.monitoringEnabled = false;
            }
        }
    },
    
    onLeave: function(retval) {
        console.log('=== Leaving sub_146675AD0 ===');
        console.log('Return value: ' + retval);
        
        console.log('entityPtr: ' + this.entityPtr);
        // Try to read updated entity data - verify this.entityPtr is still valid
        try {
            if (this.entityPtr && this.entityPtr.toInt32() !== 0) {
                console.log('Updated entity data:');
                return;
                
                // Read updated position
                try {
                    console.log('Updated position:');
                    console.log('  X: ' + this.entityPtr.add(0x1C0).readDouble());
                    console.log('  Y: ' + this.entityPtr.add(0x1C8).readDouble());
                    console.log('  Z: ' + this.entityPtr.add(0x1D0).readDouble());
                } catch (e) {
                    console.log('Error reading updated position: ' + e);
                }
                
                // Read updated velocity
                try {
                    console.log('Updated velocity:');
                    console.log('  X: ' + this.entityPtr.add(0x3C0).readFloat());
                    console.log('  Y: ' + this.entityPtr.add(0x3C4).readFloat());
                    console.log('  Z: ' + this.entityPtr.add(0x3C8).readFloat());
                } catch (e) {
                    console.log('Error reading updated velocity: ' + e);
                }
                
                // Read updated orientation
                try {
                    console.log('Updated orientation:');
                    console.log('  1D8h: ' + this.entityPtr.add(0x1D8).readFloat());
                    console.log('  1DCh: ' + this.entityPtr.add(0x1DC).readFloat());
                    console.log('  1E0h: ' + this.entityPtr.add(0x1E0).readFloat());
                    console.log('  1E4h: ' + this.entityPtr.add(0x1E4).readFloat());
                } catch (e) {
                    console.log('Error reading updated orientation: ' + e);
                }
                
                // Read flags
                try {
                    console.log('Flags:');
                    console.log('  Byte at 2418: ' + this.entityPtr.add(2418).readU8());
                    console.log('  Byte at 2419: ' + this.entityPtr.add(2419).readU8());
                } catch (e) {
                    console.log('Error reading flags: ' + e);
                }
            } else {
                console.log('Entity pointer no longer valid');
            }
        } catch (e) {
            console.log('Error reading updated entity data: ' + e);
        }
        
        // Disable memory monitoring if it was enabled
        if (this.monitoringEnabled) {
            try {
                MemoryAccessMonitor.disable();
                console.log('[+] Memory monitoring disabled');
            } catch (e) {
                console.log('[-] Error disabling memory monitoring: ' + e);
            }
        }
        
        console.log('=== Function execution completed ===');
    }
});

console.log('[+] Instrumentation complete');