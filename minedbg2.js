var base = Module.findBaseAddress('StarCitizen.exe');

// CRigidEntity::StartStep
var startStepPtr = base.add(ptr("0x67F8350"));

var physicsMultiplier = 100.0;

console.log("Hooking CRigidEntity::StartStep at: " + startStepPtr);

// Keep your original NativeFunction definition
var originalStartStep = new NativeFunction(startStepPtr, 'void', ['pointer', 'float']);

// The new, corrected function to disable both forces
function disableGravityAndCounterThrust(rigidEntity) {
    try {
        /* m_gravityImpulse (float[3]) produced at end of AddAdditionalImpulses */
        rigidEntity.add(0x68C).writeFloat(0.0);
        rigidEntity.add(0x690).writeFloat(0.0);
        rigidEntity.add(0x694).writeFloat(0.0);

        console.log("[" + rigidEntity + "] Before zero: " +
            rigidEntity.add(0x658).readDouble() + ", " +
            rigidEntity.add(0x660).readDouble() + ", " +
            rigidEntity.add(0x668).readDouble() + ", " +
            rigidEntity.add(0x670).readDouble() + ", " +
            rigidEntity.add(0x678).readDouble());


        const maxThrustMultiplier = 10.0;

        const thrust = rigidEntity.add(0xb4c).readFloat();
        const maxThrust = maxThrustMultiplier * thrust;

        rigidEntity.add(0xb4c).writeFloat(maxThrust);

        const rampUpNMultiplier = 10.0;
        const rampUpN_per_s = rigidEntity.add(0xb50).readFloat();

        rigidEntity.add(0xb50).writeFloat(rampUpN_per_s * rampUpNMultiplier);

        const gX = rigidEntity.add(0x68C).readFloat();
        const gY = rigidEntity.add(0x690).readFloat();
        const gZ = rigidEntity.add(0x694).readFloat();

        /* subtract the portion due to gravityAccum = (0x658…678) -------- */
        /*  (mass already factored in, so tiny drift remains ≈ 0.0005 N·s) */
        rigidEntity.add(0x68C).writeFloat( gX - rigidEntity.add(0x658).readDouble() * rigidEntity.add(0x6B8).readDouble() );
        rigidEntity.add(0x690).writeFloat( gY - rigidEntity.add(0x660).readDouble() * rigidEntity.add(0x6B8).readDouble() );
        rigidEntity.add(0x694).writeFloat( gZ - rigidEntity.add(0x668).readDouble() * rigidEntity.add(0x6B8).readDouble() );
    } catch (e) {
        console.log("Error zeroing gravity/thrust vectors:", e);
    }
}

// Replace the StartStep function to apply your modifications
Interceptor.replace(startStepPtr, new NativeCallback(function(rigidEntity, deltaTime) {
    // rigidEntity is args[0] (in RCX)
    // deltaTime is args[1] (in XMM1)

    if (!rigidEntity.isNull()) {
        // Call the new function that zeroes out both vectors
        disableGravityAndCounterThrust(rigidEntity);
    }

    // Apply your physics multiplier
    var newTime = deltaTime * physicsMultiplier;

    // Call the original function with the modified time
    return originalStartStep(rigidEntity, newTime);
}, 'void', ['pointer', 'float']));

// You can remove the Interceptor.attach on sub_14677F280 as this hook
// on StartStep handles it cleanly before the physics step begins.
