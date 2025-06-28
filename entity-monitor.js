// Frida hook for CreateEntityOfType function
var module0 = Process.enumerateModules()[0];
var createEntityOfTypeAddr = module0.base.add(0x669A660);

var entityTypeNames = {
    0x1: "CPhysicalEntity",
    0x2: "CRigidEntity",
    0x3: "CWheeledVehicleEntity",
    0x4: "CRopeEntityEx",
    0x5: "CParticleEntity",
    0x6: "CArticulatedEntity",
    0x7: "CRopeEntity",
    0x8: "CSoftEntity",
    0x9: "CPhysArea",
    0xa: "CSpaceshipEntity",
    0xb: "CActorEntity",
    0xc: "CPhysPlanetEntity",
    0xd: "CSoftEntityEx",
    0xe: "CHoverEntity"
};

Interceptor.attach(createEntityOfTypeAddr, {
    onEnter: function(args) {
        var entityType = args[0].toInt32();
        var a2 = args[1].toString();
        var a3 = args[2].toString();
        var entityName = "";

        // Mask the lower 48 bits of a5 handle
        var a5_raw = args[4];
        var a5_masked = a5_raw.and(ptr("0xFFFFFFFFFFFF"));
        var a5 = a5_masked.toString();

        var a6 = args[5].toInt32();

        // Read vtables for a2, a3, and a5
        var a2_vtable = "null";
        var a3_vtable = "null";
        var a5_vtable = "null";

        try {
            if (args[1] && !args[1].isNull()) {
                a2_vtable = args[1].readPointer().toString();
            }
        } catch (e) {
            a2_vtable = "null";
        }

        try {
            if (args[2] && !args[2].isNull()) {
                a3_vtable = args[2].readPointer().toString();
            }
        } catch (e) {
            a3_vtable = "null";
        }

        try {
            if (a5_masked && !a5_masked.isNull()) {
                a5_vtable = a5_masked.readPointer().toString();
            }
        } catch (e) {
            a5_vtable = "null";
        }

        if (args[3] && !args[3].isNull()) {
            try {
                entityName = args[3].readCString();
            } catch (e) {
                entityName = "null";
            }
        } else {
            entityName = "null";
        }

        var entityTypeName = entityTypeNames[entityType] || "Unknown";

        console.log("[CreateEntityOfType] Type: " + entityType + " (" + entityTypeName + "), a2: " + a2 + " (vtable: " + a2_vtable + "), a3: " + a3 + " (vtable: " + a3_vtable + "), Name: " + entityName + ", a5: " + a5 + " (vtable: " + a5_vtable + "), a6: " + a6);
    }
});
