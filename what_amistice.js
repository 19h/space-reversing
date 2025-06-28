/**
 * Frida Script for Armistice Zone Bypass - CVar Method
 *
 * This script leverages the game's built-in developer console variable (CVar)
 * 'g_disable_green_zones' to disable all Armistice Zone effects. This is the
 * most reliable and non-invasive method.
 */

// --- [1] ADDRESS DEFINITIONS ---
const TARGET_MODULE = 'StarCitizen.exe';
const globalPointers = {
    // This is the global pointer to the Console system (ICVar).
    // In the provided code, it's qword_149B4FC90. We need to find its
    // actual address in the running process. It's often near gEnv.
    // Let's assume we find it at offset 0x9B4FC90 for this example.
    pConsole: ptr('0x9B4FC90')
};

const vtableOffsets = {
    // The offset in the ICVar vtable for the function that finds a CVar.
    // This is typically named FindCVar or GetCVar. We need to find this
    // by reversing the console system. Let's assume it's the 8th function (index 7).
    findCVar_vtable_index: 7
};

// --- [2] SCRIPT CORE ---
try {
    console.log(`[+] Starting Armistice Zone Bypass (CVar Method)...`);
    const module = Process.findModuleByName(TARGET_MODULE);
    if (!module) throw new Error(`Module ${TARGET_MODULE} not found.`);
    console.log(`[+] Found module ${TARGET_MODULE} at ${module.base}`);

    // Get the absolute address of the global console pointer
    const pConsolePtr = module.base.add(globalPointers.pConsole);
    console.log(`[+] Address of pConsole pointer: ${pConsolePtr}`);

    // Read the pointer to get the actual console object instance
    const pConsole = pConsolePtr.readPointer();
    if (pConsole.isNull()) {
        throw new Error("Console system pointer (pConsole) is NULL. The game may not be fully loaded.");
    }
    console.log(`[+] Console system (ICVar) instance found at: ${pConsole}`);

    // Get the vtable of the console object
    const pConsoleVTable = pConsole.readPointer();
    console.log(`[+] Console vtable found at: ${pConsoleVTable}`);

    // Get the address of the FindCVar function from the vtable
    const findCVarPtr = pConsoleVTable.add(vtableOffsets.findCVar_vtable_index * Process.pointerSize).readPointer();
    if (findCVarPtr.isNull()) {
        throw new Error("Could not find FindCVar function in vtable. Is the index correct?");
    }
    console.log(`[+] FindCVar function found at: ${findCVarPtr}`);

    // Create a NativeFunction to call FindCVar from JavaScript
    // Signature is typically: ICVar* FindCVar(const char* name)
    const FindCVar = new NativeFunction(findCVarPtr, 'pointer', ['pointer', 'pointer']);

    // Allocate memory for the CVar name and call the function
    const cvarName = Memory.allocUtf8String("g_disable_green_zones");
    const pCVar = FindCVar(pConsole, cvarName);

    if (pCVar.isNull()) {
        throw new Error("CVar 'g_disable_green_zones' not found. It might not be registered yet or the name is wrong.");
    }
    console.log(`[+] CVar 'g_disable_green_zones' object found at: ${pCVar}`);

    // Now, we need to set its value. The integer value is usually at a fixed
    // offset within the CVar object. A common offset is 0x14 or 0x18.
    // Let's assume the integer value is at offset 0x14.
    const pCVarValue = pCVar.add(0x14); // This offset may need adjustment!

    // Read the original value for logging
    const originalValue = pCVarValue.readU32();
    console.log(`[+] Original value of g_disable_green_zones: ${originalValue}`);

    // Write the new value (1) to disable green zones
    pCVarValue.writeU32(1);
    console.log(`[+] New value written: 1`);

    // Verify the write
    const finalValue = pCVarValue.readU32();
    if (finalValue === 1) {
        console.log(`[SUCCESS] CVar 'g_disable_green_zones' has been successfully set to 1.`);
        console.log(`[+] All Armistice Zone effects should now be disabled.`);
    } else {
        throw new Error("Failed to write to CVar memory. It might be write-protected.");
    }

} catch (error) {
    console.error(`[-] An error occurred: ${error.message}\n${error.stack}`);
}
