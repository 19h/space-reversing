// Configuration
const CONFIG = {
    alwaysReturnTrue: {
        moduleName: 'StarCitizen.exe',
        functionOffset: 0x1403BBB00 - 0x140000000,
        returnType: 'bool',
        parameters: ['pointer']
    },
    lootable: {
        targetRVA: 0x6085F70,
        offsets: {
            reject: 0x1CC,
            feedback: 0x818
        }
    }
};

// Patch function to always return true
function patchAlwaysReturnTrue() {
    const targetFunction = Process.findModuleByName(CONFIG.alwaysReturnTrue.moduleName)
        .base.add(CONFIG.alwaysReturnTrue.functionOffset);

    Interceptor.replace(targetFunction, new NativeCallback(() => {
        return 1;  // Always return true
    }, CONFIG.alwaysReturnTrue.returnType, CONFIG.alwaysReturnTrue.parameters));
}

// Patch function to make all items lootable
function patchLootableItems() {
    const mainModule = Process.enumerateModules()[0];
    const originalFunction = mainModule.base.add(CONFIG.lootable.targetRVA);

    // Create native wrapper for original function
    const originalNativeFunction = new NativeFunction(
        originalFunction,
        'pointer',
        ['pointer', 'pointer']
    );

    // Create replacement callback
    const replacementCallback = new NativeCallback(function(context, itemHandle) {
        // Call original function
        const result = originalNativeFunction(context, itemHandle);

        // Clear blocked verdict
        Memory.writeU32(ptr(result).add(CONFIG.lootable.offsets.reject), 0);    // context->blocked = 0
        Memory.writeU8(ptr(result).add(CONFIG.lootable.offsets.feedback), 0);   // context->feedback = 0

        return result;
    }, 'pointer', ['pointer', 'pointer']);

    // Apply the hook
    Interceptor.replace(originalFunction, replacementCallback);
    console.log('[+] sub_146085F70 patched – all items will appear lootable.');
}

// Apply patches
patchAlwaysReturnTrue();
patchLootableItems();
