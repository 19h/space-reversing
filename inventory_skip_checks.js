/**
 * Frida Script: Dimensional Validation Function Bypass
 * Target Functions: sub_140399E60 (Outer Capacity Check), sub_1403998E0 (Inner Dimensional Check)
 * 
 * Technical Objective: Override return values of dimensional validation functions to
 * consistently yield affirmative (1/true) results, effectively bypassing size constraints.
 * 
 * Implementation Methodology: Utilizes Interceptor.attach with onLeave callbacks to
 * manipulate return values post-execution, preserving function side effects while
 * altering validation outcomes.
 */

// Configuration Constants - Modify these addresses based on target binary analysis
const OUTER_CHECK_FUNCTION_ADDRESS = ptr('0x140399E60'); // sub_140399E60 absolute address
const INNER_CHECK_FUNCTION_ADDRESS = ptr('0x1403998E0'); // sub_1403998E0 absolute address

// Validation of target addresses
if (OUTER_CHECK_FUNCTION_ADDRESS.isNull() || INNER_CHECK_FUNCTION_ADDRESS.isNull()) {
    console.error('[ERROR] Invalid function addresses specified. Verify addresses from static analysis.');
    throw new Error('Invalid function addresses');
}

// Determine target architecture for appropriate return value handling
const targetArch = Process.arch;
const is64Bit = targetArch === 'x64';

console.log(`[INIT] Target architecture: ${targetArch} (${is64Bit ? '64-bit' : '32-bit'})`);
console.log(`[INIT] Outer check function address: ${OUTER_CHECK_FUNCTION_ADDRESS}`);
console.log(`[INIT] Inner check function address: ${INNER_CHECK_FUNCTION_ADDRESS}`);

/**
 * Hook Implementation for sub_140399E60 (Outer Capacity Check)
 * 
 * Function Signature Analysis:
 * - Return Type: char (8-bit, 0 = false, non-zero = true)
 * - Calling Convention: __fastcall (first two args in RCX, RDX on x64)
 * - Parameters: 6 x __int64 (a1-a6)
 * 
 * Original Logic:
 * - Performs capacity check: if (a3 && a5 + a4 - a6 > a3) return 0;
 * - Delegates to inner check if capacity validation passes
 * 
 * Bypass Strategy: Force return value to 1 (true) regardless of internal logic
 */
const outerCheckHook = Interceptor.attach(OUTER_CHECK_FUNCTION_ADDRESS, {
    onEnter: function(args) {
        // Log function invocation with parameter values for analysis
        console.log('[HOOK] sub_140399E60 called');
        console.log(`  a1 (target properties ptr): ${args[0]}`);
        console.log(`  a2 (source properties ptr): ${args[1]}`);
        console.log(`  a3 (capacity limit): ${args[2]}`);
        console.log(`  a4 (item dimension 1): ${args[3]}`);
        console.log(`  a5 (item dimension 2): ${args[4]}`);
        console.log(`  a6 (space adjustment): ${args[5]}`);
        
        // Store arguments for potential onLeave analysis
        this.args = {
            a1: args[0],
            a2: args[1],
            a3: args[2].toInt32(),
            a4: args[3].toInt32(),
            a5: args[4].toInt32(),
            a6: args[5].toInt32()
        };
        
        // Perform preliminary analysis of the capacity check condition
        if (this.args.a3 !== 0) {
            const netRequired = this.args.a5 + this.args.a4 - this.args.a6;
            const wouldFail = netRequired > this.args.a3;
            console.log(`  Capacity check: ${netRequired} > ${this.args.a3} = ${wouldFail}`);
            if (wouldFail) {
                console.log('  [BYPASS] Would have failed capacity check');
            }
        }
    },
    
    onLeave: function(retval) {
        // Capture original return value for logging
        const originalReturn = retval.toInt32();
        console.log(`[HOOK] sub_140399E60 original return: ${originalReturn}`);
        
        // Override return value to 1 (validation success)
        retval.replace(1);
        console.log(`[HOOK] sub_140399E60 modified return: 1 (forced success)`);
    }
});

/**
 * Hook Implementation for sub_1403998E0 (Inner Dimensional Check)
 * 
 * Function Signature Analysis:
 * - Return Type: bool (typically implemented as char/int)
 * - Calling Convention: __fastcall
 * - Parameters: 2 x float* (3D dimension arrays)
 * 
 * Original Logic:
 * - Computes min, median, max dimensions for both item and target
 * - Performs ordered dimensional comparisons
 * - Returns 0 if any dimension exceeds corresponding target dimension
 * 
 * Bypass Strategy: Force return value to 1 (true) regardless of dimensional comparisons
 */
const innerCheckHook = Interceptor.attach(INNER_CHECK_FUNCTION_ADDRESS, {
    onEnter: function(args) {
        console.log('[HOOK] sub_1403998E0 called');
        
        // Read dimension arrays (3 floats each)
        try {
            const targetDims = args[0].readByteArray(12); // 3 * sizeof(float)
            const itemDims = args[1].readByteArray(12);
            
            // Parse float values for analysis (little-endian assumption)
            const targetFloats = new Float32Array(targetDims);
            const itemFloats = new Float32Array(itemDims);
            
            console.log(`  Target dimensions: [${targetFloats[0]}, ${targetFloats[1]}, ${targetFloats[2]}]`);
            console.log(`  Item dimensions: [${itemFloats[0]}, ${itemFloats[1]}, ${itemFloats[2]}]`);
            
            // Store for potential onLeave analysis
            this.dimensions = {
                target: Array.from(targetFloats),
                item: Array.from(itemFloats)
            };
            
            // Analyze special case: zero target dimensions
            if (targetFloats[0] === 0 && targetFloats[1] === 0 && targetFloats[2] === 0) {
                console.log('  [INFO] Target has zero dimensions (unrestricted)');
            }
        } catch (e) {
            console.error('  [ERROR] Failed to read dimension arrays:', e);
        }
    },
    
    onLeave: function(retval) {
        // Capture original return value
        const originalReturn = retval.toInt32();
        console.log(`[HOOK] sub_1403998E0 original return: ${originalReturn}`);
        
        // Log dimensional comparison outcome if available
        if (this.dimensions && originalReturn === 0) {
            console.log('  [BYPASS] Dimensional check failed - item exceeds target bounds');
        }
        
        // Override return value to 1 (validation success)
        retval.replace(1);
        console.log(`[HOOK] sub_1403998E0 modified return: 1 (forced success)`);
    }
});

/**
 * Alternative Implementation: Direct Function Replacement
 * 
 * This approach completely replaces the functions with minimal stubs that always
 * return success. Use this if the hook-based approach causes issues or if maximum
 * performance is required.
 */
function installDirectReplacements() {
    console.log('[INIT] Installing direct function replacements');
    
    // Replacement for sub_140399E60 - Always return 1
    const outerReplacement = new NativeCallback(function() {
        console.log('[REPLACE] sub_140399E60 called - returning 1');
        return 1;
    }, 'char', ['pointer', 'pointer', 'int64', 'int64', 'int64', 'int64'], is64Bit ? 'win64' : 'fastcall');
    
    // Replacement for sub_1403998E0 - Always return 1
    const innerReplacement = new NativeCallback(function() {
        console.log('[REPLACE] sub_1403998E0 called - returning 1');
        return 1;
    }, 'int', ['pointer', 'pointer'], is64Bit ? 'win64' : 'fastcall');
    
    Interceptor.replace(OUTER_CHECK_FUNCTION_ADDRESS, outerReplacement);
    Interceptor.replace(INNER_CHECK_FUNCTION_ADDRESS, innerReplacement);
    
    console.log('[INIT] Direct replacements installed');
}

// Uncomment the following line to use direct replacement instead of hooks
// installDirectReplacements();

/**
 * Hook Management and Cleanup
 */
console.log('[INIT] Dimensional validation bypass hooks installed successfully');

// Export cleanup function for external control
rpc.exports = {
    disable: function() {
        console.log('[CLEANUP] Removing hooks');
        outerCheckHook.detach();
        innerCheckHook.detach();
        console.log('[CLEANUP] Hooks removed');
    },
    
    enableDirectReplacement: function() {
        console.log('[CONTROL] Switching to direct replacement mode');
        outerCheckHook.detach();
        innerCheckHook.detach();
        installDirectReplacements();
    }
};

// Handle script unload
Script.pin();
