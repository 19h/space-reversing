/**
 * Star Citizen Actor Tracking System - Production Implementation v4
 * Addresses stack alignment, memory validation, and signature detection
 */

const CONSTANTS = {
    POINTER_MASK: uint64('0xFFFFFFFFFFFF'),
    HEAP_THRESHOLD: uint64('0x7F0000000000'), // Upper bound for valid user-mode addresses
    
    ENTITY_TYPES: {
        CActorEntity: 11
    },
    
    OFFSETS: {
        GEnv: {
            game: 0x0098,
            entity_system: 0x00A0,
            system: 0x00C0,
            renderer: 0x00F8
        },
        CEntitySystem: {
            entity_array: 0x0148,
            entity_class_registry: 0x0898
        },
        CEntityArray: {
            max_size: 0x0000,
            curr_size: 0x0008,
            data: 0x0018
        },
        CEntity: {
            flags: 0x0008,
            id: 0x0010,
            entity_class: 0x0020,
            x_local_pos: 0x00F8,
            y_local_pos: 0x0100,
            z_local_pos: 0x0108,
            entity_components: 0x0240,
            name: 0x0298
        }
    },
    
    GENV_OFFSET: uint64('0x9B4FBE0')
};

/**
 * Enhanced memory validation with heap boundary checking
 */
function isValidUserModePointer(ptr) {
    if (!ptr || ptr.isNull()) return false;
    
    try {
        const address = uint64(ptr.toString());
        
        // Check upper bound for user-mode addresses
        if (address.compare(CONSTANTS.HEAP_THRESHOLD) > 0) {
            console.log(`[VALIDATION] Pointer ${ptr} exceeds user-mode boundary`);
            return false;
        }
        
        // Verify memory range exists
        const range = Process.findRangeByAddress(ptr);
        if (!range) {
            console.log(`[VALIDATION] No memory range found for ${ptr}`);
            return false;
        }
        
        // Verify readable
        if (!range.protection.includes('r')) {
            console.log(`[VALIDATION] Memory at ${ptr} not readable (${range.protection})`);
            return false;
        }
        
        return true;
    } catch (e) {
        console.error(`[VALIDATION] Exception validating pointer ${ptr}: ${e}`);
        return false;
    }
}

/**
 * Stack alignment enforcement wrapper
 */
function createAlignedInterceptor(targetAddr, callbacks) {
    const trampolineSize = 128;
    const trampoline = Memory.alloc(trampolineSize);
    
    Memory.patchCode(trampoline, trampolineSize, code => {
        const writer = new X86Writer(code);
        
        // Save original RSP
        writer.putPushReg('rsp');
        
        // Align stack to 16-byte boundary
        writer.putMovRegReg('rax', 'rsp');
        writer.putAndRegU32('rsp', 0xFFFFFFF0); // Clear lower 4 bits
        
        // Allocate shadow space for Win64 ABI (32 bytes)
        writer.putSubRegImm('rsp', 0x20);
        
        // Call our handler
        writer.putMovRegAddress('rax', callbacks.onEnterAligned);
        writer.putCallReg('rax');
        
        // Restore original RSP
        writer.putAddRegImm('rsp', 0x20);
        writer.putPopReg('rsp');
        
        // Jump to original function
        writer.putJmpAddress(targetAddr);
        
        writer.flush();
    });
    
    // Replace original with trampoline
    Memory.patchCode(targetAddr, 5, code => {
        const writer = new X86Writer(code);
        writer.putJmpAddress(trampoline);
        writer.flush();
    });
    
    return trampoline;
}

/**
 * Signature detection and validation
 */
function detectFunctionSignature(funcAddr) {
    console.log('[SIGNATURE] Analyzing function signature...');
    
    try {
        // Read function prologue
        const prologue = funcAddr.readByteArray(32);
        const prologueHex = Array.from(new Uint8Array(prologue))
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');
        
        console.log(`[SIGNATURE] Prologue: ${prologueHex}`);
        
        // Common x64 function prologues
        const signatures = {
            // Standard frame pointer setup
            standard: /^(48 89 5c 24|48 89 74 24|48 89 7c 24|55 48 8b ec|48 83 ec)/,
            // Optimized leaf function
            leaf: /^(48 8b c1|48 89 c8|4c 8b c1)/,
            // Member function with 'this' in RCX
            member: /^(48 89 4c 24|48 8b 01|4c 8b 41)/
        };
        
        for (const [type, pattern] of Object.entries(signatures)) {
            if (pattern.test(prologueHex)) {
                console.log(`[SIGNATURE] Detected ${type} function pattern`);
                return type;
            }
        }
        
        console.log('[SIGNATURE] Unknown function pattern');
        return 'unknown';
    } catch (e) {
        console.error(`[SIGNATURE] Error analyzing signature: ${e}`);
        return 'error';
    }
}

/**
 * Enhanced CEntitySystem::Update hook with comprehensive validation
 */
const ProductionEntitySystemHook = {
    onEnter: function(args) {
        // Validate calling context
        const stackPtr = this.context.rsp;
        const stackAlignment = parseInt(stackPtr.toString()) % 16;
        
        if (stackAlignment !== 0) {
            console.warn(`[HOOK] Stack misalignment detected: ${stackAlignment} byte offset`);
            // Attempt to continue despite misalignment
        }
        
        // Extract potential entity system pointer from multiple sources
        const candidates = [
            { source: 'RCX', ptr: ptr(this.context.rcx) },
            { source: 'RDX', ptr: ptr(this.context.rdx) },
            { source: 'R8', ptr: ptr(this.context.r8) },
            { source: 'R9', ptr: ptr(this.context.r9) },
            { source: 'Stack+0', ptr: stackPtr.readPointer() },
            { source: 'Stack+8', ptr: stackPtr.add(8).readPointer() }
        ];
        
        let validEntitySystem = null;
        
        for (const candidate of candidates) {
            if (isValidUserModePointer(candidate.ptr)) {
                console.log(`[HOOK] Potential entity system from ${candidate.source}: ${candidate.ptr}`);
                
                // Validate entity system structure
                try {
                    const testRead = candidate.ptr.add(CONSTANTS.OFFSETS.CEntitySystem.entity_array);
                    testRead.readU64(); // Test read
                    
                    validEntitySystem = candidate.ptr;
                    console.log(`[HOOK] Validated entity system at ${candidate.ptr}`);
                    break;
                } catch (e) {
                    // Not a valid entity system
                }
            }
        }
        
        if (!validEntitySystem) {
            console.error('[HOOK] No valid entity system pointer found');
            this.skipProcessing = true;
            return;
        }
        
        this.entitySystem = validEntitySystem;
        this.skipProcessing = false;
    },
    
    onLeave: function(retval) {
        if (this.skipProcessing) return;
        
        try {
            // Minimal entity enumeration with validation
            const entityArrayBase = this.entitySystem.add(CONSTANTS.OFFSETS.CEntitySystem.entity_array);
            const maxSize = entityArrayBase.add(CONSTANTS.OFFSETS.CEntityArray.max_size).readU64();
            
            if (maxSize > 0 && maxSize < 100000) {
                console.log(`[HOOK] Entity array contains up to ${maxSize} entries`);
                
                const dataPtr = entityArrayBase.add(CONSTANTS.OFFSETS.CEntityArray.data).readPointer();
                if (isValidUserModePointer(dataPtr)) {
                    // Attempt to read first entity
                    const firstEntityPtr = dataPtr.readPointer();
                    if (isValidUserModePointer(firstEntityPtr)) {
                        console.log(`[HOOK] First entity at: ${firstEntityPtr}`);
                    }
                }
            }
        } catch (e) {
            console.error(`[HOOK] Error processing entity system: ${e}`);
        }
    }
};

/**
 * Alternative approach: Pattern-based entity system discovery
 */
function findEntitySystemViaPatterns() {
    console.log('[DISCOVERY] Searching for entity system via patterns...');
    
    const patterns = [
        // Common entity system vtable patterns
        { pattern: '48 8D 05 ?? ?? ?? ?? 48 89 01 48 8D 81 48 01 00 00', description: 'EntitySystem vtable setup' },
        { pattern: '48 8B 89 48 01 00 00 48 85 C9 74', description: 'EntityArray access' },
        { pattern: '48 8B 81 98 08 00 00 C3', description: 'ClassRegistry getter' }
    ];
    
    const mainModule = Process.enumerateModules()[0];
    
    for (const patternInfo of patterns) {
        const matches = Memory.scanSync(mainModule.base, mainModule.size, patternInfo.pattern);
        
        if (matches.length > 0) {
            console.log(`[DISCOVERY] Found ${patternInfo.description} at ${matches.length} location(s)`);
            
            for (const match of matches.slice(0, 5)) { // Check first 5 matches
                const addr = ptr(match.address);
                console.log(`[DISCOVERY] Analyzing match at ${addr}`);
                
                // Attempt to validate as entity system reference
                try {
                    const instruction = Instruction.parse(addr);
                    console.log(`[DISCOVERY] Instruction: ${instruction}`);
                } catch (e) {
                    // Continue to next match
                }
            }
        }
    }
}

/**
 * Initialize with multiple validation strategies
 */
function initializeProduction() {
    console.log('[INIT] Star Citizen Actor Tracking System v4');
    console.log(`[INIT] Process: ${Process.id} @ ${Process.enumerateModules()[0].base}`);
    
    const baseAddress = Process.enumerateModules()[0].base;
    
    // Detect function signature before hooking
    const updateAddr = baseAddress.add(0x6B7A3E0);
    const signatureType = detectFunctionSignature(updateAddr);
    
    // Attempt pattern-based discovery
    findEntitySystemViaPatterns();
    
    // Install hook with validation
    try {
        Interceptor.attach(updateAddr, ProductionEntitySystemHook);
        console.log('[INIT] Installed production hook on CEntitySystem::Update');
    } catch (e) {
        console.error(`[INIT] Failed to install hook: ${e}`);
    }
    
    // Enhanced exception handler
    Process.setExceptionHandler(details => {
        console.error('\n[EXCEPTION] === UNHANDLED EXCEPTION ===');
        console.error(`[EXCEPTION] Type: ${details.type}`);
        console.error(`[EXCEPTION] Address: ${details.address}`);
        
        if (details.memory) {
            console.error(`[EXCEPTION] Memory ${details.memory.operation} at ${details.memory.address}`);
        }
        
        if (details.context) {
            console.error('[EXCEPTION] Register dump:');
            const regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 
                          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
            for (const reg of regs) {
                if (details.context[reg] !== undefined) {
                    console.error(`  ${reg.toUpperCase()}: ${details.context[reg]}`);
                }
            }
            
            // Analyze crash location
            const rip = ptr(details.context.rip || details.context.pc);
            const module = Process.findModuleByAddress(rip);
            if (module) {
                const offset = rip.sub(module.base);
                console.error(`[EXCEPTION] Crash in ${module.name}+${offset}`);
            }
        }
        
        return false; // Allow debugging
    });
    
    console.log('[INIT] Production initialization complete');
}

// Execute initialization
initializeProduction();