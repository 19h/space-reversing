// --- Configuration ---
const MODULE_NAME = "StarCitizen.exe";         // Replace with the actual module name
const IDA_IMAGE_BASE = 0x140000000;     // The image base address of MODULE_NAME in IDA

const sub_1462E4500_RVA = 0x1462E4500 - IDA_IMAGE_BASE;
// --- End Configuration ---

function logDropItemAttempt() {
    const moduleBase = Process.enumerateModulesSync()[0].base;
    if (!moduleBase) {
        console.error(`[!] Module ${MODULE_NAME} not found. Ensure it's loaded and the name is correct.`);
        return;
    }
    console.log(`[+] Module ${MODULE_NAME} found at ${moduleBase}`);

    const targetFunctionAddr = moduleBase.add(sub_1462E4500_RVA);
    console.log(`[+] Hooking sub_1462E4500 at ${targetFunctionAddr}`);

    Interceptor.attach(targetFunctionAddr, {
        onEnter: function(args) {
            console.log(`\n[+] Entered sub_1462E4500 (Drop Item Attempt) at ${targetFunctionAddr}`);
            console.log("    Thread ID: " + this.threadId);

            // Arguments to sub_1462E4500:
            // __int64 n82 (this pointer for CSCLocalPlayerPersonalThoughtComponent) -> args[0] (in RCX)
            // const void *src (event data, item/slot being dropped) -> args[1] (in RDX)
            const n82_ptr = args[0];
            const src_ptr = args[1];

            console.log(`    n82 (this component ptr): ${n82_ptr}`);
            console.log(`    src (event data ptr):     ${src_ptr}`);

            // Attempt to read the pointer 'v6' from the stack.
            // From assembly: v6 is stored at [rsp+0x48] after the lambda call.
            // 'this.context.rsp' gives us RSP at the entry of the function.
            // The actual location of var_190 relative to the entry RSP needs to be precise.
            // The `sub rsp, 1C8h` and pushes change RSP.
            // Let's assume the offset 0x48 is relative to the RSP *after* the prolog.
            // For simplicity in a hook, it's often easier to hook *after* v6 is set,
            // or read it from where it's loaded into a register if that's simpler.

            // Let's try to read v6 after it's loaded into RAX at offset 0x130 from function start
            // (0x1462E4630 - 0x1462E4500 = 0x130)
            // This requires an inline hook or a more complex setup.

            // For an onEnter hook, the most reliable way to get v6 is if it's passed
            // or if we can calculate its stack offset precisely.
            // The lambda call `??0_lambda_9a32fed5bf61b6b509b2d3f6003082a1_@@QEAA@AEBV__crt_stdio_stream@@@Z`
            // takes `rcx` as `lea rcx, [rsp+1D8h+var_190]`.
            // `var_190` is `-190h`. So `rcx = rsp + 1D8h - 190h = rsp + 48h`.
            // This `rsp` is the rsp *before* the `sub rsp, 1C8h`.
            // So, at function entry, `v6_storage_ptr = this.context.rsp.add(0x48)`.
            // After the lambda call, `v6 = v6_storage_ptr.readPointer()`.

            // However, it's safer to read it when it's actively used.
            // Let's put a temporary hook where RAX holds v6.
            const v6_load_offset = 0x130; // Offset of 'mov rax, [rsp+1D8h+var_190]'
            const flag_check_offset = 0x149; // Offset of 'movzx eax, byte ptr [rax+10Ah]'

            this.v6_ptr = null;
            this.flag_value = -1; // Default if not found

            // We can't easily get v6 in onEnter without knowing the exact stack layout
            // relative to the initial RSP.
            // A more robust way is to use Stalker or multiple Interceptor.attach points.
            // For now, let's log what we can from args and context.

            console.log("    Context (registers at entry):");
            Object.keys(this.context).forEach(reg => {
                try {
                    // Only print general purpose registers for brevity
                    if (['pc', 'sp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'].includes(reg)) {
                         console.log(`        ${reg.toUpperCase()}: ${this.context[reg]}`);
                    }
                } catch (e) { /* might not be readable */ }
            });

            // To get the flag value, we'd ideally hook just before the JZ or read v6.
            // Let's try to read the stack location where v6 is stored.
            // RSP at entry + 0x48 (after pushes) should be where the pointer to v6 is.
            // RSP after `sub rsp, 1C8h` and 2 pushes (56, 57) is `initial_rsp - 0x1C8 - 0x10 = initial_rsp - 0x1D8`.
            // The `lea rcx, [rsp+1D8h+var_190]` means `lea rcx, [current_rsp_after_prolog + 0x48]`.
            // So, `ptr_to_v6_storage = this.context.rsp.add(0x48)`.
            try {
                const ptr_to_v6_value_on_stack = this.context.rsp.add(0x48); // This is [rsp+1D8h+var_190]
                const v6_ptr_value = ptr_to_v6_value_on_stack.readPointer();
                console.log(`    v6 (inventory context ptr from stack [rsp+0x48]): ${v6_ptr_value}`);
                if (!v6_ptr_value.isNull()) {
                    this.v6_ptr = v6_ptr_value; // Save for onLeave or further inspection
                    const flag_address = v6_ptr_value.add(0x12A);
                    const flag = flag_address.readU8();
                    this.flag_value = flag;
                    console.log(`    Amistice Flag Addr ([v6+0x12A]): ${flag_address}`);
                    console.log(`    Amistice Flag Value: 0x${flag.toString(16)} (${flag})`);
                    if (flag === 0) {
                        console.log("        -> Drop SHOULD be allowed based on this flag.");
                    } else {
                        console.log("        -> Drop SHOULD be RESTRICTED based on this flag.");
                    }
                } else {
                    console.log("        -> v6 pointer on stack is NULL.");
                }
            } catch (e) {
                console.warn(`    [!] Could not read v6 or flag from stack: ${e.message}`);
            }

            // You can also dump memory around src_ptr if you know its structure
            if (src_ptr && !src_ptr.isNull()) {
                try {
                    console.log(`    Memory dump around src_ptr (${src_ptr}):`);
                    console.log(hexdump(src_ptr, { length: 64, header: true, ansi: true }));
                } catch (e) { console.warn("        [!] Failed to hexdump src_ptr"); }
            }
        },

        onLeave: function(retval) {
            console.log(`[-] Leaving sub_1462E4500`);
            console.log(`    Return value: ${retval}`);
            // If we successfully read v6_ptr and flag_value in onEnter, they'd be available here via this.v6_ptr
            if (this.v6_ptr) {
                console.log(`    (v6 was: ${this.v6_ptr}, flag was: 0x${this.flag_value.toString(16)})`);
            }
            console.log("---");
        }
    });

    console.log("[*] Hook installed. Waiting for drop item attempts...");
}


logDropItemAttempt();

const HandleComponentEvent_RVA = 0x1462E9380 - IDA_IMAGE_BASE;
// --- End Configuration ---

function logHandleComponentEvent() {
    const moduleBase = Process.enumerateModulesSync()[0].base;
    if (!moduleBase) {
        console.error(`[!] Module ${MODULE_NAME} not found.`);
        return;
    }
    console.log(`[+] Module ${MODULE_NAME} found at ${moduleBase}`);

    const targetFunctionAddr = moduleBase.add(HandleComponentEvent_RVA);
    console.log(`[+] Hooking CSCLocalPlayerPersonalThoughtComponent::HandleComponentEvent at ${targetFunctionAddr}`);

    Interceptor.attach(targetFunctionAddr, {
        onEnter: function(args) {
            console.log(`\n[+] Entered CSCLocalPlayerPersonalThoughtComponent::HandleComponentEvent at ${targetFunctionAddr}`);
            console.log("    Thread ID: " + this.threadId);

            // Arguments:
            // __int64 a1 (this component ptr) -> args[0] (RCX)
            // ULONG_PTR a2 (event data ptr) -> args[1] (RDX)
            const componentPtr = args[0];
            const eventDataPtr_base = args[1]; // This is 'a2' from the C++

            console.log(`    Component Ptr (a1): ${componentPtr}`);
            console.log(`    Event Data Base Ptr (a2): ${eventDataPtr_base}`);

            this.componentState = -1;
            this.eventType = -1;
            this.shouldCallSub1462A6690 = false;

            if (componentPtr && !componentPtr.isNull()) {
                try {
                    const componentState = componentPtr.add(0x1CC).readU32();
                    this.componentState = componentState;
                    console.log(`    Component State [a1 + 0x1CC]: 0x${componentState.toString(16)} (${componentState})`);
                    if (componentState === 7) {
                        this.shouldCallSub1462A6690 = true;
                    }
                } catch (e) {
                    console.warn(`    [!] Failed to read component state: ${e.message}`);
                }
            }

            if (eventDataPtr_base && !eventDataPtr_base.isNull()) {
                try {
                    console.log(`    Event Data Base Ptr (a2) contents:`);
                    console.log(hexdump(eventDataPtr_base, { length: 64, header: true, ansi: true }));

                    // const void *src (passed to sub_1462A6690 as its a2) is eventDataPtr_base itself
                    // __int64 a3 (passed to sub_1462A6690 as its a3) is *(eventDataPtr_base + 8)
                    const eventDetailsPtr_a3 = eventDataPtr_base.add(8).readPointer();
                    console.log(`    Event Details Ptr (*(a2 + 8)): ${eventDetailsPtr_a3}`);

                    if (eventDetailsPtr_a3 && !eventDetailsPtr_a3.isNull()) {
                        console.log(`    Event Details Ptr (*(a2 + 8)) contents:`);
                        console.log(hexdump(eventDetailsPtr_a3, { length: 128, header: true, ansi: true })); // Dump more here

                        // The event type is at offset 0x70 from eventDetailsPtr_a3
                        const eventType = eventDetailsPtr_a3.add(0x70).readU32();
                        this.eventType = eventType;
                        console.log(`    Event Type [(*(a2 + 8)) + 0x70]: 0x${eventType.toString(16)} (${eventType})`);
                        if (eventType === 8) {
                            console.log("        -> This is a 'Drop Item' type event (type 8).");
                        } else {
                            console.log(`        -> Event type is ${eventType}, not Drop Item (8).`);
                        }
                    } else {
                        console.log("        -> Event Details Ptr (*(a2 + 8)) is NULL.");
                    }
                } catch (e) {
                    console.warn(`    [!] Failed to read event data details: ${e.message}`);
                }
            } else {
                console.log("    -> Event Data Base Ptr (a2) is NULL.");
            }
        },

        onLeave: function(retval) {
            console.log(`[-] Leaving CSCLocalPlayerPersonalThoughtComponent::HandleComponentEvent`);
            console.log(`    Return value: ${retval}`);
            if (this.componentState !== -1) {
                console.log(`    (Component state was: ${this.componentState}, Event type was: ${this.eventType})`);
                if (this.componentState === 7 && this.eventType === 8) {
                    console.log("        -> sub_1462A6690 (and subsequently sub_1462E4500 for drop) SHOULD have been called.");
                } else if (this.componentState === 7 && this.eventType !== 8) {
                    console.log("        -> sub_1462A6690 was likely called, but for a different event type.");
                } else {
                    console.log("        -> sub_1462A6690 was LIKELY NOT called due to component state.");
                }
            }
            console.log("---");
        }
    });

    console.log("[*] Hook installed on HandleComponentEvent. Waiting for inventory actions...");
}

logHandleComponentEvent();
