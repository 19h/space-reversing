/*
bool __fastcall sub_143686580(__int64 a1, int a2)
{
  bool result; // al

  switch ( a2 )
  {
    case 0:
      result = *(_DWORD *)(qword_149B3B2E0 + 1096) != 0;
      break;
    case 1:
      result = *(_DWORD *)(qword_149B3B2E0 + 1104) != 0;
      break;
    case 2:
      result = *(_DWORD *)(qword_149B3B2E0 + 1100) != 0;
      break;
    default:
      result = 1;
      break;
  }
  return result;
}
*/

const getStatName =
  statIndex => {
    switch (statIndex) {
      case 0: return "Hunger";
      case 1: return "Thirst";
      case 2: return "BloodDrugLevel";
      case 3: return "OverdoseLevel";
      case 4: return "BodyTemperature";
      case 5: return "SuitTemperature";
      case 6: return "Stun";
      case 7: return "Distortion";
      case 8: return "Pressure";
      case 9: return "GasSaturationO2";
      case 10: return "DownedDamage";
      case 11: return "HealthPool";
      case 12: return "HealthHead";
      case 13: return "HealthTorso";
      case 14: return "HealthLeftArm";
      case 15: return "HealthRightArm";
      case 16: return "HealthLeftLeg";
      case 17: return "HealthRightLeg";
      case 18: return "WearHead";
      case 19: return "WearTorso";
      case 20: return "WearLeftArm";
      case 21: return "WearRightArm";
      case 22: return "WearLeftLeg";
      case 23: return "WearRightLeg";
      case 24: return "BodyRadiation";
      case 25: return "SuitRadiation";
      case 26: return "GasSaturationCO2";
      case 27: return "GasSaturationCO";
      case 28: return "Hygiene";
      default: return "UNDEFINED";
    }
  };

const xptr = new NativeFunction(ptr(0x143686580), 'bool', ['pointer', 'uint64']);

/*
AdjustActorStat(actor_status_ptr_1, int 10, COERCE_DOUBLE((unsigned __int64) __int32 v29), __int64 v64, __int64 v17);
AdjustActorStat(actor_status_ptr, int 6, COERCE_DOUBLE((unsigned __int64)LODWORD(float v132)), *(_QWORD rdx0), __int64 v58);
*/

//Interceptor.attach(ptr(0x143681C35), {
//  onEnter: function (args) {
//    console.log("[+] AdjustActorStat called");
//    console.log("    actor_status_ptr: " + args[0]);
//    console.log("    stat_index: " + args[1]);
//    console.log("    a3 (double): " + args[2]);
//
//    console.log(getStatName(args[1]), args[1].toNumber());
//
//    // Try to capture variable arguments (va_args)
//    // In x64 calling convention, additional args would be in subsequent registers
//    console.log("    possible va_arg[0]: " + args[3]);
//    console.log("    possible va_arg[1]: " + args[4]);
//    console.log("    possible va_arg[2]: " + args[5]);
//    console.log("    possible va_arg[3]: " + args[6]);
//
//    console.log('x: ', xptr(args[0], args[1]));
//
//    // Print backtrace
//    console.log("Backtrace:");
//    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//      .map(DebugSymbol.fromAddress).join('\n'));
//  },
//
//  onLeave: function (retval) {
//    console.log("[+] AdjustActorStat returned: " + retval);
//  }
//});

/*
__int64 __fastcall sub_142E01C20(__int64 a1, unsigned __int64 a2)
__int64 __fastcall sub_14083B480(__int64 a1, __int64 (__fastcall ***a2)(_QWORD, __int64))
__int64 __fastcall sub_14083B460(__int64 a1, __int64 (__fastcall ***a2)(_QWORD, __int64))
*/

// Interceptor.attach(ptr(0x142E01C20), {
//   onEnter: function (args) {
//     console.log("[+] SWeaponStats::Destructor called");
//     console.log("    a1: " + args[0]);
//     console.log("    a2: " + args[1]);
//     // Optional: Add backtrace if needed
//     console.log("Backtrace:");
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     console.log("[+] sub_142E01C20 returned: " + retval);
//   }
// });

// Interceptor.attach(ptr(0x14083B480), {
//   onEnter: function (args) {
//     console.log("[+] SWeaponStats::Constructor called");
//     console.log("    a1: " + args[0]);
//     console.log("    a2 (pointer to function table pointer): " + args[1]);
//     // Optional: Add backtrace if needed
//     console.log("Backtrace:");
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     console.log("[+] sub_14083B480 returned: " + retval);
//   }
// });

// Interceptor.attach(ptr(0x145512270), {
//   onEnter: function (args) {
//     console.log("[+] SWeaponConnectionParams::Destructor called");
//     console.log("    a1: " + args[0]);
//     console.log("    a2 (pointer to function table pointer): " + args[1]);
//     // Optional: Add backtrace if needed
//     console.log("Backtrace:");
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     console.log("[+] sub_14083B480 returned: " + retval);
//   }
// });

// Interceptor.attach(ptr(0x142903E20), {
//   onEnter: function (args) {
//     console.log("[+] SWeaponConnectionParams::Constructor called");
//     console.log("    a1: " + args[0]);
//     console.log("    a2 (pointer to function table pointer): " + args[1]);
//     // Optional: Add backtrace if needed
//     console.log("Backtrace:");
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     console.log("[+] sub_14083B480 returned: " + retval);
//   }
// });

// Interceptor.attach(ptr(0x1472371D0), {
//   onEnter: function (args) {
//     console.log("[+] sub_1472371D0 called");
//     console.log("    pDataCore (pointer): " + args[0]); // _QWORD *
//     console.log("    a2 (int64): " + args[1]);          // __int64
//     console.log("    n16 (uint8): " + args[2]);         // unsigned __int8
//     console.log("    n2 (char): " + args[3]);           // char

//     this.a2 = args[1];

//     // Optional: Add backtrace if needed
//     console.log("Backtrace:");
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     console.log("[+] sub_1472371D0 returned (int64): " + retval);

//     hexdump(this.a2, { length: 16 });
//   }
// });


// Interceptor.attach(ptr(0x1468feb4f), {
//   onEnter: function (args) {
//     console.log("[+] ProcessEntityPropertyOverrides called");
//     console.log("    entityId (int64): " + args[0]);
//     console.log("    pEntityProperties (pointer): " + args[1]);
//     console.log("    pPropertyOverrides (pointer to pointer): " + args[2]);

//     // Optional: Add backtrace if needed
//     // console.log("Backtrace:");
//     // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//     //   .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     // Function returns void, so retval is undefined or 0 depending on Frida's handling
//     console.log("[+] ProcessEntityPropertyOverrides returned");
//   }
// });

Interceptor.attach(ptr(0x141534030), {
  onEnter: function (args) {
    console.log("[+] CrimeMetadataManager::ExtractPosition called");
    console.log("    a1 (this?): " + args[0]);
    console.log("    a2 (out_position_ptr): " + args[1]);
    this.out_position_ptr = args[1]; // Store for onLeave

    // Optional: Add backtrace if needed
    // console.log("Backtrace:");
    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
    //   .map(DebugSymbol.fromAddress).join('\n'));
  },
  onLeave: function (retval) {
    console.log("[+] CrimeMetadataManager::ExtractPosition returned (position_ptr): " + retval);
    // Optionally hexdump the output position if needed and valid
    // if (!retval.isNull()) {
    //   try { hexdump(retval, { length: 16 }); } catch (e) { console.log("Error hexdumping retval:", e); }
    // }
    // Or dump the one passed in args[1] if it's the same and potentially modified in place
    // if (this.out_position_ptr && !this.out_position_ptr.isNull()) {
    //    try { hexdump(this.out_position_ptr, { length: 16 }); } catch (e) { console.log("Error hexdumping a2:", e); }
    // }
  }
});

//Interceptor.attach(ptr(0x141533BE0), {
//  onEnter: function (args) {
//    console.log("[+] getCrimeSeverity called");
//    console.log("    a1 (crime_related_ptr?): " + args[0]);
//
//    // Optional: Add backtrace if needed
//    // console.log("Backtrace:");
//    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//    //   .map(DebugSymbol.fromAddress).join('\n'));
//  },
//  onLeave: function (retval) {
//    console.log("[+] getCrimeSeverity returned (severity): " + retval);
//  }
//});

Interceptor.attach(ptr(0x141553370), {
  onEnter: function (args) {
    console.log("[+] LawComponent::ReportCrime called");
    console.log("    this (LawComponent*): " + args[0]);
    console.log("    crime (__int64): " + args[1]);
    console.log("    suspectHandle (unsigned __int64*): " + args[2]);
    // Optionally read the value pointed to by suspectHandle if it's valid
    // if (args[2] && !args[2].isNull()) {
    //   try { console.log("    *suspectHandle: " + args[2].readU64()); } catch (e) { console.log("Error reading suspectHandle:", e); }
    // }

    // Optional: Add backtrace if needed
    // console.log("Backtrace:");
    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
    //   .map(DebugSymbol.fromAddress).join('\n'));
  },
  onLeave: function (retval) {
    console.log("[+] LawComponent::ReportCrime returned (_QWORD*): " + retval);
    // Optionally read the value pointed to by retval if it's valid
    // if (retval && !retval.isNull()) {
    //   try { console.log("    *retval: " + retval.readU64()); } catch (e) { console.log("Error reading retval:", e); }
    // }
  }
});

Interceptor.attach(ptr(0x141565BB0), {
  onEnter: function (args) {
    console.log("[+] LawComponent::TriggerCrimeEffects called");
    console.log("    crime (__int64): " + args[0]);

    // Optional: Add backtrace if needed
    // console.log("Backtrace:");
    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
    //   .map(DebugSymbol.fromAddress).join('\n'));
  },
  onLeave: function (retval) {
    console.log("[+] LawComponent::TriggerCrimeEffects returned (__int64): " + retval);
  }
});

// Define the address of the global pointer variable qword_14981D2F8
const qword_14981D2F8_addr = ptr('0x14981D2F8');

// Read the pointer stored at qword_14981D2F8_addr. This should be the pointer to the _LocaleUpdate object.
const localeUpdatePtr = qword_14981D2F8_addr.readPointer();

// Check if the pointer is valid
if (!localeUpdatePtr.isNull()) {
    // Read the vtable pointer from the beginning of the _LocaleUpdate object
    const vtablePtr = localeUpdatePtr.readPointer();

    if (!vtablePtr.isNull()) {
        // Calculate the addresses of the specific virtual function pointers within the vtable
        const funcPtrAddr376 = vtablePtr.add(376).readPointer(); // Offset 376 (0x178)
        const funcPtrAddr384 = vtablePtr.add(384).readPointer(); // Offset 384 (0x180)
        const funcPtrAddr520 = vtablePtr.add(520).readPointer(); // Offset 520 (0x208)

        // Create NativeFunction objects for each virtual function
        // Function at offset 376: takes _LocaleUpdate*, returns __int64
        const func376 = new NativeFunction(funcPtrAddr376, 'int64', ['pointer']);
        // Function at offset 384: takes _LocaleUpdate*, returns __int64
        const func384 = new NativeFunction(funcPtrAddr384, 'int64', ['pointer']);
        // Function at offset 520: takes _LocaleUpdate*, returns double
        const func520 = new NativeFunction(funcPtrAddr520, 'double', ['pointer']);

        // Call the virtual functions using the object pointer (localeUpdatePtr)
        const v42 = func376(localeUpdatePtr); // Returns Frida Int64
        const v43 = func384(localeUpdatePtr); // Returns Frida Int64
        const v44_double = func520(localeUpdatePtr); // Returns JavaScript number (double)

        // Replicate the calculations:

        // Reinterpret the bits of the double v44_double as a float
        // Allocate temporary memory, write the double, read back as float
        const tempDoublePtr = Memory.alloc(8);
        tempDoublePtr.writeDouble(v44_double);
        const v44_float = tempDoublePtr.readFloat(); // *(float *)&v44

        // v45 = (int)(float)((float)((float)v42 * 0.5) - (float)(*(float *)&v44 * 100.0));
        // Convert Int64 v42 to number for calculation. Note potential precision loss for very large int64.
        const v45_float_calc = (v42.toNumber() * 0.5) - (v44_float * 100.0);
        const v45 = Math.trunc(v45_float_calc); // C-style cast to int truncates towards zero

        // v46 = (int)(float)((float)v43 - (float)((float)v43 * 0.25));
        // Convert Int64 v43 to number.
        const v43_float = v43.toNumber();
        const v46_float_calc = v43_float - (v43_float * 0.25);
        const v46 = Math.trunc(v46_float_calc); // C-style cast to int truncates

        // v47 = *(float *)&v44 + *(float *)&v44;
        const v47 = v44_float + v44_float; // Result is a float (JS number)

        // Optional: Log the calculated values
        console.log(`[+] Replicated Calculations:`);
        console.log(`    v42 (Int64): ${v42}`);
        console.log(`    v43 (Int64): ${v43}`);
        console.log(`    v44 (double): ${v44_double}`);
        console.log(`    v44 (reinterpreted as float): ${v44_float}`);
        console.log(`    v45 (int): ${v45}`);
        console.log(`    v46 (int): ${v46}`);
        console.log(`    v47 (float): ${v47}`);

    } else {
        console.error("[-] Error: VTable pointer is null for object at " + localeUpdatePtr);
    }
} else {
    console.error("[-] Error: Pointer at qword_14981D2F8 (" + qword_14981D2F8_addr + ") is null.");
}

// // bool __fastcall is_valid_handle_typeB(unsigned __int64 *packed_handle_ptr) @ 0x14030C8B0
// Interceptor.attach(ptr('0x14030C8B0'), {
//   onEnter: function (args) {
//     //console.log("[+] is_valid_handle_typeB called");
//     //console.log("    packed_handle_ptr (pointer): " + args[0]);

//     // Store the pointer for potential use in onLeave or debugging
//     this.packed_handle_ptr = args[0];

//     // Attempt to read the packed handle value if the pointer is valid
//     if (this.packed_handle_ptr && !this.packed_handle_ptr.isNull()) {
//       try {
//         const packed_handle_value = this.packed_handle_ptr.readU64();
//         //console.log("    *packed_handle_ptr (uint64): " + packed_handle_value);
//         // Optional: Decode the handle parts based on the description
//         // const handle_ptr_part = packed_handle_value.and(ptr('0x0000FFFFFFFFFFFF')); // Lower 48 bits
//         // const handle_flags_part = packed_handle_value.shr(48).toNumber(); // Upper 16 bits
//         // console.log("      -> Pointer Part: " + handle_ptr_part);
//         // console.log("      -> Flags Part: 0x" + handle_flags_part.toString(16));
//       } catch (e) {
//         //console.log("    Error reading *packed_handle_ptr:", e);
//       }
//     } else {
//       //console.log("    packed_handle_ptr is null or invalid.");
//     }

//     // Optional: Add backtrace if needed
//     // console.log("Backtrace:");
//     // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//     //   .map(DebugSymbol.fromAddress).join('\n'));
//   },
//   onLeave: function (retval) {
//     // retval is a NativePointer (0 or 1 for bool)
//     const result = !!retval.toInt32(); // Convert to JavaScript boolean
//     //console.log("[+] is_valid_handle_typeB returned (bool): " + result);
//     if (result) {
//       //console.log("[+] Handle is valid.");
//     } else {
//       //console.log("[+] Handle is invalid.");
//     }
//   }
// });

const FUNC_OFFSET = 0x144C48B50;
// └─ if sub_144C48B50 is at 0x140000000 + 0x144C48B50, subtract the base.
//   Use Module.findBaseAddress to get the real base at runtime.

console.log("[+] Starting No-Clip Frida script");

const fnAddr = ptr(FUNC_OFFSET);
console.log(`[+] Hooking sub_144C48B50 at ${fnAddr}`);

Interceptor.attach(fnAddr, {
  onEnter(args) {
    ///////////////////////////////
    // MSVC x64 __fastcall:
    //   rcx = a1, rdx = a2, r8  = a3, r9  = a4, then stack for a5,a6
    ///////////////////////////////
    const a3 = this.context.r8;              // 3rd parameter is the object base
    const flagPtrPtr = a3.add(136);          // offset 0x88 = pointer to v17
    const v17 = Memory.readPointer(flagPtrPtr);
    if (!v17.isNull()) {
      // *v17 = 2  → No-Clip
      Memory.writeU32(v17, 2);
      // (optional) also force the “mode” to the No-Clip branch:
      Memory.writeU8(v17.add(1), 0);    // if you needed to tweak only certain bits
    }
    // now let the original run: since *v17==2 it's never zero, so early-out is skipped
  },
  onLeave(retval) {
    // no need to touch the return – it’ll be 1 on success.
  }
});

const funcAddr = ptr("0x147364B50");

console.log("[+] CXConsole::OnBeforeVarChange() hook @", funcAddr);

Interceptor.attach(funcAddr, {
  onEnter(args) {
    // __fastcall: rcx=a1, rdx=a2, r8=a3
    this.a1 = args[0];
    this.a2 = args[1];
    this.a3 = args[2];

    // Try to get the variable name via vtable call as in the prompt
    let varName = null;
    try {
      // hVar is this.a2
      const hVar = this.a2;
      if (!hVar.isNull()) {
        // Dereference vtable pointer
        const vtablePtr = hVar.readPointer();
        if (!vtablePtr.isNull()) {
          // Function pointer at offset 112 (0x70) for name getter
          const nameGetterPtr = vtablePtr.add(0x70).readPointer();
          if (!nameGetterPtr.isNull()) {
            const nameGetter = new NativeFunction(nameGetterPtr, 'pointer', ['pointer']);
            const namePtr = nameGetter(hVar);
            if (!namePtr.isNull()) {
              varName = Memory.readUtf8String(namePtr);
            }
          }
        }
      }
    } catch (e) {
      // If anything fails, just leave varName as null
      varName = null;
    }

    try {
      const value = Memory.readUtf8String(this.a3);
      if (varName !== null) {
        console.log(`[+] OnBeforeVarChange: console=${this.a1}, hVar=${this.a2}, varName="${varName}", value="${value}"`);
      } else {
        console.log(`[+] OnBeforeVarChange: console=${this.a1}, hVar=${this.a2}, value="${value}"`);
      }
    } catch(e){
      if (varName !== null) {
        console.log(`[+] OnBeforeVarChange: console=${this.a1}, hVar=${this.a2}, varName="${varName}", value=@${this.a3}`);
      } else {
        console.log(`[+] OnBeforeVarChange: console=${this.a1}, hVar=${this.a2}, value=@${this.a3}`);
      }
    }
  },
  onLeave(retval) {
    // Force success
    retval.replace(ptr(1));
    console.log("[+] Bypassed all cvar checks → returning TRUE\n");
  }
});

Interceptor.attach(ptr('0x14155A1B0'), {
  onEnter: function (args) {
    // LawComponent::ComputeFine(__int64 gameContext2, _QWORD *p_finalCallbackFunc, int a3)
    // __fastcall: rcx=gameContext2, rdx=p_finalCallbackFunc, r8d=a3

    this.gameContext2 = args[0];
    this.p_finalCallbackFunc = args[1];
    this.a3 = args[2];

    // --- Replicate the function logic in JS ---
    let v3 = ptr(0);
    let v4 = 0.0;
    let v5 = 0;
    let v6 = 0;
    let v7 = 0.0;
    let fineResult = 0;

    // Step 1: v3 = *(_QWORD *)(gameContext2 + 40);
    try {
      v3 = this.gameContext2.add(40).readPointer();
      console.log(`[ComputeFine] v3 = *(gameContext2 + 40) = ${v3}`);
    } catch (e) {
      console.log(`[ComputeFine] Error reading v3: ${e}`);
      v3 = ptr(0);
    }

    if (!v3.isNull()) {
      // Step 2: v4 = *(float *)(v3 + 76)
      try {
        v4 = v3.add(76).readFloat();
        console.log(`[ComputeFine] v4 = *(float *)(v3 + 76) = ${v4}`);
      } catch (e) {
        console.log(`[ComputeFine] Error reading v4: ${e}`);
        v4 = 0.0;
      }

      if (v4 > 0.0) {
        // Step 3: v5 = *(_DWORD *)(v3 + 80)
        //         v6 = *(_DWORD *)(v3 + 84)
        try {
          v5 = v3.add(80).readS32();
          v6 = v3.add(84).readS32();
          console.log(`[ComputeFine] v5 = *(int *)(v3 + 80) = ${v5}`);
          console.log(`[ComputeFine] v6 = *(int *)(v3 + 84) = ${v6}`);
        } catch (e) {
          console.log(`[ComputeFine] Error reading v5/v6: ${e}`);
          v5 = 0;
          v6 = 0;
        }

        // Step 4: v7 = (float)a3
        v7 = this.a3.toInt32();
        console.log(`[ComputeFine] v7 (initial) = (float)a3 = ${v7}`);

        // Step 5: if (v6 < v5)
        if (v6 < v5) {
          if (v7 > v6) {
            // v7 = (float)((float)(v5 - v6)
            //        - (float)((float)(v5 - v6) / (float)((float)((float)(a3 - v6) / (float)(v5 - v6)) + 1.0)))
            //      + (float)v6;
            let diff = v5 - v6;
            let denom = ((v7 - v6) / diff) + 1.0;
            let inner = diff / denom;
            v7 = (diff - inner) + v6;
            console.log(`[ComputeFine] v7 (adjusted, v6 < v5, v7 > v6): ${v7}`);
          }
        } else {
          // else
          if (v7 < v5) {
            v5 = v7;
            console.log(`[ComputeFine] v5 (adjusted, v6 >= v5, v7 < v5): ${v5}`);
          }
          v7 = v5;
          console.log(`[ComputeFine] v7 (set to v5): ${v7}`);
        }

        // Step 6: *p_finalCallbackFunc = (unsigned int)(int)(float)((float)(v7 / v4) * 600000000.0);
        let fineFloat = (v7 / v4) * 600000000.0;
        fineResult = (fineFloat >= 0) ? Math.floor(fineFloat) : Math.ceil(fineFloat); // C cast to int truncates toward zero
        fineResult = fineResult >>> 0; // force unsigned
        try {
          this.p_finalCallbackFunc.writeU64(fineResult);
          console.log(`[ComputeFine] *p_finalCallbackFunc = ${fineResult}`);
        } catch (e) {
          console.log(`[ComputeFine] Error writing fineResult: ${e}`);
        }
        this.computedFine = fineResult;
        this.shortCircuit = false;
      } else {
        // v4 <= 0.0
        try {
          this.p_finalCallbackFunc.writeU64(0);
          console.log(`[ComputeFine] v4 <= 0.0, *p_finalCallbackFunc = 0`);
        } catch (e) {
          console.log(`[ComputeFine] Error writing zero fine: ${e}`);
        }
        this.computedFine = 0;
        this.shortCircuit = true;
      }
    } else {
      // v3 is null
      try {
        this.p_finalCallbackFunc.writeU64(0);
        console.log(`[ComputeFine] v3 is null, *p_finalCallbackFunc = 0`);
      } catch (e) {
        console.log(`[ComputeFine] Error writing zero fine: ${e}`);
      }
      this.computedFine = 0;
      this.shortCircuit = true;
    }

    // Print all input and output for clarity
    console.log("[+] LawComponent::ComputeFine called");
    console.log("    gameContext2 (__int64): " + this.gameContext2);
    console.log("    p_finalCallbackFunc (_QWORD*): " + this.p_finalCallbackFunc);
    console.log("    a3 (int): " + this.a3.toInt32());
    console.log("    computedFine (unsigned int): " + this.computedFine);
    // Optionally, print backtrace
    console.log("Backtrace:");
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).join('\n'));
  },
  onLeave: function (retval) {
    // retval is p_finalCallbackFunc
    console.log("[+] LawComponent::ComputeFine returned (_QWORD*): " + retval);
    // Dump the value pointed to by retval if not null
    if (retval && !retval.isNull()) {
      try {
        const fineVal = retval.readU64();
        console.log("    *retval (final fine): " + fineVal);
      } catch (e) {
        console.log("Error reading *retval:", e);
      }
    }
    // Also print the computed fine from onEnter for redundancy
    if (typeof this.computedFine !== "undefined") {
      console.log("    [replicated] computedFine: " + this.computedFine);
    }
    if (this.shortCircuit) {
      console.log("    [replicated] short-circuit: fine set to 0 due to v3/v4");
    }
  }
});

/*
Persistent ammo tracker for sub_145819810.
Tracks all seen a1 pointers (gun instances), their current/max ammo, and last update time.
Prints a sorted ASCII table every 1s. Removes entries not updated in 20s.
*/

(function() {
  const AMMO_TRACK_TIMEOUT_MS = 20000;
  const AMMO_TRACK_PRINT_INTERVAL_MS = 1000;

  // Map: key = a1.toString(), value = { ptr: a1, curr: v10, max: v12, last: Date.now(), vtable: vtablePtr }
  const ammoMap = new Map();

  function clearScreen() {
    // ANSI escape code to clear screen and move cursor to top-left
    // Works in most terminals and some Frida consoles
    // If not supported, will just print a lot of newlines
    try {
      process.stdout.write('\x1b[2J\x1b[0;0H');
    } catch (e) {
      // fallback: print newlines
      for (let i = 0; i < 40; i++) console.log('');
    }
  }

  function renderTable() {
    clearScreen();
    const now = Date.now();
    // Remove stale entries
    for (const [k, v] of ammoMap.entries()) {
      if (now - v.last > AMMO_TRACK_TIMEOUT_MS) {
        ammoMap.delete(k);
      }
    }
    // Prepare sorted array
    const arr = Array.from(ammoMap.values()).sort((a, b) => {
      // Sort by pointer value (as unsigned 64-bit)
      const aVal = typeof a.ptr === "object" && a.ptr.toString ? ptr(a.ptr).toUInt32 ? ptr(a.ptr).toUInt32() : parseInt(a.ptr.toString()) : parseInt(a.ptr);
      const bVal = typeof b.ptr === "object" && b.ptr.toString ? ptr(b.ptr).toUInt32 ? ptr(b.ptr).toUInt32() : parseInt(b.ptr.toString()) : parseInt(b.ptr);
      if (aVal < bVal) return -1;
      if (aVal > bVal) return 1;
      return 0;
    });

    // Render ASCII table
    const lines = [];
    lines.push("+--------------------------+------------+------------+---------------------+--------------------------+");
    lines.push("|        Instance Ptr      | Curr Ammo  | Max Ammo   | Last Update (ago)   |      VTable Ptr          |");
    lines.push("+--------------------------+------------+------------+---------------------+--------------------------+");
    for (const entry of arr) {
      const ptrStr = entry.ptr.toString().padStart(22, " ");
      const currStr = entry.curr.toString().padStart(10, " ");
      const maxStr = entry.max.toString().padStart(10, " ");
      const agoSec = ((now - entry.last) / 1000).toFixed(1).padStart(11, " ");
      const vtableStr = entry.vtable ? entry.vtable.toString().padStart(24, " ") : " ".repeat(24);
      lines.push(`| ${ptrStr} | ${currStr} | ${maxStr} | ${agoSec} s ago | ${vtableStr} |`);
    }
    lines.push("+--------------------------+------------+------------+---------------------+--------------------------+");
    console.log(lines.join("\n"));
  }

  // Print table every second
  setInterval(renderTable, AMMO_TRACK_PRINT_INTERVAL_MS);

  Interceptor.attach(ptr('0x145819810'), {
    onEnter: function (args) {
      // __fastcall: rcx=a1, edx=a2, r8b=n2
      const a1 = args[0];
      let v10 = 0, v12 = 0, vtablePtr = null;
      try {
        v10 = a1.add(244).readU32();
        v12 = a1.add(240).readU32();
      } catch (e) {
        // Ignore read errors
      }
      try {
        vtablePtr = a1.readPointer();
      } catch (e) {
        vtablePtr = null;
      }
      // Update or insert in map
      const key = a1.toString();
      ammoMap.set(key, {
        ptr: a1,
        curr: v10,
        max: v12,
        last: Date.now(),
        vtable: vtablePtr
      });
      // No per-call printout; table is printed by timer
    },
    onLeave: function (retval) {
      // No per-call printout
    }
  });
})();
