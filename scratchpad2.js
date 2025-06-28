/*
bool __fastcall sub_1465C7320(__int64 a1, __int64 a2)
{
  float v3; // [rsp+20h] [rbp-68h]
  float v4; // [rsp+34h] [rbp-54h]
  __int64 v5; // [rsp+38h] [rbp-50h]
  __int64 v6; // [rsp+40h] [rbp-48h]
  __int64 v7[2]; // [rsp+48h] [rbp-40h] BYREF
  __int64 v8; // [rsp+58h] [rbp-30h]
  __int64 *v9; // [rsp+60h] [rbp-28h]
  __int64 v10; // [rsp+68h] [rbp-20h]
  _QWORD v11[3]; // [rsp+70h] [rbp-18h] BYREF
  __int64 v13; // [rsp+98h] [rbp+10h] BYREF

  v13 = a2;
  v5 = sub_1465C9590(a1);
  if ( !v5 )
    return 0;
  v8 = sub_14030ECF0(&v13);
  v9 = sub_141872140(v8, v11);
  v10 = *v9;
  v7[0] = v10;
  if ( !is_valid_handle_typeA(v7) )
    return 0;
  v6 = sub_1465C9110(a1);
  v4 = *(float *)(v5 + 0x58) * sub_143825690(a1, 0);
  if ( *(float *)(v6 + 0x84) > 1.0 )
    v3 = *(float *)(v6 + 0x84);
  else
    v3 = 1.0;
  v7[1] = v7[0] & 0xFFFFFFFFFFFFLL;
  return (float)((*(float (__fastcall **)(__int64))(*(_QWORD *)(v7[0] & 0xFFFFFFFFFFFFLL) + 0x580LL))(v7[0] & 0xFFFFFFFFFFFFLL)
               * (float)(v3 / 9.8100004)) <= v4;
}

char __fastcall sub_1463420C0(__int64 a1, _QWORD *a2)
{
  __int64 v3; // [rsp+20h] [rbp-58h] BYREF
  __int64 v4; // [rsp+28h] [rbp-50h]
  __int64 *v5; // [rsp+30h] [rbp-48h]
  __int64 v6; // [rsp+38h] [rbp-40h]
  __int64 v7; // [rsp+40h] [rbp-38h]
  __int64 v8; // [rsp+48h] [rbp-30h]
  __int64 v9; // [rsp+50h] [rbp-28h]
  __int64 v10; // [rsp+58h] [rbp-20h]
  _QWORD v11[3]; // [rsp+60h] [rbp-18h] BYREF

  v4 = sub_14030ECF0(a2 + 9);
  v5 = sub_1425D62E0(v4, v11);
  v6 = *v5;
  v3 = v6;
  if ( is_valid_handle_typeA(&v3) )
  {
    v8 = v3 & 0xFFFFFFFFFFFFLL;
    v7 = a2[0xA];
    if ( (unsigned __int8)sub_1465C7320(v3 & 0xFFFFFFFFFFFFLL, v7) )
    {
      return 1;
    }
    else
    {
      if ( a2[8] )
      {
        v9 = a2[8];
        sub_1402A3190(v9, "IC_CheckItemWeight: Can't carry entity");
      }
      return 0;
    }
  }
  else
  {
    if ( a2[8] )
    {
      v10 = a2[8];
      sub_1402A3190(v10, "IC_CheckItemWeight: No actor");
    }
    return 0;
  }
}
*/

console.log(-1);

const fnrplretval = [
    //[ptr(0x1405AFFD0), ptr(0x1), "valid container"], // is valid container?
    [ptr(0x14633EFC0), ptr(0x1), "badge check"], // interaction check: badge check (IC_AccountBadge)
    [ptr(0x146341AF0), ptr(0x1), "inventory store check"], // interaction check: can store in personal inventory? (IC_CanStoreInPersonalInventory)
    [ptr(0x146341C00), ptr(0x1), "actor state check"], // interaction check: check actor state (IC_CheckActorState)
    [ptr(0x1463420C0), ptr(0x1), "carryable check"], // interaction check: func above is carryable
    [ptr(0x1463433B0), ptr(0x0), "entity attached check"], // interaction check: is entity attached to other actor? (IC_EntityIsAttachedToOtherActor)
    [ptr(0x146345D50), ptr(0x0), "armor attached check"], // interaction check: does entity owner have armor attached? (IC_InteractableEntityOwnerHasArmorAttached)
    [ptr(0x146346110), ptr(0x1), "incapacitated check"], // interaction check: is interactable target incapacitated? (IC_InteractableIsIncapacitatedActor)
    [ptr(0x146348590), ptr(0x1), "lootable view check"], // LootableNotBeingViewedByAnyOtherInventory
    [ptr(0x1465C7320), ptr(0x1), "weight check"], // check weight -> is carryable
];

for (const [addr, value, desc] of fnrplretval) {
    Interceptor.attach(addr, {
        onLeave: function(retval) {
            retval.replace(value);

            //console.log("[" + addr + "] " + desc + " - forced retval: " + value);
        }
    });
}

Interceptor.replace(ptr(0x14606C700), new NativeCallback(function(a1, a2, a3, a4, a5, a6, a7, a8) {
    // Empty function body - does nothing
}, 'void', ['int64', 'char', 'int64', 'int64', 'int64', 'int', 'pointer', 'int64']));

Interceptor.replace(ptr(0x146064930), new NativeCallback(function(a1, a2, a3, a4, a5, a6, a7, a8) {
    return 0.0;
}, 'double', ['pointer', 'uint8', 'int64', 'int64', 'pointer', 'int64', 'pointer', 'pointer']));

Interceptor.replace(ptr(0x146833D70), new NativeCallback(function(a1, a2, a3) {
    return 0;
}, 'int64', ['pointer', 'float', 'float']));

Interceptor.replace(ptr(0x1469C2CF0), new NativeCallback(function() {
    // Empty function body - does nothing
}, 'void', []));

Interceptor.attach(ptr(0x145ECB7F0), {
    onEnter: function(args) {
        console.log("[0x145ECB7F0] Function called");
        console.log("Backtrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});

//Interceptor.attach(ptr(0x146ADC0A0), {
//    onEnter: function(args) {
//        console.log("[0x146ADC0A0] Function called - a1: " + args[0] + " (" + args[0].add(0x298).readPointer() + ") a2: " + args[1] + " (" + args[1].add(0x298).readPointer() + ")");
//    }
//});

Interceptor.attach(ptr(0x140BB63A0), {
    onEnter: function(args) {
        console.log("[0x140BB63A0] Function called");
        console.log("  a1: " + args[0]);
        console.log("  a2: " + args[1]);
        console.log("  a3: " + args[2]);
        console.log("  a4: " + args[3]);
        console.log("  a5: " + args[4]);
        console.log("  a6: " + args[5]);
        console.log("  a7: " + args[6]);
    },
    onLeave: function(retval) {
        console.log("[0x140BB63A0] Return value: " + retval);
    }
});
