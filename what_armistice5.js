// // Define the address for sub_14155B960 (bool return type)
// const targetAddress5 = ptr('0x14155B960');

// console.log(`[INFO] Fifth target function address identified at: ${targetAddress5}`);

// try {
//     // Hook sub_14155B960 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress5, new NativeCallback(
//         /**
//          * Replacement function for sub_14155B960.
//          * Original function: bool __fastcall sub_14155B960(__int64 a1, int a2)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
//          * @param {number} a2 - Corresponds to the original int a2 (in RDX).
//          * @returns {number} - Returns the bool value from the original function.
//          */
//         function (a1, a2) {
//             //console.log(`[HOOKED] sub_14155B960(${a1}, ${a2}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress5, 'bool', ['pointer', 'int'], 'win64');
//             const returnValue = originalFunction(a1, a2);

//             //console.log(`[INFO] Original function returned bool value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: bool
//         'bool',
//         // Argument types: __int64 and int
//         ['pointer', 'int'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress5}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress5}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// // Define the address for sub_141588DD0 (bool return type)
// const targetAddress6 = ptr('0x141588DD0');

// console.log(`[INFO] Sixth target function address identified at: ${targetAddress6}`);

// try {
//     // Hook sub_141588DD0 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress6, new NativeCallback(
//         /**
//          * Replacement function for sub_141588DD0.
//          * Original function: bool __fastcall sub_141588DD0(AK::WriteBytesCount *this, _WORD *a2)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original AK::WriteBytesCount *this (in RCX).
//          * @param {NativePointer} a2 - Corresponds to the original _WORD *a2 (in RDX).
//          * @returns {number} - Returns the bool value from the original function.
//          */
//         function (a1, a2) {
//             //console.log(`[HOOKED] sub_141588DD0(${a1}, ${a2}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress6, 'bool', ['pointer', 'pointer'], 'win64');
//             const returnValue = originalFunction(a1, a2);

//             //console.log(`[INFO] Original function returned bool value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: bool
//         'bool',
//         // Argument types: pointer and pointer
//         ['pointer', 'pointer'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress6}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress6}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// // Define the address for sub_141589560 (bool return type)
// const targetAddress7 = ptr('0x141589560');

// console.log(`[INFO] Seventh target function address identified at: ${targetAddress7}`);

// try {
//     // Hook sub_141589560 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress7, new NativeCallback(
//         /**
//          * Replacement function for sub_141589560.
//          * Original function: bool __fastcall sub_141589560(__int64 a1)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
//          * @returns {number} - Returns the bool value from the original function.
//          */
//         function (a1) {
//             //console.log(`[HOOKED] sub_141589560(${a1}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress7, 'bool', ['pointer'], 'win64');
//             const returnValue = originalFunction(a1);

//             //console.log(`[INFO] Original function returned bool value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: bool
//         'bool',
//         // Argument types: __int64
//         ['pointer'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress7}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress7}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// // Define the address for sub_141568730 (char return type)
// const targetAddress8 = ptr('0x141568730');

// console.log(`[INFO] Eighth target function address identified at: ${targetAddress8}`);

// try {
//     // Hook sub_141568730 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress8, new NativeCallback(
//         /**
//          * Replacement function for sub_141568730.
//          * Original function: char __fastcall sub_141568730(__int64 a1)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
//          * @returns {number} - Returns the char value from the original function.
//          */
//         function (a1) {
//             //console.log(`[HOOKED] sub_141568730(${a1}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress8, 'char', ['pointer'], 'win64');
//             const returnValue = originalFunction(a1);

//             //console.log(`[INFO] Original function returned char value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: char
//         'char',
//         // Argument types: __int64
//         ['pointer'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress8}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress8}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// // Define the address for sub_141599650 (char return type)
// const targetAddress9 = ptr('0x141599650');

// console.log(`[INFO] Ninth target function address identified at: ${targetAddress9}`);

// try {
//     // Hook sub_141599650 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress9, new NativeCallback(
//         /**
//          * Replacement function for sub_141599650.
//          * Original function: char __fastcall sub_141599650(__int64 a1)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
//          * @returns {number} - Returns the char value from the original function.
//          */
//         function (a1) {
//             //console.log(`[HOOKED] sub_141599650(${a1}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress9, 'char', ['pointer'], 'win64');
//             const returnValue = originalFunction(a1);

//             //console.log(`[INFO] Original function returned char value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: char
//         'char',
//         // Argument types: __int64
//         ['pointer'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress9}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress9}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// // Define the address for sub_1415A5F60 (char return type)
// const targetAddress10 = ptr('0x1415A5F60');

// console.log(`[INFO] Tenth target function address identified at: ${targetAddress10}`);

// try {
//     // Hook sub_1415A5F60 to intercept and log parameters and return value
//     Interceptor.replace(targetAddress10, new NativeCallback(
//         /**
//          * Replacement function for sub_1415A5F60.
//          * Original function: char __fastcall sub_1415A5F60(__int64 a1)
//          *
//          * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
//          * @returns {number} - Returns the char value from the original function.
//          */
//         function (a1) {
//             //console.log(`[HOOKED] sub_1415A5F60(${a1}) called.`);

//             // Call the original function to get its return value
//             const originalFunction = new NativeFunction(targetAddress10, 'char', ['pointer'], 'win64');
//             const returnValue = originalFunction(a1);

//             //console.log(`[INFO] Original function returned char value: ${returnValue}`);

//             return returnValue;
//         },
//         // Return type: char
//         'char',
//         // Argument types: __int64
//         ['pointer'],
//         // ABI specification for x64 Windows
//         'win64'
//     ));

//     //console.log(`[SUCCESS] Interceptor.replace has been successfully applied to ${targetAddress10}.`);

// } catch (error) {
//     console.error(`[FATAL] Failed to apply hook at ${targetAddress10}.`);
//     console.error(`[FATAL] Error details: ${error.message}`);
//     console.error(`[FATAL] Stack trace: \n${error.stack}`);
// }

// Interceptor.replace(
//     ptr(0x1415535D0),
//     new NativeCallback(
//         function (a1) {
//         },
//         'void',
//         ['pointer'],
//         'win64'
//     )
// );

// Interceptor.replace(
//     ptr(0x1415892F0),
//     new NativeCallback(
//         function (a1) {
//             return 1;
//         },
//         'bool',
//         ['pointer', 'pointer'],
//         'win64'
//     )
// );

// Define the address for sub_146095E10 (OnDamageResponse)
const targetAddress11 = ptr('0x146095E10');

console.log(`[INFO] Eleventh target function address identified at: ${targetAddress11}`);

try {
    // Hook sub_146095E10 to intercept and manipulate damage response
    Interceptor.replace(targetAddress11, new NativeCallback(
        /**
         * Replacement function for sub_146095E10 (OnDamageResponse).
         * Original function: void __fastcall sub_146095E10(__int64 a1, __int64 a2)
         *
         * @param {NativePointer} a1 - Corresponds to the original __int64 a1 (in RCX).
         * @param {NativePointer} a2 - Corresponds to the original __int64 a2 (in RDX) - pointer to damage result structure.
         * @returns {void} - Returns void from the original function.
         */
        function (a1, a2) {
            // Overwrite the damage result status to "Fractured" (value 2)
            // This forces the game to treat any damage as a successful fracture
            a2.writeU32(2);

            // Call the original function with the modified result
            const originalFunction = new NativeFunction(targetAddress11, 'void', ['pointer', 'pointer'], 'win64');
            originalFunction(a1, a2);
        },
        // Return type: void
        'void',
        // Argument types: __int64 and __int64
        ['pointer', 'pointer'],
        // ABI specification for x64 Windows
        'win64'
    ));

    console.log(`[SUCCESS] Rock fracturing bypass hook applied to ${targetAddress11}.`);

} catch (error) {
    console.error(`[FATAL] Failed to apply hook at ${targetAddress11}.`);
    console.error(`[FATAL] Error details: ${error.message}`);
    console.error(`[FATAL] Stack trace: \n${error.stack}`);
}
