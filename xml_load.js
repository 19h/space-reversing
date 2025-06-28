// -----------------------------------------------------------------------------
//  Star Citizen - hook for LoadingPlatformUtilities::LoadEntityFromXml
//  Decompiled RVA 0x004D553A0  (file VA 0x144D553A0, image base 0x140000000)
//
//  Build & run:
//     frida -l load-entity-from-xml.js -f "StarCitizen.exe" --no-pause
// -----------------------------------------------------------------------------
'use strict';

const moduleName = 'StarCitizen.exe';

/* -------------------------------------------------------------------------- *
 * 1.  Resolve the in-memory address                                          *
 * -------------------------------------------------------------------------- */
const base = Module.findBaseAddress(moduleName);
if (base === null) {
    throw new Error(`${moduleName} is not loaded!`);
}

/* 0x144D553A0 - 0x140000000 (default image base) = 0x004D553A0 */
const rva   = 0x004D553A0;
const impl  = base.add(rva);

console.log(`[+] ${moduleName} loaded @ ${base}`);
console.log(`[+] LoadingPlatformUtilities::LoadEntityFromXml @ ${impl}`);

/* -------------------------------------------------------------------------- *
 * 2.  Helper for the compact 64-bit entity descriptor                        *
 * -------------------------------------------------------------------------- */
function decodeEntityDescriptor(ptrVal) {
    /* ptrVal is a 64-bit integer stored in RCX */
    const raw = ptrVal.and(ptr('0xFFFFFFFFFFFFFFFF'));

    /* upper 16 bits = type/flags; lower 48 bits = ID or in-place address      */
    const typeFlags = raw.shr(48).and(0xFFFF);
    const idOrPtr   = raw.and(ptr('0xFFFFFFFFFFFF'));

    return {
        raw,
        typeFlags,
        idOrPtr
    };
}

/* -------------------------------------------------------------------------- *
 * 3.  Hook                                                                   *
 * -------------------------------------------------------------------------- */
Interceptor.attach(impl, {
    onEnter(args) {
        /* Windows-x64 fastcall → RCX,RDX,R8,R9 map to args[0…3]               */
        const entityDesc = decodeEntityDescriptor(args[0]);
        const pXmlRootPP = args[1];       // **IXmlNode       (pointer to pointer)
        const childName  = Memory.readCString(args[2]); // char const *
        const pCallback  = args[3];       // ICallback* (ref-counted)

        /* Weak attempt to dereference the XmlNode* to obtain tag text         */
        let xmlRootStr = '<unreadable>';
        try {
            const pXmlRoot = ptr(Memory.readPointer(pXmlRootPP));
            /* first virtual method often returns c-string tag for CryXML nodes */
            const vGetTag = Memory.readPointer(pXmlRoot).add(0x18);
            const getTag  = new NativeFunction(vGetTag, 'pointer', ['pointer']);
            xmlRootStr = Memory.readCString(getTag(pXmlRoot));
        } catch (_) { /* best-effort only */ }

        console.log('\n========== LoadEntityFromXml ==========');
        console.log(`entityDesc : ${entityDesc.raw}  ↠  type=0x${entityDesc.typeFlags.toString(16)}  id/ptr=0x${entityDesc.idOrPtr.toString(16)}`);
        console.log(`xmlRoot**  : ${pXmlRootPP}  -> "${xmlRootStr}"`);
        console.log(`childName  : "${childName}"`);
        console.log(`callback   : ${pCallback}`);
        console.log('=======================================\n');

        /* keep anything needed in onLeave */
        this.callback = pCallback;
    },

    onLeave(retval) {
        /* retval is void — nothing to report, but we can trace refcounts here
           if desired. For now we just confirm exit.                            */
        console.log(`↳ LoadEntityFromXml finished (callback ${this.callback})\n`);
    }
});
