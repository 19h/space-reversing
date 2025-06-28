/* ----- locate ISystem --------------------------------------------------- */
const gEnv = ptr('0x14981D200');      // SSystemGlobalEnvironment*
const pSystem  = gEnv.add(0x28).readPointer();          // ISystem*

/* ----- pick the virtual-table entry ------------------------------------- */
const vtbl             = pSystem.readPointer();         // first QWORD of the object
const SLOT_FindId      = 0x80;                          // v-table offset you saw in IDA
const fnFindInterface  = vtbl.add(SLOT_FindId).readPointer();

/* WORD __fastcall FindInterfaceId(ISystem *this, void *scratch, char *name) */
const FindInterfaceId  = new NativeFunction(
        fnFindInterface,
        'uint16',
        ['pointer', 'pointer', 'pointer']
);

/* ----- call it ---------------------------------------------------------- */
const scratch = Memory.alloc(4);
const guid    = FindInterfaceId(
        pSystem,                //  RCX / “this”
        scratch,                //  RDX
        Memory.allocUtf8String('IEntityRenderProxy')   //  R8
);

console.log(guid);
