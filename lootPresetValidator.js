// -----------------------------------------------------------------------------
//  dump_loot_preset_validator.js  —  Frida 16.x script
// -----------------------------------------------------------------------------
//  Hooks the Harvestable/Loot‑preset validator routines that were reverse‑
//  engineered from the de‑compiled listing you supplied.
//
//  What it prints (all addresses are process‑local, 64‑bit):
//  • Entry into sub_14334DF20 (the top‑level preset validator)
//      – this.rcx0      : first argument (opaque context)
//      – this.a2        : pointer to the { name‑hash, … } wrapper
//      – this.a3        : ‘quiet’ flag (0 = verbose, 1 = silent)
//      – Preset name    : resolved through helper sub_1403AF8F0
//      – LootTable ptr  : *((a2)+16)
//      – numEntries     : *(lootTable+32)
//      – For each Entry (56 bytes each)
//          ∘ ArchetypeId : first 16 bytes as hex
//          ∘ MinResults  : *(+40)
//          ∘ MaxResults  : *(+44)
//  • Every diagnostic emitted through sub_1405BD4A0 (printf‑like logger)
//  • Function exit with return value (0 = failed, 1 = passed)
//
//  HOW TO USE
//  ----------
//  $ frida -l dump_loot_preset_validator.js -p <PID>
//
// -----------------------------------------------------------------------------

"use strict";

////////////////////////////////////////////////////////////////////////////////
// Helper utilities                                                            //
////////////////////////////////////////////////////////////////////////////////

function hex(ptr) {
  return ptr.toString(16).padStart(16, "0");
}

function readUuid(ptr) {
  // 16‑byte archetype identifier → printable hex string
  const bytes = Memory.readByteArray(ptr, 16);
  const u8 = new Uint8Array(bytes);
  return Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Try to read a zero‑terminated UTF‑8 string, tolerate nullptr
function safeReadUtf8(ptr) {
  if (ptr.isNull()) return "<null>";
  try {
    return Memory.readUtf8String(ptr);
  } catch (_) {
    return "<bad‑ptr>";
  }
}

////////////////////////////////////////////////////////////////////////////////
// Constants:  offsets relative to module base                                //
////////////////////////////////////////////////////////////////////////////////

const moduleName = "StarCitizen.exe"; // <- change if needed
const base = Module.findBaseAddress(moduleName);
if (base === null) throw new Error(`Module ${moduleName} not loaded`);

// Addresses taken from the de‑compiled listing (image assumes PE base 0x140000000)
const RVA = (addr) => base.add(ptr(addr).and(ptr("0xFFFFFFFF")));

const addr_validatePreset = RVA("0x334DF20"); // sub_14334DF20
const addr_logger = RVA("0x05BD4A0"); // sub_1405BD4A0
const addr_nameResolve = RVA("0x03AF8F0"); // sub_1403AF8F0

////////////////////////////////////////////////////////////////////////////////
// NativeFunction shims                                                       //
////////////////////////////////////////////////////////////////////////////////

// const char * __fastcall nameResolve(void *nameHashWrapper)
const nameResolve = new NativeFunction(addr_nameResolve, "pointer", [
  "pointer",
]);

// int logger(unsigned int sev, unsigned int flags, const char *fmt, ...);
// We cannot know the full prototype, but we can intercept with Interceptor.

////////////////////////////////////////////////////////////////////////////////
// Hook the logger so we can capture diagnostics                              //
////////////////////////////////////////////////////////////////////////////////

//Interceptor.attach(addr_logger, {
//  onEnter(args) {
//    const fmt = args[5];
//    // The logger uses a printf‑style format string;  we just dump it raw.
//    this.message = safeReadUtf8(fmt);
//    if (this.message.indexOf("%") !== -1) {
//      // Best‑effort: replace the first seven arguments; remaining varargs
//      // are difficult to decode without type info.
//      const argv = [];
//      for (let i = 6; i < 12; i++) {
//        try {
//          argv.push(safeReadUtf8(args[i]));
//        } catch (_) {
//          argv.push(hex(args[i]));
//        }
//      }
//      console.log(`LOG[${args[0].toUInt32()}] →`, this.message, "ARGS=", argv);
//    } else {
//      console.log(`LOG[${args[0].toUInt32()}] →`, this.message);
//    }
//  },
//});

////////////////////////////////////////////////////////////////////////////////
// Hook the top‑level validator                                               //
////////////////////////////////////////////////////////////////////////////////

Interceptor.attach(addr_validatePreset, {
  onEnter(args) {
    this.retval = null; // captured later in onLeave

    const rcx0 = args[0];
    const a2 = args[1];
    const a3 = args[2].toInt32();

    // Resolve preset name via helper
    const presetNamePtr = nameResolve(a2);
    const presetName = safeReadUtf8(presetNamePtr);

    // LootTable object is *((a2)+16)
    const lootTable = Memory.readPointer(a2.add(16));
    let numEntries = 0;
    try {
      numEntries = Memory.readU64(lootTable.add(32));
    } catch (_) {
      console.log("[!] Failed to read numEntries – corrupted pointer?");
    }

    console.log(
      "\n===================== PRESET VALIDATION CALL =====================",
    );
    console.log("presetName         =", presetName);
    console.log("quietFlag (a3)     =", a3);
    console.log("lootTable          = 0x" + hex(lootTable));
    console.log("numEntries         =", numEntries);

    // Iterate through entries if table looks sane
    if (!lootTable.isNull() && numEntries > 0 && numEntries < 0x1000) {
      const entrySize = 56;
      let entryPtr = lootTable.add(24); // first entry (offset +24)
      for (let i = 0; i < numEntries; i++) {
        const archetypeIdPtr = entryPtr; // first 16 bytes
        const minResults = Memory.readU32(entryPtr.add(40));
        const maxResults = Memory.readU32(entryPtr.add(44));

        console.log(
          `  [${i}] archetypeId = ${readUuid(archetypeIdPtr)}, min=${minResults}, max=${maxResults}`,
        );
        entryPtr = entryPtr.add(entrySize);
      }
    } else {
      console.log("[!] Skipping entry dump – invalid count or pointer");
    }
  },

  onLeave(retval) {
    this.retval = retval;
    console.log("Validator returned:", retval.toInt32() ? "PASS" : "FAIL");
    console.log(
      "================================================================\n",
    );
  },
});

console.log("[*] Loot‑preset validator hook installed.");
