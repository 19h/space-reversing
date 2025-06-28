// Star Citizen Structure Analysis Tool
// Target: GetStructDataFields (sub_14723EB40)

// --- CONFIGURATION ---
const gEnvBase = ptr("0x14981d200");

function findValidDataCoreOffset(structName, startOffset, endOffset) {
    for (let offset = startOffset; offset <= endOffset; offset++) {
        const candidateAddr = gEnvBase.add(offset).readPointer();
        try {
            // Try to call GetStructDataFields with this candidate address
            const structNamePtr = Memory.allocUtf8String(structName);
            const vectorStructSize = Process.pointerSize * 3;
            const vectorStructPtr = Memory.alloc(vectorStructSize);
            Memory.writePointer(vectorStructPtr.add(0 * Process.pointerSize), NULL);
            Memory.writePointer(vectorStructPtr.add(1 * Process.pointerSize), NULL);
            Memory.writePointer(vectorStructPtr.add(2 * Process.pointerSize), NULL);

            // Try the call
            const count = GetStructDataFields(
                candidateAddr,
                structNamePtr,
                vectorStructPtr,
                GET_INHERITED_FIELDS
            );

            // If we get here, the call didn't throw. Check if count is reasonable.
            if (typeof count === "number" || (count && count.toInt32() >= 0)) {
                console.log(`[+] Found valid DataCore offset: 0x${offset.toString(16)} (Address: ${candidateAddr})`);
                return { offset, address: candidateAddr };
            }
        } catch (e) {
            // Ignore and try next offset
        }
    }
    console.error("[!] Could not find a valid DataCore offset in the given range.");
    return null;
}

console.log(findValidDataCoreOffset("CDataCore", 0x0, 0x10000));