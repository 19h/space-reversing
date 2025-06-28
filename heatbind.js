const moduleBase = Process.enumerateModulesSync()[0].base;
const moduleSize = Process.enumerateModulesSync()[0].size;

// scan for the bytes of "minTemp\0"
Memory.scan(moduleBase, moduleSize, '6D 69 6E 54 65 6D 70 00', {
  onMatch(addr, size) {
    // addr points at the 'm' of "minTemp"
    const tablePtr = addr.sub(Process.pointerSize);
    console.log('→ Found table at', tablePtr);

    // now dump out the C-string pointers
    for (let i = 0;; i++) {
      const p = tablePtr.add(i*Process.pointerSize).readPointer();
      if (p.isNull()) break;
      console.log(` [${i}] → ${Memory.readUtf8String(p)}`);
    }
  }
});
