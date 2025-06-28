/*
 *  Frida Hook Framework
 *  ====================
 *  Drop-in utilities to instrument native functions with rich,
 *  colourised logging, xhexdumps, recursive pointer inspection,
 *  and backtraces.  All heavy lifting is here; your “front-end”
 *  scripts become <10 lines.
 *
 *  Author: 2025-04-23
 *  Tested on:   Windows 10 / Win11, macOS 14, Linux 6.x
 *  Frida ≥16.2, v8 and QuickJS runtimes
 */

'use strict';

/* ─────────────────── Terminal Colours ─────────────────── */
const C = {
  reset  : '\x1b[0m',
  bold   : '\x1b[1m',
  dim    : '\x1b[2m',
  red    : '\x1b[31m',
  green  : '\x1b[32m',
  yellow : '\x1b[33m',
  blue   : '\x1b[34m',
  magenta: '\x1b[35m',
  cyan   : '\x1b[36m',
  grey   : '\x1b[90m'
};

/* ─────────────────── Generic Helpers ─────────────────── */
function pad (s, n, ch = '0') { return s.toString().padStart(n, ch); }
function hr (char = '─', n = 60, colour = C.blue) {
  console.log(`${C.bold}${colour}${char.repeat(n)}${C.reset}`);
}
function stripAnsi (s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }

/* ─────────────────── Hexdump ─────────────────── */
function xhexdump (ptr, bytes = 64, indent = '') {
  if (ptr.isNull()) {
    console.log(`${indent}${C.dim}(null pointer)${C.reset}`);
    return;
  }
  let buf;
  try { buf = ptr.readByteArray(bytes); }
  catch (e) {
    console.log(`${indent}${C.red}!! cannot read @ ${ptr}: ${e}${C.reset}`);
    return;
  }
  const U8 = new Uint8Array(buf);
  const perLine = 16;
  for (let i = 0; i < U8.length; i += perLine) {
    const line = U8.slice(i, i + perLine);
    const addr = ptr.add(i).toString(16).padStart(Process.pointerSize * 2, '0');
    let hs = '', ascii = '';
    for (let j = 0; j < perLine; j++) {
      if (j < line.length) {
        const b = line[j];
        hs    += pad(b.toString(16), 2) + ' ';
        ascii += (b>=32 && b<=126) ? String.fromCharCode(b) : '.';
      } else {
        hs    += '   ';
        ascii += ' ';
      }
      if (j === 7) hs += ' ';
    }
    console.log(`${indent}${C.yellow}${addr}${C.reset}  ${C.grey}${hs}${C.reset} ${C.cyan}${ascii}${C.reset}`);
  }
}

/* ─────────────────── Symbol formatting ─────────────────── */
function symbolise (addr) {
  try {
    const s = DebugSymbol.fromAddress(addr);
    if (s.moduleName) {
      const off = addr.sub(s.address);
      return `${C.green}${s.moduleName}!${C.reset}${C.bold}${s.name}${C.reset}` +
             (off.isZero() ? '' : ` +0x${off.toString(16)}`);
    }
  } catch (_) { /* ignore */ }
  const m = Process.findModuleByAddress(addr);
  if (m) return `${C.green}${m.name}!${C.reset}${C.grey}0x${addr.sub(m.base).toString(16)}${C.reset}`;
  return `${C.grey}${addr}${C.reset}`;
}

/* ─────────────────── Pointer Scanner ─────────────────── */
function scanPointers (base, opts, indent = '', depth = 0, seen = new Set()) {
  // Returns: boolean indicating if a pointer within the main module was found at this level or deeper.

  const {maxDepth, scanBytes, onlyMainModule = false} = opts;

  // --- Base conditions ---
  if (base.isNull() || depth >= maxDepth) {
    return false; // Stop recursion
  }

  const key = base.toString();
  if (seen.has(key)) {
    // Cycle detected: Already processing this address in the current path.
    console.log(`${indent}${C.dim}(cycle)${C.reset}`);
    return false; // Don't recurse further down this path, report no main module pointer found *here*
  }
  seen.add(key); // Mark this address as visited for the current path

  // --- Main module setup (only if filtering) ---
  let mainModuleBase = null;
  let mainModuleEnd = null;
  let mainModuleDetermined = false;
  let effectiveOnlyMainModule = onlyMainModule; // Use a flag that can be turned off if module not found
  if (onlyMainModule) {
    const mainModule = Process.mainModule;
    if (mainModule) {
      mainModuleBase = mainModule.base;
      mainModuleEnd = mainModule.base.add(mainModule.size);
      mainModuleDetermined = true;
    } else {
      // Only warn once at the top level? This might print multiple times.
      // Consider moving warning outside the recursive function if it becomes noisy.
      console.warn(`${indent}${C.yellow}Warning: Could not determine main module for filtering. Displaying all pointers.${C.reset}`);
      effectiveOnlyMainModule = false; // Disable filtering if module unknown
    }
  }

  // --- Check base readability ---
  try {
    // Check if the memory range we intend to scan is readable.
    base.readByteArray(scanBytes);
  } catch (e) {
    // Cannot read the base pointer's memory, stop scanning this branch.
    // No message needed here, as the caller might handle unreadable pointers.
    seen.delete(key); // Unwind seen set
    return false;
  }

  let foundMainInChildren = false; // Track if any pointer found (p) or any deeper pointer is in the main module

  // --- Iterate through potential pointers within the base address range ---
  for (let off = 0; off <= scanBytes - Process.pointerSize; off += Process.pointerSize) {
    const loc = base.add(off); // Memory location where the potential pointer resides
    let p; // The potential pointer value
    try {
      p = loc.readPointer();
    } catch {
      continue; // Skip if we cannot read the pointer value itself
    }

    // Skip null pointers and pointers to very low addresses (likely not valid pointers)
    if (p.isNull() || p.compare(0x10000) < 0) {
      continue;
    }

    // --- Get info about the pointer p ---
    let readable = false;
    let protection = C.dim + 'unknown' + C.reset;
    let canQueryProtection = false;
    try {
      // Check memory protection of the target address p points to
      protection = Memory.queryProtection(p);
      if (protection.includes('r')) { // Check if readable
          readable = true;
      }
      canQueryProtection = true;
    } catch (_) {
      // Ignore errors querying protection, might be invalid address
    }
    const sym = symbolise(p); // Get symbol information for the address p

    // --- Check if p points into the main module (if filtering) ---
    const pIsInMain = effectiveOnlyMainModule && mainModuleDetermined
                      ? (p.compare(mainModuleBase) >= 0 && p.compare(mainModuleEnd) < 0)
                      : false;

    // --- Recurse if the pointer target is readable ---
    let childFoundMain = false;
    if (readable) {
      // Recurse *first* to determine if this path leads to a main module pointer.
      // The recursive call will handle its own cycle checks.
      childFoundMain = scanPointers(p, opts, indent + '  ', depth + 1, seen);
    }

    // --- Decide whether to print the current step (loc -> p) ---
    let shouldPrint = false;
    if (!effectiveOnlyMainModule) {
      // Not filtering: always print this step
      shouldPrint = true;
    } else {
      // Filtering: print this step only if p itself is in the main module,
      // OR if the recursive call found a main module pointer down this path.
      if (pIsInMain || childFoundMain) {
        shouldPrint = true;
      }
    }

    // --- Print pointer details if needed ---
    if (shouldPrint) {
      const offStr = '+0x' + pad(off.toString(16), Process.pointerSize * 2);
      console.log(`${indent}${C.yellow}[${offStr}]${C.reset} → ${C.magenta}${p}${C.reset}`);
      console.log(`${indent}   ${sym}`);
      if (canQueryProtection) {
        console.log(`${indent}   ${readable ? C.cyan + 'readable' + C.reset : C.dim + 'unreadable' + C.reset} (${protection})`);
      } else {
        console.log(`${indent}   ${C.dim}readability unknown${C.reset}`);
      }
      // Note: The output for children of p (if any) would have already been printed
      // by the recursive call *before* this parent pointer's details are printed.
    }

    // --- Update overall status for this base address ---
    // If p was in main, or any child path found main, mark this branch as successful.
    if (pIsInMain || childFoundMain) {
      foundMainInChildren = true;
    }
  } // end for loop over offsets

  seen.delete(key); // Remove from seen set when returning from this level of recursion
  return foundMainInChildren; // Return whether a main module pointer was found at this level or deeper
}

/* ─────────────────── Core Hook Function ─────────────────── */
function intercept (ptrOrStr, options = {}) {
  const defaults = {
    name               : 'anonymous',
    argNames           : null,          // array<string> or null
    dumpArgs           : true,
    xhexdumpBytes       : 64,
    scanBytes          : 64,
    maxDepth           : 3,
    onlyMainModule     : true,
    backtrace          : true,
    onEnterCallback    : null,          // function(args, context, state)
    onLeaveCallback    : null,          // function(retval, context, state)
    colour             : C.blue
  };
  const cfg = Object.assign({}, defaults, options);

  const target = typeof ptrOrStr === 'string' ? ptr(ptrOrStr) : ptrOrStr;
  if (typeof target !== 'object' || target.isNull())
    throw new Error('invalid target pointer');

  console.log(`${C.bold}${C.green}[+] Intercepting ${cfg.name} @ ${target}${C.reset}`);

  Interceptor.attach(target, {
    onEnter (args) {
      const state = {};               // per-call scratch space for user
      const prefix = `${C.bold}${cfg.colour}│${C.reset}`;

      hr('┌', 60, cfg.colour);
      const ts = new Date().toISOString();
      console.log(`${prefix} ${C.dim}${ts} thread=${this.threadId}${C.reset}`);
      console.log(`${prefix} ${C.cyan}${cfg.name} entered${C.reset}`);

      /* arguments */
      if (cfg.dumpArgs) {
        const names = cfg.argNames || Array.from({length:3},(_,i)=>`arg${i}`);
        names.forEach((n,i)=>{
          const p = args[i];
          console.log(`${prefix}   ${C.cyan}${n}:${C.reset} ${p}`);
          xhexdump(p, cfg.xhexdumpBytes, prefix + '     ');
          console.log(`${prefix}     ${C.bold}${C.yellow}Pointer analysis:${C.reset}`);
          scanPointers(p, cfg, prefix + '     ');
          console.log(prefix);
        });
      }

      /* backtrace */
      if (cfg.backtrace) {
        console.log(`${prefix} ${C.green}Backtrace:${C.reset}`);
        Thread.backtrace(this.context, Backtracer.ACCURATE)
              .forEach((a,i)=>console.log(`${prefix}   ${C.dim}[${pad(i,2)}]${C.reset} ${symbolise(a)}`));
      }
      hr('├',60,cfg.colour);

      if (typeof cfg.onEnterCallback === 'function')
        try { cfg.onEnterCallback.call(this, args, this.context, state); }
        catch(e){ console.error(`${C.red}[onEnter cb] ${e}${C.reset}`); }

      this.__hookState = state;       // preserve for onLeave
    },

    onLeave (retval) {
      if (typeof cfg.onLeaveCallback === 'function')
        try { cfg.onLeaveCallback.call(this, retval, this.context, this.__hookState); }
        catch(e){ console.error(`${C.red}[onLeave cb] ${e}${C.reset}`); }

      hr('└',60,cfg.colour);
      console.log('');
    }
  });
}


// optional user-defined callbacks
function onEnter (args, ctx, st) {
  // store something for later
  st.start = Date.now();
}
function onLeave (rv, ctx, st) {
  const duration = Date.now() - st.start;
  console.log(`│   took ${duration} ms`);
}

intercept('0x1402A5FE0', {
  name        : 'sub_1402A5FE0',
  argNames    : ['a1','a2','i'],
  xhexdumpBytes: 64,
  scanBytes   : 64,
  maxDepth    : 3,
  onEnterCallback: onEnter,
  onLeaveCallback: onLeave,
  colour      : C.magenta
});
