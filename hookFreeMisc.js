/**
 * Frida Script: Intercept sub_1402A5FE0 with Recursive Pointer Analysis
 *
 * Target Function Signature:
 * __int64 __fastcall sub_1402A5FE0(__int64 a1, __int64 a2, __int64 i)
 *
 * Description:
 * This script intercepts calls to the function located at address 0x1402A5FE0.
 * It logs the function arguments (a1, a2, i) as pointers with hexdumps,
 * performs recursive analysis on potential pointers found within the argument data,
 * and logs the call stack (backtrace) upon entry using professional terminal formatting.
 */

(function () {
  // --- Configuration ---
  const targetAddress = ptr("0x1402A5FE0");
  const functionName = "sub_1402A5FE0"; // User-friendly name for logging
  const hexdumpSize = 64; // Bytes to dump for each pointer argument
  const pointerAnalysisDepth = hexdumpSize; // How many bytes of data to scan for pointers at each level
  const maxRecursionDepth = 3; // Maximum depth for recursive pointer analysis
  const pointerSize = Process.pointerSize; // Auto-detect: 4 or 8

  // --- ANSI Color Codes for Terminal Output ---
  const colors = {
    reset: "\x1b[0m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    blue: "\x1b[34m",
    green: "\x1b[32m",
    cyan: "\x1b[36m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    grey: "\x1b[90m",
    magenta: "\x1b[35m", // Added for pointer analysis
  };

  // --- Helper Function for Logging ---
  function logSeparator(char = "─", length = 60) {
    console.log(
      `${colors.bold}${colors.blue}${char.repeat(length)}${colors.reset}`,
    );
  }

  function logHeader(title) {
    const paddingLength = Math.max(0, 58 - title.length);
    const leftPadding = " ".repeat(Math.floor(paddingLength / 2));
    const rightPadding = " ".repeat(Math.ceil(paddingLength / 2));
    console.log(
      `${colors.bold}${colors.blue}│${leftPadding}${colors.yellow}${title}${rightPadding}│${colors.reset}`,
    );
  }

  /**
   * Generates and logs a formatted hexdump for a given pointer.
   * Meticulously fits the existing terminal layout.
   * @param {NativePointer} pointer The pointer to dump.
   * @param {number} size The number of bytes to dump.
   * @param {string} indent Indentation string for hexdump lines.
   * @param {string} prefix Prefix for each line (e.g., "│").
   */
  function logHexdump(
    pointer,
    size,
    indent = "     ",
    prefix = `${colors.blue}│${colors.reset}`,
  ) {
    if (pointer.isNull()) {
      console.log(
        `${prefix}${indent}${colors.dim}(null pointer)${colors.reset}`,
      );
      return;
    }
    try {
      // Use readByteArray for potentially partial reads
      const buf = pointer.readByteArray(size);
      if (!buf) {
        console.log(
          `${prefix}${indent}${colors.red}Failed to read memory at ${pointer}${colors.reset}`,
        );
        return;
      }

      const bytes = new Uint8Array(buf);
      const bytesPerLine = 16; // Standard hexdump width

      for (let i = 0; i < bytes.length; i += bytesPerLine) {
        const slice = bytes.slice(i, Math.min(i + bytesPerLine, bytes.length));
        const lineAddress = pointer.add(i); // Show actual address for each line
        const offset = lineAddress.toString(16).padStart(pointerSize * 2, "0"); // Pad address based on pointer size
        let hexString = "";
        let asciiString = "";

        for (let j = 0; j < bytesPerLine; j++) {
          if (j < slice.length) {
            const byte = slice[j];
            hexString += byte.toString(16).padStart(2, "0") + " ";
            // Printable ASCII range (32-126)
            asciiString +=
              byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".";
          } else {
            hexString += "   "; // Padding for shorter lines
            asciiString += " ";
          }
          if (j === 7) {
            // Add extra space in the middle of hex bytes
            hexString += " ";
          }
        }

        console.log(
          `${prefix}${indent}${colors.yellow}${offset}${colors.reset}  ${colors.grey}${hexString}${colors.reset} ${colors.cyan}${asciiString}${colors.reset}`,
        );
      }
      if (bytes.length < size && bytes.length > 0) {
        console.log(
          `${prefix}${indent}${colors.dim}(Read ${bytes.length} of ${size} requested bytes)${colors.reset}`,
        );
      } else if (bytes.length === 0 && size > 0) {
        console.log(
          `${prefix}${indent}${colors.dim}(Read 0 bytes at ${pointer})${colors.reset}`,
        );
      }
    } catch (e) {
      // Catch potential errors during readByteArray itself
      console.log(
        `${prefix}${indent}${colors.red}Error reading memory at ${pointer}: ${e.message}${colors.reset}`,
      );
    }
  }

  /**
   * Formats symbol information similar to the backtrace.
   * @param {NativePointer} addr The address to symbolize.
   * @returns {{symbolStr: string, isSymbol: boolean}} Formatted symbol string and a flag indicating if a symbol was found.
   */
  function formatSymbol(addr) {
    let isSymbol = false;
    try {
      const symbol = DebugSymbol.fromAddress(addr);
      let moduleInfo = "";
      let symbolInfo = `${colors.grey}${addr}${colors.reset}`; // Default to address

      if (symbol.moduleName) {
        isSymbol = true; // Found a symbol in a module
        moduleInfo = `${colors.green}${symbol.moduleName}!${colors.reset}`;
        symbolInfo = `${colors.bold}${symbol.name || "?"}${colors.reset}`;
        if (symbol.address && addr.compare(symbol.address) !== 0) {
          symbolInfo += ` + 0x${addr.sub(symbol.address).toString(16)}`;
        }
      } else {
        // Fallback if no module info from DebugSymbol
        const module = Process.findModuleByAddress(addr);
        if (module) {
          // Don't mark as 'isSymbol=true' here, as it's just an offset in a module, could still be data
          moduleInfo = `${colors.green}${module.name}!${colors.reset}`;
          symbolInfo = `${colors.grey}offset 0x${addr.sub(module.base).toString(16)}${colors.reset}`;
        }
      }
      return { symbolStr: `${moduleInfo}${symbolInfo}`, isSymbol: isSymbol };
    } catch (e) {
      // Can happen if the address is invalid or causes issues during lookup
      return {
        symbolStr: `${colors.red}Error symbolizing ${addr}: ${e.message}${colors.reset}`,
        isSymbol: false,
      };
    }
  }

  /**
   * Analyzes a potential pointer and logs details about what it points to.
   * Returns true if the pointer points to potentially analyzable data (readable, not a symbol).
   * @param {NativePointer} ptrToAnalyze The potential pointer value.
   * @param {NativePointer} ptrLocation The address where this pointer was found.
   * @param {NativePointer} baseAddress The base address of the structure being analyzed.
   * @param {string} indent Indentation string.
   * @param {string} prefix Line prefix.
   * @returns {boolean} True if the pointer points to readable data that isn't a known symbol.
   */
  function logPointerDetails(
    ptrToAnalyze,
    ptrLocation,
    baseAddress,
    indent,
    prefix,
  ) {
    const offset = ptrLocation.sub(baseAddress);
    const offsetStr = `+0x${offset.toString(16).padStart(pointerSize * 2, "0")}`; // Show offset within the structure

    // Basic validity check (adjust range as needed)
    if (ptrToAnalyze.isNull() || ptrToAnalyze.compare(0x10000) < 0) {
      // console.log(`${prefix}${indent}${colors.dim}[${offsetStr}] -> (Null or Low Address: ${ptrToAnalyze})${colors.reset}`);
      return false; // Don't log or analyze nulls or very low addresses found in data
    }

    console.log(
      `${prefix}${indent}${colors.yellow}[${offsetStr}]${colors.reset} -> ${colors.magenta}${ptrToAnalyze}${colors.reset}`,
    );
    const { symbolStr, isSymbol } = formatSymbol(ptrToAnalyze);
    if (isSymbol) {
      // Check if formatSymbol found a named symbol
      console.log(`${prefix}${indent}  ${symbolStr}`);
      return false; // Found a symbol, likely code or known global, don't recurse
    }

    // If no symbol, check memory readability and try to guess data type
    let isReadableData = false;
    try {
      const protection = Memory.queryProtection(ptrToAnalyze);
      let dataInfo = `${colors.dim}Non-readable memory${colors.reset}`;
      if (protection.includes("r")) {
        // Check for read permission
        dataInfo = `${colors.cyan}Readable Data (${protection})${colors.reset}`;
        isReadableData = true;
        // Optional: Try reading as string or add small hexdump here
        // try {
        //     const str = ptrToAnalyze.readCString(64); // Limit length
        //     if (str && str.length > 1 && str.split("").every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126)) {
        //         dataInfo += `\n${prefix}${indent}    ${colors.grey}"${str.replace(/\n/g, '\\n')}"${colors.reset}`;
        //     } else {
        //         // logHexdump(ptrToAnalyze, 16, indent + "    ", prefix); // Small hexdump preview
        //     }
        // } catch (e) { /* Ignore if not a string */ }
      }
      // Log symbol string even if it's just an offset/address when no symbol name was found
      console.log(`${prefix}${indent}  ${symbolStr}`);
      console.log(`${prefix}${indent}  ${dataInfo}`);
    } catch (e) {
      //console.log(
      //  `${prefix}${indent}  ${colors.red}Error checking memory at ${ptrToAnalyze}: ${e.message}${colors.reset}`,
      //);
      isReadableData = false; // Error occurred, assume not readable/analyzable
    }
    return isReadableData; // Return true only if readable and not a symbol
  }

  /**
   * Reads data from a base pointer and recursively analyzes potential pointers within it.
   * @param {NativePointer} basePointer The start address of the data structure.
   * @param {number} size Max number of bytes to scan at this level.
   * @param {string} indent Indentation string.
   * @param {string} prefix Line prefix.
   * @param {number} currentDepth Current recursion depth.
   * @param {number} maxDepth Maximum allowed recursion depth.
   * @param {Set<string>} visitedPointers Set of pointer addresses (as strings) already analyzed to prevent cycles.
   */
  function analyzePotentialPointers(
    basePointer,
    size,
    indent,
    prefix,
    currentDepth,
    maxDepth,
    visitedPointers,
  ) {
    // Base cases for recursion
    if (
      basePointer.isNull() ||
      currentDepth >= maxDepth ||
      size <= 0 ||
      pointerAnalysisDepth <= 0
    ) {
      return;
    }

    const basePointerStr = basePointer.toString();
    if (visitedPointers.has(basePointerStr)) {
      console.log(
        `${prefix}${indent}${colors.dim}(Recursion cycle detected or already analyzed: ${basePointer})${colors.reset}`,
      );
      return; // Already visited this pointer
    }
    visitedPointers.add(basePointerStr); // Mark as visited for this analysis path

    try {
      const scanSize = Math.min(size, pointerAnalysisDepth); // Limit scan depth for this level
      const buf = basePointer.readByteArray(scanSize);
      if (!buf) {
        // console.log(`${prefix}${indent}${colors.red}Read failed for analysis at ${basePointer}${colors.reset}`);
        return; // Read failed
      }

      const numBytes = buf.byteLength;
      for (let i = 0; i <= numBytes - pointerSize; i += pointerSize) {
        // Iterate pointer-sized steps
        const currentPtrLocation = basePointer.add(i);
        try {
          const potentialPtr = currentPtrLocation.readPointer();

          // Log details and check if it points to something worth recursing into
          const shouldRecurse = logPointerDetails(
            potentialPtr,
            currentPtrLocation,
            basePointer,
            indent,
            prefix,
          );

          if (shouldRecurse) {
            // Recursively analyze the data pointed to by potentialPtr
            analyzePotentialPointers(
              potentialPtr,
              pointerAnalysisDepth, // Use configured depth for the next level
              indent + "  ", // Increase indent for next level
              prefix,
              currentDepth + 1, // Increment depth
              maxDepth,
              visitedPointers, // Pass the visited set down
            );
          }
        } catch (readErr) {
          // Ignore errors reading individual potential pointers within the buffer
          // console.log(`${prefix}${indent}${colors.red}Error reading potential pointer at ${currentPtrLocation}: ${readErr.message}${colors.reset}`);
        }
      }
    } catch (e) {
      console.log(
        `${prefix}${indent}${colors.red}Error reading buffer for pointer analysis at ${basePointer}: ${e.message}${colors.reset}`,
      );
    } finally {
      // Important: Remove from visited set when returning up the call stack
      // This allows the same pointer to be analyzed if reached via a different path.
      visitedPointers.delete(basePointerStr);
    }
  }

  // --- Main Interception Logic ---
  try {
    console.log(
      `\n${colors.bold}${colors.green}[*] Attaching interceptor to ${functionName} at ${targetAddress}${colors.reset}`,
    );
    console.log(
      `${colors.dim}[*] Pointer Size: ${pointerSize} bytes | Max Recursion Depth: ${maxRecursionDepth}${colors.reset}`,
    );

    Interceptor.attach(targetAddress, {
      /**
       * Called when the function is entered.
       * @param {InvocationArguments} args - Function arguments.
       */
      onEnter: function (args) {
        const threadId = this.threadId;
        const timestamp = new Date().toLocaleTimeString();
        const linePrefix = `${colors.bold}${colors.blue}│${colors.reset}`; // Consistent prefix for lines

        // --- Log Entry Header ---
        logSeparator("┌");
        logHeader(`Intercepting ${functionName}`);
        const timestampLine = ` ${colors.dim}Timestamp: ${timestamp} | Thread ID: ${threadId}${colors.reset}`;
        const padding = " ".repeat(
          Math.max(0, 58 - timestampLine.replace(/\x1b\[[0-9;]*m/g, "").length),
        ); // Adjust padding for colors
        console.log(
          `${linePrefix}${timestampLine}${padding}${colors.bold}${colors.blue}│${colors.reset}`,
        );
        logSeparator("├");

        // --- Log Arguments ---
        console.log(
          `${linePrefix} ${colors.bold}${colors.cyan}Arguments:${colors.reset}`,
        );
        try {
          const argNames = ["a1 (arg0)", "a2 (arg1)", "i  (arg2)"];
          argNames.forEach((name, index) => {
            const argPtr = args[index];
            console.log(
              `${linePrefix}   ${colors.cyan}${name}:${colors.reset} ${argPtr}`,
            );
            // Log Hexdump
            logHexdump(argPtr, hexdumpSize, "     ", linePrefix);
            // Perform and Log Pointer Analysis (Recursive)
            console.log(
              `${linePrefix}${"     "}${colors.bold}${colors.yellow}Pointer Analysis (Depth 0):${colors.reset}`,
            );
            // Start recursive analysis
            analyzePotentialPointers(
              argPtr,
              pointerAnalysisDepth, // Initial size to scan
              "     ", // Initial indent
              linePrefix,
              0, // Initial depth
              maxRecursionDepth,
              new Set(), // Fresh visited set for each top-level argument
            );

            if (index < argNames.length - 1) {
              console.log(`${linePrefix}`); // Add a small separator line between args
            }
          });
        } catch (e) {
          console.log(
            `${linePrefix}   ${colors.red}Error accessing arguments: ${e.message}${colors.reset}`,
          );
          console.error(e.stack);
        }
        logSeparator("├");

        // --- Log Backtrace ---
        console.log(
          `${linePrefix} ${colors.bold}${colors.green}Backtrace:${colors.reset}`,
        );
        try {
          const context = this.context;
          const backtrace = Thread.backtrace(context, Backtracer.ACCURATE); // Or Backtracer.FUZZY

          backtrace.forEach((addr, idx) => {
            const { symbolStr } = formatSymbol(addr); // Use the refactored function
            console.log(
              `${linePrefix}   ${colors.dim}[${idx.toString().padStart(2, " ")}]${colors.reset} ${symbolStr}`,
            );
          });
        } catch (e) {
          console.log(
            `${linePrefix}   ${colors.red}Error retrieving backtrace: ${e.message}${colors.reset}`,
          );
          console.error(e.stack);
        }

        // --- Log Footer ---
        logSeparator("└");
        console.log(""); // Add a blank line for readability
      },

      /**
       * Called when the function is about to return.
       * @param {InvocationReturnValue} retval - The return value.
       */
      // onLeave: function(retval) {
      //     // Optional: Uncomment to log return value
      //     const linePrefix = `${colors.bold}${colors.red}│${colors.reset}`;
      //     logSeparator(' M ', 60); // Middle separator for return
      //     console.log(`${linePrefix} ${colors.bold}${colors.red}Return Value:${colors.reset}`);
      //     console.log(`${linePrefix}   retval: ${retval}${colors.reset}`);
      //     // Optional: Add hexdump or analysis for retval if it's a pointer
      //     // if (!retval.isNull()) {
      //     //     logHexdump(retval, hexdumpSize, "     ", linePrefix);
      //     //     analyzePotentialPointers(
      //     //         retval,
      //     //         pointerAnalysisDepth,
      //     //         "     ",
      //     //         linePrefix,
      //     //         0,
      //     //         maxRecursionDepth,
      //     //         new Set()
      //     //     );
      //     // }
      //     logSeparator('─', 60);
      //     console.log("");
      // }
    });

    console.log(
      `${colors.bold}${colors.green}[+] Interceptor attached successfully.${colors.reset}`,
    );
    console.log(
      `${colors.dim}[+] Waiting for ${functionName} to be called...${colors.reset}\n`,
    );
  } catch (error) {
    console.error(
      `\n${colors.bold}${colors.red}[!] Error attaching interceptor: ${error.message}${colors.reset}`,
    );
    console.error(`${colors.red}${error.stack}${colors.reset}\n`);
  }
})();
