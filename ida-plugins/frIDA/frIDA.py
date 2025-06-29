"""
frIDA: Runtime Pointer Resolution for IDA Pro
An isolated plugin for dynamic resolution of static pointers using Frida instrumentation.
Version: 1.1.1
"""

import os
import traceback
import time

# IDA API imports
import ida_idaapi
import ida_kernwin
import ida_bytes
import ida_name
import ida_nalt
import ida_segment
import ida_idp
import ida_typeinf
import ida_ua
import ida_xref

# Conditional Frida import
try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

#-------------------------------------------------------------------------------
# Plugin Constants and Configuration
#-------------------------------------------------------------------------------
PLUGIN_NAME = "frIDA"
PLUGIN_VERSION = "1.1.1" # Incremented version for fixes
PLUGIN_HOTKEY = "Ctrl+Alt+F"
DEBUG_MODE = True  # Set to True for verbose logging

#-------------------------------------------------------------------------------
# Logging and Utilities
#-------------------------------------------------------------------------------
def log_debug(msg):
    if DEBUG_MODE:
        print(f"[DEBUG] {PLUGIN_NAME}: {msg}")

def log_info(msg):
    print(f"[INFO] {PLUGIN_NAME}: {msg}")

def log_error(msg, exc=None):
    print(f"[ERROR] {PLUGIN_NAME}: {msg}")
    if exc:
        print(f"[ERROR] Exception: {exc}")
        if DEBUG_MODE:
            traceback.print_exc()

def get_imagebase():
    """Retrieve the rebased imagebase of the current IDB."""
    return ida_nalt.get_imagebase()

def get_file_name():
    """Extract the binary name from the current IDB."""
    root_filename = ida_nalt.get_root_filename()
    if root_filename:
        return root_filename
    input_path = ida_nalt.get_input_file_path()
    return os.path.basename(input_path) if input_path else "unknown_binary"

def get_bitness():
    """Determine whether the target is 32 or 64-bit."""
    return 64 if ida_idp.ph_get_flag() & ida_idp.PR_USE64 else 32

def is_in_executable_segment(ea):
    """Check if an address resides in an executable segment."""
    seg = ida_segment.getseg(ea)
    return seg and (seg.perm & ida_segment.SEGPERM_EXEC)

def format_address(addr, bitness=None):
    """Format an address according to architecture bitness."""
    if bitness is None:
        bitness = get_bitness()
    # Ensure addr is an integer before formatting
    try:
        addr_int = int(addr)
        return f"0x{addr_int:0{bitness//4}X}"
    except (ValueError, TypeError):
        return str(addr) # Return original string if conversion fails


#-------------------------------------------------------------------------------
# Memory Analysis Utilities
#-------------------------------------------------------------------------------
def analyze_pointer_type(ea):
    """
    Multi-layer memory type inference with context-specific heuristics.

    Args:
        ea: Effective address to analyze

    Returns:
        dict: Type metadata and structural characteristics
    """
    flags = ida_bytes.get_flags(ea)
    segment = ida_segment.getseg(ea)
    segment_name = ida_segment.get_segm_name(segment) if segment else "UNKNOWN"
    segment_class = ida_segment.get_segm_class(segment) if segment else "UNKNOWN"

    # Initialize result structure
    info = {
        'address': ea,
        'is_pointer': False,
        'size': 0,
        'type_name': 'unknown',
        'is_code_ref': False,
        'is_data_ref': False,
        'xrefs': [],
        'segment': segment_name,
        'segment_class': segment_class
    }

    # Type inference phase 1: Symbol name parsing
    name = ida_name.get_name(ea)
    if name:
        info['name'] = name
        # Parse IDA's type encoding in symbol names
        if name.startswith(('dword_', 'qword_', 'xmmword_', 'ptr_')):
            if name.startswith('dword_'):
                info['is_pointer'] = True
                info['size'] = 4
                info['type_name'] = 'dword'
            elif name.startswith('qword_'):
                info['is_pointer'] = True
                info['size'] = 8
                info['type_name'] = 'qword'
            elif name.startswith('xmmword_'):
                info['size'] = 16
                info['type_name'] = 'xmmword'
            elif name.startswith('ptr_'):
                info['is_pointer'] = True
                info['size'] = 8 if get_bitness() == 64 else 4
                info['type_name'] = 'pointer'
    else:
        # Generate synthetic name for unnamed locations
        info['name'] = f"loc_{ea:X}" if not ida_bytes.is_code(flags) else f"sub_{ea:X}"

    # Type inference phase 2: Data type flags
    if info['size'] == 0:
        if ida_bytes.is_qword(flags):
            info['is_pointer'] = True
            info['size'] = 8
            info['type_name'] = 'qword'
        elif ida_bytes.is_dword(flags):
            info['is_pointer'] = True
            info['size'] = 4
            info['type_name'] = 'dword'
        elif ida_bytes.is_word(flags):
            info['size'] = 2
            info['type_name'] = 'word'
        elif ida_bytes.is_byte(flags):
            info['size'] = 1
            info['type_name'] = 'byte'
        elif ida_bytes.is_oword(flags):
            info['size'] = 16
            info['type_name'] = 'oword'

    # Type inference phase 3: Segment-based heuristics
    if segment_name in ('.rdata', '.data', 'DATA', 'data', '.bss', 'BSS', 'CONST', '.rodata'):
        arch_ptr_size = 8 if get_bitness() == 64 else 4
        if info['size'] == arch_ptr_size and (ea % arch_ptr_size) == 0:
            info['is_pointer'] = True
            log_debug(f"Segment-based pointer inference: {info['name']} in {segment_name}")

    # Type inference phase 4: Cross-reference analysis
    xref = ida_xref.get_first_dref_to(ea)
    while xref != ida_idaapi.BADADDR:
        info['xrefs'].append(xref)
        xref_flags = ida_bytes.get_flags(xref)
        if ida_bytes.is_code(xref_flags):
            info['is_code_ref'] = True
        else:
            info['is_data_ref'] = True
        xref = ida_xref.get_next_dref_to(ea, xref)

    # Type inference phase 5: Advanced type information (if available)
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        if tif.is_ptr():
            info['is_pointer'] = True
            info['type_name'] = 'pointer'
            pointed_tif = tif.get_pointed_object()
            if pointed_tif:
                info['pointed_type'] = pointed_tif.dstr() or "unknown"
            if info['size'] == 0:
                info['size'] = 8 if get_bitness() == 64 else 4
        elif tif.get_size() > 0:
             if info['size'] == 0:
                 info['size'] = tif.get_size()
                 info['type_name'] = tif.dstr() or info['type_name']

    # Last resort: use item size if all else fails
    if info['size'] == 0:
        item_size = ida_bytes.get_item_size(ea)
        if item_size > 0:
            info['size'] = item_size
        else:
            info['size'] = 8 if get_bitness() == 64 else 4
            log_debug(f"Falling back to arch pointer size ({info['size']}) for {info['name']} at {hex(ea)}")

    # Final check: if size matches pointer size, mark as potential pointer
    if info['size'] == (8 if get_bitness() == 64 else 4):
        info['is_pointer'] = True

    log_debug(f"Memory type analysis for {info['name']} at {hex(ea)}: {info}")
    return info


#-------------------------------------------------------------------------------
# Frida Communication Core
#-------------------------------------------------------------------------------
class FridaMemoryResolver:
    """
    Memory introspection subsystem for dynamic binary analysis using Frida instrumentation.
    Handles connection, script execution, and result parsing for both pointer
    resolution and direct data reading.
    """
    def __init__(self):
        """Initialize the memory introspection subsystem."""
        self.device = None
        self.session = None
        self.script = None
        self.result = None
        self.error = None
        self.imagebase = get_imagebase() # Static base from IDA
        self.bitness = get_bitness()
        self.architecture = None
        self.target_module_name = get_file_name() # Store target module name

    def connect(self, connection_type="remote", host="127.0.0.1:27042"):
        """
        Establish communication channel with Frida instrumentation framework.

        Args:
            connection_type: Channel type ("local", "usb", "remote")
            host: Endpoint for remote connections (host:port)

        Returns:
            bool: True if connection succeeded, False otherwise
        """
        try:
            if not HAS_FRIDA:
                raise ImportError("Frida instrumentation dependency unresolved")

            self.architecture = {
                'pointer_size': 8 if self.bitness == 64 else 4,
                'endianness': 'little', # Assuming little-endian for common targets
                'register_width': 64 if self.bitness == 64 else 32
            }
            # TODO: Refine endianness check if possible/needed based on ida_idp flags

            if connection_type == "local":
                self.device = frida.get_local_device()
            elif connection_type == "usb":
                self.device = frida.get_usb_device()
            elif connection_type == "remote":
                self.device = frida.get_device_manager().add_remote_device(host)
            else:
                raise ValueError(f"Invalid channel vector: {connection_type}")

            log_debug(f"Successfully initialized {connection_type} instrumentation channel")
            return True

        except frida.ServerNotRunningError as e:
            log_error(f"Frida server not running or accessible on {host if connection_type=='remote' else connection_type}: {e}")
            return False
        except frida.TransportError as e:
            log_error(f"Transport layer error connecting via {connection_type}: {e}")
            return False
        except Exception as e:
            log_error(f"Unhandled exception in channel initialization: {e}", exc=e)
            return False

    def attach_to_process(self, target):
        """
        Establish memory introspection context in target process.
        Corrected to handle PID logging safely.

        Args:
            target: Process identifier (PID or name)

        Returns:
            bool: True if session established, False otherwise
        """
        if not self.device:
            log_error("Attempted session creation with uninitialized device context")
            return False

        try:
            target_pid = -1
            target_name = ""
            log_message_pid = "unknown" # Placeholder for logging

            if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
                # --- Attach via PID ---
                target_pid = int(target)
                log_message_pid = str(target_pid) # We know the PID we are using
                log_debug(f"Attempting attach via PID: {target_pid}")
                self.session = self.device.attach(target_pid)
            else:
                # --- Attach via Name ---
                target_name = target
                log_message_pid = f"'{target_name}'" # Log the name used for attaching
                log_debug(f"Attempting attach via name: {target_name}")
                self.session = self.device.attach(target_name)
                # NOTE: We don't reliably get the resolved PID back onto the session object easily here.

            # --- Check Session and Log ---
            if not self.session:
                 # This case is less likely as exceptions are usually thrown on failure, but check anyway.
                 log_error(f"Session object null after attach attempt to {log_message_pid}")
                 return False

            # Log success using the PID or Name we used for the attach call
            log_debug(f"Successfully attached to process {log_message_pid}")

            # --- Post-Attach Operations ---
            try:
                # Attempt operations that require a valid session
                self.session.enable_child_gating()
                log_debug("Enabled child process tracking")
            except frida.NotSupportedError:
                 log_debug("Child gating not supported on this target/platform.")
            except Exception as e:
                # Log other potential errors but don't necessarily fail the attach
                log_debug(f"Child gating initialization failed (non-fatal): {e}")

            return True # Attach succeeded

        except frida.ProcessNotFoundError as e:
            log_error(f"Target process not found: {target}")
            return False
        except frida.PermissionDeniedError as e:
            log_error(f"Insufficient privileges for process attachment: {e}")
            return False
        except frida.TransportError as e:
             log_error(f"Frida transport error during attach: {e}")
             return False
        except Exception as e:
            # Catch any other unexpected exceptions during attach
            log_error(f"Unhandled exception in session establishment: {e}", exc=e)
            return False

    def get_process_list(self):
        """
        Enumerate available processes on target device.

        Returns:
            list: Process descriptors (pid, name, etc.) or empty list on error.
        """
        if not self.device:
            log_error("Attempted process enumeration with uninitialized device")
            return []
        try:
            processes = self.device.enumerate_processes()
            log_debug(f"Enumerated {len(processes)} processes on target device")
            return processes
        except frida.TransportError as e:
            log_error(f"Transport error during process enumeration: {e}")
            return []
        except Exception as e:
            log_error(f"Unhandled exception in process enumeration: {e}", exc=e)
            return []

    def on_message(self, message, data):
        """
        Message handler for bidirectional communication with instrumentation script.

        Args:
            message: JSON message from script execution context
            data: Binary buffer for large data transfers (unused currently)
        """
        log_debug(f"Message received: Type={message.get('type')}")
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and payload.get('type') == 'error':
                self.error = payload.get('message', 'Unspecified error in script execution')
                log_error(f"Script execution error: {self.error}")
                if 'stack' in payload:
                    log_error(f"Script stack trace:\n{payload['stack']}")
            else:
                self.result = payload
                log_debug(f"Received result data from script.")
        elif message['type'] == 'error':
            self.error = message.get('description', 'Unknown script runtime error')
            stack = message.get('stack', 'No stack trace available')
            log_error(f"Fatal error in script execution:\n{self.error}\nStack:\n{stack}")
        else:
            log_debug(f"Unhandled message type: {message['type']}")

    def resolve_pointer(self, pointer_ea, pointer_info, dereference_level=1, timeout=10):
        """
        Execute memory introspection operation to resolve pointer chains.
        Corrected logging to avoid session.pid access.

        Args:
            pointer_ea: Effective address of pointer in static binary
            pointer_info: Type metadata and structural characteristics
            dereference_level: Pointer chain traversal depth
            timeout: Maximum execution time in seconds

        Returns:
            dict: Memory introspection results or error descriptor
        """
        if not self.session:
            log_error("Attempted introspection with uninitialized session")
            return {'error': 'No active instrumentation session'}

        static_imagebase = get_imagebase()
        rva = pointer_ea - static_imagebase
        module_name = self.target_module_name

        log_debug(f"Resolving pointer: EA=0x{pointer_ea:X}, RVA=0x{rva:X}, Module='{module_name}', Levels={dereference_level}")

        self.result = None
        self.error = None

        script_source = self._generate_pointer_resolution_script(
            module_name, rva, pointer_info, dereference_level)

        if DEBUG_MODE:
             log_debug("Generated Frida script.")

        try:
            self.script = self.session.create_script(script_source)
            self.script.on('message', self.on_message)
            self.script.load()
            # Corrected logging - removed reference to self.session.pid
            log_debug(f"Deployed introspection script to target process.")

            start_time = time.time()
            processed = False
            while not processed and (time.time() - start_time < timeout):
                if self.result or self.error:
                    processed = True
                else:
                    time.sleep(0.05) # Yield control briefly

            # Final check after loop
            if self.error:
                log_error(f"Script execution failed: {self.error}")
                return {'error': self.error}
            elif self.result:
                log_debug("Script execution successful.")
                return self.result
            else:
                log_error(f"Script execution timed out after {timeout} seconds.")
                # Attempt to unload script even on timeout to prevent leaks
                if self.script:
                    try: self.script.unload()
                    except: pass # Ignore errors during timeout cleanup
                return {'error': 'Execution timeout in script runtime'}

        except frida.TransportError as e:
             log_error(f"Frida transport error during script execution: {e}", exc=e)
             return {'error': f"Transport error: {e}"}
        except frida.InvalidOperationError as e:
             log_error(f"Frida invalid operation during script execution: {e}", exc=e)
             return {'error': f"Invalid operation: {e}"}
        except Exception as e:
            log_error(f"Unhandled exception in script execution: {e}", exc=e)
            return {'error': f"General execution error: {e}"}
        finally:
            # Resource cleanup
            if self.script:
                try:
                    # Detach the message handler *before* unloading
                    self.script.off('message', self.on_message)
                    self.script.unload()
                    log_debug("Unloaded script execution context")
                except frida.InvalidOperationError:
                    log_debug("Script already unloaded or session detached.")
                except Exception as e:
                    log_debug(f"Non-fatal error during script unload: {e}")
                self.script = None # Clear reference

    def _generate_pointer_resolution_script(self, module_name, rva, pointer_info, dereference_level):
        """
        Generate Frida instrumentation script for pointer chain traversal
        with code pointer detection and module offset reporting.
        """
        memory_read_directive = "readU64" if self.bitness == 64 else "readU32"
        pointer_size = self.architecture['pointer_size']

        # Determine initial read operation based on static analysis info
        initial_read_op = memory_read_directive # Default to pointer size
        if pointer_info['size'] > 0:
            if pointer_info['size'] == 8: initial_read_op = "readU64"
            elif pointer_info['size'] == 4: initial_read_op = "readU32"
            elif pointer_info['size'] == 2: initial_read_op = "readU16"
            elif pointer_info['size'] == 1: initial_read_op = "readU8"
            # else keep default pointer size read

        # Escape module name for use in JS string literal
        js_module_name = module_name.replace('\\', '\\\\').replace('"', '\\"')

        # Note: This script focuses on pointer resolution. Data reading uses _generate_data_read_script.
        return f'''
        (function() {{
            // Helper function to get module info for an address
            function getModuleInfo(address) {{
                try {{
                    const modules = Process.enumerateModules();
                    for (const mod of modules) {{
                        // Use try-catch for base/size access as they might be invalid temporarily
                        try {{
                            if (address.compare(mod.base) >= 0 &&
                                address.compare(mod.base.add(mod.size)) < 0) {{
                                return {{
                                    name: mod.name,
                                    base: mod.base.toString(),
                                    offset: address.sub(mod.base).toString(16),
                                    size: mod.size.toString(16),
                                    path: mod.path || "unknown"
                                }};
                            }}
                        }} catch (e) {{ /* Ignore module if base/size invalid */ }}
                    }}
                }} catch (e) {{ console.log("Error in getModuleInfo for " + address + ": " + e); }}
                return null; // Not found in any module
            }}

            try {{
                const ptrSize = Process.pointerSize;
                let moduleBase = Module.findBaseAddress("{js_module_name}");
                if (!moduleBase) {{
                    // Try finding module by path/name if exact name fails
                    const modules = Process.enumerateModules();
                    const found = modules.find(m => m.name === "{js_module_name}" || (m.path && m.path.endsWith("{js_module_name}")));
                    if (found) {{
                         moduleBase = found.base;
                         console.log("Found module '{js_module_name}' via secondary lookup.");
                    }} else {{
                         send({{type: "error", message: "Module identification failed: {js_module_name}"}});
                         return;
                    }}
                }}

                const pointerAddress = moduleBase.add(ptr("0x{rva:X}"));
                let dereferenceChain = [];
                let currentValue = null; // Initialize to null
                let currentAddress = pointerAddress;
                let currentModuleInfo = getModuleInfo(currentAddress); // Get info for initial address

                // Initial memory read operation (Level 0)
                try {{
                    currentValue = currentAddress.{initial_read_op}();
                }} catch(e) {{
                    console.log("Initial read with specific size failed (addr: " + currentAddress + ", op: {initial_read_op}), falling back to pointer size read.");
                    try {{
                        currentValue = currentAddress.{memory_read_directive}();
                    }} catch (e2) {{
                        send({{
                            type: "error",
                            message: `Memory access violation at base address ${{currentAddress}}: ${{e2.message}}`,
                            stack: e2.stack
                        }});
                        return;
                    }}
                }}

                // Record base pointer state (Level 0)
                dereferenceChain.push({{
                    level: 0,
                    address: currentAddress.toString(),
                    value: currentValue.toString(16), // Store value as hex string
                    offset_from_base: pointerAddress.sub(moduleBase).toString(16),
                    memory_protection: (() => {{
                        try {{ return Process.findRangeByAddress(currentAddress)?.protection || "unknown"; }}
                        catch(e) {{ return "unreadable"; }}
                    }})(),
                    module: currentModuleInfo // Include module info for level 0
                }});

                // Traverse pointer chain
                for(let i = 0; i < {dereference_level}; i++) {{
                    let nextAddress = null;
                    let valueAsString = "invalid"; // Store value before ptr conversion attempt

                    try {{
                        // Check for NULL or invalid pointer value *before* trying ptr()
                        if (currentValue === null || currentValue === undefined ||
                            (typeof currentValue.isNull === 'function' && currentValue.isNull()) ||
                            (typeof currentValue.toUInt32 === 'function' && currentValue.toUInt32() === 0) ||
                             currentValue == 0) {{ // Handle primitive 0 too
                            dereferenceChain.push({{
                                level: i + 1,
                                address: "0x0", // Represents the value read previously
                                value: "NULL",
                                error: "null_pointer_value",
                                error_details: "Value read from previous level was NULL."
                            }});
                            break; // Stop traversal
                        }}

                        valueAsString = currentValue.toString(16); // Get hex string representation

                        // Construct pointer from previous value
                        nextAddress = ptr(currentValue.toString()); // Use original value for ptr()

                    }} catch(ptrError) {{
                        // Error converting the value to a pointer
                        dereferenceChain.push({{
                            level: i + 1,
                            address: "invalid_value", // Indicate the value was bad
                            value: valueAsString, // Show the value that failed
                            error: "invalid_pointer_value",
                            error_details: `Value 0x${{valueAsString}} could not be converted to a valid pointer: ${{ptrError.message}}`
                        }});
                        break; // Stop traversal
                    }}

                    // Now we have a potentially valid nextAddress, analyze it
                    currentAddress = nextAddress; // Update currentAddress for this level (i+1)
                    let memoryProtection = "unknown";
                    let moduleInfo = null;
                    let isReadable = false;
                    let isExecutable = false;

                    try {{
                        const range = Process.findRangeByAddress(currentAddress);
                        if (range) {{
                            memoryProtection = range.protection;
                            isReadable = memoryProtection.includes('r');
                            isExecutable = memoryProtection.includes('x');
                            moduleInfo = getModuleInfo(currentAddress); // Get module info for this address
                        }} else {{
                            // Address might be valid but outside known ranges
                            memoryProtection = "unknown_range";
                            // Try a probe read to check readability (use with caution)
                            try {{ Memory.readU8(currentAddress); isReadable = true; }} catch(probeError) {{ isReadable = false; }}
                        }}
                    }} catch(e) {{
                        // Error during range lookup (less common)
                        memoryProtection = "lookup_error";
                        isReadable = false;
                        console.log("Error finding range for " + currentAddress + ": " + e);
                    }}

                    // *** Check for Executable Memory ***
                    if (isExecutable) {{
                        dereferenceChain.push({{
                            level: i + 1,
                            address: currentAddress.toString(),
                            value: "N/A", // No value read from code
                            memory_protection: memoryProtection,
                            module: moduleInfo,
                            termination_reason: "points_to_executable_code"
                        }});
                        break; // Stop traversal
                    }}

                    // Check for Non-Readable Memory
                    if (!isReadable) {{
                        dereferenceChain.push({{
                            level: i + 1,
                            address: currentAddress.toString(),
                            value: "N/A", // Cannot read value
                            error: "non_readable",
                            error_details: `Memory region not readable (Protection: ${{memoryProtection}})`,
                            memory_protection: memoryProtection,
                            module: moduleInfo
                        }});
                        break; // Stop traversal
                    }}

                    // Perform next level dereference (read pointer-sized value)
                    try {{
                        currentValue = currentAddress.{memory_read_directive}(); // Read value at currentAddress
                    }} catch(readError) {{
                        dereferenceChain.push({{
                            level: i + 1,
                            address: currentAddress.toString(), // Address where read failed
                            value: "N/A", // Read failed
                            error: "access_violation",
                            error_details: `Memory access violation reading at address: ${{readError.message}}`,
                            memory_protection: memoryProtection,
                            module: moduleInfo
                        }});
                        break; // Stop traversal
                    }}

                    // Record successful dereference state
                    dereferenceChain.push({{
                        level: i + 1,
                        address: currentAddress.toString(),
                        value: currentValue.toString(16), // Store value as hex string
                        memory_protection: memoryProtection,
                        module: moduleInfo
                    }});

                    // Check if we reached the end of requested depth
                    if (i + 1 >= {dereference_level}) {{
                         break;
                    }}

                }} // End of for loop

                // Memory context analysis for the *last valid address* in the chain
                let memoryContext = null;
                let lastValidLink = null;
                for (let j = dereferenceChain.length - 1; j >= 0; j--) {{
                    if (!dereferenceChain[j].error && !dereferenceChain[j].termination_reason && dereferenceChain[j].address !== '0x0' && dereferenceChain[j].address !== 'invalid_value') {{
                        lastValidLink = dereferenceChain[j];
                        break;
                    }}
                }}

                if (lastValidLink) {{
                    try {{
                        const finalAddress = ptr(lastValidLink.address);
                        // Read up to 16 bytes for context, but not more than ptrSize if smaller
                        const contextSize = Math.min(ptrSize, 16);
                        const memBefore = finalAddress.sub(contextSize).readByteArray(contextSize);
                        // Read the actual value location again for context
                        const memExact = finalAddress.readByteArray(contextSize);
                        const memAfter = finalAddress.add(contextSize).readByteArray(contextSize);

                        // Helper for hex conversion needed here too
                        const bytesToHexCtx = (buffer) => {{
                           if (!buffer) return "N/A";
                           return Array.from(new Uint8Array(buffer))
                               .map(b => b.toString(16).padStart(2, '0'))
                               .join(' ');
                        }};

                        memoryContext = {{
                            context_address: finalAddress.toString(),
                            before: bytesToHexCtx(memBefore),
                            exact: bytesToHexCtx(memExact),
                            after: bytesToHexCtx(memAfter)
                        }};
                    }} catch(e) {{
                        console.log(`Memory context analysis error at ${{lastValidLink.address}}: ${{e.message}}`);
                    }}
                }}

                // Return complete introspection results
                send({{
                    type: "success",
                    module_base: moduleBase.toString(),
                    pointer_name: "{pointer_info.get('name', 'unnamed')}",
                    pointer_type: "{pointer_info.get('type_name', 'unknown')}",
                    pointer_size: {pointer_info['size']},
                    module_name: "{js_module_name}",
                    rva: "0x{rva:X}",
                    chain: dereferenceChain,
                    memory_context: memoryContext,
                    architecture: {{
                        bitness: {self.bitness},
                        pointer_size: {pointer_size},
                        endianness: "{self.architecture['endianness']}"
                    }}
                }});
            }} catch(e) {{
                // Global exception handler for script initialization failures
                send({{
                    type: "error",
                    message: `Script initialization failed: ${{e.message}}`,
                    stack: e.stack
                }});
            }}
        }})();
        '''

    def read_data(self, data_ea, data_info, timeout=5):
        """
        Reads data from a specific address at runtime based on type info.

        Args:
            data_ea: Effective address of the data in static binary
            data_info: Type metadata (size, type_name)
            timeout: Maximum execution time in seconds

        Returns:
            dict: Data read results or error descriptor
        """
        if not self.session:
            log_error("Attempted data read with uninitialized session")
            return {'error': 'No active instrumentation session'}

        static_imagebase = get_imagebase()
        rva = data_ea - static_imagebase
        module_name = self.target_module_name

        log_debug(f"Reading data: EA=0x{data_ea:X}, RVA=0x{rva:X}, Module='{module_name}', Size={data_info.get('size', '?')}")

        self.result = None
        self.error = None

        # Call the data reading script generator
        script_source = self._generate_data_read_script(
            module_name, rva, data_info)
        
        if DEBUG_MODE:
             log_debug("Generated Frida data read script.")

        try:
            self.script = self.session.create_script(script_source)
            self.script.on('message', self.on_message)
            self.script.load()
            log_debug(f"Deployed data read script to target process.")

            start_time = time.time()
            processed = False
            while not processed and (time.time() - start_time < timeout):
                if self.result or self.error:
                    processed = True
                else:
                    time.sleep(0.05)

            if self.error:
                log_error(f"Script execution failed: {self.error}")
                return {'error': self.error}
            elif self.result:
                log_debug("Script execution successful.")
                return self.result
            else:
                log_error(f"Script execution timed out after {timeout} seconds.")
                if self.script:
                    try: self.script.unload()
                    except: pass
                return {'error': 'Execution timeout in script runtime'}

        except frida.TransportError as e:
             log_error(f"Frida transport error during script execution: {e}", exc=e)
             return {'error': f"Transport error: {e}"}
        except frida.InvalidOperationError as e:
             log_error(f"Frida invalid operation during script execution: {e}", exc=e)
             return {'error': f"Invalid operation: {e}"}
        except Exception as e:
            log_error(f"Unhandled exception in script execution: {e}", exc=e)
            return {'error': f"General execution error: {e}"}
        finally:
            if self.script:
                try:
                    self.script.off('message', self.on_message)
                    self.script.unload()
                    log_debug("Unloaded script execution context")
                except frida.InvalidOperationError:
                    log_debug("Script already unloaded or session detached.")
                except Exception as e:
                    log_debug(f"Non-fatal error during script unload: {e}")
                self.script = None

    def _generate_data_read_script(self, module_name, rva, data_info):
        """
        Generates Frida script to read data based on size/type.
        Includes specific handling for signed types.
        Uses simplified JS generation and robust value formatting.
        Corrected module info lookup.
        """
        # ... (Python logic to determine read_op, etc. remains the same) ...
        size = data_info.get('size', 0)
        type_name = data_info.get('type_name', 'unknown').lower().replace('_', '').replace(' ', '')
        read_op = None
        read_arg = ""
        is_byte_array = False
        is_signed = False
        is_float = False

        if size == 1:
            if 'signed' in type_name or type_name in ('int8', 'sbyte', 'char'): read_op = "readS8"; is_signed = True
            else: read_op = "readU8"
        elif size == 2:
            if 'signed' in type_name or type_name in ('int16', 'short'): read_op = "readS16"; is_signed = True
            else: read_op = "readU16"
        elif size == 4:
            if 'float' in type_name: read_op = "readFloat"; is_float = True
            elif 'signed' in type_name or type_name in ('int32', 'int', 'long'): read_op = "readS32"; is_signed = True
            else: read_op = "readU32"
        elif size == 8:
            if 'double' in type_name: read_op = "readDouble"; is_float = True
            elif 'signed' in type_name or type_name in ('int64', '__int64', 'longlong'): read_op = "readS64"; is_signed = True
            else: read_op = "readU64"
        elif size > 0:
             read_op = "readByteArray"; is_byte_array = True; read_arg = str(size)
        else:
            read_op = "readByteArray"; is_byte_array = True; size = 16; read_arg = str(size)
            log_debug(f"Unsupported or zero size, falling back to readByteArray({size}).")

        if not read_op:
             log_error("Failed to determine read operation!")
             return "send({type: 'error', message: 'Internal plugin error: Could not determine read operation'});"

        js_module_name = module_name.replace('\\', '\\\\').replace('"', '\\"')
        ptr_size = self.architecture['pointer_size']
        read_call = f"dataAddress.{read_op}({read_arg})"

        # --- Generate JavaScript ---
        return f'''
        (function() {{
            // Helper to convert ArrayBuffer to hex string
            function bytesToHex(buffer) {{
                if (!buffer) return "N/A";
                try {{
                    return Array.from(new Uint8Array(buffer))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                }} catch (e) {{ return "Error converting bytes"; }}
            }}

            // *** Re-introduce getModuleInfo helper ***
            function getModuleInfoForAddress(address) {{
                try {{
                    const modules = Process.enumerateModules();
                    for (const mod of modules) {{
                        try {{
                            if (address.compare(mod.base) >= 0 &&
                                address.compare(mod.base.add(mod.size)) < 0) {{
                                return {{
                                    name: mod.name,
                                    base: mod.base.toString(),
                                    offset: address.sub(mod.base).toString(16),
                                    size: mod.size.toString(16),
                                    path: mod.path || "unknown"
                                }};
                            }}
                        }} catch (e) {{ /* Ignore module if base/size invalid */ }}
                    }}
                }} catch (e) {{ console.log("Error in getModuleInfoForAddress for " + address + ": " + e); }}
                return null; // Not found in any module
            }}

            try {{
                let moduleBase = Module.findBaseAddress("{js_module_name}");
                if (!moduleBase) {{
                    const modules = Process.enumerateModules();
                    const found = modules.find(m => m.name === "{js_module_name}" || (m.path && m.path.endsWith("{js_module_name}")));
                    if (found) {{ moduleBase = found.base; }}
                    else {{
                         send({{type: "error", message: "Module identification failed: {js_module_name}"}});
                         return;
                    }}
                }}

                const dataAddress = moduleBase.add(ptr("0x{rva:X}"));
                let rawValue = null;
                let valueStr = "Error";
                let protection = "unknown";
                let moduleInfo = null; // Will be populated by helper
                let specificReadError = null;

                try {{
                    // Get protection and module info first
                    const range = Process.findRangeByAddress(dataAddress);
                    if (range) {{ protection = range.protection; }}
                    // *** CORRECTED: Use helper function to find module info ***
                    moduleInfo = getModuleInfoForAddress(dataAddress);

                    // --- Perform the read operation ---
                    try {{
                        console.log("Attempting read: {read_call}");
                        rawValue = {read_call};
                        console.log("Raw value read:", rawValue);
                    }} catch(readErr) {{
                        console.error("!!! Specific Read Error Caught: " + readErr.message + "\\nStack:" + readErr.stack);
                        specificReadError = readErr;
                    }}
                    // --- End read operation ---

                    if (specificReadError !== null) {{
                        send({{
                            type: "error",
                            message: `Failed to read data at ${{dataAddress}}: ${{specificReadError.message}}`,
                            stack: specificReadError.stack
                        }});
                        return;
                    }}

                    // --- Format the successfully read value ---
                    // (Formatting logic remains the same as previous correct version)
                    if (rawValue !== null && rawValue !== undefined) {{
                        if ({str(is_byte_array).lower()}) {{
                            valueStr = bytesToHex(rawValue);
                        }} else if (typeof rawValue === 'number') {{
                            if ({str(is_float).lower()}) {{ valueStr = rawValue.toString(10); }}
                            else if ({str(is_signed).lower()}) {{ valueStr = rawValue.toString(10); }}
                            else {{ valueStr = "0x" + rawValue.toString(16); }}
                        }} else if (typeof rawValue === 'object' && rawValue.toString) {{
                             valueStr = rawValue.toString();
                             if (!valueStr.startsWith("0x") && !isNaN(parseInt(valueStr, 16))) {{ valueStr = "0x" + valueStr; }}
                        }} else {{ valueStr = String(rawValue); }}
                        console.log("Formatted value:", valueStr);
                    }} else if (rawValue === null) {{ valueStr = "NULL_READ_UNEXPECTED"; }}

                }} catch (e) {{
                    if (!specificReadError) {{
                        send({{
                            type: "error",
                            message: `Error processing data at ${{dataAddress}}: ${{e.message}}`,
                            stack: e.stack
                        }});
                        return;
                    }}
                }}

                // Memory context analysis (only if read was successful)
                let memoryContext = null;
                if (specificReadError === null) {{
                    try {{
                        const contextSize = Math.min({ptr_size}, 16);
                        const readSize = Math.max(1, {size if size > 0 else 1});
                        const memBefore = dataAddress.sub(contextSize).readByteArray(contextSize);
                        const memExact = dataAddress.readByteArray(readSize);
                        const memAfter = dataAddress.add(readSize).readByteArray(contextSize);
                        memoryContext = {{
                            context_address: dataAddress.toString(),
                            before: bytesToHex(memBefore),
                            exact: bytesToHex(memExact),
                            after: bytesToHex(memAfter)
                        }};
                    }} catch(e) {{ console.log(`Memory context analysis error: ${{e.message}}`); }}
                }}

                // Send success message
                send({{
                    type: "success",
                    runtime_address: dataAddress.toString(),
                    value: valueStr,
                    raw_value_type: typeof rawValue,
                    size: {size},
                    type_name: "{data_info.get('type_name', 'unknown')}",
                    memory_protection: protection,
                    module_info: moduleInfo, // Send the result from the helper function
                    memory_context: memoryContext
                }});

            }} catch(e) {{
                send({{
                    type: "error",
                    message: `Script execution failed: ${{e.message}}`,
                    stack: e.stack
                }});
            }}
        }})();
        '''

    def cleanup(self):
        """Release instrumentation resources and communication channels."""
        log_debug("Starting cleanup...")
        # Script context cleanup
        if self.script:
            try:
                # Check if script is loaded before trying to unload
                # Note: Frida doesn't offer a direct is_loaded check easily accessible here.
                # Rely on try-except.
                self.script.unload()
                log_debug("Unloaded script execution context")
            except frida.InvalidOperationError:
                 log_debug("Script already unloaded or session detached during unload.")
            except Exception as e:
                log_debug(f"Non-fatal error during script unload: {e}")
            self.script = None

        # Session termination
        if self.session and not self.session.is_detached: # Check if attached before detaching
            try:
                self.session.detach()
                log_debug("Detached from instrumentation session")
            except frida.InvalidOperationError:
                 log_debug("Session already detached.")
            except Exception as e:
                log_debug(f"Non-fatal error during session detach: {e}")
            self.session = None

        # Reference clearing
        self.device = None
        self.result = None
        self.error = None
        log_debug("Cleanup complete.")


#-------------------------------------------------------------------------------
# IDA UI Integration
#-------------------------------------------------------------------------------
def is_in_data_segment(ea):
    """Determine if an address belongs to a data segment."""
    seg = ida_segment.getseg(ea)
    if not seg: return False
    seg_class = ida_segment.get_segm_class(seg)
    if seg_class in ('DATA', 'CONST', 'BSS'): return True
    seg_name = ida_segment.get_segm_name(seg)
    if seg_name in ('.data', '.rdata', '.bss', 'data', 'DATA', 'CONST', '.rodata'): return True
    if (seg.perm & ida_segment.SEGPERM_READ) and not (seg.perm & ida_segment.SEGPERM_EXEC): return True
    return False

# (Ensure necessary imports like ida_kernwin, ida_idaapi, ida_bytes, ida_name,
#  ida_segment, ida_idp, ida_ua, ida_xref, os, traceback, time are present)
# (Ensure helper functions like HAS_FRIDA, log_debug, log_error, analyze_pointer_type,
#  FridaMemoryResolver, is_in_data_segment, get_file_name, get_bitness,
#  get_module_info_for_addr_py are defined above)
# (Ensure PLUGIN_NAME constant is defined)

class ResolvePointerAction(ida_kernwin.action_handler_t):
    """
    IDA action handler for runtime pointer resolution.
    Uses a subclassed Choose for operand selection and Form for process selection.
    """
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """Action handler entry point."""
        try:
            if not HAS_FRIDA:
                ida_kernwin.warning(f"{PLUGIN_NAME} requires the Frida Python package.\n"
                                  f"Install with: pip install frida frida-tools")
                return 0

            target_ea = self._get_target_ea_from_context(ctx)
            if target_ea == ida_idaapi.BADADDR:
                log_debug("No valid target address found in context.")
                return 0

            log_debug(f"Target EA resolved: {hex(target_ea)}")
            item_info = analyze_pointer_type(target_ea) # Renamed to item_info for clarity
            log_debug(f"Memory type analysis result: {item_info}")

            # --- Decision Point: Pointer Resolution vs. Data Reading ---
            if item_info['is_pointer']:
                # Looks like a pointer, proceed with standard resolution
                log_debug("Target identified as pointer, proceeding with resolution.")
                if self._resolve_pointer_at_runtime(target_ea, item_info):
                    return 1 # Success
                else:
                    return 0 # Failed or cancelled during resolution
            else:
                # Doesn't look like a pointer, ask to read data instead
                log_debug("Target identified as data, asking user to read value.")
                prompt = (f"HIDECANCEL\n{PLUGIN_NAME}: Read Runtime Data?\n"
                          f"The selected location {item_info.get('name', hex(target_ea))} "
                          f"(Type: {item_info.get('type_name', 'unknown')}, Size: {item_info.get('size', '?')}) "
                          f"appears to be data, not a pointer.\n\n"
                          f"Do you want to read its current value at runtime?")
                if ida_kernwin.ask_yn(1, prompt) == 1: # User wants to read data
                    log_debug("User chose to read runtime data value.")
                    # Call the new data reading function
                    if self._read_data_at_runtime(target_ea, item_info):
                         return 1 # Success
                    else:
                         return 0 # Failed or cancelled during data read
                else:
                    log_debug("User cancelled data reading operation.")
                    return 0 # User cancelled

        except Exception as e:
            log_error(f"Unhandled exception in action handler: {e}", exc=e)
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nOperation failed unexpectedly.\n\nDetails: {e}\n\nCheck console for more info.")
            return 0
        
    def _visualize_runtime_data(self, target_ea, item_info, result):
        """Displays the read runtime data value."""
        lines = []
        lines.append(f"=== {PLUGIN_NAME}: Runtime Data Read ===")
        lines.append(f"Target: {item_info.get('name', 'unknown')} at static EA 0x{target_ea:X}")
        lines.append(f"Static Type: {item_info.get('type_name', 'unknown')} ({item_info.get('size', '?')} bytes)")

        runtime_addr = result.get('runtime_address', 'unknown')
        # Attempt to format runtime address with module+offset
        display_rt_addr = runtime_addr # Default
        mod_info_rt = result.get('module_info')
        if mod_info_rt and 'base' in mod_info_rt and 'name' in mod_info_rt:
             try:
                 rt_addr_int = int(runtime_addr, 16)
                 base_addr_int = int(mod_info_rt['base'], 16)
                 offset = rt_addr_int - base_addr_int
                 mod_name = mod_info_rt['name']
                 if len(mod_name) > 30: mod_name = mod_name[:15] + "..." + mod_name[-12:]
                 display_rt_addr = f"{mod_name}+0x{offset:X} ({runtime_addr})"
             except:
                 pass # Keep default if conversion fails

        lines.append(f"Runtime Address: {display_rt_addr}")
        lines.append(f"Memory Protection: {result.get('memory_protection', 'unknown')}")
        lines.append(f"--- Runtime Value ({result.get('type_name', '?')} / {result.get('size', '?')} bytes) ---")
        lines.append(f"  {result.get('value', 'N/A')}") # Display the formatted value from Frida

        mem_ctx = result.get('memory_context')
        if mem_ctx:
            lines.append("\n--- Memory Context ---")
            lines.append(f"Center Address: {display_rt_addr}") # Use same formatted address
            lines.append(f"  Before: {mem_ctx.get('before', 'N/A')}")
            lines.append(f"  Exact:  {mem_ctx.get('exact', 'N/A')}") # Shows the actual bytes read
            lines.append(f"  After:  {mem_ctx.get('after', 'N/A')}")

        print("\n".join(lines))
        output_widget = ida_kernwin.find_widget("Output window")
        if output_widget:
            ida_kernwin.activate_widget(output_widget, True)
        else:
            log_debug("Could not find 'Output window' to activate.")

        # --- Annotation ---
        prompt = f"HIDECANCEL\n{PLUGIN_NAME}: Annotation\nAnnotate static location 0x{target_ea:X} with runtime data?"
        if ida_kernwin.ask_yn(1, prompt) == 1:
            # Create annotation like "frIDA[Data]: 0xDEADBEEF (Runtime)"
            annotation = f"frIDA[Data]: {result.get('value', 'N/A')} (Runtime)"
            ida_bytes.set_cmt(target_ea, annotation, False)
            log_debug(f"Added annotation at 0x{target_ea:X}: {annotation}")
        
    def _read_data_at_runtime(self, target_ea, item_info):
        """Handles Frida connection and calls the data reading method."""
        resolver = FridaMemoryResolver()

        # --- Connection --- (Identical to _resolve_pointer_at_runtime)
        conn_choice = ida_kernwin.ask_buttons("Local", "Remote", "USB", 1, f"{PLUGIN_NAME}: Connection Type")
        if conn_choice < 0: return False
        conn_type = ["local", "remote", "usb"][conn_choice]
        host = "127.0.0.1:27042"
        if conn_type == "remote":
            host_input = ida_kernwin.ask_text(
                0,
                host,
                "Enter remote Frida server address (host:port):"
            )
            if not host_input: return False
            host = host_input

        ida_kernwin.show_wait_box(f"Connecting to Frida ({conn_type})...")
        if not resolver.connect(conn_type, host):
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to connect via {conn_type}" + (f" to {host}" if conn_type == "remote" else ""))
            return False

        # --- Process Selection --- (Identical to _resolve_pointer_at_runtime)
        ida_kernwin.replace_wait_box("Enumerating processes...")
        processes = resolver.get_process_list()
        if not processes:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to enumerate processes on the target device.")
            resolver.cleanup()
            return False

        process_items = [f"{p.pid}: {p.name}" for p in processes]
        current_bin_name = get_file_name()
        default_sel = -1
        for i, item in enumerate(process_items):
             proc_name = item.split(': ', 1)[-1]
             if current_bin_name and (current_bin_name == proc_name or f"{current_bin_name}.exe" == proc_name):
                 default_sel = i
                 break
        if default_sel == -1:
            for i, item in enumerate(process_items):
                if current_bin_name and current_bin_name.lower() in item.lower():
                    default_sel = i
                    break
        if default_sel == -1: default_sel = 0

        ida_kernwin.hide_wait_box()

        form_str = f"""STARTITEM 0
{PLUGIN_NAME}: Select Target Process

<#Select the target process to attach to#Process:{{ProcessDropdown}}>

"""
        process_dropdown = ida_kernwin.Form.DropdownListControl(
            items=process_items,
            readonly=True,
            selval=default_sel
        )
        f = ida_kernwin.Form(form_str, { 'ProcessDropdown': process_dropdown })
        f.Compile()
        ok = f.Execute()

        if not ok:
            log_debug("Process selection cancelled.")
            resolver.cleanup()
            return False

        choice_idx = process_dropdown.value
        if choice_idx < 0 or choice_idx >= len(processes):
             log_error(f"Invalid process selection index: {choice_idx}")
             resolver.cleanup()
             return False
        pid = processes[choice_idx].pid
        log_debug(f"User selected process PID: {pid}")

        # --- Attach --- (Identical to _resolve_pointer_at_runtime)
        ida_kernwin.show_wait_box(f"Attaching to process {pid}...")
        if not resolver.attach_to_process(pid):
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to attach to process {pid}.\nCheck permissions and if Frida is injected/running.")
            resolver.cleanup()
            return False

        # --- Read Data ---
        ida_kernwin.replace_wait_box(f"Reading runtime data at 0x{target_ea:X}...") # Update wait box text
        read_success = False
        try:
            # *** Call the NEW resolver method ***
            result = resolver.read_data(target_ea, item_info)

            ida_kernwin.hide_wait_box()

            if result and 'error' not in result:
                log_info("Runtime data read successful.")
                # *** Call the NEW visualization method ***
                self._visualize_runtime_data(target_ea, item_info, result)
                read_success = True
            elif result and 'error' in result:
                ida_kernwin.warning(f"{PLUGIN_NAME} Data Read Error:\n{result['error']}")
            else:
                ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nRuntime data read failed (no result or unexpected error).")

        except Exception as e:
            ida_kernwin.hide_wait_box()
            log_error(f"Exception during read_data call: {e}", exc=e)
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nAn unexpected error occurred during data read.\n\nDetails: {e}")
        finally:
            resolver.cleanup()
            if ida_kernwin.is_idaq() and ida_kernwin.find_widget("Wait box"):
                 try: ida_kernwin.hide_wait_box()
                 except: pass

        return read_success

    def update(self, ctx):
        """Enable action based on context and attach to popup."""
        widget_type = ctx.widget_type
        if widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_HEXVIEW):
            ida_kernwin.attach_action_to_popup(
                ctx.widget,
                None,
                f"{PLUGIN_NAME}:resolve_pointer", # Registered action name
                f"{PLUGIN_NAME}/",                # Submenu path
                ida_kernwin.SETMENU_INS           # Insertion flag
            )
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def _get_target_ea_from_context(self, ctx):
        """Get the effective address under the cursor based on the view type."""
        widget_type = ctx.widget_type

        if widget_type == ida_kernwin.BWN_DISASM:
            instr_ea = ctx.cur_ea
            if instr_ea == ida_idaapi.BADADDR: return ida_idaapi.BADADDR

            refs = self._extract_operand_references(instr_ea)
            if refs:
                if len(refs) == 1:
                    return list(refs)[0][0]
                else:
                    # --- Multiple References: Use Subclassed Choose ---
                    options = []
                    ref_list = sorted(list(refs), key=lambda x: x[0])
                    for ref_ea, is_src in ref_list:
                        name = ida_name.get_ea_name(ref_ea, ida_name.GN_VISIBLE) or f"0x{ref_ea:X}"
                        options.append(f"{name}")

                    # --- CORRECT Choose Implementation using Subclassing ---
                    class ReferenceChooser(ida_kernwin.Choose):
                        def __init__(self, title, items_list, flags=0):
                            cols = [ ["Reference Target", 40 | ida_kernwin.Choose.CHCOL_PLAIN] ]
                            ida_kernwin.Choose.__init__(
                                self,
                                title,
                                cols,
                                flags=flags)
                            self.items = items_list

                        def OnGetSize(self):
                            return len(self.items)

                        def OnGetLine(self, n):
                            if n < 0 or n >= len(self.items): return []
                            return [self.items[n]]

                    chooser = ReferenceChooser(
                        f"{PLUGIN_NAME}: Select Reference Target",
                        options,
                        flags=ida_kernwin.Choose.CH_MODAL | ida_kernwin.Choose.CH_NOBTNS
                    )
                    choice_idx = chooser.Show()
                    # --- End of CORRECT Choose Implementation ---

                    if choice_idx >= 0 and choice_idx < len(ref_list):
                        return ref_list[choice_idx][0]
                    else:
                        return ida_idaapi.BADADDR

            else: # No operand references found
                return instr_ea

        elif widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # TODO: Future improvement - investigate vu.get_selected_item()
            return ctx.cur_ea

        elif widget_type == ida_kernwin.BWN_HEXVIEW:
            return ctx.cur_ea

        return ida_idaapi.BADADDR

    def _extract_operand_references(self, instr_ea):
        """Extract memory references from instruction operands."""
        refs = set()
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, instr_ea) <= 0:
            return refs

        for i in range(ida_ua.UA_MAXOP):
            op = insn.ops[i]
            if op.type == ida_ua.o_void: break

            ref_ea = ida_idaapi.BADADDR
            is_data_target = False

            if op.type == ida_ua.o_mem:
                ref_ea = op.addr
                if ida_bytes.is_data(ida_bytes.get_flags(ref_ea)) or is_in_data_segment(ref_ea):
                    is_data_target = True

            elif op.type == ida_ua.o_displ:
                ref_ea = op.addr
                if ida_bytes.is_data(ida_bytes.get_flags(ref_ea)) or is_in_data_segment(ref_ea):
                    is_data_target = True
                elif ida_idp.ph.id == ida_idp.PLFM_386 and get_bitness() == 64 and op.specflag1 == ida_ua.X86_OP_ADDR_RIP:
                     rip_target_ea = instr_ea + insn.size + op.addr
                     if is_in_data_segment(rip_target_ea) or ida_bytes.is_data(ida_bytes.get_flags(rip_target_ea)):
                         ref_ea = rip_target_ea
                         is_data_target = True
                     else:
                         ref_ea = ida_idaapi.BADADDR

            elif op.type == ida_ua.o_imm:
                imm_val = op.value
                if ida_segment.getseg(imm_val) is not None:
                    if is_in_data_segment(imm_val) or ida_bytes.is_data(ida_bytes.get_flags(imm_val)):
                        ref_ea = imm_val
                        is_data_target = True

            if ref_ea != ida_idaapi.BADADDR and is_data_target:
                 refs.add((ref_ea, i != 0))
                 log_debug(f"Extracted operand reference: EA=0x{ref_ea:X}, Type={op.type}, IsData={is_data_target}, OpIdx={i}")

        return refs

    def _resolve_pointer_at_runtime(self, target_ea, pointer_info):
        """Core logic to connect, attach, and resolve using Frida."""
        resolver = FridaMemoryResolver()

        # --- Connection ---
        conn_choice = ida_kernwin.ask_buttons("Local", "Remote", "USB", 1, f"{PLUGIN_NAME}: Connection Type")
        if conn_choice < 0: return False
        conn_type = ["local", "remote", "usb"][conn_choice]
        host = "127.0.0.1:27042"
        if conn_type == "remote":
            host_input = ida_kernwin.ask_text(
                0,
                host,
                "Enter remote Frida server address (host:port):"
            )
            if not host_input: return False
            host = host_input

        ida_kernwin.show_wait_box(f"Connecting to Frida ({conn_type})...")
        if not resolver.connect(conn_type, host):
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to connect via {conn_type}" + (f" to {host}" if conn_type == "remote" else ""))
            return False

        # --- Process Selection (Using Form with DropdownListControl) ---
        ida_kernwin.replace_wait_box("Enumerating processes...")
        processes = resolver.get_process_list()
        if not processes:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to enumerate processes on the target device.")
            resolver.cleanup()
            return False

        process_items = [f"{p.pid}: {p.name}" for p in processes]
        current_bin_name = get_file_name()
        default_sel = -1
        for i, item in enumerate(process_items):
             proc_name = item.split(': ', 1)[-1]
             if current_bin_name and (current_bin_name == proc_name or f"{current_bin_name}.exe" == proc_name):
                 default_sel = i
                 break
        if default_sel == -1:
            for i, item in enumerate(process_items):
                if current_bin_name and current_bin_name.lower() in item.lower():
                    default_sel = i
                    break
        if default_sel == -1: default_sel = 0

        ida_kernwin.hide_wait_box()

        form_str = f"""STARTITEM 0
{PLUGIN_NAME}: Select Target Process

<#Select the target process to attach to#Process:{{ProcessDropdown}}>

"""
        process_dropdown = ida_kernwin.Form.DropdownListControl(
            items=process_items,
            readonly=True,
            selval=default_sel
        )
        f = ida_kernwin.Form(form_str, {
            'ProcessDropdown': process_dropdown
        })

        f.Compile()
        ok = f.Execute()

        if not ok:
            log_debug("Process selection cancelled.")
            resolver.cleanup()
            return False

        choice_idx = process_dropdown.value
        if choice_idx < 0 or choice_idx >= len(processes):
             log_error(f"Invalid process selection index: {choice_idx}")
             resolver.cleanup()
             return False

        pid = processes[choice_idx].pid
        log_debug(f"User selected process PID: {pid}")
        # --- End of Process Selection using Form ---

        # --- Attach ---
        ida_kernwin.show_wait_box(f"Attaching to process {pid}...")
        if not resolver.attach_to_process(pid):
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nFailed to attach to process {pid}.\nCheck permissions and if Frida is injected/running.")
            resolver.cleanup()
            return False

        # --- Dereference Level ---
        ida_kernwin.hide_wait_box() # Hide before asking level

        # Corrected ask_long call with only 2 arguments: default value and prompt
        default_deref_level = 1 # Define the default value
        prompt_message = (f"{PLUGIN_NAME}: Traversal Depth\n\n" # Combine title/prompt
                          "Enter pointer chain dereference depth (e.g., 1, 2, ...):")

        deref_level = ida_kernwin.ask_long(default_deref_level, prompt_message)

        # Handle cancellation or invalid input (ask_long returns None on cancel)
        if deref_level is None: # Check specifically for None
            log_debug("Dereference level selection cancelled.")
            resolver.cleanup()
            return False

        # Optional: Add validation if needed (e.g., ensure > 0)
        if deref_level < 1:
             log_debug(f"Invalid dereference level entered: {deref_level}. Defaulting to 1.")
             deref_level = 1 # Or ask again, or cancel

        # --- Resolve ---
        ida_kernwin.show_wait_box(f"Performing runtime resolution (Depth: {deref_level})...")
        resolution_success = False
        try:
            result = resolver.resolve_pointer(target_ea, pointer_info, deref_level)
            ida_kernwin.hide_wait_box()

            if result and 'error' not in result:
                log_info("Runtime resolution successful.")
                self._visualize_memory_introspection(target_ea, result)
                resolution_success = True
            elif result and 'error' in result:
                ida_kernwin.warning(f"{PLUGIN_NAME} Resolution Error:\n{result['error']}")
            else:
                ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nMemory introspection failed (no result or unexpected error).")

        except Exception as e:
            ida_kernwin.hide_wait_box()
            log_error(f"Exception during resolve_pointer call: {e}", exc=e)
            ida_kernwin.warning(f"{PLUGIN_NAME} Error:\nAn unexpected error occurred during resolution.\n\nDetails: {e}")
        finally:
            resolver.cleanup()
            if ida_kernwin.is_idaq() and ida_kernwin.find_widget("Wait box"):
                 try: ida_kernwin.hide_wait_box()
                 except: pass

        return resolution_success

    def _format_address_for_display(self, link):
        """Formats an address using module+offset if available."""
        addr_str = link.get('address', 'unknown')
        module_info = link.get('module')
        if not isinstance(addr_str, str): addr_str = str(addr_str)

        if not addr_str.startswith("0x"):
             if addr_str.lower() in ("invalid_value", "0x0", "null"):
                 return addr_str
             else:
                 try:
                     int(addr_str, 16)
                     addr_str = f"0x{addr_str}"
                 except ValueError:
                     return addr_str

        if module_info and 'name' in module_info and 'offset' in module_info:
            offset_str = module_info['offset']
            if not offset_str.startswith('0x'): offset_str = f"0x{offset_str}"
            mod_name = module_info['name']
            if len(mod_name) > 30: mod_name = mod_name[:15] + "..." + mod_name[-12:]
            return f"{mod_name}+{offset_str} ({addr_str})"
        else:
            return addr_str

    def _visualize_memory_introspection(self, target_ea, result):
        """Display the resolution results in IDA's output window."""
        chain = result.get('chain', [])
        if not chain:
            ida_kernwin.warning(f"{PLUGIN_NAME}: Invalid result format (missing chain).")
            return

        lines = []
        lines.append(f"=== {PLUGIN_NAME}: Runtime Memory Analysis ===")
        lines.append(f"Target: {result.get('pointer_name', 'unknown')} at static EA 0x{target_ea:X} (RVA: {result.get('rva', 'unknown')})")
        lines.append(f"Static Type: {result.get('pointer_type', 'unknown')} ({result.get('pointer_size', '?')} bytes)")
        lines.append(f"Runtime Module Base ({result.get('module_name', 'unknown')}): {result.get('module_base', 'unknown')}")
        arch_info = result.get('architecture')
        if arch_info:
            lines.append(f"Architecture: {arch_info.get('bitness', '?')}-bit, {arch_info.get('endianness', '?')} endian")

        lines.append("\n--- Memory Traversal Path ---")

        for i, link in enumerate(chain):
            level = link.get('level', -1)
            indent = "  " * level

            display_addr = self._format_address_for_display(link)
            lines.append(f"{indent}[L{level}] Address: {display_addr}")

            if 'value' in link and link['value'] != "N/A":
                 value_str = link['value']
                 if not isinstance(value_str, str): value_str = str(value_str)
                 if not value_str.startswith("0x") and value_str.lower() != "null": value_str = f"0x{value_str}"
                 lines.append(f"{indent}  -> Value: {value_str}")

            if 'memory_protection' in link:
                lines.append(f"{indent}     Prot: {link.get('memory_protection', 'unknown')}")

            if 'termination_reason' in link:
                reason = link['termination_reason'].replace('_', ' ').title()
                lines.append(f"{indent}     Stop: {reason}")

            if 'error' in link:
                error_type = link.get('error', 'unknown').replace('_', ' ').title()
                lines.append(f"{indent}     ERROR: {error_type}")
                if 'error_details' in link:
                    lines.append(f"{indent}       Details: {link.get('error_details', 'none')}")

            if level >= 0 and i < len(chain) - 1:
                 lines.append(f"{indent}  --------------------")

        mem_ctx = result.get('memory_context')
        if mem_ctx:
            lines.append("\n--- Memory Context (Around Last Valid Address) ---")
            ctx_addr_str = mem_ctx.get('context_address', '?')
            ctx_module_info = get_module_info_for_addr_py(ctx_addr_str)
            display_ctx_addr = self._format_address_for_display({'address': ctx_addr_str, 'module': ctx_module_info})
            lines.append(f"Center Address: {display_ctx_addr}")
            lines.append(f"  Before: {mem_ctx.get('before', 'N/A')}")
            lines.append(f"  Exact:  {mem_ctx.get('exact', 'N/A')}")
            lines.append(f"  After:  {mem_ctx.get('after', 'N/A')}")

        print("\n".join(lines))

        # Find the widget by its title
        output_widget = ida_kernwin.find_widget("Output window")

        # Check if the widget was found before trying to activate it
        if output_widget:
            ida_kernwin.activate_widget(output_widget, True) # Pass the widget object
        else:
            log_debug("Could not find 'Output window' to activate.")

        prompt = f"HIDECANCEL\n{PLUGIN_NAME}: Annotation\nAnnotate static location 0x{target_ea:X} with runtime result?"

        if ida_kernwin.ask_yn(1, prompt) == 1:
            if len(chain) > 0:
                # Format L0 value
                l0_val_str = chain[0].get('value', '?')
                if not isinstance(l0_val_str, str): l0_val_str = str(l0_val_str)
                if not l0_val_str.startswith("0x"): l0_val_str = f"0x{l0_val_str}"
                annotation = f"frIDA[L0]: {l0_val_str}"

                last_link = chain[-1]
                last_level = last_link.get('level', 0)

                if last_level > 0:
                    annotation += " -> "
                    runtime_addr_str = last_link.get('address', 'unknown') # Runtime address as string
                    display_target = runtime_addr_str # Default display is runtime address

                    # --- Attempt Symbol Resolution ---
                    module_info = last_link.get('module')
                    static_ea = ida_idaapi.BADADDR

                    # Try to resolve only if module info is present and seems valid
                    if module_info and 'name' in module_info and 'offset' in module_info:
                        try:
                            offset = int(module_info['offset'], 16)
                            module_name = module_info['name']
                            main_module_name = result.get('module_name', '')

                            # Heuristic: Assume it's the main module if names match
                            # TODO: Enhance this to handle other loaded modules if needed
                            if module_name == main_module_name:
                                static_base = get_imagebase()
                                if static_base != ida_idaapi.BADADDR:
                                    static_ea = static_base + offset
                                    log_debug(f"Calculated static EA: 0x{static_ea:X} (Base: 0x{static_base:X}, Offset: 0x{offset:X})")
                            else:
                                # Handling other modules requires finding their static base in IDA,
                                # which can be complex. Log for now.
                                log_debug(f"Target address in different module '{module_name}', symbol resolution might be incomplete.")
                                # As a fallback, try using the segment base if available
                                seg = ida_segment.getseg(target_ea) # Use original target_ea segment as hint? No, use runtime addr seg
                                if runtime_addr_str.startswith("0x"):
                                     rt_addr_int = int(runtime_addr_str, 16)
                                     seg_rt = ida_segment.getseg(rt_addr_int)
                                     if seg_rt:
                                         # This is still heuristic, might not map correctly statically
                                         log_debug(f"Using segment base 0x{seg_rt.start_ea:X} as potential static base for module {module_name}")
                                         # static_ea = seg_rt.start_ea + offset # This is likely incorrect mapping

                        except ValueError:
                            log_debug(f"Could not parse offset: {module_info.get('offset')}")
                        except Exception as e:
                            log_error(f"Error during static EA calculation: {e}", exc=e)

                    # Get symbol name if we found a valid static EA
                    symbol_name = None
                    if static_ea != ida_idaapi.BADADDR:
                        # Use GN_VISIBLE to get user-friendly names
                        symbol_name = ida_name.get_ea_name(static_ea, ida_name.GN_VISIBLE)
                        log_debug(f"Symbol lookup for 0x{static_ea:X}: '{symbol_name}'")

                    # Use symbol name if found, otherwise format module+offset
                    if symbol_name:
                        display_target = symbol_name
                    elif module_info and 'name' in module_info and 'offset' in module_info:
                         # Fallback to module+offset if symbol not found but info exists
                         display_target = self._format_address_for_display(last_link).split(' ')[0] # Get "module+offset" part
                    # --- End Symbol Resolution ---


                    # Construct the final part of the annotation
                    if 'error' in last_link:
                        error_type = last_link.get('error', 'unknown').replace('_',' ').title()
                        # Include runtime address in error for context
                        annotation += f"[L{last_level} ERROR: {error_type} @ {display_target} ({runtime_addr_str})]"
                    elif 'termination_reason' in last_link:
                        reason = last_link['termination_reason'].replace('_',' ').title()
                        annotation += f"[L{last_level} Stop: {reason} @ {display_target} ({runtime_addr_str})]"
                    elif 'value' in last_link and last_link['value'] != 'N/A':
                         value_str = last_link['value']
                         if not isinstance(value_str, str): value_str = str(value_str)
                         if not value_str.startswith("0x") and value_str.lower() != "null": value_str = f"0x{value_str}"
                         # Show resolved value and the symbol/location it points to
                         annotation += f"[L{last_level}]: {value_str} @ {display_target} ({runtime_addr_str})"
                    else:
                         # Fallback if no value/error/term
                         annotation += f"[L{last_level} @ {display_target} ({runtime_addr_str})]"

                # Add comment (non-repeatable)
                ida_bytes.set_cmt(target_ea, annotation, False)
                log_debug(f"Added annotation at 0x{target_ea:X}: {annotation}")

# End of ResolvePointerAction class


# Helper function (Python side) to get module info - used for context display
def get_module_info_for_addr_py(addr_str):
    try:
        if not addr_str or addr_str == '?': return None
        addr = int(addr_str, 16)
        # Prioritize Frida's module list if available (more accurate runtime info)
        # This requires passing the full module list back or querying Frida again,
        # which adds complexity. Stick to IDA's view for now.

        # Use IDA's module info first
        mod_info = ida_nalt.get_module_info(addr)
        if mod_info and mod_info.base != ida_idaapi.BADADDR:
            offset = addr - mod_info.base
            mod_name = os.path.basename(mod_info.name or "unknown")
            return {'name': mod_name, 'offset': f"0x{offset:X}"}

        # Fallback to segment info
        seg = ida_segment.getseg(addr)
        if seg:
             seg_name = ida_segment.get_segm_name(seg)
             # Heuristic: if segment base is near imagebase, assume it's part of the main module
             # This is less reliable with ASLR but better than nothing
             static_imagebase = get_imagebase()
             if abs(seg.start_ea - static_imagebase) < 0x200000: # Wider threshold
                  offset = addr - static_imagebase
                  return {'name': get_file_name(), 'offset': f"0x{offset:X}"}
             else:
                  # Treat as offset from segment start if not near imagebase
                  offset = addr - seg.start_ea
                  return {'name': f"Seg:{seg_name}", 'offset': f"0x{offset:X}"}

    except ValueError:
        pass # Invalid address string
    except Exception as e:
        log_debug(f"Error getting module info for context addr {addr_str}: {e}")
    return None


#-------------------------------------------------------------------------------
# Plugin Registration
#-------------------------------------------------------------------------------
class frIDAPlugin(ida_idaapi.plugin_t):
    """Main plugin registration class for IDA Pro."""
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Runtime Pointer Resolution using Frida"
    help = "Right-click pointers/data and select 'Resolve Pointer at Runtime' (Ctrl+Alt+F)"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "" # Hotkey registered via action

    def init(self):
        """Initialize the plugin."""
        global HAS_FRIDA

        try:
            import frida
            HAS_FRIDA = True
        except ImportError:
            HAS_FRIDA = False
            print(f"[{PLUGIN_NAME}] Warning: Frida Python package not found.")
            print(f"[{PLUGIN_NAME}] Install with: pip install frida frida-tools")
            print(f"[{PLUGIN_NAME}] Plugin will load but functionality will be disabled.")

        action_desc = ida_kernwin.action_desc_t(
            f"{PLUGIN_NAME}:resolve_pointer",
            "Resolve Pointer at Runtime",
            ResolvePointerAction(),
            PLUGIN_HOTKEY,
            "Connect to Frida and resolve this pointer's runtime value chain",
            -1
        )

        if not ida_kernwin.register_action(action_desc):
            log_error("Failed to register plugin action")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.attach_action_to_menu(
            f"Edit/Plugins/{PLUGIN_NAME}/Resolve Pointer at Runtime",
            f"{PLUGIN_NAME}:resolve_pointer",
            ida_kernwin.SETMENU_APP
        )

        log_info(f"Plugin v{PLUGIN_VERSION} initialized. Hotkey: {PLUGIN_HOTKEY}")
        print(f"[{PLUGIN_NAME}] Ready. Right-click on pointers/data or use {PLUGIN_HOTKEY}.")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Called when plugin is selected from the main menu."""
        ida_kernwin.info(
            f"{PLUGIN_NAME} v{PLUGIN_VERSION}\n\n"
            f"This plugin resolves static pointers/data at runtime using Frida.\n\n"
            f"Usage:\n"
            f"1. Right-click on a pointer, data reference, or immediate value\n"
            f"   in Disassembly, Pseudocode, or Hex View.\n"
            f"2. Select '{PLUGIN_NAME}/Resolve Pointer at Runtime' from the context menu.\n"
            f"3. Alternatively, place the cursor and press {PLUGIN_HOTKEY}.\n\n"
            f"Requires:\n"
            f"- Frida Python package (`pip install frida frida-tools`)\n"
            f"- Target process running with frida-server or frida-gadget."
        )

    def term(self):
        """Terminate the plugin."""
        ida_kernwin.detach_action_from_menu(
             f"Edit/Plugins/{PLUGIN_NAME}/Resolve Pointer at Runtime",
             f"{PLUGIN_NAME}:resolve_pointer"
        )
        ida_kernwin.unregister_action(f"{PLUGIN_NAME}:resolve_pointer")
        log_info("Plugin terminated")

#-------------------------------------------------------------------------------
# Plugin Entry Point
#-------------------------------------------------------------------------------
def PLUGIN_ENTRY():
    """IDA Pro plugin entry point."""
    return frIDAPlugin()