# -*- coding: utf-8 -*-
"""
summary: IDA Pro plugin to dump decompiled code of a function and its callers/callees/references,
         or multiple specified functions and their combined graphs.

description:
  This plugin adds:
  1. A context menu item ("Dump Function + Callers/Callees/Refs...") to the Pseudocode view.
     When activated, it prompts for depths and an output file for the *current* function.
  2. A menu item under "Edit -> Plugins -> Code Dumper (Callers/Callees/Refs)" (or similar path).
     When activated, it prompts for a comma-separated list of function names/addresses,
     then prompts for depths and an output file to be applied to *all* specified functions.

  It traverses the call graph upwards (callers) and downwards (callees/references)
  up to the specified depths from the starting function(s), collects all unique
  function addresses, decompiles them using the Hex-Rays decompiler, and saves the
  results into the selected C file.

  Callee/Reference finding includes:
  - Direct calls (via code cross-references).
  - Functions whose addresses are referenced by instructions (via data cross-references, e.g., mov reg, offset func).
  - Functions whose addresses appear as immediate operands (e.g., push offset func).
  - Functions "called" via the 'push <addr>; ret' pattern.

  All IDA API interactions are performed synchronously in the main IDA thread, managed via
  execute_sync and execute_ui_requests from background threads.

  Requires:
  - IDA Pro 7.6+ (with Python 3 and PyQt5 support for dialogs)
  - Hex-Rays Decompiler
  - Uses ida_xref API (compatible with IDA 7.x and IDA 9+)

FINAL VERSION: Uses PLUGIN_FIX for main menu integration via run().
"""

# --- Imports ---
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import idaapi
import idautils
import idc
import ida_xref   # For xref iteration
import ida_nalt
import ida_ua     # For instruction decoding
import ida_idp    # For is_ret_insn, instruction features

import threading
import os
import sys
from functools import partial
import traceback
import time
import re # For parsing addresses

# Third-party libraries (PyQt5 needed for standard IDA dialogs)
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    print("CodeDumper: PyQt5 imported successfully (needed for IDA dialogs).")
except ImportError:
    print("CodeDumper Error: PyQt5 not found. Standard IDA dialogs might not work.")
    # Allow plugin to load, but dialogs might fail later.

# --- Configuration ---
PLUGIN_NAME = "Code Dumper (Callers/Callees/Refs)"
# Context Menu Action
ACTION_ID_CTX = "codedumper:dump_callers_callees_refs_ctx"
ACTION_LABEL_CTX = "Dump Function + Callers/Callees/Refs..."
ACTION_TOOLTIP_CTX = "Decompile current function, callers, callees, and referenced functions to a C file"
MENU_PATH_CTX = "Dump code/" # Submenu path for context menu
# Multi-Function Menu Action (Action still exists, but menu entry is via plugin run())
ACTION_ID_MULTI = "codedumper:dump_multi_functions"
ACTION_LABEL_MULTI = "Dump Multiple Functions..." # Label if triggered via action API
ACTION_TOOLTIP_MULTI = "Decompile a list of functions and their combined callers/callees/refs"
# MENU_PATH_MULTI = "Plugins/" # No longer used for attachment

# --- Concurrency Control ---
g_dump_in_progress = set() # Set of func_ea currently being processed (for single context menu dumps)
g_multi_dump_active = False # Flag for multi-function dump
g_dump_lock = threading.Lock()
print("CodeDumper: Concurrency control variables initialized.")


# --- Helper Functions for Graph Traversal (MUST run in main thread) ---

def find_callers_recursive(target_ea, current_depth, max_depth, visited_eas):
    """
    Recursively finds callers up to a specified depth using xrefs.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Modifies visited_eas in place.
    """
    # Check depth first
    if current_depth > max_depth:
        return set()

    # Check if already visited *before* adding again (important for multi-start)
    if target_ea in visited_eas:
        return set()

    visited_eas.add(target_ea)
    callers = set()

    # Find direct callers to target_ea using code cross-references
    ref_ea = ida_xref.get_first_cref_to(target_ea)
    while ref_ea != idaapi.BADADDR:
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func:
            caller_ea = caller_func.start_ea
            # Recurse *only* if not already visited
            if caller_ea not in visited_eas:
                callers.add(caller_ea)
                # Pass the *same* visited_eas set down
                callers.update(find_callers_recursive(caller_ea, current_depth + 1, max_depth, visited_eas))
            # else: # Already visited or part of the initial set, don't recurse further from here
            #    pass

        ref_ea = ida_xref.get_next_cref_to(target_ea, ref_ea)

    return callers

def find_callees_recursive(target_ea, current_depth, max_depth, visited_eas):
    """
    Recursively finds callees (direct calls) and referenced functions
    up to a specified depth using instruction analysis and cross-references.
    Handles direct calls, data references to functions (e.g., mov reg, offset func),
    immediate operands containing function addresses, and push <addr>/ret patterns.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Modifies visited_eas in place.
    """
    # Check depth first
    if current_depth > max_depth:
        return set()

    # Check if already fully processed *before* adding again
    if target_ea in visited_eas:
        return set()

    # Mark as visited *now* before processing contents to handle recursion
    visited_eas.add(target_ea)
    # print(f"  [find_callees] Depth {current_depth}, Target: 0x{target_ea:X}") # Noisy

    callees_and_refs = set()

    func = ida_funcs.get_func(target_ea)
    if not func:
        # print(f"  [find_callees] Warning: Could not get func object for 0x{target_ea:X}")
        return callees_and_refs # Return empty set, already marked as visited

    current_item_ea = func.start_ea
    insn = ida_ua.insn_t()
    next_insn = ida_ua.insn_t() # For push/ret lookahead

    while current_item_ea < func.end_ea and current_item_ea != idaapi.BADADDR:
        insn_len = ida_ua.decode_insn(insn, current_item_ea)

        if insn_len == 0:
            next_ea = idc.next_head(current_item_ea, func.end_ea)
            if next_ea <= current_item_ea: break
            current_item_ea = next_ea
            continue

        # --- Check Code References FROM ---
        cref_ea = ida_xref.get_first_cref_from(current_item_ea)
        while cref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(cref_ea)
            if ref_func and ref_func.start_ea == cref_ea:
                # Recurse only if it hasn't been processed yet
                if cref_ea not in visited_eas:
                    callees_and_refs.add(cref_ea) # Add the direct reference
                    # Pass the *same* visited_eas set down
                    recursive_results = find_callees_recursive(cref_ea, current_depth + 1, max_depth, visited_eas)
                    callees_and_refs.update(recursive_results)
                # else: # Already visited or part of the initial set
                #    pass
            cref_ea = ida_xref.get_next_cref_from(current_item_ea, cref_ea)

        # --- Check Data References FROM ---
        dref_ea = ida_xref.get_first_dref_from(current_item_ea)
        while dref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(dref_ea)
            if ref_func and ref_func.start_ea == dref_ea:
                 # Recurse only if it hasn't been processed yet
                 if dref_ea not in visited_eas:
                    callees_and_refs.add(dref_ea) # Add the direct reference
                    # Pass the *same* visited_eas set down
                    recursive_results = find_callees_recursive(dref_ea, current_depth + 1, max_depth, visited_eas)
                    callees_and_refs.update(recursive_results)
                 # else: # Already visited or part of the initial set
                 #    pass
            dref_ea = ida_xref.get_next_dref_from(current_item_ea, dref_ea)

        # --- Check Immediate Operands & Push/Ret Pattern ---
        is_push_imm_func = False
        pushed_func_addr = idaapi.BADADDR

        for i in range(idaapi.UA_MAXOP):
            op = insn.ops[i]
            if op.type == idaapi.o_void: break

            if op.type == idaapi.o_imm:
                imm_val = op.value
                ref_func = ida_funcs.get_func(imm_val)
                if ref_func and ref_func.start_ea == imm_val:
                    mnem = insn.get_canon_mnem()
                    if mnem == "push":
                         is_push_imm_func = True
                         pushed_func_addr = imm_val

                    # Recurse only if it hasn't been processed yet
                    if imm_val not in visited_eas:
                        callees_and_refs.add(imm_val) # Add the direct reference
                        # Pass the *same* visited_eas set down
                        recursive_results = find_callees_recursive(imm_val, current_depth + 1, max_depth, visited_eas)
                        callees_and_refs.update(recursive_results)
                    # else: # Already visited or part of the initial set
                    #    pass

        # --- Check for 'ret' following a 'push <func_addr>' ---
        if is_push_imm_func:
            next_insn_ea = current_item_ea + insn_len
            if next_insn_ea < func.end_ea:
                next_insn_len = ida_ua.decode_insn(next_insn, next_insn_ea)
                if next_insn_len > 0:
                    if ida_idp.is_ret_insn(next_insn, ida_idp.IRI_RET_LITERALLY):
                        # Found the push <func_addr>; ret pattern
                        # The function address was already added and recursed on (if needed)
                        # by the immediate operand check above. No further action needed here.
                        pass

        # Advance
        next_ea = current_item_ea + insn_len
        if next_ea <= current_item_ea:
             next_ea = idc.next_head(current_item_ea, func.end_ea)
             if next_ea <= current_item_ea: break
        current_item_ea = next_ea

    return callees_and_refs


# --- Decompilation Function (MUST run in main thread) ---

def decompile_functions_main(eas_to_decompile):
    """
    Decompiles a set of function EAs.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Returns a dictionary {ea: decompiled_code_string_or_error}.
    """
    print(f"CodeDumper: [decompile_functions_main] Decompiling {len(eas_to_decompile)} functions in main thread...")
    results = {}
    total = len(eas_to_decompile)
    count = 0
    start_time = time.time()

    # Initialize Hex-Rays if not already done (safer)
    if not ida_hexrays.init_hexrays_plugin():
         print("CodeDumper Error: [decompile_functions_main] Failed to initialize Hex-Rays.")
         for func_ea in eas_to_decompile:
              func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
              results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Hex-Rays init failed"
         return results

    sorted_eas_list = sorted(list(eas_to_decompile)) # Decompile in a consistent order

    for func_ea in sorted_eas_list:
        count += 1
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        ida_kernwin.replace_wait_box(f"Decompiling {count}/{total}: {func_name}")
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                results[func_ea] = str(cfunc)
            else:
                results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Decompiler returned None"
                # print(f"  [decompile_main] Warning: Decompilation returned None for 0x{func_ea:X}")
        except ida_hexrays.DecompilationFailure as e:
            results[func_ea] = f"// Decompilation ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  [decompile_main] Error: Decompilation failed for 0x{func_ea:X}: {e}")
        except Exception as e:
            results[func_ea] = f"// Decompilation UNEXPECTED ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  [decompile_main] Error: Unexpected error decompiling 0x{func_ea:X}: {e}")
            traceback.print_exc()

    end_time = time.time()
    print(f"CodeDumper: [decompile_functions_main] Decompilation finished in {end_time - start_time:.2f} seconds.")
    return results

# --- Background Task Helper ---
def write_output_file(output_file_path, decompiled_results, start_func_eas, caller_depth, callee_depth):
    """Writes the decompiled results to the specified file."""
    print(f"CodeDumper: [write_output_file] Writing {len(decompiled_results)} functions to {output_file_path}...")
    num_funcs_written = 0
    try:
        name_map = {}
        name_map_container = [{}]
        eas_to_get_names = list(decompiled_results.keys())

        def get_names_main(eas, container):
            # print("  [get_names_main] Getting names in main thread...")
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(
            lambda: get_names_main(eas_to_get_names, name_map_container),
            ida_kernwin.MFF_READ
        )
        if sync_status == 1:
            name_map = name_map_container[0]
        else:
            print("CodeDumper Warning: [write_output_file] Failed to get function names. Using defaults.")
            for ea in eas_to_get_names:
                name_map[ea] = f"sub_{ea:X}"

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"// Decompiled code dump generated by {PLUGIN_NAME}\n")
            if len(start_func_eas) == 1:
                 start_ea = list(start_func_eas)[0]
                 f.write(f"// Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
            else:
                 f.write("// Start Functions:\n")
                 for start_ea in sorted(list(start_func_eas)):
                      f.write(f"//   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")

            f.write(f"// Caller Depth: {caller_depth}\n")
            f.write(f"// Callee/Ref Depth: {callee_depth}\n")
            f.write(f"// Total Functions Found: {len(decompiled_results)}\n")
            f.write(f"// {'-'*60}\n\n")

            sorted_eas = sorted(decompiled_results.keys())

            for func_ea in sorted_eas:
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                code_or_error = decompiled_results[func_ea]

                f.write(f"// --- Function: {func_name} (0x{func_ea:X}) ---\n")
                f.write(code_or_error)
                f.write(f"\n// --- End Function: {func_name} (0x{func_ea:X}) ---\n\n")

        num_funcs_written = len(decompiled_results)
        print(f"CodeDumper: [write_output_file] Successfully wrote dump file: {output_file_path}")
        return num_funcs_written

    except Exception as e:
        print(f"CodeDumper Error: [write_output_file] Failed to write output file: {e}")
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing dump file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

# --- Main Background Task (Single Function) ---

def dump_code_task(start_func_ea, caller_depth, callee_depth, output_file_path):
    """
    The main logic executed in a background thread for a SINGLE starting function.
    Orchestrates finding functions, decompiling, and writing the file.
    Uses execute_sync/execute_ui_requests for IDA API calls and UI.
    """
    start_func_ea_str = f"0x{start_func_ea:X}"
    print(f"CodeDumper: [dump_code_task] Background task started for {start_func_ea_str} (Callers: {caller_depth}, Callees/Refs: {callee_depth})")
    print(f"  Output file: {output_file_path}")

    try:
        all_funcs_to_decompile = set()
        all_funcs_to_decompile.add(start_func_ea)

        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box(f"Finding callers/callees/refs for {start_func_ea_str}...")])

        # --- Find Callers (Main Thread) ---
        caller_eas = set()
        if caller_depth > 0:
            # print(f"CodeDumper: [dump_code_task] Finding callers up to depth {caller_depth}...")
            caller_result_container = [set()]
            visited_caller_container = [set()]

            def run_find_callers_main(container, visited_set_container):
                try:
                    container[0] = find_callers_recursive(start_func_ea, 1, caller_depth, visited_set_container[0])
                    return 1
                except Exception as e:
                    print(f"  [run_find_callers_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_callers_main(caller_result_container, visited_caller_container),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                caller_eas = caller_result_container[0]
                all_funcs_to_decompile.update(caller_eas)
                print(f"CodeDumper: [dump_code_task] Found {len(caller_eas)} callers.")
            else:
                print("CodeDumper Error: [dump_code_task] Failed to find callers in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callers.")
                with g_dump_lock: g_dump_in_progress.discard(start_func_ea)
                return

        # --- Find Callees and Referenced Functions (Main Thread) ---
        callee_ref_eas = set()
        if callee_depth > 0:
            # print(f"CodeDumper: [dump_code_task] Finding callees/refs up to depth {callee_depth}...")
            callee_result_container = [set()]
            visited_callee_container = [set()]

            def run_find_callees_main(container, visited_set_container):
                try:
                    container[0] = find_callees_recursive(start_func_ea, 1, callee_depth, visited_set_container[0])
                    return 1
                except Exception as e:
                    print(f"  [run_find_callees_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_callees_main(callee_result_container, visited_callee_container),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                callee_ref_eas = callee_result_container[0]
                all_funcs_to_decompile.update(callee_ref_eas)
                print(f"CodeDumper: [dump_code_task] Found {len(callee_ref_eas)} callees/refs.")
            else:
                print("CodeDumper Error: [dump_code_task] Failed to find callees/refs in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callees/refs.")
                with g_dump_lock: g_dump_in_progress.discard(start_func_ea)
                return

        total_funcs = len(all_funcs_to_decompile)
        print(f"CodeDumper: [dump_code_task] Total unique functions to decompile: {total_funcs}")
        if total_funcs == 0:
            print("CodeDumper: [dump_code_task] No functions to decompile.")
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: No functions found to decompile.")
            with g_dump_lock: g_dump_in_progress.discard(start_func_ea)
            return

        # --- Decompile Functions (Main Thread) ---
        decompiled_results = {}
        decomp_result_container = [{}]

        def run_decompile_main(container):
            try:
                container[0] = decompile_functions_main(all_funcs_to_decompile)
                return 1
            except Exception as e:
                print(f"  [run_decompile_main] Error: {e}")
                traceback.print_exc()
                container[0] = {}
                return 0

        sync_status = ida_kernwin.execute_sync(
            lambda: run_decompile_main(decomp_result_container),
            ida_kernwin.MFF_WRITE # Decompilation might modify database
        )

        if sync_status == 1:
            decompiled_results = decomp_result_container[0]
            print(f"CodeDumper: [dump_code_task] Decompilation finished. Received {len(decompiled_results)} results.")
            if len(decompiled_results) != total_funcs:
                 print(f"CodeDumper Warning: [dump_code_task] Mismatch between expected functions ({total_funcs}) and decompiled results ({len(decompiled_results)}).")
        else:
            print("CodeDumper Error: [dump_code_task] Failed to decompile functions in main thread.")
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: Failed during decompilation.")
            with g_dump_lock: g_dump_in_progress.discard(start_func_ea)
            return

        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

        # --- Write to File (Background Thread) ---
        num_funcs_written = write_output_file(
            output_file_path,
            decompiled_results,
            {start_func_ea}, # Pass as a set for consistency
            caller_depth,
            callee_depth
        )

        if num_funcs_written > 0:
            final_message = f"{PLUGIN_NAME}: Successfully dumped {num_funcs_written} functions to:\n{output_file_path}"
            def show_final_info_sync(msg):
                ida_kernwin.info(msg)
                return 1
            ida_kernwin.execute_sync(lambda msg=final_message: show_final_info_sync(msg), ida_kernwin.MFF_WRITE)

    except Exception as e:
        print(f"CodeDumper Error: [dump_code_task] Unexpected error in background task: {e}")
        traceback.print_exc()
        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.warning(f"{PLUGIN_NAME}: An unexpected error occurred.")])
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

    finally:
        # print(f"CodeDumper: [dump_code_task] Entering finally block for {start_func_ea_str}...")
        with g_dump_lock:
            g_dump_in_progress.discard(start_func_ea)
            # print(f"CodeDumper: [dump_code_task] Concurrency flag released. Current single dumps: {g_dump_in_progress}")
        print(f"CodeDumper: [dump_code_task] Background task finished for {start_func_ea_str}.")


# --- Main Background Task (Multi Function) ---

# --- Main Background Task (Multi Function) ---

def dump_multi_code_task(start_func_eas, caller_depth, callee_depth, output_file_path):
    """
    The main logic executed in a background thread for MULTIPLE starting functions.
    Orchestrates finding functions, decompiling, and writing the file.
    Uses execute_sync/execute_ui_requests for IDA API calls and UI.
    """
    global g_multi_dump_active # To modify the global flag

    # --- Get Start Function Names (Main Thread) ---
    start_func_names = []
    start_names_container = [[]] # Container for results from main thread

    def get_start_names_main(eas, container):
        # print("  [get_start_names_main] Getting start names in main thread...")
        names = []
        for ea in eas:
            name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            names.append(f"{name}(0x{ea:X})")
        container[0] = names
        return 1 # Indicate success

    sync_status = ida_kernwin.execute_sync(
        lambda: get_start_names_main(start_func_eas, start_names_container),
        ida_kernwin.MFF_READ
    )

    if sync_status == 1:
        start_func_names = start_names_container[0]
        start_desc = ", ".join(start_func_names)
        print(f"CodeDumper: [dump_multi_code_task] Background task started for {len(start_func_eas)} functions: {start_desc}")
    else:
        # Fallback if name retrieval failed
        print(f"CodeDumper Warning: [dump_multi_code_task] Failed to get start function names. Proceeding anyway.")
        print(f"CodeDumper: [dump_multi_code_task] Background task started for {len(start_func_eas)} functions.")

    print(f"  Callers: {caller_depth}, Callees/Refs: {callee_depth}, Output file: {output_file_path}")


    # --- Main Logic (Rest of the function remains the same) ---
    try:
        # Initialize with all starting functions
        all_funcs_to_decompile = set(start_func_eas)

        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box(f"Finding callers/callees/refs for {len(start_func_eas)} functions...")])

        # --- Find Callers (Main Thread) ---
        total_caller_eas = set()

        if caller_depth > 0:
            # print(f"CodeDumper: [dump_multi_code_task] Finding callers up to depth {caller_depth}...")
            caller_result_container = [set()]
            visited_caller_container = [set()]

            def run_find_multi_callers_main(container, visited_set_container):
                combined_callers = set()
                try:
                    for start_ea in start_func_eas:
                        found = find_callers_recursive(start_ea, 1, caller_depth, visited_set_container[0])
                        combined_callers.update(found)
                    container[0] = combined_callers
                    return 1
                except Exception as e:
                    print(f"  [run_find_multi_callers_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_multi_callers_main(caller_result_container, visited_caller_container),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                total_caller_eas = caller_result_container[0]
                all_funcs_to_decompile.update(total_caller_eas)
                print(f"CodeDumper: [dump_multi_code_task] Found {len(total_caller_eas)} total unique callers.")
            else:
                print("CodeDumper Error: [dump_multi_code_task] Failed to find callers in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callers for multiple functions.")
                with g_dump_lock: g_multi_dump_active = False
                return

        # --- Find Callees and Referenced Functions (Main Thread) ---
        visited_callees = set()
        total_callee_ref_eas = set()

        if callee_depth > 0:
            # print(f"CodeDumper: [dump_multi_code_task] Finding callees/refs up to depth {callee_depth}...")
            callee_result_container = [set()]
            visited_callee_container = [visited_callees]

            def run_find_multi_callees_main(container, visited_set_container):
                combined_callees = set()
                try:
                    for start_ea in start_func_eas:
                        found = find_callees_recursive(start_ea, 1, callee_depth, visited_set_container[0])
                        combined_callees.update(found)
                    container[0] = combined_callees
                    return 1
                except Exception as e:
                    print(f"  [run_find_multi_callees_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_multi_callees_main(callee_result_container, visited_callee_container),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                total_callee_ref_eas = callee_result_container[0]
                all_funcs_to_decompile.update(total_callee_ref_eas)
                print(f"CodeDumper: [dump_multi_code_task] Found {len(total_callee_ref_eas)} total unique callees/refs.")
            else:
                print("CodeDumper Error: [dump_multi_code_task] Failed to find callees/refs in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callees/refs for multiple functions.")
                with g_dump_lock: g_multi_dump_active = False
                return

        total_funcs = len(all_funcs_to_decompile)
        print(f"CodeDumper: [dump_multi_code_task] Total unique functions to decompile: {total_funcs}")
        if total_funcs == 0:
            print("CodeDumper: [dump_multi_code_task] No functions to decompile.")
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: No functions found to decompile.")
            with g_dump_lock: g_multi_dump_active = False
            return

        # --- Decompile Functions (Main Thread) ---
        decompiled_results = {}
        decomp_result_container = [{}]

        def run_decompile_main(container):
            try:
                container[0] = decompile_functions_main(all_funcs_to_decompile)
                return 1
            except Exception as e:
                print(f"  [run_decompile_main] Error: {e}")
                traceback.print_exc()
                container[0] = {}
                return 0

        sync_status = ida_kernwin.execute_sync(
            lambda: run_decompile_main(decomp_result_container),
            ida_kernwin.MFF_WRITE # Decompilation might modify database
        )

        if sync_status == 1:
            decompiled_results = decomp_result_container[0]
            print(f"CodeDumper: [dump_multi_code_task] Decompilation finished. Received {len(decompiled_results)} results.")
            if len(decompiled_results) != total_funcs:
                 print(f"CodeDumper Warning: [dump_multi_code_task] Mismatch between expected functions ({total_funcs}) and decompiled results ({len(decompiled_results)}).")
        else:
            print("CodeDumper Error: [dump_multi_code_task] Failed to decompile functions in main thread.")
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: Failed during decompilation.")
            with g_dump_lock: g_multi_dump_active = False
            return

        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

        # --- Write to File (Background Thread) ---
        num_funcs_written = write_output_file(
            output_file_path,
            decompiled_results,
            start_func_eas, # Pass the original set of starting EAs
            caller_depth,
            callee_depth
        )

        if num_funcs_written > 0:
            final_message = f"{PLUGIN_NAME}: Successfully dumped {num_funcs_written} functions (from {len(start_func_eas)} starting points) to:\n{output_file_path}"
            def show_final_info_sync(msg):
                ida_kernwin.info(msg)
                return 1
            ida_kernwin.execute_sync(lambda msg=final_message: show_final_info_sync(msg), ida_kernwin.MFF_WRITE)

    except Exception as e:
        print(f"CodeDumper Error: [dump_multi_code_task] Unexpected error in background task: {e}")
        traceback.print_exc()
        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.warning(f"{PLUGIN_NAME}: An unexpected error occurred during multi-dump.")])
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

    finally:
        # print(f"CodeDumper: [dump_multi_code_task] Entering finally block for multi-dump...")
        with g_dump_lock:
            g_multi_dump_active = False
            # print(f"CodeDumper: [dump_multi_code_task] Multi-dump concurrency flag released.")
        print(f"CodeDumper: [dump_multi_code_task] Background task finished.")


# --- IDA Plugin Integration ---

class DumpCtxActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the context menu action."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        # print("CodeDumper: [DumpCtxActionHandler.__init__] Handler created.")

    def activate(self, ctx):
        """Called when the context menu item is clicked."""
        global g_dump_in_progress, g_multi_dump_active
        # print("CodeDumper: [DumpCtxActionHandler.activate] Action activated.")
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            # print("CodeDumper: [activate Ctx] Not in Pseudocode view. Ignoring.")
            return 1

        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            print("CodeDumper Error: [activate Ctx] Could not get vdui or cfunc.")
            ida_kernwin.warning(f"{PLUGIN_NAME}: Decompilation not available for this function.")
            return 1

        start_func_ea = vu.cfunc.entry_ea
        start_func_ea_str = f"0x{start_func_ea:X}"
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea_str}"
        # print(f"CodeDumper: [activate Ctx] Target function: {start_func_name} ({start_func_ea_str})")

        # --- Concurrency Check ---
        # print(f"CodeDumper: [activate Ctx] Acquiring lock for {start_func_ea_str}...")
        with g_dump_lock:
            # print(f"CodeDumper: [activate Ctx] Lock acquired. Checking concurrency...")
            if start_func_ea in g_dump_in_progress:
                print(f"CodeDumper: [activate Ctx] Dump already in progress for {start_func_ea_str}.")
                ida_kernwin.warning(f"{PLUGIN_NAME}: Dump already running for {start_func_name}. Please wait.")
                return 1
            if g_multi_dump_active:
                print(f"CodeDumper: [activate Ctx] Multi-dump is active. Blocking single dump.")
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function dump is currently running. Please wait.")
                return 1
            g_dump_in_progress.add(start_func_ea)
            # print(f"CodeDumper: [activate Ctx] Marked {start_func_ea_str} as in progress. Current single: {g_dump_in_progress}, Multi active: {g_multi_dump_active}")
        # print(f"CodeDumper: [activate Ctx] Lock released for {start_func_ea_str}.")


        # --- Get User Input (Main Thread via execute_sync) ---
        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None}
        input_container = [input_results]

        def get_inputs_main(container):
            try:
                c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
                if c_depth is None:
                    container[0]["caller_depth"] = -1
                    return 0 # Indicate cancellation
                container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
                if ca_depth is None:
                    container[0]["callee_depth"] = -1
                    return 0 # Indicate cancellation
                container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

                default_filename = f"{start_func_name}_dump_callers{c_depth}_callees{ca_depth}.c"
                default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename)
                output_file = ida_kernwin.ask_file(True, default_filename, "Select Output C File")
                if not output_file:
                    container[0]["output_file"] = None
                    return 0 # Indicate cancellation
                container[0]["output_file"] = output_file
                return 1 # Indicate success
            except Exception as e:
                print(f"  [get_inputs_main Ctx] Error getting input: {e}")
                traceback.print_exc()
                container[0]["caller_depth"] = -1
                container[0]["callee_depth"] = -1
                container[0]["output_file"] = None
                return -1 # Indicate error

        sync_status = ida_kernwin.execute_sync(
            lambda: get_inputs_main(input_container),
            ida_kernwin.MFF_WRITE
        )

        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]

        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path:
            print("CodeDumper: [activate Ctx] User cancelled input or input failed.")
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
                # print(f"CodeDumper: [activate Ctx] Concurrency flag released due to cancellation for {start_func_ea_str}.")
            return 1

        # --- Start Background Task ---
        print(f"CodeDumper: [activate Ctx] Starting background dump task for {start_func_ea_str}...")
        task_thread = threading.Thread(
            target=dump_code_task,
            args=(start_func_ea, caller_depth, callee_depth, output_file_path)
        )
        task_thread.start()
        # print(f"CodeDumper: [activate Ctx] Background thread started. Exiting activate.")

        return 1

    def update(self, ctx):
        """Enable the action only in the Pseudocode view with a valid cfunc."""
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class DumpMultiActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the multi-function dump action (if triggered programmatically)."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        # print("CodeDumper: [DumpMultiActionHandler.__init__] Handler created.")

    def activate(self, ctx):
        """Called when the action is triggered (e.g. via process_ui_action)."""
        print(f"CodeDumper: [DumpMultiActionHandler.activate] Action '{ACTION_ID_MULTI}' activated programmatically.")
        # We delegate the actual work to the plugin's run() method logic
        # This ensures the same input/concurrency checks happen.
        # We pass a dummy 'arg' to run() as it's not used there.
        plugin_instance = CodeDumperPlugin() # Create a temporary instance to call run_multi_dump_logic
        plugin_instance.run_multi_dump_logic()
        return 1 # Indicate action handled

    def update(self, ctx):
        """Always enable the action (it doesn't depend on context)."""
        return ida_kernwin.AST_ENABLE_ALWAYS


class DumpHooks(ida_kernwin.UI_Hooks):
    """Hooks into IDA's UI to add context menu items."""
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """Adds menu items to the widget's context menu."""
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            try:
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, ACTION_ID_CTX, MENU_PATH_CTX, ida_kernwin.SETMENU_INS
                )
            except Exception as e:
                print(f"CodeDumper Error: [Hooks] Exception attaching context action to popup: {e}")
                traceback.print_exc()


class CodeDumperPlugin(idaapi.plugin_t):
    """The main IDA Pro plugin class."""
    # Use PLUGIN_FIX to automatically add to Edit->Plugins menu
    # Remove PLUGIN_HIDE
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = "Dumps decompiled code for function(s) and their callers/callees/references"
    help = "Right-click in Pseudocode view for single func, or use Edit->Plugins menu for multi-func dump"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "" # Can assign a hotkey here like "Alt-Shift-D"
    hooks = None

    def init(self):
        """Called by IDA when loading the plugin."""
        print("-" * 60)
        print(f"CodeDumper: {self.wanted_name} plugin initializing...")

        # Check Hex-Rays
        if not ida_hexrays.init_hexrays_plugin():
            print("CodeDumper Error: [init] Hex-Rays decompiler is not available.")
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] Hex-Rays initialized.")

        # Register Context Action
        print(f"CodeDumper: [init] Registering context action '{ACTION_ID_CTX}'...")
        action_desc_ctx = ida_kernwin.action_desc_t(
            ACTION_ID_CTX, ACTION_LABEL_CTX, DumpCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_CTX, 199 # Icon ID
        )
        if not ida_kernwin.register_action(action_desc_ctx):
            print(f"CodeDumper Error: [init] Failed to register context action '{ACTION_ID_CTX}'.")
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] Context action registered successfully.")

        # Register Multi-Function Action (still useful for programmatic trigger)
        print(f"CodeDumper: [init] Registering multi-function action '{ACTION_ID_MULTI}'...")
        action_desc_multi = ida_kernwin.action_desc_t(
            ACTION_ID_MULTI,
            ACTION_LABEL_MULTI, # Use the simple label
            DumpMultiActionHandler(),
            None, # No separate hotkey/menu for this action itself
            ACTION_TOOLTIP_MULTI,
            199 # Icon ID
        )
        if not ida_kernwin.register_action(action_desc_multi):
            print(f"CodeDumper Error: [init] Failed to register multi-function action '{ACTION_ID_MULTI}'.")
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] Multi-function action registered successfully.")

        # --- Menu Attachment Removed ---
        # No longer needed, PLUGIN_FIX handles the main menu entry via run()

        # Install Hooks for Context Menu
        print("CodeDumper: [init] Installing UI hooks for context menu...")
        self.hooks = DumpHooks()
        if not self.hooks.hook():
            print("CodeDumper Error: [init] Failed to install UI hooks.")
            # Clean up registered actions
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            ida_kernwin.unregister_action(ACTION_ID_MULTI)
            self.hooks = None
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] UI hooks installed.")

        print(f"CodeDumper: {self.wanted_name} initialization complete.")
        print("-" * 60)
        return idaapi.PLUGIN_KEEP

    def run_multi_dump_logic(self):
        """Contains the logic previously in DumpMultiActionHandler.activate"""
        global g_dump_in_progress, g_multi_dump_active
        print("CodeDumper: [run_multi_dump_logic] Starting multi-dump process.")

        # --- Concurrency Check ---
        # print(f"CodeDumper: [run_multi_dump_logic] Acquiring lock...")
        with g_dump_lock:
            # print(f"CodeDumper: [run_multi_dump_logic] Lock acquired. Checking concurrency...")
            if g_multi_dump_active:
                print(f"CodeDumper: [run_multi_dump_logic] Multi-dump already active.")
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function dump is already running. Please wait.")
                return
            if g_dump_in_progress:
                print(f"CodeDumper: [run_multi_dump_logic] Single function dump(s) active: {g_dump_in_progress}. Blocking multi-dump.")
                ida_kernwin.warning(f"{PLUGIN_NAME}: One or more single function dumps are running. Please wait.")
                return
            g_multi_dump_active = True
            # print(f"CodeDumper: [run_multi_dump_logic] Marked multi-dump as active. Current single: {g_dump_in_progress}, Multi active: {g_multi_dump_active}")
        # print(f"CodeDumper: [run_multi_dump_logic] Lock released.")

        # --- Get User Input (Main Thread via execute_sync) ---
        input_results = {"start_eas": set(), "caller_depth": -1, "callee_depth": -1, "output_file": None}
        input_container = [input_results]

        def get_multi_inputs_main(container):
            try:
                # 1. Get function list
                func_list_str = ida_kernwin.ask_str("", 0, "Enter comma-separated function names or addresses (e.g., sub_123, 0x401000, MyFunc)")
                if not func_list_str:
                    return 0 # Cancelled

                # Resolve names/addresses
                start_eas = set()
                unresolved = []
                items = [item.strip() for item in func_list_str.split(',') if item.strip()]
                if not items:
                    ida_kernwin.warning(f"{PLUGIN_NAME}: No function names or addresses provided.")
                    return 0 # Cancelled (effectively)

                for item in items:
                    ea = idaapi.BADADDR
                    if item.lower().startswith("0x"):
                        try:
                            ea = int(item, 16)
                            if not ida_funcs.get_func(ea): ea = idaapi.BADADDR
                        except ValueError: ea = idaapi.BADADDR
                    elif item.isdigit():
                         try:
                            ea = int(item)
                            if not ida_funcs.get_func(ea): ea = idaapi.BADADDR
                         except ValueError: ea = idaapi.BADADDR

                    if ea == idaapi.BADADDR:
                        ea = ida_name.get_name_ea(idaapi.BADADDR, item)

                    if ea != idaapi.BADADDR and ida_funcs.get_func(ea):
                        start_eas.add(ea)
                    else:
                        unresolved.append(item)
                        print(f"  [get_multi_inputs_main] Warning: Could not resolve '{item}' to a function start address.")


                if unresolved:
                    ida_kernwin.warning(f"{PLUGIN_NAME}: Could not resolve or find functions for:\n" + "\n".join(unresolved))

                if not start_eas:
                    print("  [get_multi_inputs_main] No valid functions resolved from input.")
                    ida_kernwin.warning(f"{PLUGIN_NAME}: No valid functions found from the provided list.")
                    return 0 # Cancelled

                container[0]["start_eas"] = start_eas
                print(f"  [get_multi_inputs_main] Resolved {len(start_eas)} starting functions.")

                # 2. Get Depths
                c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
                if c_depth is None: return 0
                container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
                if ca_depth is None: return 0
                container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

                # 3. Get Output File
                first_func_ea = sorted(list(start_eas))[0]
                first_func_name = ida_funcs.get_func_name(first_func_ea) or f"sub_{first_func_ea:X}"
                default_filename = f"multi_dump_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.c"
                default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename) # Sanitize
                output_file = ida_kernwin.ask_file(True, default_filename, "Select Output C File")
                if not output_file: return 0
                container[0]["output_file"] = output_file
                return 1 # Success
            except Exception as e:
                print(f"  [get_multi_inputs_main] Error getting input: {e}")
                traceback.print_exc()
                return -1 # Error

        sync_status = ida_kernwin.execute_sync(
            lambda: get_multi_inputs_main(input_container),
            ida_kernwin.MFF_WRITE
        )

        final_inputs = input_container[0]
        start_eas = final_inputs["start_eas"]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]

        if sync_status != 1 or not start_eas or caller_depth < 0 or callee_depth < 0 or not output_file_path:
            print("CodeDumper: [run_multi_dump_logic] User cancelled input, input failed, or no valid functions.")
            with g_dump_lock:
                g_multi_dump_active = False
                # print(f"CodeDumper: [run_multi_dump_logic] Multi-dump concurrency flag released due to cancellation/error.")
            return # Exit the logic

        # --- Start Background Task ---
        print(f"CodeDumper: [run_multi_dump_logic] Starting background multi-dump task for {len(start_eas)} functions...")
        task_thread = threading.Thread(
            target=dump_multi_code_task,
            args=(start_eas, caller_depth, callee_depth, output_file_path)
        )
        task_thread.start()
        # print(f"CodeDumper: [run_multi_dump_logic] Background thread started.")


    def run(self, arg):
        """Called by IDA when running the plugin from the menu."""
        print(f"CodeDumper: {self.wanted_name} run() called (arg={arg}). Triggering multi-dump logic.")
        # Directly call the multi-dump logic here
        self.run_multi_dump_logic()


    def term(self):
        """Called by IDA when unloading the plugin."""
        print("-" * 60)
        print(f"CodeDumper: {self.wanted_name} plugin terminating...")

        # Unhook
        if self.hooks:
            print("CodeDumper: [term] Uninstalling UI hooks...")
            try:
                self.hooks.unhook()
                print("CodeDumper: [term] UI hooks uninstalled.")
            except Exception as e:
                print(f"CodeDumper Error: [term] Exception during unhooking: {e}")
            self.hooks = None

        # --- Menu Detachment Removed ---
        # No longer needed

        # Unregister Context Action
        print(f"CodeDumper: [term] Unregistering action '{ACTION_ID_CTX}'...")
        if not ida_kernwin.unregister_action(ACTION_ID_CTX):
            print(f"CodeDumper Warning: [term] Failed to unregister action '{ACTION_ID_CTX}'.")
        else:
            print("CodeDumper: [term] Context action unregistered.")

        # Unregister Multi Action
        print(f"CodeDumper: [term] Unregistering action '{ACTION_ID_MULTI}'...")
        if not ida_kernwin.unregister_action(ACTION_ID_MULTI):
            print(f"CodeDumper Warning: [term] Failed to unregister action '{ACTION_ID_MULTI}'.")
        else:
            print("CodeDumper: [term] Multi-function action unregistered.")


        # Clear concurrency state
        print("CodeDumper: [term] Clearing concurrency state...")
        with g_dump_lock:
            g_dump_in_progress.clear()
            global g_multi_dump_active
            g_multi_dump_active = False
        print("CodeDumper: [term] Concurrency state cleared.")

        print(f"CodeDumper: {self.wanted_name} termination complete.")
        print("-" * 60)


# --- Plugin Entry Point ---

def PLUGIN_ENTRY():
    """Required entry point for IDA Pro plugins."""
    # print("CodeDumper: PLUGIN_ENTRY() called.") # Less noisy
    return CodeDumperPlugin()

# --- End of Script ---
print("CodeDumper: Script loaded.")
