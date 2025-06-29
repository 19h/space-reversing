# -*- coding: utf-8 -*-
"""
Find functions that reference strings with a given substring.

Run this in the IDA Python console or save as a .py and `File → Script file...`.

The script will:
  • scan for all strings in the binary
  • filter for strings containing a given substring
  • find all functions that reference those strings
  • print a detailed report
"""

import re
import collections
import idaapi
import ida_funcs
import ida_xref
import ida_name
import idautils
import ida_kernwin

# ---------------------------------------------------------------------------
# 0.  Configurable constants
# ---------------------------------------------------------------------------
BAD           = idaapi.BADADDR

# Change this to the substring you want to search for
SEARCH_SUBSTRING = "RigidEntity"  # Modify this to your desired substring

# ---------------------------------------------------------------------------
# 1.  Find all strings containing the substring
# ---------------------------------------------------------------------------
matching_strings : list = []
for s in idautils.Strings():
    string_content = str(s)
    print(string_content)
    if SEARCH_SUBSTRING in string_content:
        matching_strings.append((string_content, s))

print(f"[String Finder] Found {len(matching_strings)} strings containing '{SEARCH_SUBSTRING}':")
for string_content, s in matching_strings:
    print(f"  String: {string_content} at 0x{s.ea:X}")

# ---------------------------------------------------------------------------
# 2.  Find all functions that reference these strings
# ---------------------------------------------------------------------------
functions_with_refs : dict[str, set[int]] = {}

for string_content, s in matching_strings:
    ref_funcs : set[int] = set()
    for fst, nxt in (
        (ida_xref.get_first_cref_to,  ida_xref.get_next_cref_to ),
        (ida_xref.get_first_dref_to,  ida_xref.get_next_dref_to ),
        (ida_xref.get_first_fcref_to, ida_xref.get_next_fcref_to),
    ):
        ref = fst(s.ea)
        while ref != BAD:
            f = ida_funcs.get_func(ref)
            if f:
                ref_funcs.add(f.start_ea)
            ref = nxt(s.ea, ref)

    if ref_funcs:
        functions_with_refs[string_content] = ref_funcs

# ---------------------------------------------------------------------------
# 3.  Print results
# ---------------------------------------------------------------------------
print(f"\n[String Finder] Functions referencing strings with '{SEARCH_SUBSTRING}':")
print("=" * 60)

total_functions = set()
for string_content, func_eas in functions_with_refs.items():
    print(f"\nString: {string_content}")
    for func_ea in func_eas:
        func_name = ida_funcs.get_func_name(func_ea)
        print(f"  Function: {func_name} at 0x{func_ea:X}")
        total_functions.add(func_ea)

print(f"\n=== Summary ===")
print(f"Total unique functions found: {len(total_functions)}")
print(f"Total strings matched: {len(functions_with_refs)}")

# ---------------------------------------------------------------------------
# 4.  Summary dialog
# ---------------------------------------------------------------------------
lines = [
    f"=== String Reference Finder ===",
    f"Search substring: '{SEARCH_SUBSTRING}'",
    f"Matching strings: {len(functions_with_refs)}",
    f"Total unique functions: {len(total_functions)}",
]

if functions_with_refs:
    lines.append("\nDetailed results:")
    for string_content, func_eas in functions_with_refs.items():
        lines.append(f"  {string_content}:")
        for func_ea in func_eas:
            func_name = ida_funcs.get_func_name(func_ea)
            lines.append(f"    {func_name} (0x{func_ea:X})")

ida_kernwin.info("\n".join(lines))
