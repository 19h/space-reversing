# -*- coding: utf-8 -*-
"""
Auto-rename functions from embedded C++ class strings.

Run this in the IDA Python console or save as a .py and `File → Script file...`.

All filtering rules are hard-wired (see header comments).  The script will:
  • scan for strings like  CSomeClass::SomeMethod
  • apply the exclusion rules
  • call ida_name.set_name() on the matching function(s)
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
CI_CAP_RE     = re.compile(r'^[CI][A-Z][A-Za-z0-9_]*::')
CPP_QUAL_RE   = re.compile(r'\b(?:[A-Z][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*\b')
BAD           = idaapi.BADADDR
SN_FLAGS      = ida_name.SN_CHECK | ida_name.SN_NOCHECK | ida_name.SN_FORCE   # conservative

# ---------------------------------------------------------------------------
# 1.  Collect all existing function names (raw + demangled) ------------------
# ---------------------------------------------------------------------------
func_names : set[str] = set()
for n in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(n)
    if not func:
        continue
    raw = ida_funcs.get_func_name(func.start_ea)
    if raw:
        func_names.add(raw)
        dem = ida_name.demangle_name(raw, 0)
        if dem:
            func_names.add(dem.split('(')[0].strip())

# ---------------------------------------------------------------------------
# 2.  PASS 1 – canonical string → occurrences -------------------------------
# ---------------------------------------------------------------------------
canon2strings : "dict[str, list]" = collections.defaultdict(list)
for s in idautils.Strings():
    for m in CPP_QUAL_RE.finditer(str(s)):
        canon2strings[m.group(0)].append(s)

# ---------------------------------------------------------------------------
# 3.  PASS 2 – canonical string → set(referring functions) ------------------
# ---------------------------------------------------------------------------
canon2funcs : dict[str, set[int]] = {}
for canon, instances in canon2strings.items():
    ref_funcs : set[int] = set()
    for s in instances:
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
    canon2funcs[canon] = ref_funcs

# ---------------------------------------------------------------------------
# 4.  PASS 3 – invert + apply rules 1-4 -------------------------------------
# ---------------------------------------------------------------------------
func2cands : "dict[int, list[str]]" = collections.defaultdict(list)
for canon, funcs in canon2funcs.items():
    if len(funcs) == 1:                      # Rule 1
        func2cands[next(iter(funcs))].append(canon)

final_pairs : list[tuple[str,int]] = []      # (canon, func_ea)

for f_ea, cands in func2cands.items():
    # Rule 2
    chosen : str | None
    if len(cands) == 1:
        chosen = cands[0]
    else:
        ci_match = [c for c in cands if CI_CAP_RE.match(c)]
        if len(ci_match) == 1:
            chosen = ci_match[0]
        else:
            continue                         # disqualify the function
    # Rule 4
    if chosen in func_names:
        continue
    # Double-check the new name is not already present elsewhere (defensive)
    if ida_name.get_name_ea(BAD, chosen) != BAD:
        continue
    final_pairs.append((chosen, f_ea))

# ---------------------------------------------------------------------------
# 5.  Perform renames --------------------------------------------------------
# ---------------------------------------------------------------------------
renamed_cnt        = 0
failed_invalid     = []
failed_collision   = []

print(f"[AutoRenamer] Attempting {len(final_pairs)} rename(s)…")

for new_name, f_ea in final_pairs:
    ok = ida_name.set_name(f_ea, new_name, SN_FLAGS)
    if ok:
        renamed_cnt += 1
        print(f"  + 0x{f_ea:X} → {new_name}")
    else:
        # determine why
        if ida_name.get_name_ea(BAD, new_name) != BAD:
            failed_collision.append((f_ea, new_name))
            print(f"  - COLLISION: {new_name} already exists")
        else:
            failed_invalid.append((f_ea, new_name))
            print(f"  - INVALID:   {new_name}")

# ---------------------------------------------------------------------------
# 6.  Summary dialog ---------------------------------------------------------
# ---------------------------------------------------------------------------
lines = [
    "=== Auto-rename summary ===",
    f"Proposed renames : {len(final_pairs)}",
    f"Successfully done: {renamed_cnt}",
]
if failed_collision:
    lines.append(f"\nName collisions ({len(failed_collision)}):")
    lines.extend(f"  0x{ea:X} → {nm}" for ea, nm in failed_collision)
if failed_invalid:
    lines.append(f"\nInvalid names ({len(failed_invalid)}):")
    lines.extend(f"  0x{ea:X} → {nm}" for ea, nm in failed_invalid)

ida_kernwin.info("\n".join(lines))
