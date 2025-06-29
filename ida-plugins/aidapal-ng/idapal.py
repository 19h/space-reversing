# -*- coding: utf-8 -*-
"""
summary: IDA Pro plugin using Google AI (Gemini) for code analysis assistance.

description:
  This plugin integrates with Google's Generative AI API (Gemini) via the google-genai SDK
  to provide suggestions for function names, comments, and local
  variable renames within IDA Pro's decompiled pseudocode view.

  It adds:
  1. Context menu items ("aiDAPal Analysis/...") to the Pseudocode view to trigger
     analysis for the CURRENT function and its context (callers/callees/references
     up to user-specified depths). Options include analyzing ALL functions in the
     context, ONLY the current function, or the current function PLUS callers/callees
     up to a specified ANALYSIS depth, while still using a potentially larger CONTEXT depth.
  2. A main menu item ("Edit -> Plugins -> aiDAPal (Google AI - Context Analysis)")
     to trigger analysis for a user-specified LIST of functions and their combined
     context (callers/callees/references up to user-specified depths).

  The results are presented in a custom PyQt5 dockable widget with tabs
  for each analyzed function, where the user can review and selectively
  apply the suggestions across multiple functions.

  Includes logic based on 'codedump' plugin to thoroughly find called functions,
  calling functions, referenced functions (via data refs, immediates, push/ret),
  and their respective callers/callees up to specified depths.
  Decompilation and other IDA API calls are performed synchronously in the main IDA thread.

  Requires:
  - IDA Pro 7.6+ (with Python 3 and PyQt5 support)
  - Hex-Rays Decompiler
  - google-genai library (`pip install google-genai`)
  - pydantic library (`pip install pydantic`)
  - A Google AI API Key set in the environment variable `GOOGLE_API_KEY`.

INTEGRATED VERSION: Includes codedump's context finding, multi-function menu trigger,
                    and depth-limited analysis option.
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
import ida_xref
import ida_typeinf
import ida_nalt
import ida_ua
import ida_idp
import ida_search

import threading
import json
import textwrap
import os
import sys
import traceback
import time
import re # For parsing addresses
import queue # Used in find_functions_within_depth

from collections import Counter, deque # Used in find_functions_within_depth
from functools import partial
from typing import Dict, List, Set, cast, Optional, Tuple

# Third-party libraries
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QScrollArea,
                                 QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                                 QGroupBox, QCheckBox, QPushButton, QFrame,
                                 QTabWidget)
    print("aiDAPal DEBUG: PyQt5 imported successfully.")
except ImportError:
    print("aiDAPal Error: PyQt5 not found. Please ensure it's installed in IDA's Python environment.")
    # Optionally, prevent the plugin from loading if PyQt5 is missing
    # raise ImportError("PyQt5 is required for the aiDAPal UI.")

try:
    from pydantic import BaseModel, Field
    print("aiDAPal DEBUG: pydantic imported successfully.")
except ImportError:
    print("aiDAPal Error: pydantic not found. Please install it: pip install pydantic")
    # raise ImportError("pydantic is required for aiDAPal.")

try:
    from google import genai
    from google.genai import types
    from google.genai import errors as google_genai_errors
    print("aiDAPal DEBUG: google-genai imported successfully.")
except ImportError:
    print("aiDAPal Error: google-genai not found. Please install it: pip install google-genai")
    # raise ImportError("google-genai is required for aiDAPal.")


# --- Configuration ---
PLUGIN_NAME = "aiDAPal (Google AI - Context Analysis)"
# Context Menu Action Prefixes
ACTION_ID_CTX_PREFIX_MULTI = "aidapal:googleai:ctx:multi:" # Analyze ALL in context
ACTION_ID_CTX_PREFIX_SINGLE = "aidapal:googleai:ctx:single:" # Analyze CURRENT only
ACTION_ID_CTX_PREFIX_DEPTH = "aidapal:googleai:ctx:depth:" # Analyze CURRENT + N levels
MENU_PATH_CTX = "aiDAPal Analysis/" # Submenu path for context menu

# Google AI Configuration
# Read API Key from environment variable for security
# GOOGLE_AI_API_KEY = os.environ.get("GOOGLE_API_KEY") # NEW: Use GOOGLE_API_KEY for google-genai
GOOGLE_AI_API_KEY = "wholetthedogsout" # Replace with your actual key or use env var
# Default model to use if multiple are available or for the primary action
# See https://ai.google.dev/models/gemini for available models (check compatibility with google-genai)
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-preview-05-20"

# List of Google AI models to offer as actions in the context menu.
# You can add more models here if desired, e.g., "gemini-1.5-pro-latest"
# Each model name will create a separate context menu entry.
# Ensure the models listed are compatible with the API usage below.
MODELS_TO_REGISTER = [DEFAULT_GEMINI_MODEL] # Keep it simple for debugging

# Safety settings for Google AI (adjust thresholds as needed)
# Convert to google.genai.types.SafetySetting format
try:
    DEFAULT_SAFETY_SETTINGS = [
        types.SafetySetting(category='HARM_CATEGORY_HATE_SPEECH', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_DANGEROUS_CONTENT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_HARASSMENT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold='BLOCK_NONE'),
        types.SafetySetting(category='HARM_CATEGORY_CIVIC_INTEGRITY', threshold='BLOCK_NONE'),
    ]
    print("aiDAPal DEBUG: Default safety settings converted to google.genai.types format.")
except NameError:
    print("aiDAPal Warning: google.genai.types not fully imported. Safety settings might not work correctly.")
    DEFAULT_SAFETY_SETTINGS = [] # Fallback to empty list
except AttributeError:
    print("aiDAPal Warning: google.genai.types.SafetySetting not found. Safety settings might not work correctly.")
    DEFAULT_SAFETY_SETTINGS = [] # Fallback

# Default depths for context gathering (can be overridden by user prompts)
DEFAULT_CONTEXT_CALLER_DEPTH = 1
DEFAULT_CONTEXT_CALLEE_DEPTH = 1
DEFAULT_ANALYSIS_DEPTH = 1 # Default for the new depth-limited mode

# --- Concurrency Control (Adopted from codedump) ---
g_analysis_in_progress = set() # Set of primary func_ea for single-context analysis runs
g_multi_analysis_active = False # Flag for multi-function analysis run
g_analysis_lock = threading.Lock() # To protect both flags/set
print("aiDAPal DEBUG: Concurrency control variables initialized (single set, multi flag).")


# -----------------------------------------------------------------------------
# 1.  DATA MODELS – kept but made internally consistent
# -----------------------------------------------------------------------------
from pydantic import BaseModel, Field

_BAD_NAME_RE = re.compile(r"\b(var\d+|v\d+|tmp|foo|bar|helper|unused)\b", re.I)
_BAD_TYPE_RE = re.compile(r"__?int(8|16|32|64)")


def _lint_name(name: str) -> bool:
    """Return *True* if the name is acceptable."""
    return _BAD_NAME_RE.search(name) is None


class VariableRename(BaseModel):
    original_name: str = Field(..., description="The original variable/argument name as seen in pseudocode.")
    new_name: str = Field(..., description="The suggested descriptive name.")
    rename_reason: str = Field(..., description="Why this rename clarifies semantics.")
    rename_reason_findings: str = Field(..., description="Evidence or observations that justify the rename.")


class SingleFunctionAnalysis(BaseModel):
    original_function_name: str = Field(..., description="Exactly as in the '// === Function:' header.")
    function_name: str = Field(..., description="IDA‑style concise descriptive name.")
    comment: str = Field(..., description="Multi‑line C‑style block comment (without /* */).")
    variables: List[VariableRename] = Field(..., description="Suggested variable/argument renames for this function.")
    observations: List[dict] = Field(..., description="Notable observations influencing interpretation.")
    function_name_reason: str = Field(..., description="Rationale for the chosen function name.")
    function_name_reason_findings: str = Field(..., description="Evidence backing the chosen function name.")
    comment_reason: str = Field(..., description="Rationale for the comment block.")
    comment_reason_findings: str = Field(..., description="Evidence backing the comment block.")


class MultiFunctionAnalysisResult(BaseModel):
    function_analyses: List[SingleFunctionAnalysis]


# -----------------------------------------------------------------------------
# 2.  JSON SCHEMA – wording & ordering made self‑consistent, no contradictory
#     "Reason must precede …" text inside field descriptions.
# -----------------------------------------------------------------------------

explicit_multi_function_analysis_schema: Dict = {
    "type": "object",
    "properties": {
        "function_analyses": {
            "type": "array",
            "description": "Per‑function analysis results.",
            "items": {
                "type": "object",
                "properties": {
                    "original_function_name": {
                        "type": "string",
                        "description": "Function name as in the header (e.g., 'sub_140001000').",
                    },
                    "observations": {
                        "type": "array",
                        "description": "Important observations about this function.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "observation": {"type": "string"},
                                "observation_impact": {"type": "string"},
                            },
                            "required": ["observation", "observation_impact"],
                            "propertyOrdering": ["observation", "observation_impact"],
                        },
                    },
                    "function_name_reason": {"type": "string"},
                    "function_name_reason_findings": {"type": "string"},
                    "function_name": {
                        "type": "string",
                        "description": "Suggested function name (IDA‑safe).",
                    },
                    "comment_reason": {"type": "string"},
                    "comment_reason_findings": {"type": "string"},
                    "comment": {
                        "type": "string",
                        "description": "C‑style comment (plain text).",
                    },
                    "variables": {
                        "type": "array",
                        "description": "Renames for local variables & args.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rename_reason": {"type": "string"},
                                "rename_reason_findings": {"type": "string"},
                                "original_name": {"type": "string"},
                                "new_name": {"type": "string"},
                            },
                            "required": [
                                "rename_reason",
                                "rename_reason_findings",
                                "original_name",
                                "new_name",
                            ],
                            "propertyOrdering": [
                                "rename_reason",
                                "rename_reason_findings",
                                "original_name",
                                "new_name",
                            ],
                        },
                    },
                },
                "required": [
                    "original_function_name",
                    "observations",
                    "function_name_reason",
                    "function_name_reason_findings",
                    "function_name",
                    "comment_reason",
                    "comment_reason_findings",
                    "comment",
                    "variables",
                ],
                "propertyOrdering": [
                    "original_function_name",
                    "observations",
                    "function_name_reason",
                    "function_name_reason_findings",
                    "function_name",
                    "comment_reason",
                    "comment_reason_findings",
                    "comment",
                    "variables",
                ],
            },
        }
    },
    "required": ["function_analyses"],
}

# -----------------------------------------------------------------------------
# 3.  Helper utilities: prototype extraction, literal harvesting, call‑graph
#    lines, and name‑quality linter.
# -----------------------------------------------------------------------------

def get_function_prototype(ea: int) -> str | None:
    """Return a textual prototype for *ea* that works across IDA versions.

    Strategy (in order):
      1.   `idc.get_type()`                – works in all 7.x builds.
      2.   legacy `idc.GetType()`          – IDA < 7.0 compatibility.
      3.   `ida_typeinf.guess_tinfo()`     – generate a tinfo_t and stringify.

    The function deliberately avoids `ida_typeinf.get_tinfo()` and
    `ida_typeinf.print_tinfo()` because their signatures vary wildly across
    minor releases and lead to brittle code.
    """
    # --- 1. idc.get_type (IDA 7.x) -----------------------------------------
    proto: str | None = None
    if hasattr(idc, "get_type"):
        try:
            proto = idc.get_type(ea)
            if proto:
                return proto
        except Exception:
            pass

    # --- 2. legacy GetType (IDA 6.x fallback) ------------------------------
    if hasattr(idc, "GetType"):
        try:
            proto = idc.GetType(ea)  # type: ignore[attr-defined]
            if proto:
                return proto
        except Exception:
            pass

    # --- 3. guess_tinfo + stringification ----------------------------------
    if hasattr(ida_typeinf, "guess_tinfo"):
        tif = ida_typeinf.tinfo_t()
        try:
            if ida_typeinf.guess_tinfo(tif, ea):
                # tinfo_t has `__str__` in 7.6+, else use `dstr()`.
                if hasattr(tif, "__str__"):
                    proto = str(tif)
                elif hasattr(tif, "dstr"):
                    proto = tif.dstr()  # type: ignore[attr-defined]
                if proto:
                    return proto
        except Exception:
            pass

    return None

# ---------------------------------------------------------------------
# Helper: thread‑safe literal & constant harvesting
# ---------------------------------------------------------------------
def _gather_literals_main(ea: int, out: list[list[str] | None]) -> int:  # noqa: D401
    """
    Collect string literals and large numeric constants referenced by *ea*.
    Runs in the GUI thread (execute_sync).

    Returns 1 for execute_sync‑success; literals are written to out[0].
    """
    func = ida_funcs.get_func(ea)
    if not func:
        out[0] = []
        return 1

    literals: list[str] = []

    # ---------- Strings ------------------------------------------------
    it = func.start_ea
    while it < func.end_ea:
        flags = ida_bytes.get_full_flags(it)
        if ida_bytes.is_strlit(flags):
            s = ida_bytes.get_strlit_contents(it, -1, ida_nalt.get_str_type(it))
            if s:
                head = (
                    s[:40].decode("utf‑8", "ignore")
                    if isinstance(s, (bytes, bytearray))
                    else str(s)[:40]
                )
                literals.append(f'string:"{head}"')
        it = ida_bytes.next_head(it, func.end_ea)

    # ---------- Big numeric constants (> 0xFFFF) -----------------------
    insn = ida_ua.insn_t()
    it = func.start_ea
    while it < func.end_ea:
        ilen = ida_ua.decode_insn(insn, it)
        if ilen == 0:
            it = idc.next_head(it, func.end_ea)
            continue
        for op in insn.ops:
            if op.type == idaapi.o_imm and op.value > 0xFFFF:
                literals.append(f"const:0x{op.value:X}")
        it += ilen

    out[0] = literals
    return 1


def gather_literals(ea: int) -> list[str]:
    """
    Thread‑safe wrapper.  Returns a list like
        ['string:"TLS handshake failed"', 'const:0xDEADBEEF', …]

    Can be called from background threads; automatically hops to the
    main GUI thread to satisfy IDA SDK restrictions.
    """
    holder: list[list[str] | None] = [None]
    ida_kernwin.execute_sync(
        lambda: _gather_literals_main(ea, holder),
        ida_kernwin.MFF_READ,
    )
    return holder[0] or []

def _gather_callgraph_edges_main(ea: int, out: list[str | None]) -> int:  # noqa: D401
    """
    Collect direct callees for *ea*.
    This helper runs **inside** execute_sync on the main thread.
    Return code 1 -> success, 0 -> failure (execute_sync convention).
    """
    func = ida_funcs.get_func(ea)
    if not func:
        out[0] = f"(unknown 0x{ea:X}) -> (none)"
        return 1

    callees: set[str] = set()
    insn = ida_ua.insn_t()
    it = func.start_ea

    while it < func.end_ea and it != idaapi.BADADDR:
        ilen = ida_ua.decode_insn(insn, it)
        if ilen == 0:                       # undecodable byte → skip
            it = idc.next_head(it, func.end_ea)
            continue

        cref = ida_xref.get_first_cref_from(it)
        while cref != idaapi.BADADDR:
            ref_f = ida_funcs.get_func(cref)
            if ref_f and ref_f.start_ea == cref:
                callees.add(ida_funcs.get_func_name(cref))
            cref = ida_xref.get_next_cref_from(it, cref)

        it += ilen

    lhs = ida_funcs.get_func_name(ea)
    rhs = ", ".join(sorted(callees)) if callees else "(none)"
    out[0] = f"{lhs} -> {rhs}"
    return 1


def gather_callgraph_edges(ea: int) -> str:
    """
    Thread‑safe wrapper: returns `"func -> callee1, callee2"` for *ea*.

    Can be called from any worker thread; automatically hops to the
    main GUI thread to comply with IDA SDK restrictions.
    """
    holder: list[str | None] = [None]
    ida_kernwin.execute_sync(
        lambda: _gather_callgraph_edges_main(ea, holder),
        ida_kernwin.MFF_READ,
    )
    # Fallback unlikely but keeps the type stable
    return holder[0] or f"(unknown 0x{ea:X}) -> (none)"

# -----------------------------------------------------------------------------
# 4.  Main async_call – fully lint‑clean
# -----------------------------------------------------------------------------
def async_call(
    start_eas: Set[int],
    context_caller_depth: int,
    context_callee_depth: int,
    model_name: str,
    analysis_mode: str, # 'all', 'current', 'depth_limited'
    analysis_depth: int = 0, # Only used if analysis_mode == 'depth_limited'
    extra_context: str | None = None,
):
    """
    Background‑thread entry point.

    • Collect an extended decompilation context (callers + callees).
    • Determine which functions within the context should be targeted for analysis.
    • Build a semantic‑rich prompt that enforces naming quality and specifies analysis scope.
    • Query the LLM and receive JSON analysis.
    • Lint identifiers, map results back to EAs, and update the UI.

    Parameters
    ----------
    start_eas
        Set of starting function entry addresses (EAs).
    context_caller_depth
        How many levels of *callers* to include for context.
    context_callee_depth
        How many levels of *callees / refs* to include for context.
    model_name
        Identifier of the LLM back‑end (e.g. “gemini‑pro”).
    analysis_mode
        Specifies which functions to analyze:
        'all': Analyze all functions found within the context depths.
        'current': Analyze only the functions in `start_eas`.
        'depth_limited': Analyze functions in `start_eas` plus callers/callees
                         within `analysis_depth`.
    analysis_depth
        If `analysis_mode` is 'depth_limited', specifies the depth for analysis targets.
    extra_context
        Optional extra text (e.g. data‑reference dump) injected into the prompt.
    """

    # ------------------------------------------------------------------
    # Sanity check
    # ------------------------------------------------------------------
    if not start_eas:
        print("aiDAPal Error: [async_call] No starting EAs provided.")
        return

    primary_ea = min(start_eas) # Used for UI tracking, even in multi-start scenarios

    # ------------------------------------------------------------------
    # Phase 1 – Extended decompilation (callers & callees for CONTEXT)
    # ------------------------------------------------------------------
    print(f"aiDAPal DEBUG: [async_call] Phase 1: Collecting context (Callers: {context_caller_depth}, Callees: {context_callee_depth})")
    ctx_container: list[Dict[int, str] | None] = [None]

    def _collect_ctx(holder: list[Dict[int, str] | None]) -> int:
        """Runs on GUI thread, fills holder[0] or leaves it None on failure."""
        holder[0] = get_extended_function_context(
            start_eas, context_caller_depth, context_callee_depth
        )
        return 1  # execute_sync success flag

    status = ida_kernwin.execute_sync(
        lambda: _collect_ctx(ctx_container), ida_kernwin.MFF_READ
    )

    if status != 1 or ctx_container[0] is None:
        print("aiDAPal Error: failed to build extended context.")
        return  # Abort early—prevents TypeError down‑stream

    all_codes: Dict[int, str] = ctx_container[0]
    if not all_codes:
        print("aiDAPal Warning: [async_call] Context collection returned no functions. Aborting.")
        return

    print(f"aiDAPal DEBUG: [async_call] Phase 1: Collected context for {len(all_codes)} functions.")

    # ------------------------------------------------------------------
    # Phase 2 – Map EA → original names (for all functions in context)
    # ------------------------------------------------------------------
    print("aiDAPal DEBUG: [async_call] Phase 2: Mapping EAs to names...")
    name_map_container: list[Dict[int, str]] = [{}]

    def _map_names(out):
        out[0] = {
            ea: ida_funcs.get_func_name(ea) or f"sub_{ea:X}" for ea in all_codes
        }
        return 1

    ida_kernwin.execute_sync(
        lambda: _map_names(name_map_container), ida_kernwin.MFF_READ
    )
    ea_to_name: Dict[int, str] = name_map_container[0]
    print(f"aiDAPal DEBUG: [async_call] Phase 2: Mapped {len(ea_to_name)} names.")

    # ------------------------------------------------------------------
    # Phase 3 - Determine Target EAs for Analysis based on mode
    # ------------------------------------------------------------------
    print(f"aiDAPal DEBUG: [async_call] Phase 3: Determining target EAs for analysis (Mode: {analysis_mode}, Depth: {analysis_depth})")
    target_analysis_eas: Set[int] = set()

    if analysis_mode == 'current':
        target_analysis_eas = start_eas.intersection(all_codes.keys()) # Ensure targets are actually in the collected context
        print(f"  Mode 'current': Target EAs = {len(target_analysis_eas)}")
    elif analysis_mode == 'all':
        target_analysis_eas = set(all_codes.keys())
        print(f"  Mode 'all': Target EAs = {len(target_analysis_eas)}")
    elif analysis_mode == 'depth_limited':
        if analysis_depth >= 0:
            target_container: list[Set[int] | None] = [None]
            def _find_targets_main(container):
                container[0] = find_functions_within_depth(start_eas, analysis_depth)
                return 1
            sync_status = ida_kernwin.execute_sync(lambda: _find_targets_main(target_container), ida_kernwin.MFF_READ)
            if sync_status == 1 and target_container[0] is not None:
                # Intersect with functions actually found in context to avoid issues
                target_analysis_eas = target_container[0].intersection(all_codes.keys())
                print(f"  Mode 'depth_limited': Found {len(target_container[0])} within depth {analysis_depth}, intersecting with context -> {len(target_analysis_eas)} target EAs.")
            else:
                print(f"  Mode 'depth_limited': Failed to find functions within depth {analysis_depth}. Defaulting to start_eas.")
                target_analysis_eas = start_eas.intersection(all_codes.keys())
        else:
            print(f"  Mode 'depth_limited': Invalid analysis_depth ({analysis_depth}). Defaulting to start_eas.")
            target_analysis_eas = start_eas.intersection(all_codes.keys())
    else:
        print(f"  Unknown analysis_mode '{analysis_mode}'. Defaulting to start_eas.")
        target_analysis_eas = start_eas.intersection(all_codes.keys())

    if not target_analysis_eas:
        print("aiDAPal Error: [async_call] No target functions identified for analysis after filtering. Aborting.")
        return

    print(f"aiDAPal DEBUG: [async_call] Phase 3: Final target EAs for analysis: {len(target_analysis_eas)}")

    # ------------------------------------------------------------------
    # Phase 4 – Build semantic‑rich prompt
    # ------------------------------------------------------------------
    print("aiDAPal DEBUG: [async_call] Phase 4: Building prompt...")
    code_blocks: List[str] = []
    call_edges: List[str] = []

    # Include code for ALL functions in the context
    for ea in sorted(all_codes):
        header = f"// === Function: {ea_to_name[ea]} (0x{ea:X}) ==="
        prototype = get_function_prototype(ea)
        proto_hdr = f"// prototype: {prototype}" if prototype else ""

        # Strip Hex‑Rays’ auto‑header if present
        body = (
            all_codes[ea].split("\n", 1)[1]
            if all_codes[ea].startswith("//")
            else all_codes[ea]
        )
        code_blocks.append("\n".join(filter(None, [header, proto_hdr, body])))
        call_edges.append(gather_callgraph_edges(ea)) # Gather edges for all context functions

    # Literal / constant tags only for the primary functions that triggered the analysis
    semantic_tags: List[str] = []
    for ea in start_eas:
        if ea in ea_to_name: # Ensure the start_ea is valid and has a name
            tags = gather_literals(ea)
            if tags:
                semantic_tags.append(
                    f"{ea_to_name[ea]} tags: " + ", ".join(tags)
                )

    # ---------------- Prompt sections ---------------------------------
    persona_block = textwrap.dedent(
        f"""
        You are an expert reverse engineer analysing decompiled C‑like pseudocode from IDA Pro.
        The context includes primary functions plus callers (up to depth {context_caller_depth})
        and callees/refs (up to depth {context_callee_depth}). Typical decompilation artefacts
        are present.
        """
    )

    naming_contract = textwrap.dedent(
        """
        ### NAMING CONTRACT
        - Encode role **and** data domain (e.g., `crc32_checksum`).
        - Share stems across producer/consumer pairs.
        - Placeholders like `tmp`, `v5` are forbidden.
        - Once a name appears, reuse it verbatim unless stronger evidence applies.
        """
    )

    analysis_items = textwrap.dedent(
        """
        For each function you are asked to analyze, provide:
        - Function Purpose
        - Key Logic / Algorithm
        - Parameters
        - Return Value
        - Suggested Function Name (with reasoning)
        - Suggested Comment (with reasoning)
        - Variable Renames (with reasoning)
        - Observations (with impact)
        """
    )

    tools_instr = (
        "Respond with pure JSON adhering to the supplied schema via the "
        "`analyze_functions` tool. Field `original_function_name` must match the "
        "header exactly. Only include analysis results for the functions specified "
        "in the analysis scope instruction below. Never return an empty `function_analyses` list "
        "if analysis was requested for at least one function."
    )

    # --- Generate Scope Instruction based on analysis_mode and target_analysis_eas ---
    target_func_names = sorted([ea_to_name[ea] for ea in target_analysis_eas if ea in ea_to_name])
    if analysis_mode == 'all':
        scope_instr = "Analyze EVERY function provided in the code context."
    elif analysis_mode == 'current' or analysis_mode == 'depth_limited':
        if target_func_names:
            scope_instr = (
                f"Analyze ONLY the following function(s): "
                f"{', '.join(target_func_names)}. "
                "Use the other functions in the code context for background information only."
            )
        else:
            # Should not happen due to earlier checks, but as a fallback:
            scope_instr = "ERROR: No target functions identified. Please analyze the primary function(s) if possible."
            print("aiDAPal WARNING: [async_call] No target function names found for scope instruction!")
    else: # Fallback
        scope_instr = "Analyze the primary function(s) that initiated this request."

    self_review = textwrap.dedent(
        """
        ### SELF‑REVIEW (mandatory, ≤ 120 words)
        After the JSON, list any generic identifiers you left *within the analyzed functions* and explain why.
        """
    )

    prompt_content = "\n\n".join(
        [
            persona_block,
            naming_contract,
            analysis_items,
            tools_instr,
            scope_instr, # Use the dynamically generated scope instruction
            "### CALLGRAPH\n" + "\n".join(call_edges),
            "### SEMANTICS (Primary Functions)\n"
            + ("\n".join(semantic_tags) if semantic_tags else "(none)"),
            "### START CODE CONTEXT\n"
            + "\n\n/* --- */\n\n".join(code_blocks)
            + "\n### END CODE CONTEXT",
            self_review,
        ]
    )
    print("aiDAPal DEBUG: [async_call] Phase 4: Prompt built.")
    # print(f"aiDAPal DEBUG: Prompt Preview:\n{prompt_content[:500]}...") # Optional: Log prompt start

    # ------------------------------------------------------------------
    # Phase 5 – Query the LLM (cancellable, non‑blocking)
    # ------------------------------------------------------------------
    print("aiDAPal DEBUG: [async_call] Phase 5: Querying LLM...")
    wait_msg = "HIDECANCEL\nQuerying LLM…"
    ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box(wait_msg)])

    # ---- Inner worker -------------------------------------------------
    result_holder: list[List[dict] | None] = [None]   # slot 0 will store the list
    exc_holder: list[Exception | None] = [None]
    cancel_event = threading.Event()                  # notify‑worker flag

    def _llm_worker():
        try:
            # You can pass `cancel_event` into the function if it supports it.
            # Otherwise just ignore; outer thread will drop the result if cancelled.
            result_holder[0] = do_google_ai_analysis(prompt_content, model_name)
        except Exception as e:
            exc_holder[0] = e

    t = threading.Thread(target=_llm_worker, name="aiDAPal-LLM")
    t.start()

    # ---- Poll loop ----------------------------------------------------
    try:
        while t.is_alive():
            if ida_kernwin.user_cancelled():
                print("aiDAPal: analysis cancelled by user.")
                cancel_event.set()      # polite ask; may be ignored
                break

            #   ► keep the GUI responsive without touching UI‑only APIs
            ida_kernwin.execute_ui_requests([lambda: None])   # safe from any thread
            time.sleep(0.1)

        t.join()  # ensure worker finished (or soon will)
    finally:
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

    # ---- Handle outcomes ----------------------------------------------
    if ida_kernwin.user_cancelled():
        print("aiDAPal DEBUG: [async_call] User cancelled LLM query.")
        return  # user aborted; nothing more to do

    if exc_holder[0]:
        print(f"aiDAPal Error: [async_call] LLM call failed: {exc_holder[0]}")
        return

    results: List[dict] | None = result_holder[0]
    if not results:
        print("aiDAPal: no analysis returned from LLM.")
        return

    print(f"aiDAPal DEBUG: [async_call] Phase 5: Received {len(results)} analysis results from LLM.")

    # ------------------------------------------------------------------
    # Phase 6 – Map analysis back to EAs + lint names
    # ------------------------------------------------------------------
    print("aiDAPal DEBUG: [async_call] Phase 6: Mapping results and linting...")
    # We already have ea_to_name from Phase 2
    name_to_ea: Dict[str, int] = {v: k for k, v in ea_to_name.items()}
    mapped: List[dict] = []
    skipped_unknown = 0
    skipped_lint_func = 0
    skipped_lint_var = 0

    for ana in results:
        oname = ana.get("original_function_name")
        if not oname or oname not in name_to_ea:
            print(f"aiDAPal Warning: unknown function '{oname}' in result – skipped")
            skipped_unknown += 1
            continue

        ea = name_to_ea[oname]
        ana["function_ea"] = ea

        # --- Check if this function was actually targeted for analysis ---
        # Although the prompt requested specific functions, the LLM might ignore it.
        # We only want to display/apply results for the functions we intended to analyze.
        if ea not in target_analysis_eas:
            print(f"aiDAPal DEBUG: Skipping result for '{oname}' (0x{ea:X}) as it was not targeted for analysis in mode '{analysis_mode}'.")
            continue

        # ---- Lint suggested names ------------------------------------
        suggested_fname = ana.get("function_name")
        if not suggested_fname or not _lint_name(suggested_fname):
            print(
                f"aiDAPal Warning: bad function name '{suggested_fname}' for {oname} – skipped function analysis"
            )
            skipped_lint_func += 1
            continue

        bad_var = next(
            (v for v in ana.get("variables", []) if not v.get("new_name") or not _lint_name(v["new_name"])),
            None,
        )
        if bad_var:
            print(
                f"aiDAPal Warning: bad variable name '{bad_var.get('new_name', 'N/A')}' in {oname} – skipped function analysis"
            )
            skipped_lint_var += 1
            continue

        mapped.append(ana)

    print(f"aiDAPal DEBUG: [async_call] Phase 6: Mapping/Linting complete. Valid results: {len(mapped)} (Skipped: {skipped_unknown} unknown, {skipped_lint_func} bad func name, {skipped_lint_var} bad var name)")

    # ------------------------------------------------------------------
    # Phase 7 – Update UI / commit names & comments
    # ------------------------------------------------------------------
    print("aiDAPal DEBUG: [async_call] Phase 7: Updating UI...")
    if mapped:
        # Use primary_ea (the initial trigger EA) for the UI form instance tracking
        ida_kernwin.execute_ui_requests(
            [partial(do_show_ui, mapped, primary_ea)]
        )
        print("aiDAPal DEBUG: [async_call] UI update request sent.")
    else:
        print("aiDAPal Warning: [async_call] No valid analyses remaining after filtering.")
        ida_kernwin.warning("aiDAPal: No valid analysis results were generated or passed filtering.")

    print("aiDAPal DEBUG: [async_call] Finished.")


# --- UI Widget Classes (Unchanged) ---
class FunctionNameWidget(QWidget):
    accepted = True
    def __init__(self, function_name):
        super(FunctionNameWidget, self).__init__()
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox("Suggested Function Name")
        group_layout = QHBoxLayout()
        group_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_layout.setSpacing(10)
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)
        self.name_label = QLabel(function_name)
        self.name_label.setWordWrap(True)
        group_layout.addWidget(self.checkbox)
        group_layout.addWidget(self.name_label)
        group_box.setLayout(group_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)
    def accepted_state_change(self, state): self.accepted = (state == QtCore.Qt.Checked)

class CommentWidget(QWidget):
    accepted = True
    def __init__(self, comment):
        super(CommentWidget, self).__init__()
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox("Suggested Comment")
        group_layout = QHBoxLayout()
        group_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        group_layout.setSpacing(10)
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)
        self.comment_area = QLabel(comment)
        self.comment_area.setWordWrap(True)
        self.comment_area.setMinimumWidth(400)
        self.comment_area.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        group_layout.addWidget(self.checkbox)
        group_layout.addWidget(self.comment_area)
        group_box.setLayout(group_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)
    def accepted_state_change(self, state): self.accepted = (state == QtCore.Qt.Checked)

class VariableWidget(QWidget):
    def __init__(self, variables):
        super(VariableWidget, self).__init__()
        main_layout = QVBoxLayout()
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        group_box = QGroupBox("Suggested Variable Renames")
        group_layout = QGridLayout()
        group_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        group_layout.setSpacing(10)
        group_layout.setColumnStretch(1, 1)
        group_layout.setColumnStretch(3, 1)
        self.checkboxes = []
        self.variable_data = variables
        columns = 2
        for i, var_data in enumerate(variables):
            row = i // columns
            col_base = (i % columns) * 4
            original_name = var_data.get('original_name', 'N/A')
            new_name = var_data.get('new_name', 'N/A')
            checkbox = QCheckBox()
            checkbox.setCheckState(QtCore.Qt.Checked)
            checkbox.stateChanged.connect(lambda state, index=i: self.accepted_state_change(state, index))
            self.checkboxes.append(checkbox)
            lbl_original = QLabel(original_name)
            lbl_arrow = QLabel("→")
            lbl_new = QLabel(new_name)
            lbl_original.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            lbl_new.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            group_layout.addWidget(checkbox, row, col_base + 0)
            group_layout.addWidget(lbl_original, row, col_base + 1)
            group_layout.addWidget(lbl_arrow, row, col_base + 2, alignment=QtCore.Qt.AlignCenter)
            group_layout.addWidget(lbl_new, row, col_base + 3)
        group_box.setLayout(group_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        scroll_area.setWidget(group_box)
        scroll_area.setMinimumHeight(100)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)
    def accepted_state_change(self, state, index): pass
    def get_selected_variables(self):
        selected = []
        for i, checkbox in enumerate(self.checkboxes):
            if checkbox.isChecked(): selected.append(self.variable_data[i])
        return selected

def _rename_lvar(
    func_ea: int,
    cfunc: "ida_hexrays.cfuncptr_t",
    lv: "ida_hexrays.lvar_t",
    new_name: str,
) -> bool:
    """
    Rename *lv* to *new_name* using whichever Hex‑Rays API is available.

    Returns True on success, False otherwise.
    """
    # 1. Newest API: cfunc.set_lvar_name(lvar_t, name, flags=0)
    if hasattr(cfunc, "set_lvar_name"):
        try:
            return cfunc.set_lvar_name(lv, new_name, 0)
        except Exception:
            pass

    # 2. Older API: cfunc.rename_lvar(lvar_t, name)
    if hasattr(cfunc, "rename_lvar"):
        try:
            return cfunc.rename_lvar(lv, new_name)
        except Exception:
            pass

    # 3. Legacy free function: rename_lvar(ea, old_name, new_name)
    try:
        return ida_hexrays.rename_lvar(func_ea, lv.name, new_name)
    except Exception:
        return False

# --- Main UI Form Class (Modified for Tabs, uses primary_func_ea for tracking) ---
class aiDAPalUIForm(ida_kernwin.PluginForm):
    """The main dockable widget form for displaying AI suggestions using tabs for multiple functions."""

    def __init__(self, analysis_results_list, primary_trigger_ea):
        super(aiDAPalUIForm, self).__init__()
        primary_trigger_ea_str = f"0x{primary_trigger_ea:X}" if primary_trigger_ea else "None"
        print(f"aiDAPal DEBUG: [aiDAPalUIForm.__init__] Initializing multi-function form for analysis triggered by {primary_trigger_ea_str}.")
        self.analysis_results = analysis_results_list if analysis_results_list else []
        # Use the *triggering* EA for tracking the form instance, even if multiple functions were analyzed
        self.primary_trigger_ea = primary_trigger_ea
        self.widgets_by_ea = {} # { func_ea: {'name':..., 'comment':..., 'vars':..., 'data':...}, ... }
        self.parent_widget = None
        print(f"aiDAPal DEBUG: [aiDAPalUIForm.__init__] Received {len(self.analysis_results)} function analysis results.")
        print(f"aiDAPal DEBUG: [aiDAPalUIForm.__init__] Initialization complete for {primary_trigger_ea_str}.")

    def OnCreate(self, form):
        print("aiDAPal DEBUG: [aiDAPalUIForm.OnCreate] Form creation started.")
        try:
            self.parent_widget = self.FormToPyQtWidget(form)
            print("aiDAPal DEBUG: [aiDAPalUIForm.OnCreate] Parent widget obtained.")
            self.PopulateForm()
            print("aiDAPal DEBUG: [aiDAPalUIForm.OnCreate] Form population finished.")
        except Exception as e:
            print(f"aiDAPal Error: [aiDAPalUIForm.OnCreate] Exception: {e}")
            traceback.print_exc()

    def PopulateForm(self):
        print("aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Starting form population with tabs.")
        if not self.parent_widget:
            print("aiDAPal Error: [aiDAPalUIForm.PopulateForm] Parent widget not available.")
            return

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        tab_widget = QTabWidget()
        self.widgets_by_ea = {}

        print(f"aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Processing {len(self.analysis_results)} results to create tabs.")
        if not self.analysis_results:
             main_layout.addWidget(QLabel("No analysis results received from AI or none passed filtering."))

        # Sort results (optional, e.g., by EA)
        sorted_results = sorted(self.analysis_results, key=lambda r: r.get('function_ea', 0))

        for result_data in sorted_results:
            func_ea = result_data.get('function_ea')
            if func_ea is None:
                print(f"aiDAPal Warning: [aiDAPalUIForm.PopulateForm] Skipping result item missing 'function_ea': {result_data.get('original_function_name', 'N/A')}")
                continue

            func_ea_str = f"0x{func_ea:X}"
            func_name_ida = None
            name_container = [None]
            def get_name_main(ea, container):
                try: container[0] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"; return 1
                except: container[0] = f"sub_{ea:X}"; return 0
            name_sync_status = ida_kernwin.execute_sync(lambda: get_name_main(func_ea, name_container), ida_kernwin.MFF_READ)
            func_name_ida = name_container[0] if name_sync_status == 1 else f"sub_{func_ea_str}"

            tab_title = f"{func_name_ida} ({func_ea_str})"
            # print(f"aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Creating tab for: {tab_title}") # Noisy

            tab_content_widget = QWidget()
            tab_layout = QVBoxLayout()
            tab_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

            func_name_sugg = result_data.get('function_name', 'N/A')
            name_widget = FunctionNameWidget(func_name_sugg)
            tab_layout.addWidget(name_widget)

            comment_sugg = result_data.get('comment', 'No comment suggested.')
            comment_widget = CommentWidget(comment_sugg)
            tab_layout.addWidget(comment_widget)

            variables_sugg = result_data.get('variables', [])
            variable_widget = None
            if variables_sugg:
                variable_widget = VariableWidget(variables_sugg)
                tab_layout.addWidget(variable_widget)
            else:
                tab_layout.addWidget(QLabel("No variable rename suggestions for this function."))

            tab_layout.addStretch(1)
            tab_content_widget.setLayout(tab_layout)
            tab_widget.addTab(tab_content_widget, tab_title)

            self.widgets_by_ea[func_ea] = {
                'name': name_widget, 'comment': comment_widget, 'vars': variable_widget, 'data': result_data
            }
            # print(f"  aiDAPal DEBUG: [PopulateForm] Widgets stored for {func_ea_str}") # Noisy

        main_layout.addWidget(tab_widget)

        print("aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Creating buttons.")
        accept_button = QPushButton("Apply Selected")
        cancel_button = QPushButton("Close")
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        print("aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Connecting button signals.")
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button.clicked.connect(self.on_cancel_clicked)

        self.parent_widget.setLayout(main_layout)
        self.parent_widget.setMinimumSize(600, 500)
        print("aiDAPal DEBUG: [aiDAPalUIForm.PopulateForm] Layout set, minimum size set. Population complete.")

    def on_accept_clicked(self):
        print("aiDAPal DEBUG: [aiDAPalUIForm.on_accept_clicked] 'Apply Selected' clicked.")
        changes_by_ea = {}
        print(f"aiDAPal DEBUG: [on_accept_clicked] Gathering selections from {len(self.widgets_by_ea)} functions...")
        for func_ea, widgets in self.widgets_by_ea.items():
            selected_changes = {}
            original_data = widgets['data']
            selected_changes['function_name'] = original_data.get('function_name') if widgets['name'] and widgets['name'].accepted else None
            selected_changes['comment'] = original_data.get('comment') if widgets['comment'] and widgets['comment'].accepted else None
            selected_vars = widgets['vars'].get_selected_variables() if widgets['vars'] else []
            selected_changes['variables'] = selected_vars
            if selected_changes['function_name'] or selected_changes['comment'] or selected_changes['variables']:
                changes_by_ea[func_ea] = selected_changes

        if not changes_by_ea:
            print("aiDAPal DEBUG: [aiDAPalUIForm.on_accept_clicked] No changes selected. Closing.")
            ida_kernwin.info("aiDAPal: No changes were selected.")
            self.Close(0)
            return

        print(f"aiDAPal DEBUG: [aiDAPalUIForm.on_accept_clicked] Final changes gathered for {len(changes_by_ea)} functions. Preparing main thread update.")
        update_result_container = [False]

        def run_update_in_main_thread(changes_dict, result_container):
            print(f"aiDAPal DEBUG: [run_update_in_main_thread] Executing in main thread...")
            try:
                result_container[0] = self._perform_ida_updates(changes_dict)
                print(f"aiDAPal DEBUG: [run_update_in_main_thread] _perform_ida_updates returned: {result_container[0]}")
                return 1
            except Exception as e_update_main:
                print(f"aiDAPal Error: [run_update_in_main_thread] Exception during main thread update: {e_update_main}")
                traceback.print_exc(); result_container[0] = False; return 0

        sync_status = ida_kernwin.execute_sync(
            lambda: run_update_in_main_thread(changes_by_ea, update_result_container),
            ida_kernwin.MFF_WRITE
        )
        print(f"aiDAPal DEBUG: [on_accept_clicked] execute_sync for updates returned status: {sync_status}")

        if sync_status == 1:
            update_success = update_result_container[0]
            print(f"aiDAPal DEBUG: [on_accept_clicked] Update success status from main thread: {update_success}")
            if update_success: ida_kernwin.info(f"aiDAPal: Applied selected changes to {len(changes_by_ea)} function(s).")
            else: ida_kernwin.warning(f"aiDAPal: Failed to apply some or all changes. Check Output window.")
        else:
            print(f"aiDAPal Error: [on_accept_clicked] execute_sync for updates failed or was cancelled (status: {sync_status}).")
            ida_kernwin.warning(f"aiDAPal: Failed to execute update operation in main thread.")

        print("aiDAPal DEBUG: [aiDAPalUIForm.on_accept_clicked] Closing form.")
        self.Close(0)
        print("aiDAPal DEBUG: [aiDAPalUIForm.on_accept_clicked] Exiting.")

    # -------------------------------------------------------------------------
    # 3.  Internal helper – must be executed in the GUI thread.
    # -------------------------------------------------------------------------
    def _perform_ida_updates(self, changes_by_ea: dict[int, dict]) -> bool:
        """
        Apply comments, function‑renames and local‑variable renames that were
        accepted in the aiDAPal UI.

        *Must* be called from the GUI thread (wrapped by `execute_sync()` in
        `run_update_in_main_thread()`).

        Returns
        -------
        bool
            *True*  – everything applied successfully.
            *False* – at least one requested change failed.
        """
        print(
            f"aiDAPal DEBUG: [_perform_ida_updates] Starting update for "
            f"{len(changes_by_ea)} function(s) (MAIN THREAD)."
        )

        overall_refresh_needed = False
        overall_success        = True

        # ---------------------------------------------------------------------
        # Some third‑party helpers (e.g. “hrt”) automatically rename lvars on
        # Hex‑Rays events.  Temporarily disable them so they cannot fight with
        # our choices and cause ping‑pong loops.
        # ---------------------------------------------------------------------
        hrt_mod = sys.modules.get("hrt")
        if hrt_mod and hasattr(hrt_mod, "disable_autorename"):
            hrt_mod.disable_autorename(True)

        try:
            # ================================================================
            # main per‑function loop
            # ================================================================
            for func_ea, changes in changes_by_ea.items():
                fea_s = f"0x{func_ea:X}"
                print(f"---  Updating {fea_s}  ---")

                func_t   = ida_funcs.get_func(func_ea)
                cfunc    = None
                decomp_ok = False

                if not func_t:
                    print(f"  aiDAPal WARNING: no func_t for {fea_s} → only name() works")
                if changes.get("variables"):
                    try:
                        cfunc = ida_hexrays.decompile(func_ea)
                        decomp_ok = cfunc is not None
                    except ida_hexrays.DecompilationFailure as e:
                        print(f"  aiDAPal WARNING: decompilation failed for {fea_s}: {e}")

                # ------------------------------------------------------------
                # 1.  Comment
                # ------------------------------------------------------------
                new_cmt = changes.get("comment")
                if new_cmt and func_t:
                    wrapped = "\n".join(textwrap.wrap(new_cmt, width=80))
                    if not ida_funcs.set_func_cmt(func_t, wrapped, False):
                        overall_success = False
                        print(f"  aiDAPal ERROR: set_func_cmt() failed for {fea_s}")

                # ------------------------------------------------------------
                # 2.  Function name
                # ------------------------------------------------------------
                new_fname = changes.get("function_name")
                if new_fname:
                    cur = ida_funcs.get_func_name(func_ea) or ""
                    if cur != new_fname:
                        if not ida_name.set_name(
                            func_ea,
                            new_fname,
                            ida_name.SN_CHECK | ida_name.SN_FORCE | ida_name.SN_NOWARN,
                        ):
                            overall_success = False
                            print(f"  aiDAPal ERROR: set_name() failed for {fea_s}")

                # ------------------------------------------------------------
                # 3.  Local‑variable renames
                # ------------------------------------------------------------
                vars_req = changes.get("variables", [])
                if vars_req and not decomp_ok:
                    print(f"  aiDAPal WARNING: skipping {len(vars_req)} lvar renames "
                          f"(cfunc unavailable for {fea_s})")
                    overall_success = False
                    vars_req = []

                if vars_req:
                    print(f"  aiDAPal DEBUG: applying {len(vars_req)} lvar renames…")
                    r_ok = r_fail = r_skip = 0

                    for item in vars_req:
                        old = item["original_name"]
                        new = item["new_name"]
                        if old == new:
                            r_skip += 1
                            continue

                        lv_obj = next(
                            (lv for lv in cfunc.get_lvars() if lv.name == old), None
                        )
                        if lv_obj is None:
                            print(f"    aiDAPal WARNING: lvar '{old}' not found.")
                            r_fail += 1
                            continue

                        # ---------------- rename with verification loop --------
                        renamed = False
                        for attempt in range(3):
                            # -------- choose API by availability --------------
                            try:
                                if hasattr(cfunc, "set_lvar_name"):
                                    renamed = cfunc.set_lvar_name(
                                        lv_obj,
                                        new,
                                        ida_hexrays.LVREN_USER
                                        | getattr(ida_hexrays, "LVREN_FINAL", 0),
                                    )
                                elif hasattr(cfunc, "rename_lvar"):
                                    renamed = cfunc.rename_lvar(lv_obj, new)
                                else:
                                    renamed = ida_hexrays.rename_lvar(
                                        func_ea, old, new
                                    )
                            except Exception as e:
                                print(f"      aiDAPal DEBUG: rename API error: {e}")
                                renamed = False

                            # ----- post‑check against third‑party overrides ----
                            if renamed and lv_obj.name == new:
                                break  # success
                            if renamed:
                                # Somebody nixed our choice → retry
                                print(
                                    f"      aiDAPal DEBUG: post‑check failed "
                                    f"('{lv_obj.name}') – retry {attempt+1}/2"
                                )
                            renamed = False

                        # ---------------- bookkeeping ------------------------
                        if renamed:
                            r_ok += 1
                        else:
                            r_fail += 1
                            overall_success = False

                    print(
                        f"  aiDAPal DEBUG: lvar summary for {fea_s}: "
                        f"ok={r_ok}, fail={r_fail}, skip={r_skip}"
                    )

                    # mark decompiler output stale if *any* rename succeeded
                    if r_ok:
                        overall_refresh_needed = True
                        ida_hexrays.mark_cfunc_dirty(func_ea)

                print(f"---  Finished {fea_s}  ---")

        finally:
            # re‑enable 3rd‑party auto‑renamers
            if hrt_mod and hasattr(hrt_mod, "disable_autorename"):
                hrt_mod.disable_autorename(False)

            if overall_refresh_needed:
                ida_kernwin.refresh_idaviews()

            print(
                "aiDAPal DEBUG: [_perform_ida_updates] done – "
                f"success={overall_success}"
            )

        return overall_success


    def on_cancel_clicked(self):
        print("aiDAPal DEBUG: [aiDAPalUIForm.on_cancel_clicked] 'Close' button clicked. Closing form.")
        self.Close(0)

    def OnClose(self, form):
        primary_trigger_ea_str = f"0x{self.primary_trigger_ea:X}" if self.primary_trigger_ea else "None"
        print(f"aiDAPal DEBUG: [aiDAPalUIForm.OnClose] Form closing for analysis triggered by {primary_trigger_ea_str}.")
        # Cleanup handled by UI wrapper


# --- UI Wrapper Class (Modified to use primary_trigger_ea) ---
class aiDAPalUI:
    """Helper class to instantiate and show the UI form, preventing duplicates for the *same analysis trigger*."""
    open_forms = {} # Class variable: Key: primary_trigger_ea, Value: aiDAPalUIForm instance

    def __init__(self, analysis_results_list=None, primary_trigger_ea=None):
        print("aiDAPal DEBUG: [aiDAPalUI.__init__] Initializing UI wrapper.")
        if primary_trigger_ea is None or primary_trigger_ea == idaapi.BADADDR:
            print("aiDAPal Error: [aiDAPalUI.__init__] Cannot show UI without a valid primary trigger EA.")
            return

        func_ea_str = f"0x{primary_trigger_ea:X}"
        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Target primary trigger EA: {func_ea_str}")

        # Check if a form for an analysis *triggered by this primary EA* is already open
        if primary_trigger_ea in aiDAPalUI.open_forms:
            print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Form for analysis triggered by {func_ea_str} already open. Activating.")
            existing_form = aiDAPalUI.open_forms[primary_trigger_ea]
            try:
                widget = existing_form.GetWidget()
                if widget: ida_kernwin.activate_widget(widget, True)
                else: print(f"aiDAPal Warning: [aiDAPalUI.__init__] Could not get widget for existing form {func_ea_str}.")
            except Exception as e: print(f"aiDAPal Warning: [aiDAPalUI.__init__] Error activating existing widget for {func_ea_str}: {e}")
            return

        self.analysis_results = analysis_results_list if analysis_results_list else []
        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] UI wrapper initialized for analysis triggered by {func_ea_str} with {len(self.analysis_results)} results.")

        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Creating new aiDAPalUIForm instance for {func_ea_str}.")
        self.plg = aiDAPalUIForm(self.analysis_results, primary_trigger_ea)
        aiDAPalUI.open_forms[primary_trigger_ea] = self.plg
        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Form instance stored in open_forms for {func_ea_str}.")

        # Set caption based on the primary trigger function
        func_name_str = None
        name_container = [None]
        def get_name_main(ea, container):
            try: container[0] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"; return 1
            except: container[0] = f"sub_{ea:X}"; return 0
        name_sync_status = ida_kernwin.execute_sync(lambda: get_name_main(primary_trigger_ea, name_container), ida_kernwin.MFF_READ)
        func_name_str = name_container[0] if name_sync_status == 1 else f"sub_{func_ea_str}"

        form_caption = f"aiDAPal Suggestions: {func_name_str} Context"
        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Setting form caption: '{form_caption}'")
        show_flags = ida_kernwin.WOPN_PERSIST | ida_kernwin.WOPN_RESTORE
        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Calling Show() for {func_ea_str} with flags {show_flags}.")
        self.plg.Show(form_caption, show_flags)

        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] Wrapping OnClose for form triggered by {func_ea_str}.")
        original_on_close = self.plg.OnClose
        wrapped_on_close = lambda form, ea=primary_trigger_ea: self.on_close_handler(form, ea, original_on_close)
        self.plg.OnClose = wrapped_on_close

        print(f"aiDAPal DEBUG: [aiDAPalUI.__init__] UI wrapper initialization complete for {func_ea_str}.")

    def on_close_handler(self, form, func_ea, original_on_close_func):
        func_ea_str = f"0x{func_ea:X}"
        print(f"aiDAPal DEBUG: [aiDAPalUI.on_close_handler] Wrapper called for form triggered by {func_ea_str}.")
        print(f"aiDAPal DEBUG: [aiDAPalUI.on_close_handler] Removing form for {func_ea_str} from tracking.")
        aiDAPalUI.open_forms.pop(func_ea, None)
        print(f"aiDAPal DEBUG: [aiDAPalUI.on_close_handler] Calling original OnClose for {func_ea_str}.")
        original_on_close_func(form)
        print(f"aiDAPal DEBUG: [aiDAPalUI.on_close_handler] Original OnClose returned for {func_ea_str}.")


# --- Helper Functions (Data Ref Comments - Unchanged) ---
def get_references_from_function(func_ea):
    refs = set()
    func = ida_funcs.get_func(func_ea)
    if not func: return refs
    fii = ida_funcs.func_item_iterator_t()
    ok = fii.set_range(func.start_ea, func.end_ea)
    if not ok: return refs
    while fii.next_code():
        insn_ea = fii.current()
        dref_ea = ida_xref.get_first_dref_from(insn_ea)
        while dref_ea != idaapi.BADADDR:
            refs.add(dref_ea)
            dref_ea = ida_xref.get_next_dref_from(insn_ea, dref_ea)
    return refs

def get_function_data_ref_comments(current_func_ea):
    ea_str = f"0x{current_func_ea:X}" if current_func_ea is not None else "None"
    # print(f"aiDAPal DEBUG: [get_function_data_ref_comments] Starting for EA: {ea_str}") # Noisy
    if current_func_ea is None: return None
    references = get_references_from_function(current_func_ea)
    if not references: return None
    # print(f"aiDAPal DEBUG: Found {len(references)} unique data references for {ea_str}.") # Noisy
    comment_lines = []
    for ref in sorted(list(references)):
        cmt_text = ""
        cmt_r = ida_bytes.get_cmt(ref, True)
        cmt_n = ida_bytes.get_cmt(ref, False)
        if cmt_r: cmt_text = cmt_r.strip()
        if cmt_n:
            cmt_n_stripped = cmt_n.strip()
            if cmt_text and cmt_text != cmt_n_stripped: cmt_text += f" // {cmt_n_stripped}"
            elif not cmt_text: cmt_text = cmt_n_stripped
        if cmt_text:
            name = ida_name.get_name(ref)
            display_ref = name if name else f"0x{ref:X}"
            comment_lines.append(f" * {display_ref}: {cmt_text}")
    if not comment_lines: return None
    header = "/* Referenced Data Comments:"
    footer = "*/"
    full_comment = header + "\n" + "\n".join(comment_lines) + "\n" + footer
    # print(f"aiDAPal DEBUG: Found {len(comment_lines)} comments for {ea_str}.") # Noisy
    return full_comment


# --- NEW: Context Gathering Helpers (from codedump) ---
# --- MUST run in main thread ---

def find_callers_recursive(target_ea, current_depth, max_depth, visited_eas):
    """Recursively finds callers up to a specified depth using xrefs."""
    if current_depth > max_depth: return set()
    if target_ea in visited_eas: return set()
    visited_eas.add(target_ea)
    callers = set()
    ref_ea = ida_xref.get_first_cref_to(target_ea)
    while ref_ea != idaapi.BADADDR:
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func:
            caller_ea = caller_func.start_ea
            if caller_ea not in visited_eas:
                callers.add(caller_ea)
                callers.update(find_callers_recursive(caller_ea, current_depth + 1, max_depth, visited_eas))
        ref_ea = ida_xref.get_next_cref_to(target_ea, ref_ea)
    return callers

def find_callees_recursive(target_ea, current_depth, max_depth, visited_eas):
    """Recursively finds callees/refs up to a specified depth."""
    if current_depth > max_depth: return set()
    if target_ea in visited_eas: return set()
    visited_eas.add(target_ea)
    callees_and_refs = set()
    func = ida_funcs.get_func(target_ea)
    if not func: return callees_and_refs

    current_item_ea = func.start_ea
    insn = ida_ua.insn_t()
    next_insn = ida_ua.insn_t()

    while current_item_ea < func.end_ea and current_item_ea != idaapi.BADADDR:
        insn_len = ida_ua.decode_insn(insn, current_item_ea)
        if insn_len == 0:
            next_ea = idc.next_head(current_item_ea, func.end_ea)
            if next_ea <= current_item_ea: break
            current_item_ea = next_ea
            continue

        # Code Refs FROM
        cref_ea = ida_xref.get_first_cref_from(current_item_ea)
        while cref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(cref_ea)
            if ref_func and ref_func.start_ea == cref_ea:
                if cref_ea not in visited_eas:
                    callees_and_refs.add(cref_ea)
                    callees_and_refs.update(find_callees_recursive(cref_ea, current_depth + 1, max_depth, visited_eas))
            cref_ea = ida_xref.get_next_cref_from(current_item_ea, cref_ea)

        # Data Refs FROM
        dref_ea = ida_xref.get_first_dref_from(current_item_ea)
        while dref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(dref_ea)
            if ref_func and ref_func.start_ea == dref_ea:
                 if dref_ea not in visited_eas:
                    callees_and_refs.add(dref_ea)
                    callees_and_refs.update(find_callees_recursive(dref_ea, current_depth + 1, max_depth, visited_eas))
            dref_ea = ida_xref.get_next_dref_from(current_item_ea, dref_ea)

        # Immediate Operands & Push/Ret
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
                    if mnem == "push": is_push_imm_func = True; pushed_func_addr = imm_val
                    if imm_val not in visited_eas:
                        callees_and_refs.add(imm_val)
                        callees_and_refs.update(find_callees_recursive(imm_val, current_depth + 1, max_depth, visited_eas))

        if is_push_imm_func:
            next_insn_ea = current_item_ea + insn_len
            if next_insn_ea < func.end_ea:
                next_insn_len = ida_ua.decode_insn(next_insn, next_insn_ea)
                if next_insn_len > 0 and ida_idp.is_ret_insn(next_insn, ida_idp.IRI_RET_LITERALLY):
                    pass # Already handled by imm check

        # Advance
        next_ea = current_item_ea + insn_len
        if next_ea <= current_item_ea:
             next_ea = idc.next_head(current_item_ea, func.end_ea)
             if next_ea <= current_item_ea: break
        current_item_ea = next_ea
    return callees_and_refs

def decompile_functions_main(eas_to_decompile):
    """Decompiles a set of function EAs. MUST run in main thread."""
    print(f"aiDAPal DEBUG: [decompile_functions_main] Decompiling {len(eas_to_decompile)} functions in main thread...")
    results = {}
    total = len(eas_to_decompile)
    count = 0
    start_time = time.time()

    if not ida_hexrays.init_hexrays_plugin():
         print("aiDAPal Error: [decompile_functions_main] Failed to initialize Hex-Rays.")
         for func_ea in eas_to_decompile:
              func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
              results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Hex-Rays init failed"
         return results

    sorted_eas_list = sorted(list(eas_to_decompile))
    for func_ea in sorted_eas_list:
        count += 1
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        ida_kernwin.replace_wait_box(f"Decompiling {count}/{total}: {func_name}")
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc: results[func_ea] = str(cfunc)
            else: results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Decompiler returned None"
        except ida_hexrays.DecompilationFailure as e:
            results[func_ea] = f"// Decompilation ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  aiDAPal DEBUG: Decompilation failed for 0x{func_ea:X}: {e}")
        except Exception as e:
            results[func_ea] = f"// Decompilation UNEXPECTED ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  aiDAPal Error: Unexpected error decompiling 0x{func_ea:X}: {e}")
            traceback.print_exc()

    end_time = time.time()
    print(f"aiDAPal DEBUG: [decompile_functions_main] Decompilation finished in {end_time - start_time:.2f} seconds.")
    return results

# --- NEW: Orchestration Function for Context Gathering ---
def get_extended_function_context(start_eas, caller_depth, callee_depth):
    """
    Finds callers, callees, and references for the starting function(s) up to
    specified depths, then decompiles all unique functions found.
    MUST be called from the main IDA thread (e.g., via execute_sync).

    Args:
        start_eas (set): A set of starting function EAs.
        caller_depth (int): How many levels of callers to find.
        callee_depth (int): How many levels of callees/references to find.

    Returns:
        dict: A dictionary {ea: decompiled_code_string_or_error}, or None on failure.
    """
    start_desc = ", ".join([f"0x{ea:X}" for ea in start_eas])
    print(f"aiDAPal DEBUG: [get_extended_function_context] Starting context collection for {len(start_eas)} function(s): {start_desc}")
    print(f"  Caller Depth: {caller_depth}, Callee/Ref Depth: {callee_depth} (MAIN THREAD)")

    all_funcs_to_process = set(start_eas)
    decompiled_results = None

    try:
        ida_kernwin.show_wait_box(f"Finding callers/callees/refs for {len(start_eas)} function(s)...")

        # --- Find Callers ---
        visited_callers = set(start_eas) # Start visited set with initial functions
        total_caller_eas = set()
        if caller_depth > 0:
            print(f"  Finding callers up to depth {caller_depth}...")
            current_callers = set(start_eas)
            for depth in range(1, caller_depth + 1):
                ida_kernwin.replace_wait_box(f"Finding callers (Depth {depth}/{caller_depth})...")
                next_level_callers = set()
                processed_in_level = set() # Avoid processing same caller multiple times if reached via different paths at same depth
                for caller_ea in current_callers:
                    if caller_ea in processed_in_level: continue
                    # Use a temporary visited set for this specific recursive call to avoid cycles within the depth search
                    # but allow revisiting nodes if reached via a shorter path earlier
                    temp_visited = set(visited_callers) # Copy visited set for this branch
                    found = find_callers_recursive(caller_ea, 1, 1, temp_visited) # Find only direct callers (depth 1)
                    newly_found = found - visited_callers # Only consider truly new callers
                    next_level_callers.update(newly_found)
                    visited_callers.update(newly_found) # Add newly found to overall visited
                    processed_in_level.add(caller_ea)
                if not next_level_callers: break # No new callers found
                total_caller_eas.update(next_level_callers)
                current_callers = next_level_callers # Move to the next level

            all_funcs_to_process.update(total_caller_eas)
            print(f"  Found {len(total_caller_eas)} unique callers within depth {caller_depth}.")

        # --- Find Callees/Refs ---
        visited_callees = set(start_eas) # Separate visited set for callee traversal, start with initial
        total_callee_ref_eas = set()
        if callee_depth > 0:
            print(f"  Finding callees/refs up to depth {callee_depth}...")
            current_callees = set(start_eas)
            for depth in range(1, callee_depth + 1):
                ida_kernwin.replace_wait_box(f"Finding callees/refs (Depth {depth}/{callee_depth})...")
                next_level_callees = set()
                processed_in_level = set()
                for callee_ea in current_callees:
                     if callee_ea in processed_in_level: continue
                     temp_visited = set(visited_callees)
                     # find_callees_recursive already handles depth internally, but let's call it iteratively for progress update
                     # We need to find direct callees/refs (depth 1) from the current level
                     # Let's refine find_callees_recursive slightly or use a simpler direct finder here.
                     # Sticking to the original recursive approach for consistency, but call it for depth 1 repeatedly.
                     # This might be less efficient than a pure BFS/DFS but reuses existing code.
                     # Let's try a BFS approach here for clarity.
                     q = deque([(callee_ea, 0)]) # (ea, current_depth)
                     found_in_iter = set()
                     processed_for_bfs = set() # Track visited within this BFS iteration

                     # Find direct (depth 1) callees/refs from callee_ea
                     func = ida_funcs.get_func(callee_ea)
                     if func:
                         item_ea = func.start_ea
                         insn = ida_ua.insn_t()
                         while item_ea < func.end_ea and item_ea != idaapi.BADADDR:
                             ilen = ida_ua.decode_insn(insn, item_ea)
                             if ilen == 0:
                                 next_ea_h = idc.next_head(item_ea, func.end_ea); item_ea = next_ea_h; continue
                             # Code Refs
                             cref = ida_xref.get_first_cref_from(item_ea)
                             while cref != idaapi.BADADDR:
                                 ref_f = ida_funcs.get_func(cref);
                                 if ref_f and ref_f.start_ea == cref and cref not in visited_callees: found_in_iter.add(cref)
                                 cref = ida_xref.get_next_cref_from(item_ea, cref)
                             # Data Refs (to functions)
                             dref = ida_xref.get_first_dref_from(item_ea)
                             while dref != idaapi.BADADDR:
                                 ref_f = ida_funcs.get_func(dref);
                                 if ref_f and ref_f.start_ea == dref and dref not in visited_callees: found_in_iter.add(dref)
                                 dref = ida_xref.get_next_dref_from(item_ea, dref)
                             # Immediates (functions)
                             for i in range(idaapi.UA_MAXOP):
                                 op = insn.ops[i];
                                 if op.type == idaapi.o_void: break
                                 if op.type == idaapi.o_imm:
                                     ref_f = ida_funcs.get_func(op.value)
                                     if ref_f and ref_f.start_ea == op.value and op.value not in visited_callees: found_in_iter.add(op.value)
                             item_ea += ilen

                     newly_found = found_in_iter - visited_callees # Ensure they are truly new
                     next_level_callees.update(newly_found)
                     visited_callees.update(newly_found)
                     processed_in_level.add(callee_ea)

                if not next_level_callees: break # No new callees/refs found
                total_callee_ref_eas.update(next_level_callees)
                current_callees = next_level_callees # Move to the next level

            all_funcs_to_process.update(total_callee_ref_eas)
            print(f"  Found {len(total_callee_ref_eas)} unique callees/refs within depth {callee_depth}.")


        total_funcs = len(all_funcs_to_process)
        print(f"  Total unique functions to decompile: {total_funcs}")
        if total_funcs == 0:
            print("  No functions to decompile.")
            ida_kernwin.hide_wait_box()
            return {} # Return empty dict

        # --- Decompile ---
        decompiled_results = decompile_functions_main(all_funcs_to_process)
        ida_kernwin.hide_wait_box()
        print(f"aiDAPal DEBUG: [get_extended_function_context] Context collection finished. Returning {len(decompiled_results)} decompiled items.")
        return decompiled_results

    except Exception as e:
        print(f"aiDAPal Error: [get_extended_function_context] Unexpected error: {e}")
        traceback.print_exc()
        ida_kernwin.hide_wait_box()
        return None # Indicate failure

# --- NEW: Helper to find functions within a specific depth (callers and callees) ---
def find_functions_within_depth(start_eas: Set[int], max_depth: int) -> Set[int]:
    """
    Performs a Breadth-First Search (BFS) from start_eas to find all functions
    reachable within max_depth, considering both callers and callees/refs.
    MUST be called from the main IDA thread.

    Args:
        start_eas (set): The initial set of function EAs.
        max_depth (int): The maximum depth to explore (0 means only start_eas).

    Returns:
        set: A set of function EAs within the specified depth.
    """
    print(f"aiDAPal DEBUG: [find_functions_within_depth] Finding functions within depth {max_depth} from {len(start_eas)} starts (MAIN THREAD)...")
    if max_depth < 0: return set()
    if max_depth == 0: return set(start_eas) # Return copies

    q = deque([(ea, 0) for ea in start_eas]) # (ea, depth)
    visited: Set[int] = set(start_eas)
    result_eas: Set[int] = set(start_eas)

    while q:
        current_ea, current_depth = q.popleft()

        if current_depth >= max_depth:
            continue

        # --- Find Neighbors (Callers + Callees/Refs) ---
        neighbors: Set[int] = set()

        # 1. Find Callers (Refs TO current_ea)
        ref_ea = ida_xref.get_first_cref_to(current_ea)
        while ref_ea != idaapi.BADADDR:
            caller_func = ida_funcs.get_func(ref_ea)
            if caller_func: neighbors.add(caller_func.start_ea)
            ref_ea = ida_xref.get_next_cref_to(current_ea, ref_ea)
        # Data refs TO (less common for calls, but include for completeness if needed)
        # dref_ea = ida_xref.get_first_dref_to(current_ea)
        # while dref_ea != idaapi.BADADDR:
        #     caller_func = ida_funcs.get_func(dref_ea)
        #     if caller_func: neighbors.add(caller_func.start_ea)
        #     dref_ea = ida_xref.get_next_dref_to(current_ea, dref_ea)

        # 2. Find Callees/Refs (Refs FROM current_ea)
        func = ida_funcs.get_func(current_ea)
        if func:
            item_ea = func.start_ea
            insn = ida_ua.insn_t()
            while item_ea < func.end_ea and item_ea != idaapi.BADADDR:
                ilen = ida_ua.decode_insn(insn, item_ea)
                if ilen == 0:
                    next_ea_h = idc.next_head(item_ea, func.end_ea); item_ea = next_ea_h; continue
                # Code Refs FROM
                cref = ida_xref.get_first_cref_from(item_ea)
                while cref != idaapi.BADADDR:
                    ref_f = ida_funcs.get_func(cref);
                    if ref_f and ref_f.start_ea == cref: neighbors.add(cref)
                    cref = ida_xref.get_next_cref_from(item_ea, cref)
                # Data Refs FROM (to functions)
                dref = ida_xref.get_first_dref_from(item_ea)
                while dref != idaapi.BADADDR:
                    ref_f = ida_funcs.get_func(dref);
                    if ref_f and ref_f.start_ea == dref: neighbors.add(dref)
                    dref = ida_xref.get_next_dref_from(item_ea, dref)
                # Immediates (functions)
                for i in range(idaapi.UA_MAXOP):
                    op = insn.ops[i];
                    if op.type == idaapi.o_void: break
                    if op.type == idaapi.o_imm:
                        ref_f = ida_funcs.get_func(op.value)
                        if ref_f and ref_f.start_ea == op.value: neighbors.add(op.value)
                item_ea += ilen

        # --- Process Neighbors ---
        for neighbor_ea in neighbors:
            if neighbor_ea != idaapi.BADADDR and neighbor_ea not in visited:
                visited.add(neighbor_ea)
                result_eas.add(neighbor_ea)
                q.append((neighbor_ea, current_depth + 1))

    print(f"aiDAPal DEBUG: [find_functions_within_depth] Found {len(result_eas)} functions total within depth {max_depth}.")
    return result_eas


# --- Google AI Interaction (Unchanged) ---
def do_google_ai_analysis(code_prompt, model_name):
    """Sends prompt to Google AI, expects multi-function JSON output."""
    print(f"aiDAPal DEBUG: [do_google_ai_analysis] Starting MULTI-FUNCTION analysis request to Google AI model: {model_name}")
    if not GOOGLE_AI_API_KEY or GOOGLE_AI_API_KEY == "YOUR_API_KEY_HERE":
        print("aiDAPal Error: [do_google_ai_analysis] GOOGLE_API_KEY not set or is placeholder.")
        ida_kernwin.warning("aiDAPal Error: Google AI API Key not configured.")
        return None
    print("aiDAPal DEBUG: [do_google_ai_analysis] API Key seems present.")
    try:
        print("aiDAPal DEBUG: [do_google_ai_analysis] Creating genai.Client...")
        client = genai.Client(api_key=GOOGLE_AI_API_KEY)
        print("aiDAPal DEBUG: [do_google_ai_analysis] Setting up types.GenerateContentConfig...")
        generation_config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=explicit_multi_function_analysis_schema,
            temperature=0.0,
            thinking_config = types.ThinkingConfig(
                thinking_budget=24576,
            ),
            safety_settings=DEFAULT_SAFETY_SETTINGS
        )
        print("aiDAPal DEBUG: [do_google_ai_analysis] Calling client.models.generate_content()...")
        response = client.models.generate_content(
            model=f'models/{model_name}',
            contents=code_prompt,
            config=generation_config
        )
        print(f"aiDAPal DEBUG: [do_google_ai_analysis] Received response object from {model_name}.")

        if not hasattr(response, 'text') or not response.text:
             print("aiDAPal Error: [do_google_ai_analysis] Response has no text content or is empty/blocked.")
             block_reason, safety_ratings = "Unknown", "N/A"
             try:
                 if hasattr(response, 'prompt_feedback') and response.prompt_feedback:
                     if hasattr(response.prompt_feedback, 'block_reason'): block_reason = response.prompt_feedback.block_reason.name if response.prompt_feedback.block_reason else "Not Specified"
                     if hasattr(response.prompt_feedback, 'safety_ratings'): safety_ratings = str([f"{sr.category.name}: {sr.probability.name}" for sr in response.prompt_feedback.safety_ratings])
                 elif hasattr(response, 'candidates') and response.candidates:
                     candidate = response.candidates[0]
                     if hasattr(candidate, 'finish_reason') and candidate.finish_reason: block_reason = candidate.finish_reason.name
                     if hasattr(candidate, 'safety_ratings') and candidate.safety_ratings: safety_ratings = str([f"{sr.category.name}: {sr.probability.name}" for sr in candidate.safety_ratings])
                 print(f"  Block Reason: {block_reason}; Safety Ratings: {safety_ratings}")
                 ida_kernwin.warning(f"aiDAPal: Google AI response was empty or blocked.\nReason: {block_reason}")
             except Exception as e_info: print(f"aiDAPal Error: Error getting finish reason/safety details: {e_info}")
             return None

        print("aiDAPal DEBUG: [do_google_ai_analysis] Response has text content. Parsing...")
        try:
            raw_text = response.text
            # print(f"aiDAPal DEBUG: Raw response text (first 100): {raw_text[:100]}...") # Noisy
            json_start, json_end, cleaned_text, search_start_index = -1, -1, "", 0
            start_marker_json = raw_text.find("```json")
            start_marker_plain = raw_text.find("```")
            if start_marker_json != -1: search_start_index = start_marker_json + 7
            elif start_marker_plain != -1:
                potential_json_start = raw_text.find('{', start_marker_plain + 3)
                if potential_json_start != -1: search_start_index = start_marker_plain + 3
            json_start = raw_text.find('{', search_start_index)
            if json_start != -1:
                end_marker = raw_text.find("```", json_start)
                if end_marker != -1: json_end = raw_text.rfind('}', json_start, end_marker)
                else: json_end = raw_text.rfind('}', json_start)
                if json_end != -1 and json_end > json_start:
                    cleaned_text = raw_text[json_start : json_end + 1].strip()
                    # print(f"aiDAPal DEBUG: Extracted JSON (len: {len(cleaned_text)}).") # Noisy
                else: print("aiDAPal Warning: Found '{' but no valid '}' afterwards.")
            else: print(f"aiDAPal Warning: Could not find JSON start '{{' after index {search_start_index}.")

            if not cleaned_text:
                 print(f"aiDAPal Error: Failed to extract JSON block from response.")
                 print(f"DEBUG Raw response:\n---\n{raw_text}\n---")
                 ida_kernwin.warning(f"aiDAPal failed to extract JSON block from response.")
                 return None

            parsed_response = json.loads(cleaned_text)
            # print("aiDAPal DEBUG: JSON parsing successful.") # Noisy

            # --- Validation ---
            if not isinstance(parsed_response, dict) or "function_analyses" not in parsed_response or not isinstance(parsed_response["function_analyses"], list):
                raise ValueError("Invalid top-level structure or missing 'function_analyses' list.")
            validated_analyses = []
            required_inner_keys = ["original_function_name", "observations", "function_name_reason", "function_name_reason_findings", "function_name", "comment_reason", "comment_reason_findings", "comment", "variables"]
            required_variable_keys = ["rename_reason", "rename_reason_findings", "original_name", "new_name"]
            required_observation_keys = ["observation", "observation_impact"]

            # print(f"aiDAPal DEBUG: Validating {len(parsed_response['function_analyses'])} analysis items...") # Noisy
            for i, func_analysis in enumerate(parsed_response["function_analyses"]):
                if not isinstance(func_analysis, dict): print(f"Warning: Item {i} not a dict. Skipping."); continue
                valid_item = True
                for key in required_inner_keys:
                    if key not in func_analysis:
                        print(f"Warning: Missing key '{key}' in item {i}. Providing default/skipping.")
                        if key == 'original_function_name': valid_item = False; break
                        elif key == 'variables': func_analysis[key] = []
                        elif key == 'observations': func_analysis[key] = []
                        elif key == 'function_name': func_analysis[key] = f"suggested_name_{i}"
                        elif key == 'comment': func_analysis[key] = "(No comment suggested)"
                        else: func_analysis[key] = ""
                if not valid_item: continue

                # Validate observations list
                if not isinstance(func_analysis.get('observations'), list): func_analysis['observations'] = []
                else:
                    validated_observations = []
                    for obs_idx, obs_item in enumerate(func_analysis['observations']):
                        if isinstance(obs_item, dict) and all(k in obs_item for k in required_observation_keys): validated_observations.append(obs_item)
                        else: print(f"Warning: Invalid observation item {obs_idx} in func analysis {i}. Skipping.")
                    func_analysis['observations'] = validated_observations

                # Validate variables list
                if not isinstance(func_analysis.get('variables'), list): func_analysis['variables'] = []
                else:
                    validated_variables = []
                    for j, var_item in enumerate(func_analysis.get('variables', [])):
                        if isinstance(var_item, dict) and all(k in var_item for k in required_variable_keys): validated_variables.append(var_item)
                        else: print(f"Warning: Invalid variable item {j} in func analysis {i}. Skipping.")
                    func_analysis['variables'] = validated_variables
                validated_analyses.append(func_analysis)

            print(f"aiDAPal DEBUG: Validation complete. {len(validated_analyses)} valid analyses found.")
            return validated_analyses

        except (json.JSONDecodeError, ValueError) as e:
            print(f"aiDAPal Error: Failed to parse or validate JSON: {e}")
            if 'raw_text' in locals(): print(f"DEBUG Response text:\n---\n{raw_text}\n---")
            ida_kernwin.warning(f"aiDAPal failed to parse/validate JSON response.\nError: {e}")
            return None
        except Exception as e_parse:
             print(f"aiDAPal Error: Unexpected error processing response: {e_parse}"); traceback.print_exc()
             ida_kernwin.warning("aiDAPal: Unexpected error processing AI response.")
             return None

    except ImportError:
        print("aiDAPal Error: Required Python libraries not found (ImportError).")
        ida_kernwin.warning("aiDAPal Error: Required Python libraries not found.")
        return None
    except Exception as e:
        print(f"aiDAPal Error: An unexpected error occurred during API interaction: {e}"); traceback.print_exc()
        ida_kernwin.warning(f"aiDAPal: An unexpected error occurred during AI interaction: {e}")
        return None

# --- Asynchronous Task Handling ---

def do_show_ui(results_list, primary_trigger_ea):
    """Callback to show the UI form in the main IDA thread."""
    func_ea_str = f"0x{primary_trigger_ea:X}" if primary_trigger_ea else "None"
    print(f"aiDAPal DEBUG: [do_show_ui] Entered. Will show UI triggered by {func_ea_str}.")
    if primary_trigger_ea is None or primary_trigger_ea == idaapi.BADADDR:
        print("aiDAPal Error: [do_show_ui] No valid primary trigger EA provided.")
        return False
    try:
        print(f"aiDAPal DEBUG: [do_show_ui] Instantiating aiDAPalUI for {func_ea_str}...")
        aiDAPalUI(results_list, primary_trigger_ea) # Pass trigger EA for tracking
        print(f"aiDAPal DEBUG: [do_show_ui] aiDAPalUI instantiation complete.")
    except Exception as e:
        print(f"aiDAPal Error: [do_show_ui] Error creating or showing UI: {e}"); traceback.print_exc()
    print(f"aiDAPal DEBUG: [do_show_ui] Exiting for {func_ea_str}. Returning False.")
    return False

# --- Analysis Task Wrappers (for concurrency control) ---

def single_analysis_task_wrapper(
    primary_func_ea: int,
    context_caller_depth: int,
    context_callee_depth: int,
    model: str,
    analysis_mode: str,
    analysis_depth: int,
    context: Optional[str]
):
    """Wrapper for async_call (single trigger) to handle concurrency flag."""
    func_ea_str = f"0x{primary_func_ea:X}" if primary_func_ea != idaapi.BADADDR else "BADADDR"
    print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] Thread started for analysis triggered by {func_ea_str}, mode '{analysis_mode}', analysis_depth {analysis_depth}, model {model}.")
    try:
        print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] Calling async_call for {func_ea_str}...")
        # Pass primary EA as a set
        async_call(
            start_eas={primary_func_ea},
            context_caller_depth=context_caller_depth,
            context_callee_depth=context_callee_depth,
            model_name=model,
            analysis_mode=analysis_mode,
            analysis_depth=analysis_depth,
            extra_context=context
        )
        print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] async_call finished for {func_ea_str}.")
    except Exception as e:
         print(f"aiDAPal Error: [single_analysis_task_wrapper] Exception during async_call for {func_ea_str}: {e}"); traceback.print_exc()
    finally:
        if primary_func_ea != idaapi.BADADDR:
            print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] Acquiring lock to clear analysis flag for {func_ea_str}...")
            with g_analysis_lock:
                g_analysis_in_progress.discard(primary_func_ea)
                print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] Analysis flag cleared for {func_ea_str}. Current single in progress: {g_analysis_in_progress}")
        else: print("aiDAPal DEBUG: [single_analysis_task_wrapper] Cannot clear flag, invalid primary func_ea.")
        print(f"aiDAPal DEBUG: [single_analysis_task_wrapper] Thread finished for analysis triggered by {func_ea_str}.")

def multi_analysis_task_wrapper(start_eas, caller_depth, callee_depth, model, context):
    """Wrapper for async_call (multi trigger from menu) to handle concurrency flag."""
    # Note: Multi-trigger currently always uses 'all' analysis mode and doesn't fetch dref comments.
    global g_multi_analysis_active
    start_desc = ", ".join([f"0x{ea:X}" for ea in start_eas])
    print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] Thread started for MULTI analysis triggered by {len(start_eas)} funcs: {start_desc}, model {model}.")
    try:
        print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] Calling async_call...")
        async_call(
            start_eas=start_eas,
            context_caller_depth=caller_depth,
            context_callee_depth=callee_depth,
            model_name=model,
            analysis_mode='all', # Multi-start always analyzes all found context functions
            analysis_depth=0, # Not applicable for 'all' mode
            extra_context=context
        )
        print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] async_call finished.")
    except Exception as e:
         print(f"aiDAPal Error: [multi_analysis_task_wrapper] Exception during async_call: {e}"); traceback.print_exc()
    finally:
        print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] Acquiring lock to clear multi-analysis flag...")
        with g_analysis_lock:
            g_multi_analysis_active = False
            print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] Multi-analysis flag cleared. Current multi active: {g_multi_analysis_active}")
        print(f"aiDAPal DEBUG: [multi_analysis_task_wrapper] Thread finished for multi-analysis.")


# --- IDA Plugin Integration (Action Handler, Hooks, Plugin Class) ---

class CtxActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the context menu actions."""
    def __init__(self, model_name, analysis_mode='all'):
        """
        Initializes the handler.

        Args:
            model_name (str): The Google AI model to use.
            analysis_mode (str): 'all', 'current', or 'depth_limited'.
        """
        self.model = model_name
        self.analysis_mode = analysis_mode
        ida_kernwin.action_handler_t.__init__(self)
        # print(f"aiDAPal DEBUG: [CtxActionHandler.__init__] Handler created for model '{self.model}', mode: '{self.analysis_mode}'") # Noisy

    def activate(self, ctx):
        """Called when the context menu item is clicked."""
        global g_analysis_in_progress, g_multi_analysis_active # Use new concurrency flags
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Action '{self.model}' (Mode: '{self.analysis_mode}') activated.")
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type != ida_kernwin.BWN_PSEUDOCODE: return 1

        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            print("aiDAPal Error: [CtxActionHandler.activate] Could not get vdui or cfunc."); ida_kernwin.warning("aiDAPal: Decompilation not available."); return 1

        primary_func_ea = vu.cfunc.entry_ea
        primary_func_ea_str = f"0x{primary_func_ea:X}"
        primary_func_name = ida_funcs.get_func_name(primary_func_ea) or f"sub_{primary_func_ea_str}"
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Target primary function: {primary_func_name} ({primary_func_ea_str})")

        # --- Concurrency Check ---
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Acquiring lock for {primary_func_ea_str}...")
        with g_analysis_lock:
            print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Lock acquired. Checking concurrency...")
            if primary_func_ea in g_analysis_in_progress:
                print(f"aiDAPal DEBUG: Single analysis already in progress for {primary_func_ea_str}."); ida_kernwin.warning(f"aiDAPal: Analysis already running for {primary_func_name}."); return 1
            if g_multi_analysis_active:
                print(f"aiDAPal DEBUG: Multi-analysis is active. Blocking single analysis."); ida_kernwin.warning(f"aiDAPal: A multi-function analysis is running. Please wait."); return 1
            g_analysis_in_progress.add(primary_func_ea)
            print(f"aiDAPal DEBUG: Marked {primary_func_ea_str} as in progress. Current single: {g_analysis_in_progress}, Multi active: {g_multi_analysis_active}")
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Lock released for {primary_func_ea_str}.")

        # --- Get User Input for Depths (Main Thread) ---
        # Initialize defaults
        context_caller_depth = -1
        context_callee_depth = -1
        analysis_depth = -1 # Only used for 'depth_limited' mode

        input_container = [{
            "context_caller_depth": -1,
            "context_callee_depth": -1,
            "analysis_depth": -1
        }]

        def get_depths_main(container, mode):
            try:
                if mode == 'depth_limited':
                    # Ask for Analysis Depth first
                    a_depth = ida_kernwin.ask_long(DEFAULT_ANALYSIS_DEPTH, "Enter ANALYSIS Depth (Functions to modify, e.g., 0, 1)")
                    if a_depth is None: return 0 # User cancelled
                    container[0]["analysis_depth"] = int(a_depth) if a_depth >= 0 else 0

                    # Ask for Context Depths (suggest >= analysis depth)
                    default_ctx_depth = max(DEFAULT_CONTEXT_CALLER_DEPTH, container[0]["analysis_depth"])
                    c_depth = ida_kernwin.ask_long(default_ctx_depth, f"Enter CONTEXT Caller Depth (>= {container[0]['analysis_depth']})")
                    if c_depth is None: return 0
                    container[0]["context_caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                    default_ctx_depth = max(DEFAULT_CONTEXT_CALLEE_DEPTH, container[0]["analysis_depth"])
                    ca_depth = ida_kernwin.ask_long(default_ctx_depth, f"Enter CONTEXT Callee/Ref Depth (>= {container[0]['analysis_depth']})")
                    if ca_depth is None: return 0
                    container[0]["context_callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

                else: # Modes 'all' or 'current'
                    # Only ask for Context Depths
                    c_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLER_DEPTH, "Enter CONTEXT Caller Depth (e.g., 0, 1, 2)")
                    if c_depth is None: return 0
                    container[0]["context_caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                    ca_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLEE_DEPTH, "Enter CONTEXT Callee/Ref Depth (e.g., 0, 1, 2)")
                    if ca_depth is None: return 0
                    container[0]["context_callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0
                    container[0]["analysis_depth"] = 0 # Not used, set to default

                # Basic validation
                if container[0]["context_caller_depth"] < 0 or container[0]["context_callee_depth"] < 0 or container[0]["analysis_depth"] < 0:
                    print("aiDAPal Error: Invalid depth input received.")
                    return -1 # Indicate error

                return 1 # Success
            except Exception as e:
                print(f"aiDAPal Error: Exception during depth input: {e}")
                traceback.print_exc()
                return -1 # Indicate error

        sync_status = ida_kernwin.execute_sync(lambda: get_depths_main(input_container, self.analysis_mode), ida_kernwin.MFF_WRITE)

        if sync_status != 1:
            print(f"aiDAPal DEBUG: [CtxActionHandler.activate] User cancelled depth input or input failed (Status: {sync_status}).")
            with g_analysis_lock: g_analysis_in_progress.discard(primary_func_ea) # Release flag
            return 1 # Indicate action handled (cancelled)

        # Retrieve depths from container
        context_caller_depth = input_container[0]["context_caller_depth"]
        context_callee_depth = input_container[0]["context_callee_depth"]
        analysis_depth = input_container[0]["analysis_depth"] # Will be 0 if mode is not 'depth_limited'

        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Depths - Context Callers: {context_caller_depth}, Context Callees: {context_callee_depth}, Analysis: {analysis_depth}")

        # --- Get Context (Data References for the PRIMARY function - RUN IN MAIN THREAD) ---
        # Only fetch if analyzing the current function or depth-limited (where current is included)
        dref_comments = None
        if self.analysis_mode == 'current' or self.analysis_mode == 'depth_limited':
            print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Getting data reference comments for {primary_func_ea_str}...")
            dref_result_container = [None]
            try:
                def get_dref_comments_main(container):
                    try: container[0] = get_function_data_ref_comments(primary_func_ea); return 1
                    except Exception as e_inner: print(f"Error getting dref comments: {e_inner}"); container[0] = None; return 0
                sync_status_dref = ida_kernwin.execute_sync(lambda: get_dref_comments_main(dref_result_container), ida_kernwin.MFF_READ)
                if sync_status_dref == 1:
                    dref_comments = dref_result_container[0]
                    if dref_comments: print(f"aiDAPal DEBUG: Found data reference comments (length: {len(dref_comments)}).")
                    else: print(f"aiDAPal DEBUG: No data reference comments found.")
                else: print(f"aiDAPal Error: execute_sync for dref comments failed (status: {sync_status_dref}).")
            except Exception as e_dref_sync: print(f"aiDAPal Error: Exception during dref comments sync: {e_dref_sync}"); traceback.print_exc()
            # Continue even if dref comments fail
        else:
             print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Skipping data reference comments fetch for mode '{self.analysis_mode}'.")


        # --- Start Analysis Thread ---
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Starting analysis thread (Mode: {self.analysis_mode}) for {primary_func_ea_str}...")
        # Use the single analysis wrapper, passing all relevant parameters
        caller = partial(
            single_analysis_task_wrapper,
            primary_func_ea,
            context_caller_depth,
            context_callee_depth,
            self.model,
            self.analysis_mode,
            analysis_depth,
            dref_comments
        )
        analysis_thread = threading.Thread(target=caller)
        analysis_thread.start()
        print(f"aiDAPal DEBUG: [CtxActionHandler.activate] Analysis thread started. Exiting activate.")
        return 1

    def update(self, ctx):
        """Enables the action only when in a pseudocode view with successful decompilation."""
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc: return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class Hooks(ida_kernwin.UI_Hooks):
    """Hooks into IDA's UI to add context menu items."""
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # print(f"aiDAPal DEBUG: [Hooks.finish_populating_widget_popup] Adding menu items...") # Noisy
            try:
                action_added = False
                for model_name in MODELS_TO_REGISTER:
                    # --- Add MULTI (Analyze ALL in Context) action ---
                    action_name_multi = f"{ACTION_ID_CTX_PREFIX_MULTI}{model_name}"
                    if ida_kernwin.attach_action_to_popup(widget, popup_handle, action_name_multi, f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS): action_added = True
                    else: print(f"Warning: Failed to attach action '{action_name_multi}'.")

                    # --- Add SINGLE (Analyze CURRENT Only) action ---
                    action_name_single = f"{ACTION_ID_CTX_PREFIX_SINGLE}{model_name}"
                    if ida_kernwin.attach_action_to_popup(widget, popup_handle, action_name_single, f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS): action_added = True
                    else: print(f"Warning: Failed to attach action '{action_name_single}'.")

                    # --- Add DEPTH_LIMITED (Analyze Current + N Levels) action ---
                    action_name_depth = f"{ACTION_ID_CTX_PREFIX_DEPTH}{model_name}"
                    if ida_kernwin.attach_action_to_popup(widget, popup_handle, action_name_depth, f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS): action_added = True
                    else: print(f"Warning: Failed to attach action '{action_name_depth}'.")


                if action_added: ida_kernwin.attach_action_to_popup(widget, popup_handle, "-", f"{MENU_PATH_CTX}", ida_kernwin.SETMENU_INS | ida_kernwin.SETMENU_FIRST)
            except Exception as e: print(f"aiDAPal Error: [Hooks] Exception attaching actions: {e}"); traceback.print_exc()


class aidapal_t(idaapi.plugin_t):
    """The main IDA Pro plugin class."""
    # Use PLUGIN_FIX for main menu entry via run()
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = "aiDAPal: Google AI assistance for Hex-Rays (Extended Context Analysis)"
    help = "Right-click in Pseudocode for context options, or use Edit->Plugins menu for multi-func analysis."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    hooks = None
    registered_actions = []

    def init(self):
        """Called by IDA when loading the plugin."""
        print("-" * 60)
        print(f"aiDAPal DEBUG: {self.wanted_name} plugin initializing...")

        # Check prerequisites
        print("aiDAPal DEBUG: [init] Checking prerequisites...")
        if not GOOGLE_AI_API_KEY or GOOGLE_AI_API_KEY == "YOUR_API_KEY_HERE":
             print("aiDAPal Warning: [init] GOOGLE_API_KEY not set or is placeholder.")
             print("  Plugin actions will not function until the key is set and IDA is restarted.")
        if not ida_hexrays.init_hexrays_plugin():
            print("aiDAPal Error: [init] Hex-Rays decompiler is not available."); print("-" * 60); return idaapi.PLUGIN_SKIP
        print("aiDAPal DEBUG: [init] Hex-Rays initialized.")

        aidapal_t.registered_actions = []
        print("aiDAPal DEBUG: [init] Cleared registered actions list.")

        try:
            print(f"aiDAPal DEBUG: [init] Registering context actions for models: {MODELS_TO_REGISTER}")
            for model_name in MODELS_TO_REGISTER:
                # --- Register MULTI (Analyze ALL in Context) action ---
                action_name_multi = f"{ACTION_ID_CTX_PREFIX_MULTI}{model_name}"
                action_label_multi = f'Analyze ALL Funcs in Context ({model_name})'
                action_tooltip_multi = f'Send current func + context to {model_name} for analysis of ALL functions found'
                action_desc_multi = ida_kernwin.action_desc_t(action_name_multi, action_label_multi, CtxActionHandler(model_name, analysis_mode='all'), None, action_tooltip_multi, 199)
                if ida_kernwin.register_action(action_desc_multi): aidapal_t.registered_actions.append(action_name_multi)
                else: print(f"Error: Failed to register action: '{action_name_multi}'")

                # --- Register SINGLE (Analyze CURRENT Only) action ---
                action_name_single = f"{ACTION_ID_CTX_PREFIX_SINGLE}{model_name}"
                action_label_single = f'Analyze CURRENT Func Only ({model_name})'
                action_tooltip_single = f'Send current func + context to {model_name} for analysis of ONLY the current function'
                action_desc_single = ida_kernwin.action_desc_t(action_name_single, action_label_single, CtxActionHandler(model_name, analysis_mode='current'), None, action_tooltip_single, 199)
                if ida_kernwin.register_action(action_desc_single): aidapal_t.registered_actions.append(action_name_single)
                else: print(f"Error: Failed to register action: '{action_name_single}'")

                # --- Register DEPTH_LIMITED (Analyze Current + N Levels) action ---
                action_name_depth = f"{ACTION_ID_CTX_PREFIX_DEPTH}{model_name}"
                action_label_depth = f'Analyze Current + N Levels ({model_name})'
                action_tooltip_depth = f'Send current func + context to {model_name} for analysis of current func and neighbors up to specified ANALYSIS depth'
                action_desc_depth = ida_kernwin.action_desc_t(action_name_depth, action_label_depth, CtxActionHandler(model_name, analysis_mode='depth_limited'), None, action_tooltip_depth, 199)
                if ida_kernwin.register_action(action_desc_depth): aidapal_t.registered_actions.append(action_name_depth)
                else: print(f"Error: Failed to register action: '{action_name_depth}'")


            if not aidapal_t.registered_actions:
                print("aiDAPal Error: [init] No context actions registered. Skipping plugin load."); print("-" * 60); return idaapi.PLUGIN_SKIP
            print(f"aiDAPal DEBUG: [init] Total context actions registered: {len(aidapal_t.registered_actions)}")

            # Install UI hooks for context menu
            print("aiDAPal DEBUG: [init] Installing UI hooks...")
            aidapal_t.hooks = Hooks()
            if not aidapal_t.hooks.hook():
                 print("Error: Failed to install UI hooks."); self._unregister_actions(); aidapal_t.hooks = None; print("-" * 60); return idaapi.PLUGIN_SKIP
            print("aiDAPal DEBUG: [init] UI hooks installed successfully.")

        except Exception as e:
            print(f"aiDAPal Error: [init] Exception during initialization: {e}"); traceback.print_exc()
            print("aiDAPal DEBUG: [init] Cleaning up due to exception..."); self._unregister_actions()
            if aidapal_t.hooks:
                try:
                    aidapal_t.hooks.unhook()
                except Exception:
                    pass
                aidapal_t.hooks = None
            print("-" * 60); return idaapi.PLUGIN_SKIP

        print(f"aiDAPal DEBUG: {self.wanted_name} plugin initialization complete.")
        print("-" * 60)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Called by IDA when running the plugin from the menu (for multi-function analysis)."""
        global g_analysis_in_progress, g_multi_analysis_active
        print(f"aiDAPal DEBUG: {self.wanted_name} run() called (arg={arg}). Triggering multi-function analysis.")

        # --- Concurrency Check ---
        print(f"aiDAPal DEBUG: [run] Acquiring lock...")
        with g_analysis_lock:
            print(f"aiDAPal DEBUG: [run] Lock acquired. Checking concurrency...")
            if g_multi_analysis_active:
                print(f"aiDAPal DEBUG: Multi-analysis already active."); ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function analysis is already running."); return
            if g_analysis_in_progress:
                print(f"aiDAPal DEBUG: Single analysis active: {g_analysis_in_progress}. Blocking multi-analysis."); ida_kernwin.warning(f"{PLUGIN_NAME}: One or more single function analyses are running."); return
            g_multi_analysis_active = True
            print(f"aiDAPal DEBUG: Marked multi-analysis as active. Current single: {g_analysis_in_progress}, Multi active: {g_multi_analysis_active}")
        print(f"aiDAPal DEBUG: [run] Lock released.")

        # --- Get User Input (Main Thread) ---
        input_results = {"start_eas": set(), "caller_depth": -1, "callee_depth": -1}
        input_container = [input_results]
        def get_multi_inputs_main(container):
            try:
                func_list_str = ida_kernwin.ask_str("", 0, "Enter comma-separated function names or addresses (e.g., sub_123, 0x401000, MyFunc)")
                if not func_list_str: return 0
                start_eas, unresolved = set(), []
                items = [item.strip() for item in func_list_str.split(',') if item.strip()]
                if not items: ida_kernwin.warning(f"{PLUGIN_NAME}: No functions provided."); return 0
                for item in items:
                    ea = idaapi.BADADDR
                    if item.lower().startswith("0x"):
                        try: ea = int(item, 16);
                        except ValueError: pass
                    elif item.isdigit():
                         try: ea = int(item);
                         except ValueError: pass
                    if ea == idaapi.BADADDR: ea = ida_name.get_name_ea(idaapi.BADADDR, item)
                    func = ida_funcs.get_func(ea)
                    if func and func.start_ea == ea: start_eas.add(ea)
                    else: unresolved.append(item); print(f"Warning: Could not resolve '{item}' to a function start.")
                if unresolved: ida_kernwin.warning(f"{PLUGIN_NAME}: Could not resolve:\n" + "\n".join(unresolved))
                if not start_eas: print("No valid functions resolved."); ida_kernwin.warning(f"{PLUGIN_NAME}: No valid functions found."); return 0
                container[0]["start_eas"] = start_eas
                print(f"Resolved {len(start_eas)} starting functions.")

                # For multi-start, only ask for CONTEXT depths
                c_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLER_DEPTH, "Enter CONTEXT Caller Depth")
                if c_depth is None: return 0
                container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0
                ca_depth = ida_kernwin.ask_long(DEFAULT_CONTEXT_CALLEE_DEPTH, "Enter CONTEXT Callee/Ref Depth")
                if ca_depth is None: return 0
                container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0
                return 1
            except Exception as e: print(f"Error getting multi input: {e}"); return -1

        sync_status = ida_kernwin.execute_sync(lambda: get_multi_inputs_main(input_container), ida_kernwin.MFF_WRITE)
        start_eas = input_container[0]["start_eas"]
        caller_depth = input_container[0]["caller_depth"]
        callee_depth = input_container[0]["callee_depth"]

        if sync_status != 1 or not start_eas or caller_depth < 0 or callee_depth < 0:
            print("aiDAPal DEBUG: [run] User cancelled input, input failed, or no valid functions.")
            with g_analysis_lock: g_multi_analysis_active = False # Release flag
            return

        # --- Start Background Task ---
        # Multi-start always analyzes the full context (analyze_only_current=False equivalent)
        # Also, don't fetch dref comments for multi-start analysis to keep it simpler.
        print(f"aiDAPal DEBUG: [run] Starting background multi-analysis task for {len(start_eas)} functions...")
        task_thread = threading.Thread(
            target=multi_analysis_task_wrapper,
            args=(start_eas, caller_depth, callee_depth, DEFAULT_GEMINI_MODEL, None) # Pass context depths, model, no dref comments
        )
        task_thread.start()
        print(f"aiDAPal DEBUG: [run] Background thread started.")

    def term(self):
        """Called by IDA when unloading the plugin."""
        print("-" * 60)
        print(f"aiDAPal DEBUG: {self.wanted_name} plugin terminating...")
        print("aiDAPal DEBUG: [term] Uninstalling UI hooks...")
        try:
            if aidapal_t.hooks: aidapal_t.hooks.unhook(); print("  UI hooks uninstalled."); aidapal_t.hooks = None
            else: print("  No UI hooks instance.")
        except Exception as e: print(f"  Error during unhooking: {e}")
        print("aiDAPal DEBUG: [term] Unregistering actions...")
        self._unregister_actions()
        print(f"aiDAPal DEBUG: [term] Closing any tracked UI forms ({len(aiDAPalUI.open_forms)})...")
        forms_to_close = list(aiDAPalUI.open_forms.items())
        for func_ea, form_instance in forms_to_close:
            try: form_instance.Close(0); print(f"  Closed form for 0x{func_ea:X}.")
            except Exception as e: print(f"  Error closing form for 0x{func_ea:X}: {e}"); aiDAPalUI.open_forms.pop(func_ea, None)
        aiDAPalUI.open_forms.clear()
        print("aiDAPal DEBUG: [term] Clearing concurrency state...")
        with g_analysis_lock:
            g_analysis_in_progress.clear()
            global g_multi_analysis_active
            g_multi_analysis_active = False
        print("aiDAPal DEBUG: [term] Concurrency state cleared.")
        print(f"aiDAPal DEBUG: {self.wanted_name} plugin termination complete.")
        print("-" * 60)

    def _unregister_actions(self):
        """Helper to unregister all actions this plugin registered."""
        print(f"aiDAPal DEBUG: [_unregister_actions] Unregistering {len(aidapal_t.registered_actions)} actions...")
        if hasattr(aidapal_t, 'registered_actions'):
            actions_to_unregister = list(aidapal_t.registered_actions)
            for action_name in actions_to_unregister:
                try:
                    if ida_kernwin.unregister_action(action_name): pass # print(f"  Unregistered '{action_name}'.") # Noisy
                    else: print(f"    Warning: Failed to unregister action '{action_name}'.")
                except Exception as e: print(f"    Error unregistering action '{action_name}': {e}")
            aidapal_t.registered_actions = []
            print("aiDAPal DEBUG: [_unregister_actions] Cleared registered actions list.")
        else: print("aiDAPal DEBUG: [_unregister_actions] No 'registered_actions' attribute found.")


# --- Plugin Entry Point ---
def PLUGIN_ENTRY():
    """Required entry point for IDA Pro plugins."""
    print("aiDAPal DEBUG: PLUGIN_ENTRY() called. Returning aidapal_t instance.")
    return aidapal_t()

# --- End of Script ---
print("aiDAPal DEBUG: Script loaded (Integrated Version with Depth-Limited Analysis).")
