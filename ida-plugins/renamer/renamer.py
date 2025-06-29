# -*- coding: utf-8 -*-
"""
summary: IDA Pro plugin to rename multiple functions from a formatted string.

description:
  This plugin adds a menu item under "Edit -> Plugins -> Batch Function Renamer".
  When activated, it prompts the user to enter a string of rename operations.

  The expected format is a comma-separated list of "old_name=new_name" pairs.
  For example:
    sub_140011A50=ProcessNetworkPacket,sub_14002B4C0=CalculateChecksum

  The plugin will parse this string and attempt to perform each rename operation.
  It provides a summary report upon completion, detailing successes and failures.

  This is useful for applying a list of function names discovered through
  other tools or analysis, without having to manually rename each one.

Requires:
  - IDA Pro 7.0+ (with Python 3 support)
"""

# --- Imports ---
import ida_kernwin
import ida_name
import idaapi
import idc

# --- Configuration ---
PLUGIN_NAME = "Batch Function Renamer"
PLUGIN_COMMENT = "Rename multiple functions from a formatted list (old_name=new_name,...)"
PLUGIN_HELP = "Enter a comma-separated list of rename operations."
PLUGIN_WANTED_HOTKEY = "" # e.g. "Alt-R"

# --- Main Plugin Class ---

class BatchRenamerPlugin(idaapi.plugin_t):
    """
    The main class for the Batch Function Renamer plugin.
    """
    # Use PLUGIN_FIX to automatically add to the Edit->Plugins menu
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def init(self):
        """
        Called by IDA when the plugin is loaded.
        This is a mandatory method.
        """
        print(f"{PLUGIN_NAME}: Plugin initialized.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Called by IDA when the plugin is run from the menu.
        This is where the main logic of the plugin resides.
        """
        print(f"{PLUGIN_NAME}: Plugin started.")

        # --- 1. Get Input from User ---
        # Provide a default string to show the user the expected format.
        default_input = "sub_140011A50=ProcessNetworkPacket, sub_14002B4C0=CalculateChecksum"

        # Use ida_kernwin.ask_str to get the user's input string.
        input_string = ida_kernwin.ask_str(
            default_input,
            0, # History ID
            f"Enter rename list (old_name=new_name, ...)"
        )

        # If the user cancelled the dialog, input_string will be None.
        if input_string is None:
            print(f"{PLUGIN_NAME}: User cancelled the operation.")
            return

        # If the user provided an empty string, there's nothing to do.
        if not input_string.strip():
            ida_kernwin.warning(f"{PLUGIN_NAME}: Input string was empty.")
            return

        # --- 2. Parse the Input String ---
        rename_operations = []
        malformed_entries = []

        # Split the main string by commas to get individual operations
        operations = input_string.split(',')

        for op in operations:
            op = op.strip()
            if not op:
                continue # Skip empty entries from trailing commas, etc.

            # Split each operation by the equals sign
            parts = op.split('=', 1) # Split only on the first '='

            if len(parts) == 2:
                old_name = parts[0].strip()
                new_name = parts[1].strip()

                # Ensure both names are non-empty after stripping whitespace
                if old_name and new_name:
                    rename_operations.append((old_name, new_name))
                else:
                    malformed_entries.append(op)
            else:
                # The entry did not contain an '='
                malformed_entries.append(op)

        if not rename_operations:
            ida_kernwin.warning(f"{PLUGIN_NAME}: No valid rename operations found in the input.")
            return

        # --- 3. Perform the Renaming ---
        renamed_count = 0
        unfound_names = []
        failed_to_rename = []

        print(f"{PLUGIN_NAME}: Attempting to perform {len(rename_operations)} renames...")

        for old_name, new_name in rename_operations:
            # Find the address (EA) of the function with the old name.
            # We use idaapi.BADADDR to search the entire database.
            target_ea = ida_name.get_name_ea(idaapi.BADADDR, old_name)

            if target_ea == idaapi.BADADDR:
                # The function name was not found in the database.
                print(f"  - FAILED (Not Found): '{old_name}'")
                unfound_names.append(old_name)
                continue

            # Attempt to set the new name at the found address.
            # ida_name.SN_CHECK validates the name to ensure it's a valid identifier.
            # This is the primary API for renaming.
            if ida_name.set_name(target_ea, new_name, ida_name.SN_CHECK):
                print(f"  - SUCCESS: Renamed '{old_name}' to '{new_name}' at 0x{target_ea:X}")
                renamed_count += 1
            else:
                # set_name() failed, likely because the new name is invalid.
                print(f"  - FAILED (Invalid Name): Could not rename '{old_name}' to '{new_name}'")
                failed_to_rename.append(f"'{old_name}' -> '{new_name}'")

        # --- 4. Report the Results to the User ---
        report_lines = [f"{PLUGIN_NAME}: Batch rename complete.\n"]
        report_lines.append(f"Successfully renamed: {renamed_count}")

        if unfound_names:
            report_lines.append(f"\nFunctions not found ({len(unfound_names)}):")
            report_lines.extend([f"  - {name}" for name in unfound_names])

        if failed_to_rename:
            report_lines.append(f"\nFailed to apply new name ({len(failed_to_rename)}):")
            report_lines.extend([f"  - {op}" for op in failed_to_rename])

        if malformed_entries:
            report_lines.append(f"\nMalformed/skipped entries ({len(malformed_entries)}):")
            report_lines.extend([f"  - {entry}" for entry in malformed_entries])

        final_report = "\n".join(report_lines)
        print(f"{PLUGIN_NAME}: Displaying final report.")
        ida_kernwin.info(final_report)


    def term(self):
        """
        Called by IDA when the plugin is unloaded.
        This is a mandatory method.
        """
        print(f"{PLUGIN_NAME}: Plugin terminated.")


# --- Plugin Entry Point ---

def PLUGIN_ENTRY():
    """
    Required entry point for IDA Pro plugins.
    """
    return BatchRenamerPlugin()
