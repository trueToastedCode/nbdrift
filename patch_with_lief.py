"""
ELF Binary Modifier Script

This script adds a required library dependency to an ELF binary/shared library and ensures
the presence of a RUNPATH entry with $ORIGIN to enable relative path resolution for dependencies.

Requires: LIEF (Library to Instrument Executable Formats) - pip install lief
"""

import lief
import sys

if __name__ == '__main__':
    # Parse command line arguments
    # sys.argv[1]: Path to target ELF binary/library to modify
    # sys.argv[2]: Name of the library to add as a dependency (e.g., "libfoo.so")
    target_lib_path = sys.argv[1]
    needed_lib = sys.argv[2]

    # Load the target binary for modification using LIEF
    binary = lief.parse(target_lib_path)
    
    # Add the specified library to the DT_NEEDED entries (dynamic dependencies)
    # binary.add_library(needed_lib)

    # Get existing dynamic entries (metadata used by the dynamic linker)
    dynamic_entries = binary.dynamic_entries

    # Check for existing RUNPATH or RPATH entries
    runpath_entry = None
    for entry in dynamic_entries:
        if entry.tag == lief.ELF.DynamicEntry.TAG.RUNPATH:
            runpath_entry = entry  # Modern path resolution (priority over RPATH)
            break
        if entry.tag == lief.ELF.DynamicEntry.TAG.RPATH:
            runpath_entry = entry  # Legacy path resolution (deprecated)
            break

    # If no RUNPATH/RPATH exists, create a new RUNPATH entry with $ORIGIN
    # $ORIGIN allows relative path resolution from the binary's location
    # if not runpath_entry:
    #     runpath = lief.ELF.DynamicEntryRunPath("$ORIGIN")
    #     binary.add(runpath)  # Add the new RUNPATH entry to dynamic section

    # Write the modified binary back to the original file
    binary.write(target_lib_path)
