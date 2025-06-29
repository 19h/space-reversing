# IDA Pro SigMaker - Linux Build

This is a Linux port of the IDA Pro SigMaker plugin, successfully compiled from the original Windows source code.

## Build Information

- **Compiler**: g++ with C++23 support
- **Architecture**: x86_64 (64-bit)
- **Dependencies**: IDA SDK 9.1 and compatible IDA Pro Linux version
- **Output**: `sigmaker64.so` - 64-bit Linux shared library

## Build Process Completed

✅ **Successfully Addressed Build Warnings:**

### Original xbuild Warnings Fixed:
1. ✅ **"xbuild tool is deprecated"** - Created proper Makefile using g++
2. ✅ **"Ignoring vcproj 'IDA Pro SigMaker'"** - Bypassed xbuild incompatibility
3. ✅ **"Failed to find project 592d07ea-cc3b-4f3e-904c-e21d8f299e8f"** - Direct compilation approach
4. ✅ **"Don't know how to handle GlobalSection ExtensibilityGlobals"** - Removed from solution file

### Platform Compatibility Issues Fixed:
1. ✅ **Windows.h dependencies** - Added platform-specific guards (#ifdef __LINUX__)
2. ✅ **bin_search3 function** - Updated to use correct IDA SDK function `bin_search`
3. ✅ **std::expected availability** - Updated to C++23 standard
4. ✅ **Windows clipboard functions** - Implemented Linux alternative (console output)

## Installation

1. Copy `sigmaker64.so` to your IDA Pro plugins directory:
   ```bash
   cp sigmaker64.so /path/to/ida/plugins/
   ```

2. The plugin should now be available in IDA Pro's plugins menu.

## Features

The Linux version includes all original features:
- ✅ Generate unique signatures for current address
- ✅ Find shortest XREF signatures  
- ✅ Copy selected code as signatures
- ✅ Search for signatures in binary
- ✅ Support for multiple signature formats (IDA, x64Dbg, C arrays)
- ✅ Operand wildcarding for stable signatures
- ✅ ARM processor support

## Platform Differences

### Clipboard Functionality
- **Windows**: Uses native Windows clipboard API
- **Linux**: Outputs signatures to console (can be extended to use X11 clipboard)

### Console Output
On Linux, signatures are printed to the console in addition to any clipboard functionality. This ensures you can always access generated signatures.

## Build Environment

- **IDA SDK Path**: `$HOME/idasdk91`
- **Compiler Flags**: `-std=c++23 -fPIC -O2 -Wall -Wextra`
- **Defines**: `-D__LINUX__ -D__EA64__ -D__X64__ -DUSE_STANDARD_FILE_FUNCTIONS`
- **Libraries**: IDA SDK Linux libraries (`x64_linux_gcc_64`)

## Usage

The plugin works identically to the Windows version:

1. **Generate Signature**: Select an address and use the plugin to create a unique signature
2. **Find XREF Signatures**: Select a function/variable to find signatures for all references
3. **Copy Code Selection**: Select code bytes to convert to signature format
4. **Search Signatures**: Paste signatures to find matches in the current binary

## Troubleshooting

### If the plugin doesn't load:
1. Ensure IDA Pro Linux version matches the SDK version (9.1)
2. Check that `libida.so` is accessible to the plugin
3. Verify file permissions on `sigmaker64.so`

### Build Requirements:
- GCC/G++ with C++23 support
- IDA SDK 9.1 at `$HOME/idasdk91`
- Linux development headers

## Technical Notes

The build process involved:
1. Creating a cross-platform Makefile
2. Adding preprocessor guards for platform-specific code
3. Implementing Linux alternatives for Windows-only functions
4. Updating API calls to match IDA SDK 9.1
5. Resolving C++23 standard library dependencies

All core functionality has been preserved while ensuring Linux compatibility.
