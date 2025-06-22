# StealthAPI

A lightweight, drop-in C library for dynamic API/syscall resolution and stealth evasion on Windows. It uses hash-based lookups to resolve functions at runtime, remaps and unhooks ntdll for clean syscalls, and patches ETW/AMSI to bypass common detections.

## Features

* **Hash-based string resolution**: djb2, CRC32, Murmur3 algorithms for ASCII names.
* **Dynamic API resolution**: `GetModuleHandleH` & `GetProcAddressH` by hash, no static imports.
* **Syscall table reconstruction**: Build a clean syscall dispatch table using the Whisperer (SW3) technique.
* **ntdll remapping & unhooking**: Load a fresh copy of `ntdll.dll` in-memory and restore original exports.
* **ETW & AMSI patching**: Disable Event Tracing for Windows (ETW) and Antimalware Scan Interface (AMSI) at runtime.
* **Minimal dependencies**: Only requires a few support files and standard Windows headers.

## Repository Layout

```
/                      # Root directory
├── api_hashing.c      # Hashing & dynamic API resolution
├── exports.c          # Syscall resolver, unhook, ETW/AMSI patches
├── strings.c          # String decryption & helper routines
├── whispers.c         # Syscall table builder (SW3)
├── unhook.c           # ntdll mapping & unhooking logic
├── structs.h          # PEB/loader data structures
├── ntdefs.h           # NTSTATUS, OBJECT_ATTRIBUTES, etc.
├── win32api.h         # Win32 API typedefs and function table
├── functions.h        # Internal helper prototypes
├── strings.h          # String helper prototypes
├── whispers.h         # Whisperer prototype definitions
├── unhook.h           # Unhook prototypes
└── CMakeLists.txt     # Build configuration
```

## Dependencies

* Windows SDK (for `<windows.h>`, NT types)
* C compiler supporting C99 or later (tested on MSVC, MinGW)
* CMake ≥ 3.5 (optional, for provided build script)

## Build Instructions

1. Clone the repo:

   ```sh
   git clone https://github.com/callsimba/StealthAPI.git
   cd Stealthapi
   ```
2. Build with CMake:

   ```sh
   mkdir build && cd build
   cmake ..
   cmake --build . --config Release
   ```

   This generates `libapi_hashing.a` and `libexports.a` (or `.lib` on Windows).

## Usage

In your C/C++ project, include the headers and link against the static libraries:

```c
#include "api_hashing.h"
#include "exports.h"

// Example: patch AMSI
if (!PatchAMSI()) {
    // handle failure
}
```

Linker flags:

```
-api_hashing -exports
```

Or, if building directly, compile all `.c` files together:

```sh
cl /O2 api_hashing.c exports.c strings.c whispers.c unhook.c /link /out:RedTeamUtils.lib
```

## Contributing

Contributions, bug reports, and pull requests are welcome! Please open an issue to discuss changes before submitting large patches.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m "Add feature"`)
4. Push to your branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Contact

For questions or feedback, reach out to my telegram @lets_sudosu or open an issue on GitHub.
