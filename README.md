# Perfect Loader

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

A reference implementation of a perfect in-memory dynamic library loader for Windows.
The implementation may be considered perfect because it does not reimplement `LoadLibrary`, an approach that is inherently incomplete.
Rather, the implementation redirects `LoadLibrary` to use in-memory data, creating a solution that will always have feature parity with the native Windows loader.

This project implements two solutions for redirecting `LoadLibrary`.
The first is based off of [A-Normal-User](https://github.com/A-Normal-User)'s [excellent work](https://github.com/A-Normal-User/MemoryDll-DllRedirect) of redirecting `LoadLibrary` by placing hooks on `NtOpenFile` and `NtMapViewOfSection`.
This project only requires a hook on `NtMapViewOfSection` for most Windows releases, but does require additional hooks to handle [changes made in Windows 11 24H2](https://github.com/EvanMcBroom/perfect-loader/issues/1#issuecomment-2578384262).
[Alex Short](https://twitter.com/alexsho71327477) 
[has a similar approach](https://github.com/rbmm/ARL/tree/main/Load) which also only requires one hook on `NtMapViewOfSection`.
Alex's approach does require you to identify a library without CFG that is larger than the in-memory library you intend to load, but he provides [code to find such a library](https://github.com/rbmm/ARL/blob/fab3ee614702f81ce63f97c3f915c7ecf06e3ed8/Load/loadmem.cpp#L99) and similar code is also provided [in this project's example file](https://github.com/EvanMcBroom/perfect-loader/blob/27ec386e9dc12456e4a5cb8a9878699028b00efc/source/run.cpp#L40).

The second solution uses a similar method to [Process Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf) of updating an opened file in a transaction and using it to create a section object.
The solution differs from [Tal Liberman](https://twitter.com/Tal_Liberman) and [Eugene Kogan](https://twitter.com/eukogan)'s work by redirecting `LoadLibrary` to use the section instead of using the section to create a new process or thread.
To my knowledge, this is a novel approach to using transactions and I personally refer to it as Module Doppelgänging to acknowledge Tal and Eugene's prior work.

## Features

- x86 and x64 support
- Reflectively inject module using manual mapping or Module Doppelgänging
- Hooking using patching or hardware breakpoints
- Disable module load notifications
- Unlink module from loader lists
- Remove or overwrite module headers
- Disable thread callbacks for a module

> :pencil2: The Module Doppelgänging and hardware breakpoint options for injecting a module are currently not supported on WoW64 processes.

## Building

Perfect loader uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.

```
git clone https://github.com/EvanMcBroom/perfect-loader.git
cd perfect-loader/builds
cmake .. -A {Win32 | x64}
cmake --build .
```

By default CMake will build the following:

| Artifact | Description |
| --- | --- |
| `perfect-loader.lib` | The main static library for the project |
| `pl.dll` | A DLL that exposes the functionality of the project as a single exported C API |
| `run.exe` | An example utility which uses the library to load a DLL from memory |
| `testdll.dll` | An example DLL which may be used with the `run.exe` utility |

Other CMake projects may use perfect loader by calling `include` on this directory from an overarching project's `CMakeLists.txt` files.
Doing so will add the static library and the shared library with the C API as CMake targets in the overarching project but will not add the `run` utility or the `testdll` library.
