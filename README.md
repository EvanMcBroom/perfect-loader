# Perfect Loader

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

A reference implementation of a perfect in-memory dynamic library loader for Windows.
The implementation may be considered perfect because it does not reimplement `LoadLibrary`, an approach that is inherently incomplete.
Rather, the implementation redirects `LoadLibrary` to use in-memory data, creating a solution that will always have feature parity with the native Windows loader.

The project implements two solutions for redirecting `LoadLibrary`.
The first is based off of [A-Normal-User](https://github.com/A-Normal-User)'s [excellent work](https://github.com/A-Normal-User/MemoryDll-DllRedirect) of redirecting `LoadLibrary` by placing hooks on `NtOpenFile` and `NtMapViewOfSection`.
Although redirecting `LoadLibrary` by placing hooks on native functions has been previously documented in various malware reports, [A-Normal-User](https://github.com/A-Normal-User)'s approach is unique in that it only requires two hooks.
[Alex Short](https://twitter.com/alexsho71327477)
[has a similar approach](https://github.com/rbmm/Load) which only requires one hook, but it was not used because it requires creating a file.

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

By default CMake will build both the `perfect-loader` static library it uses, an example utility named `run` which uses the library, and a dynamic library named `testdll` which may be used with the example.

Other CMake projects may use perfect loader by calling `include` on this directory from an overarching project's `CMakeLists.txt` files.
Doing so will add the static library as a CMake target in the overarching project but will not add the `run` utility or the `testdll` library.