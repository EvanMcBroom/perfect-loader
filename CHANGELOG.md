# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-04-30

### Added

- GUI utility for interactive testing
- Section hollowing load method
- Process instrumentation callbacks hook method
- Pre-processing API to remove process instrumentation callbacks
- Pre-processing API to remove vectored exception handlers

### Changed

- Updated project documentation and build instructions for new options and artifacts
- Dynamically resolve `KtmW32` functions to remove its hard dependency for module doppelgänging

### Fixed

- Documentation in source code for what requirement are needed for a usable host dll
- Memory protection logic for manual mapping code to correctly protect regions of memory

## Removed

- Pre/post-processing options from loader flags
- Post-processing API to disabling thread callbacks for a module

## [1.2.2] - 2025-06-18

### Fixed

- Load failures on pre-Windows 11 24H2 hosts

## [1.2.1] - 2025-01-19

### Fixed

- Visual studio 2022 compilation errors

## [1.2.0] - 2025-01-10

### Added

- Support for Windows 11 24H2
- Support for hardware-breakpoint hooks in processes that enable a protected policy to block VEH (ex. Edge)

## [1.1.0] - 2024-12-24

### Added

- Shared library with an exported C API

### Changed

- Build docs updated to list shared library

## [1.0.0] - 2023-09-30

### Added

- Initial public release
- x86/x64 support
- Manual mapping and module doppelgänging load methods
- Detour patching and hardware-breakpoint hook methods
- Loader pre/post-processing options