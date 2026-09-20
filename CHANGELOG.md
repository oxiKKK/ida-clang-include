# Changelog

## 1.3.0 - 2026-09-20

- Added optional conversion of integer-valued macros into named enum types.
- Added Python- and Clang-based macro discovery, automatic macro grouping, and a workspace for creating and editing custom enums before import.
- Added persistence for macro-enum selections and tests for macro conversion and grouping.

## 1.2.0 - 2026-05-12

- Added user profiles for saving, loading, and managing import configurations.

## 1.1.0 - 2026-04-28

- Added compatibility with IDA 7.x and 8.x and older Qt versions.
- Added structured parser configuration and a raw argument-vector mode.
- Improved the plugin UI and updated its docking and settings-saving behavior.
- Added linting, CI, pre-commit configuration, and Python project metadata.

## 1.0.0 - 2026-04-23

- Initial release.
- Added a dockable interface for importing C and C++ headers into IDA Local Types.
- Added persistent import settings, compiler options, and automatic command-preview updates.
- Added a diff preview for reviewing changes before applying them.
- Added clearer import failure reporting and fixed an issue with importing C structs.
