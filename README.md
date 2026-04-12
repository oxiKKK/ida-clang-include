# IDAPro Clang Include

Clang Include is an IDA Pro plugin for importing C and C++ header types into Local Types with clang-style parser arguments.

It lets you configure a top-level header, include paths, macros, target, and language standard from a dockable UI inside IDA. Refreshes can use either IDA's in-process parser API or external `idaclang.exe`, update plugin-managed types in place, and avoid the usual TIL reload workflow.

## Layout

- `ida_clang_include.py`: IDA plugin entry file
- `clang_include/`: implementation package

## Install

Copy `ida_clang_include.py` and the `clang_include/` directory into your IDA `plugins/` directory.

## Notes

- Settings are stored per IDB.
- Managed types are refreshed in place to reduce Local Types breakage on repeat imports.
- Existing unmanaged Local Types can be failed, skipped, or updated from the latest parsed header via the plugin options dialog.

