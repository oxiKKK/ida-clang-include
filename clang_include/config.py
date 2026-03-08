"""Shared constants and default paths for the Clang Include plugin."""

from pathlib import Path

#
# Constants used across the plugin
#
PLUGIN_NAME = "Clang Include"
PLUGIN_LONG_NAME = "IDAPro Clang Include"
PLUGIN_SLUG = "ida-clang-include"
PLUGIN_ACTION = f"{PLUGIN_SLUG}:open"
# Netnode used to store plugin state and profile data
PLUGIN_NODE = "$ ida_clang_include_plugin"
# Netnode slot used to store the plugin profile blob
SETTINGS_SLOT = 0
# Tag used to store the plugin profile blob in the netnode
SETTINGS_TAG = "S"
ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_IDACLANG = ROOT_DIR / "tools" / "idaclang" / "idaclang.exe"


