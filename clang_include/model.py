"""Persistent profile model and IDB-backed storage helpers for Clang Include."""

import json
from dataclasses import asdict, dataclass
from typing import List

import ida_kernwin
import ida_netnode

from .config import (
    DEFAULT_IDACLANG,
    PLUGIN_NAME,
    PLUGIN_NODE,
    SETTINGS_SLOT,
    SETTINGS_TAG,
)


@dataclass
class Profile:
    """Per-IDB configuration and tracked plugin state."""

    header_path: str = ""
    idaclang_path: str = str(DEFAULT_IDACLANG)
    target: str = ""
    language: str = ""
    standard: str = ""
    include_paths: List[str] = None
    macros: List[str] = None
    extra_args: str = ""
    raw_argv: str = ""
    engine: str = "auto"
    existing_type_policy: str = "skip"
    delete_missing_managed_types: bool = False
    auto_engine_order: str = "api_first"
    log_external_output: bool = True
    clear_log_before_import: bool = True
    show_success_dialog: bool = True
    managed_type_names: List[str] = None
    last_engine_used: str = ""

    def __post_init__(self) -> None:
        """Normalize mutable defaults after construction or deserialization."""

        if self.include_paths is None:
            self.include_paths = []
        if self.macros is None:
            self.macros = []
        if self.managed_type_names is None:
            self.managed_type_names = []

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        """Create a profile from persisted JSON while tolerating missing keys."""

        merged = cls()
        field_names = cls.__dataclass_fields__
        for key, value in data.items():
            if key in field_names:
                setattr(merged, key, value)
        merged.__post_init__()
        return merged


class SettingsStore:
    """IDB-backed storage layer for the plugin profile."""

    def __init__(self) -> None:
        self._node = ida_netnode.netnode(PLUGIN_NODE, 0, True)

    def load(self) -> Profile:
        """Load the current profile from the IDB netnode."""

        blob = self._node.getblob(SETTINGS_SLOT, SETTINGS_TAG)
        if not blob:
            return Profile()

        try:
            return Profile.from_dict(json.loads(blob.decode("utf-8")))
        except Exception:
            ida_kernwin.msg(
                f"{PLUGIN_NAME}: failed to load settings, using defaults.\n"
            )
            return Profile()

    def save(self, profile: Profile) -> None:
        """Persist the current profile into the IDB netnode."""

        blob = json.dumps(asdict(profile), indent=2).encode("utf-8")
        self._node.setblob(blob, SETTINGS_SLOT, SETTINGS_TAG)

