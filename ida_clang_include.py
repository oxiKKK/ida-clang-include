from typing import Any

import ida_idaapi
import ida_kernwin

from clang_include.config import PLUGIN_ACTION, PLUGIN_LONG_NAME, PLUGIN_NAME
from clang_include.manager import ClangIncludeManager
from clang_include.view import ClangIncludeView


class OpenClangIncludeAction(ida_kernwin.action_handler_t):
    """Menu action that opens or focuses the dockable Clang Include window."""

    def __init__(self, plugin: "ClangIncludePlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx: Any) -> int:
        self.plugin.run(0)
        return 1

    def update(self, ctx: Any) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class ClangIncludePlugin(ida_idaapi.plugin_t):
    """IDA plugin entrypoint.

    The main logic lives in the `clang_include` package.
    """

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_LONG_NAME
    help = "Import C/C++ headers into Local Types with clang-compatible settings"
    wanted_name = PLUGIN_LONG_NAME
    wanted_hotkey = ""
    menu_path = "Options/"

    def __init__(self) -> None:
        super().__init__()
        self.manager = None
        self.view = None

    def _ensure_view(self) -> ClangIncludeView:
        if self.manager is None:
            # The manager owns the persistent profile and all sync behavior.
            self.manager = ClangIncludeManager()

        if self.view is None:
            # Build the dockable Qt view lazily, but keep one instance alive so
            # IDA can restore its persisted docking state across sessions.
            self.view = ClangIncludeView(self.manager)

        return self.view

    def init(self) -> int:
        # Register an IDA action so the plugin shows up as a normal menu item
        # under Options.
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                PLUGIN_ACTION,
                "Clang Include...",
                OpenClangIncludeAction(self),
                None,
                self.comment,
                -1,
            )
        )
        ida_kernwin.attach_action_to_menu(self.menu_path, PLUGIN_ACTION, ida_kernwin.SETMENU_APP)
        self._ensure_view().Restore(PLUGIN_NAME)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        self._ensure_view().Show(PLUGIN_NAME)

    def term(self) -> None:
        try:
            # Cleanly unregister the action when IDA unloads the plugin.
            ida_kernwin.detach_action_from_menu(self.menu_path, PLUGIN_ACTION)
            ida_kernwin.unregister_action(PLUGIN_ACTION)
        except Exception:
            pass
        self.view = None
        self.manager = None


def PLUGIN_ENTRY() -> ClangIncludePlugin:
    """Factory function used by IDA to instantiate the plugin."""

    return ClangIncludePlugin()
