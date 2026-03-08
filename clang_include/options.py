"""Options dialog for advanced Clang Include behavior controls."""

from typing import Any, Dict, Optional

from PySide6 import QtWidgets

from .config import PLUGIN_NAME
from .model import Profile


class OptionsDialog(QtWidgets.QDialog):
    """Dialog that exposes advanced refresh behavior options."""

    def __init__(
        self,
        profile: Profile,
        parent: Optional[QtWidgets.QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{PLUGIN_NAME} Options")
        self.resize(320, 170)

        root = QtWidgets.QVBoxLayout(self)
        tabs = QtWidgets.QTabWidget()
        tabs.setDocumentMode(True)
        root.addWidget(tabs, 1)

        # Keep advanced behavior separate from the main form so the everyday
        # import path stays compact while still allowing detailed control.
        behavior_tab = QtWidgets.QWidget()
        behavior_form = QtWidgets.QFormLayout(behavior_tab)
        behavior_form.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)

        existing_policy = QtWidgets.QComboBox()
        existing_policy.addItem("Fail fast", "fail")
        existing_policy.addItem("Overwrite existing", "overwrite")
        existing_policy.addItem("Skip existing", "skip")

        auto_order = QtWidgets.QComboBox()
        auto_order.addItem("API then external", "api_first")
        auto_order.addItem("External then API", "external_first")

        delete_missing = QtWidgets.QCheckBox(
            "Delete previously managed types that are no longer present in the latest parse result"
        )
        log_external = QtWidgets.QCheckBox("Log external parser stdout/stderr")
        clear_log = QtWidgets.QCheckBox("Clear log before each import")
        show_success = QtWidgets.QCheckBox("Show success dialog after import")
        existing_policy_help = """Controls what happens when the new parse result contains a type name that already exists in Local Types and was not previously managed by this plugin.

"Fail fast" stops the refresh to protect manual work.
"Overwrite existing" removes that Local Type and imports the parsed definition.
"Skip existing" leaves the old Local Type untouched and skips just that name."""
        auto_order_help = """Defines which backend Auto mode tries first.

"API first" prioritizes the built-in IDA parser and only falls back to external parsing if the API fails to produce any types.
"External first" prioritizes the external idaclang parser and only falls back to the API if the external parser fails to produce any types. This is useful when you want to rely primarily on the external parser's behavior if that is more suitable for your project."""
        delete_missing_help = """If enabled, Clang Include removes plugin-managed types that existed in a previous import but are no longer present in the latest parse result.

Enable this when you want Local Types to mirror the current header exactly. Disable it when you want older imported types to remain available."""
        log_external_help = """If enabled, stdout and relevant stderr from external idaclang runs are copied into the log pane.

This is useful for diagnosing parser failures and verifying the exact external tool behavior."""
        clear_log_help = """If enabled, the log pane is cleared before each import starts.

Disable this if you want to compare multiple runs in one continuous log."""
        show_success_help = """If enabled, a success popup is shown after a completed import.

Disable this if you prefer a quieter workflow and rely on the status line and log instead."""

        existing_policy_label = QtWidgets.QLabel("Existing local types")
        auto_order_label = QtWidgets.QLabel("Auto engine order")
        self._set_help(existing_policy, existing_policy_help)
        self._set_help(auto_order, auto_order_help)
        self._set_help(delete_missing, delete_missing_help)
        self._set_help(log_external, log_external_help)
        self._set_help(clear_log, clear_log_help)
        self._set_help(show_success, show_success_help)

        behavior_form.addRow(existing_policy_label, existing_policy)
        behavior_form.addRow(auto_order_label, auto_order)
        behavior_form.addRow("", delete_missing)
        behavior_form.addRow("", log_external)
        behavior_form.addRow("", clear_log)
        behavior_form.addRow("", show_success)
        tabs.addTab(behavior_tab, "Behavior")

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        root.addWidget(buttons)

        self._widgets: Dict[str, QtWidgets.QWidget] = {
            "existing_type_policy": existing_policy,
            "auto_engine_order": auto_order,
            "delete_missing_managed_types": delete_missing,
            "log_external_output": log_external,
            "clear_log_before_import": clear_log,
            "show_success_dialog": show_success,
        }

        existing_policy.setCurrentIndex(
            max(0, existing_policy.findData(profile.existing_type_policy))
        )
        auto_order.setCurrentIndex(
            max(0, auto_order.findData(profile.auto_engine_order))
        )
        delete_missing.setChecked(profile.delete_missing_managed_types)
        log_external.setChecked(profile.log_external_output)
        clear_log.setChecked(profile.clear_log_before_import)
        show_success.setChecked(profile.show_success_dialog)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def _set_help(self, widget: Any, text: str) -> None:
        """Apply the same text to both tooltip and What's This help."""

        widget.setToolTip(text)
        widget.setWhatsThis(text)

    def apply_to_profile(self, profile: Profile) -> Profile:
        """Write the dialog state back into the profile object."""

        profile.existing_type_policy = self._widgets[
            "existing_type_policy"
        ].currentData()
        profile.auto_engine_order = self._widgets["auto_engine_order"].currentData()
        profile.delete_missing_managed_types = self._widgets[
            "delete_missing_managed_types"
        ].isChecked()
        profile.log_external_output = self._widgets["log_external_output"].isChecked()
        profile.clear_log_before_import = self._widgets[
            "clear_log_before_import"
        ].isChecked()
        profile.show_success_dialog = self._widgets["show_success_dialog"].isChecked()
        return profile

