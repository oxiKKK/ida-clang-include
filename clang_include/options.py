"""Options dialog for advanced Clang Include behavior controls."""

from typing import Any, Dict, Optional

from PySide6 import QtWidgets

from .config import PLUGIN_NAME
from .model import Profile


PARSER_VALUE_FIELDS = (
    (
        "idaclang_tilname",
        "Result TIL path",
        "Optional value for --idaclang-tilname. If set, the parser may also write a TIL file to this path.",
        "C:/temp/out.til",
    ),
    (
        "idaclang_tildesc",
        "TIL description",
        "Optional value for --idaclang-tildesc. Sets a custom description on a parser-generated TIL file.",
        "Imported project SDK types",
    ),
    (
        "idaclang_macros_path",
        "Macro defs path",
        "Optional value for --idaclang-macros. Points the parser at a macrodefs file.",
        "C:/temp/macrodefs.txt",
    ),
    (
        "idaclang_smptrs",
        "Smart pointer templates",
        "Optional value for --idaclang-smptrs. Use a semicolon-separated list of smart pointer template names.",
        "CComPtr;wil::com_ptr;std::unique_ptr",
    ),
    (
        "idaclang_mangle_format",
        "Mangling format",
        "Optional value for --idaclang-mangle-format, for example n, _n, or n_.",
        "_n",
    ),
)

PARSER_BOOL_FIELDS = (
    (
        "idaclang_opaqify_objc",
        "Opaqify Objective-C id/SEL",
        "Adds --idaclang-opaqify-objc. Converts Objective-C id and SEL types to opaque pointers.",
    ),
    (
        "idaclang_extra_c_mangling",
        "Add extra C-style mangling",
        "Adds --idaclang-extra-c-mangling. When compiling as C++, also emit C-like mangled names for functions.",
    ),
    (
        "idaclang_parse_static",
        "Parse internal-linkage functions",
        "Adds --idaclang-parse-static to include functions with internal linkage.",
    ),
)

LOGGING_FIELDS = (
    (
        "idaclang_log_warnings",
        "Log clang warnings",
        "Adds --idaclang-log-warnings. Warnings are printed by the parser into IDA's output window.",
    ),
    (
        "idaclang_log_ast",
        "Log AST nodes",
        "Adds --idaclang-log-ast. AST nodes are printed into IDA's output window.",
    ),
    (
        "idaclang_log_macros",
        "Log macro definitions",
        "Adds --idaclang-log-macros. Macro definitions are printed into IDA's output window.",
    ),
    (
        "idaclang_log_predefined",
        "Log predefined macros",
        "Adds --idaclang-log-predefined. Predefined libclang macros are printed into IDA's output window.",
    ),
    (
        "idaclang_log_udts",
        "Log UDT mismatches",
        "Adds --idaclang-log-udts. Warn when a UDT type does not match clang's AST.",
    ),
    (
        "idaclang_log_files",
        "Log included files",
        "Adds --idaclang-log-files. Included translation-unit files are printed into IDA's output window.",
    ),
    (
        "idaclang_log_argv",
        "Log resolved parser argv",
        "Adds --idaclang-log-argv. The fully resolved parser command line is printed into IDA's output window.",
    ),
    (
        "idaclang_log_target",
        "Log target platform details",
        "Adds --idaclang-log-target. Target platform details are printed into IDA's output window.",
    ),
)


class OptionsDialog(QtWidgets.QDialog):
    """Dialog that exposes advanced refresh behavior options."""

    def __init__(
        self,
        profile: Profile,
        parent: Optional[QtWidgets.QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{PLUGIN_NAME} Options")
        self.resize(560, 520)

        root = QtWidgets.QVBoxLayout(self)
        tabs = QtWidgets.QTabWidget()
        tabs.setDocumentMode(True)
        root.addWidget(tabs, 1)

        behavior_tab = QtWidgets.QWidget()
        behavior_form = QtWidgets.QFormLayout(behavior_tab)
        behavior_form.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)

        existing_policy = QtWidgets.QComboBox()
        existing_policy.addItem("Fail fast", "fail")
        existing_policy.addItem("Update existing from header", "update")
        existing_policy.addItem("Skip existing", "skip")
        auto_order = QtWidgets.QComboBox()
        auto_order.addItem("API then external", "api_first")
        auto_order.addItem("External then API", "external_first")
        delete_missing = QtWidgets.QCheckBox(
            "Delete previously managed types that are no longer present in the latest parse result"
        )
        log_external = QtWidgets.QCheckBox("Copy external parser stdout/stderr into the log pane")
        clear_log = QtWidgets.QCheckBox("Clear log before each import")
        show_success = QtWidgets.QCheckBox("Show success dialog after import")

        existing_policy_help = """Controls what happens when the new parse result contains a type name that already exists in Local Types and was not previously managed by this plugin.

"Fail fast" stops the refresh to protect manual work.
    "Update existing from header" replaces that Local Type with the parsed definition and adopts it into the plugin-managed set.
"Skip existing" leaves the old Local Type untouched and skips just that name."""
        auto_order_help = """Defines which backend Auto mode tries first.

"API then external" prioritizes ida_srclang and falls back to external idaclang if API parsing fails.
"External then API" prioritizes external idaclang and falls back to ida_srclang if external parsing fails."""
        delete_missing_help = """If enabled, Clang Include removes plugin-managed types that existed in a previous import but are no longer present in the latest parse result.

Enable this when you want Local Types to mirror the current header exactly. Disable it when you want older imported types to remain available."""
        log_external_help = """If enabled, external idaclang stdout and stderr are copied into the Clang Include log tab.

Disable this if you only want to see external parser output in IDA's output window."""
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

        parser_tab = QtWidgets.QWidget()
        parser_form = QtWidgets.QFormLayout(parser_tab)
        parser_form.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
        parser_note = QtWidgets.QLabel(
            "These switches apply to the external idaclang backend. The API parser ignores them."
        )
        parser_note.setWordWrap(True)
        parser_form.addRow(parser_note)
        parser_widgets: Dict[str, QtWidgets.QWidget] = {}
        for key, label_text, help_text, placeholder in PARSER_VALUE_FIELDS:
            widget = QtWidgets.QLineEdit()
            widget.setPlaceholderText(placeholder)
            self._set_help(widget, help_text)
            parser_form.addRow(QtWidgets.QLabel(label_text), widget)
            parser_widgets[key] = widget
        for key, label_text, help_text in PARSER_BOOL_FIELDS:
            widget = QtWidgets.QCheckBox(label_text)
            self._set_help(widget, help_text)
            parser_form.addRow("", widget)
            parser_widgets[key] = widget
        tabs.addTab(parser_tab, "Parser")

        logging_tab = QtWidgets.QWidget()
        logging_layout = QtWidgets.QVBoxLayout(logging_tab)
        logging_layout.setContentsMargins(12, 12, 12, 12)
        logging_layout.setSpacing(8)
        logging_note = QtWidgets.QLabel(
            "These logging switches apply to the external idaclang backend. The API parser will not receive them."
        )
        logging_note.setWordWrap(True)
        logging_layout.addWidget(logging_note)
        logging_all = QtWidgets.QCheckBox("Enable all parser logging")
        self._set_help(
            logging_all,
            "Adds --idaclang-log-all. All parser logging is printed into IDA's output window.",
        )
        logging_layout.addWidget(logging_all)
        logging_widgets: Dict[str, QtWidgets.QWidget] = {"idaclang_log_all": logging_all}
        for key, label_text, help_text in LOGGING_FIELDS:
            widget = QtWidgets.QCheckBox(label_text)
            self._set_help(widget, help_text)
            logging_layout.addWidget(widget)
            logging_widgets[key] = widget
        logging_layout.addStretch(1)
        tabs.addTab(logging_tab, "Logging")

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        root.addWidget(buttons)

        self._widgets: Dict[str, QtWidgets.QWidget] = {
            "existing_type_policy": existing_policy,
            "auto_engine_order": auto_order,
            "delete_missing_managed_types": delete_missing,
            "log_external_output": log_external,
            "clear_log_before_import": clear_log,
            "show_success_dialog": show_success,
            **parser_widgets,
            **logging_widgets,
        }
        self._logging_option_keys = [key for key, _, _ in LOGGING_FIELDS]

        current_policy = profile.existing_type_policy
        if current_policy == "overwrite":
            current_policy = "update"
        existing_policy.setCurrentIndex(max(0, existing_policy.findData(current_policy)))
        auto_order.setCurrentIndex(max(0, auto_order.findData(profile.auto_engine_order)))
        delete_missing.setChecked(profile.delete_missing_managed_types)
        log_external.setChecked(profile.log_external_output)
        clear_log.setChecked(profile.clear_log_before_import)
        show_success.setChecked(profile.show_success_dialog)

        for key, _label_text, _help_text, _placeholder in PARSER_VALUE_FIELDS:
            self._widgets[key].setText(getattr(profile, key, ""))
        for key, _label_text, _help_text in PARSER_BOOL_FIELDS:
            self._widgets[key].setChecked(getattr(profile, key, False))
        logging_all.setChecked(profile.idaclang_log_all)
        for key in self._logging_option_keys:
            self._widgets[key].setChecked(getattr(profile, key, False))

        logging_all.toggled.connect(self._sync_logging_controls)
        self._sync_logging_controls(logging_all.isChecked())
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def _set_help(self, widget: Any, text: str) -> None:
        """Apply the same text to both tooltip and What's This help."""

        widget.setToolTip(text)
        widget.setWhatsThis(text)

    def _sync_logging_controls(self, enabled: bool) -> None:
        """Disable individual logging toggles when log-all is selected."""

        for key in self._logging_option_keys:
            self._widgets[key].setEnabled(not enabled)

    def apply_to_profile(self, profile: Profile) -> Profile:
        """Write the dialog state back into the profile object."""

        profile.existing_type_policy = self._widgets["existing_type_policy"].currentData()
        profile.auto_engine_order = self._widgets["auto_engine_order"].currentData()
        profile.delete_missing_managed_types = self._widgets["delete_missing_managed_types"].isChecked()
        profile.log_external_output = self._widgets["log_external_output"].isChecked()
        profile.clear_log_before_import = self._widgets["clear_log_before_import"].isChecked()
        profile.show_success_dialog = self._widgets["show_success_dialog"].isChecked()

        for key, _label_text, _help_text, _placeholder in PARSER_VALUE_FIELDS:
            profile.__dict__[key] = self._widgets[key].text().strip()
        for key, _label_text, _help_text in PARSER_BOOL_FIELDS:
            profile.__dict__[key] = self._widgets[key].isChecked()

        profile.idaclang_log_all = self._widgets["idaclang_log_all"].isChecked()
        for key in self._logging_option_keys:
            profile.__dict__[key] = self._widgets[key].isChecked()
        return profile
