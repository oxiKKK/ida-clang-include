"""Dockable Qt view for configuring and running Clang Include imports."""

import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import ida_kernwin
import idaapi

from .config import COMMON_LANGUAGES, COMMON_STANDARDS, COMMON_TARGETS, DEFAULT_IDACLANG, PLUGIN_NAME
from .diff import SyncDiffDialog
from .manager import ClangIncludeManager
from .model import Profile
from .options import OptionsDialog

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6 import QtWidgets, QtCore
else:
    from PyQt5 import QtWidgets, QtCore


class ClangIncludeView(ida_kernwin.PluginForm):
    """Dockable UI for configuring imports and running refreshes."""

    WINDOW_TITLE = PLUGIN_NAME

    def __init__(self, manager: ClangIncludeManager) -> None:
        super().__init__()
        self.manager = manager
        self.parent: Optional[QtWidgets.QWidget] = None
        self._widgets: Dict[str, QtWidgets.QWidget] = {}
        self._preview_refresh_timer: Optional[QtCore.QTimer] = None
        self._suspend_preview_refresh = False
        self.manager.log_message.connect(self._append_log)

    def OnCreate(self, form: Any) -> None:
        """Create the Qt widget tree when IDA instantiates the dockable form."""

        self.parent = self.FormToPyQtWidget(form)
        self._build_ui()
        self._load_profile(self.manager.profile)

    def OnClose(self, form: Any) -> None:
        self.parent = None

    def Show(self, caption: str) -> None:
        ida_kernwin.PluginForm.Show(
            self,
            caption,
            options=(ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_PERSIST),
        )

    def Restore(self, caption: str) -> None:
        ida_kernwin.PluginForm.Show(
            self,
            caption,
            options=(ida_kernwin.PluginForm.WOPN_RESTORE | ida_kernwin.PluginForm.WOPN_PERSIST),
        )

    def _build_ui(self) -> None:
        """Construct the dockable window.

        The layout intentionally keeps the everyday settings compact while
        giving multi-line parser inputs and logs enough space to be usable.
        """

        root = QtWidgets.QVBoxLayout()
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        # Help text is defined inline because it also serves as a small design
        # inventory for what each field is expected to communicate.
        header_help = """Top-level header file that Clang Include will parse and import into Local Types.

Use the one umbrella header that represents the type set you want in this IDB. Refreshes always start from this file."""
        idaclang_help = """Path to the external idaclang executable used by the external parser backend.

    This is used when Engine is set to External or when Auto falls back to external parsing."""
        header_edit, header_row = self._path_row(self._browse_header, header_help)
        idaclang_edit, idaclang_row = self._path_row(self._browse_idaclang, idaclang_help)

        engine_combo = QtWidgets.QComboBox()
        engine_combo.addItem("Auto", "auto")
        engine_combo.addItem("IDA parser API only", "api")
        engine_combo.addItem("External idaclang only", "external")
        self._set_help(
            engine_combo,
            """Selects which parsing backend to use.

    Auto tries the preferred order from Options. API uses ida_srclang only. External runs idaclang.exe and loads the generated TIL.""",
        )

        target_combo = self._make_editable_combo(COMMON_TARGETS)
        language_combo = self._make_editable_combo(COMMON_LANGUAGES)
        standard_combo = self._make_editable_combo(COMMON_STANDARDS)
        target_combo.lineEdit().setPlaceholderText("Target triplet (leave blank for none)")
        language_combo.lineEdit().setPlaceholderText("Language (leave blank for none)")
        standard_combo.lineEdit().setPlaceholderText("Language standard, e.g. c11 or c++20 (leave blank for none)")
        self._set_help(
            target_combo,
            """Optional target triple passed to the parser, for example i686-pc-windows-msvc or x86_64-pc-windows-msvc.

Leave it empty to omit -target entirely. This controls ABI-sensitive layout decisions such as calling conventions, builtin type sizes, and some compiler defaults.""",
        )
        self._set_help(
            language_combo,
            """Optional source language passed with -x, such as c++ or c.

Leave it empty to omit -x. The API parser still defaults to C++ internally when no language is given.""",
        )
        self._set_help(
            standard_combo,
            """Optional language standard passed to the parser, for example c++17, c++20, or c11.

Leave it empty to omit -std entirely. Change this if the header depends on syntax or library behavior from a specific language version.""",
        )

        includes_edit = self._make_large_editor("One include path per line")
        macros_edit = self._make_large_editor("One macro per line, e.g. _WIN32 or FOO=1")
        extra_args_edit = self._make_large_editor("Extra parser args, e.g. -fms-extensions")
        argv_editor = self._make_large_editor("Edit parser argv directly", read_only=False, no_wrap=False)
        preview_edit = self._make_large_editor("Resolved command preview", read_only=True, no_wrap=False)
        self._set_help(
            argv_editor,
            """Full parser argv. This pane replaces the structured editors while Raw mode is active and is the exact argument list the parser receives.""",
        )
        self._set_help(
            includes_edit,
            """Additional include search paths, one directory per line.

These become -I arguments. Add every project, SDK, and toolchain include directory needed for the header to parse successfully.""",
        )
        self._set_help(
            macros_edit,
            """Preprocessor defines, one per line.

Each line becomes a -D argument. You can write bare flags like _WIN32 or assignments like FOO=1.""",
        )
        self._set_help(
            extra_args_edit,
            """Extra parser arguments appended after the structured fields.

Use this for switches such as -fms-extensions, warning suppressions, forced compatibility flags, or anything not covered by the UI.""",
        )
        self._set_help(
            preview_edit,
            """Resolved parser command preview, available in Structured mode only. Raw mode replaces this pane with the editable argv on the left.""",
        )

        mode_structured_radio = QtWidgets.QRadioButton("Structured")
        mode_raw_radio = QtWidgets.QRadioButton("Raw argv")
        mode_button_group = QtWidgets.QButtonGroup(self.parent)
        mode_button_group.addButton(mode_structured_radio)
        mode_button_group.addButton(mode_raw_radio)
        mode_hint = QtWidgets.QLabel("")
        mode_hint.setWordWrap(True)
        self._set_help(
            mode_structured_radio,
            "Compose argv from the include paths, macros, target, language, std, and extra-args fields.",
        )
        self._set_help(
            mode_raw_radio,
            "Edit the full parser argv directly in the right pane. Structured fields and parser-options-dialog switches are ignored.",
        )
        mode_row = QtWidgets.QHBoxLayout()
        mode_row.setContentsMargins(0, 0, 0, 0)
        mode_row.setSpacing(8)
        mode_row.addWidget(QtWidgets.QLabel("Mode:"))
        mode_row.addWidget(mode_structured_radio)
        mode_row.addWidget(mode_raw_radio)
        mode_row.addWidget(mode_hint, 1)

        profile_row = QtWidgets.QHBoxLayout()
        profile_combo = QtWidgets.QComboBox()
        profile_combo.setEditable(True)
        profile_combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        profile_combo.lineEdit().setPlaceholderText("Pick a profile, or type a new name to create one")
        profile_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        profile_load_button = QtWidgets.QPushButton("Load")
        profile_save_button = QtWidgets.QPushButton("Save")
        profile_remove_button = QtWidgets.QPushButton("Remove")
        self._set_help(
            profile_combo,
            """Cross-IDB profiles stored on disk under the IDA user dir.

Pick an existing profile to Load/Remove, or type a new name and hit Save to create one. The list is the same across every IDB on this machine.""",
        )
        self._set_help(
            profile_load_button,
            "Apply the selected global profile to the current IDB. Per-IDB state (managed type names, last engine used) is preserved.",
        )
        self._set_help(
            profile_save_button,
            """Save the current settings as a global profile under the name shown to the left.

If the name matches an existing profile it is overwritten after confirmation. Otherwise a new profile is created.""",
        )
        self._set_help(
            profile_remove_button,
            "Delete the selected global profile from disk. The current IDB's settings are not changed.",
        )
        profile_row.addWidget(QtWidgets.QLabel("Profile:"))
        profile_row.addWidget(profile_combo, 1)
        profile_row.addWidget(profile_load_button)
        profile_row.addWidget(profile_save_button)
        profile_row.addWidget(profile_remove_button)

        button_row = QtWidgets.QHBoxLayout()
        save_button = QtWidgets.QPushButton("Save")
        options_button = QtWidgets.QPushButton("Options")
        import_button = QtWidgets.QPushButton("Import / Refresh")
        clear_log_button = QtWidgets.QPushButton("Clear Log")
        button_row.addWidget(save_button)
        button_row.addWidget(options_button)
        button_row.addWidget(import_button)
        button_row.addWidget(clear_log_button)
        button_row.addStretch(1)

        status_label = QtWidgets.QLabel()
        status_label.setWordWrap(True)
        log_edit = self._make_large_editor("", read_only=True)
        log_edit.setMaximumBlockCount(5000)
        self._set_help(
            log_edit,
            """Import log output.

This shows status messages, parser execution details, overwrite/skip decisions, and any errors reported during refresh.""",
        )

        settings_group = QtWidgets.QGroupBox("Import Settings")
        settings_layout = QtWidgets.QGridLayout(settings_group)
        settings_layout.setColumnStretch(1, 1)
        settings_layout.setColumnStretch(3, 1)
        header_label = QtWidgets.QLabel("Header")
        idaclang_label = QtWidgets.QLabel("IDAClang")
        engine_label = QtWidgets.QLabel("Engine")
        target_label = QtWidgets.QLabel("Target")
        language_label = QtWidgets.QLabel("Language")
        standard_label = QtWidgets.QLabel("Std")
        settings_layout.addWidget(header_label, 0, 0)
        settings_layout.addWidget(header_row, 0, 1, 1, 3)
        settings_layout.addWidget(idaclang_label, 1, 0)
        settings_layout.addWidget(idaclang_row, 1, 1, 1, 3)
        settings_layout.addWidget(engine_label, 2, 0)
        settings_layout.addWidget(engine_combo, 2, 1)
        settings_layout.addWidget(target_label, 2, 2)
        settings_layout.addWidget(target_combo, 2, 3)
        settings_layout.addWidget(language_label, 3, 0)
        settings_layout.addWidget(language_combo, 3, 1)
        settings_layout.addWidget(standard_label, 3, 2)
        settings_layout.addWidget(standard_combo, 3, 3)

        # The left side contains editable parser inputs. The right side contains
        # derived output and logs so the preview behaves like a companion pane
        # instead of yet another stacked form field.
        editors_tabs = QtWidgets.QTabWidget()
        editors_tabs.setDocumentMode(True)
        editors_tabs.addTab(includes_edit, "Includes")
        editors_tabs.addTab(macros_edit, "Macros")
        editors_tabs.addTab(extra_args_edit, "Extra Args")

        # The left pane swaps wholesale between the structured editor tabs and
        # the single argv editor depending on the active mode.
        left_stack = QtWidgets.QStackedWidget()
        left_stack.addWidget(editors_tabs)
        left_stack.addWidget(argv_editor)
        left_stack.setMinimumWidth(420)

        output_tabs = QtWidgets.QTabWidget()
        output_tabs.setDocumentMode(True)
        output_tabs.addTab(preview_edit, "Preview")
        output_tabs.addTab(log_edit, "Log")
        editors_tabs.setTabToolTip(
            0,
            "Project, SDK, and toolchain include directories that will be passed as -I arguments.",
        )
        editors_tabs.setTabToolTip(
            1,
            "Preprocessor defines that will be passed as -D arguments.",
        )
        editors_tabs.setTabToolTip(
            2,
            "Extra clang arguments. e.g. '-fms-extensions -Wno-some-warning'. See the preview window for a preview.",
        )
        output_tabs.setTabToolTip(
            0,
            "Resolved argv in Structured mode (read-only); editable argv in Raw mode.",
        )
        output_tabs.setTabToolTip(
            1,
            "Status log for saves, imports, parser output, and errors.",
        )

        body_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        body_splitter.addWidget(left_stack)
        body_splitter.addWidget(output_tabs)
        body_splitter.setChildrenCollapsible(False)
        body_splitter.setStretchFactor(0, 3)
        body_splitter.setStretchFactor(1, 2)

        root.addLayout(profile_row)
        root.addLayout(button_row)
        root.addWidget(status_label)
        root.addWidget(settings_group)
        root.addLayout(mode_row)
        root.addWidget(body_splitter, 1)
        self.parent.setLayout(root)

        # So that the preview gets updated live.
        self._preview_refresh_timer = QtCore.QTimer(self.parent)
        self._preview_refresh_timer.setSingleShot(True)
        self._preview_refresh_timer.timeout.connect(self._refresh_preview)

        self._widgets = {
            "header_path": header_edit,
            "idaclang_path": idaclang_edit,
            "engine": engine_combo,
            "target": target_combo,
            "language": language_combo,
            "standard": standard_combo,
            "include_paths": includes_edit,
            "macros": macros_edit,
            "extra_args": extra_args_edit,
            "argv_editor": argv_editor,
            "preview": preview_edit,
            "log": log_edit,
            "output_tabs": output_tabs,
            "left_stack": left_stack,
            "status": status_label,
            "save": save_button,
            "options": options_button,
            "import": import_button,
            "clear_log": clear_log_button,
            "mode_structured": mode_structured_radio,
            "mode_raw": mode_raw_radio,
            "mode_hint": mode_hint,
            "profile_combo": profile_combo,
            "profile_load": profile_load_button,
            "profile_save": profile_save_button,
            "profile_remove": profile_remove_button,
        }
        # Field labels we toggle alongside their inputs so they dim too.
        self._structured_labels = (target_label, language_label, standard_label)
        # Cached so _on_mode_changed can pre-fill raw_argv from the resolved
        # structured preview when the user first switches to Raw mode.
        self._raw_argv_cache = self.manager.profile.raw_argv

        save_button.clicked.connect(self._save_profile)
        options_button.clicked.connect(self._open_options)
        import_button.clicked.connect(self._run_sync)
        clear_log_button.clicked.connect(log_edit.clear)
        profile_load_button.clicked.connect(self._load_global_profile)
        profile_save_button.clicked.connect(self._save_global_profile)
        profile_remove_button.clicked.connect(self._remove_global_profile)
        profile_combo.editTextChanged.connect(self._refresh_profile_buttons)
        profile_combo.currentIndexChanged.connect(self._refresh_profile_buttons)
        self._refresh_profile_list()

        for key in ("header_path", "idaclang_path"):
            self._widgets[key].textChanged.connect(self._schedule_preview_refresh)
        for key in ("target", "language", "standard"):
            self._widgets[key].editTextChanged.connect(self._schedule_preview_refresh)
            self._widgets[key].currentIndexChanged.connect(self._schedule_preview_refresh)
        for key in ("include_paths", "macros", "extra_args"):
            self._widgets[key].textChanged.connect(self._schedule_preview_refresh)
        engine_combo.currentIndexChanged.connect(self._schedule_preview_refresh)
        mode_structured_radio.toggled.connect(self._on_mode_changed)

    def _make_large_editor(
        self, placeholder: str, read_only: bool = False, no_wrap: bool = True
    ) -> QtWidgets.QPlainTextEdit:
        """Create a consistently-sized editor used throughout the window."""

        editor = QtWidgets.QPlainTextEdit()
        editor.setPlaceholderText(placeholder)
        editor.setReadOnly(read_only)
        editor.setMaximumBlockCount(2000)
        editor.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap if no_wrap else QtWidgets.QPlainTextEdit.WidgetWidth)
        editor.setMinimumHeight(220)
        return editor

    def _make_editable_combo(self, items: List[str]) -> QtWidgets.QComboBox:
        """Create an editable combo box with optional predefined values."""

        combo = QtWidgets.QComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        combo.addItems(items)
        return combo

    def _path_row(
        self,
        callback: Callable[[], None],
        help_text: str,
    ) -> Tuple[QtWidgets.QLineEdit, QtWidgets.QWidget]:
        """Create a path field paired with a browse button."""

        row = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        edit = QtWidgets.QLineEdit()
        button = QtWidgets.QPushButton("Browse")
        button.setMaximumWidth(90)
        button.clicked.connect(callback)
        self._set_help(edit, help_text)
        self._set_help(
            button,
            f"{help_text}\n\nClick to choose the path with a file picker instead of typing it manually.",
        )
        self._set_help(row, help_text)
        layout.addWidget(edit, 1)
        layout.addWidget(button)
        return edit, row

    def _set_help(self, widget: Any, text: str) -> None:
        """Apply the same text to both tooltip and What's This help."""

        widget.setToolTip(text)
        widget.setWhatsThis(text)

    def _load_profile(self, profile: Profile) -> None:
        """Populate the UI from the currently saved profile."""

        self._suspend_preview_refresh = True
        self._widgets["header_path"].setText(profile.header_path)
        self._widgets["idaclang_path"].setText(profile.idaclang_path)
        self._widgets["target"].setCurrentText(profile.target)
        self._widgets["language"].setCurrentText(profile.language)
        self._widgets["standard"].setCurrentText(profile.standard)
        self._widgets["include_paths"].setPlainText("\n".join(profile.include_paths))
        self._widgets["macros"].setPlainText("\n".join(profile.macros))
        self._widgets["extra_args"].setPlainText(profile.extra_args)
        index = self._widgets["engine"].findData(profile.engine)
        if index >= 0:
            self._widgets["engine"].setCurrentIndex(index)
        self._raw_argv_cache = profile.raw_argv
        self._widgets["argv_editor"].setPlainText(profile.raw_argv)
        is_raw = profile.input_mode == "raw"
        # Block the toggled signal during initial load so we don't trigger the
        # interactive switch logic before the rest of the form is populated.
        self._widgets["mode_structured"].blockSignals(True)
        self._widgets["mode_raw"].blockSignals(True)
        self._widgets["mode_structured"].setChecked(not is_raw)
        self._widgets["mode_raw"].setChecked(is_raw)
        self._widgets["mode_structured"].blockSignals(False)
        self._widgets["mode_raw"].blockSignals(False)
        self._apply_mode_ui(is_raw)
        self._suspend_preview_refresh = False
        self._widgets["status"].setText(self._status_text(profile))
        self._refresh_preview()

    def _collect_profile(self) -> Profile:
        """Read the current UI state back into a profile object."""

        is_raw = self._widgets["mode_raw"].isChecked()
        # In Raw mode the dedicated argv editor IS the argv. In Structured mode
        # we keep whatever raw_argv the user previously had, so toggling Raw ->
        # Structured -> Raw round-trips losslessly.
        raw_argv = self._widgets["argv_editor"].toPlainText().strip() if is_raw else self._raw_argv_cache
        return Profile(
            header_path=self._widgets["header_path"].text().strip(),
            idaclang_path=self._widgets["idaclang_path"].text().strip() or str(DEFAULT_IDACLANG),
            target=self._widgets["target"].currentText().strip(),
            language=self._widgets["language"].currentText().strip(),
            standard=self._widgets["standard"].currentText().strip(),
            include_paths=self._split_lines(self._widgets["include_paths"].toPlainText()),
            macros=self._split_lines(self._widgets["macros"].toPlainText()),
            extra_args=self._widgets["extra_args"].toPlainText().strip(),
            raw_argv=raw_argv,
            input_mode="raw" if is_raw else "structured",
            engine=self._widgets["engine"].currentData(),
            auto_engine_order=self.manager.profile.auto_engine_order,
            log_external_output=self.manager.profile.log_external_output,
            idaclang_tilname=self.manager.profile.idaclang_tilname,
            idaclang_tildesc=self.manager.profile.idaclang_tildesc,
            idaclang_macros_path=self.manager.profile.idaclang_macros_path,
            idaclang_smptrs=self.manager.profile.idaclang_smptrs,
            idaclang_mangle_format=self.manager.profile.idaclang_mangle_format,
            idaclang_opaqify_objc=self.manager.profile.idaclang_opaqify_objc,
            idaclang_extra_c_mangling=self.manager.profile.idaclang_extra_c_mangling,
            idaclang_parse_static=self.manager.profile.idaclang_parse_static,
            idaclang_log_warnings=self.manager.profile.idaclang_log_warnings,
            idaclang_log_ast=self.manager.profile.idaclang_log_ast,
            idaclang_log_macros=self.manager.profile.idaclang_log_macros,
            idaclang_log_predefined=self.manager.profile.idaclang_log_predefined,
            idaclang_log_udts=self.manager.profile.idaclang_log_udts,
            idaclang_log_files=self.manager.profile.idaclang_log_files,
            idaclang_log_argv=self.manager.profile.idaclang_log_argv,
            idaclang_log_target=self.manager.profile.idaclang_log_target,
            idaclang_log_all=self.manager.profile.idaclang_log_all,
            existing_type_policy=self.manager.profile.existing_type_policy,
            delete_missing_managed_types=self.manager.profile.delete_missing_managed_types,
            clear_log_before_import=self.manager.profile.clear_log_before_import,
            show_success_dialog=self.manager.profile.show_success_dialog,
            managed_type_names=list(self.manager.profile.managed_type_names),
            last_engine_used=self.manager.profile.last_engine_used,
        )

    def _save_profile(self) -> None:
        """Persist the current form state without running an import."""

        try:
            profile = self._collect_profile()
            self.manager.save_profile(profile)
            self._widgets["status"].setText(self._status_text(profile))
            self._refresh_preview()
        except Exception as exc:
            ida_kernwin.warning(str(exc))

    def _open_options(self) -> None:
        """Open the advanced options dialog and persist accepted changes."""

        profile = self._collect_profile()
        dialog = OptionsDialog(profile, self.parent)
        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return
        updated = dialog.apply_to_profile(profile)
        self.manager.save_profile(updated)
        self._load_profile(updated)

    def _refresh_profile_list(self, select_name: Optional[str] = None) -> None:
        """Repopulate the global-profile combobox from disk."""

        combo = self._widgets["profile_combo"]
        previous = select_name if select_name is not None else combo.currentText()
        try:
            names = self.manager.list_global_profiles()
        except Exception as exc:
            self._append_log(f"Failed to list global profiles: {exc}")
            names = []
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(names)
        if previous:
            idx = combo.findText(previous)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            else:
                combo.setEditText(previous)
        else:
            combo.setEditText("")
        combo.blockSignals(False)
        self._refresh_profile_buttons()

    def _refresh_profile_buttons(self, *_args: Any) -> None:
        """Enable/disable Load/Save/Remove based on the current combobox text.

        Load/Remove require an exact match with a saved profile. Save just
        requires a non-empty name; whether it overwrites or creates is decided
        at click time.
        """

        combo = self._widgets["profile_combo"]
        text = combo.currentText().strip()
        is_saved = bool(text) and combo.findText(text) >= 0
        self._widgets["profile_load"].setEnabled(is_saved)
        self._widgets["profile_remove"].setEnabled(is_saved)
        self._widgets["profile_save"].setEnabled(bool(text))

    def _load_global_profile(self) -> None:
        """Apply the selected global profile to the current IDB."""

        name = self._widgets["profile_combo"].currentText().strip()
        if not name:
            return
        confirm = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            f"Are you sure? Loading {name!r} will overwrite this IDB's current settings.",
        )
        if confirm != ida_kernwin.ASKBTN_YES:
            return
        try:
            self.manager.apply_global_profile(name)
        except Exception as exc:
            self._notify_failure("Load global profile failed", exc)
            return
        self._load_profile(self.manager.profile)

    def _save_global_profile(self) -> None:
        """Save the current UI state as a global profile under the typed name."""

        combo = self._widgets["profile_combo"]
        name = combo.currentText().strip()
        if not name:
            return

        is_overwrite = combo.findText(name) >= 0
        if is_overwrite:
            confirm = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                f"Overwrite global profile {name!r}?",
            )
            if confirm != ida_kernwin.ASKBTN_YES:
                return

        try:
            profile = self._collect_profile()
            self.manager.save_global_profile(name, profile)
        except Exception as exc:
            self._notify_failure("Save global profile failed", exc)
            return
        self._refresh_profile_list(select_name=name)

    def _remove_global_profile(self) -> None:
        """Delete the selected global profile from disk."""

        name = self._widgets["profile_combo"].currentText().strip()
        if not name:
            return
        confirm = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            f"Are you sure? This will permanently delete global profile {name!r} from disk.",
        )
        if confirm != ida_kernwin.ASKBTN_YES:
            return
        try:
            self.manager.delete_global_profile(name)
        except Exception as exc:
            self._notify_failure("Delete global profile failed", exc)
            return
        self._refresh_profile_list(select_name="")

    def _run_sync(self) -> None:
        """Execute one parse/import cycle from the current form values."""

        profile = self._collect_profile()
        prepared = None
        try:
            if profile.clear_log_before_import:
                self._widgets["log"].clear()

            ida_kernwin.show_wait_box("HIDECANCEL\nClang Include: parsing headers and preparing change preview...")
            prepared = self.manager.prepare_sync(profile)
        except Exception as exc:
            self._append_log(traceback.format_exc())
            self._notify_failure("Parsing failed", exc)
            return
        finally:
            ida_kernwin.hide_wait_box()

        apply_failed = False
        try:
            dialog = SyncDiffDialog(prepared.plan, self.parent)
            if dialog.exec() != QtWidgets.QDialog.Accepted:
                self.manager.log("Import canceled from change preview dialog.")
                return

            ida_kernwin.show_wait_box("HIDECANCEL\nClang Include: applying previewed Local Types changes...")
            result = self.manager.apply_prepared_sync(profile, prepared)
            self._widgets["status"].setText(
                f"Last import used {self.manager._engine_label(result.engine)}. Managed types: {len(result.type_names)}"
            )
            if profile.show_success_dialog:
                ida_kernwin.info(
                    f"{PLUGIN_NAME} imported {len(result.type_names)} managed types using {self.manager._engine_label(result.engine)}."
                )
        except Exception as exc:
            apply_failed = True
            self._append_log(traceback.format_exc())
            self._notify_failure("Import failed", exc)
        finally:
            self.manager.release_prepared_sync(prepared)
            ida_kernwin.hide_wait_box()
            self._refresh_preview(update_status=not apply_failed)

    def _notify_failure(self, title: str, exc: Exception) -> None:
        """Show a visible failure notification and focus the log pane."""

        message = str(exc).strip() or exc.__class__.__name__
        self._widgets["status"].setText(f"{title}: {message}")

        output_tabs = self._widgets.get("output_tabs")
        log_widget = self._widgets.get("log")
        if isinstance(output_tabs, QtWidgets.QTabWidget) and log_widget is not None:
            output_tabs.setCurrentWidget(log_widget)

        self._append_log(f"{title}: {message}")
        ida_kernwin.warning(f"{PLUGIN_NAME}: {title}.\n\n{message}")

    def _refresh_preview(self, update_status: bool = True) -> None:
        """Refresh the derived command preview and status summary.

        In Raw mode the preview pane is the argv input itself, so we leave it
        alone; only the status line gets recomputed.
        """

        profile = self._collect_profile()
        if profile.input_mode != "raw":
            try:
                preview = self.manager.build_preview_command(profile)
            except Exception as exc:
                preview = f"Failed to build preview: {exc}"
            self._widgets["preview"].setPlainText(preview)
        if update_status:
            self._widgets["status"].setText(self._status_text(profile))

    def _on_mode_changed(self, _checked: bool) -> None:
        """React to the user toggling Structured vs Raw mode."""

        if self._suspend_preview_refresh:
            return

        is_raw = self._widgets["mode_raw"].isChecked()
        if is_raw:
            # Seed the argv editor: prefer the user's previous raw text, fall
            # back to the currently-resolved structured argv as a starting
            # point so they don't have to type from scratch.
            seed = self._raw_argv_cache.strip()
            if not seed:
                profile = self._collect_profile_for_preview_only()
                try:
                    seed = self.manager.build_preview_command(profile)
                except Exception:
                    seed = ""
            self._widgets["argv_editor"].setPlainText(seed)
        else:
            # Leaving Raw mode: capture the user's edits so a later toggle back
            # to Raw restores them.
            self._raw_argv_cache = self._widgets["argv_editor"].toPlainText().strip()
        self._apply_mode_ui(is_raw)
        self._refresh_preview()

    def _collect_profile_for_preview_only(self) -> Profile:
        """Snapshot the form as if it were Structured mode, for argv seeding."""

        # Force structured mode + empty raw_argv so build_preview_command
        # returns the resolved structured argv regardless of current state.
        profile = self._collect_profile()
        profile.input_mode = "structured"
        profile.raw_argv = ""
        return profile

    def _apply_mode_ui(self, is_raw: bool) -> None:
        """Reshape the panes and disable/enable inputs for the active mode."""

        # Top-row structured fields stay visible but dim in Raw mode.
        for key in ("target", "language", "standard"):
            self._widgets[key].setEnabled(not is_raw)
        for label in self._structured_labels:
            label.setEnabled(not is_raw)

        # Left pane: structured tabs vs single argv editor.
        self._widgets["left_stack"].setCurrentIndex(1 if is_raw else 0)

        # Right pane: drop the Preview tab in Raw mode (the argv lives on the
        # left there); restore it when returning to Structured. removeTab does
        # not destroy the widget, so the cached preview_edit reference stays
        # valid.
        output_tabs = self._widgets["output_tabs"]
        preview = self._widgets["preview"]
        preview_index = output_tabs.indexOf(preview)
        if is_raw and preview_index >= 0:
            output_tabs.removeTab(preview_index)
        elif not is_raw and preview_index < 0:
            output_tabs.insertTab(0, preview, "Preview")
            output_tabs.setTabToolTip(0, "Resolved argv preview (read-only).")

        self._widgets["mode_hint"].setText(
            "Structured fields are ignored. Edit the argv in the left pane." if is_raw else ""
        )

        # Bring the relevant pane on the right to the front so the user can
        # see what just changed (Preview in Structured, Log in Raw).
        if is_raw:
            output_tabs.setCurrentWidget(self._widgets["log"])
        else:
            output_tabs.setCurrentWidget(preview)

    def _schedule_preview_refresh(self, *_args: Any) -> None:
        """Coalesce field edits so the preview updates immediately and consistently."""

        if self._suspend_preview_refresh or self._preview_refresh_timer is None:
            return
        self._preview_refresh_timer.start(0)

    def _status_text(self, profile: Profile) -> str:
        """Build the one-line status summary shown above the settings."""

        managed = len(profile.managed_type_names)
        policy = self._policy_label(profile.existing_type_policy)
        stale_mode = "delete stale" if profile.delete_missing_managed_types else "keep stale"
        if profile.last_engine_used:
            return (
                f"Managed types: {managed}. Last engine: {self.manager._engine_label(profile.last_engine_used)}. "
                f"Existing-type policy: {policy}. {stale_mode}."
            )
        return (
            f"Managed types: {managed}. Engine: {self.manager._engine_label(profile.engine)}. "
            f"Existing-type policy: {policy}. {stale_mode}."
        )

    def _policy_label(self, value: str) -> str:
        """Render stored policy values into human-readable status text."""

        labels = {
            "fail": "fail fast",
            "overwrite": "update existing",
            "update": "update existing",
            "skip": "skip existing",
        }
        return labels.get(value, value)

    def _append_log(self, message: str) -> None:
        """Append a new line to the visible log pane if the form exists."""

        if not self.parent:
            return
        self._widgets["log"].appendPlainText(message)

    def _browse_header(self) -> None:
        """Prompt for the top-level header file."""

        current = self._widgets["header_path"].text().strip()
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.parent,
            "Select Header",
            current or str(Path.cwd()),
            "Headers (*.h *.hpp *.hh *.hxx);;All Files (*)",
        )
        if path:
            self._widgets["header_path"].setText(path)

    def _browse_idaclang(self) -> None:
        """Prompt for the external idaclang executable path."""

        current = self._widgets["idaclang_path"].text().strip()
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.parent,
            "Select idaclang executable",
            current or str(DEFAULT_IDACLANG),
            "Executables (*.exe);;All Files (*)",
        )
        if path:
            self._widgets["idaclang_path"].setText(path)

    def _split_lines(self, text: str) -> List[str]:
        """Normalize multi-line editor input into a compact list of values."""

        return [line.strip() for line in text.splitlines() if line.strip()]
