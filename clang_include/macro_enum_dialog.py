"""Editor for the exact macro enum definitions imported into IDA."""

import copy
import re
from typing import Any, Dict, List, Optional, Sequence

import idaapi

from .config import PLUGIN_NAME
from .macro_conversion import parse_integer_literal
from .macro_grouping import (
    allocate_member_names,
    enum_definitions_error,
    group_tree_parents,
    is_c_identifier,
    macro_member_id,
    new_definition_id,
    new_member_id,
)

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6 import QtCore, QtWidgets

    EXTENDED_SELECTION = QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
    SELECT_ROWS = QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
    DIALOG_ACCEPTED = QtWidgets.QDialog.DialogCode.Accepted
    DIALOG_CANCEL = QtWidgets.QDialogButtonBox.StandardButton.Cancel
    DIALOG_OK = QtWidgets.QDialogButtonBox.StandardButton.Ok
    HORIZONTAL = QtCore.Qt.Orientation.Horizontal
    USER_ROLE = QtCore.Qt.ItemDataRole.UserRole
else:
    from PyQt5 import QtCore, QtWidgets

    EXTENDED_SELECTION = QtWidgets.QAbstractItemView.ExtendedSelection
    SELECT_ROWS = QtWidgets.QAbstractItemView.SelectRows
    DIALOG_ACCEPTED = QtWidgets.QDialog.Accepted
    DIALOG_CANCEL = QtWidgets.QDialogButtonBox.Cancel
    DIALOG_OK = QtWidgets.QDialogButtonBox.Ok
    HORIZONTAL = QtCore.Qt.Horizontal
    USER_ROLE = QtCore.Qt.UserRole


class _CustomMemberDialog(QtWidgets.QDialog):
    def __init__(self, member: Optional[dict] = None, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Custom enum value")
        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()
        self.name = QtWidgets.QLineEdit(str((member or {}).get("name", "")))
        self.literal = QtWidgets.QLineEdit(str((member or {}).get("literal", "")))
        self.literal.setPlaceholderText("0, 0x10, -1, 077, 0b1010, 42U")
        form.addRow("Member name", self.name)
        form.addRow("Integer value", self.literal)
        layout.addLayout(form)
        buttons = QtWidgets.QDialogButtonBox()
        buttons.addButton(DIALOG_OK)
        buttons.addButton(DIALOG_CANCEL)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if not is_c_identifier(self.name.text().strip()):
            QtWidgets.QMessageBox.warning(self, "Invalid name", "Enter a valid C identifier.")
            return
        try:
            if parse_integer_literal(self.literal.text().strip()) is None:
                raise ValueError("Enter a supported C integer literal.")
        except ValueError as exc:
            QtWidgets.QMessageBox.warning(self, "Invalid value", str(exc))
            return
        self.accept()

    def member(self, existing_id: str = "") -> dict:
        literal = self.literal.text().strip()
        parsed = parse_integer_literal(literal)
        if parsed is None:
            raise ValueError("Enter a supported C integer literal.")
        value, width, signed = parsed
        name = self.name.text().strip()
        return {
            "id": existing_id or new_member_id(),
            "kind": "custom",
            "name": name,
            "emitted_name": name,
            "literal": literal,
            "value": value,
            "width": width,
            "signed": signed,
        }


class MacroEnumDialog(QtWidgets.QDialog):
    """Transactionally edit the enum definitions that will be imported."""

    def __init__(
        self,
        definitions: Sequence[dict],
        suggestions: Sequence[dict],
        macros: Sequence[Any],
        parent: Optional[QtWidgets.QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._macros = {macro.name: macro for macro in macros}
        self._names = sorted(self._macros, key=str.casefold)
        self._suggestions = [dict(suggestion) for suggestion in suggestions]
        self._definitions = [self._normalize_definition(copy.deepcopy(item)) for item in definitions]
        allocate_member_names(self._definitions)
        self._current_definition_id = ""
        self._refreshing = False

        self.setWindowTitle(f"{PLUGIN_NAME} Macro Enums")
        self.resize(1280, 780)
        root = QtWidgets.QVBoxLayout(self)
        intro = QtWidgets.QLabel(
            "Build the exact enum types to import. Add detected groups, create enums from raw macros, "
            "or create an empty enum and add custom values. Changes are committed only when you continue."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)
        splitter = QtWidgets.QSplitter(HORIZONTAL)
        root.addWidget(splitter, 1)

        left = QtWidgets.QTabWidget()
        splitter.addWidget(left)

        detected = QtWidgets.QWidget()
        detected_layout = QtWidgets.QVBoxLayout(detected)
        detected_help = QtWidgets.QLabel(
            "Detected groups are suggestions. Select one or more rows and explicitly add them to the enum workspace."
        )
        detected_help.setWordWrap(True)
        detected_layout.addWidget(detected_help)
        detected_filter_row = QtWidgets.QHBoxLayout()
        self._suggestion_filter = QtWidgets.QLineEdit()
        self._suggestion_filter.setPlaceholderText("Filter detected groups or macros...")
        expand = QtWidgets.QPushButton("Expand All")
        collapse = QtWidgets.QPushButton("Collapse All")
        detected_filter_row.addWidget(self._suggestion_filter, 1)
        detected_filter_row.addWidget(expand)
        detected_filter_row.addWidget(collapse)
        detected_layout.addLayout(detected_filter_row)
        self._suggestion_tree = QtWidgets.QTreeWidget()
        self._suggestion_tree.setHeaderLabels(["Detected group", "Macros", "State"])
        self._suggestion_tree.setSelectionMode(EXTENDED_SELECTION)
        self._suggestion_tree.setSelectionBehavior(SELECT_ROWS)
        self._suggestion_tree.setAlternatingRowColors(True)
        detected_layout.addWidget(self._suggestion_tree, 1)
        detected_buttons = QtWidgets.QHBoxLayout()
        self._add_selected = QtWidgets.QPushButton("Add Selected Groups")
        self._add_all = QtWidgets.QPushButton("Add All Detected Groups")
        detected_buttons.addWidget(self._add_selected)
        detected_buttons.addWidget(self._add_all)
        detected_buttons.addStretch(1)
        detected_layout.addLayout(detected_buttons)
        left.addTab(detected, "Detected Groups")

        raw = QtWidgets.QWidget()
        raw_layout = QtWidgets.QVBoxLayout(raw)
        raw_help = QtWidgets.QLabel(
            "Select any macros. Create a new enum from them, or add them to the enum currently selected on the right."
        )
        raw_help.setWordWrap(True)
        raw_layout.addWidget(raw_help)
        raw_filter_row = QtWidgets.QHBoxLayout()
        self._raw_filter = QtWidgets.QLineEdit()
        self._raw_filter.setPlaceholderText("Filter raw macros...")
        select_visible = QtWidgets.QPushButton("Select All Visible")
        clear_selection = QtWidgets.QPushButton("Clear Selection")
        raw_filter_row.addWidget(self._raw_filter, 1)
        raw_filter_row.addWidget(select_visible)
        raw_filter_row.addWidget(clear_selection)
        raw_layout.addLayout(raw_filter_row)
        self._raw = QtWidgets.QTreeWidget()
        self._raw.setHeaderLabels(["Macro", "Value", "Used by"])
        self._raw.setSelectionMode(EXTENDED_SELECTION)
        self._raw.setSelectionBehavior(SELECT_ROWS)
        self._raw.setAlternatingRowColors(True)
        raw_layout.addWidget(self._raw, 1)
        raw_name_row = QtWidgets.QHBoxLayout()
        self._raw_enum_name = QtWidgets.QLineEdit()
        self._raw_enum_name.setPlaceholderText("MACRO_MY_ENUM")
        self._create_from_raw = QtWidgets.QPushButton("Create Enum from Selection")
        self._add_to_enum = QtWidgets.QPushButton("Add to Selected Enum")
        raw_name_row.addWidget(QtWidgets.QLabel("New enum name"))
        raw_name_row.addWidget(self._raw_enum_name, 1)
        raw_name_row.addWidget(self._create_from_raw)
        raw_name_row.addWidget(self._add_to_enum)
        raw_layout.addLayout(raw_name_row)
        left.addTab(raw, "Raw Macros")

        workspace = QtWidgets.QWidget()
        workspace_layout = QtWidgets.QVBoxLayout(workspace)
        title = QtWidgets.QLabel("Enums to import")
        title.setStyleSheet("font-weight: bold")
        workspace_layout.addWidget(title)
        workspace_help = QtWidgets.QLabel(
            "This is the authoritative import plan. Select an enum to edit its name and ordered members."
        )
        workspace_help.setWordWrap(True)
        workspace_layout.addWidget(workspace_help)
        self._enum_list = QtWidgets.QListWidget()
        self._enum_list.setAlternatingRowColors(True)
        workspace_layout.addWidget(self._enum_list, 1)
        enum_buttons = QtWidgets.QHBoxLayout()
        self._new_enum = QtWidgets.QPushButton("New Empty Enum")
        self._delete_enum = QtWidgets.QPushButton("Delete Selected Enum")
        enum_buttons.addWidget(self._new_enum)
        enum_buttons.addWidget(self._delete_enum)
        enum_buttons.addStretch(1)
        workspace_layout.addLayout(enum_buttons)
        name_form = QtWidgets.QFormLayout()
        self._enum_name = QtWidgets.QLineEdit()
        name_form.addRow("Enum name", self._enum_name)
        workspace_layout.addLayout(name_form)
        self._members = QtWidgets.QTreeWidget()
        self._members.setHeaderLabels(["Member", "Value", "Source", "Status"])
        self._members.setSelectionMode(EXTENDED_SELECTION)
        self._members.setSelectionBehavior(SELECT_ROWS)
        self._members.setAlternatingRowColors(True)
        workspace_layout.addWidget(self._members, 2)
        member_buttons = QtWidgets.QHBoxLayout()
        self._add_custom = QtWidgets.QPushButton("Add Custom Value")
        self._edit_custom = QtWidgets.QPushButton("Edit Custom Value")
        self._remove_member = QtWidgets.QPushButton("Remove Selected Members")
        self._move_up = QtWidgets.QPushButton("Move Up")
        self._move_down = QtWidgets.QPushButton("Move Down")
        for button in (self._add_custom, self._edit_custom, self._remove_member, self._move_up, self._move_down):
            member_buttons.addWidget(button)
        member_buttons.addStretch(1)
        workspace_layout.addLayout(member_buttons)
        splitter.addWidget(workspace)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        buttons = QtWidgets.QDialogButtonBox()
        buttons.addButton(DIALOG_OK)
        buttons.addButton(DIALOG_CANCEL)
        buttons.button(DIALOG_OK).setText("Continue to Preview")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        expand.clicked.connect(self._suggestion_tree.expandAll)
        collapse.clicked.connect(self._suggestion_tree.collapseAll)
        self._suggestion_filter.textChanged.connect(self._filter_suggestions)
        self._suggestion_tree.itemSelectionChanged.connect(self._sync_buttons)
        self._add_selected.clicked.connect(self._add_selected_suggestions)
        self._add_all.clicked.connect(self._add_all_suggestions)
        self._raw_filter.textChanged.connect(self._filter_raw)
        select_visible.clicked.connect(self._select_all_visible)
        clear_selection.clicked.connect(self._raw.clearSelection)
        self._raw.itemSelectionChanged.connect(self._sync_buttons)
        self._raw_enum_name.textChanged.connect(self._sync_buttons)
        self._create_from_raw.clicked.connect(self._create_from_raw_selection)
        self._add_to_enum.clicked.connect(self._add_raw_to_current)
        self._enum_list.currentItemChanged.connect(self._enum_changed)
        self._enum_name.textEdited.connect(self._enum_name_edited)
        self._enum_name.editingFinished.connect(self._refresh_raw)
        self._members.itemSelectionChanged.connect(self._sync_buttons)
        self._new_enum.clicked.connect(self._create_empty_enum)
        self._delete_enum.clicked.connect(self._delete_current_enum)
        self._add_custom.clicked.connect(self._add_custom_member)
        self._edit_custom.clicked.connect(self._edit_custom_member)
        self._remove_member.clicked.connect(self._remove_selected_members)
        self._move_up.clicked.connect(lambda: self._move_member(-1))
        self._move_down.clicked.connect(lambda: self._move_member(1))

        self._refresh_all()

    def enum_definitions(self) -> List[dict]:
        return copy.deepcopy(self._definitions)

    def _normalize_definition(self, definition: dict) -> dict:
        definition_id = str(definition.get("id") or new_definition_id())
        definition["id"] = definition_id
        definition.setdefault("owner_key", f"enum:{definition_id}")
        definition.setdefault("origin", "custom")
        definition.setdefault("source_pattern", "")
        normalized = []
        for source in definition.get("members", []):
            member = dict(source)
            if member.get("kind") == "custom":
                member.setdefault("id", new_member_id())
                member.setdefault("emitted_name", str(member.get("name", "")))
                literal = str(member.get("literal", member.get("value", "")))
                parsed = parse_integer_literal(literal)
                if parsed is not None:
                    value, width, signed = parsed
                    member.update(
                        {
                            "literal": literal,
                            "value": value,
                            "width": width,
                            "signed": signed,
                        }
                    )
                normalized.append(member)
                continue
            name = str(member.get("source_name", ""))
            if not name:
                continue
            member["kind"] = "macro"
            member.setdefault("id", macro_member_id(definition_id, name))
            member.setdefault("emitted_name", name)
            macro = self._macros.get(name)
            if macro is None:
                member["missing"] = True
                member.setdefault("last_value", 0)
                member.setdefault("width", 4)
                member.setdefault("enum_bte", 0)
                member.setdefault("enum_attrs", 0)
            else:
                member.update(
                    {
                        "last_value": macro.value,
                        "width": macro.enum_width,
                        "enum_bte": macro.enum_bte,
                        "enum_attrs": macro.enum_attrs,
                        "missing": False,
                    }
                )
            normalized.append(member)
        definition["members"] = normalized
        return definition

    def _definition(self, definition_id: str = "") -> Optional[dict]:
        wanted = definition_id or self._current_definition_id
        return next((item for item in self._definitions if item["id"] == wanted), None)

    def _available_enum_name(self, base: str) -> str:
        """Return *base* or the first unused numeric variant."""

        used = {item["enum_name"] for item in self._definitions}
        if base not in used:
            return base
        suffix = 2
        while f"{base}_{suffix}" in used:
            suffix += 1
        return f"{base}_{suffix}"

    def _new_definition_record(self, enum_name: str, origin: str, pattern: str = "") -> dict:
        """Create one empty persistent workspace definition."""

        definition_id = new_definition_id()
        return {
            "id": definition_id,
            "owner_key": f"enum:{definition_id}",
            "enum_name": enum_name,
            "origin": origin,
            "source_pattern": pattern,
            "members": [],
        }

    def _macro_member(self, definition: dict, name: str) -> dict:
        macro = self._macros[name]
        return {
            "id": macro_member_id(definition["id"], name),
            "kind": "macro",
            "source_name": name,
            "emitted_name": name,
            "last_value": macro.value,
            "width": macro.enum_width,
            "enum_bte": macro.enum_bte,
            "enum_attrs": macro.enum_attrs,
            "missing": False,
        }

    def _refresh_all(self) -> None:
        allocate_member_names(self._definitions)
        self._refreshing = True
        current_id = self._current_definition_id
        self._refresh_suggestions()
        self._refresh_raw()
        self._enum_list.clear()
        current_row = -1
        for row, definition in enumerate(self._definitions):
            item = QtWidgets.QListWidgetItem(definition["enum_name"])
            item.setData(USER_ROLE, definition["id"])
            count = len(definition.get("members", []))
            item.setToolTip(f"{count} member(s); {definition.get('origin', 'custom')}")
            self._enum_list.addItem(item)
            if definition["id"] == current_id:
                current_row = row
        if current_row < 0 and self._definitions:
            current_row = 0
        if current_row >= 0:
            self._enum_list.setCurrentRow(current_row)
            self._current_definition_id = str(self._enum_list.currentItem().data(USER_ROLE))
        else:
            self._current_definition_id = ""
        self._refresh_current_editor()
        self._refreshing = False
        self._filter_suggestions(self._suggestion_filter.text())
        self._filter_raw(self._raw_filter.text())
        self._sync_buttons()

    def _refresh_suggestions(self) -> None:
        self._suggestion_tree.clear()
        nodes = []
        for index, suggestion in enumerate(self._suggestions):
            names = self._suggestion_names(suggestion)
            existing = self._definition_for_suggestion(suggestion)
            existing_names = {
                member.get("source_name")
                for member in (existing or {}).get("members", [])
                if member.get("kind") == "macro"
            }
            new_count = len(set(names) - existing_names)
            state = "Available"
            if existing and new_count:
                state = f"Added; {new_count} new"
            elif existing:
                state = "Added"
            node = QtWidgets.QTreeWidgetItem([str(suggestion.get("enum_name", "")), str(len(names)), state])
            node.setData(0, USER_ROLE, ("suggestion", index))
            node.setToolTip(0, str(suggestion.get("pattern", "")))
            for name in names:
                macro = self._macros[name]
                child = QtWidgets.QTreeWidgetItem([name, str(macro.value), ""])
                child.setData(0, USER_ROLE, ("macro", index))
                node.addChild(child)
            nodes.append(node)
        parents = group_tree_parents([str(item.get("enum_name", "")) for item in self._suggestions])
        for index, node in enumerate(nodes):
            parent = parents[index]
            if parent is None:
                self._suggestion_tree.addTopLevelItem(node)
            else:
                nodes[parent].addChild(node)

    def _refresh_raw(self) -> None:
        selected = {str(item.data(0, USER_ROLE)) for item in self._raw.selectedItems()}
        self._raw.clear()
        uses: Dict[str, List[str]] = {}
        for definition in self._definitions:
            for member in definition.get("members", []):
                if member.get("kind") == "macro":
                    uses.setdefault(str(member.get("source_name", "")), []).append(definition["enum_name"])
        for name in self._names:
            macro = self._macros[name]
            item = QtWidgets.QTreeWidgetItem([name, str(macro.value), ", ".join(uses.get(name, []))])
            item.setData(0, USER_ROLE, name)
            self._raw.addTopLevelItem(item)
            item.setSelected(name in selected)

    def _refresh_current_editor(self) -> None:
        definition = self._definition()
        self._members.clear()
        self._enum_name.blockSignals(True)
        self._enum_name.setText(definition["enum_name"] if definition else "")
        self._enum_name.blockSignals(False)
        self._enum_name.setEnabled(definition is not None)
        if definition:
            for member in definition.get("members", []):
                if member.get("kind") == "custom":
                    name = str(member.get("name", ""))
                    value = str(member.get("literal", member.get("value", 0)))
                    source, status = "Custom", ""
                else:
                    name = str(member.get("emitted_name") or member.get("source_name", ""))
                    value = str(member.get("last_value", 0))
                    source = str(member.get("source_name", ""))
                    status = "Missing; using last value" if member.get("missing") else "Macro"
                item = QtWidgets.QTreeWidgetItem([name, value, source, status])
                item.setData(0, USER_ROLE, member["id"])
                self._members.addTopLevelItem(item)

    def _suggestion_names(self, suggestion: dict) -> List[str]:
        try:
            matcher = re.compile(str(suggestion.get("pattern", "")))
        except re.error:
            return []
        return [name for name in self._names if matcher.search(name)]

    def _definition_for_suggestion(self, suggestion: dict) -> Optional[dict]:
        pattern = str(suggestion.get("pattern", ""))
        return next(
            (
                item
                for item in self._definitions
                if item.get("origin") == "detected" and item.get("source_pattern") == pattern
            ),
            None,
        )

    def _filter_suggestions(self, text: str) -> None:
        needle = text.strip().casefold()

        def visit(item: QtWidgets.QTreeWidgetItem) -> bool:
            child_match = any(visit(item.child(index)) for index in range(item.childCount()))
            own = not needle or needle in " ".join(item.text(column) for column in range(3)).casefold()
            item.setHidden(not own and not child_match)
            if needle and child_match:
                item.setExpanded(True)
            return own or child_match

        for index in range(self._suggestion_tree.topLevelItemCount()):
            visit(self._suggestion_tree.topLevelItem(index))

    def _filter_raw(self, text: str) -> None:
        needle = text.strip().casefold()
        for row in range(self._raw.topLevelItemCount()):
            item = self._raw.topLevelItem(row)
            item.setHidden(bool(needle) and needle not in " ".join(item.text(column) for column in range(3)).casefold())

    def _select_all_visible(self) -> None:
        self._raw.blockSignals(True)
        for row in range(self._raw.topLevelItemCount()):
            item = self._raw.topLevelItem(row)
            if not item.isHidden():
                item.setSelected(True)
        self._raw.blockSignals(False)
        self._sync_buttons()

    def _selected_suggestion_indices(self) -> List[int]:
        indices = set()
        for item in self._suggestion_tree.selectedItems():
            data = item.data(0, USER_ROLE)
            if data:
                indices.add(int(data[1]))
        return sorted(indices)

    def _add_suggestions(self, indices: Sequence[int]) -> None:
        for index in indices:
            suggestion = self._suggestions[index]
            names = self._suggestion_names(suggestion)
            definition = self._definition_for_suggestion(suggestion)
            if definition is None:
                enum_name = self._available_enum_name(str(suggestion.get("enum_name", "")))
                definition = self._new_definition_record(
                    enum_name,
                    "detected",
                    str(suggestion.get("pattern", "")),
                )
                self._definitions.append(definition)
            existing = {member.get("source_name") for member in definition["members"] if member.get("kind") == "macro"}
            definition["members"].extend(self._macro_member(definition, name) for name in names if name not in existing)
            self._current_definition_id = definition["id"]
        self._refresh_all()

    def _add_selected_suggestions(self) -> None:
        self._add_suggestions(self._selected_suggestion_indices())

    def _add_all_suggestions(self) -> None:
        self._add_suggestions(range(len(self._suggestions)))

    def _selected_raw_names(self) -> List[str]:
        return sorted({str(item.data(0, USER_ROLE)) for item in self._raw.selectedItems()}, key=str.casefold)

    def _create_definition(self, enum_name: str, names: Sequence[str] = ()) -> Optional[dict]:
        enum_name = enum_name.strip()
        if not is_c_identifier(enum_name):
            QtWidgets.QMessageBox.warning(self, "Invalid enum name", "Enter a valid C identifier.")
            return None
        if any(item["enum_name"] == enum_name for item in self._definitions):
            QtWidgets.QMessageBox.warning(self, "Duplicate enum name", f"{enum_name} already exists.")
            return None
        definition = self._new_definition_record(enum_name, "custom")
        definition["members"] = [self._macro_member(definition, name) for name in names]
        self._definitions.append(definition)
        self._current_definition_id = definition["id"]
        return definition

    def _create_from_raw_selection(self) -> None:
        if self._create_definition(self._raw_enum_name.text(), self._selected_raw_names()):
            self._raw_enum_name.clear()
            self._refresh_all()

    def _add_raw_to_current(self) -> None:
        definition = self._definition()
        if definition is None:
            return
        existing = {member.get("source_name") for member in definition["members"] if member.get("kind") == "macro"}
        definition["members"].extend(
            self._macro_member(definition, name) for name in self._selected_raw_names() if name not in existing
        )
        self._refresh_all()

    def _create_empty_enum(self) -> None:
        self._create_definition(self._available_enum_name("MACRO_ENUM"))
        self._refresh_all()
        self._enum_name.setFocus()
        self._enum_name.selectAll()

    def _delete_current_enum(self) -> None:
        definition = self._definition()
        if definition is None:
            return
        self._definitions = [item for item in self._definitions if item["id"] != definition["id"]]
        self._current_definition_id = ""
        self._refresh_all()

    def _enum_changed(self, current: Any, _previous: Any) -> None:
        if self._refreshing:
            return
        self._current_definition_id = str(current.data(USER_ROLE)) if current else ""
        self._refresh_current_editor()
        self._sync_buttons()

    def _enum_name_edited(self, text: str) -> None:
        """Keep the selected definition synchronized while its name is edited."""

        if self._refreshing:
            return
        definition = self._definition()
        current = self._enum_list.currentItem()
        if definition is None or current is None:
            return
        definition["enum_name"] = text.strip()
        current.setText(text.strip() or "<unnamed enum>")

    def _selected_member_indices(self) -> List[int]:
        rows = []
        for item in self._members.selectedItems():
            row = self._members.indexOfTopLevelItem(item)
            if row >= 0:
                rows.append(row)
        return sorted(set(rows))

    def _custom_name_available(self, name: str, ignored_id: str = "") -> bool:
        for definition in self._definitions:
            for member in definition.get("members", []):
                if member.get("id") == ignored_id:
                    continue
                emitted = member.get("name") if member.get("kind") == "custom" else member.get("emitted_name")
                if emitted == name:
                    return False
        return True

    def _add_custom_member(self) -> None:
        definition = self._definition()
        if definition is None:
            return
        dialog = _CustomMemberDialog(parent=self)
        if dialog.exec() != DIALOG_ACCEPTED:
            return
        member = dialog.member()
        if not self._custom_name_available(member["name"]):
            QtWidgets.QMessageBox.warning(self, "Duplicate member name", f"{member['name']} is already used.")
            return
        definition["members"].append(member)
        self._refresh_all()

    def _edit_custom_member(self) -> None:
        definition = self._definition()
        rows = self._selected_member_indices()
        if definition is None or len(rows) != 1:
            return
        old = definition["members"][rows[0]]
        if old.get("kind") != "custom":
            return
        dialog = _CustomMemberDialog(old, self)
        if dialog.exec() != DIALOG_ACCEPTED:
            return
        member = dialog.member(str(old.get("id", "")))
        if not self._custom_name_available(member["name"], member["id"]):
            QtWidgets.QMessageBox.warning(self, "Duplicate member name", f"{member['name']} is already used.")
            return
        definition["members"][rows[0]] = member
        self._refresh_all()

    def _remove_selected_members(self) -> None:
        definition = self._definition()
        if definition is None:
            return
        for row in reversed(self._selected_member_indices()):
            del definition["members"][row]
        self._refresh_all()

    def _move_member(self, direction: int) -> None:
        definition = self._definition()
        rows = self._selected_member_indices()
        if definition is None or len(rows) != 1:
            return
        row = rows[0]
        target = row + direction
        if not 0 <= target < len(definition["members"]):
            return
        definition["members"][row], definition["members"][target] = (
            definition["members"][target],
            definition["members"][row],
        )
        self._refresh_current_editor()
        self._members.topLevelItem(target).setSelected(True)
        self._sync_buttons()

    def _sync_buttons(self, *_args: Any) -> None:
        suggestion_indices = self._selected_suggestion_indices()
        raw_names = self._selected_raw_names()
        definition = self._definition()
        member_rows = self._selected_member_indices()
        self._add_selected.setEnabled(bool(suggestion_indices))
        self._add_all.setEnabled(bool(self._suggestions))
        valid_raw_name = is_c_identifier(self._raw_enum_name.text().strip())
        unique_raw_name = not any(item["enum_name"] == self._raw_enum_name.text().strip() for item in self._definitions)
        self._create_from_raw.setEnabled(bool(raw_names and valid_raw_name and unique_raw_name))
        self._add_to_enum.setEnabled(bool(raw_names and definition))
        self._delete_enum.setEnabled(definition is not None)
        self._add_custom.setEnabled(definition is not None)
        self._remove_member.setEnabled(bool(definition and member_rows))
        custom_selected = bool(
            definition and len(member_rows) == 1 and definition["members"][member_rows[0]].get("kind") == "custom"
        )
        self._edit_custom.setEnabled(custom_selected)
        self._move_up.setEnabled(bool(definition and len(member_rows) == 1 and member_rows[0] > 0))
        self._move_down.setEnabled(
            bool(definition and len(member_rows) == 1 and member_rows[0] < len(definition["members"]) - 1)
        )

    def _accept(self) -> None:
        error = enum_definitions_error(self._definitions)
        if error:
            QtWidgets.QMessageBox.warning(self, "Invalid macro enums", error)
            return
        self.accept()
