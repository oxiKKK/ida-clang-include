"""Structured diff preview dialog for planned Local Types changes."""

import difflib
import html
from typing import Any, Dict, List, Optional

import idaapi

from .config import PLUGIN_NAME

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6 import QtCore, QtGui, QtWidgets
else:
    from PyQt5 import QtCore, QtGui, QtWidgets


class SyncDiffDialog(QtWidgets.QDialog):
    """Modal preview dialog showing planned Local Types changes in a usable layout."""

    ACTION_ORDER = ["create", "replace", "delete", "adopt", "skip", "keep"]
    ACTION_LABELS = {
        "create": "Create",
        "replace": "Replace",
        "delete": "Delete",
        "adopt": "Adopt",
        "skip": "Skip",
        "keep": "Unchanged",
    }
    ACTION_MARKERS = {
        "create": "+",
        "replace": "~",
        "delete": "-",
        "adopt": ">",
        "skip": "=",
        "keep": ".",
    }
    FILTERS = [
        ("Changed only", {"create", "replace", "delete", "adopt"}),
        ("Actionable", {"create", "replace", "delete", "adopt", "skip"}),
        ("All entries", {"create", "replace", "delete", "adopt", "skip", "keep"}),
        ("Create", {"create"}),
        ("Replace", {"replace"}),
        ("Delete", {"delete"}),
        ("Adopt", {"adopt"}),
        ("Skip", {"skip"}),
        ("Unchanged", {"keep"}),
    ]

    def __init__(self, plan: Any, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.plan = plan
        self._changes = sorted(
            list(plan.changes),
            key=lambda change: (self.ACTION_ORDER.index(change.action), change.name.lower()),
        )
        self._filtered_changes: List[Any] = []

        self.setWindowTitle(f"{PLUGIN_NAME} Change Preview")
        self.resize(1180, 760)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        summary = QtWidgets.QLabel(self._summary_text())
        summary.setWordWrap(True)
        summary.setStyleSheet("font-size: 13px; padding: 4px 0;")

        controls = QtWidgets.QHBoxLayout()
        controls.setSpacing(8)
        filter_label = QtWidgets.QLabel("View")
        self._filter_combo = QtWidgets.QComboBox()
        for label, _ in self.FILTERS:
            self._filter_combo.addItem(label)
        self._search_edit = QtWidgets.QLineEdit()
        self._search_edit.setPlaceholderText("Filter by type name or reason")
        self._visible_count = QtWidgets.QLabel()
        self._visible_count.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        controls.addWidget(filter_label)
        controls.addWidget(self._filter_combo)
        controls.addWidget(self._search_edit, 1)
        controls.addWidget(self._visible_count)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        left_panel = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        self._change_list = QtWidgets.QListWidget()
        self._change_list.setUniformItemSizes(True)
        self._change_list.setAlternatingRowColors(True)
        self._change_list.setMinimumWidth(320)
        left_layout.addWidget(self._change_list, 1)

        right_panel = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        self._detail_header = QtWidgets.QLabel("Select a planned change")
        self._detail_header.setWordWrap(True)
        self._detail_header.setStyleSheet("font-size: 14px; font-weight: 600;")

        self._diff_view = QtWidgets.QTextBrowser()
        self._diff_view.setOpenExternalLinks(False)

        right_layout.addWidget(self._detail_header)
        right_layout.addWidget(self._diff_view, 1)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.button(QtWidgets.QDialogButtonBox.Ok).setText("Apply Changes")
        buttons.button(QtWidgets.QDialogButtonBox.Cancel).setText("Cancel")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root.addWidget(summary)
        root.addLayout(controls)
        root.addWidget(splitter, 1)
        root.addWidget(buttons)

        self._filter_combo.currentIndexChanged.connect(self._refresh_list)
        self._search_edit.textChanged.connect(self._refresh_list)
        self._change_list.currentRowChanged.connect(self._show_selected_change)

        self._apply_palette_styling()
        self._refresh_list()

    def _summary_text(self) -> str:
        counts = self._count_by_action(self._changes)
        parts = [f"Engine: {self.plan.engine}"]
        for action in self.ACTION_ORDER:
            count = counts.get(action, 0)
            if count:
                parts.append(f"{self.ACTION_LABELS[action]}: {count}")
        if len(parts) == 1:
            parts.append("No changes detected")
        return ". ".join(parts) + "."

    def _refresh_list(self) -> None:
        allowed_actions = self.FILTERS[self._filter_combo.currentIndex()][1]
        needle = self._search_edit.text().strip().lower()

        self._filtered_changes = [
            change
            for change in self._changes
            if change.action in allowed_actions
            and (not needle or needle in change.name.lower() or needle in change.reason.lower())
        ]

        self._change_list.blockSignals(True)
        self._change_list.clear()
        for change in self._filtered_changes:
            item = QtWidgets.QListWidgetItem(self._list_text(change))
            item.setData(QtCore.Qt.UserRole, change)
            item.setToolTip(change.reason or self.ACTION_LABELS[change.action])
            self._change_list.addItem(item)
        self._change_list.blockSignals(False)

        total = len(self._changes)
        visible = len(self._filtered_changes)
        self._visible_count.setText(f"Showing {visible} of {total}")

        if self._filtered_changes:
            self._change_list.setCurrentRow(0)
        else:
            self._detail_header.setText("No planned changes match the current filter")
            self._diff_view.setHtml(self._empty_state_html())

    def _show_selected_change(self, row: int) -> None:
        if row < 0 or row >= len(self._filtered_changes):
            return
        change = self._filtered_changes[row]
        label = self.ACTION_LABELS[change.action]
        self._detail_header.setText(f"{label}: {change.name}\n{change.reason}")
        self._diff_view.setHtml(self._render_diff_html(change))

    def _list_text(self, change: Any) -> str:
        marker = self.ACTION_MARKERS[change.action]
        label = self.ACTION_LABELS[change.action]
        return f"{marker} {label:<10} {change.name}"

    def _count_by_action(self, changes: List[Any]) -> Dict[str, int]:
        counts = {action: 0 for action in self.ACTION_ORDER}
        for change in changes:
            counts[change.action] = counts.get(change.action, 0) + 1
        return counts

    def _render_diff_html(self, change: Any) -> str:
        colors = self._html_palette()
        if change.action == "create":
            body = self._render_single_block(change.new_decl, "add")
        elif change.action == "delete":
            body = self._render_single_block(change.old_decl, "remove")
        elif change.action in ("replace", "skip", "adopt", "keep"):
            body = self._render_line_diff(change.old_decl, change.new_decl)
        else:
            body = self._render_single_block(change.new_decl or change.old_decl, "same")

        return f"""
        <html>
        <head>
        <style>
            body {{
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                color: {colors["text"]};
                background: {colors["base"]};
            }}
            .line {{ white-space: pre; padding: 1px 8px; }}
            .add {{ background: #e8f5e9; color: #1b5e20; }}
            .remove {{ background: #fdecea; color: #8a1c12; }}
            .same {{ background: {colors["alternate_base"]}; color: {colors["text"]}; }}
            .hint {{
                color: {colors["muted_text"]};
                font-family: Segoe UI, sans-serif;
                margin-bottom: 8px;
            }}
        </style>
        </head>
        <body>
            <div class="hint">{html.escape(change.reason or self.ACTION_LABELS[change.action])}</div>
            {body}
        </body>
        </html>
        """

    def _render_single_block(self, text: str, css_class: str) -> str:
        lines = self._normalize_lines(text)
        return "".join(f'<div class="line {css_class}">{html.escape(line)}</div>' for line in lines)

    def _render_line_diff(self, old_text: str, new_text: str) -> str:
        old_lines = self._normalize_lines(old_text)
        new_lines = self._normalize_lines(new_text)
        rendered = []
        for line in difflib.ndiff(old_lines, new_lines):
            code = line[:2]
            text = line[2:]
            if code == "+ ":
                css_class = "add"
            elif code == "- ":
                css_class = "remove"
            elif code == "  ":
                css_class = "same"
            else:
                continue
            rendered.append(f'<div class="line {css_class}">{html.escape(text)}</div>')
        if not rendered:
            return self._render_single_block(old_text or new_text, "same")
        return "".join(rendered)

    def _normalize_lines(self, text: str) -> List[str]:
        if not text:
            return ["<declaration unavailable>"]
        lines = text.splitlines()
        return lines or [text]

    def _empty_state_html(self) -> str:
        colors = self._html_palette()
        return f"""
        <html>
        <body style="font-family: Segoe UI, sans-serif; color: {colors["muted_text"]}; padding: 16px; background: {colors["base"]};">
            No planned changes match the current filter.
        </body>
        </html>
        """

    def _apply_palette_styling(self) -> None:
        """Use the active Qt palette for neutral dialog colors."""

        palette = self.palette()
        border = self._color_hex(palette.color(QtGui.QPalette.Mid))
        base = self._color_hex(palette.color(QtGui.QPalette.Base))
        text = self._color_hex(palette.color(QtGui.QPalette.Text))
        muted = self._color_hex(palette.color(QtGui.QPalette.PlaceholderText))

        self._visible_count.setStyleSheet(f"color: {muted};")
        self._diff_view.setStyleSheet(
            f"QTextBrowser {{ background: {base}; color: {text}; border: 1px solid {border}; }}"
        )

    def _html_palette(self) -> Dict[str, str]:
        """Expose palette-derived colors for HTML rendering in QTextBrowser."""

        palette = self.palette()
        return {
            "base": self._color_hex(palette.color(QtGui.QPalette.Base)),
            "alternate_base": self._color_hex(palette.color(QtGui.QPalette.AlternateBase)),
            "text": self._color_hex(palette.color(QtGui.QPalette.Text)),
            "muted_text": self._color_hex(palette.color(QtGui.QPalette.PlaceholderText)),
        }

    def _color_hex(self, color: QtGui.QColor) -> str:
        """Convert a QColor into a CSS hex color string."""

        return color.name(QtGui.QColor.HexRgb)
