"""Parsing, import management, and Local Types synchronization logic."""

import copy
import locale
import re
import subprocess
import tempfile
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import ida_auto
import ida_kernwin
import ida_loader
import ida_typeinf
import idaapi

from . import compat
from .config import DEFAULT_IDACLANG, PLUGIN_NAME
from .macro_conversion import (
    MacroConversionError,
    collect_clang_macros,
    collect_python_macros,
    parse_integer_literal,
)
from .macro_grouping import is_c_identifier, partition_managed_member_names
from .model import Profile, SettingsStore
from .profiles import PER_IDB_RUNTIME_FIELDS, GlobalProfileStore

if idaapi.IDA_SDK_VERSION >= 920:
    from PySide6 import QtCore
    from PySide6.QtCore import Signal
else:
    from PyQt5 import QtCore
    from PyQt5.QtCore import pyqtSignal as Signal


class ClangIncludeError(RuntimeError):
    """Plugin-specific error used for user-visible failures."""


class SyncResult:
    """Small result object returned after one successful sync."""

    def __init__(self, engine: str, type_names: Sequence[str]) -> None:
        self.engine = engine
        self.type_names = list(type_names)


@dataclass
class TypeChange:
    """One planned Local Types action derived from a parsed import result."""

    action: str
    name: str
    old_decl: str = ""
    new_decl: str = ""
    reason: str = ""
    kind: str = "type"
    macro_name: str = ""
    ordinal: int = 0
    enum_width: int = 0
    enum_bte: int = 0
    enum_attrs: int = 0
    enum_name: str = ""
    macro_members: List[dict] = dataclass_field(default_factory=list)
    previous_macro_state: dict = dataclass_field(default_factory=dict)


@dataclass
class SyncPlan:
    """Dry-run plan describing what an import would change."""

    engine: str
    changes: List[TypeChange]
    resulting_type_names: List[str]
    resulting_macro_enums: Dict[str, dict]


@dataclass(frozen=True)
class NumericMacro:
    """One numeric source macro represented with IDA enum metadata."""

    name: str
    value: int
    enum_width: int
    enum_bte: int
    enum_attrs: int


_MACRO_MARKER_PREFIX = "ida-clang-include:macro:"


class PreparedSync:
    """Parsed temporary TIL plus the dry-run plan built from it."""

    def __init__(self, engine: str, temp_til: Any, plan: SyncPlan, numeric_macros: Sequence[NumericMacro]) -> None:
        self.engine = engine
        self.temp_til = temp_til
        self.plan = plan
        self.numeric_macros = list(numeric_macros)


class ClangIncludeManager(QtCore.QObject):
    """Coordinates parsing, conflict handling, and Local Types updates."""

    log_message = Signal(str)
    profile_changed = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._store = SettingsStore()
        self._global_store = GlobalProfileStore()
        self._profile = self._store.load()

    @property
    def profile(self) -> Profile:
        return self._profile

    def save_profile(self, profile: Profile) -> None:
        """Normalize and persist the profile into the current IDB."""

        profile.include_paths = [p for p in profile.include_paths if p]
        profile.macros = [m for m in profile.macros if m]
        profile.managed_type_names = sorted(set(profile.managed_type_names))
        profile.managed_macro_enums = dict(profile.managed_macro_enums)
        profile.macro_enum_definitions = [copy.deepcopy(item) for item in profile.macro_enum_definitions]
        self._profile = profile
        self._store.save(profile)
        self.profile_changed.emit(profile)
        self.log("Saved profile to IDB.")

    def list_global_profiles(self) -> List[str]:
        """Return the display names of profiles available on disk."""

        return self._global_store.list_names()

    def save_global_profile(self, name: str, profile: Profile) -> None:
        """Save the given profile snapshot as a named global profile."""

        path = self._global_store.save(name, profile)
        self.log(f"Saved global profile {name!r} to {path}")

    def delete_global_profile(self, name: str) -> None:
        """Remove the named global profile from disk."""

        self._global_store.delete(name)
        self.log(f"Deleted global profile {name!r}.")

    def apply_global_profile(self, name: str) -> None:
        """Load a global profile and merge it into the current IDB profile.

        Per-IDB runtime state (managed types, last engine used) is preserved
        from the current profile so loading a template never destroys what
        this IDB has already imported.
        """

        loaded = self._global_store.load(name)
        merged = loaded
        for field in PER_IDB_RUNTIME_FIELDS:
            setattr(merged, field, getattr(self._profile, field))
        self.save_profile(merged)
        self.log(f"Loaded global profile {name!r}.")

    def sync(self, profile: Profile) -> SyncResult:
        """Run one full parse-and-apply cycle.

        Auto mode may try more than one backend before reporting failure.
        """

        prepared = self.prepare_sync(profile)
        try:
            return self.apply_prepared_sync(profile, prepared)
        finally:
            self.release_prepared_sync(prepared)

    def prepare_sync(self, profile: Profile) -> PreparedSync:
        """Parse the header and build a dry-run plan without touching Local Types."""

        self._validate_profile(profile)
        self.save_profile(profile)
        numeric_macros: List[NumericMacro] = []
        if profile.import_numeric_macros:
            numeric_macros = self._collect_numeric_macros(profile)

        errors = []
        for engine in self._engine_order(profile.engine):
            temp_til = None
            try:
                self.log(f"Parsing with {self._engine_label(engine)}...")
                if engine == "external" and self._structured_logging_enabled(profile):
                    self.log(
                        "External parser logging flags are enabled. Detailed clang diagnostics will appear in the Clang Include log and IDA output window."
                    )
                temp_til = self._parse_with_engine(profile, engine)
                plan = self._build_sync_plan(
                    profile,
                    engine,
                    temp_til,
                    numeric_macros=numeric_macros,
                )
                self.log(f"Prepared {len(plan.changes)} planned change(s) using {self._engine_label(engine)}.")
                return PreparedSync(engine, temp_til, plan, numeric_macros)
            except Exception as exc:
                if temp_til is not None:
                    self._free_til(temp_til)
                message = f"{self._engine_label(engine)} failed: {exc}"
                errors.append(message)
                self.log(message)

        raise ClangIncludeError("\n".join(errors))

    def rebuild_prepared_sync(self, profile: Profile, prepared: PreparedSync) -> None:
        """Rebuild only the dry-run plan after interactive macro grouping changes."""

        prepared.plan = self._build_sync_plan(
            profile,
            prepared.engine,
            prepared.temp_til,
            numeric_macros=prepared.numeric_macros,
        )

    def apply_prepared_sync(self, profile: Profile, prepared: PreparedSync) -> SyncResult:
        """Apply a previously prepared dry-run plan to Local Types."""

        type_names, macro_enums = self._apply_sync_plan(prepared.temp_til, prepared.plan)
        profile.last_engine_used = prepared.engine
        profile.managed_type_names = type_names
        profile.managed_macro_enums = macro_enums
        self._sync_definition_member_names(profile, macro_enums)
        self.save_profile(profile)
        self.log(
            f"Imported {len(type_names)} managed types and {len(macro_enums)} macro enum(s) "
            f"using {self._engine_label(prepared.engine)}."
        )
        return SyncResult(prepared.engine, type_names)

    def _sync_definition_member_names(self, profile: Profile, states: Dict[str, dict]) -> None:
        """Persist the exact globally unique enumerator names written to IDA."""

        for definition in profile.macro_enum_definitions:
            owner_key = str(definition.get("owner_key") or f"enum:{definition.get('id', '')}")
            member_names = states.get(owner_key, {}).get("member_names", {})
            for member in definition.get("members", []):
                if member.get("kind") != "macro":
                    continue
                member_id = str(member.get("id", ""))
                source_name = str(member.get("source_name", ""))
                emitted_name = member_names.get(member_id) or member_names.get(source_name)
                if emitted_name:
                    member["emitted_name"] = str(emitted_name)

    def release_prepared_sync(self, prepared: Optional[PreparedSync]) -> None:
        """Free the temporary TIL associated with a prepared sync result."""

        if prepared is None or prepared.temp_til is None:
            return
        self._free_til(prepared.temp_til)
        prepared.temp_til = None

    def log(self, message: str) -> None:
        """Send a message to both the dockable view and IDA's output window."""

        self.log_message.emit(message)
        ida_kernwin.msg(f"{PLUGIN_NAME}: {message}\n")

    def build_preview_command(self, profile: Profile) -> str:
        """Build the parser command preview shown in the UI."""

        api_preview = subprocess.list2cmdline(
            [*self._build_api_parser_args(profile), profile.header_path]
            if profile.header_path
            else self._build_api_parser_args(profile)
        )
        external_preview = subprocess.list2cmdline(
            self._build_external_command(profile, self._external_til_path(profile))
        )

        macro_preview = ""
        if profile.import_numeric_macros:
            if profile.macro_conversion_mode == "clang":
                macro_preview = "\nEnum conversion: " + subprocess.list2cmdline(
                    [profile.macro_clang_path, *self._build_api_parser_args(profile), "-E", "-dD", profile.header_path]
                )
            else:
                macro_preview = "\nEnum conversion: Python parsing (no subprocess)"

        if profile.engine == "api":
            return api_preview + macro_preview
        if profile.engine == "external":
            return external_preview + macro_preview

        order = " -> ".join(self._engine_label(engine) for engine in self._engine_order("auto"))
        return f"Auto order: {order}\nAPI argv: {api_preview}\nExternal command: {external_preview}{macro_preview}"

    def _validate_profile(self, profile: Profile) -> None:
        """Reject invalid states before any parsing work starts."""

        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            raise ClangIncludeError("Open an IDB before using the plugin.")
        if not ida_auto.auto_is_ok():
            raise ClangIncludeError("Wait for auto-analysis to complete before importing types.")
        if not profile.header_path:
            raise ClangIncludeError("Header path is required.")
        if not Path(profile.header_path).is_file():
            raise ClangIncludeError(f"Header file does not exist: {profile.header_path}")
        if profile.engine in ("external", "auto"):
            if not Path(profile.idaclang_path).is_file():
                raise ClangIncludeError(f"idaclang executable does not exist: {profile.idaclang_path}")
        if profile.import_numeric_macros:
            if profile.macro_conversion_mode not in ("python", "clang"):
                raise ClangIncludeError("Automatic enum conversion mode must be Python or Clang.")
            if profile.macro_conversion_mode == "clang" and not Path(profile.macro_clang_path).is_file():
                raise ClangIncludeError(f"Clang executable does not exist: {profile.macro_clang_path}")

    def _engine_order(self, preferred: str) -> List[str]:
        """Resolve the backend order for the current sync run."""

        if preferred == "api":
            return ["api"]
        if preferred == "external":
            return ["external"]
        if self.profile.auto_engine_order == "external_first":
            return ["external", "api"]
        return ["api", "external"]

    def _engine_label(self, engine: str) -> str:
        """Render an internal engine identifier as user-facing text."""

        labels = {
            "api": "IDA parser API",
            "external": "external idaclang",
        }
        return labels.get(engine, engine)

    def _parse_with_engine(self, profile: Profile, engine: str) -> Any:
        """Parse with one backend and return the temporary TIL."""

        match engine:
            case "api":
                return self._parse_with_api(profile)
            case "external":
                return self._parse_with_external(profile)
            case _:
                raise ClangIncludeError(f"Unknown engine: {engine}")

    def _build_api_parser_args(self, profile: Profile) -> List[str]:
        """Build argv for the IDA parser API.

        Raw mode hands the user's argv through verbatim. Structured mode
        composes argv from the individual profile fields.
        """

        if profile.input_mode == "raw":
            return self._split_raw_args(profile.raw_argv)

        args = self._build_structured_parser_args(profile)
        args.extend(self._split_raw_args(profile.extra_args))
        return args

    def _build_external_parser_args(self, profile: Profile) -> List[str]:
        """Build argv for the external idaclang executable."""

        if profile.input_mode == "raw":
            return self._split_raw_args(profile.raw_argv)

        args = self._build_structured_parser_args(profile)
        args.extend(self._build_idaclang_args(profile))
        args.extend(self._split_raw_args(profile.extra_args))
        return args

    def _build_structured_parser_args(self, profile: Profile) -> List[str]:
        """Build the common structured parser arguments shared by both backends."""

        args: List[str] = []
        if profile.target.strip():
            args.extend(["-target", profile.target.strip()])
        if profile.language.strip():
            args.extend(["-x", profile.language.strip()])
        if profile.standard.strip():
            args.append(f"-std={profile.standard.strip()}")
        for include_path in profile.include_paths:
            args.extend(["-I", include_path])
        for macro in profile.macros:
            macro = macro.strip()
            if macro:
                args.append(f"-D{macro}")
        return args

    def _build_idaclang_args(self, profile: Profile) -> List[str]:
        """Append advanced parser switches configured from the options dialog."""

        args: List[str] = []
        value_options = (
            ("idaclang_tildesc", "--idaclang-tildesc"),
            ("idaclang_macros_path", "--idaclang-macros"),
            ("idaclang_smptrs", "--idaclang-smptrs"),
            ("idaclang_mangle_format", "--idaclang-mangle-format"),
        )
        for attr_name, flag in value_options:
            value = getattr(profile, attr_name, "").strip()
            if value:
                args.extend([flag, value])

        bool_options = (
            ("idaclang_opaqify_objc", "--idaclang-opaqify-objc"),
            ("idaclang_extra_c_mangling", "--idaclang-extra-c-mangling"),
            ("idaclang_parse_static", "--idaclang-parse-static"),
        )
        for attr_name, flag in bool_options:
            if getattr(profile, attr_name, False):
                args.append(flag)

        if profile.idaclang_log_all:
            args.append("--idaclang-log-all")
            return args

        log_options = (
            ("idaclang_log_warnings", "--idaclang-log-warnings"),
            ("idaclang_log_ast", "--idaclang-log-ast"),
            ("idaclang_log_macros", "--idaclang-log-macros"),
            ("idaclang_log_predefined", "--idaclang-log-predefined"),
            ("idaclang_log_udts", "--idaclang-log-udts"),
            ("idaclang_log_files", "--idaclang-log-files"),
            ("idaclang_log_argv", "--idaclang-log-argv"),
            ("idaclang_log_target", "--idaclang-log-target"),
        )
        for attr_name, flag in log_options:
            if getattr(profile, attr_name, False):
                args.append(flag)
        return args

    def _structured_logging_enabled(self, profile: Profile) -> bool:
        """Return whether any structured parser logging option is enabled."""

        return any(
            getattr(profile, attr_name, False)
            for attr_name in (
                "idaclang_log_warnings",
                "idaclang_log_ast",
                "idaclang_log_macros",
                "idaclang_log_predefined",
                "idaclang_log_udts",
                "idaclang_log_files",
                "idaclang_log_argv",
                "idaclang_log_target",
                "idaclang_log_all",
            )
        )

    def _split_raw_args(self, raw: str) -> List[str]:
        """Split a Windows-style command line fragment into argv tokens."""

        import shlex

        if not raw.strip():
            return []
        return shlex.split(raw, posix=False)

    def _parse_with_api(self, profile: Profile) -> Any:
        """Use IDA's in-process source parser to build a temporary TIL."""

        srclang = compat.srclang_for(profile.language)
        argv = subprocess.list2cmdline(self._build_api_parser_args(profile))

        # Parse into a temporary TIL first. Only after a fully successful parse
        # do we touch the IDB's Local Types.
        temp_til = ida_typeinf.new_til(
            "clang_include_api",
            "Clang Include API parse result",
        )
        try:
            parser_name, err_count = compat.parse_with_srclang(srclang, argv, temp_til, profile.header_path)
        except compat.CompatError as exc:
            ida_typeinf.free_til(temp_til)
            raise ClangIncludeError(str(exc))

        if err_count < 0:
            ida_typeinf.free_til(temp_til)
            raise ClangIncludeError(f"ida_srclang parser {parser_name} was not available.")
        if err_count != 0:
            ida_typeinf.free_til(temp_til)
            raise ClangIncludeError(
                f"ida_srclang reported {err_count} parse errors. "
                "Review the Clang Include Log tab or IDA output window for compiler diagnostics."
            )
        return temp_til

    def _parse_with_external(self, profile: Profile) -> Any:
        """Run external idaclang.exe and load the generated temporary TIL."""

        temp_til_path = self._external_til_path(profile)
        temp_til_path.parent.mkdir(parents=True, exist_ok=True)
        if temp_til_path.exists():
            temp_til_path.unlink()

        command = self._build_external_command(profile, temp_til_path)
        delete_after_load = not profile.idaclang_tilname.strip()
        try:
            self.log(f"Running external parser: {subprocess.list2cmdline(command)}")
            completed = subprocess.run(command, capture_output=True, text=False, check=False)
            stdout = self._decode_process_output(completed.stdout)
            stderr = self._decode_process_output(completed.stderr)
            compiler_errors = self._extract_compiler_errors(stdout, stderr)
            should_log_output = profile.log_external_output or completed.returncode != 0 or bool(compiler_errors)
            if should_log_output and stdout:
                self.log(stdout)
            if should_log_output and stderr:
                self.log(stderr)

            if completed.returncode != 0 or compiler_errors:
                first_error = compiler_errors[0] if compiler_errors else ""
                message = "idaclang reported compiler errors. Review the Clang Include Log tab for diagnostics."
                if completed.returncode != 0:
                    message = (
                        f"idaclang exited with code {completed.returncode}. "
                        "Review the Clang Include Log tab for diagnostics."
                    )
                if first_error:
                    message += f" First diagnostic: {first_error}"
                raise ClangIncludeError(message)

            if not temp_til_path.is_file():
                raise ClangIncludeError("idaclang completed without producing a TIL file.")
            temp_til = ida_typeinf.load_til(str(temp_til_path))
            if not temp_til:
                raise ClangIncludeError(f"Failed to load generated TIL: {temp_til_path}")
            return temp_til
        finally:
            try:
                if delete_after_load and temp_til_path.exists():
                    temp_til_path.unlink()
            except Exception:
                pass

    def _build_external_command(self, profile: Profile, til_path: Path) -> List[str]:
        """Build the full external idaclang command line."""

        return [
            profile.idaclang_path or str(DEFAULT_IDACLANG),
            *self._build_external_parser_args(profile),
            "--idaclang-tilname",
            str(til_path),
            profile.header_path,
        ]

    def _collect_numeric_macros(self, profile: Profile) -> List[NumericMacro]:
        """Discover numeric source macros with the configured fast converter."""

        try:
            if profile.macro_conversion_mode == "clang":
                values = collect_clang_macros(
                    profile.macro_clang_path,
                    profile.header_path,
                    self._build_api_parser_args(profile),
                )
            else:
                values = collect_python_macros(
                    profile.header_path,
                    self._macro_include_paths(profile),
                    self._command_line_macro_names(profile),
                )
        except MacroConversionError as exc:
            raise ClangIncludeError(str(exc)) from exc

        macros: List[NumericMacro] = []
        for value in values:
            details = ida_typeinf.enum_type_data_t()
            details.set_nbytes(value.width)
            details.set_enum_radix(16, value.signed)
            macros.append(
                NumericMacro(
                    name=value.name,
                    value=value.value,
                    enum_width=value.width,
                    enum_bte=int(details.bte),
                    enum_attrs=int(details.taenum_bits),
                )
            )
        self.log(f"Automatic enum conversion found {len(macros)} numeric macro(s).")
        return macros

    def _macro_include_paths(self, profile: Profile) -> List[str]:
        """Extract project include directories without treating system paths as project files."""

        paths: List[str] = []
        args = self._build_api_parser_args(profile)
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "-I" and index + 1 < len(args):
                index += 1
                paths.append(args[index])
            elif arg.startswith("-I") and len(arg) > 2:
                paths.append(arg[2:])
            index += 1
        return paths

    def _command_line_macro_names(self, profile: Profile) -> set[str]:
        """Return -D names, which configure parsing but are not source macros."""

        names = set()
        args = self._build_api_parser_args(profile)
        index = 0
        while index < len(args):
            arg = args[index]
            value = ""
            if arg == "-D" and index + 1 < len(args):
                index += 1
                value = args[index]
            elif arg.startswith("-D"):
                value = arg[2:]
            if value:
                name = value.split("=", 1)[0]
                if re.fullmatch(r"[A-Za-z_]\w*", name):
                    names.add(name)
            index += 1
        return names

    def _external_til_path(self, profile: Profile) -> Path:
        """Return the output TIL path used by the external parser."""

        if profile.idaclang_tilname.strip():
            return Path(profile.idaclang_tilname)
        return Path(tempfile.gettempdir()) / "ida-clang-include" / "managed-temp.til"

    def _extract_compiler_errors(self, *texts: str) -> List[str]:
        """Collect lines that look like compiler errors from parser output."""

        errors: List[str] = []
        for text in texts:
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                lower = line.lower()
                if "warning" in lower and "error" not in lower:
                    continue
                if (
                    "fatal error:" in lower
                    or ": error:" in lower
                    or " error " in lower
                    or lower.startswith("error ")
                    or lower.startswith("error:")
                ):
                    errors.append(line)
        return errors

    def _decode_process_output(self, data: Optional[bytes]) -> str:
        """Decode subprocess output safely without relying on the host code page."""

        if not data:
            return ""

        encodings = ["utf-8", locale.getpreferredencoding(False), "cp1252", "latin-1"]
        tried = set()
        for encoding in encodings:
            if not encoding or encoding in tried:
                continue
            tried.add(encoding)
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue

        return data.decode("utf-8", errors="replace")

    def _build_sync_plan(
        self,
        profile: Profile,
        engine: str,
        source_til: Any,
        numeric_macros: Sequence[NumericMacro],
    ) -> SyncPlan:
        """Compute the Local Types changes implied by the parsed source TIL."""

        source_names = sorted(compat.til_type_names(source_til))
        macro_workspace_enabled = profile.import_numeric_macros
        if not source_names and not numeric_macros and not macro_workspace_enabled:
            raise ClangIncludeError("Parser succeeded but produced no named types or numeric macros.")

        idati = ida_typeinf.get_idati()
        managed_set = set(profile.managed_type_names)
        source_set = set(source_names)
        stale_managed = sorted(managed_set - source_set)
        changes: List[TypeChange] = []

        # Optionally remove names that used to be managed by the plugin but no
        # longer appear in the current parse result.
        if profile.delete_missing_managed_types:
            for name in stale_managed:
                if self._type_exists(idati, name):
                    changes.append(
                        TypeChange(
                            action="delete",
                            name=name,
                            old_decl=self._get_named_type_decl(idati, name),
                            reason="Previously managed type no longer exists in the latest parse result.",
                        )
                    )

        conflicts = []
        skipped_names = set()
        imported_names = []
        for name in source_names:
            new_decl = self._get_named_type_decl(source_til, name)
            if not self._type_exists(idati, name):
                changes.append(
                    TypeChange(
                        action="create",
                        name=name,
                        new_decl=new_decl,
                        reason="New named type from the parsed header.",
                    )
                )
                imported_names.append(name)
                continue

            old_decl = self._get_named_type_decl(idati, name)
            unchanged = bool(old_decl) and old_decl == new_decl

            # Managed names already belong to the plugin, so they are candidates
            # for in-place replacement rather than conflict handling.
            if name in managed_set:
                imported_names.append(name)
                if unchanged:
                    changes.append(
                        TypeChange(
                            action="keep",
                            name=name,
                            old_decl=old_decl,
                            new_decl=new_decl,
                            reason="Managed type is unchanged.",
                        )
                    )
                else:
                    changes.append(
                        TypeChange(
                            action="replace",
                            name=name,
                            old_decl=old_decl,
                            new_decl=new_decl,
                            reason="Managed type will be refreshed in place.",
                        )
                    )
                continue

            # Unmanaged collisions follow the user-selected conflict policy.
            if profile.existing_type_policy in ("overwrite", "update"):
                imported_names.append(name)
                if unchanged:
                    changes.append(
                        TypeChange(
                            action="adopt",
                            name=name,
                            old_decl=old_decl,
                            new_decl=new_decl,
                            reason="Existing unmanaged type already matches and will become plugin-managed.",
                        )
                    )
                else:
                    changes.append(
                        TypeChange(
                            action="replace",
                            name=name,
                            old_decl=old_decl,
                            new_decl=new_decl,
                            reason="Existing unmanaged type will be updated from the parsed header per policy.",
                        )
                    )
                continue
            if profile.existing_type_policy == "skip":
                skipped_names.add(name)
                changes.append(
                    TypeChange(
                        action="skip",
                        name=name,
                        old_decl=old_decl,
                        new_decl=new_decl,
                        reason="Existing unmanaged type will be left untouched per policy.",
                    )
                )
                continue
            conflicts.append(name)

        if conflicts:
            preview = ", ".join(conflicts[:10])
            suffix = "" if len(conflicts) <= 10 else f" (+{len(conflicts) - 10} more)"
            raise ClangIncludeError(
                "Import blocked by existing unmanaged Local Types: "
                f"{preview}{suffix}. Change the existing-type policy in Options to update or skip them."
            )

        # If stale managed types are kept, they remain in the managed set for
        # future refreshes.
        if not profile.delete_missing_managed_types:
            imported_names.extend(stale_managed)
        if profile.import_numeric_macros:
            macro_changes, resulting_macro_enums = self._build_macro_changes(profile, numeric_macros)
            changes.extend(macro_changes)
        else:
            resulting_macro_enums = copy.deepcopy(profile.managed_macro_enums)
        return SyncPlan(
            engine=engine,
            changes=changes,
            resulting_type_names=sorted(set(imported_names)),
            resulting_macro_enums=resulting_macro_enums,
        )

    def _build_macro_changes(
        self,
        profile: Profile,
        numeric_macros: Sequence[NumericMacro],
    ) -> Tuple[List[TypeChange], Dict[str, dict]]:
        """Plan exactly the macro enums defined by the workspace."""

        idati = ida_typeinf.get_idati()
        macros_by_name = {macro.name: macro for macro in numeric_macros}
        definitions = list(profile.macro_enum_definitions)
        enum_names = set()
        owner_keys = set()
        active_member_names: Dict[str, Dict[str, str]] = {}
        for definition in definitions:
            definition_id = str(definition.get("id", "")).strip()
            enum_name = str(definition.get("enum_name", "")).strip()
            owner_key = str(definition.get("owner_key") or f"enum:{definition_id}")
            if not definition_id:
                raise ClangIncludeError(f"Macro enum {enum_name!r} has no stable identity.")
            if not is_c_identifier(enum_name):
                raise ClangIncludeError(f"Macro enum name {enum_name!r} is not a valid C identifier.")
            if enum_name in enum_names:
                raise ClangIncludeError(f"Macro enum name {enum_name!r} is duplicated.")
            if owner_key in owner_keys:
                raise ClangIncludeError(f"Macro enum ownership key {owner_key!r} is duplicated.")

            active_names = active_member_names.setdefault(owner_key, {})
            local_names = set()
            for member in definition.get("members", []):
                member_id = str(member.get("id", "")).strip()
                if not member_id or member_id in active_names:
                    raise ClangIncludeError(f"A member in {enum_name} has a missing or duplicated identity.")
                if member.get("kind") == "custom":
                    desired_name = str(member.get("name", "")).strip()
                else:
                    source_name = str(member.get("source_name", "")).strip()
                    desired_name = str(member.get("emitted_name") or source_name).strip()
                    if source_name:
                        active_names[source_name] = desired_name  # Legacy state key.
                if not is_c_identifier(desired_name):
                    raise ClangIncludeError(
                        f"Macro enum member {desired_name!r} in {enum_name} is not a valid C identifier."
                    )
                if desired_name in local_names:
                    raise ClangIncludeError(f"Macro enum member {desired_name!r} is duplicated in {enum_name}.")
                active_names[member_id] = desired_name
                local_names.add(desired_name)

            if not local_names:
                raise ClangIncludeError(f"Macro enum {enum_name} has no members.")
            enum_names.add(enum_name)
            owner_keys.add(owner_key)
        previous = dict(profile.managed_macro_enums)
        resolved: Dict[str, dict] = {}
        for owner_key, raw_state in sorted(previous.items()):
            state = self._normalize_macro_state(owner_key, raw_state)
            ordinal = self._find_managed_macro_ordinal(idati, owner_key, state)
            if ordinal <= 0:
                continue
            state["ordinal"] = ordinal
            resolved[owner_key] = state
        reserved, reclaimable = partition_managed_member_names(resolved, active_member_names)

        changes: List[TypeChange] = []
        resulting: Dict[str, dict] = {}
        incoming_owners = owner_keys
        for definition in definitions:
            definition_id = str(definition.get("id", ""))
            owner_key = str(definition.get("owner_key") or f"enum:{definition_id}")
            enum_name = str(definition["enum_name"])
            old_state = resolved.get(owner_key, {})
            old_names = dict(old_state.get("member_names", {}))
            owned_old_names = set(old_names.values())
            member_names: Dict[str, str] = {}
            members = []
            metadata = []
            for member in definition.get("members", []):
                member_id = str(member.get("id") or "")
                if not member_id:
                    raise ClangIncludeError(f"A member in {enum_name} has no stable identity.")
                kind = str(member.get("kind", "macro"))
                previous_name = old_names.get(member_id)
                if kind == "custom":
                    desired_name = str(member.get("name", "")).strip()
                    if previous_name == desired_name:
                        emitted_name = previous_name
                    else:
                        if (
                            desired_name in reserved
                            or (desired_name not in reclaimable and self._enum_member_exists(idati, desired_name))
                        ) and desired_name not in owned_old_names:
                            raise ClangIncludeError(
                                f"Custom enum member {desired_name} already exists in the IDB. "
                                "Choose a globally unique member name."
                            )
                        emitted_name = desired_name
                        reserved.add(emitted_name)
                    literal = str(member.get("literal", member.get("value", "")))
                    parsed = parse_integer_literal(literal)
                    if parsed is None:
                        raise ClangIncludeError(
                            f"Custom enum member {desired_name} has an unsupported integer value: {literal!r}."
                        )
                    value, width, signed = parsed
                    details = ida_typeinf.enum_type_data_t()
                    details.set_nbytes(width)
                    details.set_enum_radix(16, signed)
                    metadata.append((width, int(details.bte), int(details.taenum_bits)))
                else:
                    source_name = str(member.get("source_name", "")).strip()
                    previous_name = previous_name or old_names.get(source_name)
                    desired_name = str(member.get("emitted_name") or source_name)
                    if previous_name == desired_name:
                        emitted_name = previous_name
                    else:
                        emitted_name = self._available_macro_member_name(idati, desired_name, reserved, reclaimable)
                        reserved.add(emitted_name)
                    macro = macros_by_name.get(source_name)
                    if macro is None:
                        value = int(member.get("last_value", 0))
                        width = int(member.get("width", 4) or 4)
                        enum_bte = int(member.get("enum_bte", 0))
                        enum_attrs = int(member.get("enum_attrs", 0))
                    else:
                        value = macro.value
                        width = macro.enum_width
                        enum_bte = macro.enum_bte
                        enum_attrs = macro.enum_attrs
                    metadata.append((width, enum_bte, enum_attrs))
                member_names[member_id] = emitted_name
                members.append(
                    {
                        "member_id": member_id,
                        "member_name": emitted_name,
                        "value": value,
                    }
                )

            if not members:
                raise ClangIncludeError(f"Macro enum {enum_name} has no members.")
            width, enum_bte, enum_attrs = max(metadata, key=lambda item: item[0])
            ordinal = int(old_state.get("ordinal", 0) or 0)
            old_enum = self._read_managed_macro_enum(idati, ordinal, owner_key) if ordinal else None
            if old_enum is not None and old_enum["enum_width"] > width:
                width = old_enum["enum_width"]
                enum_bte = old_enum["enum_bte"]
                enum_attrs = old_enum["enum_attrs"]

            new_decl = self._macro_decl(enum_name, members)
            action = "create"
            old_decl = ""
            reason = f"New macro enum {enum_name} with {len(members)} member(s)."
            if old_enum is not None:
                old_members = [
                    {
                        "member_name": member_name,
                        "value": old_enum["values"].get(member_name, 0),
                    }
                    for member_name in old_state["member_names"].values()
                ]
                old_decl = self._macro_decl(str(old_state.get("enum_name", enum_name)), old_members)
                expected_values = {member["member_name"]: member["value"] for member in members}
                unchanged = (
                    old_enum["values"] == expected_values
                    and old_enum["member_order"] == [member["member_name"] for member in members]
                    and old_enum["enum_width"] == width
                    and old_enum["enum_bte"] == enum_bte
                    and old_enum["enum_attrs"] == enum_attrs
                    and self._numbered_type_name(idati, ordinal) == enum_name
                )
                action = "keep" if unchanged else "replace"
                reason = (
                    "Managed macro enum is unchanged."
                    if unchanged
                    else "Managed macro enum membership, value, order, or name will be refreshed."
                )

            resulting[owner_key] = {
                "enum_name": enum_name,
                "member_names": member_names,
                "ordinal": ordinal,
            }
            changes.append(
                TypeChange(
                    action=action,
                    name=enum_name,
                    old_decl=old_decl,
                    new_decl=new_decl,
                    reason=reason,
                    kind="macro",
                    macro_name=owner_key,
                    ordinal=ordinal,
                    enum_width=width,
                    enum_bte=enum_bte,
                    enum_attrs=enum_attrs,
                    enum_name=enum_name,
                    macro_members=members,
                    previous_macro_state=copy.deepcopy(old_state),
                )
            )

        for owner_key, state in sorted(resolved.items()):
            if owner_key in incoming_owners:
                continue
            ordinal = int(state.get("ordinal", 0) or 0)
            old_enum = self._read_managed_macro_enum(idati, ordinal, owner_key)
            if old_enum is None:
                continue
            members = [
                {
                    "member_id": member_id,
                    "member_name": member_name,
                    "value": old_enum["values"].get(member_name, 0),
                }
                for member_id, member_name in state["member_names"].items()
            ]
            changes.append(
                TypeChange(
                    action="delete",
                    name=state["enum_name"],
                    old_decl=self._macro_decl(state["enum_name"], members),
                    reason="Removed from the macro enum workspace.",
                    kind="macro",
                    macro_name=owner_key,
                    ordinal=ordinal,
                    enum_name=state["enum_name"],
                    macro_members=members,
                    previous_macro_state=copy.deepcopy(state),
                )
            )

        return changes, resulting

    def _normalize_macro_state(self, owner_key: str, state: dict) -> dict:
        """Upgrade legacy one-macro state to the grouped state shape."""

        if "member_names" in state:
            member_names = {str(name): str(member) for name, member in state["member_names"].items()}
        else:
            member_names = {owner_key: str(state.get("member_name", owner_key))}
        return {
            "enum_name": str(state.get("enum_name", self._macro_enum_name(owner_key))),
            "member_names": member_names,
            "ordinal": int(state.get("ordinal", 0) or 0),
        }

    def _available_macro_member_name(
        self,
        til: Any,
        base: str,
        reserved: set[str],
        reclaimable: set[str],
    ) -> str:
        """Choose BASE or BASE_N, reusing names freed by this same plan."""

        candidate = base
        suffix = 1
        while candidate in reserved or (candidate not in reclaimable and self._enum_member_exists(til, candidate)):
            suffix += 1
            candidate = f"{base}_{suffix}"
        return candidate

    def _enum_member_exists(self, til: Any, name: str) -> bool:
        """Return whether any existing enum already defines this member name."""

        tif = ida_typeinf.tinfo_t()
        try:
            return int(ida_typeinf.get_tinfo_by_edm_name(tif, til, name)) >= 0
        except Exception:
            for ordinal in range(1, int(ida_typeinf.get_ordinal_limit(til) or 0)):
                current = self._numbered_tinfo(til, ordinal)
                if current is None or not current.is_enum():
                    continue
                details = ida_typeinf.enum_type_data_t()
                if current.get_enum_details(details) and any(str(edm.name) == name for edm in details):
                    return True
            return False

    def _find_managed_macro_ordinal(self, til: Any, owner_key: str, state: dict) -> int:
        """Validate the cached ordinal, then recover it by ownership marker."""

        ordinal = int(state.get("ordinal", 0) or 0)
        if ordinal > 0 and self._read_managed_macro_enum(til, ordinal, owner_key) is not None:
            return ordinal
        limit = int(ida_typeinf.get_ordinal_limit(til) or 0)
        for candidate in range(1, limit):
            if self._read_managed_macro_enum(til, candidate, owner_key) is not None:
                return candidate
        return 0

    def _numbered_tinfo(self, til: Any, ordinal: int) -> Optional[Any]:
        """Read a numbered Local Type using API shapes available across IDA releases."""

        tif = ida_typeinf.tinfo_t()
        try:
            if tif.get_numbered_type(til, ordinal):
                return tif
        except Exception:
            try:
                candidate = til.get_numbered_type(ordinal)
                if candidate:
                    return candidate
            except Exception:
                pass
        return None

    def _numbered_type_name(self, til: Any, ordinal: int) -> str:
        tif = self._numbered_tinfo(til, ordinal)
        if tif is None:
            return ""
        try:
            return str(tif.get_type_name() or "")
        except Exception:
            return ""

    def _read_managed_macro_enum(self, til: Any, ordinal: int, owner_key: str) -> Optional[dict]:
        """Read an enum only when its plugin ownership marker matches."""

        tif = self._numbered_tinfo(til, ordinal)
        if tif is None or not tif.is_enum():
            return None
        try:
            comment = str(tif.get_type_cmt() or "")
        except Exception:
            comment = ""
        if comment != _MACRO_MARKER_PREFIX + owner_key:
            return None
        details = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(details):
            return None
        return {
            "values": {str(member.name): int(member.value) for member in details},
            "member_order": [str(member.name) for member in details],
            "enum_width": int(tif.get_enum_width()),
            "enum_bte": int(details.bte),
            "enum_attrs": int(details.taenum_bits),
        }

    def _macro_enum_name(self, macro_name: str) -> str:
        return f"MACRO_{macro_name}"

    def _macro_decl(self, enum_name: str, members: Sequence[dict]) -> str:
        body = ",\n".join(f"    {member['member_name']} = {member['value']}" for member in members)
        return f"enum {enum_name} {{\n{body}\n}};"

    def _macro_change_state(self, change: TypeChange, ordinal: int) -> dict:
        return {
            "enum_name": change.enum_name,
            "member_names": {member["member_id"]: member["member_name"] for member in change.macro_members},
            "ordinal": ordinal,
        }

    def _apply_sync_plan(self, source_til: Any, plan: SyncPlan) -> Tuple[List[str], Dict[str, dict]]:
        """Apply a previously computed sync plan to Local Types."""

        idati = ida_typeinf.get_idati()
        failed: List[str] = []
        failed_types = set()
        resulting_macro_enums = copy.deepcopy(plan.resulting_macro_enums)

        for change in plan.changes:
            if change.action != "delete":
                continue
            if change.kind == "macro":
                try:
                    if self._read_managed_macro_enum(idati, change.ordinal, change.macro_name) is not None:
                        if not ida_typeinf.del_numbered_type(idati, change.ordinal):
                            raise ClangIncludeError("del_numbered_type returned false")
                    self.log(f"Deleted stale managed macro enum: {change.enum_name}")
                except Exception as exc:
                    failed.append(change.enum_name)
                    resulting_macro_enums[change.macro_name] = copy.deepcopy(change.previous_macro_state)
                    self.log(f"Failed to delete macro enum {change.enum_name}: {exc}")
                continue
            if self._type_exists(idati, change.name):
                try:
                    ida_typeinf.del_named_type(idati, change.name, ida_typeinf.NTF_TYPE)
                    self.log(f"Deleted stale managed type: {change.name}")
                except Exception as exc:
                    failed.append(change.name)
                    failed_types.add(change.name)
                    self.log(f"Failed to delete {change.name}: {exc}")

        for change in plan.changes:
            if change.action not in ("create", "replace"):
                if change.action == "skip":
                    self.log(f"Skipping existing unmanaged Local Type: {change.name}")
                elif change.action == "adopt":
                    self.log(f"Adopting unchanged unmanaged Local Type into managed set: {change.name}")
                continue

            if change.kind == "macro":
                try:
                    ordinal = self._write_macro_enum(idati, change)
                    resulting_macro_enums[change.macro_name] = self._macro_change_state(change, ordinal)
                    verb = "Updated" if change.action == "replace" else "Created"
                    self.log(f"{verb} macro enum {change.enum_name} with {len(change.macro_members)} member(s).")
                except Exception as exc:
                    failed.append(change.enum_name)
                    if change.action == "create":
                        resulting_macro_enums.pop(change.macro_name, None)
                    else:
                        resulting_macro_enums[change.macro_name] = copy.deepcopy(change.previous_macro_state)
                    self.log(f"Failed on macro enum {change.enum_name}: {exc}")
                continue

            replace = change.action == "replace"
            if replace and self._local_type_exists(idati, change.name):
                self.log(f"Updating Local Type from parsed header: {change.name}")
            elif replace:
                self.log(f"Creating Local Type shadow for existing base/library type: {change.name}")
            else:
                self.log(f"Creating Local Type: {change.name}")
            try:
                self._write_named_type(idati, source_til, change.name, replace=replace)
            except Exception as exc:
                failed.append(change.name)
                failed_types.add(change.name)
                self.log(f"Failed on {change.name}: {exc}")

        if failed:
            preview = ", ".join(failed[:5])
            suffix = "" if len(failed) <= 5 else f" (+{len(failed) - 5} more)"
            self.log(f"Import completed with {len(failed)} failure(s): {preview}{suffix}")

        return (
            [name for name in plan.resulting_type_names if name not in failed_types],
            resulting_macro_enums,
        )

    def _write_macro_enum(self, til: Any, change: TypeChange) -> int:
        """Create or replace one plugin-owned named enum."""

        details = ida_typeinf.enum_type_data_t()
        details.bte = change.enum_bte
        details.taenum_bits = change.enum_attrs
        for member in change.macro_members:
            edm = ida_typeinf.edm_t()
            edm.name = member["member_name"]
            edm.value = member["value"]
            details.push_back(edm)
        tif = ida_typeinf.tinfo_t()
        if not tif.create_enum(details):
            raise ClangIncludeError("could not construct enum tinfo")
        result = tif.set_type_cmt(_MACRO_MARKER_PREFIX + change.macro_name)
        if result != ida_typeinf.TERR_OK:
            raise ClangIncludeError(f"could not set ownership marker: {compat.tinfo_errstr(result)}")

        ordinal = change.ordinal
        allocated = False
        if ordinal <= 0:
            ordinal = int(ida_typeinf.alloc_type_ordinal(til) or 0)
            if ordinal <= 0:
                raise ClangIncludeError("could not allocate a Local Type ordinal")
            allocated = True
        flags = int(ida_typeinf.NTF_REPLACE) if change.action == "replace" else 0
        result = tif.set_numbered_type(til, ordinal, flags, change.enum_name)
        if result != ida_typeinf.TERR_OK:
            if allocated:
                try:
                    ida_typeinf.del_numbered_type(til, ordinal)
                except Exception:
                    pass
            raise ClangIncludeError(f"could not store enum {change.enum_name}: {compat.tinfo_errstr(result)}")
        try:
            ida_typeinf.set_type_choosable(til, ordinal, True)
        except Exception:
            pass
        return ordinal

    def _type_exists(self, til: Any, name: str) -> bool:
        """Check whether a named type already exists in the given type library."""

        tif = ida_typeinf.tinfo_t()
        return bool(tif.get_named_type(til, name))

    def _local_type_exists(self, til: Any, name: str) -> bool:
        """Check whether a named type has a real local ordinal in this TIL."""

        return self._get_local_type_ordinal(til, name) > 0

    def _get_local_type_ordinal(self, til: Any, name: str) -> int:
        """Resolve the local ordinal for one named type, if it exists locally."""

        return compat.local_type_ordinal(til, name)

    def _get_named_type_decl(self, til: Any, name: str) -> str:
        """Return a best-effort declaration string for one named type."""

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            return ""
        decl = self._print_tinfo_decl(tif, name)
        if decl:
            return decl
        decl = self._normalize_decl_text(tif.dstr())
        if decl:
            return decl
        return name

    def _print_tinfo_decl(self, tif: ida_typeinf.tinfo_t, name: str) -> str:
        """Ask IDA for a fuller C-style declaration for diff rendering."""

        flags = self._print_decl_flags()

        decl = self._normalize_decl_text(ida_typeinf.print_tinfo("", 0, 0, flags, tif, name, ""))
        return decl

    def _normalize_decl_text(self, value: Any) -> str:
        """Convert printer output into a trimmed declaration string."""

        if value is None:
            return ""
        text = str(value).strip()
        return text

    def _print_decl_flags(self) -> int:
        """Build a conservative flag set for multi-line C declarations."""

        return (
            int(ida_typeinf.PRTYPE_TYPE)
            | int(ida_typeinf.PRTYPE_DEF)
            | int(ida_typeinf.PRTYPE_MULTI)
            | int(ida_typeinf.PRTYPE_SEMI)
            | int(ida_typeinf.PRTYPE_METHODS)
        )

    def _free_til(self, til: Any) -> None:
        """Release a temporary TIL and ignore teardown errors."""

        try:
            ida_typeinf.free_til(til)
        except Exception:
            pass

    def _write_named_type(
        self,
        target_til: Any,
        source_til: Any,
        name: str,
        replace: bool,
    ) -> None:
        """Create or replace one named type in the target type library.

        New imports still use `import_type()` because it brings along dependent
        declarations from the temporary parse TIL. Replacements must preserve the
        existing Local Types ordinal so all current references keep pointing at
        the same logical type after an update.
        """

        if replace and self._local_type_exists(target_til, name):
            self._replace_named_type_in_place(target_til, source_til, name)
            return

        if not compat.import_named_type(target_til, source_til, name):
            action = "replace" if replace else "create"
            raise ClangIncludeError(f"Failed to {action} type {name}: import_type")

    def _replace_named_type_in_place(
        self,
        target_til: Any,
        source_til: Any,
        name: str,
    ) -> None:
        """Overwrite an existing named type without changing its ordinal."""

        ordinal = self._get_local_type_ordinal(target_til, name)
        if ordinal <= 0:
            raise ClangIncludeError(f"Failed to update type {name}: could not resolve existing ordinal")

        named_type = ida_typeinf.get_named_type(
            source_til,
            name,
            int(ida_typeinf.NTF_TYPE),
        )
        if not named_type:
            raise ClangIncludeError(f"Failed to read serialized type data: {name}")

        _code, type_data, field_data, type_cmt, field_cmts, sclass, _value = named_type
        result = ida_typeinf.set_numbered_type(
            target_til,
            ordinal,
            int(ida_typeinf.NTF_TYPE) | int(ida_typeinf.NTF_REPLACE),
            name,
            type_data,
            field_data,
            type_cmt,
            field_cmts,
            sclass,
        )
        if result != ida_typeinf.TERR_OK:
            error_text = compat.tinfo_errstr(result)
            raise ClangIncludeError(f"Failed to update type {name} in place: {error_text}")
