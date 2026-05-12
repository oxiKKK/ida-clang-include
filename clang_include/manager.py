"""Parsing, import management, and Local Types synchronization logic."""

import locale
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence

import ida_auto
import ida_kernwin
import ida_loader
import ida_typeinf
import idaapi

from . import compat
from .config import DEFAULT_IDACLANG, PLUGIN_NAME
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

    pass


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


@dataclass
class SyncPlan:
    """Dry-run plan describing what an import would change."""

    engine: str
    changes: List[TypeChange]
    resulting_type_names: List[str]


class PreparedSync:
    """Parsed temporary TIL plus the dry-run plan built from it."""

    def __init__(self, engine: str, temp_til: Any, plan: SyncPlan) -> None:
        self.engine = engine
        self.temp_til = temp_til
        self.plan = plan


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
                plan = self._build_sync_plan(profile, engine, temp_til)
                self.log(f"Prepared {len(plan.changes)} planned change(s) using {self._engine_label(engine)}.")
                return PreparedSync(engine, temp_til, plan)
            except Exception as exc:
                if temp_til is not None:
                    self._free_til(temp_til)
                message = f"{self._engine_label(engine)} failed: {exc}"
                errors.append(message)
                self.log(message)

        raise ClangIncludeError("\n".join(errors))

    def apply_prepared_sync(self, profile: Profile, prepared: PreparedSync) -> SyncResult:
        """Apply a previously prepared dry-run plan to Local Types."""

        type_names = self._apply_sync_plan(prepared.temp_til, prepared.plan)
        profile.last_engine_used = prepared.engine
        profile.managed_type_names = type_names
        self.save_profile(profile)
        self.log(f"Imported {len(type_names)} managed types using {self._engine_label(prepared.engine)}.")
        return SyncResult(prepared.engine, type_names)

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

        if profile.engine == "api":
            return api_preview
        if profile.engine == "external":
            return external_preview

        order = " -> ".join(self._engine_label(engine) for engine in self._engine_order("auto"))
        return f"Auto order: {order}\nAPI argv: {api_preview}\nExternal command: {external_preview}"

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
    ) -> SyncPlan:
        """Compute the Local Types changes implied by the parsed source TIL."""

        source_names = sorted(compat.til_type_names(source_til))
        if not source_names:
            raise ClangIncludeError("Parser succeeded but produced no named types.")

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
        return SyncPlan(
            engine=engine,
            changes=changes,
            resulting_type_names=sorted(set(imported_names)),
        )

    def _apply_sync_plan(self, source_til: Any, plan: SyncPlan) -> List[str]:
        """Apply a previously computed sync plan to Local Types."""

        idati = ida_typeinf.get_idati()

        failed: List[str] = []

        for change in plan.changes:
            if change.action == "delete" and self._type_exists(idati, change.name):
                try:
                    ida_typeinf.del_named_type(idati, change.name, ida_typeinf.NTF_TYPE)
                    self.log(f"Deleted stale managed type: {change.name}")
                except Exception as exc:
                    failed.append(change.name)
                    self.log(f"Failed to delete {change.name}: {exc}")

        for change in plan.changes:
            if change.action not in ("create", "replace"):
                if change.action == "skip":
                    self.log(f"Skipping existing unmanaged Local Type: {change.name}")
                elif change.action == "adopt":
                    self.log(f"Adopting unchanged unmanaged Local Type into managed set: {change.name}")
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
                self.log(f"Failed on {change.name}: {exc}")

        if failed:
            preview = ", ".join(failed[:5])
            suffix = "" if len(failed) <= 5 else f" (+{len(failed) - 5} more)"
            self.log(f"Import completed with {len(failed)} failure(s): {preview}{suffix}")

        failed_set = set(failed)
        return [name for name in plan.resulting_type_names if name not in failed_set]

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
