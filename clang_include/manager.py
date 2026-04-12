"""Parsing, import management, and Local Types synchronization logic."""

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence

import ida_auto
import ida_kernwin
import ida_loader
import ida_srclang
import ida_typeinf
from PySide6 import QtCore

from .config import DEFAULT_IDACLANG, PLUGIN_NAME
from .model import Profile, SettingsStore


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

    log_message = QtCore.Signal(str)
    profile_changed = QtCore.Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._store = SettingsStore()
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

        engines = self._engine_order(profile.engine)
        errors = []
        for engine in engines:
            temp_til = None
            try:
                self.log(f"Parsing with {engine} engine...")
                temp_til = self._parse_with_engine(profile, engine)
                plan = self._build_sync_plan(profile, engine, temp_til)
                self.log(
                    f"Prepared {len(plan.changes)} planned change(s) using {engine}."
                )
                return PreparedSync(engine, temp_til, plan)
            except Exception as exc:
                if temp_til is not None:
                    self._free_til(temp_til)
                message = f"{engine} engine failed: {exc}"
                errors.append(message)
                self.log(message)

        raise ClangIncludeError("\n".join(errors))

    def apply_prepared_sync(
        self, profile: Profile, prepared: PreparedSync
    ) -> SyncResult:
        """Apply a previously prepared dry-run plan to Local Types."""

        type_names = self._apply_sync_plan(prepared.temp_til, prepared.plan)
        profile.last_engine_used = prepared.engine
        profile.managed_type_names = type_names
        self.save_profile(profile)
        self.log(f"Imported {len(type_names)} managed types using {prepared.engine}.")
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
        """Build the external-style command preview shown in the UI."""

        args = self._build_parser_args(profile)
        full = [
            profile.idaclang_path or str(DEFAULT_IDACLANG),
            *args,
            "--idaclang-tilname",
            str(self._external_temp_til_path()),
            profile.header_path,
        ]
        return subprocess.list2cmdline(full)

    def _validate_profile(self, profile: Profile) -> None:
        """Reject invalid states before any parsing work starts."""

        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            raise ClangIncludeError("Open an IDB before using the plugin.")
        if not ida_auto.auto_is_ok():
            raise ClangIncludeError(
                "Wait for auto-analysis to complete before importing types."
            )
        if not profile.header_path:
            raise ClangIncludeError("Header path is required.")
        if not Path(profile.header_path).is_file():
            raise ClangIncludeError(f"Header file does not exist: {profile.header_path}")
        if profile.engine in ("external", "auto"):
            if not Path(profile.idaclang_path).is_file():
                raise ClangIncludeError(
                    f"idaclang executable does not exist: {profile.idaclang_path}"
                )

    def _engine_order(self, preferred: str) -> List[str]:
        """Resolve the backend order for the current sync run."""

        if preferred == "api":
            return ["api"]
        if preferred == "external":
            return ["external"]

        if self.profile.auto_engine_order == "external_first":
            return ["external", "api"]
        return ["api", "external"]

    def _parse_with_engine(self, profile: Profile, engine: str) -> Any:
        """Parse with one backend and return the temporary TIL."""

        match engine:
            case "api":
                return self._parse_with_api(profile)
            case "external":
                return self._parse_with_external(profile)
            case _:
                raise ClangIncludeError(f"Unknown engine: {engine}")

    def _build_parser_args(self, profile: Profile) -> List[str]:
        """Build argv for either parser backend.

        A non-empty raw argv field overrides the structured controls because it
        represents the user's exact desired command line.
        """

        if profile.raw_argv.strip():
            return self._split_raw_args(profile.raw_argv)

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
        args.extend(self._split_raw_args(profile.extra_args))
        return args

    def _split_raw_args(self, raw: str) -> List[str]:
        """Split a Windows-style command line fragment into argv tokens."""

        import shlex

        if not raw.strip():
            return []
        return shlex.split(raw, posix=False)

    def _parse_with_api(self, profile: Profile) -> Any:
        """Use IDA's in-process source parser to build a temporary TIL."""

        language = (profile.language or "c++").lower()
        if language in ("c", "objc"):
            srclang = (
                ida_srclang.SRCLANG_C if language == "c" else ida_srclang.SRCLANG_OBJC
            )
        elif language in ("objective-c++", "objcpp", "objc++"):
            srclang = ida_srclang.SRCLANG_OBJCPP
        else:
            srclang = ida_srclang.SRCLANG_CPP

        if not ida_srclang.select_parser_by_srclang(srclang):
            raise ClangIncludeError(
                f"No source parser is available in ida_srclang for language: {profile.language}"
            )
        parser_name = ida_srclang.get_selected_parser_name()
        if not parser_name:
            raise ClangIncludeError("ida_srclang did not return a parser name.")

        argv = subprocess.list2cmdline(self._build_parser_args(profile))
        rc = ida_srclang.set_parser_argv(parser_name, argv)
        if rc != 0:
            raise ClangIncludeError(
                f"set_parser_argv failed with code {rc} for parser {parser_name}."
            )

        # Parse into a temporary TIL first. Only after a fully successful parse
        # do we touch the IDB's Local Types.
        temp_til = ida_typeinf.new_til(
            "clang_include_api",
            "Clang Include API parse result",
        )
        err_count = ida_srclang.parse_decls_with_parser(
            parser_name, temp_til, profile.header_path, True
        )
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

        args = self._build_parser_args(profile)
        temp_til_path = self._external_temp_til_path()
        temp_til_path.parent.mkdir(parents=True, exist_ok=True)
        if temp_til_path.exists():
            temp_til_path.unlink()
        try:
            command = [
                profile.idaclang_path,
                *args,
                "--idaclang-tilname",
                str(temp_til_path),
                profile.header_path,
            ]
            # Logging the exact command makes parser issues reproducible and
            # easy to compare with manual command-line runs.
            self.log(f"Running external parser: {subprocess.list2cmdline(command)}")
            completed = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            if profile.log_external_output and completed.stdout.strip():
                self.log(completed.stdout.strip())
            stderr = completed.stderr.strip()
            if profile.log_external_output and stderr:
                self.log(stderr)
            if completed.returncode != 0:
                first_line = stderr.splitlines()[0] if stderr else ""
                raise ClangIncludeError(
                    f"idaclang exited with code {completed.returncode}. "
                    "Review the Clang Include Log tab for compiler diagnostics."
                    + (f" First diagnostic: {first_line}" if first_line else "")
                )
            if not temp_til_path.is_file():
                raise ClangIncludeError("idaclang completed without producing a TIL file.")
            temp_til = ida_typeinf.load_til(str(temp_til_path))
            if not temp_til:
                raise ClangIncludeError(f"Failed to load generated TIL: {temp_til_path}")
            return temp_til
        finally:
            try:
                if temp_til_path.exists():
                    temp_til_path.unlink()
            except Exception:
                pass

    def _external_temp_til_path(self) -> Path:
        """Return the concrete temporary .til path used by external parsing."""

        return Path(tempfile.gettempdir()) / "ida-clang-include" / "managed-temp.til"

    def _build_sync_plan(
        self,
        profile: Profile,
        engine: str,
        source_til: Any,
    ) -> SyncPlan:
        """Compute the Local Types changes implied by the parsed source TIL."""

        source_names = sorted(source_til.type_names)
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

        for change in plan.changes:
            if change.action == "delete" and self._type_exists(idati, change.name):
                ida_typeinf.del_named_type(idati, change.name, ida_typeinf.NTF_TYPE)
                self.log(f"Deleted stale managed type: {change.name}")

        for change in plan.changes:
            if change.action not in ("create", "replace"):
                if change.action == "skip":
                    self.log(f"Skipping existing unmanaged Local Type: {change.name}")
                elif change.action == "adopt":
                    self.log(
                        f"Adopting unchanged unmanaged Local Type into managed set: {change.name}"
                    )
                continue

            replace = change.action == "replace"
            if replace and self._local_type_exists(idati, change.name):
                self.log(f"Updating Local Type from parsed header: {change.name}")
            elif replace:
                self.log(
                    f"Creating Local Type shadow for existing base/library type: {change.name}"
                )
            else:
                self.log(f"Creating Local Type: {change.name}")
            self._write_named_type(idati, source_til, change.name, replace=replace)

        return list(plan.resulting_type_names)

    def _type_exists(self, til: Any, name: str) -> bool:
        """Check whether a named type already exists in the given type library."""

        tif = ida_typeinf.tinfo_t()
        return bool(tif.get_named_type(til, name))

    def _local_type_exists(self, til: Any, name: str) -> bool:
        """Check whether a named type has a real local ordinal in this TIL."""

        return self._get_local_type_ordinal(til, name) > 0

    def _get_local_type_ordinal(self, til: Any, name: str) -> int:
        """Resolve the local ordinal for one named type, if it exists locally."""

        ordinal = int(ida_typeinf.get_type_ordinal(til, name) or 0)
        if ordinal > 0:
            return ordinal

        tid = int(ida_typeinf.get_named_type_tid(name) or ida_typeinf.BADORD)
        if tid in (ida_typeinf.BADORD, 0):
            return 0
        return int(ida_typeinf.get_tid_ordinal(tid) or 0)

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

        decl = self._normalize_decl_text(
            ida_typeinf.print_tinfo("", 0, 0, flags, tif, name, "")
        )
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

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(source_til, name):
            raise ClangIncludeError(f"Failed to read parsed type: {name}")

        imported_tif = target_til.import_type(tif)
        if not imported_tif:
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
            raise ClangIncludeError(
                f"Failed to update type {name}: could not resolve existing ordinal"
            )

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
            error_text = ida_typeinf.tinfo_errstr(result) or str(result)
            raise ClangIncludeError(
                f"Failed to update type {name} in place: {error_text}"
            )

