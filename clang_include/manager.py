"""Parsing, import orchestration, and Local Types synchronization logic."""

import subprocess
import tempfile
from pathlib import Path
from typing import Any, List, Sequence

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

        self._validate_profile(profile)
        self.save_profile(profile)

        engines = self._engine_order(profile.engine)
        errors = []
        for engine in engines:
            try:
                self.log(f"Parsing with {engine} engine...")
                result = self._sync_with_engine(profile, engine)
                profile.last_engine_used = engine
                profile.managed_type_names = result.type_names
                self.save_profile(profile)
                self.log(
                    f"Imported {len(result.type_names)} managed types using {engine}."
                )
                return result
            except Exception as exc:
                message = f"{engine} engine failed: {exc}"
                errors.append(message)
                self.log(message)

        raise ClangIncludeError("\n".join(errors))

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
            "<managed-temp.til>",
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

    def _sync_with_engine(self, profile: Profile, engine: str) -> SyncResult:
        """Parse with one backend and apply the resulting named types."""

        temp_til = None
        try:
            # Get the parsed types into a temporary TIL, then merge them into
            # the IDB's main TIL according to the plugin's rules.
            match engine:
                case "api":
                    temp_til = self._parse_with_api(profile)
                case "external":
                    temp_til = self._parse_with_external(profile)
                case _:
                    raise ClangIncludeError(f"Unknown engine: {engine}")

            type_names = self._apply_managed_types(temp_til, profile.managed_type_names)
            return SyncResult(engine, type_names)
        finally:
            # Temporary TILs are only used as an intermediate graph.
            if temp_til is not None:
                try:
                    ida_typeinf.free_til(temp_til)
                except Exception:
                    pass

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
        language = profile.language.strip() or "c++"
        args.extend(["-x", language])
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
            raise ClangIncludeError(f"ida_srclang reported {err_count} parse errors.")
        return temp_til

    def _parse_with_external(self, profile: Profile) -> Any:
        """Run external idaclang.exe and load the generated temporary TIL."""

        args = self._build_parser_args(profile)
        with tempfile.TemporaryDirectory(prefix="type_sync_") as temp_dir:
            temp_til_path = Path(temp_dir) / "type_sync.til"
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
            if (
                profile.log_external_output
                and completed.stderr.strip()
                and completed.returncode == 0
            ):
                self.log(completed.stderr.strip())
            if completed.returncode != 0:
                stderr = completed.stderr.strip()
                raise ClangIncludeError(
                    f"idaclang exited with code {completed.returncode}."
                    + (f" stderr: {stderr}" if stderr else "")
                )
            if not temp_til_path.is_file():
                raise ClangIncludeError("idaclang completed without producing a TIL file.")
            temp_til = ida_typeinf.load_til(str(temp_til_path))
            if not temp_til:
                raise ClangIncludeError(f"Failed to load generated TIL: {temp_til_path}")
            return temp_til

    def _apply_managed_types(
        self,
        source_til: Any,
        managed_names: Sequence[str],
    ) -> List[str]:
        """Merge parsed named types into Local Types."""

        source_names = sorted(source_til.type_names)
        if not source_names:
            raise ClangIncludeError("Parser succeeded but produced no named types.")

        idati = ida_typeinf.get_idati()
        managed_set = set(managed_names)
        source_set = set(source_names)
        stale_managed = sorted(managed_set - source_set)

        # Optionally remove names that used to be managed by the plugin but no
        # longer appear in the current parse result.
        if self.profile.delete_missing_managed_types:
            for name in stale_managed:
                if self._type_exists(idati, name):
                    ida_typeinf.del_named_type(idati, name, ida_typeinf.NTF_TYPE)
                    self.log(f"Deleted stale managed type: {name}")

        conflicts = []
        skipped_names = set()
        for name in source_names:
            if not self._type_exists(idati, name):
                continue

            # Managed names already belong to the plugin, so they are candidates
            # for in-place replacement rather than conflict handling.
            if name in managed_set:
                continue

            # Unmanaged collisions follow the user-selected conflict policy.
            if self.profile.existing_type_policy == "overwrite":
                self.log(f"Overwriting existing unmanaged Local Type: {name}")
                continue
            if self.profile.existing_type_policy == "skip":
                skipped_names.add(name)
                self.log(f"Skipping existing unmanaged Local Type: {name}")
                continue
            conflicts.append(name)

        if conflicts:
            preview = ", ".join(conflicts[:10])
            suffix = "" if len(conflicts) <= 10 else f" (+{len(conflicts) - 10} more)"
            raise ClangIncludeError(
                "Import blocked by existing unmanaged Local Types: "
                f"{preview}{suffix}. Change the overwrite policy in Options to overwrite or skip them."
            )

        imported_names = []
        for name in source_names:
            if name in skipped_names:
                continue

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(source_til, name):
                raise ClangIncludeError(f"Failed to read parsed type: {name}")

            # Replace if the name is already managed by the plugin or if the
            # user explicitly chose to overwrite an unmanaged collision.
            replace = name in managed_set or (
                self.profile.existing_type_policy == "overwrite"
                and self._type_exists(idati, name)
            )
            self._write_named_type(idati, tif, name, replace=replace)
            imported_names.append(name)

        # If stale managed types are kept, they remain in the managed set for
        # future refreshes.
        if not self.profile.delete_missing_managed_types:
            imported_names.extend(stale_managed)
        return sorted(set(imported_names))

    def _type_exists(self, til: Any, name: str) -> bool:
        """Check whether a named type already exists in the given type library."""

        tif = ida_typeinf.tinfo_t()
        return bool(tif.get_named_type(til, name))

    def _write_named_type(
        self,
        target_til: Any,
        tif: ida_typeinf.tinfo_t,
        name: str,
        replace: bool,
    ) -> None:
        """Create or replace one named type in the target type library."""

        flags = ida_typeinf.NTF_TYPE
        if replace:
            flags |= ida_typeinf.NTF_REPLACE

        code = tif.set_named_type(target_til, name, flags)
        if code != ida_typeinf.TERR_OK:
            action = "replace" if replace else "create"
            raise ClangIncludeError(
                f"Failed to {action} type {name}: {ida_typeinf.tinfo_errstr(code)}"
            )

