"""On-disk storage for global, cross-IDB Clang Include profiles."""

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import List

from .model import Profile

# Fields owned by a specific IDB rather than by the cross-IDB configuration.
# These are excluded when serializing a global profile and preserved on the
# current IDB when one is loaded.
PER_IDB_RUNTIME_FIELDS = ("managed_type_names", "last_engine_used")


def _global_profiles_dir() -> Path:
    """Resolve the on-disk directory used to store global profiles.

    Imported lazily so test environments without IDA can still import this
    module if they ever need to.
    """

    import idaapi

    return Path(idaapi.get_user_idadir()) / "cfg" / "clang_include" / "profiles"


def _filename_short_formatted_name(name: str) -> str:
    """Convert a display name into a filesystem-safe formatted-name."""

    lowered = name.strip().lower()
    formatted = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return formatted or "profile"


class GlobalProfileStore:
    """Read/write named profiles stored as JSON files on disk."""

    def __init__(self) -> None:
        self._dir = _global_profiles_dir()
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def path_for(self, name: str) -> Path:
        """Return the on-disk path that would back the given display name."""

        return self._dir / f"{_filename_short_formatted_name(name)}.json"

    def list_names(self) -> List[str]:
        """Return the display names of all profiles currently on disk."""

        names: List[str] = []
        for path in self._dir.glob("*.json"):
            try:
                blob = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            name = blob.get("name") if isinstance(blob, dict) else None
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
            else:
                names.append(path.stem)
        return sorted(set(names), key=str.casefold)

    def load(self, name: str) -> Profile:
        """Load one profile from disk into a Profile dataclass.

        The returned profile only contains the shared fields; callers merge it
        onto the current IDB profile so per-IDB runtime state survives.
        """

        path = self._existing_path_for(name)
        blob = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(blob, dict):
            raise ValueError(f"Profile file is malformed: {path}")
        data = blob.get("profile") if "profile" in blob else blob
        if not isinstance(data, dict):
            raise ValueError(f"Profile file has no profile object: {path}")
        # Defensive: drop runtime fields if a hand-edited file kept them.
        for field in PER_IDB_RUNTIME_FIELDS:
            data.pop(field, None)
        return Profile.from_dict(data)

    def save(self, name: str, profile: Profile) -> Path:
        """Persist a profile snapshot to disk under the given display name."""

        if not name or not name.strip():
            raise ValueError("Profile name cannot be empty.")
        data = asdict(profile)
        for field in PER_IDB_RUNTIME_FIELDS:
            data.pop(field, None)
        blob = {
            "name": name.strip(),
            "version": 1,
            "profile": data,
        }
        path = self.path_for(name)
        path.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        return path

    def delete(self, name: str) -> None:
        """Remove the on-disk file backing the given display name."""

        path = self._existing_path_for(name)
        path.unlink()

    def _existing_path_for(self, name: str) -> Path:
        """Resolve a display name to its on-disk file, falling back to a scan.

        The formatted-name rule is deterministic for new files, but a hand-edited file
        could have a different filename while still carrying the right `name`
        field. Try the formatted-name first, then scan as a fallback.
        """

        path = self.path_for(name)
        if path.is_file():
            return path
        target = name.strip()
        for candidate in self._dir.glob("*.json"):
            try:
                blob = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(blob, dict) and blob.get("name", "").strip() == target:
                return candidate
        raise FileNotFoundError(f"No global profile named {name!r}")
