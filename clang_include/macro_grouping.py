"""Pure helpers for persistent macro enum definitions and suggestions."""

import re
import uuid
from typing import Dict, Iterable, List, Sequence

from .macro_conversion import parse_integer_literal

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_]\w*$")
_DEFINITION_NAMESPACE = uuid.UUID("00c196ba-e6bb-4a7e-8dd8-71bcb01726fa")


def is_c_identifier(value: str) -> bool:
    """Return whether *value* can be used as a C enum or enumerator name."""

    return bool(_IDENTIFIER_RE.fullmatch(value))


def stable_definition_id(enum_name: str, pattern: str = "") -> str:
    """Return a deterministic ID for a migrated enum definition."""

    return str(uuid.uuid5(_DEFINITION_NAMESPACE, f"{enum_name}\n{pattern}"))


def new_definition_id() -> str:
    """Return a new persistent enum-definition ID."""

    return str(uuid.uuid4())


def new_member_id() -> str:
    """Return a new persistent enum-member ID."""

    return str(uuid.uuid4())


def macro_member_id(definition_id: str, macro_name: str) -> str:
    """Return the stable member ID for a macro within one enum definition."""

    return str(uuid.uuid5(_DEFINITION_NAMESPACE, f"{definition_id}\nmacro\n{macro_name}"))


def migrate_group_rules(rules: Sequence[dict]) -> List[dict]:
    """Convert removed regex grouping rules into snapshot enum definitions."""

    definitions: List[dict] = []
    for rule in rules:
        enum_name = str(rule.get("enum_name", "")).strip()
        pattern = str(rule.get("pattern", "")).strip()
        if not is_c_identifier(enum_name):
            continue
        definition_id = stable_definition_id(enum_name, pattern)
        members = []
        for raw_name in rule.get("selected", []):
            name = str(raw_name).strip()
            if not is_c_identifier(name):
                continue
            members.append(
                {
                    "id": macro_member_id(definition_id, name),
                    "kind": "macro",
                    "source_name": name,
                    "emitted_name": name,
                    "last_value": 0,
                    "width": 4,
                    "enum_bte": 0,
                    "enum_attrs": 0,
                    "missing": True,
                }
            )
        definitions.append(
            {
                "id": definition_id,
                "owner_key": f"group:{enum_name}",
                "enum_name": enum_name,
                "origin": "detected",
                "source_pattern": pattern,
                "members": members,
            }
        )
    return definitions


def suggest_macro_groups(macro_names: Iterable[str], minimum_members: int = 2) -> List[dict]:
    """Suggest every broad and specific shared underscore-prefix level."""

    prefixes: Dict[str, set[str]] = {}
    for name in sorted(set(macro_names), key=str.casefold):
        parts = name.split("_")
        for length in range(1, len(parts)):
            if all(parts[:length]):
                prefix = "_".join(parts[:length]) + "_"
                prefixes.setdefault(prefix, set()).add(name)

    suggestions: List[dict] = []
    ordered = sorted(prefixes.items(), key=lambda item: (item[0].count("_"), item[0].casefold()))
    for prefix, members in ordered:
        if len(members) < minimum_members:
            continue
        suggestions.append(
            {
                "enum_name": "MACRO_" + prefix.rstrip("_"),
                "pattern": "^" + re.escape(prefix),
            }
        )
    return suggestions


def partition_managed_member_names(
    states: Dict[str, dict],
    active_member_names: Dict[str, Dict[str, str]],
) -> tuple[set[str], set[str]]:
    """Split existing names into retained and freed-by-this-plan sets."""

    reserved = set()
    reclaimable = set()
    for owner_key, state in states.items():
        active_names = active_member_names.get(owner_key, {})
        for member_key, member_name in state.get("member_names", {}).items():
            target = reserved if active_names.get(member_key) == member_name else reclaimable
            target.add(str(member_name))
    return reserved, reclaimable


def allocate_member_names(definitions: Sequence[dict]) -> None:
    """Assign stable, globally unique names to macro-backed members in place."""

    used = {
        str(member.get("name", ""))
        for definition in definitions
        for member in definition.get("members", [])
        if member.get("kind") == "custom"
    }
    for definition in definitions:
        for member in definition.get("members", []):
            if member.get("kind") == "custom":
                continue
            source_name = str(member.get("source_name", ""))
            current = str(member.get("emitted_name") or source_name)
            if current and current not in used:
                member["emitted_name"] = current
                used.add(current)
                continue
            suffix = 2
            candidate = f"{source_name}_{suffix}"
            while candidate in used:
                suffix += 1
                candidate = f"{source_name}_{suffix}"
            member["emitted_name"] = candidate
            used.add(candidate)


def enum_definitions_error(definitions: Sequence[dict]) -> str:
    """Return the first user-facing workspace validation error, if any."""

    enum_names = set()
    member_names = set()
    for definition in definitions:
        enum_name = str(definition.get("enum_name", "")).strip()
        if not is_c_identifier(enum_name):
            return f"{enum_name!r} is not a valid enum name."
        if enum_name in enum_names:
            return f"Enum name {enum_name} is used more than once."
        if not definition.get("members"):
            return f"{enum_name} has no members. Add a value or delete the enum."
        enum_names.add(enum_name)
        local_names = set()
        for member in definition["members"]:
            if member.get("kind") == "custom":
                name = str(member.get("name", ""))
                literal = str(member.get("literal", member.get("value", "")))
                if parse_integer_literal(literal) is None:
                    return f"{literal!r} is not a supported integer value for {name}."
            else:
                name = str(member.get("emitted_name", ""))
            if not is_c_identifier(name):
                return f"{name!r} in {enum_name} is not a valid member name."
            if name in local_names:
                return f"{name} appears more than once in {enum_name}."
            if member.get("kind") == "custom" and name in member_names:
                return f"Custom member name {name} is already used by another imported enum."
            local_names.add(name)
            member_names.add(name)
    return ""


def group_tree_parents(enum_names: Sequence[str]) -> List[int | None]:
    """Return the nearest underscore-prefix parent index for each enum name."""

    names = list(enum_names)
    parents: List[int | None] = []
    for index, name in enumerate(names):
        candidates = [
            (len(parent), parent_index)
            for parent_index, parent in enumerate(names)
            if parent_index != index and name.startswith(parent + "_")
        ]
        parents.append(max(candidates)[1] if candidates else None)
    return parents
