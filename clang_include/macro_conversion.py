"""Fast numeric-macro discovery without depending on IDA modules."""

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class MacroValue:
    name: str
    value: int
    width: int = 4
    signed: bool = True


class MacroConversionError(RuntimeError):
    pass


_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)(.*)$")
_UNDEF_RE = re.compile(r"^\s*#\s*undef\s+([A-Za-z_]\w*)")
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')
_DIRECTIVE_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
_LINE_MARKER_RE = re.compile(r'^#\s+\d+\s+"([^"]+)"(.*)$')
_INTEGER_RE = re.compile(
    r"^(?P<sign>[+-]?)\s*(?P<number>0[xX][0-9a-fA-F']+|0[bB][01']+|0[0-7']*|[1-9][0-9']*)"
    r"(?P<suffix>[uUlLzZ]*)$"
)
_VALID_SUFFIXES = {"", "u", "l", "ul", "lu", "ll", "ull", "llu", "z", "uz", "zu"}


def parse_integer_literal(text: str) -> Optional[Tuple[int, int, bool]]:
    """Parse a conservative C/C++ integer literal as value, width, signed."""

    match = _INTEGER_RE.fullmatch(_strip_outer_parentheses(text.strip()))
    if not match:
        return None
    suffix = match.group("suffix").lower()
    if suffix not in _VALID_SUFFIXES:
        return None
    number = match.group("number").replace("'", "")
    if number.lower().startswith("0x"):
        base = 16
    elif number.lower().startswith("0b"):
        base = 2
    elif len(number) > 1 and number.startswith("0"):
        base = 8
    else:
        base = 10
    value = int(number, base)
    if match.group("sign") == "-":
        value = -value
    unsigned = "u" in suffix
    width = 8 if "ll" in suffix or "z" in suffix or value > 0xFFFFFFFF or value < -0x80000000 else 4
    if unsigned and value < 0:
        value &= (1 << (width * 8)) - 1
    return value, width, not unsigned


def collect_python_macros(
    header_path: str,
    include_paths: Sequence[str],
    predefined_names: Iterable[str] = (),
) -> List[MacroValue]:
    scanner = _PythonScanner(include_paths, predefined_names)
    scanner.scan(Path(header_path))
    return sorted(scanner.values.values(), key=lambda item: item.name.casefold())


class _PythonScanner:
    def __init__(self, include_paths: Sequence[str], predefined_names: Iterable[str]) -> None:
        self.include_paths = [Path(path).resolve() for path in include_paths if path]
        self.defined: Set[str] = set(predefined_names)
        self.values: Dict[str, MacroValue] = {}
        self.visited: Set[Path] = set()

    def scan(self, path: Path) -> None:
        try:
            path = path.resolve()
        except OSError:
            return
        if path in self.visited or not path.is_file():
            return
        self.visited.add(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        active = True
        frames: List[dict] = []
        for line in _logical_lines(_remove_comments(text)):
            directive = _DIRECTIVE_RE.match(line)
            if directive:
                active = self._conditional(directive.group(1), directive.group(2).strip(), frames, active)
                continue
            if not active:
                continue
            undef = _UNDEF_RE.match(line)
            if undef:
                name = undef.group(1)
                self.defined.discard(name)
                self.values.pop(name, None)
                continue
            define = _DEFINE_RE.match(line)
            if define:
                name, tail = define.groups()
                if tail.startswith("("):  # no whitespace means function-like
                    continue
                self.defined.add(name)
                parsed = parse_integer_literal(tail.strip())
                if parsed is None:
                    self.values.pop(name, None)
                else:
                    value, width, signed = parsed
                    self.values[name] = MacroValue(name, value, width, signed)
                continue
            include = _INCLUDE_RE.match(line)
            if include:
                resolved = self._resolve_include(path.parent, include.group(1), include.group(2).strip())
                if resolved is not None:
                    self.scan(resolved)

    def _conditional(self, kind: str, expression: str, frames: List[dict], active: bool) -> bool:
        if kind in ("if", "ifdef", "ifndef"):
            parent = active
            result = self._condition_value(kind, expression) if parent else False
            known = result is not None
            branch = bool(parent and known and result)
            frames.append({"parent": parent, "taken": branch, "known": known})
            return branch
        if not frames:
            return active
        frame = frames[-1]
        if kind == "endif":
            frames.pop()
            return bool(frame["parent"])
        if kind == "else":
            branch = bool(frame["parent"] and frame["known"] and not frame["taken"])
        else:
            result = self._condition_value("if", expression)
            branch = bool(frame["parent"] and frame["known"] and not frame["taken"] and result is True)
            frame["known"] = bool(frame["known"] and result is not None)
        frame["taken"] = bool(frame["taken"] or branch)
        return branch

    def _condition_value(self, kind: str, expression: str) -> Optional[bool]:
        if kind == "ifdef":
            return expression in self.defined
        if kind == "ifndef":
            return expression not in self.defined
        if expression in ("0", "1"):
            return expression == "1"
        match = re.fullmatch(r"(!?)\s*defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|\s+([A-Za-z_]\w*))", expression)
        if not match:
            return None
        result = (match.group(2) or match.group(3)) in self.defined
        return not result if match.group(1) else result

    def _resolve_include(self, current_dir: Path, delimiter: str, name: str) -> Optional[Path]:
        roots = ([current_dir] if delimiter == '"' else []) + self.include_paths
        for root in roots:
            candidate = (root / name).resolve()
            if candidate.is_file():
                return candidate
        return None


def collect_clang_macros(clang_path: str, header_path: str, args: Sequence[str]) -> List[MacroValue]:
    """Discover and evaluate project macros with exactly two Clang runs."""

    clang_args = _sanitize_clang_args(args)
    preprocessed = _run_clang([clang_path, *clang_args, "-E", "-dD", header_path])
    if preprocessed.returncode != 0:
        raise MacroConversionError(
            _first_error(preprocessed.stderr) or f"Clang exited with code {preprocessed.returncode}"
        )
    candidates = _parse_preprocessed_definitions(preprocessed.stdout)
    if not candidates:
        return []

    with tempfile.TemporaryDirectory(prefix="ida-clang-include-clang-") as directory:
        wrapper = Path(directory) / "macro-evaluation.h"
        include_path = Path(header_path).resolve().as_posix().replace('"', '\\"')
        names = sorted(candidates, key=str.casefold)
        lines = [f'#include "{include_path}"']
        for index, name in enumerate(names):
            lines.extend((f"#ifdef {name}", f"enum {{ __clang_include_macro_{index} = ({name}) }};", "#endif"))
        wrapper.write_text("\n".join(lines) + "\n", encoding="utf-8")
        dumped = _run_clang(
            [
                clang_path,
                *clang_args,
                "-fsyntax-only",
                "-Xclang",
                "-ast-dump=json",
                "-Xclang",
                "-ast-dump-filter=__clang_include_macro_",
                str(wrapper),
            ]
        )
        objects = _decode_json_stream(dumped.stdout)
        if not objects and "fatal error:" in dumped.stderr.lower():
            raise MacroConversionError(_first_error(dumped.stderr) or "Clang AST evaluation failed")

    synthetic_names = {f"__clang_include_macro_{index}": name for index, name in enumerate(names)}
    result: List[MacroValue] = []
    for node in objects:
        macro_name = synthetic_names.get(node.get("name", ""))
        constant = _find_constant_expr(node)
        if macro_name is None or constant is None or "value" not in constant:
            continue
        try:
            value = int(constant["value"], 10)
        except (TypeError, ValueError):
            continue
        qual_type = str(constant.get("type", {}).get("qualType", "int"))
        width = _clang_type_width(qual_type, clang_args)
        if width <= 8 and -(1 << 63) <= value <= (1 << 64) - 1:
            result.append(MacroValue(macro_name, value, width, "unsigned" not in qual_type))
    return sorted(result, key=lambda item: item.name.casefold())


def _parse_preprocessed_definitions(text: str) -> Set[str]:
    definitions: Dict[str, bool] = {}
    current_source = False
    current_system = False
    system_files: Set[str] = set()
    for line in _logical_lines(text):
        marker = _LINE_MARKER_RE.match(line)
        if marker:
            filename, flag_text = marker.groups()
            flags = {int(value) for value in flag_text.split() if value.isdigit()}
            if 3 in flags:
                system_files.add(filename)
            current_system = filename in system_files
            current_source = not (filename.startswith("<") and filename.endswith(">"))
            continue
        undef = _UNDEF_RE.match(line)
        if undef:
            definitions.pop(undef.group(1), None)
            continue
        define = _DEFINE_RE.match(line)
        if define:
            name, tail = define.groups()
            definitions[name] = bool(
                current_source and not current_system and not tail.startswith("(") and tail.strip()
            )
    return {name for name, is_project in definitions.items() if is_project}


def _sanitize_clang_args(args: Sequence[str]) -> List[str]:
    result: List[str] = []
    skip = False
    value_options = {"-o", "--output", "--idaclang-tilname", "--idaclang-tildesc", "--idaclang-macros"}
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in value_options:
            skip = True
            continue
        if arg == "-E" or arg.startswith("--idaclang-"):
            continue
        result.append(arg)
    return result


def _run_clang(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except OSError as exc:
        raise MacroConversionError(f"Could not run Clang: {exc}") from exc


def _decode_json_stream(text: str) -> List[dict]:
    decoder = json.JSONDecoder()
    values: List[dict] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            break
        if isinstance(value, dict):
            values.append(value)
    return values


def _find_constant_expr(node: dict) -> Optional[dict]:
    for child in node.get("inner", []):
        if child.get("kind") == "ConstantExpr" and "value" in child:
            return child
        found = _find_constant_expr(child)
        if found is not None:
            return found
    return None


def _clang_type_width(qual_type: str, args: Sequence[str]) -> int:
    lowered = qual_type.lower()
    if "__int128" in lowered:
        return 16
    if "long long" in lowered:
        return 8
    if re.search(r"\blong\b", lowered):
        target = " ".join(args).lower()
        return 4 if "windows" in target or "msvc" in target else 8
    if "short" in lowered:
        return 2
    if "char" in lowered:
        return 1
    return 4


def _logical_lines(text: str) -> List[str]:
    return re.sub(r"\\\r?\n", "", text).splitlines()


def _remove_comments(text: str) -> str:
    return re.sub(r"//[^\r\n]*", "", re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL))


def _strip_outer_parentheses(text: str) -> str:
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        encloses_all = True
        for index, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(text) - 1:
                    encloses_all = False
                    break
            if depth < 0:
                return text
        if depth != 0 or not encloses_all:
            break
        text = text[1:-1].strip()
    return text


def _first_error(stderr: str) -> str:
    for line in stderr.splitlines():
        if "error:" in line.lower():
            return line.strip()
    return stderr.strip().splitlines()[0] if stderr.strip() else ""
