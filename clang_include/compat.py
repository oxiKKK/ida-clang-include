"""Feature-detected shims smoothing over IDA 7.x/8.x vs 9.x API differences.

The 9.0 type-system overhaul moved several free functions onto til_t/tinfo_t,
introduced new helpers (tinfo_errstr, get_named_type_tid, get_tid_ordinal),
added SRCLANG_OBJCPP, and added get_selected_parser_name. These shims gate on
the presence of each symbol so the plugin works on any IDA version that
provides at least one of the two API shapes.
"""

from typing import Any, List, Tuple

import ida_netnode
import ida_srclang
import ida_typeinf

_HAS_TIL_TYPE_NAMES = hasattr(ida_typeinf.til_t, "type_names")
_HAS_TIL_IMPORT_TYPE_METHOD = hasattr(ida_typeinf.til_t, "import_type")
_HAS_TINFO_ERRSTR = hasattr(ida_typeinf, "tinfo_errstr")
_HAS_NAMED_TYPE_TID = hasattr(ida_typeinf, "get_named_type_tid") and hasattr(
    ida_typeinf, "get_tid_ordinal"
)
_HAS_SRCLANG_OBJCPP = hasattr(ida_srclang, "SRCLANG_OBJCPP")
_HAS_SELECTED_PARSER_NAME = hasattr(ida_srclang, "get_selected_parser_name")


# Pre-9.x ships a single bundled source parser registered as "clang". 9.x
# returns the active parser name dynamically via get_selected_parser_name.
_LEGACY_PARSER_NAME = "clang"


class CompatError(RuntimeError):
    """Raised when the compat layer cannot satisfy a request on this IDA build."""


def til_type_names(til: Any) -> List[str]:
    """Return all named types in a TIL, regardless of IDA version."""

    if _HAS_TIL_TYPE_NAMES:
        return list(til.type_names)

    names: List[str] = []
    name = ida_typeinf.first_named_type(til, ida_typeinf.NTF_TYPE)
    while name:
        names.append(name)
        name = ida_typeinf.next_named_type(til, name, ida_typeinf.NTF_TYPE)
    return names


def import_named_type(target_til: Any, source_til: Any, name: str) -> bool:
    """Copy one named type from source_til into target_til.

    9.x exposes til_t.import_type(tinfo_t) which can target any til. Pre-9.x
    has a free function whose write destination is hard-coded to the IDB; it
    only reads from the supplied til. The plugin always passes idati as the
    target, so on pre-9.x we simply ignore target_til.
    """

    if _HAS_TIL_IMPORT_TYPE_METHOD:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(source_til, name):
            return False
        return bool(target_til.import_type(tif))

    # Pre-9.x import_type pulls dependencies recursively, so the type may
    # already be in the target by the time we explicitly request it. With
    # default flags, a re-import on an existing name returns BADNODE; treat
    # an already-present type as success since the caller's goal is met.
    if ida_typeinf.get_type_ordinal(target_til, name) > 0:
        return True
    tid = ida_typeinf.import_type(source_til, -1, name)
    return tid != ida_netnode.BADNODE


def local_type_ordinal(til: Any, name: str) -> int:
    """Resolve the local-type ordinal for one name.

    Pre-9.x stores local types as ordinals exclusively, so get_type_ordinal is
    authoritative. 9.x can also reach an ordinal through the type's TID, which
    helps for shadow types whose name is registered without a local ordinal.
    """

    ordinal = int(ida_typeinf.get_type_ordinal(til, name) or 0)
    if ordinal > 0 or not _HAS_NAMED_TYPE_TID:
        return ordinal

    tid = int(ida_typeinf.get_named_type_tid(name) or ida_typeinf.BADORD)
    if tid in (ida_typeinf.BADORD, 0):
        return 0
    return int(ida_typeinf.get_tid_ordinal(tid) or 0)


def tinfo_errstr(code: int) -> str:
    """Render a tinfo_code_t. Pre-9.x has no formatter, so we just stringify."""

    if _HAS_TINFO_ERRSTR:
        return ida_typeinf.tinfo_errstr(code) or str(code)
    return f"tinfo error code {code}"


def srclang_for(language: str) -> int:
    """Map a profile language string to a SRCLANG_* constant.

    Pre-9.x has no SRCLANG_OBJCPP; we fall back to SRCLANG_OBJC so the user
    still gets Objective-C parsing instead of an outright failure.
    """

    lang = (language or "c++").lower()
    if lang == "c":
        return ida_srclang.SRCLANG_C
    if lang == "objc":
        return ida_srclang.SRCLANG_OBJC
    if lang in ("objective-c++", "objcpp", "objc++"):
        if _HAS_SRCLANG_OBJCPP:
            return ida_srclang.SRCLANG_OBJCPP
        return ida_srclang.SRCLANG_OBJC
    return ida_srclang.SRCLANG_CPP


def parse_with_srclang(
    srclang: int,
    argv: str,
    til: Any,
    header_path: str,
) -> Tuple[str, int]:
    """Run the IDA source parser and return (parser_name, error_count).

    Raises CompatError if no parser supports the language or argv setup fails.
    """

    if not ida_srclang.select_parser_by_srclang(srclang):
        raise CompatError(
            f"No source parser is available in ida_srclang for srclang {srclang}."
        )

    if _HAS_SELECTED_PARSER_NAME:
        parser_name = ida_srclang.get_selected_parser_name()
        if not parser_name:
            raise CompatError("ida_srclang did not return a parser name.")
    else:
        parser_name = _LEGACY_PARSER_NAME

    rc = ida_srclang.set_parser_argv(parser_name, argv)
    if rc != 0:
        raise CompatError(
            f"set_parser_argv failed with code {rc} for parser {parser_name}."
        )

    err_count = ida_srclang.parse_decls_with_parser(parser_name, til, header_path, True)
    return parser_name, err_count
