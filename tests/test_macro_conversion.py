import tempfile
import unittest
from subprocess import CompletedProcess
from pathlib import Path
from unittest import mock

from clang_include import macro_conversion
from clang_include.macro_conversion import collect_clang_macros, collect_python_macros, parse_integer_literal


class IntegerLiteralTests(unittest.TestCase):
    def test_common_integer_literals(self) -> None:
        self.assertEqual(parse_integer_literal("1337"), (1337, 4, True))
        self.assertEqual(parse_integer_literal("(0xFFu)"), (255, 4, False))
        self.assertEqual(parse_integer_literal("077"), (63, 4, True))
        self.assertEqual(parse_integer_literal("0b1010UL"), (10, 4, False))
        self.assertEqual(parse_integer_literal("-42LL"), (-42, 8, True))

    def test_expressions_are_left_for_clang(self) -> None:
        self.assertIsNone(parse_integer_literal("1 << 4"))
        self.assertIsNone(parse_integer_literal("sizeof(int)"))


class PythonScannerTests(unittest.TestCase):
    def test_scans_recursive_project_headers_and_skips_unsupported_macros(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            included = root / "included.h"
            header = root / "main.h"
            included.write_text("#define SAME 1337\n#define EXPRESSION (1 << 4)\n", encoding="utf-8")
            header.write_text(
                '#include "included.h"\n#define VALUE 1337\n#define FUNCTION(x) (x)\n',
                encoding="utf-8",
            )

            values = collect_python_macros(str(header), [str(root)])

        self.assertEqual([(item.name, item.value) for item in values], [("SAME", 1337), ("VALUE", 1337)])

    def test_honors_simple_header_guards_and_undef(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "guarded.h"
            header.write_text(
                "#ifndef GUARDED_H\n#define GUARDED_H\n#define LIVE 7\n#endif\n#define REMOVED 8\n#undef REMOVED\n",
                encoding="utf-8",
            )
            values = collect_python_macros(str(header), [])

        self.assertEqual([(item.name, item.value) for item in values], [("LIVE", 7)])


class ClangScannerTests(unittest.TestCase):
    def test_uses_exactly_two_clang_processes(self) -> None:
        preprocessed = '# 1 "C:/project/main.h"\n#define VALUE (7 + 2)\n'
        ast = (
            '{"kind":"EnumConstantDecl","name":"__clang_include_macro_0",'
            '"inner":[{"kind":"ConstantExpr","value":"9","type":{"qualType":"int"}}]}'
        )
        runs = [
            CompletedProcess([], 0, preprocessed, ""),
            CompletedProcess([], 0, ast, ""),
        ]
        with mock.patch.object(macro_conversion, "_run_clang", side_effect=runs) as runner:
            values = collect_clang_macros("clang", "C:/project/main.h", [])

        self.assertEqual(runner.call_count, 2)
        self.assertEqual([(item.name, item.value) for item in values], [("VALUE", 9)])


if __name__ == "__main__":
    unittest.main()
