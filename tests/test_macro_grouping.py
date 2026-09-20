import unittest

from clang_include.macro_grouping import (
    allocate_member_names,
    enum_definitions_error,
    group_tree_parents,
    is_c_identifier,
    migrate_group_rules,
    partition_managed_member_names,
    stable_definition_id,
    suggest_macro_groups,
)


class MacroGroupingTests(unittest.TestCase):
    def test_migrates_legacy_rules_to_stable_snapshot_definitions(self) -> None:
        rules = [
            {
                "enum_name": "MACRO_IDC",
                "pattern": "^IDC_",
                "selected": ["IDC_OK", "IDC_CANCEL"],
            }
        ]

        first = migrate_group_rules(rules)
        second = migrate_group_rules(rules)

        self.assertEqual(first, second)
        self.assertEqual(first[0]["id"], stable_definition_id("MACRO_IDC", "^IDC_"))
        self.assertEqual(first[0]["owner_key"], "group:MACRO_IDC")
        self.assertEqual(
            [member["source_name"] for member in first[0]["members"]],
            ["IDC_OK", "IDC_CANCEL"],
        )
        self.assertTrue(all(member["missing"] for member in first[0]["members"]))

    def test_migration_skips_invalid_legacy_names(self) -> None:
        rules = [
            {"enum_name": "not-valid", "pattern": ".*", "selected": ["IDC_OK"]},
            {"enum_name": "MACRO_OK", "pattern": ".*", "selected": ["GOOD", "not-valid"]},
        ]

        definitions = migrate_group_rules(rules)

        self.assertEqual([item["enum_name"] for item in definitions], ["MACRO_OK"])
        self.assertEqual([item["source_name"] for item in definitions[0]["members"]], ["GOOD"])

    def test_identifier_validation(self) -> None:
        self.assertTrue(is_c_identifier("MACRO_IDC"))
        self.assertTrue(is_c_identifier("_private"))
        self.assertFalse(is_c_identifier("not-valid"))
        self.assertFalse(is_c_identifier("1_VALUE"))

    def test_detection_exposes_broad_and_specific_choices(self) -> None:
        suggestions = suggest_macro_groups(
            ["IDC_PLAYERINFO_NAME", "IDC_PLAYERINFO_MODEL", "IDC_VIDSELECT_A", "IDC_VIDSELECT_B"]
        )

        self.assertEqual(
            [rule["enum_name"] for rule in suggestions],
            ["MACRO_IDC", "MACRO_IDC_PLAYERINFO", "MACRO_IDC_VIDSELECT"],
        )

    def test_detection_requires_multiple_members(self) -> None:
        suggestions = suggest_macro_groups(["IDC_ONLY", "HTTP_A", "HTTP_B"])

        self.assertEqual([rule["enum_name"] for rule in suggestions], ["MACRO_HTTP"])

    def test_names_from_deleted_or_renamed_enums_are_reclaimable(self) -> None:
        states = {
            "deleted": {"member_names": {"old-id": "OLD_NAME"}},
            "retained": {"member_names": {"same-id": "SAME_NAME", "renamed-id": "OLD_RENAMED"}},
        }
        active = {
            "retained": {
                "same-id": "SAME_NAME",
                "renamed-id": "NEW_RENAMED",
            }
        }

        reserved, reclaimable = partition_managed_member_names(states, active)

        self.assertEqual(reserved, {"SAME_NAME"})
        self.assertEqual(reclaimable, {"OLD_NAME", "OLD_RENAMED"})

    def test_allocates_stable_names_for_overlapping_macro_groups(self) -> None:
        definitions = [
            {
                "enum_name": "MACRO_ALL",
                "members": [
                    {"kind": "macro", "source_name": "VALUE", "emitted_name": "VALUE"},
                ],
            },
            {
                "enum_name": "MACRO_SPECIFIC",
                "members": [
                    {"kind": "macro", "source_name": "VALUE", "emitted_name": "VALUE"},
                    {"kind": "macro", "source_name": "OTHER", "emitted_name": "OTHER"},
                ],
            },
        ]

        allocate_member_names(definitions)
        allocate_member_names(definitions)

        self.assertEqual(definitions[0]["members"][0]["emitted_name"], "VALUE")
        self.assertEqual(definitions[1]["members"][0]["emitted_name"], "VALUE_2")
        self.assertEqual(definitions[1]["members"][1]["emitted_name"], "OTHER")

    def test_custom_names_take_precedence_over_macro_names(self) -> None:
        definitions = [
            {
                "enum_name": "MACRO_TEST",
                "members": [
                    {"kind": "macro", "source_name": "TRUE", "emitted_name": "TRUE"},
                    {"kind": "custom", "name": "TRUE", "literal": "1"},
                ],
            }
        ]

        allocate_member_names(definitions)

        self.assertEqual(definitions[0]["members"][0]["emitted_name"], "TRUE_2")
        self.assertEqual(enum_definitions_error(definitions), "")

    def test_definition_validation_rejects_empty_and_duplicate_names(self) -> None:
        self.assertEqual(
            enum_definitions_error([{"enum_name": "EMPTY", "members": []}]),
            "EMPTY has no members. Add a value or delete the enum.",
        )
        definitions = [
            {"enum_name": "SAME", "members": [{"kind": "custom", "name": "A", "literal": "1"}]},
            {"enum_name": "SAME", "members": [{"kind": "custom", "name": "B", "literal": "2"}]},
        ]
        self.assertEqual(enum_definitions_error(definitions), "Enum name SAME is used more than once.")
        malformed = [
            {
                "enum_name": "BAD_VALUE",
                "members": [{"kind": "custom", "name": "VALUE", "literal": "1 << 4"}],
            }
        ]
        self.assertIn("not a supported integer value", enum_definitions_error(malformed))

    def test_group_tree_uses_nearest_prefix_parent_regardless_of_order(self) -> None:
        names = [
            "MACRO_IDC_PLAYERINFO_NAME",
            "MACRO_IDC",
            "MACRO_IDC_PLAYERINFO",
            "MACRO_HTTP",
        ]

        self.assertEqual(group_tree_parents(names), [2, None, 1, None])


if __name__ == "__main__":
    unittest.main()
