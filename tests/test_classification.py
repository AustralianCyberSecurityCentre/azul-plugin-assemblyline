import json
import os
import unittest
from os import path
from unittest import mock

from assemblyline_client.common.classification import Classification as AlClassification
from azul_security import security
from parameterized import parameterized

from azul_plugin_assemblyline import settings
from tests.support import resetEnv


class ClassificationMappingTests(unittest.TestCase):
    cur_setting: settings.Settings

    @classmethod
    def setUpClass(cls):
        resetEnv()
        cls.cur_setting = settings.Settings()
        super().setUpClass()

    @parameterized.expand(
        [
            ("simple1", "TLP:CLEAR", True),
            ("simple2", "MORE OFFICIAL//TRUESTRIKE/FIREBALL", True),
            ("simple2", "TLP:ORANGE", False),
            ("simple2", "MORE OFFICIAL//IMAGINARY/FIREBALL//REL TO APPLE", False),
            ("simple2", "MORE OFFICIAL//TRUESTRIKE/FIREBALL//REL TO SKITTLES", False),
        ]
    )
    def test_is_valid(self, _, test_input: str, ok: bool):
        """Test basic one to one classification mappings."""
        self.assertEqual(self.cur_setting.is_valid_security(test_input), ok)

    @parameterized.expand(
        [
            ("simple1", "TLP:CLEAR", "OFFICIAL TLP:CLEAR"),
            ("simple2", "TLP:GREEN", "OFFICIAL TLP:GREEN"),
            ("simple3", "TLP:AMBER+STRICT", "OFFICIAL TLP:AMBER+STRICT"),
            (
                "simple4",
                "TLP:CLEAR//ULTRALONGREQUIREDTOCAUSESPECIALBUGS",
                "OFFICIAL ULTRALONGREQUIREDTOCAUSESPECIALBUGS TLP:CLEAR",
            ),
            ("simple_cavet", "TLP:CLEAR//FIREBALL", "OFFICIAL FIREBALL TLP:CLEAR"),
            ("simple_no_mapping", "OFFICIAL", "OFFICIAL"),
            ("simple_rel_1", "MORE OFFICIAL//REL TO APPLE", "MORE OFFICIAL REL:APPLE"),
            ("simple_rel_2", "MORE OFFICIAL//REL TO APPLE, BEE", "MORE OFFICIAL REL:APPLE,BEE"),
            (
                "simple_cavets_and_rel",
                "MORE OFFICIAL//TRUESTRIKE//REL TO APPLE, BEE",
                "MORE OFFICIAL TRUESTRIKE REL:APPLE,BEE",
            ),
            ("complex_subgroup_1", "MORE OFFICIAL//REL TO APPLE, BEE/ZEBRA", "MORE OFFICIAL REL:APPLE,SPADE"),
            (
                "complex_subgroup_2",
                "MORE OFFICIAL//REL TO APPLE, DOG/CAR, DOG/ELEPHANT",
                "MORE OFFICIAL REL:APPLE,CAR,ELEPHANT",
            ),
            (
                "complex_subgroup_3",
                "MORE OFFICIAL//REL TO APPLE, BEE/ZEBRA, DOG/CAR",
                "MORE OFFICIAL REL:APPLE,CAR,SPADE",
            ),
            (
                "complex_subgroup_and_cavet",
                "MORE OFFICIAL//TRUESTRIKE/FIREBALL//REL TO APPLE, BEE/ZEBRA, DOG/CAR",
                "MORE OFFICIAL FIREBALL TRUESTRIKE REL:APPLE,CAR,SPADE",
            ),
            (
                "unmapped_cavet_from_al",
                "MORE OFFICIAL//IMAGINARY/FIREBALL//REL TO APPLE",
                None,
                True,
            ),
            (
                "unmapped_rel_from_al",
                "MORE OFFICIAL//TRUESTRIKE/FIREBALL//REL TO SKITTLES",
                None,
                True,
            ),
        ]
    )
    def test_classification(self, _, test_input: str, expected: str, fail: bool = False):
        """Test basic one to one classification mappings."""
        if not fail:
            final_string = self.cur_setting.combine_security([test_input])
            print(f"{final_string}=={expected}")
            self.assertEqual(final_string, expected)
            self.assertTrue(self.cur_setting.is_valid_security(test_input))
        else:
            self.assertRaises(security.SecurityParseException, self.cur_setting.combine_security, [test_input])

    @parameterized.expand(
        [
            ("simple_merge_tlps_1", ["TLP:CLEAR", "TLP:GREEN"], "OFFICIAL TLP:GREEN"),
            ("simple_merge_tlps_2", ["TLP:GREEN", "TLP:CLEAR", "TLP:AMBER+STRICT"], "OFFICIAL TLP:AMBER+STRICT"),
            (
                "simple_merge_tlps_3",
                ["TLP:GREEN", "TLP:CLEAR", "TLP:AMBER+STRICT//FIREBALL"],
                "OFFICIAL FIREBALL TLP:AMBER+STRICT",
            ),
            ("simple_cavet", ["TLP:GREEN", "TLP:CLEAR//FIREBALL"], "OFFICIAL FIREBALL TLP:GREEN"),
            (
                "simple_2_cavet",
                ["TLP:GREEN//FIREBALL", "TLP:CLEAR//TRUESTRIKE"],
                "OFFICIAL FIREBALL TRUESTRIKE TLP:GREEN",
            ),
            (
                "complex merge with group overrides",
                [
                    "MORE OFFICIAL//TRUESTRIKE/FIREBALL//REL TO APPLE, BEE/ZEBRA, DOG/CAR",
                    "MORE OFFICIAL//REL TO APPLE, DOG, CAR, ELEPHANT",
                    "MORE OFFICIAL//REL APPLE",
                ],
                "MORE OFFICIAL FIREBALL TRUESTRIKE REL:APPLE",
            ),
            (
                "complex merge with None groups overrides",
                [
                    "MORE OFFICIAL//TRUESTRIKE/FIREBALL//REL TO APPLE, BEE/ZEBRA, DOG/CAR",
                    "MORE OFFICIAL//REL TO APPLE, DOG, CAR, ELEPHANT",
                    "MORE OFFICIAL//REL APPLE",
                ],
                "MORE OFFICIAL FIREBALL TRUESTRIKE REL:APPLE",
            ),
        ]
    )
    def test_classification_combine_multiple(self, _, test_inputs: list[str], expected: str):
        """Test combining multiple security strings"""
        final_string = self.cur_setting.combine_security(test_inputs)
        print(f"{final_string}=={expected}")
        self.assertEqual(final_string, expected)
        for line in test_inputs:
            self.assertTrue(self.cur_setting.is_valid_security(line))

    def create_mock_classification_def(self) -> AlClassification:
        basepath = path.dirname(__file__)
        path_to_al_def = os.path.join(basepath, "data", "extracted_al_classification", "al_definition.json")
        with open(path_to_al_def, "r") as f:
            al_definition = json.loads(f.read())
            return AlClassification(al_definition)

    @parameterized.expand(
        [
            ("simple1", "TLP:CLEAR", "OFFICIAL TLP:CLEAR"),
            ("simple2", "TLP:GREEN", "OFFICIAL TLP:GREEN"),
            ("simple3", "TLP:AMBER+STRICT", "OFFICIAL TLP:AMBER+STRICT"),
            (
                "simple4",
                "TLP:CLEAR//ULTRALONGREQUIREDTOCAUSESPECIALBUGS",
                "OFFICIAL ULTRALONGREQUIREDTOCAUSESPECIALBUGS TLP:CLEAR",
            ),
            ("simple_cavet", "TLP:CLEAR//FIREBALL", "OFFICIAL FIREBALL TLP:CLEAR"),
            ("simple_no_mapping", "OFFICIAL", "OFFICIAL"),
            ("simple_rel_1", "MORE OFFICIAL//REL TO APPLE", "MORE OFFICIAL REL:APPLE"),
            ("simple_rel_2", "MORE OFFICIAL//REL TO APPLE, BEE", "MORE OFFICIAL REL:APPLE,BEE"),
            (
                "simple_cavets_and_rel",
                "MORE OFFICIAL//TRUESTRIKE//REL TO APPLE, BEE",
                "MORE OFFICIAL TRUESTRIKE REL:APPLE,BEE",
            ),
            ("complex_subgroup_1", "MORE OFFICIAL//REL TO APPLE/ZEBRA", "MORE OFFICIAL REL:APPLE,SPADE"),
            (
                "complex_subgroup_2",
                "MORE OFFICIAL//REL TO APPLE/CAR/ELEPHANT",
                "MORE OFFICIAL REL:APPLE,CAR,ELEPHANT",
            ),
            (
                "complex_subgroup_3",
                "MORE OFFICIAL//REL TO APPLE/CAR/ZEBRA",
                "MORE OFFICIAL REL:APPLE,CAR,SPADE",
            ),
            (
                "complex_subgroup_and_cavet",
                "MORE OFFICIAL//FIREBALL/TRUESTRIKE//REL TO APPLE/CAR/ZEBRA",
                "MORE OFFICIAL FIREBALL TRUESTRIKE REL:APPLE,CAR,SPADE",
            ),
            (
                "unmapped_cavet_from_al",
                None,
                "MORE OFFICIAL IMAGINARY FIREBALL REL:APPLE",
                True,
            ),
            (
                "unmapped_rel_from_al",
                None,
                "MORE OFFICIAL TRUESTRIKE FIREBALL REL:SKITTLES",
                True,
            ),
            (
                "null_mapping",
                None,
                None,
                False,
            ),
        ]
    )
    def test_convert_from_azul_to_al_classification(
        self, _, test_al_classification: str, test_azul_classification: str, fail: bool = False
    ):
        """Test convert an Azul classification to an AL one."""
        mock_al_client = mock.MagicMock()
        mock_al_client.groups_map_lts = {"APPLE": "ALE", "BEE": "BEE", "DOG": "DOG"}
        mock_al_client.groups_aliases = {}
        mock_al_client.level_map_lts = {
            "INVALID": "INV",
            "NULL": "NULL",
            "TLP:CLEAR": "TLP:C",
            "TLP:GREEN": "TLP:G",
            "TLP:AMBER": "TLP:A",
            "OFFICIAL": "OFFICIAL",
            "TLP:AMBER+STRICT": "TLP:A+S",
        }
        mock_al_client.level_aliases = {
            "OFFICIAL-TLP:W": "TLP:C",
            "OFFICIAL-TLP:WHITE": "TLP:C",
            "OFFICIAL-TLP:CLEAR": "TLP:C",
            "OFFICIAL-TLP:C": "TLP:C",
            "TLP:W": "TLP:C",
            "TLP:WHITE": "TLP:C",
            "OFFICIAL-TLP:G": "TLP:G",
            "OFFICIAL-TLP:GREEN": "TLP:G",
            "OFFICIAL-TLP:AMBER": "TLP:A",
            "OFFICIAL-TLP:A": "TLP:A",
            "OFFICIAL": "OFFICIAL",
            "OFFICIAL-TLP:AMBER+STRICT": "TLP:A+S",
            "OFFICIAL-TLP:A+S": "TLP:A+S",
        }
        mock_al_client.get_classification_engine.return_value = self.create_mock_classification_def()

        if not fail:
            final_string = self.cur_setting.convert_azul_classification_to_al(mock_al_client, test_azul_classification)
            print(f"{final_string}=={test_al_classification}")
            self.assertEqual(final_string, test_al_classification)
        else:
            self.assertRaises(
                settings.AlSecurityConversionError,
                self.cur_setting.convert_azul_classification_to_al,
                mock_al_client,
                test_azul_classification,
            )
