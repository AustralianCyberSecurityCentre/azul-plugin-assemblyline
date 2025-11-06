import json
import os


def resetEnv():
    # AL builtin settings
    os.environ["al_url"] = "hxxp://localhost:8888"
    os.environ["al_user"] = "1234"
    os.environ["al_token"] = "1234"
    # SECURITY SETTINGS
    os.environ["security_minimum_required_access"] = json.dumps([])
    os.environ["security_default"] = "OFFICIAL"
    os.environ["security_presets"] = json.dumps([])
    os.environ["security_allow_releasability_priority_gte"] = "30"
    os.environ["security_labels"] = json.dumps(
        {
            "classification": {
                "title": "Classifications",
                "options": [
                    {"name": "LESS OFFICIAL", "priority": "10"},
                    {"name": "OFFICIAL", "priority": "20"},
                    {"name": "MORE OFFICIAL", "priority": "30"},
                ],
            },
            "caveat": {
                "title": "Required",
                "options": [
                    {"name": "FIREBALL"},
                    {"name": "TRUESTRIKE"},
                    {"name": "ULTRALONGREQUIREDTOCAUSESPECIALBUGS"},
                ],
            },
            "releasability": {
                "title": "Groups",
                "origin": "REL:APPLE",
                "prefix": "REL:",
                "options": [
                    {"name": "REL:APPLE"},
                    {"name": "REL:BEE"},
                    {"name": "REL:CAR"},
                    {"name": "REL:DOG"},
                    {"name": "REL:ELEPHANT"},
                    {"name": "REL:SPADE"},
                ],
            },
            "tlp": {
                "title": "TLP",
                "options": [
                    {"name": "TLP:CLEAR"},
                    {"name": "TLP:GREEN"},
                    {"name": "TLP:AMBER"},
                    {"name": "TLP:AMBER+STRICT"},
                ],
            },
        }
    )
    # azul_plugin_assemblyline settings
    os.environ["security_map"] = json.dumps(
        {
            # TLPS
            "TLP:WHITE": ["OFFICIAL", "TLP:CLEAR"],
            "TLP:W": ["OFFICIAL", "TLP:CLEAR"],
            "TLP:CLEAR": ["OFFICIAL", "TLP:CLEAR"],
            "TLP:GREEN": ["OFFICIAL", "TLP:GREEN"],
            "TLP:G": ["OFFICIAL", "TLP:GREEN"],
            "TLP:AMBER": ["OFFICIAL", "TLP:AMBER"],
            "TLP:AMBER+STRICT": ["OFFICIAL", "TLP:AMBER+STRICT"],
            "LESS OFFICIAL": ["LESS OFFICIAL"],
            "MORE OFFICIAL": ["MORE OFFICIAL"],
            "FIREBALL": ["FIREBALL"],
            "TRUESTRIKE": ["TRUESTRIKE"],
            "APPLE": ["REL:APPLE"],
            "BEE": ["REL:BEE"],
            "CAR": ["REL:CAR"],
            "DOG": ["REL:DOG"],
            "ELEPHANT": ["REL:ELEPHANT"],
            "ZEBRA": ["REL:SPADE"],  # Odd mapping to catch edge cases for group to subgroup mappings
            "ULTRALONGREQUIREDTOCAUSESPECIALBUGS": ["ULTRALONGREQUIREDTOCAUSESPECIALBUGS"],
        }
    )
    os.environ["group_to_subgroup_mapping"] = json.dumps({"DOG": ["ELEPHANT", "CAR"], "BEE": ["ZEBRA"]})
