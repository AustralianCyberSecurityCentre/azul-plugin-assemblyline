"""Load a security setting map between Azul and Assemblyline."""

import logging
import re
import traceback
from functools import cache, cached_property

import assemblyline_client as al
from assemblyline_client.common.classification import Classification as AlClassification
from azul_security import security
from pydantic import PrivateAttr, computed_field
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class AlSecurityConversionError(Exception):
    """Exception raised when an Azul classification couldn't be converted to an assemblyline one."""

    pass


@cache
def get_classification_definition(al_client: al.Client4) -> AlClassification:
    """Get the classification definition from the assemblyline server to allow for security mappings."""
    current_error = None
    for _ in range(10):
        try:
            return al_client.get_classification_engine()
        except Exception as e:
            logger.warning("Failed to get assemblyline's classification engine.")
            current_error = e
    raise AlSecurityConversionError(f"Couldn't get Assemblyline's classification with error {current_error}")


@cache
def get_list_of_al_groups(classification_def: AlClassification):
    """Get all the assemblyline groups (exculding sub groups)."""
    # Get all the groups and their aliases so no matter what Azul users we can work it out.
    all_groups = (
        # Group aliases contains short names mapped to long names.
        # {"ALIAS_FOR_APPLE": "ALE", 'BE': 'B", "MOTOR_VEHICLE": "C"}
        list(classification_def.groups_aliases.keys())
        + list(classification_def.groups_aliases.values())
        # groups_map_lts contains group long names mapped to short names.
        # {'APPLE': 'ALE', 'BEE': 'B', 'CAR': 'C', 'DOG': 'DG'}
        + list(classification_def.groups_map_lts.keys())
        + list(classification_def.groups_map_lts.values())
    )
    return list(set(all_groups))


@cache
def get_list_of_al_levels(classification_def: AlClassification):
    """Get all the assemblyline levels (e.g classifications OFFICAL, MORE OFFICIAL)."""
    # Get all the groups and their aliases so no matter what Azul users we can work it out.
    all_levels = (
        # Group aliases contains short names mapped to long names.
        # {'INVALID': 'INV', 'NULL': 'NULL', 'TLP:CLEAR': 'TLP:C'}
        list(classification_def.levels_aliases.keys())
        + list(classification_def.levels_aliases.values())
        # groups_map_lts contains group long names mapped to short names.
        # {'OFFICIAL-TLP:W': 'TLP:C', 'OFFICIAL-TLP:WHITE': 'TLP:C'}
        + list(classification_def.levels_map_lts.keys())
        + list(classification_def.levels_map_lts.values())
    )
    return list(set(all_levels))


class Settings(BaseSettings):
    """Settings for the plugin."""

    azul_instance: str = "azul"
    azul_instance_key: str = "azul_instance"
    # Name of the assemblyline source
    al_source: str = "assemblyline"
    # Priority of submissions sent to Assemblyline.
    al_priority: int = 1000

    # Security headers applied to the uvicorn server
    plugin_headers: dict[str, str] = dict()

    # Url to the assemblyline instance
    al_url: str
    # Username for user authenticating to Assemblyline.
    al_user: str
    # API Token for Assemblyline user.
    al_token: str
    # Submission profile for AL submissions
    al_submission_profile: str = "static"
    # Enable/Disable SSL Verify
    al_verify: str = "true"
    # Security mapping from Assemblyline security strings to Azul security strings if they are different.
    security_map: dict[str, list] = dict()
    # security_map: dict[str, list] = {
    #     # TLPS
    #     "TLP:WHITE": ["OFFICIAL", "TLP:CLEAR"],
    #     "TLP:W": ["OFFICIAL", "TLP:CLEAR"],
    #     "TLP:CLEAR": ["OFFICIAL", "TLP:CLEAR"],
    #     "TLP:GREEN": ["OFFICIAL", "TLP:GREEN"],
    #     "TLP:G": ["OFFICIAL", "TLP:GREEN"],
    #     "TLP:AMBER": ["OFFICIAL", "TLP:AMBER"],
    #     "TLP:AMBER+STRICT": ["OFFICIAL", "TLP:AMBER+STRICT"],
    #     "LESS OFFICIAL": ["LESS OFFICIAL"],
    #     "MORE OFFICIAL": ["MORE OFFICIAL"],
    #     "FIREBALL": ["FIREBALL"],
    #     "TRUESTRIKE": ["TRUESTRIKE"],
    #     "APPLE": ["REL:APPLE"],
    #     "BEE": ["REL:BEE"],
    #     "CAR": ["REL:CAR"],
    #     "DOG": ["REL:DOG"],
    #     "ELEPHANT": ["REL:ELEPHANT"],
    #     "ZEBRA": ["REL:SPADE"],  # Odd mapping to catch edge cases for group to subgroup mappngs
    # }
    # Dictionary containg a map of an Assemblyline Group to it's subgroup.
    # This is needed to remove the group mapping in the event the subgroup is present.
    # NOTE - all subgroups listed here must map to only one Azul Group.
    group_to_subgroup_mapping: dict[str, list[str]] = dict()
    # group_to_subgroup_mapping: dict[str, list[str]] = {"DOG": ["ELEPHANT", "CAR"], "BEE": ["ZEBRA"]}

    # Timeout to ensure assemblyline client eventually times out.
    client_timeout_seconds: int = 180

    @computed_field
    @cached_property
    def sorted_security_map(self) -> dict[str, list]:
        """Security map sorted with the longest Azul values first to prevent mapping issues when keys overlap."""
        return dict(sorted(self.security_map.items(), key=lambda kv: len("".join(kv[1])), reverse=True))

    @computed_field
    @cached_property
    def subgroup_to_group(self) -> dict[str, str]:
        """Maps a subgroup token to a group token that should be removed if subgroup is present."""
        subgroup_to_remove = {}
        # Map all AL data to azul.
        for al_group, al_subgroups in self.group_to_subgroup_mapping.items():
            for al_subgroup in al_subgroups:
                # Map the subgroup to the parent group
                subgroup_to_remove[al_subgroup] = al_group

        return subgroup_to_remove

    # allow specifying the log level
    log_level: str = "INFO"
    _security: security.Security = PrivateAttr(default_factory=security.Security)

    def is_valid_security(self, clsf: str):
        """Return true if all groups from assembyline can be mapped to azul."""
        tokens = self._convert_al_clsf_to_al_tokens(clsf)
        final_tokens = set()
        for t in tokens:
            if t in self.security_map.keys():
                final_tokens.update(self.security_map[t])
            else:
                final_tokens.add(t)
        try:
            self._security.string_normalise(" ".join(final_tokens))
        except security.SecurityParseException:
            return False
        return True

    def _convert_al_clsf_to_al_tokens(self, al_clsf: str) -> set[str] | None:
        """Converts Assemblyline security string to individual tokens."""
        tokens = set(re.split(r",|\/", al_clsf.replace("REL TO", "").replace("REL", "")))
        final_tokens = set()
        for t in tokens:
            t = t.strip()
            # Filter out empty tokens
            if not t:
                continue
            final_tokens.add(t)

        return final_tokens

    def convert_azul_classification_to_al(self, al_client: al.Client4, azul_classification: str) -> str | None:
        """Convert an azul classification to an assemblyline one.

        Ensure ALL of a security string is mapped to an Assemblyline equivalent with no leftovers.
        Then adds groups and everything else like this:
        LEVEL//RELEASABILITY//SUB_GROUP//REL TO GROUP1//REL TO GROUP2
        which after normalization will look like this:
        LEVEL//RELEASABILITY//REL TO GROUP1, GROUP2/SUB_GROUP

        """
        if azul_classification is None:
            logger.warning("Provided Azul classification was None.")
            return None

        classification_def = get_classification_definition(al_client)

        mapped_classification = azul_classification
        # All commas become REL:Group to allow for sorted_security_map mapping to work.
        mapped_classification = mapped_classification.replace(",", " REL:")

        al_classification_tokens = list()

        # Map potentially multiple Azul classifications to one AL classification
        for al_mapped_classification, azul_mapped_classification in self.sorted_security_map.items():
            all_tokens_match = True
            for azul_token in azul_mapped_classification:
                if azul_token not in mapped_classification:
                    # Token missing
                    all_tokens_match = False
                    break

            if not all_tokens_match or len(azul_mapped_classification) == 0:
                continue

            # All tokens are in the string or the azul_mapped_classification is empty.
            al_classification_tokens.append(al_mapped_classification)
            for azul_token in azul_mapped_classification:
                mapped_classification = mapped_classification.replace(azul_token, "", 1)

        mapped_classification = mapped_classification.strip()
        if len(mapped_classification) > 0:
            logger.warning(f"Leftovers '{mapped_classification}' will be implicitly mapped.")
            al_classification_tokens.append(mapped_classification)

        # Make all groups in the security string start with REL TO
        al_groups = get_list_of_al_groups(classification_def)
        al_classification = ""
        for token in list(al_classification_tokens):
            if token in al_groups:
                al_classification += f"//REL TO {token}"
                al_classification_tokens.remove(token)

        # al_classification looks like this '' or 'REL TO APPLE//REL TO BEE' - normalize will fix it up.

        # Ensure the levels are at the front of the list, which is required by AL normalization.
        all_levels = get_list_of_al_levels(classification_def)
        for level in all_levels:
            if level in al_classification_tokens:
                al_classification_tokens.remove(level)
                al_classification_tokens.insert(0, level)

        al_classification = "//".join(al_classification_tokens) + al_classification

        # Now if should look like this 'OFFICIAL//FIREBALL//SUB_GROUP//REL TO APPLE//REL TO BEE - normalize fixes it.

        # Normalise first as a classification may become valid after normalisation
        normalize_error = None
        try:
            al_classification = classification_def.normalize_classification(al_classification)
        except Exception as e:
            normalize_error = e
            logger.warning(f"Failed to normalize classification with error {traceback.format_exc()}")

        if classification_def.is_valid(al_classification):
            return al_classification

        raise AlSecurityConversionError(
            f"The Azul classification {azul_classification} was converted into the"
            + f" Assemblyline classification {al_classification} which is not a valid assemblyline classification.\n"
            + f"With normalization error {normalize_error}"
        )

    def combine_security(self, al_clsfs: list[str]) -> str | None:
        """Convert Assemblyline classifications to an Azul compatible Classification string."""
        al_tokens = []
        for clsf in al_clsfs:
            al_tokens.append(self._convert_al_clsf_to_al_tokens(clsf))

        # Find all tokens that need to be removed if present based on subgrouping.
        tokens_to_remove = set()
        for clsfs in al_tokens:
            for token in clsfs:
                if token in self.subgroup_to_group.keys():
                    tokens_to_remove.add(self.subgroup_to_group[token])

        securities = []
        for clsfs in al_tokens:
            # Remove group if a subgroup was present
            fixed_tokens = clsfs.difference(tokens_to_remove)

            final_tokens = set()
            for t in fixed_tokens:
                if t in self.security_map.keys():
                    final_tokens.update(self.security_map[t])
                else:
                    final_tokens.add(t)

            securities.append(self._security.string_normalise(" ".join(final_tokens)))

        securities = [s for s in securities if s is not None]
        if len(securities) == 0:
            return None
        security_merged = self._security.string_combine(securities)
        return security_merged
