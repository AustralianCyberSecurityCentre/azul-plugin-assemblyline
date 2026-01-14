"""Map Assemblyline triage results into Azul binary events."""

import json
from collections import defaultdict

from azul_runner import (
    BinaryPlugin,
    DataLabel,
    Event,
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from azul_runner import settings as azr_settings
from azul_runner import (
    storage,
)
from packaging.version import parse as parse_version

from azul_plugin_assemblyline import common
from azul_plugin_assemblyline.settings import Settings as AlClientSettings

from . import models


class ServerVersionException(Exception):
    """Plugin not compatible with saved data format from azul-assemblyline server."""

    pass


class AzulPluginAssemblyline(BinaryPlugin):
    """Map Assemblyline triage results into Azul binary events."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.06.11"
    SETTINGS = add_settings(
        # File size to process
        filter_max_content_size=(int, 10 * 1024 * 1024),
    )
    # Using pusher so output events will be mapped events rather than enriched because they are coming from an
    # external sourced (assemblyline)
    _IS_USING_PUSHER = True

    FEATURES = [
        Feature("assemblyline_score", desc="Assemblyline score for submission", type=FeatureType.Integer),
        Feature("assemblyline_type", desc="Assemblyline identified type", type=FeatureType.String),
        Feature("attack", desc="Mitre att&ck reference ids, e.g. 'T1129'", type=FeatureType.String),
        Feature("av_signature", "Name of antivirus signature that was triggered", type=FeatureType.String),
        Feature(
            "behaviour_signature", desc="Behavioural signature name that the sample triggered", type=FeatureType.String
        ),
        Feature("campaign_id", desc="Server/campaign id for malware", type=FeatureType.String),
        Feature("category", desc="Capability/purpose of the malware", type=FeatureType.String),
        Feature("config_name", desc="Name of malware/config that were able to extract", type=FeatureType.String),
        Feature("document_author", desc="Document author name", type=FeatureType.String),
        Feature("document_company", desc="Company name of user who authored the document", type=FeatureType.String),
        Feature("document_last_author", desc="Last author name of the document", type=FeatureType.String),
        Feature("document_title", desc="Document title", type=FeatureType.String),
        Feature("domain", desc="Domain name observed or extracted from the sample", type=FeatureType.String),
        Feature("family", desc="Family of malware that was detected", type=FeatureType.String),
        Feature("filename", "The name of the file", type=FeatureType.Filepath),
        Feature("heuristic", desc="Heuristic raised", type=FeatureType.String),
        Feature("ip_address", desc="IP address observed or extracted from the sample", type=FeatureType.String),
        Feature("ja3", desc="JA3 string for TLS", type=FeatureType.String),
        Feature("ja3_digest", desc="JA3 digest (md5[JA3]) for TLS", type=FeatureType.String),
        Feature(
            "macro_suspicious",
            desc="Suspicious keywords related to macros that may be used by malware",
            type=FeatureType.String,
        ),
        Feature("mail_address", desc="Email addresses", type=FeatureType.String),
        Feature("mail_message_id", desc="Unique ID assigned to the mail message", type=FeatureType.String),
        Feature("mail_subject", desc="Message subject line", type=FeatureType.String),
        Feature("mutex", desc="Mutex to prevent multiple instances", type=FeatureType.String),
        Feature("network_signature_id", desc="ID assigned to the signature", type=FeatureType.String),
        Feature("network_signature_message", desc="Short description of results", type=FeatureType.String),
        Feature("ole_comments", desc="Any comments set for the OLE document", type=FeatureType.String),
        Feature("ole_subject", desc="OLE document subject", type=FeatureType.String),
        Feature("password", desc="Any password extracted from the binary", type=FeatureType.String),
        Feature("pe_export", desc="Name of the DLL exported", type=FeatureType.String),
        Feature("pe_export_function", desc="Name of the exported function", type=FeatureType.String),
        Feature("pe_import_hash", desc="MD5 hash of the import entries", type=FeatureType.String),
        Feature(
            "pe_import_hash_sorted",
            desc="MD5 imports sorted hash as per Quarklabs implementation",
            type=FeatureType.String,
        ),
        Feature("pe_section", desc="Name of the PE section", type=FeatureType.String),
        Feature("pe_section_hash", desc="MD5 of the contents of the section", type=FeatureType.String),
        Feature("port", desc="Port used to communicate", type=FeatureType.Integer),
        Feature("registry", desc="A registry key", type=FeatureType.String),
        Feature("strings_api", desc="Strings related to API calls or similar", type=FeatureType.String),
        Feature(
            "strings_dangerous",
            desc="Strings that can indicate a binary could be used maliciously",
            type=FeatureType.String,
        ),
        Feature("strings_decoded", desc="Decoded strings from within malware", type=FeatureType.String),
        Feature("uri", desc="URI observed or extracted from the sample", type=FeatureType.Uri),
        Feature("user_agent", desc="User agent of http request/response", type=FeatureType.String),
        Feature("vector", desc="Calculated vectors used to identify code", type=FeatureType.String),
        Feature("yararule", desc="Name of the rule for the Yara Match", type=FeatureType.String),
        Feature(
            "yara_match",
            desc="Binary string signature match extracted by the labelling yara rule",
            type=FeatureType.String,
        ),
        Feature("submission_metadata", desc="Submission metadata provided to Assemblyline", type=FeatureType.String),
        # Possibly map timestamps in the future, but need to determine how best to ensure consistency.
        # AL stores timestamps as strings, and each service decides the string format.
        # Feature("compile_time", desc="Compile Time", type=datetime),
        # Feature("document_created", desc="Time the document was created", type=datetime),
        # Feature("document_last_saved", desc="Time the document was last saved", type=datetime),
        # Feature("mail_date desc="Time the email was sent in UTC", type=datetime),
    ]

    tag_map = {
        "attribution.campaign": "campaign_id",
        "attribution.category": "category",
        "attribution.family": "family",
        "attribution.implant": "config_name",
        "av.virus_name": "av_signature",
        "dynamic.mutex": "mutex",
        "dynamic.registry_key": "registry",
        "file.ole.macro.suspicious_string": "macro_suspicious",
        "file.ole.summary.author": "document_author",
        "file.ole.summary.comment": "ole_comments",
        "file.ole.summary.company": "document_company",
        "file.ole.summary.last_saved_by": "document_last_author",
        "file.ole.summary.subject": "ole_subject",
        "file.ole.summary.title": "document_title",
        "file.path": "filename",
        "file.pe.exports.function_name": "pe_export_function",
        "file.pe.exports.module_name": "pe_export",
        "file.pe.imports.imphash": "pe_import_hash_sorted",
        "file.pe.imports.md5": "pe_import_hash",
        "file.pe.sections.name": "pe_section",
        "file.pe.sections.hash": "pe_section_hash",
        "file.pe.versions.filename": "filename",
        "file.rule.yara": "yararule",
        "file.string.api": "strings_api",
        "file.string.blacklisted": "strings_dangerous",
        "file.string.decoded": "strings_decoded",
        "heuristic.attack.attack_id": "attack",
        "heuristic.signature.name": "behaviour_signature",
        "info.password": "password",
        "network.dynamic.domain": "domain",
        "network.dynamic.ip": "ip_address",
        "network.dynamic.uri": "uri",
        "network.email.address": "mail_address",
        "network.email.msg_id": "mail_message_id",
        "network.email.subject": "mail_subject",
        "network.port": "port",
        "network.signature.signature_id": "network_signature_id",
        "network.signature.message": "network_signature_message",
        "network.static.domain": "domain",
        "network.static.ip": "ip_address",
        "network.static.uri": "uri",
        "network.tls.ja3_hash": "ja3_digest",
        "network.tls.ja3_string": "ja3",
        "network.user_agent": "user_agent",
        "vector": "vector",
        # Possibly map timestamps in the future, but need to determine how best to ensure consistency.
        # AL stores timestamps as strings, and each service decides the string format.
        # "file.ole.summary.create_time": "document_created",
        # "file.ole.summary.last_saved_time": "document_last_saved",
        # "file.pe.linker.timestamp": "compile_time",
        # "network.email.date": "mail_date",
    }

    def __init__(self, config: azr_settings.Settings | dict | None = None):
        super().__init__(config)
        self.al_settings = AlClientSettings()
        self.al_client_ref = common.setup_al_client(self.al_settings, self.logger)

    def process_yara_hits(self, al_result: models.Full.Result) -> list[FeatureValue]:
        """Process a yara hit from the full result of an assemblyline run."""
        yara_hits: list[FeatureValue] = []
        if al_result.response.service_name.lower() != "yara":
            return yara_hits

        result_section = al_result.result.get("sections", [])
        if len(result_section) < 1:
            return yara_hits

        for section in result_section:
            string_hits: list[str] = section.get("body", {}).get("string_hits", [])
            for string_hit in string_hits:
                # Parse yara string hits in the form
                """
                "string_hits": [
                    "a : ''\\\\x90'' [@ 0x1598ee, 0x16b4dd, 0x184ba2, 0x191517, 0x242571...] (6x)",
                    "b : ''\\\\x90'' [@ 0x190977, 0x309fb4] (2x)",
                    "d : ''\\\\x91'' [@ 0x16b4e0, 0x182604, 0x185577, 0x19ca0a, 0x19ca0b...] (35x)",
                ],
                """
                split_str = string_hit.split("[@")
                hit_values = "[@".join(split_str[:-1])
                addresses = split_str[-1]

                # Convert the hit into something sensible
                hit_values = hit_values.split(": '")
                if len(hit_values) < 1:
                    self.logger.warning(f"Failed to split a yara hit's hit value out. hit was {string_hit}")
                    continue
                hit_string = "".join(hit_values[1:])
                # Cut off the single quotes around the match.
                if hit_string.startswith("'") and hit_string.endswith("'"):
                    hit_string = hit_string[1:-2]

                # Strip out non address info:
                addresses = addresses.split("]")[0]
                addresses = addresses.replace("...", "")
                for addr in addresses.split(","):
                    string_address = addr.strip()
                    try:
                        offset_as_int = int(string_address, 16)
                    except Exception:
                        self.logger.warning(f"Failed to split and convert yara hit's offset. hit was {string_hit}")
                        continue
                    yara_hits.append(
                        FeatureValue(hit_string, label=section.get("body", {}).get("name", ""), offset=offset_as_int)
                    )
        return yara_hits

    def execute(self, job: Job):
        """Run the plugin."""
        try:
            self.meta = models.Wrapper(**json.loads(job.get_data(DataLabel.ASSEMBLYLINE).read().decode("utf8")))
            # To collect new samples for tests uncomment out the below line.
            # self.logger.warning(self.meta.model_dump_json())
        except storage.ProxyFileNotFoundError as e:
            return State(
                State.Label.ERROR_EXCEPTION,
                message="The event is missing the stream with the label assemblyline. "
                + f"This shouldn't happen and means the server has had an issue, error was {e}",
            )
        except Exception as e:
            return State(
                State.Label.ERROR_EXCEPTION,
                message=f"Unable to get the stream with label assemblyline for an unknown reason, error was: {e}",
            )
        if self.meta.version != 1:
            raise ServerVersionException("Version of azul-assemblyline server data is not compatible with plugin.")

        # FUTURE - give scope to do things differently when submitted to assemblyline from Azul.
        self.submitted_by_azul = False
        azul_instance = self.meta.action.submission.metadata.get(self.al_settings.azul_instance_key)
        if azul_instance:
            if azul_instance == self.al_settings.azul_instance:
                self.submitted_by_azul = True
            else:
                # from a different azul instance, avoid crossover by not mapping this data
                return State(
                    State.Label.OPT_OUT,
                    message=f"report from azul instance '{azul_instance}' not '{self.al_settings.azul_instance}'",
                )

        for meta_key, meta_value in self.meta.action.submission.metadata.items():
            # Ignore keys that are used during re-ingest that aren't interesting
            if meta_key in ["azul_instance", "azul_source", "azul_file_info"]:
                continue
            self.add_feature_values("submission_metadata", FeatureValue(meta_value, label=meta_key))

        self.add_feature_values("assemblyline_score", self.meta.action.submission.max_score)

        # initialise mappings for recursive walk
        self.ontology_map: dict[str, list[models.Result]] = {}
        self.map_extracted: dict[str, models.Full.Result.Response.Extracted] = {}
        self.map_extracted_service: dict[str, models.Full.Result] = {}
        self.map_yara_hits: dict[str, list[FeatureValue]] = defaultdict(list)

        # map ontologies to sha256
        self.meta.ontologies.sort(key=lambda x: (x.file.sha256, x.service.name))
        for o in self.meta.ontologies:
            self.ontology_map.setdefault(o.file.sha256, []).append(o)

        # map services that extracted files to the files sh256 for later lookup
        for v in self.meta.full.results.values():
            for ex in v.response.extracted:
                # only care about last service that extracted the file
                self.map_extracted[ex.sha256] = ex
                self.map_extracted_service[ex.sha256] = v
            # Add different hits to one another
            self.map_yara_hits[v.sha256] = self.map_yara_hits[v.sha256] + self.process_yara_hits(v)

        # navigate through tree
        # assumption - only one top level file
        self._recursive_tree(None, list(self.meta.full.file_tree.values())[0])

    def _recursive_tree(self, _parent: Event | None, _tree: models.SubTree):
        """Recursively walk the submission.

        * Extracts and adds children.
        * Maps AL tags to Features.

        This method should **only** be called by `execute`.
        """
        file_info = self.meta.full.file_infos[_tree.sha256]

        if _parent:
            # Can't do any child metadata as a mapped event can't have child extracted events.
            if self.submitted_by_azul:
                return

            # add/get child
            ex = self.map_extracted[_tree.sha256]
            service = self.map_extracted_service[_tree.sha256]

            # shorten descriptions in some cases
            desc = ex.description.replace("Extracted using ", "")

            # If the event was submitted by Azul we don't want the binary content. This is also
            # because the events would become extracted events attached to a mapped event which is problematic
            data = common.download_uncarted_al_file(self.al_client_ref, _tree.sha256)
            c = _parent.add_child_with_data({"action": service.response.service_name, "note": desc}, data)

            c.magic = file_info.magic
            c.mime = file_info.mime
            c.sha256 = file_info.sha256
            c.sha1 = file_info.sha1
            c.md5 = file_info.md5
            c.size = _tree.size
            c.file_format = file_info.type
        else:
            # this is a root of the tree
            c = self._event_main

        c.add_feature_values("assemblyline_type", file_info.type)
        # map data from tree
        for name in _tree.name:
            if _tree.sha256 == name:
                continue
            c.add_feature_values("filename", name)

        # Apply yara hits if the sha256 has any.
        if self.map_yara_hits.get(c.sha256):
            for match_fv in self.map_yara_hits[c.sha256]:
                c.add_feature_values("yara_match", match_fv)

        # map data from ontologies
        o: models.Result
        for o in self.ontology_map.get(_tree.sha256, []):
            if o.odm_type != "Assemblyline Result Ontology":
                raise Exception(f"unknown odm_type {o.odm_type} in {o}")
            if not (parse_version("1.0") <= parse_version(o.odm_version) < parse_version("2.0")):
                raise Exception(f"unknown odm_version {o.odm_version} in {o}")

            if results := o.results:
                # map some tags
                for k, vs in results.tags.items():
                    if f := self.tag_map.get(k):
                        c.add_feature_values(f, [FeatureValue(v) for v in vs])

                # map heuristics
                for h in results.heuristics:
                    c.add_feature_values("heuristic", FeatureValue(h.name, label=f"{h.heur_id} | score {h.score}"))

        # recurse all children
        for gc in _tree.children.values():
            self._recursive_tree(c, gc)


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginAssemblyline)


if __name__ == "__main__":
    main()
