"""Assemblyline structures."""

import json
from typing import Annotated, Any

from azul_bedrock import models_network as azm
from pydantic import BaseModel, BeforeValidator, ConfigDict


def _convert_string_to_dict(input_val: Any):
    """Convert a dictionary that has been json serialized back into a dictionary."""
    if isinstance(input_val, str):
        return json.loads(input_val)
    return input_val


class AssemblylineAzulMetadata(BaseModel):
    """Model for standardising the metadata keys for data passed in then out of Assemblyline."""

    model_config = ConfigDict(extra="allow")
    azul_source: Annotated[azm.Source, BeforeValidator(_convert_string_to_dict)]
    azul_file_info: Annotated[azm.FileInfo, BeforeValidator(_convert_string_to_dict)]
    sha256: str = ""


class BaseAlModel(BaseModel):
    """Base Model for all Assemblyline structs."""

    model_config = ConfigDict(extra="allow")


class ObjectID(BaseAlModel):
    """Assemblyline Struct."""

    tag: str
    ontology_id: str
    service_name: str = "unknown"
    guid: str | None = None
    treeid: str | None = None
    processtree: str | None = None
    time_observed: str | None = None
    session: str | None = None


class Result(BaseAlModel):
    """Assemblyline Struct."""

    class File(BaseAlModel):
        """Assemblyline Struct."""

        class PE(BaseAlModel):
            """Assemblyline Struct."""

            name: str | None = None
            format: str | None = None
            imphash: str | None = None
            entrypoint: int | None = None
            header: dict | None = None
            optional_header: dict | None = None
            dos_header: dict | None = None
            rich_header: dict | None = None
            nx: bool | None = None
            authentihash: dict | None = None
            tls: dict | None = None
            position_independent: bool | None = None
            is_reproducible_build: bool | None = None
            size_of_headers: int | None = None
            virtual_size: int | None = None
            size: int | None = None
            sections: list[dict] = []
            debugs: list[dict] = []
            export: dict | None = None
            imports: list[dict] = []
            load_configuration: dict | None = None
            resources_manager: dict | None = None
            resources: list[dict] = []
            verify_signature: str | None = None
            signatures: list[dict] = []
            overlay: dict | None = None
            relocations: list[dict] = []

        md5: str
        sha1: str
        sha256: str
        type: str | None = None
        size: int
        names: list[str] = []
        parent: str | None = None
        pe: PE | None = None

    class Service(BaseAlModel):
        """Assemblyline Struct."""

        name: str
        version: str
        tool_version: str | None = None

    class Submission(BaseAlModel):
        """Assemblyline Struct."""

        date: str | None = None
        metadata: dict
        sid: str | None = None
        source_system: str | None = None
        original_source: str | None = None
        classification: str
        submitter: str | None = None
        retention_id: str | None = None
        max_score: int | None = None

    class Results(BaseAlModel):
        """Assemblyline Struct."""

        class Antivirus(BaseAlModel):
            """Assemblyline Struct."""

            objectid: ObjectID
            engine_name: str
            engine_version: str | None = None
            engine_definition_version: str | None = None
            virus_name: str | None = None
            category: str | None = None

        class MalwareConfig(BaseAlModel):
            """Assemblyline Struct."""

            config_extractor: str

            family: list[str]
            version: str | None = None
            category: list[str] | None = None

            attack: list[str] | None = None
            capability_enabled: list[str] | None = None
            capability_disabled: list[str] | None = None
            campaign_id: list[str] | None = None
            identifier: list[str] | None = None
            decoded_strings: list[str] | None = None
            password: list[str] | None = None
            mutex: list[str] | None = None
            pipe: list[str] | None = None
            ipc: list[dict[str, Any]] | None = None
            sleep_delay: int | None = None
            sleep_delay_jitter: int | None = None
            inject_exe: list[str] | None = None

            binaries: list[dict[str, Any]] | None = None
            ftp: list[dict[str, Any]] | None = None
            smtp: list[dict[str, Any]] | None = None
            http: list[dict[str, Any]] | None = None
            ssh: list[dict[str, Any]] | None = None
            proxy: list[dict[str, Any]] | None = None
            dns: list[dict[str, Any]] | None = None
            tcp: list[dict[str, Any]] | None = None
            udp: list[dict[str, Any]] | None = None
            encryption: list[dict[str, Any]] | None = None
            service: list[dict[str, Any]] | None = None
            cryptocurrency: list[dict[str, Any]] | None = None
            paths: list[dict[str, Any]] | None = None
            registry: list[dict[str, Any]] | None = None

            other: dict | None = None

        class Netflow(BaseAlModel):
            """Assemblyline Struct."""

            objectid: ObjectID
            destination_ip: str | None = None
            destination_port: int | None = None
            transport_layer_protocol: str | None = None
            direction: str | None = None
            process: Any | None = None
            source_ip: str | None = None
            source_port: int | None = None
            http_details: Any | None = None
            dns_details: Any | None = None
            connection_type: str | None = None

        class Process(BaseAlModel):
            """Assemblyline Struct."""

            objectid: ObjectID
            image: str
            start_time: str

            # parent process details
            pobjectid: ObjectID | None = None
            pimage: str | None = None
            pcommand_line: str | None = None
            ppid: int | None = None

            pid: int | None = None
            command_line: str | None = None
            end_time: str | None = None
            integrity_level: str | None = None
            image_hash: str | None = None
            original_file_name: str | None = None

        class Heuristic(BaseAlModel):
            """Assemblyline Struct."""

            heur_id: str
            score: int
            times_raised: int
            name: str
            tags: dict[str, list]

        antivirus: list[Antivirus] = []
        http: list[dict] = []
        malwareconfig: list[MalwareConfig] = []
        netflow: list[Netflow] = []
        process: list[Process] = []
        sandbox: list[dict] = []
        signature: list[dict] = []
        tags: dict[str, list] = {}
        heuristics: list[Heuristic] = []
        score: int | None = None

    odm_type: str
    odm_version: str
    classification: str
    file: File
    service: Service
    submission: Submission | None = None
    results: Results | None = None


class SubmissionFile(BaseAlModel):
    """Assemblyline Struct."""

    name: str
    size: int | None = None
    sha256: str


class Submission(BaseAlModel):
    """Assemblyline Struct."""

    class Times(BaseAlModel):
        """Assemblyline Struct."""

        completed: str
        submitted: str

    # Allow lots of None values to allow for bad submissions to be handled.
    archive_ts: str | None = None
    classification: str
    error_count: int
    errors: list[Any]
    expiry_ts: str | None = None
    file_count: int
    files: list[SubmissionFile]
    max_score: int
    metadata: dict
    params: dict
    results: list[str] = []  # big list of services that produced data
    sid: str
    state: str
    times: Times
    verdict: dict
    scan_key: Any


class ActionApi(BaseAlModel):
    """Assemblyline Struct."""

    # SubmissionMessage is provided to the post processing action if a cache hit has occurred.
    class SubmissionMessage(BaseAlModel):
        """Assemblyline struct."""

        sid: str
        time: str
        files: list[SubmissionFile]
        metadata: dict
        notification: dict = dict()
        params: dict
        scan_key: str

    is_cache: bool
    score: int
    # Submission is provided to the post processing action if a normal submission
    # SubmissionMessage is provided when there is a cache hit.
    submission: Submission | SubmissionMessage


class Action(BaseAlModel):
    """Assemblyline Struct."""

    is_cache: bool
    score: int
    submission: Submission


class SubTree(BaseAlModel):
    """Assemblyline Struct."""

    children: dict[str, "SubTree"] = {}
    name: list[str] = []
    score: int
    sha256: str
    size: int
    truncated: bool
    type: str


class Full(BaseAlModel):
    """Assemblyline Struct."""

    class FileInfo(BaseAlModel):
        """Assemblyline Struct."""

        archive_ts: str | None = None
        ascii: str
        classification: str
        entropy: float
        expiry_ts: str
        hex: str
        magic: str
        md5: str
        mime: str
        sha1: str
        sha256: str
        size: int
        ssdeep: str
        type: str

    class Result(BaseAlModel):
        """Assemblyline Struct."""

        class Response(BaseAlModel):
            """Assemblyline Struct."""

            class Extracted(BaseAlModel):
                """Assemblyline Struct."""

                classification: str | None = None
                description: str
                name: str
                sha256: str

            extracted: list[Extracted]
            service_name: str
            service_version: str

        response: Response
        classification: str = ""
        result: dict
        sha256: str
        size: int | None = None
        type: str | None = None

    class Params(BaseAlModel):
        """Assemblyline Struct."""

        classification: str
        deep_scan: bool
        description: str
        groups: list[str]
        submitter: str
        ttl: int
        type: str

    classification: str
    error_count: int
    errors: dict
    file_count: int
    files: list
    file_infos: dict[str, FileInfo] = {}
    file_tree: dict[str, SubTree] = {}
    missing_error_keys: list = []
    missing_result_keys: list = []
    results: dict[str, Result] = {}
    state: str
    times: dict = {}
    params: Params


class Wrapper(BaseModel):
    """Custom structure for holding multiple Assemblyline models."""

    version: int
    action: Action | None = None
    ontologies: list[Result] = []
    full: Full | None = None
