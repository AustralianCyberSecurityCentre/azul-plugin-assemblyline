"""Server to receive Assemblyline action information and send to Azul."""

import json
import logging
import multiprocessing
import re

import assemblyline_client as al
import structlog
from azul_bedrock import models_network as azm
from azul_runner import main as azr_main
from azul_runner import storage
from azul_runner.pusher import Pusher
from azul_security import security
from fastapi import BackgroundTasks, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from prometheus_client import Counter
from starlette_exporter import PrometheusMiddleware, handle_metrics

from azul_plugin_assemblyline import common
from azul_plugin_assemblyline.plugin import AzulPluginAssemblyline
from azul_plugin_assemblyline.settings import Settings

from . import models

prom_classifications_dropped = Counter(
    "azul_plugin_assemblyline_dropped_classifications",
    "Total number of assemblyline jobs dropped because they had an unknown classification.",
    ["classification"],
)
prom_classifications_dropped.labels("")

settings = Settings()


def create_pusher(register: bool = False) -> Pusher:
    """Treat pusher as a singleton to avoid test input args."""
    args = azr_main.parse_args()
    config = azr_main.args_to_config(args)
    pusher = Pusher(AzulPluginAssemblyline, config, register)
    return pusher


log_level = getattr(logging, settings.log_level.upper(), "INFO")
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(log_level))
logger = structlog.get_logger()

# default description line
desc_default = re.compile(
    r"""
    (?:\[.+\]\s)?  # params.type
    (?:
        (?P<inspect>Inspection)\sof\s(?P<itype>file|URL):\s(?P<ipath>.*) |
        (?P<resubmit>Resubmit)?\s(?P<rpath>.*)\sfor\sanalysis
    )
""",
    re.VERBOSE,
)

al_client_ref = common.setup_al_client(settings, logger)

logger.info("Finshed setup for connections to Assemblyline and Azul.")
app = FastAPI()

# Add prometheus metrics to application.
app.add_middleware(
    PrometheusMiddleware,
    app_name="azul_plugin_assemblyline",
    prefix="azul_plugin_assemblyline",
    group_paths=True,
)
app.add_route("/metrics", handle_metrics)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """When a request is invalid provide additional logging information."""
    exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
    logger.info(f"{request}: {exc_str}")
    content = {"status_code": 10422, "message": exc_str, "data": None}
    return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@app.get("/")
def read_root():
    """Nonsense content."""
    return "OK"


def fix_description(desc: str):
    """Cleanup the description.

    Remove type from description and attempt to standardise name.
    The description is a free text field that is input by the client on submission.
    The submission type is then prefixed to this input wrapped in square braces:
        ie: [TYPE] Description

    If default description is used, remove filename/hash to better group submissions.
    By default "Inspection of file: <filename/hash>" or "Resubmit <file> for analysis" is used if not specified.
    """
    m = desc_default.match(desc)
    if m:
        desc = m["inspect"] or m["resubmit"]
    return desc


def multiprocess_submission(action: models.ActionApi):
    """Use multiprocessing to process the submission, as it fixes a memory leak.

    The memory leak is fixed because when the subprocess is closed all memory is released.
    This memory leak showed no heap growth or larger number of threads.
    """
    process = multiprocessing.Process(
        target=process_submission,
        args=(action, al_client_ref),
    )
    process.start()
    process.join()
    process.close()


def process_submission(api_action: models.ActionApi, al_client: al.Client4):
    """With Assemblyline action, enrich with more AL api calls and send to Azul."""
    if api_action.is_cache:  # Cache hit so need to get the submission.
        submission: models.Submission = al_client.submission(api_action.submission.sid)
        action = models.Action(is_cache=api_action.is_cache, score=api_action.score, submission=submission)
    else:  # Non-cache hit so submission should be a Submission Type.
        if isinstance(api_action.submission, models.Submission):
            action = models.Action(
                is_cache=api_action.is_cache, score=api_action.score, submission=api_action.submission
            )
        else:
            raise Exception(
                "Non-cache hit did not use a submission " + f"type can't process api_action {api_action.model_dump()}"
            )

    submitted_by_azul = False
    azul_instance = action.submission.metadata.get(settings.azul_instance_key)
    if azul_instance:
        if azul_instance == settings.azul_instance:
            logger.info(
                f"Metadata only for submission with metadata {action.submission.metadata} as it was submitted by azul."
            )
            submitted_by_azul = True
        else:
            logger.info(f"Report from azul instance '{azul_instance}' not '{settings.azul_instance}'.")
            # from a different azul instance, avoid crossover by not mapping this data
            return

    if settings.azul_instance_key in action.submission.metadata:
        submitted_by_azul = True

    clsf = action.submission.classification
    if not settings.is_valid_security(clsf):
        logger.info(f"skipping classification '{clsf}' for action with sha256 '{action.submission.files[0].sha256}'")
        prom_classifications_dropped.labels(str(clsf)).inc()
        return
    clsfs = [clsf]

    sha256 = action.submission.files[0].sha256

    # fetch ontologies and encode
    ontologies: list[dict] = []

    for ontology in al_client.ontology.submission(action.submission.sid):
        clsf = ontology["classification"]
        if not settings.is_valid_security(clsf):
            logger.info(
                f"skipping classification '{clsf}' for ontology on sha256 '{action.submission.files[0].sha256}'"
            )
            continue
        clsfs.append(clsf)
        ontologies.append(ontology)

    # all results of submission except for ontologies
    full = models.Full(**al_client.submission.full(action.submission.sid))
    clsf = full.classification
    if not settings.is_valid_security(clsf):
        logger.warning(
            f"skipping classification '{clsf}' for submission on sha256 '{action.submission.files[0].sha256}'"
        )
        prom_classifications_dropped.labels(str(clsf)).inc()
        return
    clsfs.append(full.classification)
    for k in list(full.results.keys()):
        result = full.results[k]
        clsf = result.classification
        if not settings.is_valid_security(clsf):
            logger.info(f"skipping full.result with classification: {clsf}")
            logger.info(
                f"skipping classification '{clsf}' for a result on sha256 '{action.submission.files[0].sha256}'"
            )
            full.results.pop(k)
            continue
        clsfs.append(clsf)

    al_meta = {
        "version": 1,
        "action": action.model_dump(),
        "ontologies": ontologies,
        "full": full.model_dump(),
    }

    # submit clsfs to azul and get max
    # compute security (sorted to allow for easier testing)

    max_clsf = ""
    try:
        max_clsf = settings.combine_security(clsfs)
    except security.SecurityParseException as ex:
        arg = ""
        if len(ex.args) > 0:
            arg = ex.args[0]
        logger.warning(f"Couldn't map classifications {clsfs} with exception '{arg}'")
        prom_classifications_dropped.labels(str(clsf)).inc()
        return

    logger.debug(f"uploading meta: {json.dumps(al_meta, indent=2)}")

    # Re-create the pusher every time to prevent memory leak.
    pusher = create_pusher()

    # fetch and submit the parent submission.
    root_submission = list(full.file_tree.values())[0]
    filename = root_submission.name[0] if len(root_submission.name[0]) > 0 else root_submission.sha256

    # Put the metadata contents into the plugin as a local stream.
    meta_contents = json.dumps(al_meta, indent=4).encode()
    with storage.StorageProxyFile(
        source=settings.al_source,
        label=azm.DataLabel.ASSEMBLYLINE,
        hash=sha256,
        init_data=meta_contents,
        file_info=azm.Datastream(label=azm.DataLabel.ASSEMBLYLINE, file_format="text/json"),
        allow_unbounded_read=True,
    ) as meta_spf:
        if submitted_by_azul:
            azul_meta = models.AssemblylineAzulMetadata(**action.submission.metadata)

            azul_source = azul_meta.azul_source
            azul_file_info = azul_meta.azul_file_info
            sha256 = root_submission.sha256

            pusher.push_once_mapped(
                source_file_info=azul_file_info,
                source_info=azul_source,
                security=max_clsf if max_clsf else "",
                relationship={"external": "Enriched by Assemblyline"},
                filename=filename,
                local=[meta_spf],
            )

            logger.info(f"Completed mapping file {sha256}")
        else:
            content = common.download_uncarted_al_file(al_client, root_submission.sha256)
            references: dict[str, str] = {
                "type": str(action.submission.params["type"]),
                "description": fix_description(action.submission.params["description"]),
                "user": str(action.submission.params["submitter"]),
            }

            sha256 = pusher.push_once_sourced(
                content=content,
                source_label=settings.al_source,
                references=references,
                security=max_clsf if max_clsf else "",
                filename=filename,
                local=[meta_spf],
            )

            logger.info(f"Completed sourcing file {sha256}")


@app.post("/")
def post_simple(action: models.ActionApi, bg: BackgroundTasks):
    """Handle assemblyline action and forward to Azul."""
    logger.info(f"schedule - {action.submission.sid} - {action.submission.files[0].sha256}")
    bg.add_task(multiprocess_submission, action)
    return "thanks"


def main():
    """Start server."""
    import uvicorn

    # Register plugin
    create_pusher(register=True)

    headers: list[tuple[str, str]] = []
    for header_label, header_val in settings.plugin_headers.items():
        headers.append((header_label.strip(), header_val.strip()))

    uvicorn.run(app, host="0.0.0.0", port=8850, log_level="info", headers=headers)  # nosec B104


if __name__ == "__main__":
    main()
