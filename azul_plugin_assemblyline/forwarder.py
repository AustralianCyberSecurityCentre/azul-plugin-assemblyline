"""Forward azul binaries to Assemblyline."""

import contextlib
import json
import time
import traceback

import assemblyline_client as al
from azul_runner import BinaryPlugin, Job, State, add_settings, cmdline_run

from azul_plugin_assemblyline import common, settings
from azul_plugin_assemblyline.models import AssemblylineAzulMetadata
from azul_plugin_assemblyline.settings import Settings as AlClientSettings

CLIENT_MAX_RETRY_COUNT = 10
CLIENT_RETRY_SLEEP_SECONDS = 10


class AzulPluginAssemblylineForwarder(BinaryPlugin):
    """Forward events in Azul into Assemblyline to try and get more features."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.08.25"
    SETTINGS = add_settings(
        # Max of 100MB going back through AL to reduce load
        filter_max_content_size=100 * 1024 * 1024,
        # Only want live events to prevent excessive submissions to Assemblyline
        require_historic=False,
    )
    FEATURES = []

    def __init__(self, config: settings.Settings | dict = None):
        super().__init__(config)
        self.al_settings = AlClientSettings()
        self.al_client_ref = common.setup_al_client(self.al_settings, self.logger)

    def execute(self, job: Job):
        """Run the plugin."""
        # Ignore all jobs from the Assemblyline source.
        if job.event.source.name == self.al_settings.al_source:
            return State(
                State.Label.OPT_OUT, failure_name="Already in Assemblyline", message="Source is from Assemblyline."
            )

        # Ignore all jobs if the sha256 is already in Assemblyline.
        for attempt in range(CLIENT_MAX_RETRY_COUNT):
            try:
                if len(self.al_client_ref.hash_search(job.event.entity.sha256)["al"]["items"]) > 0:
                    return State(
                        State.Label.OPT_OUT,
                        failure_name="Already in Assemblyline",
                        message="Checked Assemblyline and already there.",
                    )
            except al.ClientError as e:
                self.logger.warning(
                    "Retrying as failed to verify if file is already in Assemblyline due to client error "
                    + f"status code: {e.status_code} message: {e.api_response}"
                )
                if attempt >= CLIENT_MAX_RETRY_COUNT - 1:
                    return State(
                        State.Label.ERROR_EXCEPTION,
                        failure_name="Assemblyline Network Error",
                        message="Couldn't contact Assemblyline with "
                        + f"status code: {e.status_code} message: {e.api_response}",
                    )
                time.sleep(CLIENT_RETRY_SLEEP_SECONDS)
                continue
            except KeyError:
                error_msg = (
                    "Got a key error when checking if a hash was in Assemblyline this shouldn't happen!\n"
                    + traceback.format_exc()
                )
                self.logger.error(error_msg)
                return State(State.Label.ERROR_EXCEPTION, message=error_msg)
            except Exception:
                return State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="Assemblyline Network Error",
                    message="Failed to check if file was in Assemblyline with error\n" + traceback.format_exc(),
                )
            break

        # Create AL equivalent security string
        try:
            al_security_string = self.al_settings.convert_azul_classification_to_al(
                self.al_client_ref, job.event.source.security
            )
        except Exception as e:
            msg = (
                "couldn't convert Azul security string "
                + f"{job.event.source.security} into an Assemblyline security label with error {e}"
            )
            self.logger.warning(msg)
            return State(
                State.Label.ERROR_EXCEPTION,
                message=msg,
            )

        # Get the binary file and submit it to Assemblyline.
        content = job.get_data()
        filename = "unknown"
        with contextlib.suppress(Exception):
            if job.event.source.path[0].filename:
                filename = job.event.source.path[0].filename

        for attempt in range(CLIENT_MAX_RETRY_COUNT):
            description = f"[{self.al_settings.azul_instance}] enrich file sourced from {job.event.source.name}"
            try:
                azul_meta = AssemblylineAzulMetadata(
                    azul_source=job.event.source,
                    azul_file_info=job.event.entity.to_file_info(),
                    sha256=job.event.entity.sha256 if job.event.entity.sha256 else "",
                )
                azul_meta_dict = azul_meta.model_dump(exclude_none=True)
                azul_meta_dict[self.al_settings.azul_instance_key] = self.al_settings.azul_instance
                # Convert the dict field into a string
                azul_meta_dict["azul_source"] = json.dumps(azul_meta_dict["azul_source"])
                azul_meta_dict["azul_file_info"] = json.dumps(azul_meta_dict["azul_file_info"])

                self.al_client_ref.ingest(
                    path=content.get_filepath(),
                    fname=filename,
                    params=common.UploadSettings(
                        classification=al_security_string,
                        priority=self.al_settings.al_priority,
                        description=description,
                    ).model_dump(exclude_none=True),
                    metadata=azul_meta_dict,
                    # avoid alerts as this isn't a true feed
                    alert=False,
                    submission_profile=self.al_settings.al_submission_profile,
                )
            except al.ClientError as e:
                self.logger.warning(
                    "Retrying as failed to submit file to Assemblyline due to client error "
                    + f"status code: {e.status_code} message: '{e.api_response}'"
                )
                if attempt >= CLIENT_MAX_RETRY_COUNT - 1:
                    return State(
                        State.Label.ERROR_EXCEPTION,
                        message="Couldn't contact Assemblyline with error \n" + traceback.format_exc(),
                    )
                time.sleep(CLIENT_RETRY_SLEEP_SECONDS)
                continue
            except Exception:
                return State(
                    State.Label.ERROR_EXCEPTION,
                    message="Failed to submit file to Assemblyline with error\n" + traceback.format_exc(),
                )
            break


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginAssemblylineForwarder)


if __name__ == "__main__":
    main()
