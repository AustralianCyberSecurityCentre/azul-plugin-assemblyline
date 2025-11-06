"""Code common to both main.py and plugin.py."""

import io
from logging import Logger

import assemblyline_client as al
import cart
from pydantic import BaseModel

from azul_plugin_assemblyline.settings import Settings as alSettings


class UploadSettings(BaseModel):
    """Data class that holds the settings for uploading to Assemblyline."""

    classification: str | None
    description: str = ""
    deep_scan: bool = False
    priority: int = 1000
    ignore_cache: bool = False


def setup_al_client(settings: alSettings, logger: Logger) -> al.Client4:
    """Setup the AL client for interactions with Assemblyline."""
    verify = True
    if settings.al_verify:
        if settings.al_verify.lower() == "false":
            verify = False
        elif settings.al_verify.lower() != "true":
            # verify can be a path to ca file
            verify = settings.al_verify

    logger.info(
        f"Connecting to Assemblyline with the Assemblyline Client with the AL URL '{settings.al_url}'"
        + f" and username '{settings.al_user}'."
    )
    return al.get_client(
        settings.al_url,
        apikey=(settings.al_user, settings.al_token),
        verify=verify,
        timeout=settings.client_timeout_seconds,
    )


def download_uncarted_al_file(al_client: al.Client4, sha256: str) -> bytes:
    """Uncart stream to normal file."""
    carted_content: bytes = al_client.file.download(sha256)
    unpacked = io.BytesIO()
    cart.unpack_stream(io.BytesIO(carted_content), unpacked)
    unpacked.seek(0)
    return unpacked.getvalue()
